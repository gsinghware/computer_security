#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,&len,-1,1,0,0,x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE* f, mpz_t x)
{
	size_t i,len = mpz_size(x)*sizeof(mp_limb_t);
	unsigned char* buf = malloc(len);
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b = (len >> 8*i) % 256;
		fwrite(&b,sizeof(char),1,f);
	}
	Z2BYTES(buf,len,x);
	fwrite(buf,sizeof(char),len,f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

int zFromFile(FILE* f, mpz_t x)
{
	size_t i,len=0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b,1,1,f);
		len += (b << 8*i);
	}
	unsigned char* buf = malloc(len);
	fread(buf,1,len,f);
	BYTES2Z(x,buf,len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

/* TODO: write this.  Use the prf to get random byte strings of
 * the right length, and then test for primality (see the ISPRIME
 * macro above).  Once you've found the primes, set up the other
 * pieces of the key ({en,de}crypting exponents, and n=pq). */

int rsa_keyGen(size_t keyBits, RSA_KEY* K)
{
	rsa_initKey(K);											/* init the key, n p q e d = 0 */

	/* Step 1: Choose two distinct prime numbers p and q. */

	int n = 0;												/* n: prime count */
	int r = 0;												/* r: isPrime result */

	while (1) 
	{	
		unsigned char* _buff;								/* buffer for randBytes */
		_buff = malloc(keyBits/8);	 						/* allocote bytes in memory */
		randBytes(_buff, keyBits/8);						/* generate random bytes */
		NEWZ(num);											/* inti mpz int */
		BYTES2Z(num, _buff, keyBits/8);						/* convert bytes to integer */

		r = ISPRIME(num);											
		if (r > 0) 											/* probably a prime */
		{
			n++;											/* increment prime count */
			if (n == 1)
				mpz_set(K->p, num);							/* set p */
			else 
			{
				mpz_set(K->q, num);							/* set q */
				break;
			}
		}
		free(_buff);
	}

	/* Step 2: Compute n = pq. */

	NEWZ(rop); mpz_mul(rop, K->q, K->p);
	mpz_set(K->n, rop);										/* set n */

	/* Step 3: Compute φ(n) = φ(p)φ(q) = (p − 1)(q − 1). */

	NEWZ(p1); mpz_sub_ui(p1, K->p, 1);
	NEWZ(p2); mpz_sub_ui(p2, K->q, 1);
	NEWZ(phi_n); mpz_mul(phi_n, p1, p2);

	/* Step 4: Choose an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1; i.e., e and φ(n) are coprime.*/

	NEWZ(e); mpz_set_ui(e, 2);

	NEWZ(result);
	mpz_gcd(result, e, phi_n);

	while (mpz_get_ui(result) != 1)
	{
		mpz_add_ui(e, e, 1);
		mpz_gcd(result, e, phi_n);
	}

	mpz_set(K->e, e);										/* set e */

	/* Step 5: Determine d as d ≡ e^−1 (mod φ(n)); i.e., d is the modular multiplicative inverse of e (modulo φ(n)). */

	NEWZ(g); NEWZ(d); NEWZ(t);
	mpz_gcdext(g, d, t, e, phi_n);
	
	// to avoid negative d
	mpz_add(d, d, phi_n);

	mpz_set(K->d, d);										/* set d */

	// gmp_printf("---------------------------------------------------\n");
	// gmp_printf("RSA Key Generation\n");
	// gmp_printf("---------------------------------------------------\n");

	// gmp_printf("p\n------------------------------------------------\n%Zd\n", K->p);
	// gmp_printf("---------------------------------------------------\n");

	// gmp_printf("q\n------------------------------------------------\n%Zd\n", K->q);
	// gmp_printf("---------------------------------------------------\n");

	// gmp_printf("n\n------------------------------------------------\n%Zd\n", K->n);
	// gmp_printf("---------------------------------------------------\n");

	// gmp_printf("e\n------------------------------------------------\n%Zd\n", K->e);
	// gmp_printf("---------------------------------------------------\n");

	// gmp_printf("d\n------------------------------------------------\n%Zd\n", K->d);
	// gmp_printf("---------------------------------------------------\n");

	// gmp_printf("---------------------------------------------------\n");
	// gmp_printf("g\n------------------------------------------------\n%Zd\n", g);
	// gmp_printf("---------------------------------------------------\n");

	// gmp_printf("---------------------------------------------------\n");
	// gmp_printf("t\n------------------------------------------------\n%Zd\n", t);
	// gmp_printf("---------------------------------------------------\n");

	return 0;
}

/* TODO: write this.  Use BYTES2Z to get integers, and then
 * Z2BYTES to write the output buffer. */

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	NEWZ(cipherText);
	NEWZ(num);
	BYTES2Z(num, inBuf, len);
	mpz_powm(cipherText, num, K->e, K->n);
	Z2BYTES(outBuf, len, cipherText);
	return len; /* TODO: return should be # bytes written */
}

/* TODO: write this.  See remarks above. */

size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	NEWZ(plainText);
	NEWZ(num);
	BYTES2Z(num, inBuf, len);
	mpz_powm(plainText, num, K->d, K->n);
	Z2BYTES(outBuf, len, plainText);
	return len;
}

size_t rsa_numBytesN(RSA_KEY* K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY* K)
{
	mpz_init(K->d); mpz_set_ui(K->d,0);
	mpz_init(K->e); mpz_set_ui(K->e,0);
	mpz_init(K->p); mpz_set_ui(K->p,0);
	mpz_init(K->q); mpz_set_ui(K->q,0);
	mpz_init(K->n); mpz_set_ui(K->n,0);
	return 0;
}

int rsa_writePublic(FILE* f, RSA_KEY* K)
{
	/* only write n,e */
	zToFile(f,K->n);
	zToFile(f,K->e);
	return 0;
}
int rsa_writePrivate(FILE* f, RSA_KEY* K)
{
	// zToFile(f,K->n);
	// zToFile(f,K->e);
	zToFile(f,K->p);
	zToFile(f,K->q);
	zToFile(f,K->d);
	return 0;
}
int rsa_readPublic(FILE* f, RSA_KEY* K)
{
	// rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	return 0;
}
int rsa_readPrivate(FILE* f, RSA_KEY* K)
{
	// rsa_initKey(K);
	// zFromFile(f,K->n);
	// printf("writing N to file\n");
	// zFromFile(f,K->e);
	// printf("writing E to file\n");
	zFromFile(f,K->p);
	// printf("writing P to file\n");
	zFromFile(f,K->q);
	// printf("writing Q to file\n");
	zFromFile(f,K->d);
	// printf("writing D to file\n");
	return 0;
}
int rsa_shredKey(RSA_KEY* K)
{
	/* clear memory for key. */
	mpz_t* L[5] = {&K->d,&K->e,&K->n,&K->p,&K->q};
	size_t i;
	for (i = 0; i < 5; i++) {
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs) {
			memset(mpz_limbs_write(*L[i],nLimbs),0,nLimbs*sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}
