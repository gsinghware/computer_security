#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+-------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(C) (32 bytes for SHA256) |
 * +------------+--------------------+-------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

// CPA Secure

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

	if (entropy != NULL)
	{
		unsigned char* out1_buff;
		out1_buff = malloc(64);
		HMAC(EVP_sha512(), KDF_KEY, 32, entropy, entLen, out1_buff, NULL);

		for (int i = 0; i < 32; i++)
			K->hmacKey[i] = out1_buff[i];

		for (int i = 32; i < 64; i++)
			K->aesKey[i-32] = out1_buff[i];

		free(out1_buff);
	}
	else 
	{
		unsigned char* _buff1;								/* buffer for randBytes */
		_buff1 = malloc(32);	 							/* allocote bytes in memory */
		randBytes(_buff1, 32);							 	/* generate random bytes */

		for (int i = 0; i < 32; i++)
			K->hmacKey[i] = _buff1[i];

		unsigned char* _buff2;								/* buffer for randBytes */
		_buff2 = malloc(32);	 							/* allocote bytes in memory */
		randBytes(_buff2, 32);							 	/* generate random bytes */

		for (int i = 0; i < 32; i++)
			K->aesKey[i] = _buff2[i];

		free(_buff1);
		free(_buff2);
	}

	return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}

size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */

	/* +------------+--------------------+-------------------------------+
	 * | 16 byte IV | C = AES(plaintext) | HMAC(C) (32 bytes for SHA256) |
	 * +------------+--------------------+-------------------------------+ */

	// printf("Message before decrypt\n");
	// for (int i = 0; i < len; ++i)
	// {
	// 	printf("%u", inBuf[i]);
	// }
	// printf("\n");

	// printf("ENCRYPTING MODE --- ENCRYPTING MODE --- ENCRYPTING MODE --- ENCRYPTING MODE\n");
	// printf("ENCRYPTING MODE --- ENCRYPTING MODE --- ENCRYPTING MODE --- ENCRYPTING MODE\n");
	// printf("ENCRYPTING MODE --- ENCRYPTING MODE --- ENCRYPTING MODE --- ENCRYPTING MODE\n");

	// printf("------------\nText to be encrypted\n");

	// for (int i = 0; i < len; i++) {
	// 	printf("%c", inBuf[i]);
	// }

	// printf("\n------------\n\n");

	if (IV == NULL)
		for (int i = 0; i < 16; i++) IV[i] = i;

	memcpy(outBuf, IV, 16);

	// printf("------------\nAfter adding the 16 IV\n");

	// for (int i = 0; i < len; i++) {
	// 	printf("%u ", outBuf[i]);
	// }

	// printf("\n------------\n\n");

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV))
		ERR_print_errors_fp(stderr);

	int nWritten;
	if (1 != EVP_EncryptUpdate(ctx, outBuf + 16, &nWritten, inBuf, len))
		ERR_print_errors_fp(stderr);

	EVP_CIPHER_CTX_free(ctx);

	int total = 16 + 32 + nWritten;

	// printf("------------\nThis is the middle IV + AES(plaintext), before adding the HMAC\n");

	// for (int i = 0; i < total - 32; i++) {
	// 	printf("%u ", outBuf[i]);
	// }

	// printf("\n------------\n\n");

	unsigned char myBuf[nWritten];
	memcpy(myBuf, outBuf+16, nWritten);

	// printf("------------\nThis is the AES(ciphertext) alone\n");
	
	// for (int i = 0; i < nWritten; i++) {
	// 	printf("%u ", myBuf[i]);
	// }

	// printf("\n------------\n\n");

	unsigned char* _HMAC = malloc(HM_LEN);
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, outBuf, nWritten+16, _HMAC, NULL);
	memcpy(outBuf + 16 + nWritten, _HMAC, 32);

	// printf("------------\nCipher Text of the plain text, after adding the HMAC\n");

	// for (int i = 0; i < total; i++) 
	// {
	// 	printf("%u ", outBuf[i]);
	// }

	// printf("\n------------\n\n");

	return total;
}

size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{

	if (IV == NULL)
		for (int i = 0; i < 16; i++) IV[i] = i;

	// printf("I'm in encrypt file function \n");
	// printf("%s %s\n", fnin, fnout);

	/* TODO: write this.  Hint: mmap. */

	int fd = open(fnin, O_RDONLY);
    if (fd == -1) return -1;

    struct stat sb;
    if (fstat(fd, &sb) == -1) return -1;

    if (sb.st_size == 0) return -1;

    char *src;
    src = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (src == MAP_FAILED)
    	return -1;

    // for (int i = 0; i < sb.st_size; i++)
    // 	printf("%c", src[i]);

    // printf("\n");

    size_t len = strlen(src) + 1;
    size_t ctLen = ske_getOutputLen(len);
    unsigned char *ct = malloc(ctLen+1);
    size_t total = ske_encrypt(ct, (unsigned char*)src, len, K, IV);

    // printf("total - %zu\n", total);

    int dd = open(fnout, O_CREAT | O_RDWR, S_IRWXU);

    write(dd, ct, (int)total);

	return 0;
}

size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{

	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	/* +------------+--------------------+-------------------------------+
	 * | 16 byte IV | C = AES(plaintext) | HMAC(C) (32 bytes for SHA256) |
	 * +------------+--------------------+-------------------------------+ */

	// printf("DECRYPTION MODE --- DECRYPTION MODE --- DECRYPTION MODE --- DECRYPTION MODE\n");
	// printf("DECRYPTION MODE --- DECRYPTION MODE --- DECRYPTION MODE --- DECRYPTION MODE\n");
	// printf("DECRYPTION MODE --- DECRYPTION MODE --- DECRYPTION MODE --- DECRYPTION MODE\n");

	// printf("------------\nCipher Text of the plain text, IV + AES(plaintext) + HMAC\n");

	// for (int i = 0; i < len; i++) 
	// {
	// 	printf("%u ", inBuf[i]);
	// }

	// printf("\n------------\n\n");
	
	unsigned char hmac[32];
	
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, inBuf, len-32, hmac, NULL);

	for (int i = 0; i < 32; i++)
    {
        if (hmac[i] != inBuf[len-32+i])
            return -1;  
    }

	unsigned char IV[16];
	for (int i = 0; i < 16; i++) IV[i] = i;

	int x = len - 32 - 16;
	
	unsigned char ct[x];

	// printf("length - %i x - %i\n", len, x);
	// printf("------------\nThis is the AES(plaintext) alone\n");

	for (int i = 16; i < 16 + x; i++)
	{
		// printf("%u ", inBuf[i]);
		ct[i-16] = inBuf[i];
	}

	// printf("\n------------\n\n");

	EVP_CIPHER_CTX* ctx1 = EVP_CIPHER_CTX_new();
	ctx1 = EVP_CIPHER_CTX_new();
	
	if (1!=EVP_DecryptInit_ex(ctx1, EVP_aes_256_ctr(), 0, K->aesKey, IV))
		ERR_print_errors_fp(stderr);

	size_t ctLen = x;
	// printf("ctLen - %zu\n", ctLen);

	int nWritten = 0;
	if (1!=EVP_DecryptUpdate(ctx1, outBuf, &nWritten, ct, ctLen))
		ERR_print_errors_fp(stderr);

	return 0;
}

size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */

	int fd = open(fnin, O_RDONLY);
    if (fd == -1) return -1;

    struct stat sb;
    if (fstat(fd, &sb) == -1) return -1;

    if (sb.st_size == 0) return -1;

    unsigned char *src;
    src = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (src == MAP_FAILED)
    	return -1;

    char* pt = malloc(sb.st_size-48);
    ske_decrypt((unsigned char*)pt, src, sb.st_size, K);

	printf("Message after decrypt\n");
    for (int i = 0; i < (sb.st_size-48); i++)
    	printf("%c", pt[i]);

    printf("\n");

    FILE *f = fopen(fnout, "w");
    fprintf(f, "%s", pt);
    fclose(f);

}

