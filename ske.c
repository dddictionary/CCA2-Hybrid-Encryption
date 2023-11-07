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
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define IV_LEN 16
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

	size_t k2 = KLEN_SKE * 2;
	unsigned char tempKey[k2];

	//if entropy is given, apply KDF to it
	if (entropy) {
		HMAC(EVP_sha512(), KDF_KEY, HM_LEN, entropy,entLen, tempKey, NULL);
	} else {
		//random key
		randBytes(tempKey, k2);
	}
	//copy values into keys object
	memcpy(K->hmacKey, tempKey, KLEN_SKE); //lower tempKey
	memcpy(K->aesKey, tempKey+KLEN_SKE, KLEN_SKE); // upper tempKey

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
	//if no IV given, generate random IV
	if (!IV) {
		randBytes(IV, 16);
	}
	//Encrypt
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); //set up a new context for cipher text.
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV) != 1) {
		perror("Error in ecryption.");
	}

	int num;
	unsigned char cipherTextBuf[len];
	unsigned char ivCipherTextBuf[AES_BLOCK_SIZE + len];
	memcpy(ivCipherTextBuf, IV, AES_BLOCK_SIZE); //copy IV into buffer

	if (EVP_EncryptUpdate(ctx, cipherTextBuf, &num, inBuf, len) != 1) {
		perror("Error in encryption.");
	}

	memcpy(ivCipherTextBuf + AES_BLOCK_SIZE, cipherTextBuf, num); //copy cipher text into buffer
	unsigned char tempHMACKey[HM_LEN];
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, ivCipherTextBuf, AES_BLOCK_SIZE + len, tempHMACKey, NULL); //generate HMAC

	memcpy(outBuf, IV, 16);
	memcpy(outBuf + 16, cipherTextBuf, num);
	memcpy(outBuf+16+num, tempHMACKey, HM_LEN);
	EVP_CIPHER_CTX_free(ctx); //free context

	return AES_BLOCK_SIZE+num+HM_LEN; /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */
}

size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */
	int fdIn, fdOut;
	struct stat st;

	size_t fileSize, num;
	unsigned char *mappedFile;

	fdIn = open(fnin, O_RDONLY);

	if (fdIn < 0) {
		perror("Error opening file.");
		return 1;
	}

	stat(fnin, &st);
	fileSize = st.st_size;

	mappedFile = mmap(NULL, fileSize, PROT_READ, MMAP_SEQ, fdIn, 0);

	if (mappedFile == MAP_FAILED) {
		perror("Error mapping file.");
		return 1;
	}

	unsigned char tempBuf[fileSize+AES_BLOCK_SIZE+HM_LEN];
	num = ske_encrypt(tempBuf, mappedFile, fileSize, K, IV);

	fdOut = open(fnout, O_RDWR | O_CREAT, S_IRWXU);

	if (fdOut < 0) {
		perror("Error opening file.");
		return 1;
	}

	if (lseek(fdOut, offset_out, SEEK_SET) < 0) {
		perror("Error seeking file.");
		return 1;
	}

	if (write(fdOut, tempBuf, num) < 0) {
		perror("Error writing to file.");
		return 1;
	}

	close(fdIn);
	close(fdOut);
	munmap(mappedFile, fileSize);
	return num;
}

size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
	unsigned char *mac = malloc(HM_LEN);
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, inBuf, len-HM_LEN, mac, NULL); //generate HMAC
	if(memcmp(mac, inBuf + len - HM_LEN, HM_LEN) != 0) {
		perror("Error: MAC does not match.");
		return -1;
	}

	//extract IV
	unsigned char *IV = malloc(IV_LEN);
	memcpy(IV, inBuf, IV_LEN);

	//get ctx

	int nWritten;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, K->aesKey, IV) != 1) {
		perror("Error in decryption.");
	}

	if (EVP_DecryptUpdate(ctx, outBuf, &nWritten, inBuf + IV_LEN, len - IV_LEN - HM_LEN) != 1) {
		perror("Error in decryption.");
	}

	free(mac);
	free(IV);
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */
	int fdIn, fdOut;
	struct stat st;
	size_t fileSize, num;
	unsigned char *mappedFile;

	fdIn = open(fnin, O_RDONLY);
	if (fdIn < 0) {
		perror("Error opening file.");
		return 1;
	}

	stat(fnin, &st);
	fileSize = st.st_size-offset_in;

	mappedFile = mmap(NULL,fileSize, PROT_READ,MMAP_SEQ, fdIn, 0);

	if (mappedFile == MAP_FAILED) {
		perror("Error mapping file.");
		return 1;
	}

	unsigned char tempBuf[fileSize-AES_BLOCK_SIZE-HM_LEN];

	num = ske_decrypt(tempBuf, mappedFile+offset_in, fileSize, K);

	fdOut = open(fnout, O_RDWR | O_CREAT, S_IRWXU);

	if (fdOut < 0) {
		perror("Error opening file.");
		return 1;
	}

	if (write(fdOut, tempBuf, num) < 0) {
		perror("Error writing to file.");
		return 1;
	}

	close(fdIn);
	close(fdOut);
	munmap(mappedFile, fileSize);

	return num;
}
