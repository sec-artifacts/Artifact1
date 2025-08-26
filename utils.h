

#ifndef VERIFIABLEPROVENANCE_UTILS_H
#define VERIFIABLEPROVENANCE_UTILS_H
#include <openssl/evp.h>
#include <emmintrin.h>
#include <stdarg.h>

#define SHA256_DIGEST_LENGTH 32

void xor_32bytes(const unsigned char *data1, const unsigned char *data2, unsigned char *result);
void printFormatHash(const char *format, ...);
int SHA256_Init(EVP_MD_CTX* ctx);
int SHA256_Update1(EVP_MD_CTX *ctx, const void* data, size_t length);
int SHA256_Final(unsigned char* outHash, EVP_MD_CTX *ctx);
void printHash(unsigned char* hash);
int StrHash(unsigned char *output, const void* input, EVP_MD_CTX* sha256, size_t input_length);
//int MultiStrHash(int count, ...);
int MultiStrHash(const void*input1, int len1, const void* input2, int len2, EVP_MD_CTX* sha256, unsigned char output[]);
void AddHash(unsigned char* input1, unsigned char* input2, unsigned char* output);
void UpdateSumHash(unsigned char* sumHash, unsigned char* originalEleHash, unsigned char* modifiedEleHash,
                   unsigned char* output);
#endif //VERIFIABLEPROVENANCE_UTILS_H
