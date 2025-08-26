
#ifndef VERIFIABLEPROVENANCE_UTILS_CPP
#define VERIFIABLEPROVENANCE_UTILS_CPP
#include "utils.h"

#define SHA256_DIGEST_LENGTH 32

void xor_32bytes(const unsigned char *data1, const unsigned char *data2, unsigned char *result){
    // LOAD THE FIRST 16 BYTES INTO 128-BIT REGISTERS
    __m128i part1_data1 = _mm_loadu_si128((__m128i*)data1);
    __m128i part1_data2 = _mm_loadu_si128((__m128i*)data2);
    __m128i part1_result = _mm_xor_si128(part1_data1, part1_data2);

    // LOAD THE LAST 16 BYTES INTO 128-BIT REGISTERS
    __m128i part2_data1 = _mm_loadu_si128((__m128i*)(data1 + 16));
    __m128i part2_data2 = _mm_loadu_si128((__m128i*)(data2 + 16));
    __m128i part2_result = _mm_xor_si128(part2_data1, part2_data2);

    // STORE THE RESULT
    _mm_storeu_si128((__m128i*)result, part1_result);
    _mm_storeu_si128((__m128i*)(result + 16), part2_result);
}

void printFormatHash(const char *format, ...) {
    va_list args;
    va_start(args, format);

    while (*format != '\0') {
        if (*format == '%') {
            format++;
            if (*format == 'd') {
                int value = va_arg(args, int);
                printf("%d", value);
            } else if (*format == 'f') {
                double value = va_arg(args, double);
                printf("%f", value);
            } else if (*format == 's') {
                char* value = va_arg(args, char*);
                printf("%s", value);
            } else if (*format == 'c') {
                int value = va_arg(args, int);
                printf("%c", value);
            } else if(*format == 'H') {
                unsigned char *hash = va_arg(args, unsigned char*);
                for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                    printf("%02x", hash[i]);
                }
            }
            else {
                printf("Unsupported format specifier: %c", *format);
            }
        }
        else {
            printf("%c", *format);
        }
        format++; 
    }
    va_end(args);
}
int SHA256_Init(EVP_MD_CTX* ctx){
//    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    return 0;
}

int SHA256_Update1(EVP_MD_CTX *ctx, const void* data, size_t length){
    if(EVP_DigestUpdate(ctx, data,length) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    return 0;
}

int SHA256_Final(unsigned char* outHash, EVP_MD_CTX *ctx){
    if(EVP_DigestFinal_ex(ctx, outHash, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_DigestInit_ex(ctx, nullptr, nullptr);
    return 0;
}
void printHash(unsigned char* hash) {
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
}
int StrHash(unsigned char *output, const void* input, EVP_MD_CTX* sha256, size_t input_length) {
//    EVP_MD_CTX* sha256;
//    sha256 = SHA256_Init();
    if(sha256 == nullptr) return -1;
    if(SHA256_Update1(sha256, input, input_length)!=0)return -1;
    if(SHA256_Final(output, sha256)!=0)return -1;
    return 0;
}
int MultiStrHash(const void* input1, int len1, const void*input2, int len2, EVP_MD_CTX* sha256, unsigned char *output){
//    EVP_MD_CTX* sha256;
//    sha256 = SHA256_Init();
    if(sha256 == nullptr) return -1;
    if(SHA256_Update1(sha256, input1, len1)!=0)return -1;
    if(SHA256_Update1(sha256, input2, len2)!=0)return -1;
    if(SHA256_Final(output, sha256)!=0) return -1;
    return 0;
}
void AddHash(unsigned char* input1, unsigned char* input2, unsigned char* output){
    xor_32bytes(input1, input2, output);
}
void UpdateSumHash(unsigned char* sumHash, unsigned char* originalEleHash,
                   unsigned char* modifiedEleHash, unsigned char* output){
    xor_32bytes(sumHash, originalEleHash, output);
    xor_32bytes(output, modifiedEleHash, output);
}
#endif //VERIFIABLEPROVENANCE_UTILS_CPP
