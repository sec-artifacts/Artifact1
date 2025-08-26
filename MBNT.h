
#ifndef VERIFIABLEPROVENANCE_MBNT_H
#define VERIFIABLEPROVENANCE_MBNT_H

#include <cstring>
#include <vector>
#include <map>
#include <stack>
#include <string>
#include <cmath>
#include "utils.h"


struct BntNode{
    unsigned char value[SHA256_DIGEST_LENGTH];
    BntNode *left, *right, *parent;
    int height;
    int leftTreeMax;
    int rightTreeMax;
};
struct ProofNode{
    BntNode* data;
    unsigned char pathLen;
    unsigned int path;
};
typedef struct{
   int x, y;
   int leftIndex, rightIndex;
}RQuery;
typedef struct{
    int key;
    const void* value;
    int vLen;
}RValue;
typedef int (*HashFunc)(unsigned char* output, const void* input, EVP_MD_CTX* ctx, size_t cnt);
class CBnt{
private:
    EVP_MD_CTX *sha256;
    void _queryLeft(int x, int leftMost, BntNode *root, int &leftIndex, ProofNode* proofLeft[], int &leftLen,
                        unsigned int currPath, int pathLen);
    void _queryRight(int y, int rightMost, BntNode *root, int &rightIndex, ProofNode* proofRight[], int &rightLen,
                         unsigned int currPath, int pathLen);
    BntNode* _query(int key, BntNode* root, ProofNode** proof, int &pLen,  int &index, unsigned int currPath);
    void _destroy_bnt(BntNode*);
    int BitCount2(int n);
    void _clearFinalizedTempNode();
    void _rangeQuery(int x, int leftMost, int y, int rightMost, BntNode* currRoot,
                int &leftIndex, int &rightIndex,
                ProofNode* proofLeft[], int &leftLen,
                ProofNode* proofRight[], int &rightLen,
                unsigned int currPath, int pathLen);
    void _multiRangeQuery(BntNode* currRoot, int currTreeIndex, int leftMost, int rightMost, int x[], int y[], int i, int j,
                          int leftIndex[], int rightIndex[], ProofNode** leftProof[], int leftLen[],
                          ProofNode** rightProof[], int rightLen[], bool results[], unsigned int currPath, int pathLen);
    void _multiRangeQuery(BntNode* currRoot, int currTreeIndex, int leftMost, int rightMost,
                          std::vector<RQuery>& Q, int i, int j,
                          ProofNode** leftProof[], int leftLen[],
                          ProofNode** rightProof[], int rightLen[], bool results[],
                          unsigned int currPath, int pathLen);
    void _pushMergeProofInStack(std::stack<ProofNode*> &nStack, ProofNode* currentNode);
    HashFunc hashFunc;
public:
    BntNode *root;
    bool hasFinalized;
    size_t totalNode;
    unsigned char rootHash[SHA256_DIGEST_LENGTH];
    std::vector<BntNode*> subTreeRoot;
    std::vector<BntNode*> finalizedNodes;
    std::vector<BntNode*> leaves;
    CBnt();
    template<typename HashFunc>
    CBnt(HashFunc f);
    //init multiple strings
    template<typename HashFunc>
    CBnt(std::string data[], size_t dataLen, HashFunc f);
    template<typename HashFunc>
    CBnt(unsigned char* data[], size_t item_size, size_t datalen, HashFunc f);
    template<typename HashFunc>
    CBnt(int key[], std::string data[], size_t dataLen, HashFunc f);
    template<typename HashFunc>
    CBnt(int key[], unsigned char* data[], size_t item_size, size_t datalen, HashFunc f);
    ~CBnt();
    static int StrHash(unsigned char *output, const void* input, EVP_MD_CTX* sha256, size_t input_length);
    static int MergeHash(unsigned char *output, const void * left,
                          size_t left_length,
                          const void *right,
                          size_t right_length,
                          EVP_MD_CTX* sha256);
    static int NodeHash(BntNode* node, EVP_MD_CTX* sha256, unsigned char*output);
    static int LowBit(size_t x);
    void _insert(int height, BntNode* insertSubTreeRoot, std::vector<BntNode*>* insertLeaves);
    bool InsertTree(int key, const void* v, size_t v_len);
    bool QueryAndProve(int key, ProofNode** proof, int &pLen, int &index);
    bool VerifyExist(int key, const void *v, size_t vLen, ProofNode* proof[], int plen);
    bool VerifyExist(int key, std::string v, ProofNode* proof[], int plen);
    bool VerifyNonExist(int key, ProofNode* proof[], int plen);
    BntNode* MergeChildren(BntNode*, BntNode*);
    BntNode* foldr();
    BntNode* FinalizeTree();
    ProofNode** InitializeProof();
    ProofNode*** InitializeMultiProof(int n);
    static
    void FreeMultiProof(ProofNode ***multiProof, int pLen[], int n);
    void DestroyBnt();
    BntNode* NewLeafNode(int, const void*, size_t);
    void PrintNode(BntNode*);
    size_t getHeight();
    unsigned int getNextPath(std::stack<ProofNode*> &nStack, int currPos, int &pathLen);
    static void FreeProof(ProofNode* proof[], size_t proofSize);
    static void FreeProofNode(ProofNode* proof);
    ProofNode* NewProofLeaf(int key, const void* v, size_t vLen,
                            unsigned int path, unsigned int pathLen);
    bool RangeQueryAndProve(int x, int y,
                            int &leftIndex, int &rightIndex,
                            ProofNode* proofLeft[], int &leftLen,
                            ProofNode* proofRight[], int &rightLen);

    int MultiRangeQueryAndProve(int x[], int y[], int rangeLen, int leftIndex[],
                                 int rightIndex[], ProofNode** leftProof[], int leftLen[],
                                 ProofNode** rightProof[], int rightLen[], bool results[]);
    int MultiRangeQueryAndProve(std::vector<RQuery>& Q, int rangeLen,
                                ProofNode** leftProof[], int leftLen[],
                                ProofNode** rightProof[], int rightLen[],
                                bool results[]);
    bool VerifyMultiRanges(int x[], int y[], int rangeLen, bool results[],
                           int key[], const void* value[], size_t item_size[], size_t cnt[],
                           ProofNode** proofLeft[], int leftLen[],
                           ProofNode** proofRight[], int rightLen[]);
    bool VerifyMultiRanges(int x[], int y[], int rangeLen, bool results[],
                           int key[], std::string value[], size_t cnt[],
                           ProofNode** proofLeft[], int leftLen[],
                           ProofNode** proofRight[], int rightLen[]);
    bool VerifyMultiRanges(std::vector<RQuery>& Q,
                           std::vector<std::vector<RValue>>& Value,
                           int rangeLen,
                           bool results[],
                           ProofNode** proofLeft[], int leftLen[],
                           ProofNode** proofRight[], int rightLen[]);
    bool VerifyMultiRanges(std::vector<RQuery>& Q,
                           std::vector<std::vector<RValue>>& Value,
                           int hist_rangeLen,
                           std::vector<bool> results,
                           ProofNode** proofLeft[], int leftLen[],
                           ProofNode** proofRight[], int rightLen[]);
    ProofNode* MergeProofNode(ProofNode *left, ProofNode *right);
    bool VerifyRangeExist(int x, int y,
                          int key[], const void* valueList[], size_t item_size[],
                          size_t cnt,
                          ProofNode* proofLeft[], int leftLen,
                          ProofNode* proofRight[], int rightLen);
    bool VerifyRangeExist(int x, int y,
                          int key[], std::string strList[],
                          size_t cnt,
                          ProofNode* proofLeft[], int leftLen,
                          ProofNode* proofRight[], int rightLen);
    bool VerifyRangeExist(int x, int y,
                          int key[], const void* valueList[],
                          size_t item_size, size_t cnt,
                          ProofNode* proofLeft[], int leftLen,
                          ProofNode* proofRight[], int rightLen);
    bool VerifyRangeNonExist(int x, int y, ProofNode* proofLeft[], int leftLen, ProofNode* proofRight[], int rightLen);
    void UpdateLeafNode(BntNode *node, const void * v, size_t v_len);
    bool UpdateTree(BntNode *node, const void * v, size_t v_len);
    bool UpdateTree(int key, const void * v, size_t v_len);
    bool UpdateTree(int key, std::string v);

};
template<typename HashFunc>
CBnt::CBnt(HashFunc f){
    root = nullptr;
    totalNode = 0;
    hasFinalized = false;
    sha256 = EVP_MD_CTX_new();
    SHA256_Init(sha256);
    memset(rootHash, 0, 32);
    this->hashFunc = f;
}
template<typename F>
CBnt::CBnt(std::string data[], size_t dataLen, F f) {
    root= nullptr;
    totalNode=0;
    hasFinalized = false;
    memset(rootHash, 0, 32);
    this->hashFunc = f;
    sha256 = EVP_MD_CTX_new();
    SHA256_Init(sha256);
    for(int i = 0; i < dataLen; i++) {
        this->InsertTree(i, (unsigned char*)data[i].c_str(), data[i].length());
    }
}
template<typename F>
CBnt::CBnt(unsigned char *data[], size_t item_size, size_t dataLen, F f){
    root = nullptr;
    totalNode = 0;
    hasFinalized = true;
    memset(rootHash, 0, 32);
    this->hashFunc = f;
    sha256 = EVP_MD_CTX_new();
    SHA256_Init(sha256);
    for(int i = 0; i < dataLen; i++){
        this->InsertTree(i, data[i], item_size);
    }
}
template<typename F>
CBnt::CBnt(int key[], std::string data[], size_t dataLen, F f){
    root = nullptr;
    totalNode = 0;
    hasFinalized = true;
    memset(rootHash, 0, 32);
    this->hashFunc = f;
    sha256 = EVP_MD_CTX_new();
    SHA256_Init(sha256);
    for(int i = 0; i < dataLen; i++){
        this->InsertTree(key[i], (unsigned char*)data[i].c_str(), data[i].length());
    }
}
template<typename F>
CBnt::CBnt(int key[], unsigned char* data[], size_t item_size, size_t dataLen, F f){
    root = nullptr;
    totalNode = 0;
    hasFinalized = true;
    memset(rootHash, 0, 32);
    this->hashFunc = f;
    sha256 = EVP_MD_CTX_new();
    SHA256_Init(sha256);
    for(int i = 0; i < dataLen; i++) {
        this->InsertTree(key[i], data[i], item_size);
    }
}
#endif //VERIFIABLEPROVENANCE_MBNT_H
