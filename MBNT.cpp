
#include "MBNT.h"
#include <set>

CBnt::CBnt(){
    root = nullptr;
    totalNode=0;
    this->hashFunc=StrHash;
    memset(rootHash, 0, 32);
    sha256 = EVP_MD_CTX_new();
    SHA256_Init(sha256);
}
CBnt::~CBnt(){
    EVP_MD_CTX_free(sha256);
    DestroyBnt();
}
int CBnt::StrHash(unsigned char *output, const void* input, EVP_MD_CTX* sha256, size_t input_length) {
//    EVP_MD_CTX* sha256;
//    sha256 = SHA256_Init();
    if(sha256 == nullptr) return -1;
    if(SHA256_Update1(sha256, input, input_length)!=0)return -1;
    if(SHA256_Final(output, sha256)!=0)return -1;
    return 0;
}
int CBnt::NodeHash(BntNode* node, EVP_MD_CTX* sha256, unsigned char*output){
    memset(output, 0, 32);
    if(node == nullptr){
        return 0;
    }
//    EVP_MD_CTX* sha256;
//    sha256 = SHA256_Init();
    if(sha256 == nullptr) return -1;
    if(SHA256_Update1(sha256, node->value, SHA256_DIGEST_LENGTH)!=0) return -1;
    if(SHA256_Update1(sha256, (unsigned char*)&node->leftTreeMax, 4)!=0)return -1;
    if(SHA256_Update1(sha256, (unsigned char*)&node->rightTreeMax, 4)!=0)return -1;
    if(SHA256_Final(output, sha256)!=0)return -1;
    return 0;
}
int CBnt::MergeHash( unsigned char *output, const void * left, size_t left_length,
                     const void *right, size_t right_length, EVP_MD_CTX* sha256) {
//    EVP_MD_CTX* sha256;
//    sha256 = SHA256_Init();
    if(SHA256_Update1(sha256, left, left_length)!=0) return -1;
    if(SHA256_Update1(sha256, right, right_length)!=0) return -1;
    if(SHA256_Final(output, sha256) !=0) return -1;
    return 0;
}

int CBnt::LowBit(size_t x) {
    return x & (-x);
}
BntNode* CBnt::foldr() {
    size_t nLen = subTreeRoot.size();
    if(nLen == 0){
        return nullptr;
    }
    if((nLen & (nLen - 1)) == 0){
        return subTreeRoot[nLen - 1];
    }
    BntNode* vRoot = subTreeRoot[nLen - 1];
    size_t remainShape = nLen - LowBit(nLen);
    while(remainShape>0){
        vRoot = MergeChildren(subTreeRoot[remainShape-1], vRoot);
        totalNode++;
        finalizedNodes.push_back(vRoot);
        remainShape -= LowBit(remainShape);
    }
    return vRoot;
}
BntNode *CBnt::FinalizeTree() {
    _clearFinalizedTempNode();
    root = foldr();
    NodeHash(root, sha256, rootHash);
    hasFinalized = true;
    return root;
}
void CBnt::_destroy_bnt(BntNode* root){
    if(root == nullptr) return;
    _destroy_bnt(root->left);
    _destroy_bnt(root->right);
    delete root;
}

void CBnt::DestroyBnt() {
    _destroy_bnt(root);
}
BntNode* CBnt::_query(int key, BntNode* currRoot, ProofNode** proof, int &pLen, int &index,  unsigned int currPath){
    if(key <= currRoot->leftTreeMax){
        if(currRoot->right != nullptr){
            proof[pLen] = new ProofNode;
            proof[pLen]->data = currRoot->right;
            proof[pLen]->path = (currPath << 1) | 1;
            proof[pLen]->pathLen = pLen + 1;
            pLen++;
        }
        if(currRoot->left == nullptr) {
            return currRoot;
        }
        else {
            currPath = (currPath << 1) | 0;
            return _query(key, currRoot->left, proof, pLen,  index, currPath);
        }
    }
    else if(key <= currRoot->rightTreeMax){
        if(currRoot->left != nullptr){
            proof[pLen] = new ProofNode;
            proof[pLen]->data = currRoot->left;
            proof[pLen]->path = (currPath << 1) | 0;
            proof[pLen]->pathLen = pLen + 1;
            pLen++;
        }
        if(currRoot->right == nullptr) {
            return currRoot;
        }
        else {
            currPath = (currPath << 1) | 1;
            index += (1 << (currRoot->height - 2));
//            index += (1 << (root->height - 2));
            return _query(key, currRoot->right, proof, pLen, index, currPath);
        }
    }
    else{
        return currRoot;
    }
}
size_t CBnt::getHeight(){
    size_t nLen = leaves.size();
    if(nLen == 0) return 0;
    if(nLen == 1)
        return 1;
    double bitLen = log2((double)nLen - 1);
    return size_t(bitLen + 2);
}
BntNode* CBnt::MergeChildren(BntNode *left, BntNode *right){
    auto newRoot = new BntNode;
    int leftTreeMax = left->rightTreeMax;
    int rightTreeMax = right->rightTreeMax;
    MergeHash(newRoot->value, left->value, SHA256_DIGEST_LENGTH, right->value, SHA256_DIGEST_LENGTH, sha256);
    newRoot->leftTreeMax = leftTreeMax;
    newRoot->rightTreeMax = rightTreeMax;
    newRoot->left = left;
    newRoot->right = right;
    newRoot->parent = nullptr;
    newRoot->height = (int) fmax(left->height, right->height) + 1;
    left->parent = newRoot;
    right->parent = newRoot;
    return newRoot;
}
void CBnt::_insert(int height, BntNode *insertSubTreeRoot, std::vector<BntNode*> *insertLeaves) {
    size_t add = 1 << height; //typically 1
    size_t nLen = subTreeRoot.size();
    size_t mergeEndPoint = (nLen + add) & nLen;
    size_t remainMergeShape = nLen;
    auto vRoot = insertSubTreeRoot;
    while(remainMergeShape > mergeEndPoint){
        BntNode* mergedRoot = subTreeRoot[remainMergeShape - 1];
        vRoot = MergeChildren(mergedRoot, vRoot);
        totalNode++;
        remainMergeShape -= LowBit(remainMergeShape);
    }
    totalNode += add;
    subTreeRoot.push_back(vRoot);
    if(height != 0) {
        for(int i = 0; i < (*insertLeaves).size(); i++) {
            leaves.push_back((*insertLeaves)[i]);
        }
    }
    else{
        leaves.push_back(insertSubTreeRoot);
    }
    hasFinalized = false;
}
BntNode* CBnt::NewLeafNode(int key, const void* v, size_t v_len){
    if(v_len > SHA256_DIGEST_LENGTH) return nullptr;
    auto newNode = new BntNode;
    newNode->leftTreeMax = key;
    newNode->rightTreeMax = key;
    newNode->left = nullptr;
    newNode->right = nullptr;
    newNode->parent = nullptr;
    newNode->height = 1;
    hashFunc(newNode->value, v, sha256, v_len);
    return newNode;
}
ProofNode* CBnt::NewProofLeaf(int key, const void* v, size_t vLen, unsigned int path, unsigned int pathLen){
    auto pNode = new ProofNode;
    pNode->data = new BntNode;
    pNode->data->leftTreeMax = key;
    pNode->data->rightTreeMax = key;
    pNode->data->right = nullptr;
    pNode->data->left = nullptr;
    pNode->data->height = -1;
    hashFunc(pNode->data->value, v, sha256, vLen);
    pNode->path = path;
    pNode->pathLen = (unsigned char) pathLen;
    return pNode;
}
void CBnt::UpdateLeafNode(BntNode *node, const void* v, size_t v_len){
    if(v_len > SHA256_DIGEST_LENGTH) return;
    hashFunc(node->value, v, sha256, v_len);
}
bool CBnt::InsertTree(int k, const void *v, size_t v_len) {
    if(leaves.size() > 0 && leaves.back()->rightTreeMax > k){
        printf("inserted key is not incremental\n");
        return false;
    }
    BntNode * newLeaf = NewLeafNode(k, v, v_len);
    std::vector<BntNode*> newLeaves = {newLeaf};
    int maxKey = INT32_MIN;
    if(!leaves.empty()){
        maxKey = leaves.back()->rightTreeMax;
    }
    if(k < maxKey){
        printf("[Error Insertion] Not incremental key!");
        return false;
    }
    this->_insert(0, newLeaf, &newLeaves);
    return true;
}


bool CBnt::VerifyExist(int key, const void* value, size_t vLen, ProofNode* proof[], int plen){
    if(plen < 1){
        return false;
    }
    unsigned int startPath = proof[plen - 1]->path;
    startPath = (startPath ^ 1);
    auto currentNode = NewProofLeaf(key, value, vLen, startPath, proof[plen-1]->pathLen);
    ProofNode* newNode;
    for(int i= (int)plen - 1; i >= 0; i--){
        if(proof[i]->path & 1)
            newNode = MergeProofNode(currentNode, proof[i]);
        else
            newNode = MergeProofNode(proof[i], currentNode);
        FreeProofNode(currentNode);
        currentNode = newNode;
        if(currentNode == nullptr) {
            return false;
        }
    }
    unsigned char newRootHash[SHA256_DIGEST_LENGTH];
    NodeHash(currentNode->data, sha256, newRootHash);
    bool result = false;
    if(memcmp(newRootHash, rootHash, SHA256_DIGEST_LENGTH) == 0){
        result = true;
    }
    FreeProofNode(currentNode);
    return result;
}
bool CBnt::VerifyExist(int key, std::string v, ProofNode* proof[], int plen){
    return VerifyExist(key, (unsigned char*) v.c_str(), v.length(), proof, plen);
}
bool CBnt::QueryAndProve(int key, ProofNode** proof, int &pLen, int &index) {
    pLen = 0;
    size_t nLen = subTreeRoot.size();
    index = 0;
    BntNode *qNode = _query(key, root, proof, pLen, index, 0);
    if(qNode->leftTreeMax == qNode->rightTreeMax && qNode->leftTreeMax == key){
//        proof[pLen].data = qNode;
        return true;
    }
    else{
        proof[pLen] = new ProofNode;
        proof[pLen]->data = qNode;
        proof[pLen]->path = index;
        proof[pLen++]->pathLen = pLen;
        return false;
    }
}
void CBnt::PrintNode(BntNode* node){
    printFormatHash("(leftM: %d, rightM:%d, value: %H)", node->leftTreeMax, node->rightTreeMax, node->value);
}
bool CBnt::VerifyNonExist(int key, ProofNode* proof[], int plen) {
    auto leafNode = proof[plen-1]->data;
    if(plen < 1) return false;
    if(leafNode->leftTreeMax == leafNode->rightTreeMax && leafNode->leftTreeMax == key){
        //exactly match
        return false;
    }
    auto currentNode = new ProofNode;
    memcpy(currentNode, proof[plen-1], sizeof(ProofNode));
    ProofNode* newNode;
    for(int i = (int)plen-2; i >= 0; i--){
        if(proof[i]->path & 1){
            newNode = MergeProofNode(currentNode, proof[i]);
        }
        else{
            newNode = MergeProofNode(proof[i], currentNode);
        }
        FreeProofNode(currentNode);
        currentNode = newNode;
        if(currentNode == nullptr){
            return false;
        }
    }
    unsigned char newRootHash[SHA256_DIGEST_LENGTH];
    NodeHash(currentNode->data, sha256, newRootHash);
    bool result = false;
    if(memcmp(newRootHash, rootHash, SHA256_DIGEST_LENGTH) == 0){
        result = true;
    }
    FreeProofNode(currentNode);
    return result;
}
ProofNode** CBnt::InitializeProof(){
    size_t height = this->getHeight();
    auto proof = new ProofNode*[height];
    for(int i = 0; i < height; i++){
        proof[i] = nullptr;
    }
    return proof;
}
ProofNode*** CBnt::InitializeMultiProof(int n){
    size_t height = this->getHeight();
    auto multiProof = new ProofNode**[n];
    for(int i = 0; i < n; i++){
        multiProof[i] = new ProofNode*[height];
        for(int j = 0; j < height; j++){
            multiProof[i][j] = nullptr;
        }
    }
    return multiProof;
}

void CBnt::FreeProof(ProofNode **proof, size_t pLen) {
    for(int i = 0; i < pLen; i++){
        FreeProofNode(proof[i]);
    }
    delete[] proof;
}
void CBnt::FreeMultiProof(ProofNode ***multiProof, int pLen[], int n) {
    if(multiProof == nullptr) return;
    if(pLen == nullptr) return;
    for(int i = 0; i < n; i++) {
        for (int j = 0; j < pLen[i]; j++) {
            FreeProofNode(multiProof[i][j]);
        }
        delete[] multiProof[i];
    }
    delete[] multiProof;
}
ProofNode* CBnt::MergeProofNode(ProofNode *left, ProofNode *right){
    if(left->pathLen != right->pathLen){
        return nullptr;
    }
    if(left->pathLen <= 0){
        return nullptr;
    }
    unsigned int leftPath = left->path;
    unsigned int rightPath = right->path;
    if(((leftPath ^ rightPath) & 1) != 1){
        return nullptr;
    }
    auto newProofNode = new ProofNode;
    newProofNode->path = leftPath >> 1;
    newProofNode->pathLen = left->pathLen - 1;
    auto newRoot = new BntNode;
    int leftTreeMax = left->data->rightTreeMax;
    int rightTreeMax = right->data->rightTreeMax;
    MergeHash(newRoot->value, left->data->value, SHA256_DIGEST_LENGTH,
              right->data->value, SHA256_DIGEST_LENGTH, sha256);
    newRoot->leftTreeMax = leftTreeMax;
    newRoot->rightTreeMax = rightTreeMax;
    newRoot->left = nullptr;
    newRoot->right = nullptr;
    newRoot->parent = nullptr;
    newRoot->height = -(int)fmax(abs(left->data->height), abs(right->data->height)) - 1;
    //minus -> not in tree
    newProofNode->data = newRoot;
    return newProofNode;
}
void CBnt::FreeProofNode(ProofNode *proofNode){
    if(proofNode == nullptr) return;
    if(proofNode->data != nullptr && proofNode->data->height < 0) delete proofNode->data;
    delete proofNode;
}
void CBnt::_clearFinalizedTempNode() {
    for(auto & finalizedNode : finalizedNodes){
        delete finalizedNode;
    }
    finalizedNodes.clear();
}
int CBnt::BitCount2(int n)
{
    int c =0 ;
    for (c =0; n; ++c)
    {
        n &= (n -1) ; // clear 1 at the lowest bit.
    }
    return c;
}
bool CBnt::UpdateTree(BntNode *node, const void * v, size_t v_len){
    UpdateLeafNode(node, v, v_len);
    auto curr = node;
    auto parent = node->parent;
    while(parent != nullptr){
        if(parent->left == curr){
            MergeHash(parent->value, curr->value, SHA256_DIGEST_LENGTH,
                      parent->right->value, SHA256_DIGEST_LENGTH, sha256);
        }
        else if(parent->right == curr){
            MergeHash(parent->value, parent->left->value, SHA256_DIGEST_LENGTH,
                      curr->value, SHA256_DIGEST_LENGTH, sha256);
        }
        else{
            return false;
        }
        curr = parent;
        parent = parent->parent;
    }
    if(curr != root){
        return false;
    }
    NodeHash(root, sha256, rootHash);
    return true;
}
bool CBnt::UpdateTree(int key, const void* v, size_t v_len){
    ProofNode** proof = InitializeProof();
    int leafIndex = 0;
    int plen = 0;
    if(!QueryAndProve(key, proof, plen, leafIndex)){
        printf("no value for the key %d", key);
        return false;
    }
    UpdateLeafNode(leaves[leafIndex], v, v_len);
    auto curr = leaves[leafIndex];
    auto parent = leaves[leafIndex]->parent;
    while(parent != nullptr){
        if(parent->left == curr){
            MergeHash(parent->value, curr->value, SHA256_DIGEST_LENGTH,
                      parent->right->value, SHA256_DIGEST_LENGTH, sha256);
        }
        else if(parent->right == curr){
            MergeHash(parent->value, parent->left->value, SHA256_DIGEST_LENGTH,
                      curr->value, SHA256_DIGEST_LENGTH, sha256);
        }
        else{
            return false;
        }
        curr = parent;
        parent = parent->parent;
    }
    if(curr != root){
        return false;
    }
    NodeHash(root, sha256, rootHash);
    FreeProof(proof, plen);
    return true;
}
bool CBnt::UpdateTree(int key, std::string v){
    return this->UpdateTree(key, (unsigned char*)v.c_str(), v.length());
}
void CBnt::_pushMergeProofInStack(std::stack<ProofNode*> &nStack, ProofNode* currentNode){
    if(currentNode == nullptr) return;
    while((!nStack.empty() && nStack.top()->pathLen == currentNode->pathLen &&
           ((currentNode->path ^ nStack.top()->path) & 1) == 1
           && currentNode->pathLen >= 0)) {
        auto sTop = nStack.top();
        auto newNode = MergeProofNode(sTop, currentNode);
        if(currentNode->data->height < 0) {
            FreeProofNode(currentNode);
        }
        if(sTop->data->height < 0) {
            FreeProofNode(sTop);
        }
        nStack.pop();
        currentNode = newNode;
        if(currentNode == nullptr){
            break;
        }
    }
    if(currentNode == nullptr){
        return;
    }
    nStack.push(currentNode);
}

unsigned int CBnt::getNextPath(std::stack<ProofNode*> &nStack, int currPos, int &pathLen){
    if(nStack.empty()){
        pathLen = (int) getHeight() - 1;
        return 0;
    }
    int path = 0;
    pathLen = 0;
    int maxHeight = (int) getHeight();
    if(!nStack.empty()) {
        path = ((int) nStack.top()->path | 1);
        pathLen = nStack.top()->pathLen;
        maxHeight = abs(nStack.top()->data->height);
    }
    if(currPos >= leaves.size()) return path;
    if(maxHeight <= 1) return currPos;
    if((currPos + (1 << (maxHeight - 1))) <= leaves.size()){
        pathLen += maxHeight - 1;
        return currPos;
    }
    int t = leaves.size() - currPos;
    int subHeight = -1;
    if(t == 1){
        subHeight =  1;
    }
    else {
        subHeight = (int) log2((double) t - 1) + 2;
    }
    pathLen += subHeight - 1;
    path = path << (subHeight - 1);
    return path;
}