
#ifndef VERIFIABLEPROVENANCE_VERSIONPROV_H
#define VERIFIABLEPROVENANCE_VERSIONPROV_H
#include <vector>
#include <string>
#include <cstring>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <queue>
#include "MBNT.h"
#include "dataset_handler.h"
typedef struct NodeVer{
    struct NodeVer* prevVersion;
    struct NodeVer* nextVersion;
    int nid; //processId
    int vid; //versionId
    int timestamp;
    short inForwardChainId;
    unsigned char forwardProof[32] = {0};
    unsigned char backwardProof[32] = {0};
    int headIn;
    int headOut;
    bool history;
    unsigned char status; //0: has been synchronized in GraphMBnt;
    //1: not synchronized and newly added in GraphMBnT,
    //2: not sync and modified in GraphMBnt
}NodeVer, *NodeVerPtr;

typedef struct Edge{
    NodeVerPtr srcNodeVer;
    NodeVerPtr destNodeVer;
    int nextInEdge;  //edge ID in vector<EdgePtr> edge;
    int nextOutEdge; //edge ID in vector<EdgePtr> edge;
    char Info[10];
}Edge, *EdgePtr;

class compareNodeVerPtr
{
public:
    bool operator () (const NodeVerPtr left, const NodeVerPtr right) const
    {
        if (nullptr == left || nullptr == right) return true;
        else if(left->nid != right->nid) return (left->nid < right->nid);
        else  return left->vid < right->vid;
    }
};

class compareEdgePtr
{
public:
    bool operator () (const EdgePtr left, const EdgePtr right) const
    {
        if(nullptr == left)
            return true;
        else if(nullptr == left->destNodeVer) return true;
        else if(left->destNodeVer->timestamp != right->destNodeVer->timestamp)
            return (left->destNodeVer->timestamp < right->destNodeVer->timestamp);
        else return left->destNodeVer->nid < right->destNodeVer->nid;
    }
};

typedef struct{
    NodeVerPtr currChainHead;
    short currChainCount;
    int nid;
    //Merkle Proof Class;
    unsigned char currChainHash[32];
    CBnt *histChainTree;
}NodeTimeCommit;


typedef struct{
    NodeVerPtr node;
    unsigned char* originalHash;
}UpdatedNode;

typedef struct{
    int nid;
    struct historyProof {
        ProofNode ***proofLeft, ***proofRight;
        int *leftLen, *rightLen;
        int rangeLen;
    } HistoryProof;
    struct currChainProof{
        NodeVerPtr* currNodes;
        int currNodeLen;
    } CurrChainProof;
}NodeTimeChainProof;

class GNodeProof{
public:
    ProofNode ***proofLeft, ***proofRight;
    int *leftLen, *rightLen;
    int rangeLen;
    std::unordered_map<int, NodeTimeChainProof*> TimeChainProof;
    GNodeProof(){
        leftLen = nullptr;
        rightLen = nullptr;
        proofLeft = nullptr;
        proofRight = nullptr;
        rangeLen = 0;
    }
};

class SubGraph{
public:
    int totalNode = 0;
    int totalNodeVer = 0;
    int totalEdges = 0;
    SubGraph();
    SubGraph(int maxChainEdgeNum);
    std::unordered_map<int, std::set<NodeVerPtr, compareNodeVerPtr>> nodes;
    std::unordered_map<int, EdgePtr> edges;
    int maxChainEdgeNum;
    int currChainNodeNum;
    bool startOfChain(NodeVerPtr n);
    void PrintAllNodes();
    void PrintAllEdges();
    void clear();
    void addNode(NodeVerPtr n);
    void addEdge(int eid, EdgePtr e);
    bool containNodeVer(NodeVerPtr n);
    bool containEdge(int eid);
    NodeVerPtr GetParent(NodeVerPtr n);
    EdgePtr GetInEdge(NodeVerPtr n);
    EdgePtr GetLastOutEdge(NodeVerPtr n);
    EdgePtr nextOutEdge(EdgePtr e);
    void GetChainStartVers(int nid, std::vector<RQuery> &hist_Query, int &hist_rangeLen,
                           std::vector<std::vector<RValue>> *hist_Value,
                           NodeVerPtr curr_chainStart[],
                           int& curr_nodeLen);
    void GetNodeRangeQuery(std::vector<int>& Nids,
                           std::vector<RQuery> &node_Query,
                           int &rangeLen,
                           std::vector<std::vector<RValue>>* node_Value);
    ~SubGraph();
};
class VersionProv {
private:
    EVP_MD_CTX* sha256;
    int reservedCurrVersions;
    int maxChainEdgeNum;
    FILE* flog = nullptr;
    NodeVerPtr addNewNodeVersion(int timestamp, int nid);
    EdgePtr addNewEdge(NodeVerPtr srcNode, NodeVerPtr destNode, char* info);
    void _forward_dfs(NodeVerPtr node, SubGraph* graph);
    void _backward_dfs(NodeVerPtr node, SubGraph *subGraph);
    void _BackPropaVerHash(NodeVerPtr newNode, unsigned char* originalHash, bool originalEndChain=false);
    void _BackPropaNodeHash(EdgePtr e, unsigned char* oldAdjHash, bool originalEndChain=false);
    void BackPropaNodeVerHash(NodeVerPtr currNode, unsigned char* oldNodeVerHash, bool originalEndChain=false);
    void TruncateTimeChain(NodeVerPtr currNode, unsigned char* originalHash);
    bool _verifyForwardNodeProof(NodeVerPtr currNodeVer,
                                 std::unordered_set<NodeVerPtr> &verifiedNodes,
                                 SubGraph *subGraph, std::queue<NodeVerPtr> &chainStartQueue);
//    bool _verifyForwardNodeProof_BFS(NodeVerPtr startNodeVer,
//                                     std::unordered_set<NodeVerPtr> &verifiedNodes,
//                                     SubGraph *subGraph, std::queue<NodeVerPtr> &chainStartQueue);
    bool _verifyBackwardNodeProof(NodeVerPtr currNodeVer,
                                  std::unordered_set<NodeVerPtr> &verifiedNodes,
                                  SubGraph *subGraph,
                                  std::queue<NodeVerPtr> &nextNodes);
    static int TimeChainHash(unsigned char *output, const void* nT, EVP_MD_CTX* sha256, size_t cnt=1);
    static int SingleNodeVerHash(unsigned char *output, const void* node, EVP_MD_CTX* sha256, size_t cnt=1);
    static bool NodeVerHash(NodeVerPtr node, unsigned char* output, EVP_MD_CTX* sha256, int flag = 0);
public:
    size_t estimatedTime = 0;
    size_t totalVersions;
    std::vector<NodeVerPtr> nodes;
    std::vector<NodeTimeCommit*> nodeTimeCommits;
    std::vector<EdgePtr> edges;
    std::queue<UpdatedNode> updatedNodes;
    CBnt* graphMBNT;
    VersionProv();
    VersionProv(int maxChainEdgeNum, int reservedCurrVersions);
    VersionProv(int maxNodeNum, int maxEdgeNum, int maxChainEdgeNum, int reservedCurrVersions);
    ~VersionProv();
    bool AdjEdgeHash(EdgePtr edge, unsigned char* output, int direction = 0);
    bool AdjEdgeHash(char* edgeInfo, unsigned char *adjNodeHash, unsigned char* output);
    bool AddEdge(Event *e, int stat = 1);
    bool AddEdge(int sourceNid, int destNid, int timestamp, char* eInfo, int infoLen, int stat = 1);
//    void BackwardTrace(int nid, int startTime, int endTime, std::vector<EdgePtr>& resultEdges);
    NodeVerPtr ForwardTrace(int nid, int startTime, int endTime,
                            SubGraph* graph,
                            GNodeProof* gNodeProof);
    NodeVerPtr BackwardTrace(int nid, int startTime, int endTime,
                             SubGraph *subGraph, GNodeProof* gNodeProof);
    void GetSons(NodeVerPtr node, std::unordered_set<NodeVerPtr> &sons);
    NodeVerPtr GetParent(NodeVerPtr node);
    NodeVerPtr GetPrevVer(NodeVerPtr node);
    void PrintNodeVer(NodeVerPtr node);
    void PrintAllNodeVers(int nid);
    void PrintNodeTimeCommitment(NodeTimeCommit* n);
    bool VerifyBackwardProof(NodeVerPtr endNodeVer, SubGraph *subGraph, GNodeProof* gProof);
    bool VerifyForwardProof(NodeVerPtr startNodeVer, SubGraph *subGraph, GNodeProof* GProof);
    bool VerifyChainStartNodes(SubGraph *subGraph,
                               GNodeProof* GProof,
                               std::unordered_set<NodeVerPtr>* verifyNodes);
    void Finalize();
    void GetChainStartForwardProof(SubGraph* subGraph, GNodeProof* GProof);
    void FreeGraphProof(GNodeProof* gProof);
};
void testProvGraph();
void testProvGraph1();

#endif //VERIFIABLEPROVENANCE_VERSIONPROV_H
