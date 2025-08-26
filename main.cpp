#include "MBNT.h"
#include "Log.h"
#include "VersionProv.h"
#include "SSdataset_handler.h"
#include "TCdataset_handler.h"
#include <ctime>
#include <random>

int dataSetTest(){
    int totalTimestamp = 0;
    VersionProv verProvGraph = VersionProv(4, 1);
    Event e;
    auto tcHandler = TCdataset_handler((char*)"../TC/cadets.bin");
    if(tcHandler.Initialize() == -1){
        printf("opening file failed\n");
        return -1;
    }
    long start = clock();
    while(true){
        if(!tcHandler.ReadEvent(&e)) break;
        verProvGraph.AddEdge(&e, 1);
        totalTimestamp++;
    }
    long end = clock();
    printf("total stat Time: %ld", verProvGraph.estimatedTime);
    verProvGraph.Finalize();
    printf("add %ld edges within %f secs\n", verProvGraph.edges.size(),
           (end - start) * 1.0 / CLOCKS_PER_SEC);
    auto nodes = verProvGraph.nodes;
    auto edges = verProvGraph.edges;
    printf("total nodes: %ld, total node version: %ld, total edges: %ld\n",
           nodes.size(), verProvGraph.totalVersions, edges.size());
    tcHandler.Close();
    int bnid = 7300, btimeStart = 0, btimeEnd = totalTimestamp;
    SubGraph* subGraph = new SubGraph;
    GNodeProof* gProof = new GNodeProof;
    start = clock();
    auto endNodeVer = verProvGraph.BackwardTrace(bnid, btimeStart, btimeEnd,
                                                 subGraph, gProof);
    end = clock();
    printf("Duration for Backward Trace: %f\n", (end-start) * 1.0 / CLOCKS_PER_SEC);
    if(endNodeVer) {
        printf("****************Backward Trace from [%d, %d]******************\n", endNodeVer->nid, endNodeVer->vid);
        printf("****************Total Nodes: %d, Total Node Vers: %d, total edges: %d******************\n", subGraph->totalNode,
               subGraph->totalNodeVer, subGraph->totalEdges);
        start = clock();
        if (verProvGraph.VerifyBackwardProof(endNodeVer, subGraph, gProof)) {
            printf("Backward proof verified\n");
        } else {
            printf("Backward proof not verified\n");
        }
        end = clock();
        printf("Verification Time: %f\n", (end-start) * 1.0 / CLOCKS_PER_SEC);
    }
    else{
        printf( "Node %d does not exist\n", bnid);
    }
    SubGraph* subGraph_forward = new SubGraph;
    GNodeProof* gProof_forward = new GNodeProof;
    int snid = 3668, stimeStart = 0, stimeEnd = totalTimestamp;
    start = clock();
    auto startNodeVer = verProvGraph.ForwardTrace(snid, stimeStart, stimeEnd,
                                                   subGraph_forward, gProof_forward);
    end = clock();
    printf("Duration for Forward Trace: %f\n", (end-start) * 1.0 / CLOCKS_PER_SEC);
    if(startNodeVer){
        printf("****************Forward Trace from [%d, %d]******************\n", startNodeVer->nid,
               startNodeVer->vid);
        printf("****************Total Nodes: %d, Total Node Vers: %d, total edges; %d******************\n",
               subGraph_forward->totalNode, subGraph_forward->totalNodeVer, subGraph_forward->totalEdges);
        start = clock();
        if(verProvGraph.VerifyForwardProof(startNodeVer, subGraph_forward, gProof_forward)){
            printf("forward proof verified\n");
        }
        else{
            printf("forward proof not verified\n");
        }
        end = clock();
        printf("Verification Time: %f", (end-start)*1.0 / CLOCKS_PER_SEC);
    }
    delete subGraph;
    delete subGraph_forward;
    verProvGraph.FreeGraphProof(gProof);
    verProvGraph.FreeGraphProof(gProof_forward);
    return 0;
}

int main(){
    dataSetTest();
    return 0;
}