
#include "SSdataset_handler.h"
#include <cstring>


int SSDatasetHandler::Initialize() {
    if(DatasetHandler::Initialize() == -1) return -1;
    std::string colTitle;
//    fp->getline(colTitle, 100);

    input_stream << fp->rdbuf();

    getline(input_stream, colTitle);
//    printf("title: %s", colTitle);
    return 0;
}
SSDatasetHandler::~SSDatasetHandler(){
    input_stream.clear();
    IDMap.clear();
}
int SSDatasetHandler::ReadEvent(Event *e){
    int itemID, srcID, dstID;
    char srcType[20], dstType[20];
    char info[100];
    if(!input_stream.getline(info, 100)) return 0;
    sscanf(info, "%d,%d,%[^','],%d,%[^','],%[^',']",
           &itemID, &srcID,
           srcType, &dstID,
           dstType, e->einfo);
    if(IDMap.find(srcID) == IDMap.end()){
        IDMap[srcID] = currNID;
        srcID = currNID;
        currNID++;
    }
    else {
        srcID = IDMap[srcID];
    }
    if(IDMap.find(dstID) == IDMap.end()){
        IDMap[dstID] = currNID;
        dstID = currNID;
        currNID++;
    }
    else {
        dstID = IDMap[dstID];
    }
    e->srcID = srcID;
    e->dstID = dstID;
    e->timestamp = timestamp;
//    strncpy(e->einfo, edgeType, 10);
    timestamp++;
    return 1;
}