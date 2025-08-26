#include "dataset_handler.h"
#include <cstring>

DatasetHandler::DatasetHandler() {
    fp = NULL;
    timestamp = 0;
    memset(datasetFile, 0, 50);
}
DatasetHandler::DatasetHandler(char fname[]) {
    fp = NULL;
    timestamp = 0;
    strcpy(datasetFile, fname);
}
int DatasetHandler::Initialize() {
    timestamp = 0;
    fp = new std::ifstream(datasetFile, std::ios::in);
    if(fp->fail()) {
        delete fp;
        fp = NULL;
        return -1;
    }
    return 0;
}
void DatasetHandler::Close() {
    if(fp != NULL) {
        fp->close();
        delete fp;
    }
}