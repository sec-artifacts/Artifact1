

#include "TCdataset_handler.h"

int TCdataset_handler::Initialize() {
    timestamp = 0;
    fp = new std::ifstream(datasetFile,std::ios::binary|std::ios::in);
    if(fp->fail()) {
        delete fp;
        fp = NULL;
        return -1;
    }
    return 0;
}
int TCdataset_handler::ReadEvent(Event *e){
    if(!fp->read((char*)e, sizeof(Event))) return 0;
    return 1;
}