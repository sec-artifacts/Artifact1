
#ifndef VERIFIABLEPROVENANCE_TCDATASET_HANDLER_H
#define VERIFIABLEPROVENANCE_TCDATASET_HANDLER_H
#include "dataset_handler.h"

class TCdataset_handler: public DatasetHandler{
public:
    TCdataset_handler():DatasetHandler(){};
    TCdataset_handler(char name[]):DatasetHandler(name){};
    int Initialize();
    int ReadEvent(Event *e);
//    ~TCdataset_handler();
};
#endif //VERIFIABLEPROVENANCE_TCDATASET_HANDLER_H
