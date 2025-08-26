

#ifndef VERIFIABLEPROVENANCE_SSDATASET_HANDLER_H
#define VERIFIABLEPROVENANCE_SSDATASET_HANDLER_H
#include "dataset_handler.h"
#include <unordered_map>
#include <string>
#include <sstream>

class SSDatasetHandler: public DatasetHandler{
public:
    int currNID = 0;
    std::stringstream input_stream;
    std::unordered_map<int, int> IDMap;
    SSDatasetHandler():DatasetHandler(){};
    SSDatasetHandler(char name[]):DatasetHandler(name){};
    int Initialize();
    int ReadEvent(Event *e);
    ~SSDatasetHandler();
};
#endif //VERIFIABLEPROVENANCE_SSDATASET_HANDLER_H
