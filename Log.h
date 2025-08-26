
#ifndef VERIFIABLEPROVENANCE_LOG_H
#define VERIFIABLEPROVENANCE_LOG_H
#include <iostream>
#include <cstring>

class Log {
private:
    FILE* fp = nullptr;
public:
    Log(){};
    int init(char[]);
    void write(char[]);
    void close();
};


#endif //VERIFIABLEPROVENANCE_LOG_H
