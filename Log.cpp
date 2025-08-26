

#include "Log.h"


int Log::init(char *fname) {
    fp = fopen(fname, "w");
    if(fp) return 1;
    else return 0;
}

void Log::write(char *l) {
    fwrite(l, 1, strlen(l), fp);
}

void Log::close() {
    if(fp) fclose(fp);
}