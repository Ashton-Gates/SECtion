#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H
#include <stddef.h>


struct MemoryStruct {
  char *memory;
  size_t size;
};

size_t write_callback(char *data, size_t size, size_t nmemb, void *userp);

#endif
