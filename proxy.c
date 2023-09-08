#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include "proxy.h"

typedef struct {
    char *data;
    size_t size;
} MemoryStruct;

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    MemoryStruct *data = (MemoryStruct *)userdata;
    char *ptr_new = realloc(data->data, data->size + realsize + 1);

    if(ptr_new == NULL) {
        fprintf(stderr, "Failed to allocate memory for response data.\n");
        return 0; // return 0 to signal an error
    }

    data->data = ptr_new;
    memcpy(&(data->data[data->size]), ptr, realsize);
    data->size += realsize;
    data->data[data->size] = '\0';
    return realsize;
}

static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    size_t real_size = size * nitems;
    MemoryStruct *mem = (MemoryStruct *)userdata;
    char *ptr = realloc(mem->data, mem->size + real_size + 1);
    if(!ptr) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), buffer, real_size);
    mem->size += real_size;
    mem->data[mem->size] = 0; // Null-terminate
    return real_size;
}

static size_t null_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    return size * nmemb; // Discard data and return the amount processed
}

int is_open_proxy(char *target) {
    CURL *curl;
    CURLcode res;
    int result = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://www.example.com");
        curl_easy_setopt(curl, CURLOPT_PROXY, target);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, null_write_callback);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        res = curl_easy_perform(curl);
        if(res == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            
            if(response_code == 200) {
                result = 1; // Proxy is open
            }
        }

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return result;
}

void proxy_scan(char *target) {
    printf("Scanning proxy server %s...\n", target);
    
    if(is_open_proxy(target)) {
        printf("%s appears to be an open proxy.\n", target);
    } else {
        printf("%s does not appear to be an open proxy.\n", target);
    }

    check_misconfigured_headers(target);
    check_error_messages(target);
}

void check_misconfigured_headers(char *target) {
    CURL *curl;
    CURLcode res;
    MemoryStruct chunk = {.data = NULL, .size = 0};

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, target);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &chunk);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            // Examples of checks:
            if(!strstr(chunk.data, "Strict-Transport-Security")) {
                printf("Missing Strict-Transport-Security header!\n");
            }
            if(!strstr(chunk.data, "X-Frame-Options")) {
                printf("Missing X-Frame-Options header!\n");
            }
            // ... add more checks as needed
        }

        curl_easy_cleanup(curl);
        free(chunk.data);
    }

    curl_global_cleanup();
}

void check_error_messages(char *target) {
    CURL *curl;
    CURLcode res;
    MemoryStruct chunk = {.data = NULL, .size = 0};

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, target);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            const char* patterns[] = {
                "SQL syntax;", 
                "Unexpected error occurred", 
                "has encountered a problem", 
            };

            for(size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); ++i) {
                if(strstr(chunk.data, patterns[i])) {
                    printf("Potential error message found: '%s'\n", patterns[i]);
                }
            }
        }

        curl_easy_cleanup(curl);
        free(chunk.data);
    }

    curl_global_cleanup();
}
