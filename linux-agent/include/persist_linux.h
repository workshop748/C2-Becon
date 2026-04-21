// linux-agent/include/persist_linux.h
#pragma once

// Persistence via crontab
int persist_crontab(const char* agent_path);

// Persistence via ~/.bashrc
int persist_bashrc(const char* agent_path);

// Persistence via systemd user unit
int persist_systemd_user(const char* agent_path);

// Remove all persistence
int persist_remove_linux(void);
