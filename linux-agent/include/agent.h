// linux-agent/include/agent.h
#pragma once

// Main agent run loop
void agent_run(void);

// Task dispatcher
void dispatch_task_linux(const unsigned char* data, size_t len);
