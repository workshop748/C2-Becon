# AIC2S Beacon — Data Flow Diagrams

## Level 0 DFD — Beacon Context Diagram

The beacon as a single process interacting with external entities.

```mermaid
flowchart LR
    subgraph External["External Entities"]
        TargetHost([Target Host<br/>Windows 10 VM<br/>192.168.1.178])
        C2Server[(C2 Server<br/>192.168.1.69:8443<br/>TLS 1.2)]
        AVEDR([AV / EDR<br/>Defender, NTDLL,<br/>AMSI, ETW])
        ConfigStore([Config Store<br/>config.h /<br/>config.local.h])
    end

    Beacon[[AIC2S Beacon<br/>beacon.exe / beacon.dll]]

    TargetHost -->|Windows APIs:<br/>OS version, hostname,<br/>IP, ports, services,<br/>CPUID, PEB| Beacon
    Beacon -->|Encrypted Recon JSON<br/>+ Task Results<br/>AES-256-CBC in TLS| C2Server
    C2Server -->|Encrypted Task Commands<br/>whoami, shell,<br/>grab_creds, screenshot| Beacon
    Beacon -->|Patch / Unhook:<br/>NTDLL .text overwrite,<br/>AMSI prologue patch,<br/>ETW prologue patch| AVEDR
    ConfigStore -->|Build-time params:<br/>host, port, keys,<br/>sleep, jitter| Beacon
    Beacon -->|Read/Write:<br/>Registry Run keys,<br/>COM CLSID hijack| TargetHost
    Beacon -->|Read:<br/>Chrome LoginData,<br/>Local State,<br/>GDI framebuffer| TargetHost
```

---

## Level 1 DFD — Internal Module Data Flow

Decomposition of the beacon process into modules showing the check-in cycle.

```mermaid
flowchart TB
    subgraph Init["Initialization Phase"]
        direction TB
        E1[evasion.c<br/>NTDLL Unhook] --> E2[evasion.c<br/>AMSI Patch]
        E2 --> E3[evasion.c<br/>ETW Patch]
        E3 --> AA[anti_analysis.c<br/>VM + Debugger Check]
        AA -->|flags: is_vm,<br/>is_debugged| WL
        WL[comms.c<br/>IP Whitelist Gate]
    end

    subgraph CheckIn["Check-In Cycle"]
        direction TB
        CC[comms.c<br/>checking_connection<br/>HTTPS GET] -->|HTTP 200 OK| RC
        RC[recon.c<br/>recon_collect<br/>Windows APIs] -->|CHECKIN_INFO<br/>struct| RS
        RS[recon.c<br/>recon_serialize<br/>JSON output] -->|880 B JSON<br/>AgentFindings| ENC
        ENC[crypto.c<br/>aes_encrypt_payload<br/>AES-256-CBC BCrypt] -->|896 B<br/>ciphertext| POST
        POST[comms.c<br/>beacon_post<br/>WinHTTP HTTPS POST<br/>API-hashed ptrs]
    end

    subgraph Response["Response Processing"]
        direction TB
        RECV[comms.c<br/>Read response<br/>chunks] -->|64 B encrypted<br/>response| DEC
        DEC[crypto.c<br/>aes_decrypt_payload] -->|53 B task JSON<br/>id + command + args| DISP
        DISP[comms.c<br/>dispatch_task<br/>Route command]
    end

    subgraph PostEx["Post-Exploitation Handlers"]
        direction TB
        SS[postex.c<br/>Screenshot<br/>GDI BitBlt]
        CRED[postex.c<br/>Credential Harvest<br/>Chrome LoginData]
        SHELL[comms.c<br/>Shell exec<br/>cmd.exe /c pipe]
        PERSIST[persist.c<br/>Registry Run /<br/>COM Hijack]
        KILL[killswitch.c<br/>Hard / Soft Kill]
    end

    subgraph Sleep["Sleep Phase"]
        direction TB
        EKKO[comms.c<br/>ekko_sleep<br/>7-frame ROP chain] -->|RC4 encrypt<br/>beacon image| DORMANT
        DORMANT[Memory encrypted<br/>PAGE_READWRITE] -->|Timer fires +<br/>jitter interval| WAKE
        WAKE[Decrypt image<br/>Restore PAGE_EXECUTE_READ]
    end

    C2[(C2 Server<br/>192.168.1.69:8443)]

    WL --> CC
    POST -->|TLS 1.2<br/>encrypted POST| C2
    C2 -->|TLS 1.2<br/>encrypted response| RECV
    DISP -->|whoami / shell| SHELL
    DISP -->|screenshot| SS
    DISP -->|grab_creds| CRED
    DISP -->|persist_reg /<br/>persist_com| PERSIST
    DISP -->|kill_hard /<br/>kill_soft| KILL

    SS -->|Results JSON| ENC2[crypto.c<br/>Encrypt result]
    CRED -->|Results JSON| ENC2
    SHELL -->|Results JSON| ENC2
    ENC2 -->|Encrypted POST| C2

    WAKE --> CC

    style Init fill:#f9f0ff,stroke:#7b2d8e
    style CheckIn fill:#f0f7ff,stroke:#2d5f8e
    style Response fill:#fff7f0,stroke:#8e5f2d
    style PostEx fill:#f0fff0,stroke:#2d8e2d
    style Sleep fill:#fff0f0,stroke:#8e2d2d
```

---

## Data Flow Summary Table

| # | Source | Data | Destination | Description |
|---|--------|------|-------------|-------------|
| 1 | Target Host (Windows APIs) | OS, hostname, username, IP, ports, services | recon.c | Host reconnaissance collection |
| 2 | recon.c | CHECKIN_INFO struct (15+ fields) | recon_serialize() | Struct-to-JSON conversion |
| 3 | recon_serialize() | 880 B AgentFindings JSON | crypto.c | Plaintext ready for encryption |
| 4 | crypto.c (encrypt) | 896 B AES-256-CBC ciphertext | comms.c beacon_post() | Encrypted payload for transmission |
| 5 | comms.c beacon_post() | HTTPS POST (TLS 1.2) | C2 Server (8443/tcp) | Encrypted check-in over network |
| 6 | C2 Server | 64 B encrypted task response | comms.c (recv) | Task command from operator |
| 7 | crypto.c (decrypt) | 53 B task JSON (id, command, args) | dispatch_task() | Decrypted command for routing |
| 8 | dispatch_task() | Command + args | Handler module | Route to appropriate handler |
| 9 | postex.c (screenshot) | 4,024 B GDI capture | crypto.c → comms.c | Screenshot exfiltration |
| 10 | postex.c (creds) | 237,922 B base64 bundle | crypto.c → comms.c | Credential exfiltration |
| 11 | evasion.c | Clean .text bytes (1,151,574 B) | In-memory NTDLL | EDR hook removal |
| 12 | evasion.c | Patched prologue bytes | AMSI (amsi.dll) | Disable content scanning |
| 13 | evasion.c | Patched prologue bytes | ETW (ntdll.dll) | Suppress event telemetry |
| 14 | comms.c (Ekko) | RC4-encrypted PE image | Beacon memory pages | Sleep-time memory obfuscation |
| 15 | persist.c | Registry value / CLSID entry | Windows Registry | Boot persistence |
| 16 | anti_analysis.c | CPUID + debug port results | recon.c (flags) | Environment detection |
| 17 | config.h | Macros (host, port, keys, sleep) | All modules | Build-time configuration |
