# C2 Beacon ↔ TeamServer JSON Schema

All payloads are AES-256-CBC encrypted on the wire.  
Wire format: `[IV 16B][ciphertext (PKCS7 padded)]`  
The JSON below is the **plaintext** inside that envelope.

Session keys are derived via HKDF-SHA256 from a per-build master secret
(salt = agent_id, ikm = master_secret).

---

## 1. Checkin Request

**Beacon → TeamServer**  
`POST /api/agents/:id/checkin`

```json
{
  "hostname": "WORKSTATION-01",
  "os":       "Windows 10 Pro 22H2",
  "ip":       "192.168.1.42"
}
```

| Field      | Type   | Required | Description                        |
|------------|--------|----------|------------------------------------|
| `hostname` | string | yes      | NetBIOS or FQDN of the host       |
| `os`       | string | yes      | OS version string                  |
| `ip`       | string | yes      | Primary IPv4 address               |

---

## 2. Checkin Response

**TeamServer → Beacon**  
Returned in the HTTP response body (encrypted).

### When a task is queued

```json
{
  "task": {
    "id":      "a1b2c3d4-...",
    "command": "whoami",
    "args":    null
  }
}
```

### When no tasks are pending

```json
{
  "task": null
}
```

| Field          | Type        | Description                           |
|----------------|-------------|---------------------------------------|
| `task`         | object/null | `null` if nothing is queued           |
| `task.id`      | string      | UUID of the task (for result posting) |
| `task.command`  | string     | Command to execute                    |
| `task.args`    | string/null | Optional arguments                    |

---

## 3. Result Submission

**Beacon → TeamServer**  
`POST /api/agents/:id/result`

```json
{
  "task_id":   "a1b2c3d4-...",
  "output":    "desktop-pc\\jsmith",
  "exit_code": 0
}
```

| Field       | Type   | Required | Description                          |
|-------------|--------|----------|--------------------------------------|
| `task_id`   | string | yes      | UUID of the completed task           |
| `output`    | string | yes      | Stdout/stderr captured by the beacon |
| `exit_code` | int    | no       | Process exit code (0 = success)      |

---

## 4. Notes

- All string fields are UTF-8.
- `task.args` may be `null` or omitted entirely.
- The TeamServer models that consume/produce these structures are in
  `TeamServerAPI/src/db/models.rs` (`Agent`, `Task`, `TaskResult`).
