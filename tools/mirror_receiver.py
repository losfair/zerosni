#!/usr/bin/env python3
"""Mirror receiver for zerosni TLS interception - decodes HTTP/1.1 traffic."""

import argparse
import itertools
import socket
import struct

DIR_CLIENT = 0x00
DIR_SERVER = 0x01

_conn_id_counter = itertools.count(1)


def parse_http1_request(data: bytes) -> dict | None:
    try:
        idx = data.find(b"\r\n\r\n")
        header_part = data[: idx if idx != -1 else len(data)]
        lines = header_part.split(b"\r\n")
        if not lines:
            return None
        req_line = lines[0].decode("utf-8", errors="replace")
        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.decode().strip().lower()] = v.decode().strip()
        return {"type": "request", "line": req_line, "headers": headers}
    except Exception:
        return None


def parse_http1_response(data: bytes) -> dict | None:
    try:
        idx = data.find(b"\r\n\r\n")
        header_part = data[: idx if idx != -1 else len(data)]
        lines = header_part.split(b"\r\n")
        if not lines:
            return None
        status_line = lines[0].decode("utf-8", errors="replace")
        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.decode().strip().lower()] = v.decode().strip()
        return {"type": "response", "line": status_line, "headers": headers}
    except Exception:
        return None


def handle_connection(conn: socket.socket, addr):
    conn_id = next(_conn_id_counter)
    print(f"[+] Connection {conn_id} from {addr}")
    buf = b""

    while True:
        try:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk

            while len(buf) >= 5:
                direction = buf[0]
                size = struct.unpack("<I", buf[1:5])[0]
                if len(buf) < 5 + size:
                    break
                data = buf[5 : 5 + size]
                buf = buf[5 + size :]

                dir_str = "C->S" if direction == DIR_CLIENT else "S->C"
                prefix = f"[{conn_id} {dir_str}]"

                if direction == DIR_CLIENT:
                    parsed = parse_http1_request(data)
                    if parsed:
                        print(f"{prefix} {parsed['line']}")
                        for k, v in parsed["headers"].items():
                            print(f"         {k}: {v}")
                    else:
                        print(f"{prefix} {len(data)} bytes")
                else:
                    parsed = parse_http1_response(data)
                    if parsed:
                        print(f"{prefix} {parsed['line']}")
                    else:
                        print(f"{prefix} {len(data)} bytes")

        except Exception as e:
            print(f"[-] Connection {conn_id} error: {e}")
            break

    conn.close()
    print(f"[-] Connection {conn_id} closed")


def main():
    parser = argparse.ArgumentParser(description="zerosni mirror receiver")
    parser.add_argument("-p", "--port", type=int, default=9000, help="Listen port")
    parser.add_argument("-b", "--bind", default="127.0.0.1", help="Bind address")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.listen(16)
    print(f"[*] Listening on {args.bind}:{args.port}")

    while True:
        conn, addr = sock.accept()
        handle_connection(conn, addr)


if __name__ == "__main__":
    main()
