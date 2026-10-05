#!/usr/bin/env python3
"""Optional byte relay for real Cloudflare health probes; TLS stays end-to-end.
The AF_UNIX hop joins network namespaces without changing host routing/firewall.
"""
import argparse
import socket
import threading

p = argparse.ArgumentParser()
p.add_argument('--socket', required=True)
p.add_argument('--outside-interface')
args = p.parse_args()


def handle(client):
    upstream = socket.socket(socket.AF_INET if args.outside_interface else socket.AF_UNIX)
    if args.outside_interface:
        upstream.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.outside_interface.encode() + b'\0')
        upstream.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x400)
        upstream.connect(('1.1.1.1', 443))
    else:
        upstream.connect(args.socket)

    def copy(src, dst):
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        finally:
            try: dst.shutdown(socket.SHUT_WR)
            except OSError: pass
    t = threading.Thread(target=copy, args=(client, upstream))
    t.start()
    try: copy(upstream, client)
    finally:
        t.join()
        client.close()
        upstream.close()


listener = socket.socket(socket.AF_UNIX if args.outside_interface else socket.AF_INET)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(args.socket if args.outside_interface else ('1.1.1.1', 443))
listener.listen()
while True:
    client, _ = listener.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
