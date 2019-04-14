# -*- coding: utf-8 -*-
import pickle
import socket
from socketserver import BaseRequestHandler

EOF = b"\xff\x00" * 6 + b"\xee\x00\xff\x00"  # Arbitrary, but 16 bytes total.


# Clients.
class ClientMixIn:
    def parley(self, code, *data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(self.remote_address)
            send_eof(s, (code, data))
            return recv_eof(s)


# Servers.
class Handler(BaseRequestHandler):
    def handle(self):
        # BaseRequestHandler exposes the receiving socket as `self.request`.
        code, payload = recv_eof(self.request)
        out_data = self.server._handlers[code](*payload)
        send_eof(self.request, out_data)


# Sockets.
def send_eof(sock, out_data):
    """Pickles a Python object and transmits it on a socket."""
    out_data = pickle.dumps(out_data) + EOF

    sent = 0
    while sent < len(out_data):
        sent_now = sock.send(out_data[sent:])
        if not sent_now:
            raise OSError("socket connection broken")
        sent += sent_now

    return sent - len(EOF)


def recv_eof(sock):
    """Receives data on a socket and unpickles a Python object."""
    received = b""
    while not received.endswith(EOF):
        received += sock.recv(4096)

    received = received.rstrip(EOF)
    return pickle.loads(received)
