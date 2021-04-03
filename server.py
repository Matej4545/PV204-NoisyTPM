import socket

from cryptography.hazmat.primitives import serialization
from itertools import cycle
from noise.backends.default.diffie_hellmans import ED25519
from noise.connection import NoiseConnection, Keypair

import constants


class Server:
    def __init__(self):
        self.sock = socket.socket()
        self.key_pair = ED25519().generate_keypair()

    def start_listening(self):
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("localhost", constants.SERVER_PORT))
        self.sock.listen(1)
        self.conn, addr = self.sock.accept()
        print("Accepted connection from", addr)

    def exchange_public_keys(self) -> bytes:
        client_public_key = self.conn.recv(constants.CLIENT_PORT)
        self.conn.send(self.key_pair.public_bytes)
        return client_public_key

    def set_connection_keys(self):
        client_public_key = self.exchange_public_keys()
        self.noise = NoiseConnection.from_name(b"Noise_KK_25519_AESGCM_SHA256")
        self.noise.set_keypair_from_private_bytes(
            Keypair.STATIC,
            self.key_pair.private.private_bytes(
                format=serialization.PrivateFormat.Raw,
                encoding=serialization.Encoding.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        self.noise.set_keypair_from_public_bytes(
            Keypair.REMOTE_STATIC, client_public_key
        )

    def noise_handshake(self):
        self.noise.set_as_responder()
        self.noise.start_handshake()
        # Perform handshake. Break when finished
        for action in cycle(["receive", "send"]):
            if self.noise.handshake_finished:
                break
            elif action == "send":
                ciphertext = self.noise.write_message()
                self.conn.sendall(ciphertext)
            elif action == "receive":
                data = self.conn.recv(constants.CLIENT_PORT)
                plaintext = self.noise.read_message(data)

    def communication(self):
        # Endless loop "echoing" received data
        while True:
            data = self.conn.recv(constants.CLIENT_PORT)
            if not data:
                break
            received = self.noise.decrypt(data)
            print(received)
            self.conn.sendall(self.noise.encrypt(b"Hello client!"))

    def run(self):
        self.start_listening()
        self.set_connection_keys()
        self.noise_handshake()
        self.communication()


if __name__ == "__main__":
    server = Server()
    server.run()
