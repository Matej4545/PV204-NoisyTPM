import socket

from cryptography.hazmat.primitives import serialization
from noise.backends.default.diffie_hellmans import ED25519
from noise.connection import NoiseConnection, Keypair
from sys import argv
import constants


class Client:
    def __init__(self):
        self.sock = socket.socket()
        self.key_pair = ED25519().generate_keypair()

    def exchange_public_keys(self) -> bytes:
        self.sock.send(self.key_pair.public_bytes)
        return self.sock.recv(constants.SERVER_PORT)

    def set_connection_keys(self):
        server_public_key = self.exchange_public_keys()
        self.noise = NoiseConnection.from_name(b"Noise_KK_25519_AESGCM_SHA256")
        self.noise.set_keypair_from_private_bytes(
            Keypair.STATIC,
            self.key_pair.private.private_bytes(
                format=serialization.PrivateFormat.Raw,
                encoding=serialization.Encoding.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        self.noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, server_public_key)

    def noise_handshake(self):
        self.noise.set_as_initiator()
        self.noise.start_handshake()
        message = self.noise.write_message()
        self.sock.send(message)
        received = self.sock.recv(constants.CLIENT_PORT)
        payload = self.noise.read_message(received)

    def send_encrypted_msg(self, message: str):
        encrypted_message = self.noise.encrypt(bytes(message, encoding="UTF-8"))
        self.sock.send(encrypted_message)

    def receive_and_decrypt_msg(self):
        ciphertext = self.sock.recv(constants.CLIENT_PORT)
        plaintext = self.noise.decrypt(ciphertext)
        print(plaintext)

    def run(self, message):
        self.sock.connect(("localhost", constants.SERVER_PORT))
        self.set_connection_keys()
        self.noise_handshake()
        self.send_encrypted_msg(message)
        self.receive_and_decrypt_msg()


if __name__ == "__main__":
    client = Client()
    if len(argv):
        client.run(argv[1])
    else:
        print("Please write message as argument")
