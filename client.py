import socket

from cryptography.hazmat.primitives import serialization
from noise.backends.default.diffie_hellmans import ED25519
from noise.connection import NoiseConnection, Keypair
from sys import argv
import constants
import argparse
import threading


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
        self.noise.set_keypair_from_public_bytes(
            Keypair.REMOTE_STATIC, server_public_key
        )

    def noise_handshake(self):
        self.noise.set_as_initiator()
        self.noise.start_handshake()
        message = self.noise.write_message()
        self.sock.send(message)
        received = self.sock.recv(4096)
        payload = self.noise.read_message(received)

    def send_encrypted_msg(self, message: str):
        encrypted_message = self.noise.encrypt(bytes(message, encoding="UTF-8"))
        self.sock.send(encrypted_message)

    def send_messages(self):
        print("You can write messages now, [q, quit, exit] to quit:")
        while True:
            user_input = input("Message: ")
            if len(user_input) == 0:
                print("Please input valid message, [q, quit, exit] to quit.")
                continue
            if user_input.lower() in ["q", "quit", "exit"]:
                return
            self.sock = socket.socket()
            self.sock.connect((self.ip, self.port))
            self.set_connection_keys()
            self.noise_handshake()
            self.send_encrypted_msg(user_input)
            self.receive_and_decrypt_msg()
            self.sock.close()

    def receive_and_decrypt_msg(self):
        ciphertext = self.sock.recv(4096)
        plaintext = self.noise.decrypt(ciphertext)
        print(f'Server: {plaintext.decode("utf-8") }')

    def register(self):
        # TODO: read TPMs PCR values and somehow send them to a server
        print("Registration complete, your identifier is <TOP_SECRET_PCR_HASH>")
        return True

    def run(self, ip, port, message):
        self.ip = ip
        self.port = port
        if message:  # One time
            self.sock.connect((ip, port))
            self.set_connection_keys()
            self.noise_handshake()
            self.send_encrypted_msg(message)
            self.receive_and_decrypt_msg()
        else:  # Multiple messages
            self.send_messages()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PV204 NoisyTPM - this is a part of team project for PV204. \
                                                Client app can communicate with server using Noise framework \
                                                and authenticate via TPM. Please see \
                                                'https://github.com/Matej4545/PV204-NoisyTPM/' for more info."
    )
    parser.add_argument(
        "-s",
        "--server",
        dest="server",
        metavar="IP",
        type=str,
        nargs=1,
        default="localhost",
        help="An IP address or hostname of the server.",
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="port",
        metavar="PORT",
        type=int,
        nargs=1,
        default=5555,
        help="A port where the server is listening.",
    )
    parser.add_argument(
        "-m",
        "--message",
        metavar="MESSAGE",
        dest="message",
        type=str,
        nargs="+",
        help="Specify message as argument. For interactive session please omit.",
    )
    parser.add_argument(
        "-r --register",
        dest="register",
        action="store_true",
        default=False,
        help="If you are not authenticated or running the app first time, you will need to register.",
    )
    args = parser.parse_args()

    try:
        message = "" if args.message is None else "".join(args.message).strip()
        server = args.server[0].strip()
        port = args.port[0]
        client = Client()
        if args.register:
            client.register()
        client.run(server, port, message)
    except Exception as e:
        print("An error occured! Quitting app.")
        print(e)
