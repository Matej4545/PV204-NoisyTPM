import socket
import pickle
from cryptography.hazmat.primitives import serialization
from noise.backends.default.diffie_hellmans import ED25519
from noise.connection import NoiseConnection, Keypair
from sys import argv

import constants
import argparse
import TPM2.Tpm as Tpm2
from TPM2.Crypt import Crypto
from tpm2_util import get_signed_pcr_values


class Client:
    def __init__(self, server, port):
        self.sock = socket.socket()
        self.key_pair = ED25519().generate_keypair()
        self.ip = server
        self.port = port

    def exchange_public_keys(self) -> bytes:
        self.sock.send(self.key_pair.public_bytes)
        return self.sock.recv(constants.SERVER_NOISE_PORT)

    def set_connection_keys(self):
        server_public_key = self.exchange_public_keys()
        self.noise = NoiseConnection.from_name(b"Noise_KKpsk0_25519_AESGCM_SHA256")
        self.noise.set_keypair_from_private_bytes(
            Keypair.STATIC,
            self.key_pair.private.private_bytes(
                format=serialization.PrivateFormat.Raw,
                encoding=serialization.Encoding.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        self.noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, server_public_key)

    def tpm_connect(self, use_simulator=False):
        self.tpm = Tpm2.Tpm(useSimulator=use_simulator)
        self.tpm.connect()

    def quote_tpm_data(self, pcr_bitmap):
        self.tpm_connect(use_simulator=False)
        nonce = Crypto.randomBytes(20)
        tpm_data = get_signed_pcr_values(self.tpm, nonce, pcr_bitmap)
        if tpm_data is None:
            raise RuntimeError("Oh no! Something malicious has happened! Signed pcr values were not provided.")
        return tpm_data

    def preshared_tpm_value(self) -> bytes:
        pcr_bitmap = [0b11111111, 0b00000000, 0b00000000]  # Quote PCR 0-7
        tpm_data = self.quote_tpm_data(pcr_bitmap)
        self.sock.send(pickle.dumps(tpm_data))  # data, public key, signature
        data, _, _ = tpm_data
        return bytes(data[-32:])  # Quoted digest from TPM PCR

    def noise_handshake(self):
        self.noise.set_as_initiator()
        tpm_pcr_preshared = self.preshared_tpm_value()
        self.noise.set_psks(psk=tpm_pcr_preshared)
        self.noise.start_handshake()
        message = self.noise.write_message()
        self.sock.send(message)
        received = self.sock.recv(constants.SOCK_BUFFER)
        payload = self.noise.read_message(received)

    def send_encrypted_msg(self, message: str):
        encrypted_message = self.noise.encrypt(bytes(message, encoding="UTF-8"))
        self.sock.send(encrypted_message)

    def send_messages(self):
        print("________________")
        print(f"Connected to {self.sock.getpeername()} from {self.sock.getsockname()}")
        print("You can write messages now, [r] to re-estabilish connection, [q, quit, exit] to quit:")
        print("________________")
        while True:
            user_input = input("Message: ")
            if len(user_input) == 0:
                print("Please input valid message, [r] to re-estabilish connection, [q, quit, exit] to quit.")
                continue
            if user_input.lower() in ["r"]:
                self.end_connection()
                self.set_connection()
                print("________________")
                print(f"New connection to {self.sock.getpeername()} from {self.sock.getsockname()}")
                print("________________")
                continue
            if user_input.lower() in ["q", "quit", "exit"]:
                return
            self.communicate(user_input)

    def communicate(self, message):
        # Trying to send multiple messages with one session
        self.send_encrypted_msg(message)
        self.receive_and_decrypt_msg()

    def set_connection(self):
        print(f"Initializing connection to {self.ip}:{self.port}...", end="")
        self.sock = socket.socket()
        self.sock.connect((self.ip, self.port))
        print("OK\nSetting Noise keys...", end="")
        self.set_connection_keys()
        print("OK\nPerforming Noise handshake...", end="")
        self.noise_handshake()
        print("OK\n")

    def end_connection(self):
        print("Closing connection...", end="")
        self.sock.close()
        print("OK")

    def receive_and_decrypt_msg(self):
        ciphertext = self.sock.recv(constants.SOCK_BUFFER)
        plaintext = self.noise.decrypt(ciphertext).decode("UTF-8")
        print(f"Server response: {plaintext}", end="\n")

    def register(self):
        # TODO: read TPMs PCR values and somehow send them to a server
        print("Registration complete, your identifier is <TOP_SECRET_PCR_HASH>")
        return True

    def run(self, message):
        self.set_connection()
        if message:  # One time
            self.communicate(message)
        else:  # Multiple messages
            self.send_messages()
        self.end_connection()


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
        default="localhost",
        help="An IP address or hostname of the server.",
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="port",
        metavar="PORT",
        type=int,
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
        client = Client(args.server.strip(), args.port)
        if args.register:
            client.register()
        client.run(message)
    except Exception as e:
        print("An error occured! Quitting app.")
        print(e)
