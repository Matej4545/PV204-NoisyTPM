import socket

from cryptography.hazmat.primitives import serialization
from noise.backends.default.diffie_hellmans import ED25519
from noise.connection import NoiseConnection, Keypair

import constants

def main():
    sock = socket.socket()
    sock.connect(("localhost", constants.SERVER_PORT))


    key_pair = ED25519().generate_keypair()
    sock.send(key_pair.public_bytes)
    server_public_key = sock.recv(constants.SERVER_PORT)

    noise = NoiseConnection.from_name(b"Noise_KK_25519_AESGCM_SHA256")
    noise.set_keypair_from_private_bytes(Keypair.STATIC, key_pair.private.private_bytes(
        format=serialization.PrivateFormat.Raw,
        encoding=serialization.Encoding.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ))
    noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, server_public_key)

    noise.set_as_initiator()
    noise.start_handshake()
    message = noise.write_message()
    sock.send(message)
    received = sock.recv(constants.CLIENT_PORT)
    payload = noise.read_message(received)

    encrypted_message = noise.encrypt(b"Hello server!")
    sock.send(encrypted_message)

    ciphertext = sock.recv(constants.CLIENT_PORT)
    plaintext = noise.decrypt(ciphertext)
    print(plaintext)

if __name__ == '__main__':
    main()
