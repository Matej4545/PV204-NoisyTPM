import socket
from cryptography.hazmat.primitives import serialization
from itertools import cycle


from noise.backends.default.diffie_hellmans import ED25519
from noise.connection import NoiseConnection, Keypair

import constants

def main():
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', constants.SERVER_PORT))
    sock.listen(1)
    conn, addr = sock.accept()
    print('Accepted connection from', addr)

    key_pair = ED25519().generate_keypair()
    client_public_key = conn.recv(constants.CLIENT_PORT)
    conn.send(key_pair.public_bytes)

    noise = NoiseConnection.from_name(b"Noise_KK_25519_AESGCM_SHA256")
    noise.set_keypair_from_private_bytes(Keypair.STATIC, key_pair.private.private_bytes(
        format=serialization.PrivateFormat.Raw,
        encoding=serialization.Encoding.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ))
    noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, client_public_key)

    noise.set_as_responder()
    noise.start_handshake()
    # Perform handshake. Break when finished
    for action in cycle(['receive', 'send']):
        if noise.handshake_finished:
            break
        elif action == 'send':
            ciphertext = noise.write_message()
            conn.sendall(ciphertext)
        elif action == 'receive':
            data = conn.recv(constants.CLIENT_PORT)
            plaintext = noise.read_message(data)

    # Endless loop "echoing" received data
    while True:
        data = conn.recv(constants.CLIENT_PORT)
        if not data:
            break
        received = noise.decrypt(data)
        conn.sendall(noise.encrypt(received))

if __name__ == '__main__':
    main()
