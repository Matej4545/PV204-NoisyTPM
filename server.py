import socket
import pickle

from cryptography.hazmat.primitives import serialization
from itertools import cycle
from noise.backends.default.diffie_hellmans import ED25519
from noise.connection import NoiseConnection, Keypair
from noise.exceptions import NoiseHandshakeError, NoiseValueError
from flask import Flask, render_template, request, jsonify
from os import path, makedirs
import constants
import jsonpickle
import logging
import threading
import time
import interfaces
from signal import signal, SIGINT
from sys import exit

# Set logging
logger = logging.getLogger("server_logger")
logger.setLevel(constants.SERVER_LOG_LEVEL)
fh = logging.FileHandler("server.log")
ch = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)


class Server:
    def __init__(self):
        self.sock = socket.socket()
        self.key_pair = ED25519().generate_keypair()
        self.user_list = []
        self.message_list = []
        self.requests = []
        self.active_sessions = []
        self.deserialize()
        self.isRunning = True
        logger.info("Server initialized.")

    def start_listening(self):
        try:
            logger.info("Start listening")
            while self.isRunning:
                # Conn is new socket
                conn, addr = self.sock.accept()
                self.requests.append((conn, addr))
                logger.info(f"New connection from {addr} in queue (queue len {len(self.requests)}")
            logger.info("Stop listening")
        except Exception:
            logging.error("An error occured in listener method!", exc_info=1)
            self.restart()

    def exchange_public_keys(self, conn) -> bytes:
        client_public_key = conn.recv(constants.SOCK_BUFFER)
        conn.send(self.key_pair.public_bytes)
        return client_public_key

    def set_connection_keys(self, conn):
        try:
            client_public_key = self.exchange_public_keys(conn)
            self.noise = NoiseConnection.from_name(b"Noise_KK_25519_AESGCM_SHA256")
            self.noise.set_keypair_from_private_bytes(
                Keypair.STATIC,
                self.key_pair.private.private_bytes(
                    format=serialization.PrivateFormat.Raw,
                    encoding=serialization.Encoding.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
            )
            self.noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, client_public_key)
            logger.debug(f"Keys set successfully.")
            return True
        except NoiseValueError:
            logger.debug("Not valid Noise communication - invalid length of public bytes.")
            return False

    def receive_tpm_data(self, conn):
        # TODO better storing client's tpm_data
        self.tpm_data = conn.recv(constants.SOCK_BUFFER)
        self.tpm_data = pickle.loads(self.tpm_data)
        logger.debug(f"TPM data has been received.")

    def preshared_tpm_value(self, conn) -> bytes:
        self.receive_tpm_data(conn)
        data, _, _ = self.tpm_data
        return bytes(data[-32:])

    def noise_handshake(self, conn):
        try:
            self.noise.set_as_responder()
            self.noise.start_handshake()
            # Perform handshake. Break when finished
            for action in cycle(["receive", "send"]):
                if self.noise.handshake_finished:
                    break
                elif action == "send":
                    ciphertext = self.noise.write_message()
                    conn.sendall(ciphertext)
                elif action == "receive":
                    data = conn.recv(constants.SOCK_BUFFER)
                    plaintext = self.noise.read_message(data)
        except NoiseHandshakeError:
            logger.error("Error in handshake.")

    def communication(self, conn: socket.socket):
        # Endless loop "echoing" received data
        while True:
            data = conn.recv(constants.SOCK_BUFFER)
            if not data:
                peer_info = conn.getpeername()
                logger.debug(f"No data in {peer_info}, closing socket.")
                conn.close()
                logger.info(f"Socket {peer_info} closed.")
                return
            received = self.noise.decrypt(data)
            logger.debug(f"Request received, len: {len(received)}")
            self.handle_request(received, conn.getpeername())  # Now only port, should be user UUID based on TPM
            response = f"Success, len: {len(received)}, received data: '{received}'"
            conn.sendall(self.noise.encrypt(response.encode("UTF-8")))

    def handle_request(self, request, user=None):
        """This should include logic to start TPM hash evaluation, register new client or whatever"""
        logger.debug(f"Payload: {request}")
        # TODO: connect with user key
        user = f"{user[0]}:{user[1]}"
        self.message_list.append(interfaces.Message(user, request.decode("utf-8")))
        logger.debug(f"Message length: {len(self.message_list)}")

    def deserialize_from_file(self, file) -> dict:
        """Method to read objects from file using jsonpickle"""
        try:
            filepath = path.join(constants.SERVER_DATA_PATH, file)
            with open(filepath, "r") as input_file:
                res = jsonpickle.decode(input_file.read())
                logger.debug(f"Deserialized sucessfully from {filepath}")
                return res
        except FileNotFoundError as err:
            logger.warn(f"File {filepath} was not found!")
            raise err

    def serialize_to_file(self, file, data):
        """Method to write objects to file using jsonpickle"""
        try:
            filepath = path.join(constants.SERVER_DATA_PATH, file)
            makedirs(path.dirname(filepath), exist_ok=True)
            with open(filepath, "w") as output_file:
                output_file.write(jsonpickle.encode(data))
                logger.debug(f"Serialized sucessfully to {filepath}")
        except FileNotFoundError as err:
            logger.error(f"File {filepath} was not found!")
            raise err

    def deserialize(self):
        try:
            out = self.deserialize_from_file(constants.SERVER_CLIENTS_FILENAME)
            self.user_list = list(set(list(out) + self.user_list))
        except FileNotFoundError:
            logger.warn("Client list file probably does not yet exists.")
        try:
            out = self.deserialize_from_file(constants.SERVER_MESSAGES_FILENAME)
            self.message_list = list(set(list(out) + self.message_list))
        except FileNotFoundError:
            logger.warn("Message list file probably does not yet exists.")

    def serialize(self):
        self.serialize_to_file(constants.SERVER_CLIENTS_FILENAME, self.user_list)
        self.serialize_to_file(constants.SERVER_MESSAGES_FILENAME, self.message_list)

    def handle_requests(self):
        while self.isRunning:
            if len(self.requests) != 0:
                try:
                    req = self.requests.pop()
                    logger.debug(f"Serving request {req[0].getpeername()}")
                    conn: socket.socket = req[0]
                    if not self.set_connection_keys(conn):
                        conn.close()
                        continue
                    self.noise_handshake(conn)
                    # Set keepalive
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)  # After 1 second
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)  # Every 5 seconds
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)  # End after 5 failes attempts
                    logger.info(f"Request from {conn.getpeername()} is active.")
                    self.communication(conn)
                    logger.debug(f"Looking for new requests.")
                except Exception:
                    logger.error(f"Exception occured while handling request {req}", exc_info=1)
                    continue

    def purge(self):
        self.message_list.clear()
        self.user_list.clear()
        self.serialize()

    def initialize(self):
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", constants.SERVER_PORT))
        self.sock.listen(1)
        self.listen_thread = threading.Thread(target=self.start_listening, daemon=True)
        self.req_thread = threading.Thread(target=self.handle_requests, daemon=True)
        self.listen_thread.start()
        self.req_thread.start()

    def create_user(self, username, pubkey, pcr_hash):
        user = interfaces.User(pubkey, pcr_hash, username)
        self.user_list.append(user)
        return user

    def stop(self):
        try:
            self.req_thread.join()
            self.listen_thread.join()
            self.sock.close()
        finally:
            self.serialize()
    
    def restart(self):
        self.stop()
        self.initialize()


server = Server()
server.initialize()

"""FLASK FRONTEND"""
app = Flask(__name__)


@app.route("/", methods=["GET"])
def return_main():
    logger.debug(f"array length: {len(server.message_list)}")
    return render_template("index.html", len=len(server.message_list), message_list=server.message_list)


@app.route("/users", methods=["GET"])
def return_users():
    """This is only for demonstration purposes."""
    return render_template("users.html", len=len(server.user_list), user_list=server.user_list)


@app.route("/about", methods=["GET"])
def return_about():
    return render_template("about.html")


@app.route("/purge", methods=["POST"])
def purge():
    if request.json["magic"] == "please":
        server.purge()
        return jsonify({"message": "There you go!"}), 204
    else:
        return jsonify({"message": "Provide the magic word."}), 401


@app.route("/register", methods=["POST"])
def register():
    # Would be nice to validate parameters to prevent XSS
    username = request.json["username"]
    pcr_hash = request.json["pcr_hash"]
    pubkey = request.json["pubkey"]
    try:
        res = server.create_user(username, pubkey, pcr_hash)
        logger.debug(f"New user: {res.uid}, {res.username}, {res.pcr_hash}, {res.pubkey}")
        return jsonify({"message": "User created"}), 201
    except:
        logger.error("Could not create user")
        logger.error(request.form.listvalues())


def sigint_handler(signal_received, frame):
    logger.info("Ctrl-C catched, trying to serialize server data")
    server.stop()
    exit(0)


if __name__ == "__main__":
    signal(SIGINT, sigint_handler)
    app.run(port=constants.SERVER_PORT, host=constants.SERVER_LISTEN_IP, ssl_context=constants.SERVER_SSL_POLICY)
