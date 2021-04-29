import uuid
import datetime as dt


class User(object):
    def __init__(self, pubkey: tuple, pcr_hash: bytes, s: bytes, username=None):
        """Seriazable object representing an User entity"""
        self.pcr_hash = pcr_hash  # Probably we would like to hash it at some point?
        self.username = username
        self.pubkey = pubkey
        self.uid = uuid.uuid4()
        self.s = s

    def check(self, pcr_hash):
        return pcr_hash == self.pcr_hash


class Message(object):
    def __init__(self, uid, content):
        self.timestamp = dt.datetime.utcnow()
        self.content = content
        self.uid = uid
