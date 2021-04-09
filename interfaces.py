import uuid
import datetime as dt

class Client(object):
    def __init__(self, tpm_key,username = None):
        """Seriazable object representing a Client entity"""
        self.tpm_key = tpm_key # Probably we would like to hash it at some point?
        self.username = username
        self.uid = uuid.uuid4()


class Message(object):
    def __init__(self, uid, content):
        self.timestamp = dt.datetime.utcnow()
        self.content = content
        self.uid = uid