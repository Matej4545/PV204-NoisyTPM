import os
import random
import subprocess
import tempfile

from ctypes import cdll
from distutils import spawn
from time import sleep


class BaseTpmSimulator(object):
    def __init__(self):
        self.tpm = None

    def start(self):
        tpm = None
        for _ in range(0, 10):
            random_port = random.randrange(2321, 65534)
            tpm = self._start(port=random_port)
            if tpm:
                self.tpm = tpm
                break

        if not tpm:
            raise SystemError("Could not start simulator")

    def close(self):
        self.tpm.terminate()


class IBMSimulator(BaseTpmSimulator):
    exe = "tpm_server"
    libname = "libtss2-tcti-mssim.so"

    def __init__(self):
        self._port = None
        super().__init__()
        self.working_dir = tempfile.TemporaryDirectory()

    def _start(self, port):
        cwd = os.getcwd()
        os.chdir(self.working_dir.name)
        try:
            cmd = ["tpm_server", "-rm", "-port", "{}".format(port)]
            tpm = subprocess.Popen(cmd)
            sleep(2)

            if not tpm.poll():
                self._port = port
                return tpm
            return None

        finally:
            os.chdir(cwd)

    @property
    def tcti_name_conf(self):
        if self._port is None:
            return None
        return f"mssim:port={self._port}"


class TpmSimulator(object):
    SIMULATOR = IBMSimulator

    @staticmethod
    def getSimulator():
        sim = TpmSimulator.SIMULATOR
        exe = spawn.find_executable(sim.exe)
        cdll.LoadLibrary(sim.libname)
        return sim()


""" To start simulator use setUp method. To stop simulator use tearDown method. """
simulator = TpmSimulator.getSimulator()
