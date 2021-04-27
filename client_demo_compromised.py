from client import *
from tpm2_util import tpm_pcr_extend
import TPM2.Tpm as Tpm2


def run_compromised_client():
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

    # demo part simulating a change in one PCR
    hacker_tpm = Tpm2.Tpm(True)
    hacker_tpm.connect()
    tpm_pcr_extend(hacker_tpm, 0, "Hack the Planet!")  # 0 is BIOS hash
    hacker_tpm.close()

    try:
        message = "" if args.message is None else "".join(args.message).strip()
        client = Client(args.server.strip(), args.port)
        if args.register:
            client.register()
        client.run(message)
    except Exception as e:
        print("An error occurred! Quitting app.")
        print(e)


if __name__ == "__main__":
    run_compromised_client()
