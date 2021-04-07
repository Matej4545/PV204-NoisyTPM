import TPM2.Tpm as Tpm2


def tpm_test():
    """A 'Hello, World' for TPM, except it just shows a random hex string."""

    # host="127.0.0.1", port=2321
    tpm = Tpm2.Tpm(useSimulator=True)

    # TPM object needs to connect to a real TPM or a simulator
    tpm.connect()

    # get 10 random bytes
    tpm_rnd_bytes = tpm.GetRandom(10)
    print(tpm_rnd_bytes.hex())


if __name__ == "__main__":
    tpm_test()
