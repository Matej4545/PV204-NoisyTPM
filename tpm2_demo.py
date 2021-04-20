import TPM2.Tpm as Tpm2
import tpm2_util as tu
from TPM2.Crypt import Crypto


def tpm2_demo():
    """A TPM2 demo showcasing some of its functionalities.
    Uses a real TPM by default.
    """
    # host="127.0.0.1", port=2321
    # set 'useSimulator' to True to use a TCP TPM. In that case a simulator needs to be running
    # use a real TPM when set to False
    tpm = Tpm2.Tpm(useSimulator=False)

    # TPM object needs to connect to a real TPM or a simulator
    try:
        tpm.connect()
    except Exception as e:
        print(e)
        return

    # get random bytes from TPM (this is limited by the size of the largest hash function, e.g., SHA256)
    tpm_rnd_bytes = tu.get_random_bytes(tpm, 10)
    print(f"{len(tpm_rnd_bytes)} random bytes:", tpm_rnd_bytes)

    # get year of the TPM
    print("Year:", tu.get_property_year(tpm))

    # get string defined by the vendor
    print("Vendor string 1:", tu.get_property_vendor_string(tpm))

    # get the minimum of bitmap bytes for PCR selection, usually TPMs have 24 PCRs, i.e., 3 bytes
    print("PCR min select:", tu.get_pcr_min_select(tpm))

    # get plaintext SHA1 PCR values, optionally specify a selection bitmap, e.g. 0b00001111 for PCR0-3
    print("\nPCR SHA1 hashes:")
    plaintext_pcr = tu.get_pcr_values(tpm)
    for i, pcr_val in enumerate(plaintext_pcr):
        print(f"PCR{i}", pcr_val.hex())

    if len(plaintext_pcr) == 0:
        print("No PCRs were selected or TPM returned empty buffer.")
        return

    # quote PCR values to securely get their digest, signature, and public key
    # the signature's validity is checked
    # the signature is also randomized with a nonce
    # this can be used for a remote attestation
    nonce_size = 20
    nonce = Crypto.randomBytes(nonce_size)
    signed_pcr = tu.get_signed_pcr_values(tpm, Crypto.randomBytes(20))
    if signed_pcr is None:
        print("Oh no! Something malicious has happened!")
        return

    data, (ec_x, ec_y), (sig_r, sig_s) = signed_pcr
    print("\nQuoted digest from TPM: ", data[-32:].hex())

    # PCR digest comparison
    # we may check the quoted digest ourselves
    hs = Crypto.tpmAlgToPy(Tpm2.TPM_ALG_ID.SHA256)()
    for pcr_val in plaintext_pcr:
        hs.update(pcr_val)
    print("Our recalculated digest:", hs.hexdigest())

    print("\nECDSA (NIST-P256) public key: x = ", ec_x.hex(), ", y = ", ec_y.hex(), sep="")
    print("Signature: r = ", sig_r.hex(), ", s = ", sig_s.hex(), sep="")
    print(f"{nonce_size} bytes large nonce: {nonce.hex()}, do not reuse :)")

    # we may also validate the signature without TPM using cryptography.hazmat
    print("\nSignature verification using hazmat:", end=" ")
    if tu.ecdsa_validate(ec_x, ec_y, sig_r, sig_s, data):
        print("OK")
    else:
        print("FAIL")


if __name__ == "__main__":
    tpm2_demo()
