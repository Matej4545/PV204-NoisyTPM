from TPM2.Tpm import *


def get_random_bytes(tpm: Tpm, n: int) -> list[int]:
    """Get 'n' random bytes."""
    rnd_bytes = tpm.GetRandom(n)
    return list(rnd_bytes)


def get_property_year(tpm: Tpm) -> int:
    """Get year of the TPM."""
    cap_res = tpm.GetCapability(TPM_CAP.TPM_PROPERTIES, TPM_PT.YEAR, 1)
    year = cap_res.capabilityData.tpmProperty[0].value
    return year


def get_property_vendor_string(tpm: Tpm) -> str:
    """Get vendor string 1 from the TPM."""
    cap_res = tpm.GetCapability(TPM_CAP.TPM_PROPERTIES, TPM_PT.VENDOR_STRING_1, 1)
    string = cap_res.capabilityData.tpmProperty[0].value

    res_bytes = string.to_bytes(int(string.bit_length() / 8 + 0.5), "big")
    return "".join([chr(i) for i in res_bytes])


def get_pcr_values(tpm: Tpm, alg: TPM_ALG_ID = TPM_ALG_ID.SHA1) -> list[bytearray]:
    """Get PCR 0-7 SHA1 values as bytearrays.
    Default hash algorithm is SHA1. Other hash algorithms might not be supported."""
    cap_res = tpm.GetCapability(TPM_CAP.TPM_PROPERTIES, TPM_PT.PCR_SELECT_MIN, 1)
    select_min = cap_res.capabilityData.tpmProperty[0].value - 1

    # little endian PCR selection bitmap
    select_list = [0b11111111]
    select_list.extend([0 for _ in range(select_min)])

    pcr_select = TPMS_PCR_SELECTION(alg, bytes(select_list))
    try:
        pcr_res = tpm.PCR_Read([pcr_select])
    except TpmError as tpm_e:
        print(tpm_e)
        return []

    pcr_list = [pcr_val.buffer for pcr_val in pcr_res.pcrValues]
    return pcr_list


def tpm2_demo(use_sim: bool = False):
    """A demo for TPM2 showcasing some of its functionalities.
    Uses a real TPM by default.
    Set 'use_sim' to True to use a TCP TPM.
    """
    # host="127.0.0.1", port=2321
    tpm = Tpm(useSimulator=use_sim)

    # TPM object needs to connect to a real TPM or a simulator
    try:
        tpm.connect()
    except Exception as e:
        print(e)
        return

    n = 10
    print(f"{n} random bytes:", get_random_bytes(tpm, n))
    print("Year:", get_property_year(tpm))
    print("Vendor string 1:", get_property_vendor_string(tpm))

    print("\nPCR hash values:")
    for i, pcr_val in enumerate(get_pcr_values(tpm)):
        print(f"PCR{i}", pcr_val.hex())


if __name__ == "__main__":
    tpm2_demo()
