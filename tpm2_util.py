from TPM2.Tpm import *
from TPM2.Crypt import Crypto
from typing import List

import cryptography.hazmat.primitives.asymmetric.ec as ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


AIK_TEMPLATE = TPMT_PUBLIC(
    TPM_ALG_ID.SHA256,
    TPMA_OBJECT.restricted
    | TPMA_OBJECT.sign
    | TPMA_OBJECT.sensitiveDataOrigin
    | TPMA_OBJECT.fixedTPM
    | TPMA_OBJECT.fixedParent
    | TPMA_OBJECT.userWithAuth,
    None,
    TPMS_ECC_PARMS(
        TPMT_SYM_DEF_OBJECT(), TPMS_SIG_SCHEME_ECDSA(TPM_ALG_ID.SHA256), TPM_ECC_CURVE.NIST_P256, TPMS_NULL_KDF_SCHEME()
    ),
    TPMS_ECC_POINT(),
)

AIK_HANDLE = TPM_HANDLE(0x81000000)
"""Currently not used."""


class AttestData:
    """A wrapper class for attested data."""

    def __init__(self, data: bytearray):
        attest = TPMS_ATTEST.fromBytes(data)

        # ignores attributes: type, clockInfo
        self.__magic = attest.magic
        self.__signing_key_name = attest.qualifiedSigner
        self.__nonce = attest.extraData
        self.__firmware_version = attest.firmwareVersion
        self.__pcr_hash_id = attest.attested.pcrSelect[0].hash
        self.__pcr_select = attest.attested.pcrSelect
        self.__digest = attest.attested.pcrDigest

    def magic(self) -> int:
        return self.__magic

    def signing_key_name(self) -> str:
        return self.__signing_key_name.hex()

    def nonce(self) -> str:
        return self.__nonce.hex()

    def firmware_version(self) -> int:
        return self.__firmware_version

    def pcr_hash_id(self) -> int:
        return int(self.__pcr_hash_id)

    def pcr_select(self) -> List[bool]:
        bool_arr = 24 * [False]
        for select in self.__pcr_select:
            for j, byte in enumerate(select.pcrSelect):
                for i in range(8):
                    bool_arr[8 * j + i] |= bool((byte >> i) & 1)
        return bool_arr

    def digest(self) -> str:
        return self.__digest.hex()


def create_aik(tpm: Tpm) -> bool:
    """Create a persistent primary attestation identity key (AIK)."""
    try:
        key_res = tpm.CreatePrimary(TPM_HANDLE(TPM_RH.OWNER), TPMS_SENSITIVE_CREATE(), AIK_TEMPLATE, None, None)
    except TpmError as tpm_e:
        print(tpm_e)
        return False

    try:
        tpm.EvictControl(TPM_HANDLE(TPM_RH.OWNER), key_res.handle, AIK_HANDLE)
    except TpmError as tpm_e:
        tpm.FlushContext(key_res.handle)
        print(tpm_e)
        return False

    tpm.FlushContext(key_res.handle)
    return True


def flush_aik(tpm: Tpm) -> bool:
    """Release the persistent primary attestation identity key (AIK)."""
    try:
        tpm.EvictControl(TPM_HANDLE(TPM_RH.OWNER), AIK_HANDLE, AIK_HANDLE)
    except TpmError as tpm_e:
        print(tpm_e)
        return False

    return True


def ecdsa_validate(x: bytearray, y: bytearray, r: bytearray, s: bytearray, data: bytearray) -> bool:
    """Validates ECDSA (r, s) signature for NIST-P256 (SECP256R1) with public point (x, y)."""
    pub_nums = ec.EllipticCurvePublicNumbers(
        curve=ec.SECP256R1(), x=int.from_bytes(x, "big"), y=int.from_bytes(y, "big")
    )
    pub_key = pub_nums.public_key()

    try:
        pub_key.verify(
            encode_dss_signature(r=int.from_bytes(r, "big"), s=int.from_bytes(s, "big")),
            data,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as sig_e:
        print(sig_e)
        return False

    return True


def tpm_self_verify_signature(tpm: Tpm, aik: TPM_HANDLE, sig: TPMU_SIGNATURE, data: bytearray) -> bool:
    """Verify the signature after Quote with loaded AIK (Attestation Identity Key)."""
    hs = Crypto.tpmAlgToPy(TPM_ALG_ID.SHA256)()
    hs.update(data)
    try:
        tpm.VerifySignature(aik, hs.digest(), sig)
    except TpmError as tpm_e:
        print(tpm_e)
        return False
    return True


def get_random_bytes(tpm: Tpm, n: int) -> List[int]:
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


def get_pcr_min_select(tpm: Tpm) -> int:
    """Get the minimum of bytes for PCR Select bitmap."""
    cap_res = tpm.GetCapability(TPM_CAP.TPM_PROPERTIES, TPM_PT.PCR_SELECT_MIN, 1)
    return cap_res.capabilityData.tpmProperty[0].value


def helper_get_pcr_select_list(pcr_list: List[int], alg: TPM_ALG_ID) -> TPMS_PCR_SELECTION:
    """PCR selection bitmap."""
    if pcr_list is None:
        select_list = [255, 0, 0]
    else:
        select_list = pcr_list[:3]
        pcr_len = len(select_list)
        select_list.extend([0 for _ in range(3 - pcr_len)])

    return TPMS_PCR_SELECTION(alg, bytes(select_list))


def get_pcr_values(tpm: Tpm, pcr_list: List[int] = None, alg: TPM_ALG_ID = TPM_ALG_ID.SHA1) -> List[bytearray]:
    """Get PCR SHA1 values as bytearrays.
    pcr_list is a bitmap for PCR selection (7|6|5|4|3|2|1|0)(15|14|13|12|11|10|9|8)(23|22|21|20|19|18|17|16).
    Default hash algorithm is SHA1. Other hash algorithms might not be supported.
    Note this is prone to MitM attack."""
    pcr_select = []
    for i, byte in enumerate(pcr_list):
        pcr_select_byte = helper_get_pcr_select_list(i * [0] + [byte], alg)
        try:
            pcr_res = tpm.PCR_Read([pcr_select_byte])
        except TpmError as tpm_e:
            print(tpm_e)
            return []

        pcr_select += [pcr_val.buffer for pcr_val in pcr_res.pcrValues]

    return pcr_select


def get_signed_pcr_values(
    tpm: Tpm, nonce: bytearray, pcr_list: List[int] = None, alg: TPM_ALG_ID = TPM_ALG_ID.SHA1
) -> (bytearray, (bytearray, bytearray), (bytearray, bytearray)) or None:
    """Get attested PCR values with signature over 'data'.
    nonce should be a random number.
    pcr_list is a bitmap for PCR selection (7|6|5|4|3|2|1|0)(15|14|13|12|11|10|9|8)(23|22|21|20|19|18|17|16).
    Returns 'data, pub_key=(x, y), sig=(r, s)' as bytearrays or None if signature is invalid.
    Last 32 bytes (SHA256) of 'data' is PCR digest.
    """
    pcr_select = helper_get_pcr_select_list(pcr_list, alg)

    try:
        key_res = tpm.CreatePrimary(TPM_HANDLE(TPM_RH.OWNER), TPMS_SENSITIVE_CREATE(), AIK_TEMPLATE, None, None)
    except TpmError as tpm_e:
        print(tpm_e)
        return

    aik = key_res.handle  # attestation identity key
    try:
        quote_res = tpm.Quote(aik, nonce, TPMS_SIG_SCHEME_ECDSA(TPM_ALG_ID.SHA256), [pcr_select])
    except TpmError as tpm_e:
        tpm.FlushContext(aik)
        print(tpm_e)
        return

    # get quoted data as bytearray
    buf = TpmBuffer()
    quote_res.quoted.toTpm(buf)
    buf.trim()

    ec_x = key_res.outPublic.unique.x
    ec_y = key_res.outPublic.unique.y
    sig_r = quote_res.signature.signatureR
    sig_s = quote_res.signature.signatureS
    data = buf.buffer

    # self-test
    if not tpm_self_verify_signature(tpm, aik, quote_res.signature, data):
        tpm.FlushContext(aik)
        return

    # unload AIK
    tpm.FlushContext(aik)

    # data, public key, signature
    return data, (ec_x, ec_y), (sig_r, sig_s)
