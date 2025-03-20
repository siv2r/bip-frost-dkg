import json
from typing import NoReturn, List

from chilldkg_ref.chilldkg import (
    SessionParams,
    ParticipantMsg1,
    ParticipantMsg2,
    CoordinatorMsg1
)
import chilldkg_ref.encpedpop as encpedpop

def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()

def bytes_list_to_hex(lst: List[bytes]) -> List[str]:
    return [l_i.hex().upper() for l_i in lst]

def hex_list_to_bytes(lst: List[str]) -> List[bytes]:
    return [bytes.fromhex(l_i) for l_i in lst]

def write_json(filename: str, data: dict) -> NoReturn:
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def exception_asdict(e: Exception) -> dict:
    error_info = {"type": e.__class__.__name__}

    for key, value in e.__dict__.items():
        if isinstance(value, (str, int)):
            error_info[key] = value
        elif isinstance(value, bytes):
            error_info[key] = bytes_to_hex(value)
        elif isinstance(value, encpedpop.ParticipantInvestigationData):
            error_info[key] = pinv_data_asdict(value)
        else:
            raise NotImplementedError(f"Conversion for type {type(value).__name__} is not implemented")

    # the last argument might contain the error message
    if len(e.args) > 0 and isinstance(e.args[-1], str):
        error_info.setdefault("message", e.args[-1])
    return error_info

def expect_exception(try_fn, expected_exception):
    try:
        try_fn()
    except expected_exception as e:
        return exception_asdict(e)
    except Exception as e:
        raise AssertionError(f"Wrong exception raised: {type(e).__name__}")
    else:
        raise AssertionError("Expected exception")

def params_asdict(params: SessionParams) -> dict:
    return {
        "hostpubkeys": bytes_list_to_hex(params.hostpubkeys),
        "t": params.t
    }

def pmsg1_asdict(pmsg1: ParticipantMsg1) -> dict:
    enc_pmsg = pmsg1.enc_pmsg
    simpl_pmsg = enc_pmsg.simpl_pmsg

    result = {
        "simpl_pmsg": {
            "com": bytes_to_hex(simpl_pmsg.com.to_bytes()),
            "pop": bytes_to_hex(pmsg1.enc_pmsg.simpl_pmsg.pop)
        },
        "pubnonce": bytes_to_hex(enc_pmsg.pubnonce),
        "enc_shares": [str(share).upper() for share in enc_pmsg.enc_shares]
    }
    return result

def pmsg2_asdict(pmsg2: ParticipantMsg2) -> dict:
    return {
        "sig": bytes_to_hex(pmsg2.sig)
    }

def pinv_data_asdict(pinv_data: encpedpop.ParticipantInvestigationData) -> dict:
    secshare = pinv_data.simpl_bstate.secshare.to_bytes()
    pubshare = pinv_data.simpl_bstate.pubshare.to_bytes_compressed_with_infinity()
    enc_secshare = pinv_data.enc_secshare.to_bytes()
    pads = [pad.to_bytes() for pad in pinv_data.pads]
    return {
        "simpl_bstate": {
            "n": pinv_data.simpl_bstate.n,
            "idx": pinv_data.simpl_bstate.idx,
            "secshare": bytes_to_hex(secshare),
            "pubshare": bytes_to_hex(pubshare)
        },
        "enc_secshare": bytes_to_hex(enc_secshare),
        "pads": bytes_list_to_hex(pads),
    }

def cmsg1_asdict(cmsg1: CoordinatorMsg1) -> dict:
    enc_cmsg = cmsg1.enc_cmsg
    simpl_cmsg = enc_cmsg.simpl_cmsg

    coms_to_secrets = [
        ge.to_bytes_compressed_with_infinity()
        for ge in simpl_cmsg.coms_to_secrets
    ]
    sum_coms_to_nonconst_terms = [
        ge.to_bytes_compressed_with_infinity()
        for ge in simpl_cmsg.sum_coms_to_nonconst_terms
    ]
    result = {
        "simpl_cmsg": {
            "coms_to_secrets": bytes_list_to_hex(coms_to_secrets),
            "sum_coms_to_nonconst_terms": bytes_list_to_hex(sum_coms_to_nonconst_terms),
            "pops": bytes_list_to_hex(simpl_cmsg.pops)
        },
        "pubnonces": bytes_list_to_hex(enc_cmsg.pubnonces),
        "enc_secshares": [str(share).upper() for share in cmsg1.enc_secshares]
    }
    return result
