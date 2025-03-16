from secp256k1lab.secp256k1 import Scalar
from secp256k1lab.util import bytes_from_int
from .util import *

from chilldkg_ref.chilldkg import (
    hostpubkey_gen,
    params_id,
    recover
)
import chilldkg_ref.chilldkg as chilldkg

def generate_hostpubkey_vectors():
    vectors = {"valid_test_cases": [], "error_test_cases": []}

    # --- Valid test case 1 ---
    hostseckey = bytes.fromhex("631C047D50A67E45E27ED1FF25FCE179CAF059A2120D346ACD9774C1F2BAB66F")
    expected_pubkey = hostpubkey_gen(hostseckey)
    vectors["valid_test_cases"].append({
        "hostseckey": bytes_to_hex(hostseckey),
        "expected_hostpubkey": bytes_to_hex(expected_pubkey),
        "comment": "valid host secret key"
    })

    # --- Error test case 1: Wrong length ---
    short_hostseckey = bytes.fromhex("631C047D50A67E45E27ED1FF25FCE179")
    assert len(short_hostseckey) == 16
    error = expect_exception(
        lambda: hostpubkey_gen(short_hostseckey),
        chilldkg.HostSeckeyError
    )
    vectors["error_test_cases"].append({
        "hostseckey": bytes_to_hex(short_hostseckey),
        "error": error,
        "comment": "length of host secret key is not 32 bytes"
    })
    # --- Error test case 2: Out-of-range hostseckey (Scalar.ORDER) ---
    invalid_hostseckey = bytes_from_int(Scalar.SIZE)
    error = expect_exception(
        lambda: hostpubkey_gen(invalid_hostseckey),
        ValueError
    )
    vectors["error_test_cases"].append({
        "hostseckey": bytes_to_hex(invalid_hostseckey),
        "error": error,
        "comment": "host secret key is out of range"
    })
    # --- Error test case 3: zeroed hostseckey ---
    zeroed_hostseckey = b"\x00" * 32
    error = expect_exception(
        lambda: hostpubkey_gen(zeroed_hostseckey),
        ValueError
    )
    vectors["error_test_cases"].append({
        "hostseckey": bytes_to_hex(zeroed_hostseckey),
        "error": error,
        "comment": "zeroed host secret key"
    })

    return vectors

def generate_params_id_vectors():
    vectors = {"valid_test_cases": [], "error_test_cases": []}
    hostseckeys = hex_list_to_bytes([
        "ADE179B2C56CB75868D44B333C16C89CB00DFDE378AD79C84D0CCE856E4F9207",
        "94BB10C1DE15783C3F3E49167A0951CACD2803F13AAC456C816E88AB4AC76330",
        "F129C2D30096C972F14BB6764CC003C97119C0E32831EA4858F0DD0DFB780FAA"
    ])
    hostpubkeys = [hostpubkey_gen(sk) for sk in hostseckeys]

    # --- Valid test cases ---
    valid_cases = [
        {"t": 2, "comment": ""},
        {"t": 1, "comment": "min threshold value"},
        {"t": len(hostpubkeys), "comment": "max threshold value"}
    ]

    for case in valid_cases:
        t = case["t"]
        params = chilldkg.SessionParams(hostpubkeys, t)
        expected_params_id = params_id(params)
        test_case = {
            "params": {
                "hostpubkeys": bytes_list_to_hex(hostpubkeys),
                "t": t
            },
            "expected_params_id": bytes_to_hex(expected_params_id),
        }
        if case["comment"]:
            test_case["comment"] = case["comment"]
        vectors["valid_test_cases"].append(test_case)

    # --- Error test case 1: Invalid threshold ---
    t = 0
    params = chilldkg.SessionParams(hostpubkeys, t)
    error = expect_exception(
        lambda: params_id(params),
        chilldkg.ThresholdOrCountError
    )
    vectors["error_test_cases"].append({
        "params": {
            "hostpubkeys": bytes_list_to_hex(hostpubkeys),
            "t": t
        },
        "error": error,
        "comment": "invalid threshold value"
    })
    # --- Error test case 2: hostpubkeys list contains duplicate values---
    t = 2
    with_duplicate = [hostpubkeys[0], hostpubkeys[1], hostpubkeys[2], hostpubkeys[1]]
    params = chilldkg.SessionParams(with_duplicate, t)
    error = expect_exception(
        lambda: params_id(params),
        chilldkg.DuplicateHostPubkeyError
    )
    vectors["error_test_cases"].append({
        "params": {
            "hostpubkeys": bytes_list_to_hex(with_duplicate),
            "t": t
        },
        "error": error,
        "comment": "hostpubkeys list contains duplicate values"
    })
    # --- Error test case 2: hostpubkeys list contains an invalid value---
    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    t = 2
    with_invalid = [hostpubkeys[0], invalid_hostpubkey, hostpubkeys[2]]
    params = chilldkg.SessionParams(with_invalid, t)
    error = expect_exception(
        lambda: params_id(params),
        chilldkg.InvalidHostPubkeyError
    )
    vectors["error_test_cases"].append({
        "params": {
            "hostpubkeys": bytes_list_to_hex(with_invalid),
            "t": t
        },
        "error": error,
        "comment": "hostpubkeys list contains an invalid value"
    })

    return vectors

def generate_recover_vectors():
    vectors = {"valid_test_cases": [], "error_test_cases": []}
    return vectors
