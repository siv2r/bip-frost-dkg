import copy
from .util import *

from chilldkg_ref.chilldkg import (
    coordinator_step1,
    coordinator_finalize,
    coordinator_investigate,
)
import chilldkg_ref.chilldkg as chilldkg

def generate_coordinator_step1_vectors():
    vectors = {"valid_test_cases": [], "error_test_cases": []}

    hostseckeys = hex_list_to_bytes([
        "ADE179B2C56CB75868D44B333C16C89CB00DFDE378AD79C84D0CCE856E4F9207",
        "94BB10C1DE15783C3F3E49167A0951CACD2803F13AAC456C816E88AB4AC76330",
        "F129C2D30096C972F14BB6764CC003C97119C0E32831EA4858F0DD0DFB780FAA"
    ])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    randoms = hex_list_to_bytes([
        "42B53D62E27380D6F7096EDA1C28C57DDB89FCD4CE5B843EDAC220E165B5A7EC",
        "FDE223740111491D5E60BEFB447A2D8C0B12D4B1CE1A0D6BF5A16CBA7E420153",
        "E5CFC54DA8EE57BA97C389060D00BB840A9DDF6BF1E32AE3D3598373EF384EE7"
    ])
    assert len(randoms) == len(hostpubkeys)

    # --- Valid Test Case 1 ---
    params = chilldkg.SessionParams(hostpubkeys, 2)
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        _, msg = chilldkg.participant_step1(hostseckeys[i], params, randoms[i])
        pmsgs1.append(msg)
    _, expected_cmsg1 = coordinator_step1(pmsgs1, params)
    vectors["valid_test_cases"].append({
        "pmsgs1": [pmsg1_asdict(m) for m in pmsgs1],
        "params": params_asdict(params),
        "expected_cmsg1": cmsg1_asdict(expected_cmsg1)
    })

    # --- Error Test Case 1: Invalid threshold ---
    invalid_params = chilldkg.SessionParams(hostpubkeys, 0)
    error = expect_exception(
        lambda: coordinator_step1(pmsgs1, invalid_params),
        chilldkg.ThresholdOrCountError
    )
    vectors["error_test_cases"].append({
        "pmsgs1": [pmsg1_asdict(m) for m in pmsgs1],
        "params": params_asdict(invalid_params),
        "error": error,
        "comment": "invalid threshold value"
    })
    # --- Error Test Case 2: hostpubkeys list contains duplicate values ---
    with_duplicate = [hostpubkeys[0], hostpubkeys[1], hostpubkeys[2], hostpubkeys[1]]
    duplicate_params = chilldkg.SessionParams(with_duplicate, 2)
    error = expect_exception(
        lambda: coordinator_step1(pmsgs1, duplicate_params),
        chilldkg.DuplicateHostPubkeyError
    )
    vectors["error_test_cases"].append({
        "pmsgs1": [pmsg1_asdict(m) for m in pmsgs1],
        "params": params_asdict(invalid_params),
        "error": error,
        "comment": "hostpubkeys list contains duplicate values"
    })
    # --- Error Test Case 3: hostpubkeys list contains an invalid value ---
    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    with_invalid = [hostpubkeys[0], invalid_hostpubkey, hostpubkeys[2]]
    invalid_params = chilldkg.SessionParams(with_invalid, 2)
    error = expect_exception(
        lambda: coordinator_step1(pmsgs1, invalid_params),
        chilldkg.InvalidHostPubkeyError
    )
    vectors["error_test_cases"].append({
        "pmsgs1": [pmsg1_asdict(m) for m in pmsgs1],
        "params": params_asdict(invalid_params),
        "error": error,
        "comment": "hostpubkeys list contains and invalid value"
    })
    # --- Error Test Case 4: Participant (index 1) message has an enc_shares list of invalid length ---
    invalid_pmsgs1 = copy.deepcopy(pmsgs1)
    invalid_pmsgs1[1].enc_pmsg.enc_shares.pop()
    error = expect_exception(
        lambda: coordinator_step1(invalid_pmsgs1, params),
        chilldkg.FaultyParticipantOrCoordinatorError # REVIEW: why is this working? shouldn't it raise an error saying encpedpop.FaultyParticipantOrCoordinatorError was raised instead?
    )
    vectors["error_test_cases"].append({
        "pmsgs1": [pmsg1_asdict(m) for m in invalid_pmsgs1],
        "params": params_asdict(invalid_params),
        "error": error,
        "comment": "participant (index 1) message has an enc_shares list of invalid length"
    })

    return vectors

def generate_coordinator_finalize_vectors():
    vectors = {"valid_test_cases": [], "error_test_cases": []}
    return vectors

def generate_coordinator_investigate_vectors():
    vectors = {"valid_test_cases": [], "error_test_cases": []}
    return vectors