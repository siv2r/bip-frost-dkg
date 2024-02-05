# Reference implementation of BIP DKG. This file is automatically generated by
# reference_py_gen.sh.

from secp256k1 import n as GROUP_ORDER, Point, G, point_mul, schnorr_sign as sign, schnorr_verify as verify_sig, tagged_hash, bytes_from_point, pubkey_gen, individual_pk, point_add_multi, scalar_add_multi, int_from_bytes, bytes_from_int, cpoint, cbytes, cbytes_ext
from typing import Tuple, List, Optional, Callable, Any, Union, Dict, Literal, Coroutine
from network import SignerChannel, CoordinatorChannels
from util import *

biptag = "BIP DKG: "

def tagged_hash_bip_dkg(tag: str, msg: bytes) -> bytes:
    return tagged_hash(biptag + tag, msg)

def kdf(seed: bytes, tag: str, extra_input: bytes = b'') -> bytes:
    # TODO: consider different KDF
    return tagged_hash_bip_dkg(tag + "KDF ", seed + extra_input)

# A scalar is represented by an integer modulo GROUP_ORDER
Scalar = int

# A polynomial of degree t - 1 is represented by a list of t coefficients
# f(x) = coeffs[0] + ... + coeff[t] * x^n
Polynomial = List[Scalar]

# Evaluates polynomial f at x
def polynomial_evaluate(f: Polynomial, x: Scalar) -> Scalar:
   value = 0
   # Reverse coefficients to compute evaluation via Horner's method
   for coeff in f[::-1]:
        value = (value * x) % GROUP_ORDER
        value = (value + coeff) % GROUP_ORDER
   return value

# Returns [f(1), ..., f(n)] for polynomial f with coefficients coeffs
def secret_share_shard(f: Polynomial, n: int) -> List[Scalar]:
    return [polynomial_evaluate(f, x_i) for x_i in range(1, n + 1)]

# A VSS Commitment is a list of points
VSSCommitment = List[Optional[Point]]

VSSCommitmentSum = Tuple[List[Optional[Point]], List[bytes]]

def serialize_vss_commitment_sum(vss_commitment_sum: VSSCommitmentSum)-> bytes:
    return b''.join([cbytes_ext(P) for P in vss_commitment_sum[0]]) + b''.join(vss_commitment_sum[1])

# Returns commitments to the coefficients of f
def vss_commit(f: Polynomial) -> VSSCommitment:
    vss_commitment = []
    for coeff in f:
        A_i = point_mul(G, coeff)
        vss_commitment.append(A_i)
    return vss_commitment

def vss_verify(signer_idx: int, share: Scalar, vss_commitment: VSSCommitment) -> bool:
    P = point_mul(G, share)
    Q = [point_mul(vss_commitment[j], pow(signer_idx + 1, j) % GROUP_ORDER) \
         for j in range(0, len(vss_commitment))]
    return P == point_add_multi(Q)

# Sum the commitments to the i-th coefficients from the given vss_commitments
# for i > 0. This procedure is introduced by Pedersen in section 5.1 of
# 'Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing'.
def vss_sum_commitments(vss_commitments: List[Tuple[VSSCommitment, bytes]], t: int) -> VSSCommitmentSum:
    n = len(vss_commitments)
    assert(all(len(vss_commitment[0]) == t for vss_commitment in vss_commitments))
    # The returned array consists of 2*n + t - 1 elements
    # [vss_commitments[0][0][0], ..., vss_commitments[n-1][0][0],
    #  sum_group(vss_commitments[i][1]), ..., sum_group(vss_commitments[i][t-1]),
    #  vss_commitments[0][1], ..., vss_commitments[n-1][1]]
    return ([vss_commitments[i][0][0] for i in range(n)] + \
           [point_add_multi([vss_commitments[i][0][j] for i in range(n)]) for j in range(1, t)],
           [vss_commitments[i][1] for i in range(n)])

# Outputs the shared public key and individual public keys of the participants
def derive_group_info(vss_commitment: VSSCommitment, n: int, t: int) -> Tuple[Optional[Point], List[Optional[Point]]]:
  pk = vss_commitment[0]
  participant_public_keys = []
  for signer_idx in range(0, n):
    pk_i = point_add_multi([point_mul(vss_commitment[j], pow(signer_idx + 1, j) % GROUP_ORDER) \
                            for j in range(0, len(vss_commitment))])
    participant_public_keys += [pk_i]
  return pk, participant_public_keys

SimplPedPopR1State = Tuple[int, int, int]
VSS_PoK_msg = (biptag + "VSS PoK").encode()

def simplpedpop_round1(seed: bytes, t: int, n: int, my_idx: int) -> Tuple[SimplPedPopR1State, Tuple[VSSCommitment, bytes], List[Scalar]]:
    """
    Start SimplPedPop by generating messages to send to the other participants.

    :param bytes seed: FRESH, UNIFORMLY RANDOM 32-byte string
    :param int t: threshold
    :param int n: number of participants
    :param int my_idx:
    :return: a state, a VSS commitment and shares
    """
    assert(t < 2**(4*8))
    coeffs = [int_from_bytes(kdf(seed, "coeffs", i.to_bytes(4, byteorder="big"))) % GROUP_ORDER for i in range(t)]
    # TODO: fix aux_rand
    assert(my_idx < 2**(4*8))
    sig = sign(VSS_PoK_msg + my_idx.to_bytes(4, byteorder="big"), bytes_from_int(coeffs[0]), kdf(seed, "VSS PoK"))
    my_vss_commitment = (vss_commit(coeffs), sig)
    my_generated_shares = secret_share_shard(coeffs, n)
    state = (t, n, my_idx)
    return state, my_vss_commitment, my_generated_shares

DKGOutput = Tuple[bytes, Tuple[Scalar, Optional[Point], List[Optional[Point]]]]

def simplpedpop_finalize(state: SimplPedPopR1State,
                         vss_commitments_sum: VSSCommitmentSum, shares_sum: Scalar) \
                         -> DKGOutput:
    """
    Take the messages received from the participants and finalize the DKG

    :param List[bytes] vss_commitments_sum: output of running vss_sum_commitments() with vss_commitments from all participants (including this participant) (TODO: not a list of bytes)
    :param vss_commitments_sum: TODO
    :param scalar shares_sum: sum of shares received by all participants (including this participant) for this participant mod group order
    :param eta: Optional argument for extra data that goes into `Eq`
    :return: a final share, the shared pubkey, the individual participants' pubkeys
    """
    t, n, my_idx = state
    assert(len(vss_commitments_sum) == 2)
    assert(len(vss_commitments_sum[0]) == n + t - 1)
    assert(len(vss_commitments_sum[1]) == n)

    for i in range(n):
        P_i = vss_commitments_sum[0][i]
        if P_i is None:
            raise InvalidContributionError(i, "Participant sent invalid commitment")
        else:
            pk_i = bytes_from_point(P_i)
            if not verify_sig(VSS_PoK_msg + i.to_bytes(4, byteorder="big"), pk_i, vss_commitments_sum[1][i]):
                raise InvalidContributionError(i, "Participant sent invalid proof-of-knowledge")
    # TODO: also add t, n to eta?
    eta = serialize_vss_commitment_sum(vss_commitments_sum)
    # Strip the signatures and sum the commitments to the constant coefficients
    vss_commitments_sum_coeffs = [point_add_multi([vss_commitments_sum[0][i] for i in range(n)])] + vss_commitments_sum[0][n:n+t-1]
    if not vss_verify(my_idx, shares_sum, vss_commitments_sum_coeffs):
        raise VSSVerifyError()
    shared_pubkey, signer_pubkeys = derive_group_info(vss_commitments_sum_coeffs, n, t)
    return eta, (shares_sum, shared_pubkey, signer_pubkeys)

def ecdh(deckey: bytes, enckey: bytes, context: bytes) -> Scalar:
    x = int_from_bytes(deckey)
    assert(x != 0)
    Y = cpoint(enckey)
    Z = point_mul(Y, x)
    assert Z is not None
    return int_from_bytes(tagged_hash_bip_dkg("ECDH", cbytes(Z) + context))

def encrypt(share: Scalar, my_deckey: bytes, enckey: bytes, context: bytes) -> Scalar:
    return (share + ecdh(my_deckey, enckey, context)) % GROUP_ORDER

EncPedPopR1State = Tuple[bytes, bytes]

def encpedpop_round1(seed: bytes) -> Tuple[EncPedPopR1State, bytes]:
    my_deckey = kdf(seed, "deckey")
    my_enckey = individual_pk(my_deckey)
    state1 = (my_deckey, my_enckey)
    return state1, my_enckey

EncPedPopR2State = Tuple[int, bytes, bytes, List[bytes], SimplPedPopR1State]

def encpedpop_round2(seed: bytes, state1: EncPedPopR1State, t: int, n: int, enckeys: List[bytes]) -> Tuple[EncPedPopR2State, Tuple[VSSCommitment, bytes], List[Scalar]]:
    assert(n == len(enckeys))
    if len(enckeys) != len(set(enckeys)):
        raise DuplicateEnckeysError

    my_deckey, my_enckey = state1
    # Protect against reuse of seed in case we previously exported shares
    # encrypted under wrong enckeys.
    assert(t < 2**(4*8))
    enc_context = t.to_bytes(4, byteorder="big") + b''.join(enckeys)
    seed_ = tagged_hash_bip_dkg("EncPedPop seed", seed + enc_context)
    try:
        my_idx = enckeys.index(my_enckey)
    except ValueError:
        raise BadCoordinatorError("Coordinator sent list of encryption keys that does not contain our key.")
    simpl_state, vss_commitment, shares = simplpedpop_round1(seed_, t, n, my_idx)
    enc_shares = [encrypt(shares[i], my_deckey, enckeys[i], enc_context) for i in range(n)]
    state2 = (t, my_deckey, my_enckey, enckeys, simpl_state)
    return state2, vss_commitment, enc_shares

def encpedpop_finalize(state2: EncPedPopR2State, vss_commitments_sum: VSSCommitmentSum, enc_shares_sum: Scalar) -> DKGOutput:
    t, my_deckey, my_enckey, enckeys, simpl_state = state2
    n = len(enckeys)

    assert(len(vss_commitments_sum) == 2)
    assert(len(vss_commitments_sum[0]) == n + t - 1)
    assert(len(vss_commitments_sum[1]) == n)

    enc_context = t.to_bytes(4, byteorder="big") + b''.join(enckeys)
    ecdh_keys = [ecdh(my_deckey, enckeys[i], enc_context) for i in range(n)]
    shares_sum = (enc_shares_sum - scalar_add_multi(ecdh_keys)) % GROUP_ORDER
    eta, dkg_output = simplpedpop_finalize(simpl_state, vss_commitments_sum, shares_sum)
    eta += b''.join(enckeys)
    return eta, dkg_output

def recpedpop_hostpubkey(seed: bytes) -> Tuple[bytes, bytes]:
    my_hostsigkey = kdf(seed, "hostsigkey")
    # TODO: rename to distinguish plain and xonly key gen
    my_hostverkey = pubkey_gen(my_hostsigkey)
    return (my_hostsigkey, my_hostverkey)

Setup = Tuple[List[bytes], int, bytes]
def recpedpop_setup_id(hostverkeys: List[bytes], t: int, context_string: bytes) -> Tuple[Setup, bytes]:
    assert(t < 2**(4*8))
    setup_id = tagged_hash("setup id", b''.join(hostverkeys) + t.to_bytes(4, byteorder="big") + context_string)
    setup = (hostverkeys, t, setup_id)
    return setup, setup_id

RecPedPopR1State = Tuple[List[bytes], int, bytes, EncPedPopR1State, bytes]

def recpedpop_round1(seed: bytes, setup: Setup) -> Tuple[RecPedPopR1State, bytes]:
    hostverkeys, t, setup_id = setup

    # Derive setup-dependent seed
    seed_ = kdf(seed, "setup", setup_id)

    enc_state1, my_enckey =  encpedpop_round1(seed_)
    state1 = (hostverkeys, t, setup_id, enc_state1, my_enckey)
    return state1, my_enckey

RecPedPopR2State = Tuple[bytes, int, EncPedPopR2State]

def recpedpop_round2(seed: bytes, state1: RecPedPopR1State, enckeys: List[bytes]) -> Tuple[RecPedPopR2State, List[bytes], Tuple[VSSCommitment, bytes], List[Scalar]]:
    hostverkeys, t, setup_id, enc_state1, my_enckey = state1

    seed_ = kdf(seed, "setup", setup_id)
    n = len(hostverkeys)
    enc_state2, vss_commitment, enc_shares = encpedpop_round2(seed_, enc_state1, t, n, enckeys)
    my_idx = enckeys.index(my_enckey)
    state2 = (setup_id, my_idx, enc_state2)
    return state2, hostverkeys, vss_commitment, enc_shares

def recpedpop_finalize(seed: bytes, state2: RecPedPopR2State, vss_commitments_sum: VSSCommitmentSum, all_enc_shares_sum: List[Scalar]) -> DKGOutput:
    (setup_id, my_idx, enc_state2) = state2

    # TODO Not sure if we need to include setup_id as eta here. But it won't hurt.
    # Include the enc_shares in eta to ensure that participants agree on all
    # shares, which in turn ensures that they have the right transcript.
    # TODO This means all parties who hold the "transcript" in the end should
    # participate in Eq?
    my_enc_shares_sum = all_enc_shares_sum[my_idx]
    eta, dkg_output = encpedpop_finalize(enc_state2, vss_commitments_sum, my_enc_shares_sum)
    eta += setup_id + b''.join([bytes_from_int(share) for share in all_enc_shares_sum])
    return eta, dkg_output

EqualityCheck = Callable[[bytes], Coroutine[Any, Any, bool]]

async def recpedpop(chan: SignerChannel, seed: bytes, my_hostsigkey: bytes, setup: Setup):
    state1, my_enckey = recpedpop_round1(seed, setup)
    chan.send(my_enckey)
    enckeys = await chan.receive()

    state2, hostverkeys, my_vss_commitment, my_generated_enc_shares =  recpedpop_round2(seed, state1, enckeys)
    chan.send((my_vss_commitment, my_generated_enc_shares))
    vss_commitments_sum, enc_shares_sum = await chan.receive()

    try:
        res = recpedpop_finalize(seed, state2, vss_commitments_sum, enc_shares_sum)
    except Exception as e:
        print("Exception", repr(e))
        return False
    eta, (shares_sum, shared_pubkey, signer_pubkeys) = res
    cert = await certifying_eq(chan, my_hostsigkey, hostverkeys, eta)
    transcript = (setup, enckeys, vss_commitments_sum, enc_shares_sum, cert)
    return shares_sum, shared_pubkey, signer_pubkeys, transcript

def verify_cert(hostverkeys: List[bytes], x: bytes, sigs: List[bytes]) -> bool:
    n = len(hostverkeys)
    if len(sigs) != n:
        return False
    is_valid = [verify_sig(x, hostverkeys[i], sigs[i]) for i in range(n)]
    return all(is_valid)

async def certifying_eq(chan: SignerChannel, my_hostsigkey: bytes, hostverkeys: List[bytes], x: bytes) -> List[bytes]:
    n = len(hostverkeys)
    # TODO: fix aux_rand
    chan.send(("SIG", sign(x, my_hostsigkey, b'0'*32)))
    sigs = [b''] * len(hostverkeys)
    while(True):
        i, ty, msg = await chan.receive()
        if ty == "SIG":
            is_valid = verify_sig(x, hostverkeys[i], msg)
            if sigs[i] == b'' and is_valid:
                sigs[i] = msg
            elif not is_valid:
                print("sig not valid for x", x)
                # The signer `hpk` is either malicious or an honest signer
                # whose input is not equal to `x`. This means that there is
                # some malicious signer or that some messages have been
                # tampered with on the wire. We must not abort, and we could
                # still output True when receiving a cert later, but we
                # should indicate to the user (logs?) that something went
                # wrong.)
                pass
            if sigs.count(b'') == 0:
                cert = sigs
                chan.send(("CERT", cert))
                return cert
        if ty == "CERT":
            sigs = msg
            if verify_cert(hostverkeys, x, sigs):
                chan.send(("CERT", cert))
                return cert

async def recpedpop_coordinate(chans: CoordinatorChannels, t: int, n: int) -> None:
    enckeys = []
    for i in range(n):
        enckeys += [await chans.receive_from(i)]
    chans.send_all(enckeys)
    vss_commitments = []
    enc_shares_sum = [0]*n
    for i in range(n):
        vss_commitment, enc_shares = await chans.receive_from(i)
        vss_commitments += [vss_commitment]
        enc_shares_sum = [ (enc_shares_sum[j] + enc_shares[j]) % GROUP_ORDER for j in range(n) ]
    vss_commitments_sum = vss_sum_commitments(vss_commitments, t)
    chans.send_all((vss_commitments_sum, enc_shares_sum))
    while(True):
        for i in range(n):
            ty, msg = await chans.receive_from(i)
            chans.send_all((i, ty, msg))
            # TODO: make more robust against malicious participants
            if ty == "CERT":
                return
