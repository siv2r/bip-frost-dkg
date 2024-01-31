from random import randint
import secrets
from secp256k1 import n as GROUP_ORDER, scalar_add_multi, point_mul, G
from reference import * 
import sys

def test_vss_correctness():
    def rand_polynomial(t):
        return [randint(1, GROUP_ORDER - 1) for _ in range(1, t + 1)]
    for t in range(1, 3):
        for n in range(t, 2*t + 1):
            f = rand_polynomial(t)
            shares = secret_share_shard(f, n)
            assert(len(shares) == n)
            assert(all(vss_verify(i, shares[i], vss_commit(f)) for i in range(n)))

def simulate_simplpedpop(seeds, t, n, Eq):
    assert(len(seeds) == n)
    round1_outputs = []
    dkg_outputs = []
    for i in range(n):
        round1_outputs += [simplpedpop_round1(seeds[i], t, n)]
    vss_commitments = [out[1] for out in round1_outputs]
    vss_commitments_sum = vss_sum_commitments(vss_commitments, t) 
    for i in range(n):
        shares_sum = scalar_add_multi([out[2][i] for out in round1_outputs])
        dkg_outputs += [simplpedpop_finalize(round1_outputs[i][0], i, vss_commitments_sum, shares_sum, Eq)]
    return dkg_outputs 

def simulate_encpedpop(seeds, t, n, Eq):
    assert(len(seeds) == n)
    round1_outputs = []
    round2_outputs = []
    dkg_outputs = []
    for i in range(n):
        round1_outputs += [encpedpop_round1(seeds[i])]

    enckeys = [out[1] for out in round1_outputs]
    for i in range(n):
        round2_outputs += [encpedpop_round2(seeds[i], round1_outputs[i][0], t, n, enckeys)]

    vss_commitments = [out[1] for out in round2_outputs]
    vss_commitments_sum = vss_sum_commitments(vss_commitments, t) 
    for i in range(n):
        enc_shares_sum = scalar_add_multi([out[2][i] for out in round2_outputs])
        dkg_outputs += [encpedpop_finalize(round2_outputs[i][0], vss_commitments_sum, enc_shares_sum, Eq)]
    return dkg_outputs 

# Adapted from BIP 324
def scalar_inv(a: int):
    """Compute the modular inverse of a modulo n using the extended Euclidean
    Algorithm. See https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers.
    """
    a = a % GROUP_ORDER
    if a == 0:
        return 0
    if sys.hexversion >= 0x3080000:
        # More efficient version available in Python 3.8.
        return pow(a, -1, GROUP_ORDER)
    t1, t2 = 0, 1
    r1, r2 = GROUP_ORDER, a
    while r2 != 0:
        q = r1 // r2
        t1, t2 = t2, t1 - q * t2
        r1, r2 = r2, r1 - q * r2
    if r1 > 1:
        return None
    if t1 < 0:
        t1 += GROUP_ORDER
    return t1

def derive_interpolating_value(L, x_i):
    assert(x_i in L)
    assert(all(L.count(x_j) <= 1 for x_j in L))
    numerator = 1
    denominator = 1
    for x_j in L:
        if x_j == x_i: continue
        numerator = (numerator * x_j) % GROUP_ORDER
        denominator = (denominator * ((x_j - x_i) % GROUP_ORDER)) % GROUP_ORDER
    denom_inv = scalar_inv(denominator)
    return (numerator * denom_inv) % GROUP_ORDER

def recover_secret(signer_indices, shares):
    interpolated_shares = []
    t = len(shares)
    assert(len(signer_indices) == t)
    for i in range(t):
        l = derive_interpolating_value(signer_indices, signer_indices[i])
        interpolated_shares += [(l * shares[i]) % GROUP_ORDER]
    recovered_secret = scalar_add_multi(interpolated_shares)
    return recovered_secret

def test_recover_secret():
    f = [23, 42]
    shares = [polynomial_evaluate(f, i) for i in [1, 2, 3]]
    assert(recover_secret([1,2], [shares[0], shares[1]]) == f[0])
    assert(recover_secret([1,3], [shares[0], shares[2]]) == f[0])
    assert(recover_secret([2,3], [shares[1], shares[2]]) == f[0])

def dkg_correctness(t, n, simulate_dkg):
    Eq = lambda x: True
    seeds = [secrets.token_bytes(32) for _ in range(n)]

    dkg_outputs = simulate_dkg(seeds, t, n, Eq)
    assert(all([out != False for out in dkg_outputs]))
    shares = [out[0] for out in dkg_outputs]
    shared_pubkeys = [out[1] for out in dkg_outputs]
    signer_pubkeys = [out[2] for out in dkg_outputs]

    # Check that the shared pubkey and signer_pubkeys are the same for all
    # participants
    assert(len(set(shared_pubkeys)) == 1)
    shared_pubkey = shared_pubkeys[0]
    for i in range(1, n):
        assert(signer_pubkeys[0] == signer_pubkeys[i])

    # Check that the share corresponds to the signer_pubkey
    for i in range(n):
        assert(point_mul(G, shares[i]) == signer_pubkeys[0][i])

    # Check that the first t signers (TODO: should be an arbitrary set) can
    # recover the shared pubkey 
    recovered_secret = recover_secret(list(range(1, t+1)), shares[0:t])
    assert(point_mul(G, recovered_secret) == shared_pubkey)

def test_simplpedpop_correctness():
    for t in range(1, 3):
        for n in range(t, 2*t + 1):
            dkg_correctness(t, n, simulate_simplpedpop)

test_vss_correctness()
test_recover_secret()
test_simplpedpop_correctness()
dkg_correctness(2, 3, simulate_encpedpop)