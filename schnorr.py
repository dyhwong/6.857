import requests
import json
import random
from hashlib import sha256
import binascii

SERVER_URL = "http://6857rsa.csail.mit.edu:8080"
TEAM = "dyhwong,stewarta,tzhan,virdi"

def main():
    part_a()
    part_b()
    # part_c: SHA256 produces a 256-bit value output and is collision resistant because it can be modelled as a random oracle so we would have to find a collision for SHA256(c.parent_hash) + SHA256(c.code_diff) + SHA256(c.author). Since each of these values has a fixed length, namely 256 bits, we cannot find a collision by moving bits from SHA256(c.code_diff) to SHA256(c.author). Hence, we must find collision for each of inner SHA256 values. Since SHA256 is collision resistant, we can conclude that H2 is collision resistant.
    part_d()

def part_a():
    h0_collision = {
            "commit_one": {
                "parent_hash": "440d75ea21ebbbed9360f4b268d3caa7aa22736c195763aa2b42dceb7d933463",
                "code_diff": "<Fix for CVE-2016-XXXX>",
                "author": TEAM
                },
            "commit_two": {
                "parent_hash": "440d75ea21ebbbed9360f4b268d3caa7aa22736c195763aa2b42dceb7d933463",
                "code_diff": "",
                "author": "<Fix for CVE-2016-XXXX>" + TEAM
                },
            }
    r = requests.post(SERVER_URL + "/H0/collision", data=json.dumps(h0_collision))
    print(r.text)

def part_b():
    h1_collision = {
            "commit_one": {
                "parent_hash": "440d75ea21ebbbed9360f4b268d3caa7aa22736c195763aa2b42dceb7d933463",
                "code_diff": "||<Fix for CVE-2016-XXXX>",
                "author": TEAM
                },
            "commit_two": {
                "parent_hash": "440d75ea21ebbbed9360f4b268d3caa7aa22736c195763aa2b42dceb7d933463",
                "code_diff": "",
                "author": "|<Fix for CVE-2016-XXXX>|" + TEAM
                },
            }
    r = requests.post(SERVER_URL + "/H1/collision", data=json.dumps(h1_collision))
    print(r.text)


##########################################################
#   Schnorr Signature Utility Functions and Parameters   #
##########################################################

#   g generates a subgroup of order q in Zp* s.t.  p = qr + 1
p = int("911751a4cf97698ea1b838bd667bff15586475737ed460fd1b107f3a3b9584ec4830d538220a8960663aa271aa86fe8a5c42b27f6f336a82e3e19ac1ba735c829d560a81ad5d81b2cf83eb1ae7ee56ca969e4f05c1f1a92d33d3363379c3ac8aa19db6bc0e30649260c3458630af9caf328a2e8b5dc24acf070ebc3f500bc111", 16)
q = int("d7f56c5297e7425fd701440305fad0bbb8a88498edd6d52ef89d11472e8e0851", 16)
g = int("27dfb89f51a160d90a32eee926e96dff7abf98634181acb0a77ba4f7f6bca962e3449dd2372d500be28f61b0daf24cb1368d0fd1392cc85c4eb5c20440b9f7421754c7b1ee01f0553dd847decb60bb2ae8e749197d8d462fdae1278206b3a7e56b9ba0f84d53cdaf535270eb2c90ed2c61c3ea4d1521cad87701d554be02df5f", 16)

#   computes e = H(M || hex(r))
def H(hashed_commit_hex_string, r_int):
    hex_encoded_r = hex(r_int).encode("utf-8")[2:] # removes the 0x
    H_of_M_concat_r = sha256(hashed_commit_hex_string + hex_encoded_r).digest()
    return int.from_bytes(H_of_M_concat_r, byteorder="big")

#   Hashes, then hex encodes the input
def SHA256hex(x):
    if isinstance(x, str):
        #   always encode unicode strings to raw bytes
        x = x.encode("utf-8")
    return binascii.hexlify(sha256(x).digest())

#   Bob's latest and greatest commit hash function
def H2(c):
    a = SHA256hex(c["parent_hash"])
    b = SHA256hex(c["code_diff"])
    c = SHA256hex(c["author"])
    return SHA256hex(a + b + c)

def part_d():
    commit_d = {
            "parent_hash": "440d75ea21ebbbed9360f4b268d3caa7aa22736c195763aa2b42dceb7d933463",
            "code_diff": "...my code changes...",
            "author": TEAM,
            }
    #   TODO: generate a random Schnorr signing key and signing randomness, then
    #   sign commit_d's hash
    #   Note: random.randint(1, n) draws random integer in [1,n]
    #   Note: pow(a, b, m) computes a**b mod m

    # key generation
    x = random.randint(1, q - 1)
    y = pow(g, x, p)

    # signing
    k = random.randint(1, q - 1)
    r_int = pow(g, k, p)

    M = H2(commit_d)
    e = H(M, r_int) % q
    s = (k - x * e) % q

    # verifying
    r_v = (pow(g, s, p) * pow(y, e, p)) % p
    e_v = H(M, r_v) % q
    assert(e_v == e)

    #   Submit to server and print result
    signature_request = {
            "commit": commit_d,
            "signature": {
                "y": hex(y)[2:],
                "e": hex(e)[2:],
                "s": hex(s)[2:],
                },
            }
    r = requests.post(SERVER_URL + "/H2/signature", data=json.dumps(signature_request))
    print(r.text)

if __name__ == "__main__":
    main()
