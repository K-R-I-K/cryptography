from random import randrange
from hashlib import sha1
from gmpy2 import xmpz, to_binary, invert, powmod, is_prime


def generate_p_q(L, N):
    bits_per_chunk = N  # g >= 160
    num_chunks = (L - 1) // bits_per_chunk
    remaining_bits = (L - 1) % bits_per_chunk

    while True:
        # Generate q
        while True:
            s = xmpz(randrange(1, 2  bits_per_chunk))
            a = sha1(to_binary(s)).hexdigest()
            zz = xmpz((s + 1) % (2  bits_per_chunk))
            z = sha1(to_binary(zz)).hexdigest()
            U = int(a, 16) ^ int(z, 16)
            mask = 2  (N - 1) + 1
            q = U | mask
            if is_prime(q, 20):
                break

        # Generate p
        counter = 0
        offset = 2
        while counter < 4096:
            V = []
            for k in range(num_chunks + 1):
                arg = xmpz((s + offset + k) % (2  bits_per_chunk))
                zzv = sha1(to_binary(arg)).hexdigest()
                V.append(int(zzv, 16))
            W = sum(V[qq] * 2  (bits_per_chunk * qq) for qq in range(num_chunks))
            W += (V[num_chunks] % 2  remaining_bits) * 2  (bits_per_chunk * num_chunks)
            X = W + 2  (L - 1)
            c = X % (2 * q)
            p = X - c + 1  # p = X - (c - 1)
            if p >= 2 ** (L - 1) and is_prime(p, 10):
                return p, q
            counter += 1
            offset += num_chunks + 1


def generate_g(p, q):
    while True:
        h = randrange(2, p - 1)
        exp = xmpz((p - 1) // q)
        g = powmod(h, exp, p)
        if g > 1:
            break
    return g


def generate_keys(g, p, q):
    x = randrange(2, q)  # x < q
    y = powmod(g, x, p)
    return x, y


def generate_params(L, N):
    p, q = generate_p_q(L, N)
    g = generate_g(p, q)
    return p, q, g


def sign(M, p, q, g, x):
    if not validate_params(p, q, g):
        raise Exception("Invalid parameters")

    while True:
        k = randrange(2, q)  # k < q
        r = powmod(g, k, p) % q
        m = int(sha1(M).hexdigest(), 16)
        try:
            s = (invert(k, q) * (m + x * r)) % q
            return r, s
        except ZeroDivisionError:
            pass


def verify(M, r, s, p, q, g, y):
    if not validate_params(p, q, g):
        raise Exception("Invalid parameters")
    if not validate_sign(r, s, q):
        return False
    try:
        w = invert(s, q)
    except ZeroDivisionError:
        return False
    m = int(sha1(M).hexdigest(), 16)
    u1 = (m * w) % q
    u2 = (r * w) % q
    v = (powmod(g, u1, p) * powmod(y, u2, p)) % p % q
    return v == r


def validate_params(p, q, g):
    if is_prime(p) and is_prime(q):
        return True
    if powmod(g, q, p) == 1 and g > 1 and (p - 1) % q:
        return True
    return False


def validate_sign(r, s, q):
    return 0 < r < q and 0 < s < q


def main():
    N = 160
    L = 1024
    p, q, g = generate_params(L, N)
    x, y = generate_keys(g, p, q)

    text = "secret info"
    M = str.encode(text, "ascii")
    r, s = sign(M, p, q, g, x)
    if verify(M, r, s, p, q, g, y):
        print('Verify true')


if name == "main":
    main()