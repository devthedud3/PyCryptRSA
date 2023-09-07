import math
import random
from gmpy2 import f_mod

_random = random.SystemRandom()


class RSA:
    def __init__(self):
        self.key = []
        self.cache = {}

    def ext_euclidean(self, x, y):
        if y == 0:
            d, s, t = x, 1, 0
        else:
            d, p, q = self.ext_euclidean(y, x % y)
            s = q
            t = p - q * (x // y)
        return d, s, t

    def prime_factorize(self, n):
        n = n - 1 if int(str(n)[-1]) % 2 != 0 else n
        _prime = []
        u = 1
        while (n % 2) == 0:
            p = 2
            _prime.append(p)
            n /= p
        sqrt_n = int(math.sqrt(n)) + 1
        for p in range(3, sqrt_n, 2):
            while (n % p) == 0:
                _prime.append(p)
                n /= p
        if n > sqrt_n - 1:
            p = n
            _prime.append(p)
        k = _prime.count(2)
        for i in list(filter(lambda x: x > 2, _prime)):
            u *= i

        return int(u), k

    def miller_rabin(self, n, s):
        exp, k = self.prime_factorize(n)
        for i in range(1, s):
            a = _random.randint(2, n - 2)
            res = self.powmod_sm(a, exp, n)
            if res not in [1, n - 1]:
                for j in range(1, k - 1):
                    res = self.powmod_sm(res, res, n)
                    if res == 1:
                        return False
                if res != n - 1:
                    return False
        return True

    def powmod_sm(self, x, y, mod):
        exp = format(y, 'b')
        value = x
        for i in exp[1:]:
            value = f_mod(value * value, mod)
            if i == '1':
                value = f_mod(value * x, mod)
        return value

    def keygen(self, s):
        pq = []
        while len(pq) < 2:
            a = _random.randint(2**14, 2**30)
            if self.miller_rabin(a, s) and a not in pq:
                pq.append(a)

        n = pq[0] * pq[1]
        phi_n = (pq[0] - 1) * (pq[1] - 1)
        while True:
            e = _random.randint(1, phi_n - 1)
            gcd, s, d = self.ext_euclidean(phi_n, e)
            if gcd == 1 and d > 0:
                self.cache["n"], self.cache["e"], self.cache["d"] = hex(n), hex(e), hex(d)
                print("Public Key: %s, %s\nPrivate Key: %s" % (format(n, '#x'), format(e, '#x'), format(d, '#x')))
                return [n, e], [n, d]

    def encrypt(self, pt,  keys=None):
        self.key = self.keygen(512)
        pub_key = self.key[0] if not keys else list(map(lambda key: eval(key), keys))
        assert pt
        res = self.powmod_sm(pt, pub_key[1], pub_key[0])
        self.cache["ct"] = hex(res)
        print("Ciphertext: %s" % format(res, '#x'))
        return res

    def decrypt(self, ct=None, keys=None):
        private_key = [self.key[0][0], self.key[1][0]] if not keys else list(map(lambda key: eval(str(key)), keys))
        assert ct or self.cache["ct"]
        cipher = self.cache["ct"] if not ct else eval(str(ct))
        res = self.powmod_sm(cipher, private_key[1], private_key[0])
        print("Plaintext: %s" % res)
        return res


if __name__ in ["__main__", "__live_coding__"]:
    r = RSA()
    cipherText = 0x24fc86fe9cbeb43
    pk = [0x268eb2a78013e89, 0x8940dfbcaff063]
    r.decrypt(cipherText, pk)

