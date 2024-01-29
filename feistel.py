from typing import List
import base58
import hmac
import hashlib


def sha256(msg: bytes) -> bytes:
    return hashlib.sha256(msg).digest()


def kdf(key: bytes, msg: bytes) -> bytes:
    return hmac.digest(key, msg, hashlib.sha256)


def rf(key: bytes, msg: int) -> int:
    digest = kdf(key, msg.to_bytes(8, "little"))
    result = int.from_bytes(digest[:6], "little") & 0x1FFFFFFFFFF
    return result


class Cipher:
    rounds: int = 22
    round_keys: List[bytes] = []

    def __init__(self, key):
        assert len(key) >= 32
        key = sha256(key)
        for i in range(self.rounds):
            self.round_keys.append(kdf(key, 8 * i.to_bytes(8, "little")))

    def encrypt(self, val: int, tweak=b"") -> str:
        # 4321098765432109876543210987654321098765432109876543210987654321
        # leftleftleftleftleftleftleftleftrightrightrightrightrightrightri
        # 10987654321098765432109876543210987654321
        # leftleftleftleftleftleftleftleft000000000
        # 000000000rightrightrightrightrightrightri

        left = (val & 0xFFFFFFFF00000000) >> 23
        right = val & 0x00000000FFFFFFFF

        for i in range(2):
            left, right = right, left ^ rf(kdf(self.round_keys[i], tweak), right)

        for i in range(2, self.rounds - 2):
            left, right = right, left ^ rf(self.round_keys[i], right)

        for i in range(self.rounds - 2, self.rounds):
            left, right = right, left ^ rf(kdf(self.round_keys[i], tweak), right)

        return base58.encode(left) + base58.encode(right)

    def decrypt(self, val: str, tweak=b"") -> int:
        left = base58.decode(val[:7])
        right = base58.decode(val[7:])

        for i in reversed(range(self.rounds - 2, self.rounds)):
            left, right = right ^ rf(kdf(self.round_keys[i], tweak), left), left

        for i in reversed(range(2, self.rounds - 2)):
            left, right = right ^ rf(self.round_keys[i], left), left

        for i in reversed(range(2)):
            left, right = right ^ rf(kdf(self.round_keys[i], tweak), left), left

        left_zeroes = left & ~0x1FFFFFFFE00
        right_zeroes = right & ~0xFFFFFFFF
        if left_zeroes or right_zeroes:
            raise ValueError("invalid ciphertext")

        return (left << 23) ^ right


if __name__ == "__main__":
    import timeit

    key = b"helloworld"
    tweak = b"tweak"

    c = Cipher(key)
    print(c.encrypt(123, tweak))
    # print(c.decrypt("fQgf7J8qHgBcd4", tweak))
    try:
        print(c.decrypt("89dyeYRed4bfH6", tweak))
    except ValueError:
        pass

    print(c.encrypt(0xFFFFFFFFFFFFFFFF))
    try:
        print(c.decrypt("zmM9yuR17YXq9G"))
    except ValueError:
        pass

    for i in range(0, 0xFFFFFFFFFFFFFFFF, 0x50505050505050):
        assert i == c.decrypt(c.encrypt(i))

    tweak = b"tweak"

    def bench():
        c = Cipher(b"helloworld")
        c.decrypt(c.encrypt(123, tweak), tweak)

    print(timeit.Timer(bench).timeit(number=1000), "ms")
    print("")
