import base58
import hmac


def kdf(key, msg):
    return hmac.digest(key, b"F" + msg, "sha256")

def rf(key, msg):
    digest = kdf(key, msg.to_bytes(6, "big"))
    result = int.from_bytes(digest[:6], "big") & 0x1ffffffffff
    return result

class Cipher:
    rounds = 18
    round_keys = []

    def __init__(self, key):
        for i in range(self.rounds):
            # hashing only i should be sufficient, but could make related-key attacks easier
            # so make sure more bits are flipped in the message
            # is this necessary?
            val = 332937403377012377 + i * 6565350101298335 % 461168601842738001
            self.round_keys.append(kdf(key, val.to_bytes(8, "big")))

    def encrypt(self, val: int, tweak=b""):
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


    def decrypt(self, val: str, tweak=b""):
        left = base58.decode(val[:7])
        right = base58.decode(val[7:])

        for i in reversed(range(self.rounds - 2, self.rounds)):
            left, right = right ^ rf(kdf(self.round_keys[i], tweak), left), left

        for i in reversed(range(2, self.rounds - 2)):
            left, right = right ^ rf(self.round_keys[i], left), left

        for i in reversed(range(2)):
            left, right = right ^ rf(kdf(self.round_keys[i], tweak), left), left

        return (left << 23) ^ right
    

if __name__ == "__main__":
    import timeit

    c = Cipher(b"helloworld")
    print(c.encrypt(123, b"twea"));
    print(c.decrypt("11111111111138"))

    print(c.encrypt(0xFFFFFFFFFFFFFFFF));
    print(c.decrypt("zmM9yuR17YXq9G"));

    for i in range(0, 0xFFFFFFFFFFFFFFFF, 0x50505050505050):
        assert i == c.decrypt(c.encrypt(i))

    tweak = b"tweak"
    def bench():
        c = Cipher(b"helloworld")
        c.decrypt(c.encrypt(123, tweak), tweak)

    print(timeit.Timer(bench).timeit(number=10000))
    print("")
