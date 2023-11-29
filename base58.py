alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

max_int = 0x1ffffffffff
max_token = "zmM9z4E"


def encode(input: int) -> str:
    if input < 0 or input > max_int:
        raise ValueError(f"Expected integer between 0 and {max_int}, got {input}")

    result = ""
    num = input
    for i in range(7):
        num, rem = divmod(num, 58)
        result = alphabet[rem] + result
    assert num == 0
    return result


def decode(input: str) -> int:
    if len(input) != 7:
        raise ValueError(
            f"Expected token of length 7, got token of length {len(input)}"
        )

    if input > max_token:
        raise ValueError("Token is too big to decode into a 64-bit integer", input)

    result = 0
    for ch in input:
        result *= 58
        index = alphabet.index(ch)
        result += index
    return result
