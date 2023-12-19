# Encoding

base58 is URL-safe and compact.

Using any encoding using letters makes it possible to end up with dirty words in the token. An alternative would be to use numbers, or numbers and letters alternating.

# Length

We would like to support 64-bits integers, as these are widely used in databases and programming languages. [Paragon](https://paragonie.com/blog/2015/09/comprehensive-guide-url-parameter-encryption-in-php) suggests tokens of 72 bits. Larger is more secure, but less usable for URLs.

If we use base58 encoding, we need at least 13 chars for 72 bits. With base58 encoding, 41 bits fits almost in 7 characters, which would make 14 characters more optimal.

# Number of rounds

Dunkelman 2020:

> This means that for FF1 and FF3-1 the number of rounds should be at least 18

It would make sense to desire 64-bit security. With 82 bits, this would be ~4/5n bits, which would require 6 x 4 = 24 rounds (or 22 if exact).

# Tweak combination

DV 2017:

> Our attack exploits the “bad domain separation” in FF3.

> As a quick fix, we can propose to change the length of the tweak in FF3 so that
the adversary has no longer control on what is XORed to the round index. The
same should hold if some other part of the tweak is XORed to a counter in a
CBC mode, as proposed by the authors of the construction. We obtain a
scheme with a shorter tweak, to which we concatenate the round index instead
of XORing it.

# HMAC related key attack

Peyrin 2012:

> Our proposed solution is instead to force an extra fixed bit (or byte) before the input message M.

# Implicit zero check 

32 bits encrypt encrypt into 41 bits. 41 bits decrypt into 32 bits, so 9 bits are thrown away. These bits should be checked, but not explicitly as this will give an oracle.

This doesn't seem possible. If we map 82 bits into 64 bits, some collisions are going to occur. We could:

* distribute collisions evenly over 64 bits
* err towards higher numbers, assuming that valid numbers are low
* throw an exception, but this will likely provide an oracle giving information on 18 bits after at most 2^18 queries
* return null or 0 or -1
* return negative numbers (what about zero?)

# Endianness

Should we use little endian so we don't need any conversion?

# Performance

Goals:

- construction, encryption and decryption in less than 1ms
- changing tweak is cheaper than changing key

# References

1. [Bellare, M., Rogaway, P., & Spies, T. (2010). The FFX mode of operation for format-preserving encryption. NIST submission, 20(19), 1-18](https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/ffx/ffx-spec.pdf)
1. [Durak, F. B., & Vaudenay, S. (2017, July). Breaking the FF3 format-preserving encryption standard over small domains. In Annual international cryptology conference (pp. 679-707). Cham: Springer International Publishing](https://infoscience.epfl.ch/record/231304/files/fpe_bps.pdf)
1. [Dunkelman, O., Kumar, A., Lambooij, E., & Sanadhya, S. K. (2020). Cryptanalysis of Feistel-based format-preserving encryption. Cryptology ePrint Archive](https://eprint.iacr.org/2020/1311.pdf)
1. [Yan, H., Wang, L., Shen, Y., & Lai, X. (2020, August). Tweaking Key-Alternating Feistel Block Ciphers. In International Conference on Applied Cryptography and Network Security (pp. 69-88). Cham: Springer International Publishing](https://infoscience.epfl.ch/record/279641/files/ACNS%202020.pdf)
1. [Peyrin, T., Sasaki, Y., & Wang, L. (2012). Generic related-key attacks for HMAC. In Advances in Cryptology–ASIACRYPT 2012: 18th International Conference on the Theory and Application of Cryptology and Information Security, Beijing, China, December 2-6, 2012. Proceedings 18 (pp. 580-597). Springer Berlin Heidelberg](https://eprint.iacr.org/2012/684.pdf)
