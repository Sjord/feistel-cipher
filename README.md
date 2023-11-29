41 bits -> 7 base58 chars

Dunkelman 2020:

> This means that for FF1 and FF3-1 the number of rounds should be at least 18

DV 2017:

> Our attack exploits the “bad domain separation” in FF3.

> As a quick fix, we can propose to change the length of the tweak in FF3 so that
the adversary has no longer control on what is XORed to the round index. The
same should hold if some other part of the tweak is XORed to a counter in a
CBC mode, as proposed by the authors of the construction. We obtain a
scheme with a shorter tweak, to which we concatenate the round index instead
of XORing it.

Implicit zero check

32 bits encrypt encrypt into 41 bits. 41 bits decrypt into 32 bits, so 9 bits are thrown away. These bits should be checked, but not explicitly as this will give an oracle.

Peyrin 2012:

> Our proposed solution is instead to force an extra fixed bit (or byte) before the input message M.

1. [Bellare, M., Rogaway, P., & Spies, T. (2010). The FFX mode of operation for format-preserving encryption. NIST submission, 20(19), 1-18](https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/ffx/ffx-spec.pdf)
1. [Durak, F. B., & Vaudenay, S. (2017, July). Breaking the FF3 format-preserving encryption standard over small domains. In Annual international cryptology conference (pp. 679-707). Cham: Springer International Publishing](https://infoscience.epfl.ch/record/231304/files/fpe_bps.pdf)
1. [Dunkelman, O., Kumar, A., Lambooij, E., & Sanadhya, S. K. (2020). Cryptanalysis of Feistel-based format-preserving encryption. Cryptology ePrint Archive](https://eprint.iacr.org/2020/1311.pdf)
1. [Yan, H., Wang, L., Shen, Y., & Lai, X. (2020, August). Tweaking Key-Alternating Feistel Block Ciphers. In International Conference on Applied Cryptography and Network Security (pp. 69-88). Cham: Springer International Publishing](https://infoscience.epfl.ch/record/279641/files/ACNS%202020.pdf)
1. [Peyrin, T., Sasaki, Y., & Wang, L. (2012). Generic related-key attacks for HMAC. In Advances in Cryptology–ASIACRYPT 2012: 18th International Conference on the Theory and Application of Cryptology and Information Security, Beijing, China, December 2-6, 2012. Proceedings 18 (pp. 580-597). Springer Berlin Heidelberg](https://eprint.iacr.org/2012/684.pdf)
