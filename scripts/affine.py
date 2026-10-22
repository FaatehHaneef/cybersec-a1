"""
affine.py - shared affine-cipher maths for the PsycoSupport analysis.

Affine cipher over Z_26 (A=0 ... Z=25):
    encrypt  E(x) = (a*x + b) mod 26
    decrypt  D(y) = a^-1 * (y - b) mod 26,   valid only when gcd(a, 26) = 1

PsycoSupport uses it in two ways:
  * Server -> Client: plain affine on the letters of an uppercase reply
    (spaces kept, punctuation stripped).
  * Client -> Server: each character is first written as two hex digits
    (e.g. 'e' = 0x65 -> digits 6, 5); each digit (0-15) is then treated as a
    letter index and affine-encrypted. So every plaintext character becomes
    two cipher letters.
"""
from math import gcd

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Standard English letter frequencies (%), A..Z (Lewand, "Cryptological Mathematics").
ENGLISH_FREQ = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
                0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
                6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074]

VALID_A = [a for a in range(1, 26) if gcd(a, 26) == 1]  # 12 values


def num(ch):
    return ord(ch.upper()) - 65


def letter(n):
    return ALPHABET[n % 26]


def egcd_steps(a, m=26):
    """Extended Euclid. Returns (inverse or None, list of human-readable steps)."""
    steps = []
    r0, r1, s0, s1 = m, a % m, 0, 1
    while r1:
        q = r0 // r1
        steps.append(f"{r0} = {q}*{r1} + {r0 - q * r1}")
        r0, r1 = r1, r0 - q * r1
        s0, s1 = s1, s0 - q * s1
    if r0 != 1:
        return None, steps
    return s0 % m, steps


def modinv(a, m=26):
    return egcd_steps(a, m)[0]


def decrypt_letters(text, a, b):
    ai = modinv(a)
    return "".join(letter(ai * (num(c) - b)) if c.isalpha() else c for c in text)


def encrypt_letters(text, a, b):
    return "".join(letter(a * num(c) + b) if c.isalpha() else c for c in text)


def letter_counts(text):
    letters = [c for c in text.upper() if c.isalpha()]
    return {ch: letters.count(ch) for ch in ALPHABET}, len(letters)


def chi_squared(text):
    """How far a text's letter distribution is from English (lower = more English)."""
    counts, n = letter_counts(text)
    if n == 0:
        return float("inf")
    return sum((counts[ch] - n * f / 100) ** 2 / (n * f / 100)
               for ch, f in zip(ALPHABET, ENGLISH_FREQ))


def solve_key(p1, c1, p2, c2):
    """
    Solve  a*p1 + b = c1,  a*p2 + b = c2  (mod 26)  for (a, b).
    Subtracting gives a*(p1 - p2) = (c1 - c2) mod 26. Returns every solution
    with gcd(a, 26) = 1 (there can be 0, 1 or several when p1 - p2 is not
    invertible mod 26).
    """
    d, e = (p1 - p2) % 26, (c1 - c2) % 26
    return [(a, (c1 - a * p1) % 26) for a in VALID_A if (a * d) % 26 == e]


# ---- Client -> Server hex layer -------------------------------------------

def client_decrypt(text, a, b):
    """Undo the client scheme: letters -> hex digits -> characters. None if invalid."""
    letters = [c for c in text if c.isalpha()]
    ai = modinv(a)
    digits = [(ai * (num(c) - b)) % 26 for c in letters]
    if len(digits) % 2 or any(d > 15 for d in digits):
        return None
    return "".join(chr(16 * digits[i] + digits[i + 1]) for i in range(0, len(digits), 2))


def client_encrypt(text, a, b):
    return "".join(letter(a * int(h, 16) + b) for ch in text for h in f"{ord(ch):02x}")


def pairs(text):
    letters = [c for c in text if c.isalpha()]
    return [letters[i] + letters[i + 1] for i in range(0, len(letters) - 1, 2)]


# ---- Key schedule observed in this lab --------------------------------------

def key_for_mood(mood):
    """Key schedule recovered by this analysis: a = 2*mood + 1, b = 2*mood (mod 26)."""
    return (2 * mood + 1) % 26, (2 * mood) % 26
