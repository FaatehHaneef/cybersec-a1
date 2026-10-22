#!/usr/bin/env python3
"""
decrypt.py - general PsycoSupport decryptor (any mood, either direction).

How it picks the key:
  1. If --mood is given, use the recovered key schedule
         a = 2*mood + 1,  b = 2*mood   (mod 26)
     which held for every mood tested (2, 5, 8, 10) in both directions.
  2. Otherwise (or if the scheduled key is invalid, e.g. gcd(a, 26) != 1),
     search all 312 valid keys:
       - server text: pick the key whose output is most English-like (chi-squared)
       - client text: pick the key that turns the letter pairs into readable ASCII
  Direction is auto-detected if not given: client ciphertexts are an even run of
  letters with no word breaks pattern and use at most 16 distinct letters.

The username does not change the key (it only appears as the first word of
every server reply, which is a useful known-plaintext crib).

Examples:
  python scripts/decrypt.py "NKKLCJ UL AIWXRA BUQC OIWPC" --mood 5
  python scripts/decrypt.py "YXOEIIIDIDIM"
  python scripts/decrypt.py --csv ciphertexts.csv
"""
import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from affine import (VALID_A, chi_squared, client_decrypt, decrypt_letters,  # noqa: E402
                    key_for_mood)


def detect_direction(text):
    letters = [c for c in text if c.isalpha()]
    return "client" if len(set(letters)) <= 16 and len(letters) % 2 == 0 and text.count(" ") <= 1 else "server"


def readable(s):
    return s is not None and all(ch.isprintable() for ch in s)


def solve(text, direction, mood=None):
    """Return ((a, b), plaintext, method)."""
    if mood is not None:
        a, b = key_for_mood(mood)
        if a in VALID_A:
            plain = decrypt_letters(text, a, b) if direction == "server" else client_decrypt(text, a, b)
            if direction == "server" or readable(plain):
                return (a, b), plain, f"key schedule for mood {mood}"
    keys = [(a, b) for a in VALID_A for b in range(26)]
    if direction == "server":
        a, b = min(keys, key=lambda k: chi_squared(decrypt_letters(text, *k)))
        return (a, b), decrypt_letters(text, a, b), "exhaustive search (chi-squared)"
    for a, b in keys:
        plain = client_decrypt(text, a, b)
        if readable(plain) and sum(ch.isalpha() or ch == " " for ch in plain) / len(plain) > 0.9:
            return (a, b), plain, "exhaustive search (valid ASCII)"
    return None, None, "no key found"


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("ciphertext", nargs="?")
    p.add_argument("--mood", type=int)
    p.add_argument("--direction", choices=["client", "server"])
    p.add_argument("--csv", help="decrypt every row of ciphertexts.csv (mood ignored, key searched)")
    args = p.parse_args()

    if args.csv:
        for row in csv.DictReader(open(args.csv, encoding="utf-8")):
            direction = detect_direction(row["ciphertext"])
            key, plain, method = solve(row["ciphertext"], direction)
            match = "matches schedule" if key == key_for_mood(int(row["mood"])) else "DIFFERS from schedule"
            print(f"{row['id']} [{direction}, mood {row['mood']}] key {key} via {method} ({match})\n    {plain[:90]}")
        return
    if not args.ciphertext:
        p.error("give a ciphertext or --csv")
    direction = args.direction or detect_direction(args.ciphertext)
    key, plain, method = solve(args.ciphertext, direction, args.mood)
    print(f"direction: {direction}\nkey (a, b): {key}  [{method}]\nplaintext: {plain}")


if __name__ == "__main__":
    main()
