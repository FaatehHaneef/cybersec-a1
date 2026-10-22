#!/usr/bin/env python3
"""
crack_keys.py - recover the affine keys (a, b) from the ciphertexts alone,
showing every step, then decrypt all sessions.

Ciphertexts are grouped by (direction, mood), because the capture showed that
the same mood gives the same key (S1 and S3 start identically).

Server -> Client (plain affine on letters):
  1. Rank cipher letters by frequency. Hypothesis: most frequent = 'E'.
  2. Pair it with each of the next most frequent cipher letters as T/A/O/I/N.
  3. Solve the two linear congruences for (a, b); drop keys with gcd(a,26) != 1.
  4. Decrypt with each candidate and score it against English (chi-squared).
  5. Keep the best; confirm with an exhaustive search over all 312 keys.

Client -> Server (hex layer, two letters per character):
  1. Count letter PAIRS. Hypothesis: most frequent pair = space = 0x20,
     i.e. digits (2, 0).
  2. Solve a*2 + b = c1, a*0 + b = c2 (mod 26). Because 2 is not invertible
     mod 26 this gives 0 or 2 candidates for a.
  3. Keep the candidate whose decryption is valid (all digits <= 15) and readable.

Outputs: output/key_derivation.md, output/decryptions.md, output/keys.json,
         output/figures/verify_mood<m>.png

Usage:  python scripts/crack_keys.py ciphertexts.csv output
"""
import csv
import json
import os
import sys
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from affine import (ALPHABET, ENGLISH_FREQ, VALID_A, chi_squared, client_decrypt,  # noqa: E402
                    decrypt_letters, egcd_steps, key_for_mood, letter, letter_counts,
                    modinv, num, pairs, solve_key)

CIPHER, ENGLISH, MUTED, GRID = "#2a78d6", "#eb6834", "#898781", "#e1e0d9"
SECOND_GUESSES = "TAOIN"   # common English letters tried as the 2nd mapping
CANDIDATE_DEPTH = 5        # how many next-ranked cipher letters to try


def inverse_working(x):
    inv, steps = egcd_steps(x)
    lines = [f"  - Euclid on (26, {x}): " + "; ".join(steps)]
    if inv is None:
        lines.append(f"  - gcd(26, {x}) != 1, so {x} has no inverse mod 26")
    else:
        lines.append(f"  - back-substituting gives {x}^-1 = {inv} (check: {x} x {inv} = {x * inv} = "
                     f"{x * inv // 26}x26 + 1 = 1 mod 26)")
    return lines


def show_equations(p1, c1, p2, c2):
    """Markdown lines solving a*p1+b=c1, a*p2+b=c2 step by step."""
    P1, C1, P2, C2 = (letter(v) for v in (p1, c1, p2, c2))
    d, e = (p1 - p2) % 26, (c1 - c2) % 26
    out = [f"- Mapping {P1}->{C1}: a*{p1} + b = {c1} (mod 26)",
           f"- Mapping {P2}->{C2}: a*{p2} + b = {c2} (mod 26)",
           f"- Subtract: a*({p1} - {p2}) = {c1} - {c2}  =>  {d}a = {e} (mod 26)"]
    inv, _ = egcd_steps(d)
    if inv is not None:
        out += [f"- {d} is invertible mod 26:"] + inverse_working(d)
        a = (inv * e) % 26
        out.append(f"- a = {inv} x {e} mod 26 = {inv * e} mod 26 = **{a}**")
    else:
        sols = [a for a in range(26) if (a * d) % 26 == e]
        out.append(f"- gcd({d}, 26) != 1, so solve by testing a = 0..25: solutions a in {sols or 'none'}")
    return out


def crack_server(group_id, rows):
    text = " ".join(r["ciphertext"] for r in rows)
    counts, n = letter_counts(text)
    ranked = sorted(ALPHABET, key=lambda c: (-counts[c], c))
    md = [f"### {group_id}: Server -> Client, mood {rows[0]['mood']} ({', '.join(r['id'] for r in rows)}; {n} letters)",
          "",
          f"Most frequent cipher letters: " + ", ".join(f"{c} ({100 * counts[c] / n:.1f}%)" for c in ranked[:6]),
          "",
          f"**Hypothesis 1:** the most frequent cipher letter **{ranked[0]}** is plaintext **E** (12.7% in English).",
          "Pair it with the next most frequent cipher letters as common English letters and test every candidate:",
          "",
          "| # | Mapping 1 | Mapping 2 | Solved (a, b) | gcd(a,26)=1? | chi^2 of decryption | Decryption starts |",
          "|---:|:---:|:---:|:---:|:---:|---:|:---|"]
    candidates = []
    i = 0
    for c2 in ranked[1:1 + CANDIDATE_DEPTH]:
        for p2 in SECOND_GUESSES:
            i += 1
            sols = solve_key(num("E"), num(ranked[0]), num(p2), num(c2))
            if not sols:
                md.append(f"| {i} | E->{ranked[0]} | {p2}->{c2} | none | no | - | - |")
                continue
            for a, b in sols:
                plain = decrypt_letters(text, a, b)
                chi = chi_squared(plain)
                candidates.append((round(chi, 6), i, a, b, p2, c2))  # ties -> first tested
                md.append(f"| {i} | E->{ranked[0]} | {p2}->{c2} | ({a}, {b}) | yes | {chi:.1f} | `{plain[:30]}` |")

    chi, _, a, b, p2, c2 = min(candidates)
    md += ["", f"**Best candidate:** E->{ranked[0]} and {p2}->{c2} give **(a, b) = ({a}, {b})** "
               f"with chi^2 = {chi:.1f} (English-like text scores low; wrong keys score in the hundreds or thousands).",
           "", "**Working for the chosen key:**", ""]
    md += show_equations(num("E"), num(ranked[0]), num(p2), num(c2))
    md += [f"- b = {num(ranked[0])} - {a}x4 mod 26 = **{b}**",
           f"- Check gcd({a}, 26) = 1, so the key is valid. Decryption needs a^-1:"]
    md += inverse_working(a)
    ai = modinv(a)
    md += [f"- Decryption rule: **D(y) = {ai}(y - {b}) mod 26**", ""]

    brute = sorted((chi_squared(decrypt_letters(text, ka, kb)), ka, kb) for ka in VALID_A for kb in range(26))
    md += ["**Confirmation by exhaustive search** over all 12 x 26 = 312 valid keys (lowest chi^2 = most English-like):", ""]
    md += [f"{k + 1}. (a, b) = ({ka}, {kb}): chi^2 = {kc:.1f}" for k, (kc, ka, kb) in enumerate(brute[:3])]
    md.append("")
    return (a, b), md


def crack_client(group_id, rows):
    text = "".join(r["ciphertext"] for r in rows)
    pc = Counter(pairs(text))
    ranked = sorted(pc, key=lambda p: (-pc[p], p))
    total = sum(pc.values())
    md = [f"### {group_id}: Client -> Server, mood {rows[0]['mood']} ({', '.join(r['id'] for r in rows)}; {total} pairs)",
          "",
          f"Each plaintext character is sent as **two** cipher letters: only {len(set(c for c in text if c.isalpha()))} "
          "distinct letters appear (at most 16 are possible, one per hex digit 0-15). So the unit of frequency "
          "analysis is the letter **pair**.",
          "",
          "Most frequent pairs: " + ", ".join(f"{p} ({100 * pc[p] / total:.1f}%)" for p in ranked[:5]),
          "",
          "**Hypothesis:** the most frequent pair is the **space** character (about 15-20% of English text), "
          "ASCII 0x20, i.e. hex digits **(2, 0)**. Test the top pairs in turn:",
          ""]
    chosen = None
    for p in ranked[:3]:
        hi, lo = num(p[0]), num(p[1])
        sols = solve_key(2, hi, 0, lo)
        md.append(f"- Pair **{p}** = space: a*2 + b = {hi}, a*0 + b = {lo} => b = {lo}, 2a = {(hi - lo) % 26} (mod 26)")
        if not sols:
            md.append(f"  - 2a = {(hi - lo) % 26} has no solution with gcd(a,26)=1 "
                      f"({'odd right-hand side' if (hi - lo) % 2 else 'no valid a'}): **reject**")
            continue
        for a, b in sols:
            plain = client_decrypt(text, a, b)
            if plain is None or not all(ch.isprintable() for ch in plain):
                md.append(f"  - (a, b) = ({a}, {b}): produces digits > 15 / unprintable bytes: **reject**")
            else:
                md.append(f"  - (a, b) = ({a}, {b}): decrypts to readable text `{plain[:40]}`: **accept**")
                chosen = chosen or (a, b, p)
        if chosen:
            break
    a, b, p = chosen
    hi, lo = num(p[0]), num(p[1])
    md += ["", f"**Working for the chosen key** (pair {p} = space = digits 2, 0):", "",
           f"- From digit 0: a*0 + b = {lo}  =>  **b = {lo}**",
           f"- From digit 2: 2a + {lo} = {hi} (mod 26)  =>  2a = {(hi - lo) % 26} (mod 26)",
           f"- gcd(2, 26) = 2, so there are two solutions: a = {(hi - lo) % 26 // 2} or a = {(hi - lo) % 26 // 2 + 13}; "
           f"a = {(hi - lo) % 26 // 2 + 13 if a == (hi - lo) % 26 // 2 else (hi - lo) % 26 // 2} fails "
           f"(gcd with 26 != 1 or unreadable output), leaving **a = {a}**",
           f"- Check gcd({a}, 26) = 1; inverse needed for decryption:"]
    md += inverse_working(a)
    md += [f"- Decryption rule per letter: digit = {modinv(a)}(y - {b}) mod 26; then each digit pair (hi, lo) "
           f"is the character with code 16*hi + lo", ""]
    return (a, b), md


def verify_figure(mood, key, server_rows, path):
    plain = " ".join(decrypt_letters(r["ciphertext"], *key) for r in server_rows)
    counts, n = letter_counts(plain)
    x = range(26)
    fig, ax = plt.subplots(figsize=(9, 3))
    ax.bar([i - 0.2 for i in x], [100 * counts[c] / n for c in ALPHABET], width=0.4, color=CIPHER,
           label=f"Decrypted with (a, b) = {key}")
    ax.bar([i + 0.2 for i in x], ENGLISH_FREQ, width=0.4, color=ENGLISH, label="English")
    ax.set_xticks(list(x))
    ax.set_xticklabels(list(ALPHABET))
    ax.set_title(f"Mood {mood}: decrypted letter frequencies now match English", loc="left", fontweight="bold")
    ax.set_ylabel("% of letters")
    ax.grid(axis="y", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def decryption_steps(cipher_word, a, b):
    ai = modinv(a)
    return ", ".join(f"{c}={num(c)} -> {ai}x({num(c)}-{b}) = {ai * (num(c) - b)} mod 26 = {(ai * (num(c) - b)) % 26} = "
                     f"{letter(ai * (num(c) - b))}" for c in cipher_word)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    csv_path, out = sys.argv[1], sys.argv[2]
    os.makedirs(f"{out}/figures", exist_ok=True)
    rows = list(csv.DictReader(open(csv_path, encoding="utf-8")))
    groups = defaultdict(list)
    for r in rows:
        groups[(r["id"][0], int(r["mood"]))].append(r)

    keys = {}
    md = ["# Key derivation (affine cipher, a and b mod 26)", "",
          "Letters are numbered A=0, B=1, ..., Z=25. Encryption is E(x) = (ax + b) mod 26 and decryption "
          "D(y) = a^-1(y - b) mod 26, which requires gcd(a, 26) = 1, so a is one of "
          f"{', '.join(map(str, VALID_A))}.", ""]
    for (side, mood) in sorted(groups):
        gid = f"{'Server' if side == 'S' else 'Client'}-mood{mood}"
        key, lines = (crack_server if side == "S" else crack_client)(gid, groups[(side, mood)])
        keys[gid] = {"direction": "Server -> Client" if side == "S" else "Client -> Server",
                     "mood": mood, "a": key[0], "b": key[1], "a_inverse": modinv(key[0])}
        md += lines
        if side == "S":
            verify_figure(mood, key, groups[(side, mood)], f"{out}/figures/verify_mood{mood}.png")
        print(f"{gid:<18} key (a, b) = {key}")

    md += ["## Key schedule across moods", "",
           "| Mood | Server key (a, b) | Client key (a, b) | 2*mood + 1 | 2*mood |",
           "|---:|:---:|:---:|---:|---:|"]
    for mood in sorted({m for _, m in groups}):
        s, c = keys.get(f"Server-mood{mood}"), keys.get(f"Client-mood{mood}")
        md.append(f"| {mood} | ({s['a']}, {s['b']}) | ({c['a']}, {c['b']}) | {2 * mood + 1} | {2 * mood} |")
    consistent = all(key_for_mood(v["mood"]) == (v["a"], v["b"]) for v in keys.values())
    md += ["", f"Both directions use the **same key for the same mood**, and every recovered key fits "
               f"**a = 2*mood + 1, b = 2*mood (mod 26)**: {'confirmed for all moods tested' if consistent else 'NOT consistent'}.",
           ""]

    # Decryptions
    dec = ["# Decryption results", ""]
    for r in sorted(rows, key=lambda r: (int(r["session"]), r["id"][0])):
        side, mood = r["id"][0], int(r["mood"])
        k = keys[f"{'Server' if side == 'S' else 'Client'}-mood{mood}"]
        a, b = k["a"], k["b"]
        dec += [f"## {r['id']}: {r['direction']}, session {r['session']}, mood {mood}", "",
                f"- Recovered key: (a, b) = ({a}, {b}), a^-1 = {k['a_inverse']}",
                f"- Ciphertext: `{r['ciphertext']}`"]
        if side == "S":
            first = r["ciphertext"].split()[0]
            dec += [f"- Steps (first word `{first}`): {decryption_steps(first, a, b)}",
                    f"- **Plaintext:** {decrypt_letters(r['ciphertext'], a, b)}", ""]
        else:
            letters = [c for c in r["ciphertext"] if c.isalpha()]
            ai = modinv(a)
            digits = [(ai * (num(c) - b)) % 26 for c in letters[:6]]
            chars = [chr(16 * digits[i] + digits[i + 1]) for i in (0, 2, 4)]
            dec += [f"- Steps (first 3 characters): letters {' '.join(letters[:6])} -> digits "
                    f"{' '.join(map(str, digits))} (each {ai}x(y-{b}) mod 26) -> hex "
                    f"{' '.join(f'{digits[i]:x}{digits[i + 1]:x}' for i in (0, 2, 4))} -> {chars!r}",
                    f"- **Plaintext message:** {client_decrypt(r['ciphertext'], a, b)}",
                    f"- Username field `{r['username_enc']}` -> **{client_decrypt(r['username_enc'], a, b)}**; "
                    f"API-key field `{r['api_key_enc']}` -> **{client_decrypt(r['api_key_enc'], a, b)}**", ""]

    with open(f"{out}/key_derivation.md", "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    with open(f"{out}/decryptions.md", "w", encoding="utf-8") as f:
        f.write("\n".join(dec))
    with open(f"{out}/keys.json", "w") as f:
        json.dump(keys, f, indent=2)
    print(f"\nWrote {out}/key_derivation.md, {out}/decryptions.md, {out}/keys.json and verification charts.")


if __name__ == "__main__":
    main()
