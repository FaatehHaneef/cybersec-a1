#!/usr/bin/env python3
"""
frequency_analysis.py - Al-Kindi frequency analysis of the captured ciphertexts.

For every ciphertext in ciphertexts.csv:
  * preprocessing: keep only the letters A-Z (spaces/JSON/punctuation removed)
  * count each letter and its relative frequency (%)
  * compare with standard English frequencies, rank against rank
  * Server -> Client: tables + charts per ciphertext
  * Client -> Server: also counts letter PAIRS, because each plaintext
    character is sent as two cipher letters

Outputs:
  output/tables/freq_<id>.csv        full count tables
  output/figures/freq_<id>.png       charts
  output/frequency_tables.md         all tables in Markdown (for the report)

Usage:  python scripts/frequency_analysis.py ciphertexts.csv output
"""
import csv
import os
import sys
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from affine import ALPHABET, ENGLISH_FREQ, letter_counts, pairs  # noqa: E402

CIPHER = "#2a78d6"   # series 1: ciphertext
ENGLISH = "#eb6834"  # series 2: English reference
INK, MUTED, GRID = "#0b0b0b", "#898781", "#e1e0d9"

plt.rcParams.update({
    "font.size": 9, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.titleweight": "bold",
    "axes.spines.top": False, "axes.spines.right": False,
})

ENGLISH_RANKED = sorted(zip(ALPHABET, ENGLISH_FREQ), key=lambda x: -x[1])


def style(ax):
    ax.grid(axis="y", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)


def server_figure(row, counts, n, path):
    pct = [100 * counts[c] / n for c in ALPHABET]
    ranked = sorted(ALPHABET, key=lambda c: (-counts[c], c))
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 6.2))

    ax1.bar(list(ALPHABET), pct, color=CIPHER, width=0.7)
    ax1.set_title(f"{row['id']} ({row['direction']}, mood {row['mood']}): ciphertext letter frequency, n = {n}",
                  loc="left")
    ax1.set_ylabel("% of letters")
    style(ax1)

    x = range(26)
    w = 0.4
    ax2.bar([i - w / 2 for i in x], [100 * counts[c] / n for c in ranked], width=w, color=CIPHER, label="Ciphertext")
    ax2.bar([i + w / 2 for i in x], [f for _, f in ENGLISH_RANKED], width=w, color=ENGLISH, label="English")
    ax2.set_xticks(list(x))
    ax2.set_xticklabels([f"{c}\n{e}" for c, (e, _) in zip(ranked, ENGLISH_RANKED)])
    ax2.set_title("Ranked comparison: cipher letter (top) vs English letter (bottom) of the same rank", loc="left")
    ax2.set_ylabel("% of letters")
    ax2.legend(frameon=False, loc="upper right")
    style(ax2)

    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return ranked


def client_figure(row, counts, n, pair_counts, path):
    pct = [100 * counts[c] / n for c in ALPHABET]
    top = pair_counts.most_common(10)
    total_pairs = sum(pair_counts.values())
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 3.6), gridspec_kw={"width_ratios": [1.6, 1]})

    ax1.bar(list(ALPHABET), pct, color=CIPHER, width=0.7)
    used = sum(1 for c in ALPHABET if counts[c])
    ax1.set_title(f"{row['id']} (mood {row['mood']}): single letters, only {used} of 26 used", loc="left")
    ax1.set_ylabel("% of letters")
    style(ax1)

    ax2.barh([p for p, _ in top][::-1], [100 * k / total_pairs for _, k in top][::-1], color=CIPHER, height=0.6)
    ax2.set_title("Top 10 letter pairs (= characters)", loc="left")
    ax2.set_xlabel("% of pairs")
    ax2.grid(axis="x", color=GRID, linewidth=0.6)
    ax2.set_axisbelow(True)

    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    csv_path, out = sys.argv[1], sys.argv[2]
    os.makedirs(f"{out}/tables", exist_ok=True)
    os.makedirs(f"{out}/figures", exist_ok=True)
    rows = list(csv.DictReader(open(csv_path, encoding="utf-8")))

    md = ["# Frequency tables (Al-Kindi method)", "",
          "Preprocessing: only the letters A-Z are counted; spaces, JSON syntax and punctuation are removed.", ""]

    for row in rows:
        text = row["ciphertext"]
        counts, n = letter_counts(text)
        with open(f"{out}/tables/freq_{row['id']}.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["letter", "count", "percent", "english_percent"])
            for c, e in zip(ALPHABET, ENGLISH_FREQ):
                w.writerow([c, counts[c], round(100 * counts[c] / n, 2), e])

        md += [f"## {row['id']}: {row['direction']}, mood {row['mood']} ({n} letters)", ""]
        ranked = sorted(ALPHABET, key=lambda c: (-counts[c], c))

        if row["id"].startswith("S"):
            server_figure(row, counts, n, f"{out}/figures/freq_{row['id']}.png")
            md += ["| Rank | Cipher letter | Count | % | English letter | English % |",
                   "|---:|:---:|---:|---:|:---:|---:|"]
            for i, (c, (e, ef)) in enumerate(zip(ranked, ENGLISH_RANKED), start=1):
                md.append(f"| {i} | {c} | {counts[c]} | {100 * counts[c] / n:.2f} | {e} | {ef:.2f} |")
        else:
            pair_counts = Counter(pairs(text))
            client_figure(row, counts, n, pair_counts, f"{out}/figures/freq_{row['id']}.png")
            used = [c for c in ranked if counts[c]]
            md += [f"Only **{len(used)}** distinct letters are used (a normal English text uses ~20-26), "
                   "which shows each letter stands for a small set of symbols (hex digits 0-15).", "",
                   "| Rank | Cipher letter | Count | % |", "|---:|:---:|---:|---:|"]
            for i, c in enumerate(used, start=1):
                md.append(f"| {i} | {c} | {counts[c]} | {100 * counts[c] / n:.2f} |")
            total = sum(pair_counts.values())
            md += ["", f"Letter pairs ({total} pairs = {total} plaintext characters):", "",
                   "| Rank | Pair | Count | % |", "|---:|:---:|---:|---:|"]
            for i, (p, k) in enumerate(pair_counts.most_common(8), start=1):
                md.append(f"| {i} | {p} | {k} | {100 * k / total:.2f} |")
        md.append("")
        print(f"{row['id']}: {n} letters, top 5 = {' '.join(ranked[:5])}")

    with open(f"{out}/frequency_tables.md", "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print(f"\nTables, charts and {out}/frequency_tables.md written.")


if __name__ == "__main__":
    main()
