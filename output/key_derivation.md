# Key derivation (affine cipher, a and b mod 26)

Letters are numbered A=0, B=1, ..., Z=25. Encryption is E(x) = (ax + b) mod 26 and decryption D(y) = a^-1(y - b) mod 26, which requires gcd(a, 26) = 1, so a is one of 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25.

### Client-mood2: Client -> Server, mood 2 (C2; 30 pairs)

Each plaintext character is sent as **two** cipher letters: only 13 distinct letters appear (at most 16 are possible, one per hex digit 0-15). So the unit of frequency analysis is the letter **pair**.

Most frequent pairs: ID (16.7%), OE (16.7%), NT (13.3%), IJ (6.7%), IR (6.7%)

**Hypothesis:** the most frequent pair is the **space** character (about 15-20% of English text), ASCII 0x20, i.e. hex digits **(2, 0)**. Test the top pairs in turn:

- Pair **ID** = space: a*2 + b = 8, a*0 + b = 3 => b = 3, 2a = 5 (mod 26)
  - 2a = 5 has no solution with gcd(a,26)=1 (odd right-hand side): **reject**
- Pair **OE** = space: a*2 + b = 14, a*0 + b = 4 => b = 4, 2a = 10 (mod 26)
  - (a, b) = (5, 4): decrypts to readable text `I feel stressed about my exams`: **accept**

**Working for the chosen key** (pair OE = space = digits 2, 0):

- From digit 0: a*0 + b = 4  =>  **b = 4**
- From digit 2: 2a + 4 = 14 (mod 26)  =>  2a = 10 (mod 26)
- gcd(2, 26) = 2, so there are two solutions: a = 5 or a = 18; a = 18 fails (gcd with 26 != 1 or unreadable output), leaving **a = 5**
- Check gcd(5, 26) = 1; inverse needed for decryption:
  - Euclid on (26, 5): 26 = 5*5 + 1; 5 = 5*1 + 0
  - back-substituting gives 5^-1 = 21 (check: 5 x 21 = 105 = 4x26 + 1 = 1 mod 26)
- Decryption rule per letter: digit = 21(y - 4) mod 26; then each digit pair (hi, lo) is the character with code 16*hi + lo

### Client-mood5: Client -> Server, mood 5 (C1, C3; 116 pairs)

Each plaintext character is sent as **two** cipher letters: only 14 distinct letters appear (at most 16 are possible, one per hex digit 0-15). So the unit of frequency analysis is the letter **pair**.

Most frequent pairs: GK (19.0%), YN (17.2%), YM (9.5%), YI (8.6%), YF (5.2%)

**Hypothesis:** the most frequent pair is the **space** character (about 15-20% of English text), ASCII 0x20, i.e. hex digits **(2, 0)**. Test the top pairs in turn:

- Pair **GK** = space: a*2 + b = 6, a*0 + b = 10 => b = 10, 2a = 22 (mod 26)
  - (a, b) = (11, 10): decrypts to readable text `I have not been sleeping well and I feel`: **accept**

**Working for the chosen key** (pair GK = space = digits 2, 0):

- From digit 0: a*0 + b = 10  =>  **b = 10**
- From digit 2: 2a + 10 = 6 (mod 26)  =>  2a = 22 (mod 26)
- gcd(2, 26) = 2, so there are two solutions: a = 11 or a = 24; a = 24 fails (gcd with 26 != 1 or unreadable output), leaving **a = 11**
- Check gcd(11, 26) = 1; inverse needed for decryption:
  - Euclid on (26, 11): 26 = 2*11 + 4; 11 = 2*4 + 3; 4 = 1*3 + 1; 3 = 3*1 + 0
  - back-substituting gives 11^-1 = 19 (check: 11 x 19 = 209 = 8x26 + 1 = 1 mod 26)
- Decryption rule per letter: digit = 19(y - 10) mod 26; then each digit pair (hi, lo) is the character with code 16*hi + lo

### Client-mood8: Client -> Server, mood 8 (C4; 60 pairs)

Each plaintext character is sent as **two** cipher letters: only 14 distinct letters appear (at most 16 are possible, one per hex digit 0-15). So the unit of frequency analysis is the letter **pair**.

Most frequent pairs: YQ (20.0%), FG (11.7%), OX (10.0%), OL (8.3%), FY (6.7%)

**Hypothesis:** the most frequent pair is the **space** character (about 15-20% of English text), ASCII 0x20, i.e. hex digits **(2, 0)**. Test the top pairs in turn:

- Pair **YQ** = space: a*2 + b = 24, a*0 + b = 16 => b = 16, 2a = 8 (mod 26)
  - (a, b) = (17, 16): decrypts to readable text `I got a good grade but I still worry abo`: **accept**

**Working for the chosen key** (pair YQ = space = digits 2, 0):

- From digit 0: a*0 + b = 16  =>  **b = 16**
- From digit 2: 2a + 16 = 24 (mod 26)  =>  2a = 8 (mod 26)
- gcd(2, 26) = 2, so there are two solutions: a = 4 or a = 17; a = 4 fails (gcd with 26 != 1 or unreadable output), leaving **a = 17**
- Check gcd(17, 26) = 1; inverse needed for decryption:
  - Euclid on (26, 17): 26 = 1*17 + 9; 17 = 1*9 + 8; 9 = 1*8 + 1; 8 = 8*1 + 0
  - back-substituting gives 17^-1 = 23 (check: 17 x 23 = 391 = 15x26 + 1 = 1 mod 26)
- Decryption rule per letter: digit = 23(y - 16) mod 26; then each digit pair (hi, lo) is the character with code 16*hi + lo

### Client-mood10: Client -> Server, mood 10 (C5; 57 pairs)

Each plaintext character is sent as **two** cipher letters: only 14 distinct letters appear (at most 16 are possible, one per hex digit 0-15). So the unit of frequency analysis is the letter **pair**.

Most frequent pairs: KU (19.3%), LA (12.3%), QP (8.8%), QV (8.8%), QX (7.0%)

**Hypothesis:** the most frequent pair is the **space** character (about 15-20% of English text), ASCII 0x20, i.e. hex digits **(2, 0)**. Test the top pairs in turn:

- Pair **KU** = space: a*2 + b = 10, a*0 + b = 20 => b = 20, 2a = 16 (mod 26)
  - (a, b) = (21, 20): decrypts to readable text `I feel great today and want tips to keep`: **accept**

**Working for the chosen key** (pair KU = space = digits 2, 0):

- From digit 0: a*0 + b = 20  =>  **b = 20**
- From digit 2: 2a + 20 = 10 (mod 26)  =>  2a = 16 (mod 26)
- gcd(2, 26) = 2, so there are two solutions: a = 8 or a = 21; a = 8 fails (gcd with 26 != 1 or unreadable output), leaving **a = 21**
- Check gcd(21, 26) = 1; inverse needed for decryption:
  - Euclid on (26, 21): 26 = 1*21 + 5; 21 = 4*5 + 1; 5 = 5*1 + 0
  - back-substituting gives 21^-1 = 5 (check: 21 x 5 = 105 = 4x26 + 1 = 1 mod 26)
- Decryption rule per letter: digit = 5(y - 20) mod 26; then each digit pair (hi, lo) is the character with code 16*hi + lo

### Server-mood2: Server -> Client, mood 2 (S2; 622 letters)

Most frequent cipher letters: Y (12.9%), E (9.5%), V (8.2%), W (7.4%), R (6.9%), S (5.8%)

**Hypothesis 1:** the most frequent cipher letter **Y** is plaintext **E** (12.7% in English).
Pair it with the next most frequent cipher letters as common English letters and test every candidate:

| # | Mapping 1 | Mapping 2 | Solved (a, b) | gcd(a,26)=1? | chi^2 of decryption | Decryption starts |
|---:|:---:|:---:|:---:|:---:|---:|:---|
| 1 | E->Y | T->E | none | no | - | - |
| 2 | E->Y | A->E | (5, 4) | yes | 43.4 | `FAATEH I CAN SENSE THAT YOURE ` |
| 3 | E->Y | O->E | (11, 6) | yes | 6596.5 | `VOOZED U WOB IEBIE ZDOZ GSQRE ` |
| 4 | E->Y | I->E | (21, 18) | yes | 3246.3 | `DIIPEB A GIV QEVQE PBIP KUORE ` |
| 5 | E->Y | N->E | none | no | - | - |
| 6 | E->Y | T->V | (5, 4) | yes | 43.4 | `FAATEH I CAN SENSE THAT YOURE ` |
| 7 | E->Y | A->V | none | no | - | - |
| 8 | E->Y | O->V | none | no | - | - |
| 9 | E->Y | I->V | none | no | - | - |
| 10 | E->Y | N->V | (17, 8) | yes | 5376.7 | `PMMNEL W IMZ CEZCE NLMN QKYRE ` |
| 11 | E->Y | T->W | none | no | - | - |
| 12 | E->Y | A->W | (7, 22) | yes | 7088.2 | `BQQLEV S KQD OEDOE LVQL WAIRE ` |
| 13 | E->Y | O->W | (5, 4) | yes | 43.4 | `FAATEH I CAN SENSE THAT YOURE ` |
| 14 | E->Y | I->W | (19, 0) | yes | 7048.4 | `HSSXEN Q YSF UEFUE XNSX MIARE ` |
| 15 | E->Y | N->W | none | no | - | - |
| 16 | E->Y | T->R | (3, 12) | yes | 2127.7 | `XGGDEJ C SGT KETKE DJGD UMWRE ` |
| 17 | E->Y | A->R | none | no | - | - |
| 18 | E->Y | O->R | none | no | - | - |
| 19 | E->Y | I->R | none | no | - | - |
| 20 | E->Y | N->R | (5, 4) | yes | 43.4 | `FAATEH I CAN SENSE THAT YOURE ` |
| 21 | E->Y | T->S | none | no | - | - |
| 22 | E->Y | A->S | (21, 18) | yes | 3246.3 | `DIIPEB A GIV QEVQE PBIP KUORE ` |
| 23 | E->Y | O->S | (15, 16) | yes | 6712.1 | `NUUJEF O MUH AEHAE JFUJ CQSRE ` |
| 24 | E->Y | I->S | (5, 4) | yes | 43.4 | `FAATEH I CAN SENSE THAT YOURE ` |
| 25 | E->Y | N->S | none | no | - | - |

**Best candidate:** E->Y and A->E give **(a, b) = (5, 4)** with chi^2 = 43.4 (English-like text scores low; wrong keys score in the hundreds or thousands).

**Working for the chosen key:**

- Mapping E->Y: a*4 + b = 24 (mod 26)
- Mapping A->E: a*0 + b = 4 (mod 26)
- Subtract: a*(4 - 0) = 24 - 4  =>  4a = 20 (mod 26)
- gcd(4, 26) != 1, so solve by testing a = 0..25: solutions a in [5, 18]
- b = 24 - 5x4 mod 26 = **4**
- Check gcd(5, 26) = 1, so the key is valid. Decryption needs a^-1:
  - Euclid on (26, 5): 26 = 5*5 + 1; 5 = 5*1 + 0
  - back-substituting gives 5^-1 = 21 (check: 5 x 21 = 105 = 4x26 + 1 = 1 mod 26)
- Decryption rule: **D(y) = 21(y - 4) mod 26**

**Confirmation by exhaustive search** over all 12 x 26 = 312 valid keys (lowest chi^2 = most English-like):

1. (a, b) = (5, 4): chi^2 = 43.4
2. (a, b) = (9, 24): chi^2 = 855.4
3. (a, b) = (25, 24): chi^2 = 1030.5

### Server-mood5: Server -> Client, mood 5 (S1, S3; 1640 letters)

Most frequent cipher letters: C (11.5%), L (9.9%), I (8.8%), K (7.7%), U (7.1%), X (6.4%)

**Hypothesis 1:** the most frequent cipher letter **C** is plaintext **E** (12.7% in English).
Pair it with the next most frequent cipher letters as common English letters and test every candidate:

| # | Mapping 1 | Mapping 2 | Solved (a, b) | gcd(a,26)=1? | chi^2 of decryption | Decryption starts |
|---:|:---:|:---:|:---:|:---:|---:|:---|
| 1 | E->C | T->L | (11, 10) | yes | 87.5 | `FAATEH IT SOUNDS LIKE YOURE GO` |
| 2 | E->C | A->L | none | no | - | - |
| 3 | E->C | O->L | none | no | - | - |
| 4 | E->C | I->L | none | no | - | - |
| 5 | E->C | N->L | (1, 24) | yes | 13298.3 | `PMMNEL WN CKYZTC DWSE QKYRE AK` |
| 6 | E->C | T->I | none | no | - | - |
| 7 | E->C | A->I | (5, 8) | yes | 12854.1 | `BQQLEV SL OAIDHO JSME WAIRE YA` |
| 8 | E->C | O->I | (11, 10) | yes | 87.5 | `FAATEH IT SOUNDS LIKE YOURE GO` |
| 9 | E->C | I->I | (21, 22) | yes | 22905.0 | `HSSXEN QX UIAFBU ZQWE MIARE KI` |
| 10 | E->C | N->I | none | no | - | - |
| 11 | E->C | T->K | none | no | - | - |
| 12 | E->C | A->K | (11, 10) | yes | 87.5 | `FAATEH IT SOUNDS LIKE YOURE GO` |
| 13 | E->C | O->K | (19, 4) | yes | 25781.8 | `VOOZED UZ ISQBNI TUCE GSQRE MS` |
| 14 | E->C | I->K | (15, 20) | yes | 8611.1 | `DIIPEB AP QUOVFQ XAYE KUORE CU` |
| 15 | E->C | N->K | none | no | - | - |
| 16 | E->C | T->U | none | no | - | - |
| 17 | E->C | A->U | (15, 20) | yes | 8611.1 | `DIIPEB AP QUOVFQ XAYE KUORE CU` |
| 18 | E->C | O->U | (7, 0) | yes | 24816.9 | `NUUJEF OJ AQSHVA POGE CQSRE WQ` |
| 19 | E->C | I->U | (11, 10) | yes | 87.5 | `FAATEH IT SOUNDS LIKE YOURE GO` |
| 20 | E->C | N->U | none | no | - | - |
| 21 | E->C | T->X | (17, 12) | yes | 7096.0 | `XGGDEJ CD KMWTLK HCOE UMWRE QM` |
| 22 | E->C | A->X | none | no | - | - |
| 23 | E->C | O->X | none | no | - | - |
| 24 | E->C | I->X | none | no | - | - |
| 25 | E->C | N->X | (11, 10) | yes | 87.5 | `FAATEH IT SOUNDS LIKE YOURE GO` |

**Best candidate:** E->C and T->L give **(a, b) = (11, 10)** with chi^2 = 87.5 (English-like text scores low; wrong keys score in the hundreds or thousands).

**Working for the chosen key:**

- Mapping E->C: a*4 + b = 2 (mod 26)
- Mapping T->L: a*19 + b = 11 (mod 26)
- Subtract: a*(4 - 19) = 2 - 11  =>  11a = 17 (mod 26)
- 11 is invertible mod 26:
  - Euclid on (26, 11): 26 = 2*11 + 4; 11 = 2*4 + 3; 4 = 1*3 + 1; 3 = 3*1 + 0
  - back-substituting gives 11^-1 = 19 (check: 11 x 19 = 209 = 8x26 + 1 = 1 mod 26)
- a = 19 x 17 mod 26 = 323 mod 26 = **11**
- b = 2 - 11x4 mod 26 = **10**
- Check gcd(11, 26) = 1, so the key is valid. Decryption needs a^-1:
  - Euclid on (26, 11): 26 = 2*11 + 4; 11 = 2*4 + 3; 4 = 1*3 + 1; 3 = 3*1 + 0
  - back-substituting gives 11^-1 = 19 (check: 11 x 19 = 209 = 8x26 + 1 = 1 mod 26)
- Decryption rule: **D(y) = 19(y - 10) mod 26**

**Confirmation by exhaustive search** over all 12 x 26 = 312 valid keys (lowest chi^2 = most English-like):

1. (a, b) = (11, 10): chi^2 = 87.5
2. (a, b) = (25, 2): chi^2 = 2183.9
3. (a, b) = (19, 24): chi^2 = 2483.5

### Server-mood8: Server -> Client, mood 8 (S4; 666 letters)

Most frequent cipher letters: G (11.6%), B (10.5%), Q (9.6%), U (9.2%), D (8.1%), T (6.5%)

**Hypothesis 1:** the most frequent cipher letter **G** is plaintext **E** (12.7% in English).
Pair it with the next most frequent cipher letters as common English letters and test every candidate:

| # | Mapping 1 | Mapping 2 | Solved (a, b) | gcd(a,26)=1? | chi^2 of decryption | Decryption starts |
|---:|:---:|:---:|:---:|:---:|---:|:---|
| 1 | E->G | T->B | (17, 16) | yes | 39.5 | `FAATEH IT SOUNDS LIKE YOURE FE` |
| 2 | E->G | A->B | none | no | - | - |
| 3 | E->G | O->B | none | no | - | - |
| 4 | E->G | I->B | none | no | - | - |
| 5 | E->G | N->B | (11, 14) | yes | 7447.5 | `PMMNEL WN CKYZTC DWSE QKYRE PE` |
| 6 | E->G | T->Q | none | no | - | - |
| 7 | E->G | A->Q | (17, 16) | yes | 39.5 | `FAATEH IT SOUNDS LIKE YOURE FE` |
| 8 | E->G | O->Q | (1, 2) | yes | 11218.1 | `VOOZED UZ ISQBNI TUCE GSQRE VE` |
| 9 | E->G | I->Q | (9, 22) | yes | 2963.2 | `DIIPEB AP QUOVFQ XAYE KUORE DE` |
| 10 | E->G | N->Q | none | no | - | - |
| 11 | E->G | T->U | none | no | - | - |
| 12 | E->G | A->U | (3, 20) | yes | 7170.0 | `BQQLEV SL OAIDHO JSME WAIRE BE` |
| 13 | E->G | O->U | (17, 16) | yes | 39.5 | `FAATEH IT SOUNDS LIKE YOURE FE` |
| 14 | E->G | I->U | (23, 18) | yes | 7514.7 | `HSSXEN QX UIAFBU ZQWE MIARE HE` |
| 15 | E->G | N->U | none | no | - | - |
| 16 | E->G | T->D | (5, 12) | yes | 2228.6 | `XGGDEJ CD KMWTLK HCOE UMWRE XE` |
| 17 | E->G | A->D | none | no | - | - |
| 18 | E->G | O->D | none | no | - | - |
| 19 | E->G | I->D | none | no | - | - |
| 20 | E->G | N->D | (17, 16) | yes | 39.5 | `FAATEH IT SOUNDS LIKE YOURE FE` |
| 21 | E->G | T->T | none | no | - | - |
| 22 | E->G | A->T | none | no | - | - |
| 23 | E->G | O->T | none | no | - | - |
| 24 | E->G | I->T | none | no | - | - |
| 25 | E->G | N->T | none | no | - | - |

**Best candidate:** E->G and T->B give **(a, b) = (17, 16)** with chi^2 = 39.5 (English-like text scores low; wrong keys score in the hundreds or thousands).

**Working for the chosen key:**

- Mapping E->G: a*4 + b = 6 (mod 26)
- Mapping T->B: a*19 + b = 1 (mod 26)
- Subtract: a*(4 - 19) = 6 - 1  =>  11a = 5 (mod 26)
- 11 is invertible mod 26:
  - Euclid on (26, 11): 26 = 2*11 + 4; 11 = 2*4 + 3; 4 = 1*3 + 1; 3 = 3*1 + 0
  - back-substituting gives 11^-1 = 19 (check: 11 x 19 = 209 = 8x26 + 1 = 1 mod 26)
- a = 19 x 5 mod 26 = 95 mod 26 = **17**
- b = 6 - 17x4 mod 26 = **16**
- Check gcd(17, 26) = 1, so the key is valid. Decryption needs a^-1:
  - Euclid on (26, 17): 26 = 1*17 + 9; 17 = 1*9 + 8; 9 = 1*8 + 1; 8 = 8*1 + 0
  - back-substituting gives 17^-1 = 23 (check: 17 x 23 = 391 = 15x26 + 1 = 1 mod 26)
- Decryption rule: **D(y) = 23(y - 16) mod 26**

**Confirmation by exhaustive search** over all 12 x 26 = 312 valid keys (lowest chi^2 = most English-like):

1. (a, b) = (17, 16): chi^2 = 39.5
2. (a, b) = (15, 19): chi^2 = 940.8
3. (a, b) = (1, 14): chi^2 = 1083.1

### Server-mood10: Server -> Client, mood 10 (S5; 672 letters)

Most frequent cipher letters: A (11.8%), U (9.4%), D (8.9%), C (7.9%), H (7.6%), G (6.8%)

**Hypothesis 1:** the most frequent cipher letter **A** is plaintext **E** (12.7% in English).
Pair it with the next most frequent cipher letters as common English letters and test every candidate:

| # | Mapping 1 | Mapping 2 | Solved (a, b) | gcd(a,26)=1? | chi^2 of decryption | Decryption starts |
|---:|:---:|:---:|:---:|:---:|---:|:---|
| 1 | E->A | T->U | none | no | - | - |
| 2 | E->A | A->U | (21, 20) | yes | 31.5 | `FAATEH IT SOUNDS LIKE YOURE FE` |
| 3 | E->A | O->U | (15, 18) | yes | 8353.1 | `VOOZED UZ ISQBNI TUCE GSQRE VE` |
| 4 | E->A | I->U | (5, 6) | yes | 3721.3 | `DIIPEB AP QUOVFQ XAYE KUORE DE` |
| 5 | E->A | N->U | none | no | - | - |
| 6 | E->A | T->D | (21, 20) | yes | 31.5 | `FAATEH IT SOUNDS LIKE YOURE FE` |
| 7 | E->A | A->D | none | no | - | - |
| 8 | E->A | O->D | none | no | - | - |
| 9 | E->A | I->D | none | no | - | - |
| 10 | E->A | N->D | (9, 16) | yes | 6752.6 | `PMMNEL WN CKYZTC DWSE QKYRE PE` |
| 11 | E->A | T->C | none | no | - | - |
| 12 | E->A | A->C | (19, 2) | yes | 7614.2 | `BQQLEV SL OAIDHO JSME WAIRE BE` |
| 13 | E->A | O->C | (21, 20) | yes | 31.5 | `FAATEH IT SOUNDS LIKE YOURE FE` |
| 14 | E->A | I->C | (7, 24) | yes | 9463.7 | `HSSXEN QX UIAFBU ZQWE MIARE HE` |
| 15 | E->A | N->C | none | no | - | - |
| 16 | E->A | T->H | (23, 12) | yes | 2005.1 | `XGGDEJ CD KMWTLK HCOE UMWRE XE` |
| 17 | E->A | A->H | none | no | - | - |
| 18 | E->A | O->H | none | no | - | - |
| 19 | E->A | I->H | none | no | - | - |
| 20 | E->A | N->H | (21, 20) | yes | 31.5 | `FAATEH IT SOUNDS LIKE YOURE FE` |
| 21 | E->A | T->G | none | no | - | - |
| 22 | E->A | A->G | (5, 6) | yes | 3721.3 | `DIIPEB AP QUOVFQ XAYE KUORE DE` |
| 23 | E->A | O->G | (11, 8) | yes | 8287.8 | `NUUJEF OJ AQSHVA POGE CQSRE NE` |
| 24 | E->A | I->G | (21, 20) | yes | 31.5 | `FAATEH IT SOUNDS LIKE YOURE FE` |
| 25 | E->A | N->G | none | no | - | - |

**Best candidate:** E->A and A->U give **(a, b) = (21, 20)** with chi^2 = 31.5 (English-like text scores low; wrong keys score in the hundreds or thousands).

**Working for the chosen key:**

- Mapping E->A: a*4 + b = 0 (mod 26)
- Mapping A->U: a*0 + b = 20 (mod 26)
- Subtract: a*(4 - 0) = 0 - 20  =>  4a = 6 (mod 26)
- gcd(4, 26) != 1, so solve by testing a = 0..25: solutions a in [8, 21]
- b = 0 - 21x4 mod 26 = **20**
- Check gcd(21, 26) = 1, so the key is valid. Decryption needs a^-1:
  - Euclid on (26, 21): 26 = 1*21 + 5; 21 = 4*5 + 1; 5 = 5*1 + 0
  - back-substituting gives 21^-1 = 5 (check: 21 x 5 = 105 = 4x26 + 1 = 1 mod 26)
- Decryption rule: **D(y) = 5(y - 20) mod 26**

**Confirmation by exhaustive search** over all 12 x 26 = 312 valid keys (lowest chi^2 = most English-like):

1. (a, b) = (21, 20): chi^2 = 31.5
2. (a, b) = (15, 16): chi^2 = 953.2
3. (a, b) = (17, 13): chi^2 = 1189.4

## Key schedule across moods

| Mood | Server key (a, b) | Client key (a, b) | 2*mood + 1 | 2*mood |
|---:|:---:|:---:|---:|---:|
| 2 | (5, 4) | (5, 4) | 5 | 4 |
| 5 | (11, 10) | (11, 10) | 11 | 10 |
| 8 | (17, 16) | (17, 16) | 17 | 16 |
| 10 | (21, 20) | (21, 20) | 21 | 20 |

Both directions use the **same key for the same mood**, and every recovered key fits **a = 2*mood + 1, b = 2*mood (mod 26)**: confirmed for all moods tested.
