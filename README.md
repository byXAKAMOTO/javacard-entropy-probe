# javacard-entropy-probe

An **open probe for the random generator of a Java Card secure element.**

Built and maintained by [XAKAMOTO](https://xakamoto.com).

A secure element is only worth what its keys are worth, and its keys are only worth what the generator that produced them is worth. That claim should not rest on the vendor's word — nor on the word of whoever wrote the closed applet that holds your money.

This applet lets **anyone** pull as much output as they like from the chip's random generator and run it through their own statistical batteries. It is small enough to read in one sitting, and that is the point.

---

## Contents

- [What it is](#what-it-is)
- [What it deliberately does not do](#what-it-deliberately-does-not-do)
- [About the algorithm identifier](#about-the-algorithm-identifier-which-is-the-part-people-misread)
- [Hardware you need](#hardware-you-need)
- [Getting GlobalPlatformPro](#getting-globalplatformpro)
- [Building](#building)
- [Installing](#installing)
- [Probing](#probing)
- [Uninstalling](#uninstalling)
- [What the probe measures](#what-the-probe-measures)
- [Results on an NXP J3R180](#results-on-an-nxp-j3r180)
- [AID](#aid)
- [Licence and attribution](#licence-and-attribution)

---

## What it is

A single Java Card applet, in its own CAP, under its own AID. Four commands, no state.

| APDU | name | what it does |
| --- | --- | --- |
| `00 B0 00 00 Le` | GET RANDOM | returns `Le` bytes from the generator (`Le = 0` means 256) |
| `00 B2 00 00 00` | DESCRIBE | the card's own declaration about the algorithm it uses |
| `00 B4 00 00 01` | ALGORITHM | one byte: the `RandomData` constant actually requested |
| `00 B6 00 00 00` | NOTICE | the attribution notice (see [Licence](#licence-and-attribution)) |

Every other INS returns `6D00`.

## What it deliberately does not do

- **It writes no persistent memory.** Not one byte. It cannot be worn out, and you can pull gigabytes through it without consuming the endurance of the chip.
- **It keeps no state** between commands and **holds no secret**.
- **It authenticates nobody and protects nothing**, because it has nothing to protect.
- **It uses only the standard Java Card API** — `javacard.framework` and `javacard.security`. No vendor-proprietary package is imported. `build.sh` fails the build if anyone adds one.

## About the algorithm identifier, which is the part people misread

The applet asks the platform for `RandomData.ALG_PSEUDO_RANDOM`.

Do not read that name as *"a software pseudorandom generator"*. On JCOP 4.x every `RandomData` identifier maps to the **same engine**, and that engine is a **DRG.4 certified DRBG under AIS 20, seeded and continuously reseeded from the chip's physical true random source**. The identifier picks an API label; it does not select a source.

`ALG_PSEUDO_RANDOM` is the identifier **NXP recommends in writing**, in the JCOP 4 manual, section 4.2.5.8 — the same section that declares the single mapping. The manual's words are: *"It is proposed to use `ALG_PSEUDO_RANDOM`."*

It is also measurable. Generating 8 KB inside the card, all six identifiers cost the same per 32 bytes:

```
6.647   6.647   6.646   6.646   6.696   6.652    ms per 32 bytes
```

A software PRNG, a DRBG and a raw TRNG do not agree to the third decimal. That timing is also why the call is slow: the operating system runs continuous statistical tests over the physical source and inserts wait states to collect entropy. **The slowness is the guarantee, not a symptom.**

**This is the same identifier, obtained the same way, that the XAKA applet uses for its key material** — and for the same reason. A battery run against this probe measures the same engine that produces XAKA keys.

## Hardware you need

- **A Java Card secure element** with a Global Platform Issuer Security Domain you can authenticate to. Development cards normally ship with the well-known default keys `404142434445464748494A4B4C4D4E4F`; a card whose keys have been rotated needs `--key`.
- **A PC/SC reader.** Contact or contactless, either works. Development here was done with an **Identiv uTrust 3700 F** contactless reader.
- **A Java runtime** for GlobalPlatformPro, and a **Java Card SDK** if you want to build the CAP yourself rather than use a release.
- **Python 3 with `pyscard`** for the probe tool. Measuring needs nothing else; `--load`, `--delete`, `--once` and `--many` also call `gp.jar`:

```bash
pip install pyscard
```

## Getting GlobalPlatformPro

`gp.jar` is the tool used to load and delete applets. It is a separate open-source project:

```
https://github.com/martinpaljak/GlobalPlatformPro
```

Download `gp.jar` from its releases page and run it with any Java 11 or newer runtime:

```bash
java -jar gp.jar --version
```

Everywhere below, `gp` means `java -jar gp.jar`.

> **Always pass `--reader`.** Without it, `gp` picks the *first* PC/SC reader it finds, which may not be the one you think you are talking to. With two readers connected, a `--delete` on the wrong card is silent and irreversible.

## Building

```bash
bash build.sh
```

Override the toolchain locations if yours differ:

```bash
JC_BUILDER=/path/to/jcide/builder JC_API=/path/to/api_classic/lib bash build.sh
```

The build refuses to proceed if the source imports anything outside the standard Java Card API, and refuses to convert a `.class` older than its `.java`. The output is `bin/entropyprobe/javacard/entropyprobe.cap`.

## Installing

```bash
gp --reader "Identiv uTrust 3700 F CL Reader 0" --install bin/entropyprobe/javacard/entropyprobe.cap
```

Check it is there:

```bash
gp --reader "Identiv uTrust 3700 F CL Reader 0" --list
```

You should see both the package and the applet instance:

```
APP: 454E54524F505901 (SELECTABLE)
PKG: 454E54524F5059   (LOADED)
```

## Probing

```bash
python tools/entropy_probe.py --readers
python tools/entropy_probe.py --reader YOUR_READER_SERIAL
```

The second line is `--full`, the default: every check, with a sample of 1 000 000 bytes and sixteen power cuts. That is the run that backs a recommendation.

**Name the reader by its serial.** `--readers` prints it. The number at the end of a PC/SC name is handed out by the driver in power-on order, and it moves when a reader is unplugged; with several readers of the same model, the name picks a slot and the serial picks a device. The tool refuses to guess: with several readers and no `--reader`, or a name that matches more than one, it stops.

| option | meaning |
| --- | --- |
| `--readers` | list the readers with their serial numbers, and exit |
| `--full` | every check with the large sample (the default) |
| `--once` | the pre-sealing check of a bare chip: load, basic checks, delete, verdict — see below |
| `--many` | `--once` chip after chip on the same reader, until Ctrl+C — see below |
| `--load` | install the applet, and prove it: listed by the card and answering SELECT |
| `--delete` | remove instance and package, and prove they are gone |
| `--reader R` | the reader: its serial, or a piece of its name |
| `--bytes N` | bytes for the single-session tests (`--full` 1 000 000, `--once` and `--many` 65 536, minimum 2 500) |
| `--restarts N` | power-up cycles for the across-reboots test (default 16, `0` to skip) |
| `--restart-bytes N` | bytes pulled per power-up (default 1024) |
| `--out FILE` | dump the raw output for a real battery |
| `--gp PATH` | GlobalPlatformPro's `gp.jar`, for `--load`, `--delete`, `--once` and `--many` (or `GP_JAR`) |
| `--java PATH` | a Java 11+ runtime for `gp.jar` (or `GP_JAVA`; default `java`) |
| `--key HEX` | the card's security domain key, if it is not the default `404142…4F` |
| `--cap PATH` | the CAP to install (default: the one in `bin/`) |
| `--mute` | no sound at the verdict (colour switches itself off when the output is not a terminal, or with `NO_COLOR`) |

Exit codes: `0` passed, `1` the chip failed a check — loading included —, `2` could not test (no reader, no `gp.jar`, wrong key…). A `2` says nothing about the chip. `--many` returns `1` if any chip was rejected, else `2` if any was left without a verdict, else `0`.

**Every verdict is also seen and heard**, so it can be told from across the bench without reading it: green and a short rising pair of notes for `CHIP OK`, red and a low falling pair for `CHIP REJECTED`, yellow and the same note twice for `NO VERDICT`. `--full` does the same with its own verdict. The notes are soft sine tones at a quarter of full volume, played by Windows; elsewhere they become terminal bells, one, three or two. `--mute` silences them.

**Every verdict also says how long the chip took**, split into load, generator and delete. When `--many` ends, it adds the batch: total and average checking time per chip, the fastest and the slowest, and the pace of the whole batch from the first chip put down to the last verdict, swaps included.

### Before sealing a chip: `--once`

```bash
python tools/entropy_probe.py --reader YOUR_READER_SERIAL --once --gp gp.jar --java /path/to/java17/bin/java
```

For a **bare chip, before it goes into a product**, so that a broken one is caught while it can still be set aside instead of after it has been sealed. It answers two questions and only those: does this chip load an applet, and is its generator not broken. It installs the applet, runs the single-session checks on 65 536 bytes plus the sixteen power cuts — the one check that sees a dead noise source behind a healthy DRBG —, deletes the applet whatever happened, and prints `CHIP OK` or `CHIP REJECTED`. It takes well under a minute. `GP_JAR` and `GP_JAVA` can stand in for `--gp` and `--java`: set them once and leave both out.

Two things it will not do. **It will not retry a refused key**: if the card rejects the key, it stops and sends nothing more, because every failed authentication counts against the card and enough of them can lock it for good. And **it is not the recommendation**: that is `--full`.

### A batch: `--many`

```bash
python tools/entropy_probe.py --reader YOUR_READER_SERIAL --many
```

`--once`, chip after chip on the same reader, until Ctrl+C. Put a chip on the reader and it is tested; after the verdict, take it off and put on the next one. A chip only counts as new after the reader has been empty, so one left on the reader is never tested twice. Waiting touches no card: the tool only asks the PC/SC service whether the reader holds one.

Ctrl+C ends the batch and prints how many chips passed, and which were rejected or left without a verdict, by their order in the batch (`#3`). A chip interrupted in the middle of its test counts as without a verdict, because the probe may still be on it: test it again before sealing it. The batch stops on its own only when no chip could be tested anyway: `gp.jar`, Java or the CAP missing, the reader gone, or a **refused key**, because the next chip of the same batch would almost certainly refuse it too and every attempt counts against the chip that receives it. With `--out`, each chip gets its own file: `entropy-001.bin`, `entropy-002.bin`…

A thorough run, with the raw output kept:

```bash
python tools/entropy_probe.py --reader YOUR_READER_SERIAL --out entropy.bin
```

Then feed the raw output to a real battery:

```bash
dieharder -a -g 201 -f entropy.bin
ent entropy.bin
```

> **Throughput note.** The cost is **per request, not per byte**. Measured on a J3R180: 5.57 ms per 32 bytes when asking 32 bytes at a time, 1.33 ms per 32 bytes when asking 255. The continuous health test and the reseed check are paid once per call, so larger requests are about four times cheaper per byte.

## Uninstalling

Delete the instance first, then the package:

```bash
gp --reader "Identiv uTrust 3700 F CL Reader 0" --delete 454E54524F505901
```

```bash
gp --reader "Identiv uTrust 3700 F CL Reader 0" --delete 454E54524F5059
```

Both in one call also works:

```bash
gp --reader "Identiv uTrust 3700 F CL Reader 0" --delete 454E54524F505901 --delete 454E54524F5059
```

The applet writes no persistent memory, so deleting it leaves nothing behind.

## What the probe measures

| criterion | what is implemented |
| --- | --- |
| **FIPS 140-2, section 4.9.1** | the four power-up tests on exactly 20 000 bits, with the acceptance intervals of the standard: Monobit (`9725 < X < 10275`), Poker (`2.16 < X < 46.17`), Runs (per-length intervals), Long Run (`< 26`) |
| **NIST SP 800-22 Rev 1a** | Frequency (Monobit), section 2.1, and Runs, section 2.3, each as a p-value against `alpha = 0.01` |
| **Own sanity checks** | byte chi-square, serial correlation, compression ratio, repeated 32-byte blocks. Not from any standard; they catch a stuck generator instantly |
| **Across power-ups** | pulls, cuts the card's power, pulls again, and compares between sessions |

**That last one is the important one, and no single-session battery can do it.** On a certified secure element the output comes from a DRBG, so it is *whitened*. A dead physical noise source behind a healthy DRBG produces statistically impeccable output within one power-up, and every other test above would pass. A generator that reseeds from a dead source **repeats its stream after each reset**, and that is visible only from outside, between sessions.

**A failure that chance explains is retested once.** At `alpha = 0.01` each NIST test fails 1 % of healthy samples by definition, and the byte chi-square leaves 200–310 about 1.5 % of the time. Measured on 6 000 samples of `os.urandom` through the tool's own code, 3 to 4 % of healthy samples fail one of the three: in a batch of 100 good chips, three or four rejected. When those three are the only failures, the tool pulls a fresh sample of the same size and rejects only if that one fails too, which brings false rejections to about 0.2 % — 8 of 4 000, measured end to end. A broken generator is not rescued by it: it fails both samples, and by far. FIPS 140-2, correlation, compression, repeated blocks and the across-power-ups test reject at the first failure.

**Passing this tool is not a certification and not a randomness evaluation.** It means the generator is not obviously broken and does not repeat across power-ups. For anything stronger, run dieharder, the NIST STS or TestU01 on the raw output. That is the whole point: you measure it yourself.

## Results on an NXP J3R180

Measured through an Identiv uTrust 3700 F, 32 768 bytes plus 5 power-up cycles:

```
algorithm declared by the card: 0x01  ALG_PSEUDO_RANDOM

FIPS 140-2, section 4.9.1 - on 20000 bits
  Monobit    X = 9877     9725 < X < 10275       PASS
  Poker      X = 8.448    2.16 < X < 46.17       PASS
  Runs                                           PASS
  Long run   longest = 14   longest run < 26     PASS

NIST SP 800-22 Rev 1a - alpha = 0.01
  2.1 Frequency (Monobit)   s = 1.3750   p = 0.169131   PASS
  2.3 Runs                  V = 131143   p = 0.778681   PASS

Own sanity checks
  byte chi-square (255 df)  242.5
  serial correlation        +0.004328
  compression ratio         1.0005
  repeated 32-byte blocks   0

Across power-ups - 5 restarts
  identical sessions            0
  distinct 16-byte prefixes     5
  repeated blocks across only   0

throughput: 24145 bytes/s  (1.33 ms per 32 bytes at 255 bytes per request)
```

## AID

| | |
| --- | --- |
| package | `454E54524F5059` (ASCII `ENTROPY`) |
| applet | `454E54524F505901` |

**If you fork this for production use, register your own RID.** ISO/IEC 7816-5 assigns 5-byte registered identifiers; the AID above is fine for development and evaluation cards, but a shared namespace collides the moment two vendors ship it.

## Licence and attribution

**Apache License 2.0.** See [LICENSE](LICENSE) and [NOTICE](NOTICE).

You may use this in a commercial product, embed it in your own card, extend it, and **keep your own source closed**. There is no copyleft here.

What you must do in return is **say that you used it**. Apache-2.0 section 4(d) requires that the contents of the [NOTICE](NOTICE) file be carried into derivative works, and it lets you satisfy that in any one of three places: the source you distribute, the documentation you ship with it, or **a display generated by the derivative work**.

That third option is why the `NOTICE` command exists. If you embed this applet in a product, the attribution travels **inside the card** and answers for itself:

```
$ 00 B6 00 00 00

EntropyProbe. Copyright 2026 XAKAMOTO.
Licensed under Apache-2.0. This notice must be retained
in derivative works and in products that embed this applet.
github.com/byXAKAMOTO/javacard-entropy-probe
```

Section 4(b) also requires derivative works to carry prominent notices stating that you changed the files, and 4(c) requires you to retain the existing copyright and attribution notices. The licence additionally grants you a patent licence for this contribution.

*This is a plain-language summary, not legal advice. The [LICENSE](LICENSE) file governs.*

---

Built and maintained by **XAKAMOTO** — [xakamoto.com](https://xakamoto.com)

NXP and JCOP are trademarks of NXP B.V. This project is not affiliated with or endorsed by NXP B.V.
