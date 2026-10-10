# -*- coding: utf-8 -*-
#
# Copyright 2026 XAKAMOTO
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Probe the random generator of a secure element through the open EntropyProbe applet.

Measuring needs pyscard and nothing else, so the tool can be published alongside the applet and
audited on its own. Loading and deleting the applet (--load, --delete, --once, --many) also
need GlobalPlatformPro's gp.jar and a Java 11+ runtime, given with --gp / --java or the GP_JAR /
GP_JAVA environment variables.

    python entropy_probe.py --readers                     list the readers, with serial numbers
    python entropy_probe.py --reader 5502... --once       load, basic checks, delete, verdict
    python entropy_probe.py --reader 5502... --many       --once chip after chip, until Ctrl+C
    python entropy_probe.py --reader 5502... --load       install the applet
    python entropy_probe.py --reader 5502...              --full: every check (the default)
    python entropy_probe.py --reader 5502... --delete     remove the applet
    python entropy_probe.py --reader "ACS" --bytes 1000000 --out entropy.bin

--once is the check to run on a bare chip BEFORE it is sealed into a product: it proves that
the chip loads an applet and that its generator is not broken, and it leaves nothing behind.
--many does the same for a batch: after each verdict it waits for the chip to be taken off the
reader and for the next one, until Ctrl+C. --full is the recommendation: a larger sample and
the same sixteen power cuts.

Every verdict is also seen and heard: green and a short rising pair of notes for CHIP OK, red
and a low falling pair for REJECTED, yellow and the same note twice for NO VERDICT. --mute
silences it; colour switches itself off when the output is not a terminal, or with NO_COLOR.

Every verdict also says how long the chip took, step by step. When --many ends it adds the
batch: total and average checking time per chip, and the pace with the swaps included.

Exit codes: 0 passed, 1 the chip failed a check (loading included), 2 could not test (no
reader, no gp.jar, wrong key...). A 2 says nothing about the chip. --many returns 1 if any
chip was rejected, else 2 if any was left without a verdict, else 0.

WHAT IT IMPLEMENTS, AND AGAINST WHICH PUBLISHED CRITERIA

  FIPS 140-2, section 4.9.1  - the four power-up tests, on exactly 20 000 bits, with the
                               acceptance intervals printed verbatim from the standard.
                               Monobit, Poker, Runs, Long Run.
  NIST SP 800-22 Rev 1a      - Frequency (Monobit), section 2.1, and Runs, section 2.3,
                               each reported as a p-value against the usual alpha = 0.01.
  Own sanity checks          - byte chi-square, serial correlation, compression ratio and
                               repeated 32-byte blocks. Not from any standard; they are here
                               because they catch a stuck generator instantly.
  Across power-ups           - see below. This one is not in any of those standards and it is
                               the one that matters most for a secure element.

ONE RETEST, AND ONLY FOR WHAT CHANCE EXPLAINS. At alpha = 0.01 each NIST test fails 1 % of
healthy samples by definition, and the byte chi-square leaves 200..310 about 1.5 % of the
time: together, 3 to 4 % of healthy samples. When those are the only failures, a fresh sample
of the same size decides, and false rejections drop to about 0.2 %. Anything else rejects at
once.

WHAT THIS IS NOT. It is a FIRST-PASS FILTER. Passing it means the generator is not obviously
broken; it is not a randomness evaluation and it is not a certification. For that, run a real
battery on the raw output, which is why --out exists:

    dieharder -a -g 201 -f entropy.bin
    NIST STS (sts-2.1.2), TestU01 BigCrush, or ent

THE LIMIT THAT HAS TO BE SAID OUT LOUD. On a certified secure element the output comes from a
DRBG, so it is WHITENED. A dead physical noise source behind a healthy DRBG produces
statistically impeccable output within one power-up, and every test above would pass. That is
why --restarts exists: it pulls, cuts the card's power, pulls again, and compares ACROSS
power-ups. A generator that reseeds from a dead source repeats its stream after each reset, and
that is visible only from outside, between sessions. Nothing measured inside a single power-up
can see it.
"""
import argparse
import io
import math
import os
import re
import struct
import subprocess
import sys
import time
import wave
import zlib

AID = bytes.fromhex("454E54524F505901")
PKG_AID = "454E54524F5059"
APP_AID = AID.hex().upper()
DEFAULT_CAP = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "bin", "entropyprobe", "javacard",
    "entropyprobe.cap"))
SCARD_ATTR_VENDOR_IFD_SERIAL_NO = 0x00010103

# What each mode pulls unless --bytes / --restarts say otherwise. Both keep SIXTEEN power cuts:
# the across-power-ups test is the one that catches a dead noise source behind a healthy DRBG,
# and it is cheap. --full adds sample size, which is what the NIST tests and --out need.
MODE_DEFAULTS = {"full": (1000000, 16), "once": (65536, 16)}


class CannotTest(Exception):
    """The run could not happen. Says nothing about the chip: exit code 2, not 1."""


class StopRun(CannotTest):
    """Nothing can be tested until someone fixes this: gp.jar, Java, the CAP, the reader, a
    refused key. --many ends on it instead of waiting for the next chip."""


class ChipFailed(Exception):
    """The chip itself misbehaved: it would not load the applet, or its generator stopped."""


INS_GET_RANDOM = 0xB0
INS_DESCRIBE = 0xB2
INS_ALGORITHM = 0xB4

ALG_NAMES = {1: "ALG_PSEUDO_RANDOM", 2: "ALG_SECURE_RANDOM", 3: "ALG_TRNG",
             4: "ALG_PRESEEDED_DRBG", 5: "ALG_FAST", 6: "ALG_KEYGENERATION"}

ALPHA = 0.01          # NIST SP 800-22 significance level
FIPS_BITS = 20000     # FIPS 140-2 4.9.1 operates on exactly this many bits


# ------------------------------------------------------------------------------ card access

class SelectFailed(Exception):
    """The applet did not answer SELECT: not installed, or installed and not selectable."""


def reader_serial(name):
    """The reader's own serial number, or "" if it cannot be read.

    Read in DIRECT mode, without a card and without touching one: it is an attribute of the
    reader. It matters because PC/SC names are "<model> <n>", and <n> is handed out by the driver
    in power-on order: unplug one reader and the others are renumbered. With several readers of
    the same model, the name picks a slot; the serial picks a device.

    One attempt only. On a reader that has hung, SCardConnect blocks with no timeout, and
    insisting would only stack the hangs.
    """
    try:
        from smartcard.scard import (SCardEstablishContext, SCardConnect, SCardGetAttrib,
                                     SCardDisconnect, SCardReleaseContext, SCARD_SCOPE_USER,
                                     SCARD_SHARE_DIRECT, SCARD_LEAVE_CARD, SCARD_S_SUCCESS)
    except Exception:
        return ""
    hr, ctx = SCardEstablishContext(SCARD_SCOPE_USER)
    if hr != SCARD_S_SUCCESS:
        return ""
    try:
        hr, hcard, _ = SCardConnect(ctx, name, SCARD_SHARE_DIRECT, 0)
        if hr != SCARD_S_SUCCESS:
            return ""
        try:
            hr, val = SCardGetAttrib(hcard, SCARD_ATTR_VENDOR_IFD_SERIAL_NO)
            if hr != SCARD_S_SUCCESS or not val:
                return ""
            return bytes(val).rstrip(b"\x00").decode("utf-8", "replace").strip()
        finally:
            SCardDisconnect(hcard, SCARD_LEAVE_CARD)
    finally:
        SCardReleaseContext(ctx)


def all_readers():
    try:
        from smartcard.System import readers
    except ImportError:
        raise CannotTest("pyscard is not installed:  pip install pyscard")
    rl = readers()
    if not rl:
        raise CannotTest("no PC/SC readers found.")
    return rl


def find_reader(pattern):
    """The ONE reader that --reader names, by serial or by a piece of its name.

    It refuses to guess. With several readers and no --reader, or a name that matches more than
    one, it stops instead of taking the first: this tool installs and deletes applets and cuts
    the power of whatever card is in the field, and doing that to the card in someone else's
    reader is not an error message, it is their session gone.
    """
    rl = all_readers()
    if pattern is None:
        if len(rl) == 1:
            return rl[0]
        raise CannotTest("there are %d readers; say which one with --reader, preferably by its "
                         "serial.\n      See them with --readers." % len(rl))
    by_name = [r for r in rl if pattern.lower() in str(r).lower()]
    if len(by_name) == 1:
        return by_name[0]
    by_serial = [r for r in rl if reader_serial(str(r)) == pattern]
    if len(by_serial) == 1:
        return by_serial[0]
    if len(by_name) > 1:
        raise CannotTest("%r matches %d readers. Use the serial of the one you mean; see "
                         "--readers." % (pattern, len(by_name)))
    raise CannotTest("no reader matches %r by name or by serial. See --readers." % pattern)


def list_readers():
    print("  Reading a serial OPENS the reader. If one of them has hung, this stops on it, and")
    print("  the last name printed tells you which.")
    print()
    print("    %-3s %-46s %-16s %s" % ("#", "NAME", "SERIAL", "CARD"))
    for i, r in enumerate(all_readers()):
        name = str(r)
        sys.stdout.write("    looking at %-46s\r" % name[:46])
        sys.stdout.flush()
        try:
            c = r.createConnection()
            c.connect()
            c.disconnect()
            card = "yes"
        except Exception as e:
            txt = str(e).lower()
            card = "IN USE" if ("shar" in txt or "8010000b" in txt) else "no"
        serial = reader_serial(name)
        sys.stdout.write(" " * 64 + "\r")
        print("    %-3d %-46s %-16s %s" % (i, name, serial or "-", card))
    print()
    print("  Pass the SERIAL to --reader. The number at the end of a name is handed out by the")
    print("  driver in power-on order, and it moves when a reader is unplugged.")
    print()
    return 0


def slot_state(ctx, reader):
    """"card" or "empty", as the PC/SC service sees the reader; None if the reader has gone.

    It asks the service, not the card: nothing is powered, reset or selected.
    """
    from smartcard.scard import (SCardGetStatusChange, SCARD_S_SUCCESS, SCARD_STATE_UNAWARE,
                                 SCARD_STATE_PRESENT, SCARD_STATE_UNKNOWN,
                                 SCARD_STATE_UNAVAILABLE)
    hr, states = SCardGetStatusChange(ctx, 0, [(str(reader), SCARD_STATE_UNAWARE)])
    if hr != SCARD_S_SUCCESS or not states:
        return None
    ev = states[0][1]
    if ev & (SCARD_STATE_UNKNOWN | SCARD_STATE_UNAVAILABLE):
        return None
    return "card" if ev & SCARD_STATE_PRESENT else "empty"


def transmit(con, cmd):
    """con.transmit, with a card that stops answering (taken off the reader, or dead) raised as
    CannotTest instead of a traceback: in --many a traceback would end the whole batch."""
    try:
        return con.transmit(cmd)
    except Exception as e:
        raise CannotTest("the card stopped answering: %s" % e)


def connect(reader):
    con = reader.createConnection()
    try:
        con.connect()
    except Exception as e:
        raise CannotTest("cannot talk to the card in %s: %s" % (reader, e))
    d, sw1, sw2 = transmit(con, [0x00, 0xA4, 0x04, 0x00, len(AID)] + list(AID))
    sw = (sw1 << 8) | sw2
    if sw != 0x9000:
        raise SelectFailed("SELECT of EntropyProbe returned %04X" % sw)
    return con


def power_cycle(con, reader):
    """Cut the card's POWER and bring it back, so the next pull comes from a fresh boot.

    A plain disconnect is not enough: the point is to force the platform to re-seed, which is
    what makes the across-power-ups comparison meaningful.
    """
    try:
        from smartcard.scard import SCardDisconnect, SCARD_UNPOWER_CARD
        comp = con.component
        SCardDisconnect(comp.hcard, SCARD_UNPOWER_CARD)
        comp.hcard = None
    except Exception:
        try:
            con.disconnect()
        except Exception:
            pass
    time.sleep(0.25)      # let the field actually collapse before coming back
    return connect(reader)


def apdu(con, ins, le=0):
    d, sw1, sw2 = transmit(con, [0x00, ins, 0x00, 0x00, le])
    return bytes(d), (sw1 << 8) | sw2


def pull(con, n, quiet=False):
    out = bytearray()
    t0 = time.time()
    while len(out) < n:
        k = min(255, n - len(out))
        d, sw = apdu(con, INS_GET_RANDOM, le=k)
        if sw != 0x9000:
            raise ChipFailed("GET RANDOM returned %04X after %d bytes" % (sw, len(out)))
        if len(d) != k:
            raise ChipFailed("asked the generator for %d bytes and got %d" % (k, len(d)))
        out += d
        if not quiet and len(out) % 25500 == 0:
            print("    %d bytes..." % len(out))
    return bytes(out), time.time() - t0


def bits_of(b):
    out = []
    for x in b:
        for i in range(7, -1, -1):
            out.append((x >> i) & 1)
    return out


# ---------------------------------------------------------- FIPS 140-2, section 4.9.1

def fips_monobit(bits):
    """Acceptance interval from the standard: 9725 < X < 10275 on 20 000 bits."""
    x = sum(bits)
    return x, (9725 < x < 10275), "9725 < X < 10275"


def fips_poker(bits):
    """5000 four-bit segments. X = (16/5000)*sum(f_i^2) - 5000. Pass: 2.16 < X < 46.17."""
    f = [0] * 16
    for i in range(0, 20000, 4):
        f[(bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3]] += 1
    x = (16.0 / 5000.0) * sum(v * v for v in f) - 5000.0
    return x, (2.16 < x < 46.17), "2.16 < X < 46.17"


FIPS_RUNS_INTERVALS = {1: (2315, 2685), 2: (1114, 1386), 3: (527, 723),
                       4: (240, 384), 5: (103, 209), 6: (103, 209)}


def fips_runs(bits):
    """Runs of each length, counted separately for zeros and ones. Lengths 6 and above are
    pooled into the '6+' bucket, as the standard prescribes."""
    counts = {0: {k: 0 for k in FIPS_RUNS_INTERVALS},
              1: {k: 0 for k in FIPS_RUNS_INTERVALS}}
    longest = 0
    val, ln = bits[0], 1
    for b in bits[1:]:
        if b == val:
            ln += 1
        else:
            counts[val][min(ln, 6)] += 1
            longest = max(longest, ln)
            val, ln = b, 1
    counts[val][min(ln, 6)] += 1
    longest = max(longest, ln)

    ok = True
    filas = []
    for k in sorted(FIPS_RUNS_INTERVALS):
        lo, hi = FIPS_RUNS_INTERVALS[k]
        for v in (0, 1):
            c = counts[v][k]
            bien = lo <= c <= hi
            ok = ok and bien
            filas.append((("%d+" % k) if k == 6 else str(k), v, c, lo, hi, bien))
    return filas, ok, longest


def fips_long_run(longest):
    """No run of 26 bits or more."""
    return longest, longest < 26, "longest run < 26"


# ------------------------------------------------------- NIST SP 800-22 Rev 1a, with p-values

def nist_frequency(bits):
    """Section 2.1, Frequency (Monobit). p = erfc(|s_obs| / sqrt(2))."""
    n = len(bits)
    s = abs(sum(1 if b else -1 for b in bits)) / math.sqrt(n)
    return s, math.erfc(s / math.sqrt(2))


def nist_runs(bits):
    """Section 2.3, Runs. Requires the frequency prerequisite to hold first."""
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return None, 0.0, False
    v = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
    num = abs(v - 2.0 * n * pi * (1 - pi))
    den = 2.0 * math.sqrt(2.0 * n) * pi * (1 - pi)
    return v, math.erfc(num / den), True


# ------------------------------------------------------------------------ own sanity checks

def byte_chi_square(b):
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    exp = len(b) / 256.0
    return sum((c - exp) ** 2 / exp for c in counts)


def serial_correlation(b):
    n = len(b) - 1
    if n < 2:
        return 0.0
    x, y = b[:-1], b[1:]
    mx, my = sum(x) / n, sum(y) / n
    num = sum((a - mx) * (c - my) for a, c in zip(x, y))
    dx = math.sqrt(sum((a - mx) ** 2 for a in x))
    dy = math.sqrt(sum((d - my) ** 2 for d in y))
    return num / (dx * dy) if dx and dy else 0.0


def compression(b):
    return len(zlib.compress(bytes(b), 9)) / len(b)


def repeated_blocks(b, size=32):
    seen, dup = set(), 0
    for i in range(0, len(b) - size + 1, size):
        t = bytes(b[i:i + size])
        if t in seen:
            dup += 1
        seen.add(t)
    return dup


# ------------------------------------------------------------------------------------ report

def si(b):
    return "PASS" if b else "FAIL"


def run_fips_and_nist(data, flags, chance):
    """FIPS failures go to `flags`. NIST failures go to `chance`: see retest()."""
    bits = bits_of(data[:FIPS_BITS // 8])
    print("  " + "=" * 72)
    print("  FIPS 140-2, section 4.9.1 - power-up tests, on %d bits" % FIPS_BITS)
    print("  " + "=" * 72)

    x, ok1, crit = fips_monobit(bits)
    print("    Monobit    X = %-8d %-22s %s" % (x, crit, si(ok1)))
    xp, ok2, critp = fips_poker(bits)
    print("    Poker      X = %-8.3f %-22s %s" % (xp, critp, si(ok2)))
    filas, ok3, longest = fips_runs(bits)
    print("    Runs                                              %s" % si(ok3))
    for k, v, c, lo, hi, bien in filas:
        if not bien:
            print("        length %-3s of %d : %-6d outside [%d, %d]" % (k, v, c, lo, hi))
    lr, ok4, critl = fips_long_run(longest)
    print("    Long run   longest = %-4d %-19s %s" % (lr, critl, si(ok4)))
    for nombre, o in (("FIPS Monobit", ok1), ("FIPS Poker", ok2),
                      ("FIPS Runs", ok3), ("FIPS Long run", ok4)):
        if not o:
            flags.append("%s FAILED (FIPS 140-2 4.9.1)" % nombre)

    print()
    print("  " + "=" * 72)
    print("  NIST SP 800-22 Rev 1a - p-values, alpha = %.2f, on the full sample" % ALPHA)
    print("  " + "=" * 72)
    allbits = bits_of(data)
    s, p1 = nist_frequency(allbits)
    print("    2.1 Frequency (Monobit)   s = %-8.4f p = %.6f   %s"
          % (s, p1, si(p1 >= ALPHA)))
    if p1 < ALPHA:
        chance.append("NIST 2.1 Frequency p = %.6f is below alpha" % p1)
    v, p2, prereq = nist_runs(allbits)
    if not prereq:
        print("    2.3 Runs                  prerequisite not met (frequency too skewed)")
        chance.append("NIST 2.3 Runs could not run: the frequency prerequisite failed")
    else:
        print("    2.3 Runs                  V = %-8d p = %.6f   %s"
              % (v, p2, si(p2 >= ALPHA)))
        if p2 < ALPHA:
            chance.append("NIST 2.3 Runs p = %.6f is below alpha" % p2)


def run_sanity(data, flags, chance):
    """The chi-square goes to `chance` (see retest()); the rest, to `flags`."""
    print()
    print("  " + "=" * 72)
    print("  Own sanity checks - not from any standard, but they catch a stuck generator")
    print("  " + "=" * 72)
    chi = byte_chi_square(data)
    sc = serial_correlation(data)
    comp = compression(data)
    dup = repeated_blocks(data)
    print("    byte chi-square (255 df)  %-10.1f healthy: roughly 200 to 310" % chi)
    print("    serial correlation        %+-10.6f healthy: very close to 0" % sc)
    print("    compression ratio         %-10.4f healthy: >= 1.0" % comp)
    print("    repeated 32-byte blocks   %-10d healthy: 0" % dup)
    if not (200 < chi < 310):
        chance.append("byte chi-square out of range: the distribution is not flat")
    if abs(sc) > 0.02:
        flags.append("consecutive bytes are correlated")
    if comp < 1.0:
        flags.append("THE OUTPUT COMPRESSES: that does not happen to a random sequence")
    if dup:
        flags.append("REPEATED 32-BYTE BLOCKS: the generator is stuck")


def retest(con, n_bytes):
    """A fresh sample, for a first one that failed ONLY the checks a healthy generator fails by
    chance. Returns what still counts: nothing if the fresh sample passes, else all it failed.

    NIST 2.1 and 2.3 at alpha = 0.01 fail 1 % of healthy samples each, by definition, and the
    byte chi-square falls outside 200..310 for about 1.5 %. Measured on 6000 samples of
    os.urandom through these same functions, 3 to 4 % of healthy samples fail one of the three:
    a batch of 100 good chips would lose three or four. Asking the fresh sample to fail as well
    brings false rejections to about 0.2 % (8 of 4000, measured end to end). A broken generator
    is not rescued by it: it fails both samples, and by far. Everything else (FIPS 140-2,
    correlation, compression, repeated blocks, across power-ups) rejects at the first failure.
    """
    print()
    print("  " + "=" * 72)
    print("  RETEST - the sample failed only checks that a healthy generator fails by chance,")
    print("  about one sample in 30. A fresh sample of %d bytes decides." % n_bytes)
    print("  " + "=" * 72)
    data, _ = pull(con, n_bytes)
    print()
    flags, chance = [], []
    run_fips_and_nist(data, flags, chance)
    run_sanity(data, flags, chance)
    print()
    if not (flags or chance):
        print("    the fresh sample passes every check: the first failure was chance")
        return []
    print("    the fresh sample fails too")
    return ["on the retest: %s" % f for f in flags + chance]


def run_restarts(con, reader, n_restarts, chunk, flags):
    """The test no single-session battery can do, and the one that matters on a DRBG."""
    print()
    print("  " + "=" * 72)
    print("  Across power-ups - %d restarts of %d bytes each" % (n_restarts, chunk))
    print("  " + "=" * 72)
    print("    A DRBG re-seeded from a DEAD noise source repeats its stream after every")
    print("    reset, and produces impeccable statistics within each session. Only a")
    print("    comparison BETWEEN power-ups can see it.")
    print()
    sesiones = []
    for i in range(n_restarts):
        d, _ = pull(con, chunk, quiet=True)
        sesiones.append(d)
        print("    session %d/%d  first 16 bytes: %s" % (i + 1, n_restarts, d[:16].hex().upper()))
        if i < n_restarts - 1:
            con = power_cycle(con, reader)
    print()
    iguales = sum(1 for i in range(len(sesiones)) for j in range(i + 1, len(sesiones))
                  if sesiones[i] == sesiones[j])
    prefijos = len({s[:16] for s in sesiones})
    todos = b"".join(sesiones)
    dup_cross = repeated_blocks(todos) - sum(repeated_blocks(s) for s in sesiones)
    print("    identical sessions            %-6d must be 0" % iguales)
    print("    distinct 16-byte prefixes     %-6d must be %d" % (prefijos, n_restarts))
    print("    repeated blocks across only   %-6d must be 0" % dup_cross)
    if iguales:
        flags.append("TWO SESSIONS CAME BACK IDENTICAL AFTER A POWER CUT: the generator "
                     "repeats between boots. This is the failure mode that whitening hides.")
    if prefijos != n_restarts:
        flags.append("two power-ups produced the same first 16 bytes")
    if dup_cross:
        flags.append("32-byte blocks repeat ACROSS power-ups")
    return con


# ---------------------------------------------------------------- loading and deleting (gp.jar)

class KeyRefused(StopRun):
    """The security domain rejected the key. Nothing else may be sent to it in this run."""


def tail(out, n=12):
    lines = [l for l in out.strip().splitlines() if l.strip()]
    return "\n".join("        | " + l for l in lines[-n:])


def gp(a, reader, *args):
    """Run gp.jar against THIS reader, by its full name, and return (exit code, output).

    The reader is resolved once, by pyscard, and its full name travels in every call. Without
    --reader, gp.jar takes the first PC/SC reader it finds, which with two readers connected is
    how a --delete lands on the wrong card.
    """
    jar = a.gp or os.environ.get("GP_JAR")
    java = a.java or os.environ.get("GP_JAVA") or "java"
    if not jar:
        raise StopRun("loading and deleting need GlobalPlatformPro: pass --gp <path to "
                      "gp.jar>, or set GP_JAR.\n      If you have just set it, open a new "
                      "window: one that was already open does not see it.")
    if not os.path.isfile(jar):
        raise StopRun("gp.jar is not at %s" % jar)
    cmd = [java, "-jar", jar, "--reader", str(reader)]
    if a.key:
        cmd += ["--key", a.key]
    cmd += list(args)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except FileNotFoundError:
        raise StopRun("cannot run %r. Pass --java with a Java 11+ runtime, or set GP_JAVA."
                      % java)
    except subprocess.TimeoutExpired:
        raise CannotTest("gp.jar did not answer in 180 s: the reader may have hung.")
    out = (p.stdout or "") + (p.stderr or "")
    low = out.lower()
    if "unsupportedclassversionerror" in low:
        raise StopRun("gp.jar needs Java 11 or newer, and %s is older. Pass --java." % java)
    # gp.jar's own words when the card cryptogram does not verify. Matched on "invalid" and on
    # the warning, not on "cryptogram" alone: a successful run can print "Verified card
    # cryptogram", and treating that as a refusal would stop a healthy card.
    if "cryptogram invalid" in low or "brick your card" in low or "do not re-try" in low:
        raise KeyRefused(
            "THE CARD REFUSED THE KEY: its security domain does not use %s.\n"
            "      STOP HERE and do not retry. Every failed authentication counts, and enough "
            "of them can\n      lock the card for good. Ask the supplier for the transport key "
            "and pass it with --key."
            % ("the key given with --key" if a.key else "gp.jar's default key, 404142...4F"))
    return p.returncode, out


def installed(a, reader):
    """(instance present, package present), from gp.jar --list.

    Matched as whole AIDs on their own lines: the instance AID starts with the package AID, so a
    plain substring test would find the package wherever the instance is listed.
    """
    rc, out = gp(a, reader, "--list")
    if rc != 0:
        raise CannotTest("gp.jar --list failed (exit %d):\n%s" % (rc, tail(out)))
    up = out.upper()
    app = re.search(r"APP:\s*%s(?![0-9A-F])" % APP_AID, up) is not None
    pkg = re.search(r"PKG:\s*%s(?![0-9A-F])" % PKG_AID, up) is not None
    return app, pkg


def delete_applet(a, reader):
    app, pkg = installed(a, reader)
    if not (app or pkg):
        print("  the applet is not on the card: nothing to delete")
        return
    args = (["--delete", APP_AID] if app else []) + (["--delete", PKG_AID] if pkg else [])
    rc, out = gp(a, reader, *args)
    app, pkg = installed(a, reader)
    if app or pkg:
        raise ChipFailed("the applet is still on the card after deleting it (gp.jar exit %d):\n%s"
                         % (rc, tail(out)))
    print("  applet deleted: instance and package are gone")


def load_applet(a, reader):
    """Install the probe, and prove it: listed by the card AND answering SELECT.

    If a previous run left it on the card it is deleted first, so that what is measured is a
    real load and not a leftover.
    """
    cap = a.cap or DEFAULT_CAP
    if not os.path.isfile(cap):
        raise StopRun("the CAP is not at %s. Build it, or pass --cap." % cap)
    app, pkg = installed(a, reader)
    if app or pkg:
        print("  the applet was already on the card: deleting it first, so this load is a real one")
        delete_applet(a, reader)
    print("  installing %s ..." % os.path.basename(cap))
    t0 = time.time()
    rc, out = gp(a, reader, "--install", cap)
    dt = time.time() - t0
    app, pkg = installed(a, reader)
    if not (app and pkg):
        raise ChipFailed("THE CHIP DID NOT LOAD THE APPLET (gp.jar exit %d):\n%s" % (rc, tail(out)))
    try:
        connect(reader).disconnect()
    except SelectFailed as e:
        raise ChipFailed("the applet is listed but does not answer: %s" % e)
    print("  loaded in %.1f s: the card lists package and instance, and the applet answers" % dt)


# ----------------------------------------------------------------------------- verdict signals

# One colour and one short tune per verdict, so that it can be told from across the bench
# without reading it. (Hz, ms) per note, 0 Hz being a silence: CHIP OK rises, REJECTED falls
# low, NO VERDICT repeats one note.
VERDICT_COLOUR = {0: "32", 1: "31", 2: "33"}            # green, red, yellow
VERDICT_TUNE = {0: [(880, 80), (1319, 130)],
                1: [(392, 180), (311, 300)],
                2: [(659, 110), (0, 70), (659, 110)]}


def colour_works():
    """Colour only on a terminal, and never with NO_COLOR. The classic Windows console prints
    the escape codes as garbage unless VT processing is on, so it is switched on here; if that
    fails, there is no colour."""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        out = k32.GetStdHandle(-11)                                  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        return bool(k32.GetConsoleMode(out, ctypes.byref(mode))
                    and k32.SetConsoleMode(out, mode.value | 0x0004))  # VT processing
    except Exception:
        return False


def paint(a, text, verdict):
    return "\x1b[1;%sm%s\x1b[0m" % (VERDICT_COLOUR[verdict], text) if a.colour else text


def say(a, verdict, *lines):
    for line in lines:
        print(paint(a, line, verdict))


def tune_wav(notes, rate=22050, volume=0.25):
    """A WAV in memory: sine notes at a quarter of full scale, each with an 8 ms fade in and a
    40 ms fade out, so that nothing clicks and nothing is loud."""
    frames = bytearray()
    for hz, ms in notes:
        n, rise, fall = rate * ms // 1000, rate * 8 // 1000, rate * 40 // 1000
        for i in range(n):
            env = min(1.0, i / rise, (n - i) / fall) if hz else 0.0
            frames += struct.pack("<h", int(volume * 32767 * env
                                            * math.sin(2 * math.pi * hz * i / rate)))
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(frames))
    return buf.getvalue()


def announce(a, verdict):
    """The verdict as a short tune; outside Windows, as terminal bells: one for CHIP OK, three
    for REJECTED, two for NO VERDICT. It must never cost a verdict, so a machine without sound
    simply stays quiet."""
    if a.mute:
        return
    sys.stdout.flush()
    try:
        import winsound
    except ImportError:
        if sys.stdout.isatty():
            for _ in range({0: 1, 1: 3, 2: 2}[verdict]):
                sys.stdout.write("\a")
                sys.stdout.flush()
                time.sleep(0.2)
        return
    try:
        winsound.PlaySound(tune_wav(VERDICT_TUNE[verdict]),
                           winsound.SND_MEMORY | winsound.SND_NODEFAULT)
    except Exception:
        pass


# ------------------------------------------------------------------------------ the three runs

def measure(reader, n_bytes, n_restarts, restart_bytes, out_path):
    """Pull, test, and return the list of failures. Empty means every check passed."""
    con = connect(reader)

    d, sw = apdu(con, INS_ALGORITHM, le=1)
    if sw == 0x9000 and d:
        print("  algorithm declared by the card: 0x%02X  %s"
              % (d[0], ALG_NAMES.get(d[0], "unknown")))
    d, sw = apdu(con, INS_DESCRIBE)
    if sw == 0x9000 and d:
        print()
        for line in d.decode("ascii", "replace").split("\n"):
            print("    | %s" % line)
    print()

    print("  pulling %d bytes in chunks of 255..." % n_bytes)
    data, dt = pull(con, n_bytes)
    print()
    print("  %d bytes in %.1f s  =  %.0f bytes/s  (%.2f ms per 32 bytes)"
          % (len(data), dt, len(data) / dt, (dt / len(data)) * 32 * 1000))
    print("  note: the cost is PER REQUEST, not per byte. Pulling 255 bytes at a time is")
    print("  about four times cheaper per byte than pulling 32.")
    print()

    flags, chance = [], []
    run_fips_and_nist(data, flags, chance)
    run_sanity(data, flags, chance)
    if chance and not flags:
        again = retest(con, n_bytes)
        chance = chance + again if again else []
    flags += chance
    if n_restarts > 0:
        con = run_restarts(con, reader, n_restarts, restart_bytes, flags)
    try:
        con.disconnect()
    except Exception:
        pass

    if out_path:
        with open(out_path, "wb") as f:
            f.write(data)
        print()
        print("  raw output written to %s  (%d bytes)" % (out_path, len(data)))
        print("  dieharder -a -g 201 -f %s" % out_path)
        print("  ent %s" % out_path)
    return flags


def full(a, reader):
    """Every check, with the large sample: the run that backs a recommendation."""
    t0 = time.time()
    try:
        flags = measure(reader, a.bytes, a.restarts, a.restart_bytes, a.out)
    except SelectFailed as e:
        raise CannotTest("%s: the applet is not on this card. Install it with --load." % e)
    verdict = 1 if flags else 0
    rule = paint(a, "  " + "=" * 72, verdict)
    print()
    print(rule)
    if flags:
        say(a, 1, "  [X] DID NOT PASS")
        for f in flags:
            print("      - %s" % f)
        print()
        print("  Do not use this part for anything that holds value.")
    else:
        say(a, 0, "  [+] PASSES EVERY CHECK IN THIS TOOL")
        print()
        print("      That is not a certification and not a randomness evaluation. It means")
        print("      the generator is not obviously broken, and that it does not repeat")
        print("      across power-ups. To claim more, run a real battery on the raw output.")
    print()
    print("      time: %s" % hms(time.time() - t0))
    print(rule)
    print()
    announce(a, verdict)
    return verdict


def step(title):
    print()
    print("  " + "-" * 72)
    print("  %s" % title)
    print("  " + "-" * 72)


def hms(s):
    """58.2 s, 4 min 52 s, 1 h 03 min: what reads at a glance from the bench."""
    if s < 60:
        return "%.1f s" % s
    if s < 3600:
        return "%d min %02d s" % (s // 60, s % 60)
    return "%d h %02d min" % (s // 3600, s % 3600 // 60)


def once(a, reader):
    """The check for a bare chip BEFORE it is sealed into a product. Load, test, delete, verdict.

    It answers two questions and only two: does this chip load an applet, and is its generator
    not broken. Across power-ups is included on purpose: it is the one check that sees a dead
    noise source behind a healthy DRBG, and that failure passes every statistical test inside a
    single power-up.

    The applet is deleted whatever happened, except on a StopRun: then either nothing reached
    the card (gp.jar, Java or the CAP missing), or the card has refused the key and nothing
    more may be sent to it, because every further authentication would count against it.

    Returns the verdict (0 OK, 1 rejected, 2 no verdict) and the seconds the chip took.
    """
    problems, leftover, steps = [], None, []    # steps: (name, seconds) of those that ran
    t0 = t = time.time()
    step("1/3  LOAD - does the chip take an applet?")
    try:
        load_applet(a, reader)
    except StopRun:
        raise
    except ChipFailed as e:
        problems.append(str(e))
    except CannotTest as e:
        leftover = "the load could not finish: %s" % e
    steps.append(("load", time.time() - t))
    if not (problems or leftover):
        step("2/3  GENERATOR - basic checks, %d bytes and %d power cuts" % (a.bytes, a.restarts))
        t = time.time()
        try:
            problems += measure(reader, a.bytes, a.restarts, a.restart_bytes, a.out)
        except (ChipFailed, SelectFailed) as e:
            problems.append(str(e))
        except CannotTest as e:
            leftover = "the checks could not finish: %s" % e
        steps.append(("generator", time.time() - t))
    step("3/3  DELETE - leave nothing on the chip")
    t = time.time()
    try:
        delete_applet(a, reader)
    except StopRun:
        raise
    except (ChipFailed, CannotTest) as e:
        leftover = ((leftover + "\n      ") if leftover else "") + \
            "THE PROBE MAY STILL BE ON THE CHIP: %s\n      Run --delete before sealing it." % e
    steps.append(("delete", time.time() - t))
    took = time.time() - t0

    verdict = 1 if problems else (2 if leftover else 0)
    rule = paint(a, "  " + "=" * 72, verdict)
    print()
    print(rule)
    if problems:
        say(a, 1, "  [X] CHIP REJECTED - do not seal it into a product")
        for p in problems:
            print("      - %s" % p)
    elif leftover:
        say(a, 2, "  [!] NO VERDICT")
    else:
        say(a, 0, "  [+] CHIP OK - it loads an applet, its generator passed the basic checks,",
                  "      and the probe is gone.")
        print()
        print("      A pre-sealing check, not the recommendation: that is --full.")
    if leftover:
        print()
        print("      %s" % leftover)
    print()
    print("      time: %s   (%s)" % (hms(took), ", ".join("%s %s" % (name, hms(s))
                                                         for name, s in steps)))
    print(rule)
    print()
    announce(a, verdict)
    return verdict, took


POLL = 0.2       # seconds between two looks at the reader while --many waits
SETTLE = 1.0     # a chip has to stay on the reader this long before it is tested...
GONE = 1.0       # ...and the reader has to stay empty this long before the chip counts as gone


def wait_for(reader, want, hold):
    """Wait until the reader has shown `want` ("card" or "empty") for `hold` seconds in a row.

    In a row, because a contactless chip that is being put down or picked up comes and goes for
    a moment, and each blip would otherwise count as a new chip. Only the PC/SC service is
    asked, so waiting touches no card; and it polls instead of blocking, so Ctrl+C gets through.
    """
    from smartcard.scard import (SCardEstablishContext, SCardReleaseContext, SCARD_SCOPE_USER,
                                 SCARD_S_SUCCESS)
    hr, ctx = SCardEstablishContext(SCARD_SCOPE_USER)
    if hr != SCARD_S_SUCCESS:
        raise StopRun("the PC/SC service does not answer.")
    try:
        since = None
        while True:
            state = slot_state(ctx, reader)
            if state is None:
                raise StopRun("the reader %s is gone." % reader)
            if state != want:
                since = None
            elif since is None:
                since = time.time()
            elif time.time() - since >= hold:
                return
            time.sleep(POLL)
    finally:
        SCardReleaseContext(ctx)


def many(a, reader):
    """--once for a batch: chip after chip on the same reader, until Ctrl+C.

    A chip only counts as new after the reader has been empty, so the same chip is never tested
    twice in a row by itself. The loop ends on its own only when no chip could be tested anyway:
    gp.jar, Java or the CAP missing, the reader gone, or a refused key. After a refused key the
    next chip of the same batch would almost certainly refuse it too, and every attempt counts
    against the chip that receives it.
    """
    chips = {0: [], 1: [], 2: []}       # verdict, as --once returns it -> chip numbers
    out, n, testing, interrupted, stopped = a.out, 0, False, False, None
    took, first, last = [], None, None  # seconds per finished chip; first chip on, last verdict
    print()
    print("  --many: put the chips on the reader one at a time. Ctrl+C when there are no more.")
    try:
        while True:
            print()
            print("  waiting for a chip...")
            wait_for(reader, "card", SETTLE)
            n += 1
            if first is None:
                first = time.time()
            print()
            print("  " + "#" * 72)
            print("  CHIP %d" % n)
            print("  " + "#" * 72)
            if out:
                root, ext = os.path.splitext(out)
                a.out = "%s-%03d%s" % (root, n, ext)
            testing = True
            verdict, seconds = once(a, reader)
            testing = False
            last = time.time()
            chips[verdict].append(n)
            took.append(seconds)
            print("  so far: %d OK, %d rejected, %d without a verdict; %s per chip on average"
                  % (len(chips[0]), len(chips[1]), len(chips[2]), hms(sum(took) / len(took))))
            print()
            print("  take the chip off the reader...")
            wait_for(reader, "empty", GONE)
    except StopRun as e:
        stopped = str(e)
    except KeyboardInterrupt:
        interrupted = testing
    if testing:
        chips[2].append(n)

    print()
    print("  " + "=" * 72)
    if stopped:
        say(a, 2, "  [!] --many STOPPED: %s" % stopped)
        print()
    if interrupted:
        say(a, 2, "  [!] chip %d was interrupted in the middle of its test: it has no verdict, "
                  "and the" % n,
                  "      probe may still be on it. Test it again before sealing it.")
        print()
    print("  --many: %d chip%s" % (n, "" if n == 1 else "s"))
    for label, verdict in (("OK", 0), ("REJECTED", 1), ("NO VERDICT", 2)):
        which = " ".join("#%d" % k for k in chips[verdict]) if verdict else ""
        print(("      %-11s %3d   %s" % (label, len(chips[verdict]), which)).rstrip())
    if took:
        # Only chips that reached a verdict: an interrupted one has no complete time. The batch
        # runs from the first chip put down to the last verdict, so the swaps count and the
        # wait before the first chip and after the last one do not.
        spread = "   (%s to %s)" % (hms(min(took)), hms(max(took))) if len(took) > 1 else ""
        print()
        print("      checking      %-11s   %s per chip%s"
              % (hms(sum(took)), hms(sum(took) / len(took)), spread))
        print("      whole batch   %-11s   %s per chip, swaps included"
              % (hms(last - first), hms((last - first) / len(took))))
    print("  " + "=" * 72)
    print()
    if stopped:
        announce(a, 2)      # nobody pressed Ctrl+C: whoever is at the bench has to hear it
    if chips[1]:
        return 1
    return 2 if (chips[2] or stopped) else 0


# ---------------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--readers", action="store_true",
                      help="list the readers with their serial numbers, and exit")
    mode.add_argument("--load", action="store_true",
                      help="install the applet (needs gp.jar and Java 11+)")
    mode.add_argument("--delete", action="store_true",
                      help="remove the applet (needs gp.jar and Java 11+)")
    mode.add_argument("--once", action="store_true",
                      help="pre-sealing check of a bare chip: load, basic checks, delete, verdict")
    mode.add_argument("--many", action="store_true",
                      help="--once chip after chip on the same reader, until Ctrl+C")
    mode.add_argument("--full", action="store_true",
                      help="every check with a large sample, the recommendation (the default)")
    ap.add_argument("--reader", default=None,
                    help="the reader: its serial (see --readers) or a piece of its name")
    ap.add_argument("--bytes", type=int, default=None,
                    help="bytes for the single-session tests (--full %d, --once and --many %d)"
                         % (MODE_DEFAULTS["full"][0], MODE_DEFAULTS["once"][0]))
    ap.add_argument("--restarts", type=int, default=None,
                    help="power-up cycles (default %d, 0 to skip)" % MODE_DEFAULTS["full"][1])
    ap.add_argument("--restart-bytes", type=int, default=1024, help="bytes pulled per power-up")
    ap.add_argument("--out", default=None, help="dump the raw output to this file")
    ap.add_argument("--gp", default=None, help="path to GlobalPlatformPro's gp.jar (or GP_JAR)")
    ap.add_argument("--java", default=None,
                    help="a Java 11+ runtime for gp.jar (or GP_JAVA; default: java)")
    ap.add_argument("--key", default=None,
                    help="the card's security domain key in hex, if not the default 404142...4F")
    ap.add_argument("--cap", default=None, help="the CAP to install (default: the one in bin/)")
    ap.add_argument("--mute", action="store_true",
                    help="no sound at the verdict (colour switches itself off when the output "
                         "is not a terminal, or with NO_COLOR)")
    a = ap.parse_args()
    a.colour = colour_works()
    reviews = not (a.readers or a.load or a.delete)     # the runs that end in a verdict

    try:
        if a.readers:
            return list_readers()
        n_bytes, n_restarts = MODE_DEFAULTS["once" if (a.once or a.many) else "full"]
        a.bytes = n_bytes if a.bytes is None else a.bytes
        a.restarts = n_restarts if a.restarts is None else a.restarts
        if not (a.load or a.delete) and a.bytes < FIPS_BITS // 8:
            raise CannotTest("--bytes must be at least %d: FIPS 140-2 4.9.1 needs %d bits."
                             % (FIPS_BITS // 8, FIPS_BITS))
        reader = find_reader(a.reader)
        print("  reader: %s" % reader)
        if a.load:
            load_applet(a, reader)
            return 0
        if a.delete:
            delete_applet(a, reader)
            return 0
        if a.once:
            return once(a, reader)[0]
        if a.many:
            return many(a, reader)
        return full(a, reader)
    except CannotTest as e:
        print()
        say(a, 2, "  [!] COULD NOT TEST: %s" % e)
        print("      This says nothing about the chip.")
        print()
        if reviews:
            announce(a, 2)
        return 2
    except (ChipFailed, SelectFailed) as e:
        print()
        say(a, 1, "  [X] %s" % e)
        print()
        if reviews:
            announce(a, 1)
        return 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
