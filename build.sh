#!/usr/bin/env bash
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
#
# ---------------------------------------------------------------------------------------------
# Builds EntropyProbe.
#
# THE THING THAT MATTERS ABOUT THIS BUILD: there is no vendor-proprietary package anywhere in
# it. No JCOPx classpath, no proprietary .exp on the export path. The applet uses only the
# standard Java Card API, and that is precisely what makes this source publishable without
# anyone's permission.
#
# If someone ever adds an import of a proprietary package, the build below would happily keep
# compiling and the applet would quietly stop being publishable. Hence the explicit check.
#
# Override the toolchain locations with environment variables if yours differ:
#   JC_BUILDER   the JCIDE builder directory (ECJ, manifold, converter)
#   JC_API       the classic API lib directory (api_classic.jar and export files)
#   JDK_TOOLS    path to tools.jar of a JDK 8
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/src"
OUT="$HERE/bin"

B="${JC_BUILDER:-C:/JCKit/SDK/Tools/JCIDE/builder}"
API="${JC_API:-C:/JCKit/SDK/Tools/ChipPack/JAVACOS/lib/java_card_kit/3_0_4/lib}"
TOOLS="${JDK_TOOLS:-C:/Program Files/Eclipse Adoptium/jdk-8.0.492.9-hotspot/lib/tools.jar}"
ECJ_CP="$B/ECJ/ecj.jar;$B/manifold/manifold-2020.1.42.jar;$B/manifold/manifold-preprocessor-2020.1.37.jar;$B/manifold/manifold-rt-2020.1.37.jar;$B/manifold/manifold-util-2020.1.42.jar;$TOOLS"

# AID. ASCII "ENTROPY" for the package, +01 for the applet instance.
#
# IF YOU FORK THIS FOR PRODUCTION, REGISTER YOUR OWN RID. ISO/IEC 7816-5 assigns 5-byte
# registered identifiers; what follows is fine for development and evaluation cards, but a
# shared namespace collides the moment two vendors ship it.
PKG_AID="0x45:0x4E:0x54:0x52:0x4F:0x50:0x59"
APP_AID="0x45:0x4E:0x54:0x52:0x4F:0x50:0x59:0x01"

mkdir -p "$OUT"

echo "== checking there are no proprietary dependencies =="
if grep -rn "com\.nxp\|jcopx\|javacardx" "$SRC"; then
  echo "ERROR: EntropyProbe imports something that is not the standard Java Card API." >&2
  echo "That import breaks the one property that makes this applet publishable." >&2
  exit 1
fi
echo "   javacard.framework and javacard.security only. Publishable."

for f in "$B/ECJ/ecj.jar" "$API/api_classic.jar"; do
  [ -f "$f" ] || { echo "ERROR: missing $f  (set JC_BUILDER / JC_API)" >&2; exit 1; }
done

echo "== compiling =="
cd "$SRC"
# NO PIPE THE COMPILER THROUGH tail. It hid a real compile error once: the converter then
# happily converted a STALE .class and produced a CAP that was missing a command, which only
# showed up as a 6D00 on the card. Show everything, and stop on failure.
if ! java -cp "$ECJ_CP" org.eclipse.jdt.internal.compiler.batch.FTMain \
     -1.7 -target 1.7 -encoding windows-1252 \
     -d "$OUT" -classpath "$API/api_classic.jar" \
     entropyprobe/*.java; then
  echo "ERROR: compilation failed. Not converting." >&2
  exit 1
fi

# The converter reads .class files, so a stale one converts silently. Refuse if the class is
# older than its source.
if [ "$SRC/entropyprobe/EntropyProbe.java" -nt "$OUT/entropyprobe/EntropyProbe.class" ]; then
  echo "ERROR: EntropyProbe.class is older than its source. The compile did not run." >&2
  exit 1
fi

echo "== converting =="
java -jar "$B/converter/ft222/ft222.jar" \
  -classdir "$OUT" \
  -exportpath "$API/../export_files/api_classic_export_files" \
  -out EXP JCA CAP \
  -d "$OUT" \
  -applet $APP_AID entropyprobe.EntropyProbe \
  entropyprobe $PKG_AID 1.0

echo "== done =="
find "$OUT" -name '*.cap' | sed 's/^/   /'
echo "   install with:  gp --reader <READER> --install <cap>"
