#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "${1:-}" != "--no-build" ]]; then
  echo "Building Paper shadowJar..."
  ./gradlew :paper:shadowJar --console=plain
fi

WORK_DIR="paper/build/smoke-run"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/plugins"

JAR="$(find paper/build/libs -maxdepth 1 -name 'JustLogin-*.jar' | head -n 1)"
if [[ -z "$JAR" ]]; then
  echo "Missing Paper shadowJar"
  exit 1
fi
cp "$JAR" "$WORK_DIR/plugins/JustLogin.jar"

# Let run-paper mount the built plugin jar cleanly without duplicate copies
rm -rf paper/run/plugins/JustLogin* paper/run/logs/latest.log 2>/dev/null || true
mkdir -p paper/run/plugins

# Standalone /premium hook only activates on servers without Mojang authentication (online-mode=false), which is what
# the banner check below expects. A fresh CI server defaults to online-mode=true, so force it here.
PROPS="paper/run/server.properties"
if [[ -f "$PROPS" ]] && grep -q '^online-mode=' "$PROPS"; then
  sed -i.bak 's/^online-mode=.*/online-mode=false/' "$PROPS" && rm -f "$PROPS.bak"
else
  echo "online-mode=false" >> "$PROPS"
fi

# Pick a free TCP port so smoke tests never collide with another local Minecraft server
SMOKE_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"

# Feed 'stop' as soon as the server finishes starting (Done line appears)
FIFO="$(mktemp -u)"
mkfifo "$FIFO"
trap 'rm -f "$FIFO"' EXIT

(
  ./gradlew :paper:runServer --console=plain --args="--nogui --port $SMOKE_PORT" < "$FIFO"
) > "$WORK_DIR/server.out" 2>&1 &
SRV_PID=$!
exec 3>"$FIFO"

DEADLINE=$((SECONDS + 180))
STARTED=0
while (( SECONDS < DEADLINE )); do
  if ! kill -0 "$SRV_PID" 2>/dev/null; then
    break
  fi
  if grep -q "Done (" "$WORK_DIR/server.out" 2>/dev/null; then
    STARTED=1
    sleep 2
    echo "stop" >&3
    break
  fi
  sleep 1
done

exec 3>&-
wait "$SRV_PID" || true

LOG="$WORK_DIR/server.out"
LATEST="paper/run/logs/latest.log"
if (( STARTED == 0 )); then
  echo "Smoke server failed to start:"
  tail -n 60 "$LOG"
  exit 1
fi

CHECK_LOG="$LOG"
if [[ -f "$LATEST" ]]; then
  CHECK_LOG="$LATEST"
fi

if ! grep -q "JustLogin v" "$CHECK_LOG" || ! grep -q "Ready in" "$CHECK_LOG"; then
  echo "JustLogin banner / Ready in line missing from server log!"
  tail -n 60 "$CHECK_LOG"
  exit 1
fi

if ! grep -q "standalone + premium (hook active)" "$CHECK_LOG"; then
  echo "JustLogin standalone + premium (hook active) banner missing — NMS reflection hook may be broken!"
  tail -n 60 "$CHECK_LOG"
  exit 1
fi

if grep -E "ERROR|SEVERE|Exception" "$CHECK_LOG" | grep -qi "JustLogin"; then
  echo "JustLogin errors detected in smoke server log:"
  grep -i -E "JustLogin|ERROR|SEVERE|Exception" "$CHECK_LOG"
  exit 1
fi

for f in \
  paper/run/plugins/JustLogin/config.yml \
  paper/run/plugins/JustLogin/messages_en.yml \
  paper/run/plugins/JustLogin/data/justlogin.db \
  paper/run/plugins/JustLogin/secrets.key; do
  if [[ ! -f "$f" ]]; then
    echo "Expected plugin data file was not created: $f"
    exit 1
  fi
done

echo "Smoke test passed (JustLogin started cleanly, banner + data files verified)."
