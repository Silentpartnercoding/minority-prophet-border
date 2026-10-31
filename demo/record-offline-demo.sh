#!/bin/sh
# Record the offline rehearsal as a terminal recording under demo/recordings/.
# Uses asciinema when installed, otherwise script(1). A plain log is always kept.
set -eu
cd "$(dirname "$0")/.."
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DIR="demo/recordings"
mkdir -p "$DIR"
RUN="sh demo/offline-rehearsal.sh"

if command -v asciinema >/dev/null 2>&1; then
  asciinema rec --overwrite -q -c "$RUN" "$DIR/rehearsal-$STAMP.cast"
  echo "recording: $DIR/rehearsal-$STAMP.cast (play with: asciinema play <file>)"
elif script --version 2>/dev/null | grep -q util-linux; then
  script -q -e --log-timing "$DIR/rehearsal-$STAMP.timing" \
    -c "$RUN" "$DIR/rehearsal-$STAMP.typescript" >/dev/null
  echo "recording: $DIR/rehearsal-$STAMP.typescript"
  echo "replay with: scriptreplay -t $DIR/rehearsal-$STAMP.timing $DIR/rehearsal-$STAMP.typescript"
elif command -v script >/dev/null 2>&1; then
  # BSD/macOS script(1): -r records with timing, play back with script -p.
  script -q -r "$DIR/rehearsal-$STAMP.typescript" $RUN >/dev/null
  echo "recording: $DIR/rehearsal-$STAMP.typescript (replay with: script -p <file>)"
fi

$RUN > "$DIR/rehearsal-$STAMP.log" 2>&1
echo "log: $DIR/rehearsal-$STAMP.log"
