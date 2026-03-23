#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# stop-all.sh — stops all SpanTag microservices
#
# Works on: Linux, macOS, Git Bash on Windows
# ─────────────────────────────────────────────────────────────────────────────

echo "Stopping all SpanTag services..."

PORTS=(9090 9091 9092 9093 9094 9095 9096 1013)

for PORT in "${PORTS[@]}"; do
  # Find PID listening on this port
  PID=$(lsof -ti tcp:"$PORT" 2>/dev/null)
  if [ -n "$PID" ]; then
    echo "  Killing PID $PID on :$PORT"
    kill -9 "$PID" 2>/dev/null || true
  fi
done

# Also kill any Maven spring-boot:run processes as a fallback
pkill -f "spring-boot:run" 2>/dev/null || true

echo ""
echo "All SpanTag services stopped."
echo "Logs are in: ./logs/"
