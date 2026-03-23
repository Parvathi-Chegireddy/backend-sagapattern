#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# start-all.sh — starts all SpanTag microservices in dependency order
#
# Usage:
#   cd /path/to/your/project/root   (where all service folders live)
#   chmod +x start-all.sh
#   ./start-all.sh
#
# Startup order matters:
#   1. regularAuthentication — auth DB + user registration/login
#   2. profile               — JWT issuer (auth needs it on login)
#   3. userservice           — profile page data
#   4. oauth2-service        — Google/GitHub login
#   5. payment-service       — must be running before order-service
#   6. order-service         — saga orchestrator (calls payment-service)
#   7. dashboard             — optional analytics service
#   8. Apigatewayapplication — start LAST — routes everything
#
# Logs go to logs/<service>.log in the project root.
# ─────────────────────────────────────────────────────────────────────────────

set -e

ROOT=$(pwd)
LOG_DIR="$ROOT/logs"
mkdir -p "$LOG_DIR"

SERVICES=(
  "regularAuthentication:9090"
  "profile:9093"
  "userservice:9091"
  "oauth2-service:9092"
  "payment-service:9096"
  "order-service:9095"
  "dashboard:9094"
  "Apigatewayapplication:1013"
)

# ── wait_for_port: block until a service's port is open ──────────────────────
wait_for_port() {
  local name=$1
  local port=$2
  local attempts=0
  local max=30
  echo "   Waiting for $name to listen on :$port ..."
  while ! nc -z localhost "$port" 2>/dev/null; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge "$max" ]; then
      echo "   ⚠  $name did not start on :$port after ${max}s — continuing anyway"
      return
    fi
    sleep 1
  done
  echo "   ✓ $name is up on :$port"
}

# ── start each service ────────────────────────────────────────────────────────
for entry in "${SERVICES[@]}"; do
  SERVICE="${entry%%:*}"
  PORT="${entry##*:}"

  echo ""
  echo "▶  Starting $SERVICE (port $PORT)..."

  SERVICE_DIR="$ROOT/$SERVICE"
  if [ ! -d "$SERVICE_DIR" ]; then
    echo "   ⚠  Directory $SERVICE_DIR not found — skipping"
    continue
  fi

  cd "$SERVICE_DIR"
  mvn spring-boot:run > "$LOG_DIR/$SERVICE.log" 2>&1 &
  echo "   PID $! → logs/$SERVICE.log"

  # Wait for this service to be ready before starting the next
  wait_for_port "$SERVICE" "$PORT"
done

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  All services started."
echo "  Gateway:  http://localhost:1013"
echo "  Frontend: http://localhost:5173"
echo ""
echo "  Logs: $LOG_DIR/"
echo "  Stop: ./stop-all.sh"
echo "═══════════════════════════════════════════════════════"

# Keep script running so Ctrl-C stops everything cleanly
wait
