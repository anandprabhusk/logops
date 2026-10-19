#!/usr/bin/env bash
# =============================================================================
# manage-logops.sh — Zero-Leak LogOps AI Diagnostic Platform Manager
# =============================================================================
# Companion Platform for Filtr: Enterprise Log Ingestion, Redaction & Rehydration
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} ${BOLD}$*${NC}"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Detect compose command
COMPOSE_CMD=""
if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    error "Neither 'docker compose' nor 'docker-compose' found on system."
    exit 1
fi

# Load existing environment
if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

LOGOPS_PORT="${LOGOPS_PORT:-8888}"

# -----------------------------------------------------------------------------
# Command: status
# -----------------------------------------------------------------------------
cmd_status() {
    echo -e "${BOLD}=== LogOps Intelligence Platform Status ===${NC}"
    echo
    
    local container_status
    container_status="$(docker inspect --format='{{.State.Status}}' logops-platform 2>/dev/null || echo "not running")"
    echo -e "Platform Container (logops-platform): ${BOLD}${container_status}${NC}"

    if [ "${container_status}" = "running" ]; then
        local health_status
        health_status="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}no healthcheck{{end}}' logops-platform 2>/dev/null || echo "unknown")"
        echo -e "Healthcheck Status:                   ${GREEN}${BOLD}${health_status}${NC}"
        echo -e "Ingestion & Dashboard URL:            ${CYAN}http://localhost:${LOGOPS_PORT}${NC}"
        
        # Test HTTP health endpoint
        if curl -s -f "http://localhost:${LOGOPS_PORT}/api/health" >/dev/null 2>&1; then
            echo -e "API Gateway:                          ${GREEN}Operational (200 OK)${NC}"
        else
            echo -e "API Gateway:                          ${YELLOW}Initializing / Unreachable${NC}"
        fi
    fi

    echo ""
    echo -e "Configuration (.env):"
    echo -e "  LOGOPS_PORT:     ${LOGOPS_PORT}"
    echo -e "  FILTR_URL:       ${FILTR_URL:-http://filtr:80} (Redaction & Rehydration Core)"
    echo -e "  LLM_URL:         ${LLM_URL:-http://host.docker.internal:11434}"
    echo -e "  LLM_MODEL:       ${LLM_MODEL:-deepseek-r1:8b}"
    echo -e "  COMPOSE_PROFILES: ${COMPOSE_PROFILES:-not configured}"
    echo
}

# -----------------------------------------------------------------------------
# Command: enable
# -----------------------------------------------------------------------------
cmd_enable() {
    info "Enabling LogOps profile in .env..."
    if [ ! -f .env ]; then
        touch .env
    fi

    # Update or append COMPOSE_PROFILES
    if grep -qE '^COMPOSE_PROFILES=' .env; then
        local current_profiles
        current_profiles="$(grep -E '^COMPOSE_PROFILES=' .env | cut -d= -f2-)"
        if [[ "${current_profiles}" != *"logops"* ]]; then
            sed -i -E 's/^COMPOSE_PROFILES=(.*)/COMPOSE_PROFILES=\1,logops/' .env
            # Clean double commas if any
            sed -i -E 's/,,/,/g' .env
            sed -i -E 's/=,/=/g' .env
        fi
    else
        echo "COMPOSE_PROFILES=logops" >> .env
    fi

    # Ensure LOGOPS_PORT is declared
    if ! grep -qE '^LOGOPS_PORT=' .env; then
        echo "LOGOPS_PORT=8888" >> .env
    fi

    success "LogOps profile enabled in .env."
    info "Starting LogOps platform container..."
    cmd_start
}

# -----------------------------------------------------------------------------
# Command: disable
# -----------------------------------------------------------------------------
cmd_disable() {
    info "Disabling LogOps platform..."
    cmd_stop

    if [ -f .env ] && grep -qE '^COMPOSE_PROFILES=' .env; then
        # Remove logops from comma-separated list
        sed -i -E 's/logops,?//g' .env
        sed -i -E 's/,logops//g' .env
        sed -i -E 's/COMPOSE_PROFILES=$//' .env
        # Clean empty lines
        sed -i -E '/^COMPOSE_PROFILES=$/d' .env
        success "Removed logops from COMPOSE_PROFILES in .env."
    fi
}

# -----------------------------------------------------------------------------
# Command: start
# -----------------------------------------------------------------------------
cmd_start() {
    info "Starting LogOps platform with profile 'logops'..."
    
    # Auto-load local offline package if present
    for ltar in ./logops-docker-*.tar.gz "${SCRIPT_DIR}"/logops-docker-*.tar.gz; do
        if [ -f "${ltar}" ]; then
            info "Ensuring LogOps offline image is loaded from ${ltar}..."
            docker load < "${ltar}" 2>/dev/null || true
            break
        fi
    done

    # Ensure compatibility tags
    local target_img="${LOGOPS_IMAGE:-ghcr.io/kisa-ops/logops:v1.0.0}"
    if docker image inspect "${target_img}" >/dev/null 2>&1; then
        docker tag "${target_img}" "ghcr.io/kisa-ops/logops:v1.0.0" 2>/dev/null || true
        docker tag "${target_img}" "ghcr.io/kisa-ops/logops:latest" 2>/dev/null || true
        ${COMPOSE_CMD} --profile logops up -d logops
    elif docker images --format '{{.Repository}}:{{.Tag}}' | grep -q 'logops'; then
        local found_img
        found_img=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep 'logops' | head -n 1)
        info "Found local LogOps image: ${found_img}, tagging as ${target_img}..."
        docker tag "${found_img}" "${target_img}" 2>/dev/null || true
        docker tag "${found_img}" "ghcr.io/kisa-ops/logops:v1.0.0" 2>/dev/null || true
        ${COMPOSE_CMD} --profile logops up -d logops
    else
        info "No local LogOps image found; building from source..."
        ${COMPOSE_CMD} --profile logops up -d --build logops
    fi
    success "LogOps platform started at http://localhost:${LOGOPS_PORT}"
}

# -----------------------------------------------------------------------------
# Command: stop
# -----------------------------------------------------------------------------
cmd_stop() {
    info "Stopping LogOps container..."
    docker stop logops-platform >/dev/null 2>&1 || true
    docker rm logops-platform >/dev/null 2>&1 || true
    success "LogOps container stopped and removed."
}

# -----------------------------------------------------------------------------
# Command: logs
# -----------------------------------------------------------------------------
cmd_logs() {
    ${COMPOSE_CMD} logs -f logops
}

# -----------------------------------------------------------------------------
# Command: test
# -----------------------------------------------------------------------------
cmd_test() {
    info "Verifying LogOps health on http://localhost:${LOGOPS_PORT}/api/health..."
    if curl -s -f "http://localhost:${LOGOPS_PORT}/api/health"; then
        echo ""
        success "LogOps healthcheck passed!"
    else
        echo ""
        error "Healthcheck failed. Is the container running?"
        exit 1
    fi
}

# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Command: restart
# -----------------------------------------------------------------------------
cmd_restart() {
    info "Restarting LogOps platform container (zero impact on filtr)..."
    docker restart logops-platform >/dev/null 2>&1 || {
        warn "Container not running, starting now..."
        cmd_start
    }
    success "LogOps platform restarted successfully."
}

# -----------------------------------------------------------------------------
# Command: bridge (Verify filtr Redaction Link)
# -----------------------------------------------------------------------------
cmd_bridge() {
    echo -e "${BOLD}=== filtr Redaction & Rehydration Bridge Verification ===${NC}"
    echo ""
    
    local target_filtr="${FILTR_URL:-http://filtr:80}"
    local host_filtr="http://localhost:8080"
    
    info "Configured LogOps Redaction Target: ${CYAN}${target_filtr}${NC}"
    
    # Test inside container network first if container is up
    local bridge_ok=false
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'logops-platform'; then
        info "Probing filtr endpoint from inside logops-platform container..."
        local probe_res
        probe_res=$(docker exec logops-platform wget -q -O - --timeout=3 "${target_filtr}/api/health" 2>/dev/null || true)
        if [[ "${probe_res}" == *"UP"* ]] || [[ "${probe_res}" == *""status""* ]] || [[ "${probe_res}" == *""success""* ]]; then
            success "Internal Docker Bridge: CONNECTED (${target_filtr}/api/health)"
            bridge_ok=true
        else
            warn "Container cannot reach ${target_filtr}/api/health directly."
        fi
    fi

    # Test from host as fallback
    if [ "${bridge_ok}" = false ]; then
        info "Testing host connectivity to filtr at ${host_filtr} and ${target_filtr}..."
        if curl -s -f --connect-timeout 3 "${host_filtr}/api/health" >/dev/null 2>&1; then
            success "Host-level filtr API: OPERATIONAL at ${host_filtr}/api/health"
            bridge_ok=true
        elif curl -s -f --connect-timeout 3 "${target_filtr}/api/health" >/dev/null 2>&1; then
            success "Host-level filtr API: OPERATIONAL at ${target_filtr}/api/health"
            bridge_ok=true
        else
            warn "filtr API returned no response. Verify filtr-app container is running."
        fi
    fi

    echo ""
    if [ "${bridge_ok}" = true ]; then
        success "Zero-Leak Bridge is ACTIVE: All PII/IP/Secret redaction & rehydration are processed through filtr."
    else
        warn "LogOps is currently operating in STANDALONE FALLBACK mode (in-memory vault active)."
        info "To connect to filtr, ensure filtr is running: docker compose up -d filtr"
    fi
    echo ""
}

# -----------------------------------------------------------------------------
# Command: config (Configure filtr URL and LLM)
# -----------------------------------------------------------------------------
cmd_config() {
    echo -e "${BOLD}=== Configure LogOps & filtr Integration Settings ===${NC}"
    echo ""
    if [ ! -f .env ]; then touch .env; fi

    echo -ne "${BOLD}Enter filtr Core URL [default: ${FILTR_URL:-http://filtr:80}]: ${NC}"
    read -r input_furl
    if [ -n "${input_furl}" ]; then
        if grep -q '^FILTR_URL=' .env; then
            sed -i "s|^FILTR_URL=.*|FILTR_URL=${input_furl}|g" .env
        else
            echo "FILTR_URL=${input_furl}" >> .env
        fi
        success "Updated FILTR_URL in .env to ${input_furl}"
    fi

    echo -ne "${BOLD}Enter LogOps HTTP Port [default: ${LOGOPS_PORT:-8888}]: ${NC}"
    read -r input_port
    if [ -n "${input_port}" ]; then
        if grep -q '^LOGOPS_PORT=' .env; then
            sed -i "s|^LOGOPS_PORT=.*|LOGOPS_PORT=${input_port}|g" .env
        else
            echo "LOGOPS_PORT=${input_port}" >> .env
        fi
        success "Updated LOGOPS_PORT in .env to ${input_port}"
    fi

    echo -ne "${BOLD}Enter Local LLM Engine URL [default: ${LLM_URL:-http://host.docker.internal:11434}]: ${NC}"
    read -r input_llm
    if [ -n "${input_llm}" ]; then
        if grep -q '^LLM_URL=' .env; then
            sed -i "s|^LLM_URL=.*|LLM_URL=${input_llm}|g" .env
        else
            echo "LLM_URL=${input_llm}" >> .env
        fi
        success "Updated LLM_URL in .env to ${input_llm}"
    fi

    echo ""
    success "Settings saved. Restart LogOps to apply: ./manage-logops.sh restart"
}

# -----------------------------------------------------------------------------
# Command: build (Build and export LogOps image separately)
# -----------------------------------------------------------------------------
cmd_build() {
    echo -e "${BOLD}=== Building LogOps Independent Container Image ===${NC}"
    echo ""
    local ver
    ver="$(git describe --tags --always 2>/dev/null || echo "v1.0.0")"
    ver="${ver#v}"
    local tag="ghcr.io/kisa-ops/logops:v${ver}"
    local tarball="logops-docker-v${ver}.tar.gz"

    info "Building container image ${tag} from ./logops..."
    docker build \
        --provenance=false \
        -t "${tag}" \
        -t "ghcr.io/kisa-ops/logops:latest" \
        -t "logops:v${ver}" \
        -t "logops:latest" \
        "$(if [ -d "${SCRIPT_DIR}/logops" ]; then echo "${SCRIPT_DIR}/logops"; else echo "${SCRIPT_DIR}"; fi)"

    info "Exporting archive to ${tarball}..."
    docker save "${tag}" "ghcr.io/kisa-ops/logops:latest" "logops:latest" | gzip > "${SCRIPT_DIR}/${tarball}"
    local size
    size=$(du -h "${SCRIPT_DIR}/${tarball}" | awk '{print $1}')
    success "Independent LogOps package built: ${BOLD}${tarball}${NC} (${size})"
}

# Help
# -----------------------------------------------------------------------------
cmd_help() {
    echo -e "${BOLD}LogOps Zero-Leak Platform Manager${NC}"
    echo "Usage: ./manage-logops.sh [command]"
    echo ""
    echo "Commands:"
    echo "  status       Display current container state and configuration"
    echo "  enable       Enable logops in .env and start container"
    echo "  disable      Stop container and remove logops from .env profiles"
    echo "  start        Start the logops container via docker compose"
    echo "  stop         Stop and remove the logops container"
    echo "  logs         Tail container output logs"
    echo "  test         Verify REST API health endpoint
  bridge       Verify data redaction and rehydration link with filtr
  restart      Restart the LogOps container without touching filtr
  config       Interactive wizard to configure filtr URL and LLM
  build        Build independent LogOps container image and tarball"
    echo "  help         Display this help message"
}

case "${1:-status}" in
    status)  cmd_status ;;
    enable)  cmd_enable ;;
    disable) cmd_disable ;;
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    logs)    cmd_logs ;;
    test)    cmd_test ;;
    bridge)  cmd_bridge ;;
    restart) cmd_restart ;;
    config)  cmd_config ;;
    build)   cmd_build ;;
    help|-h|--help) cmd_help ;;
    *)
        error "Unknown command: ${1}"
        cmd_help
        exit 1
        ;;
esac
