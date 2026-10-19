#!/usr/bin/env bash
# =============================================================================
# admin-logops.sh — LogOps Intelligence Platform Operations & Release Manager
# =============================================================================
# Zero-Leak AI Incident Analytics Platform for Enterprise Infrastructure
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

APP_NAME="logops"
if [ -d "${SCRIPT_DIR}/logops" ]; then
    LOGOPS_DIR="${SCRIPT_DIR}/logops"
else
    LOGOPS_DIR="${SCRIPT_DIR}"
fi
PKG_FILE="${LOGOPS_DIR}/server/package.json"
DIST_REPO="https://github.com/kisa-ops/filtr"

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
MAGENTA='\033[0;35m'
DIM='\033[2m'
GRAY='\033[0;90m'
NC='\033[0m'

info()    { echo -e "${CYAN}ℹ [INFO]${NC} $*"; }
success() { echo -e "${GREEN}✔ [SUCCESS]${NC} $*"; }
warn()    { echo -e "${YELLOW}⚠ [WARN]${NC} $*"; }
error()   { echo -e "${RED}✖ [ERROR]${NC} $*" >&2; }

banner() {
    echo -e "${MAGENTA}${BOLD}================================================================================${NC}"
    echo -e "${MAGENTA}${BOLD}  LogOps Intelligence Platform — Release & Lifecycle Manager                    ${NC}"
    echo -e "${MAGENTA}${BOLD}================================================================================${NC}"
    echo ""
}

# -----------------------------------------------------------------------------
# 1. Version Helpers
# -----------------------------------------------------------------------------
get_current_version() {
    if [ -f "${PKG_FILE}" ]; then
        node -e "console.log(require('${PKG_FILE}').version || '1.0.0')" 2>/dev/null || echo "1.0.0"
    else
        echo "1.0.0"
    fi
}

bump_version() {
    local target_type="${1:-}"
    local current_ver
    current_ver="$(get_current_version)"
    current_ver="${current_ver#v}"

    local major minor patch
    IFS='.' read -r major minor patch <<< "${current_ver}"
    patch="${patch%%-*}"

    local new_ver=""
    if [ -z "${target_type}" ]; then
        echo ""
        echo -e "${BOLD}${CYAN}=== Semantic Version Increment for LogOps ===${NC}"
        echo -e "Current LogOps Version: ${BOLD}${GREEN}v${current_ver}${NC}"
        echo ""
        echo "Select version increment target:"
        echo "  1) Patch (${major}.${minor}.$((patch + 1))) — Routine fixes, minor improvements"
        echo "  2) Minor (${major}.$((minor + 1)).0) — New log parsers, connectors, features"
        echo "  3) Major ($((major + 1)).0.0) — Major architecture changes"
        echo "  4) Custom explicit version string"
        echo "  0) Cancel"
        echo ""
        echo -ne "${BOLD}Choice [1-4]: ${NC}"
        read -r choice
        case "${choice}" in
            1) new_ver="${major}.${minor}.$((patch + 1))" ;;
            2) new_ver="${major}.$((minor + 1)).0" ;;
            3) new_ver="$((major + 1)).0.0" ;;
            4)
                echo -ne "${BOLD}Enter explicit version (e.g. 1.2.0): ${NC}"
                read -r custom_v
                new_ver="${custom_v#v}"
                ;;
            *) return 0 ;;
        esac
    else
        case "${target_type}" in
            patch) new_ver="${major}.${minor}.$((patch + 1))" ;;
            minor) new_ver="${major}.$((minor + 1)).0" ;;
            major) new_ver="$((major + 1)).0.0" ;;
            v*|*.*.*) new_ver="${target_type#v}" ;;
            *)
                error "Invalid increment type: ${target_type}. Use patch, minor, major, or X.Y.Z"
                return 1
                ;;
        esac
    fi

    info "Updating LogOps version from v${current_ver} to v${new_ver}..."

    # Update logops/server/package.json
    if [ -f "${PKG_FILE}" ]; then
        node -e "
            const fs = require('fs');
            const p = '${PKG_FILE}';
            const j = JSON.parse(fs.readFileSync(p, 'utf8'));
            j.version = '${new_ver}';
            fs.writeFileSync(p, JSON.stringify(j, null, 2), 'utf8');
        "
        success "Updated ${PKG_FILE} to ${new_ver}"
    fi

    # Update badge in dist/index.html
    local dist_index="${LOGOPS_DIR}/dist/index.html"
    if [ -f "${dist_index}" ]; then
        sed -i -E "s/LogOps<span class=\"text-indigo-400\">Intelligence<\/span><\/span>[[:space:]]*<span[^>]*>v[0-9]+\.[0-9]+\.[0-9]+<\/span>/LogOps<span class=\"text-indigo-400\">Intelligence<\/span><\/span><span class=\"px-2 py-0.5 rounded-full text-[10px] font-semibold bg-indigo-500\/10 text-indigo-400 border border-indigo-500\/20\">v${new_ver}<\/span>/" "${dist_index}" || true
    fi

    success "LogOps version bumped to v${new_ver}"
}

# -----------------------------------------------------------------------------
# 2. Status & Overview
# -----------------------------------------------------------------------------
show_status() {
    local ver
    ver="$(get_current_version)"
    local port="${LOGOPS_PORT:-8888}"
    local filtr_url="${FILTR_URL:-http://filtr:80}"
    local llm_url="${LLM_URL:-http://host.docker.internal:11434}"
    local llm_model="${LLM_MODEL:-deepseek-r1:8b}"

    local container_status="not running"
    if command -v docker >/dev/null 2>&1; then
        container_status="$(docker inspect --format='{{.State.Status}}' logops-platform 2>/dev/null || echo "not running")"
    fi

    echo -e "${BOLD}${CYAN}=== LogOps Intelligence Platform Status ===${NC}"
    echo -e "  LogOps Version:      ${BOLD}${GREEN}v${ver}${NC}"
    echo -e "  Container State:     ${BOLD}${container_status}${NC}"
    echo -e "  Dashboard URL:       ${CYAN}http://localhost:${port}${NC}"
    echo -e "  filtr Core Bridge:   ${CYAN}${filtr_url}${NC} (Redaction Engine)"
    echo -e "  Local LLM Target:    ${CYAN}${llm_url}${NC} [${llm_model}]"

    # Check ELK Harvester state if data file exists
    local elk_cfg="${LOGOPS_DIR}/server/data/elk_config.json"
    if [ -f "${elk_cfg}" ]; then
        local elk_enabled
        elk_enabled="$(node -e "try { console.log(require('${elk_cfg}').enabled ? 'Active' : 'Paused'); } catch { console.log('Unknown'); }" 2>/dev/null || echo "Unknown")"
        local elk_url
        elk_url="$(node -e "try { console.log(require('${elk_cfg}').elasticsearchUrl || ''); } catch { console.log(''); }" 2>/dev/null || echo "")"
        echo -e "  ELK Harvester:       ${BOLD}${elk_enabled}${NC} (${elk_url:-not configured})"
    fi
    echo ""
}

# -----------------------------------------------------------------------------
# 3. Build & Package
# -----------------------------------------------------------------------------
build_package() {
    local version="${1:-$(get_current_version)}"
    version="${version#v}"
    local tarball_name="logops-docker-v${version}.tar.gz"

    echo ""
    echo -e "${BOLD}${CYAN}=== Building LogOps Offline Package (v${version}) ===${NC}"

    if ! command -v docker >/dev/null 2>&1; then
        error "Docker is required to build container images."
        return 1
    fi

    info "Building container image ghcr.io/kisa-ops/logops:v${version}..."
    docker build \
        --provenance=false \
        -t "ghcr.io/kisa-ops/logops:v${version}" \
        -t "ghcr.io/kisa-ops/logops:latest" \
        -t "logops:v${version}" \
        -t "logops:latest" \
        "${LOGOPS_DIR}"

    success "Docker image built successfully."

    info "Exporting container archive to ${tarball_name}..."
    docker save \
        "ghcr.io/kisa-ops/logops:v${version}" \
        "ghcr.io/kisa-ops/logops:latest" \
        "logops:v${version}" \
        "logops:latest" | gzip > "${SCRIPT_DIR}/${tarball_name}"

    local size
    size=$(du -h "${SCRIPT_DIR}/${tarball_name}" | awk '{print $1}')
    local checksum
    checksum=$(sha256sum "${SCRIPT_DIR}/${tarball_name}" | awk '{print $1}')

    success "Package created: ${BOLD}${tarball_name}${NC} (${size})"
    echo -e "SHA256: ${DIM}${checksum}${NC}"
}

# -----------------------------------------------------------------------------
# 4. Clean Up
# -----------------------------------------------------------------------------
cleanup() {
    echo ""
    echo -e "${BOLD}${CYAN}=== LogOps Artifact Clean Up ===${NC}"
    echo "Cleaning LogOps runtime logs and old offline tarballs..."
    rm -f "${SCRIPT_DIR}"/logops-docker-*.tar.gz
    rm -f "${LOGOPS_DIR}/server/server.log"
    success "Cleaned LogOps package archives and server logs."
}

# -----------------------------------------------------------------------------
# 5. Publish Release Asset to GitHub
# -----------------------------------------------------------------------------
publish_release() {
    local version="${1:-$(get_current_version)}"
    version="${version#v}"
    local tag="v${version}"
    local tarball_name="logops-docker-v${version}.tar.gz"
    local tarball_path="${SCRIPT_DIR}/${tarball_name}"

    echo ""
    echo -e "${BOLD}${CYAN}=== Publish LogOps Package to GitHub Release ===${NC}"

    if [ ! -f "${tarball_path}" ]; then
        warn "Package ${tarball_name} not found. Building now..."
        build_package "${version}"
    fi

    local token="${GITHUB_TOKEN:-}"
    if [ -z "${token}" ]; then
        echo -ne "${BOLD}Enter GitHub Personal Access Token (PAT): ${NC}"
        read -rs token
        echo ""
    fi

    if [ -z "${token}" ]; then
        error "GitHub PAT required for publishing release asset."
        return 1
    fi

    local repo_slug
    repo_slug=$(echo "${DIST_REPO}" | sed -E 's|https://github.com/||; s|\.git$||')

    info "Finding release ${tag} on ${repo_slug}..."
    local check_rel
    check_rel=$(curl -s -H "Authorization: Bearer ${token}" "https://api.github.com/repos/${repo_slug}/releases/tags/${tag}" || true)
    local rel_id
    rel_id=$(echo "${check_rel}" | grep '"id":' | head -n 1 | sed -E 's/.*: *([0-9]+).*/\1/' || true)

    if [ -z "${rel_id}" ]; then
        error "Release ${tag} does not exist on ${repo_slug}. Create release tag first via admin-filtr.sh."
        return 1
    fi

    info "Uploading ${tarball_name} ($(du -h "${tarball_path}" | awk '{print $1}')) to release ${tag}..."
    local upload_url="https://uploads.github.com/repos/${repo_slug}/releases/${rel_id}/assets?name=${tarball_name}"
    local upload_res
    upload_res=$(curl -s -X POST \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/gzip" \
        --data-binary "@${tarball_path}" \
        "${upload_url}")

    if echo "${upload_res}" | grep -q '"state": *"uploaded"'; then
        success "Uploaded ${tarball_name} to https://github.com/${repo_slug}/releases/tag/${tag}"
    elif echo "${upload_res}" | grep -q 'already_exists'; then
        warn "Asset ${tarball_name} is already attached to release ${tag}."
    else
        warn "Upload response: $(echo "${upload_res}" | head -n 3)"
    fi
}

# -----------------------------------------------------------------------------
# 6. Runtime Management Wrapper
# -----------------------------------------------------------------------------
manage_runtime() {
    local cmd="${1:-status}"
    if [ -x "${SCRIPT_DIR}/manage-logops.sh" ]; then
        "${SCRIPT_DIR}/manage-logops.sh" "$@"
    else
        error "manage-logops.sh script not found in ${SCRIPT_DIR}."
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
show_help() {
    cat << EOF
${BOLD}LogOps Intelligence Platform — Standalone Administration Utility${NC}
Usage: ./admin-logops.sh [COMMAND] [OPTIONS]

COMMANDS:
    status                      Show container state, ports, bridge, and ELK harvester status
    version [patch|minor|major] Increment semantic version in logops/server/package.json
    build [version]             Build LogOps container image and export logops-docker-v*.tar.gz
    deploy | enable             Deploy & launch LogOps container via docker compose
    stop | disable              Stop and remove LogOps container
    restart                     Restart LogOps container independently with zero impact on filtr
    bridge                      Verify Zero-Leak data redaction & rehydration link with filtr
    test                        Test LogOps REST health API endpoint
    config                      Interactively configure FILTR_URL, LOGOPS_PORT, and LLM engine
    clean                       Remove old tarballs and local runtime logs
    publish [version]           Upload logops-docker-v*.tar.gz to GitHub Release
    logs                        Tail live platform container logs
    help                        Show this command reference guide

EXAMPLES:
    ./admin-logops.sh                   # Launch interactive administration menu
    ./admin-logops.sh status            # View container and bridge status
    ./admin-logops.sh build             # Build image and export offline tarball
    ./admin-logops.sh deploy            # Deploy LogOps container
    ./admin-logops.sh bridge            # Test redaction connection to filtr
    ./admin-logops.sh version patch     # Bump patch version (e.g. 1.0.0 -> 1.0.1)
EOF
}

# -----------------------------------------------------------------------------
# Interactive Menu
# -----------------------------------------------------------------------------
interactive_menu() {
    while true; do
        banner
        show_status
        echo -e "${BOLD}LogOps Platform Operations:${NC}"
        echo "  1) 📊 Refresh Status & Diagnostics"
        echo "  2) 🏷️  Version Management & Semantic Bump"
        echo "  3) 📦 Build Container Image & Offline Tarball"
        echo "  4) 🚀 Deploy / Start LogOps Container"
        echo "  5) 🔄 Restart LogOps (Zero impact on filtr)"
        echo "  6) 🛑 Stop LogOps Platform"
        echo "  7) 🛡️ Verify filtr Redaction & Rehydration Bridge"
        echo "  8) 🔍 Test LogOps REST Health API"
        echo "  9) ⚙️ Configure filtr URL & LLM Settings (.env)"
        echo "  10) 🧹 Clean Old Tarballs & Logs"
        echo "  11) 🌐 Publish Package to GitHub Release"
        echo "  12) 📋 Tail Live Container Logs"
        echo "  0) Exit"
        echo ""
        echo -ne "${BOLD}Enter choice [0-12]: ${NC}"
        read -r choice
        case "${choice}" in
            1) ;;
            2) bump_version ;;
            3) build_package ;;
            4) manage_runtime enable ;;
            5) manage_runtime restart ;;
            6) manage_runtime disable ;;
            7) manage_runtime bridge ;;
            8) manage_runtime test ;;
            9) manage_runtime config ;;
            10) cleanup ;;
            11) publish_release ;;
            12) manage_runtime logs ;;
            0) exit 0 ;;
            *) warn "Invalid selection." ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# Dispatcher
# -----------------------------------------------------------------------------
case "${1:-}" in
    ""|menu)
        interactive_menu
        ;;
    status)
        show_status
        ;;
    version|bump)
        shift
        bump_version "$@"
        ;;
    build|package)
        shift
        build_package "$@"
        ;;
    deploy|enable|start)
        manage_runtime enable
        ;;
    stop|disable)
        manage_runtime disable
        ;;
    restart)
        manage_runtime restart
        ;;
    bridge|test-bridge)
        manage_runtime bridge
        ;;
    test|health)
        manage_runtime test
        ;;
    config|configure)
        manage_runtime config
        ;;
    clean|cleanup)
        cleanup
        ;;
    publish)
        shift
        publish_release "$@"
        ;;
    logs)
        manage_runtime logs
        ;;
    help|-h|--help)
        show_help
        ;;
    *)
        error "Unknown command: ${1}"
        show_help
        exit 1
        ;;
esac
