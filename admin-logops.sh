#!/usr/bin/env bash
# =============================================================================
# admin-logops.sh — LogOps Platform Administration & Deployment Manager
# =============================================================================
# Automated Repository Updates (anandprabhusk/logops) & Image Packaging
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
REPO_URL="https://github.com/anandprabhusk/logops"
REPO_SLUG="anandprabhusk/logops"

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
    echo -e "${MAGENTA}${BOLD}  LogOps Intelligence Platform — Release & Deployment Manager                  ${NC}"
    echo -e "${MAGENTA}${BOLD}  Target Repository: ${REPO_URL}                      ${NC}"
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
        sed -i -E "s/v[0-9]+\.[0-9]+\.[0-9]+ • Zero-Leak/v${new_ver} • Zero-Leak/g" "${dist_index}" || true
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
    local filtr_url="${FILTR_URL:-http://localhost:8080}"
    local llm_url="${LLM_URL:-http://localhost:11434}"
    local llm_model="${LLM_MODEL:-deepseek-r1:8b}"

    local container_status="not running"
    if command -v docker >/dev/null 2>&1; then
        container_status="$(docker inspect --format='{{.State.Status}}' logops-platform 2>/dev/null || echo "not running")"
    fi

    local git_remote
    git_remote="$(git remote get-url origin 2>/dev/null || echo "not configured")"
    local git_branch
    git_branch="$(git branch --show-current 2>/dev/null || echo "unknown")"
    local git_dirty
    git_dirty="$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"

    echo -e "${BOLD}${CYAN}=== LogOps Platform Status & Repository Overview ===${NC}"
    echo -e "  LogOps Version:      ${BOLD}${GREEN}v${ver}${NC}"
    echo -e "  Target GitHub Repo:  ${CYAN}${REPO_URL}${NC}"
    echo -e "  Git Origin Remote:   ${BOLD}${git_remote}${NC} (${git_branch})"
    echo -e "  Uncommitted Changes: ${BOLD}$([ "${git_dirty}" -gt 0 ] && echo -e "${YELLOW}${git_dirty} files modified${NC}" || echo -e "${GREEN}Clean working tree${NC}")"
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
# 3. Update & Sync GitHub Repository (anandprabhusk/logops)
# -----------------------------------------------------------------------------
update_repo() {
    local commit_msg="${1:-}"

    echo ""
    echo -e "${BOLD}${CYAN}=== Updating GitHub Repository: ${REPO_URL} ===${NC}"

    # 1. Ensure remote origin is set
    local cur_remote
    cur_remote="$(git remote get-url origin 2>/dev/null || echo "")"
    if [ "${cur_remote}" != "${REPO_URL}.git" ] && [ "${cur_remote}" != "${REPO_URL}" ]; then
        info "Configuring git remote origin to ${REPO_URL}.git..."
        git remote remove origin 2>/dev/null || true
        git remote add origin "${REPO_URL}.git"
        success "Remote origin configured."
    fi

    # 2. Check for changes or initial commit
    local ver
    ver="$(get_current_version)"
    local current_branch
    current_branch="$(git branch --show-current 2>/dev/null || echo "main")"
    if [ -z "${current_branch}" ]; then
        current_branch="main"
        git branch -M main
    fi

    # 3. Prompt for commit message if empty and changes exist
    local dirty_count
    dirty_count="$(git status --porcelain | wc -l | tr -d ' ')"

    if [ "${dirty_count}" -gt 0 ]; then
        if [ -z "${commit_msg}" ]; then
            echo -e "${YELLOW}Detected ${dirty_count} changed file(s):${NC}"
            git status -s
            echo ""
            echo -ne "${BOLD}Enter commit message [Default: 'Release v${ver}: Zero-Leak LogOps AI Diagnostic Platform']: ${NC}"
            read -r input_msg
            commit_msg="${input_msg:-Release v${ver}: Zero-Leak LogOps AI Diagnostic Platform}"
        fi

        info "Staging all files..."
        git add -A

        info "Committing changes with message: '${commit_msg}'..."
        git commit -m "${commit_msg}"
        success "Changes committed."
    else
        info "Working tree is clean. Proceeding with remote push/sync."
    fi

    # 4. Push to GitHub
    info "Pushing ${current_branch} to ${REPO_URL}..."
    if git push -u origin "${current_branch}"; then
        success "Repository updated successfully: ${BOLD}${REPO_URL}${NC}"
    else
        warn "Direct push failed. Retrying with GitHub CLI authentication..."
        if command -v gh >/dev/null 2>&1; then
            gh auth setup-git
            git push -u origin "${current_branch}"
            success "Repository updated successfully via gh credential helper."
        else
            error "Push failed. Please ensure you have write permissions or run 'gh auth login'."
            return 1
        fi
    fi

    # 5. Optional Tag Creation
    local tag="v${ver}"
    if ! git rev-parse "${tag}" >/dev/null 2>&1; then
        info "Tagging commit as ${tag}..."
        git tag -a "${tag}" -m "Release ${tag}"
        git push origin "${tag}" || true
        success "Pushed tag ${tag} to GitHub."
    fi

    echo ""
}

# -----------------------------------------------------------------------------
# 4. Build Container Images for Deployment
# -----------------------------------------------------------------------------
build_package() {
    local version="${1:-$(get_current_version)}"
    version="${version#v}"
    local tarball_name="logops-docker-v${version}.tar.gz"
    local sha_name="${tarball_name}.sha256"

    echo ""
    echo -e "${BOLD}${CYAN}=== Building LogOps Deployment Images & Offline Package (v${version}) ===${NC}"

    if ! command -v docker >/dev/null 2>&1; then
        error "Docker is required to build deployment images."
        return 1
    fi

    info "Building production container image with multiple tags..."
    docker build \
        --provenance=false \
        -t "anandprabhusk/logops:v${version}" \
        -t "anandprabhusk/logops:latest" \
        -t "ghcr.io/anandprabhusk/logops:v${version}" \
        -t "ghcr.io/anandprabhusk/logops:latest" \
        -t "logops:v${version}" \
        -t "logops:latest" \
        "${LOGOPS_DIR}"

    success "Docker container images built successfully:"
    echo "    • anandprabhusk/logops:v${version}"
    echo "    • anandprabhusk/logops:latest"
    echo "    • ghcr.io/anandprabhusk/logops:v${version}"
    echo "    • ghcr.io/anandprabhusk/logops:latest"
    echo "    • logops:v${version}"

    info "Exporting full deployment container archive to ${tarball_name}..."
    docker save \
        "anandprabhusk/logops:v${version}" \
        "anandprabhusk/logops:latest" \
        "ghcr.io/anandprabhusk/logops:v${version}" \
        "ghcr.io/anandprabhusk/logops:latest" \
        "logops:v${version}" \
        "logops:latest" | gzip > "${SCRIPT_DIR}/${tarball_name}"

    local size
    size=$(du -h "${SCRIPT_DIR}/${tarball_name}" | awk '{print $1}')
    local checksum
    checksum=$(sha256sum "${SCRIPT_DIR}/${tarball_name}" | awk '{print $1}')
    echo "${checksum}  ${tarball_name}" > "${SCRIPT_DIR}/${sha_name}"

    success "Deployment package created: ${BOLD}${tarball_name}${NC} (${size})"
    echo -e "SHA256: ${DIM}${checksum}${NC} (saved to ${sha_name})"
    echo ""
}

# -----------------------------------------------------------------------------
# 5. Push Built Images to Container Registry
# -----------------------------------------------------------------------------
push_images() {
    local version="${1:-$(get_current_version)}"
    version="${version#v}"

    echo ""
    echo -e "${BOLD}${CYAN}=== Push LogOps Images to Registry ===${NC}"
    echo "Choose target registry:"
    echo "  1) GitHub Container Registry (ghcr.io/anandprabhusk/logops)"
    echo "  2) Docker Hub (anandprabhusk/logops)"
    echo "  3) Both Registries"
    echo "  0) Cancel"
    echo ""
    echo -ne "${BOLD}Choice [1-3]: ${NC}"
    read -r reg_choice

    case "${reg_choice}" in
        1)
            info "Pushing to ghcr.io/anandprabhusk/logops..."
            docker push "ghcr.io/anandprabhusk/logops:v${version}"
            docker push "ghcr.io/anandprabhusk/logops:latest"
            success "Pushed to GitHub Container Registry."
            ;;
        2)
            info "Pushing to Docker Hub (anandprabhusk/logops)..."
            docker push "anandprabhusk/logops:v${version}"
            docker push "anandprabhusk/logops:latest"
            success "Pushed to Docker Hub."
            ;;
        3)
            info "Pushing to both ghcr.io and Docker Hub..."
            docker push "ghcr.io/anandprabhusk/logops:v${version}" || true
            docker push "ghcr.io/anandprabhusk/logops:latest" || true
            docker push "anandprabhusk/logops:v${version}" || true
            docker push "anandprabhusk/logops:latest" || true
            success "Pushed images to all configured registries."
            ;;
        *)
            info "Image push cancelled."
            ;;
    esac
}

# -----------------------------------------------------------------------------
# 6. Publish Release to GitHub (anandprabhusk/logops)
# -----------------------------------------------------------------------------
publish_release() {
    local version="${1:-$(get_current_version)}"
    version="${version#v}"
    local tag="v${version}"
    local tarball_name="logops-docker-v${version}.tar.gz"
    local tarball_path="${SCRIPT_DIR}/${tarball_name}"
    local sha_name="${tarball_name}.sha256"
    local sha_path="${SCRIPT_DIR}/${sha_name}"

    echo ""
    echo -e "${BOLD}${CYAN}=== Publish LogOps Package to GitHub Release (${REPO_SLUG}) ===${NC}"

    if [ ! -f "${tarball_path}" ]; then
        warn "Package ${tarball_name} not found. Building now..."
        build_package "${version}"
    fi

    # Use gh CLI if available
    if command -v gh >/dev/null 2>&1; then
        info "Creating or updating GitHub Release ${tag} via gh CLI..."
        
        local notes="## LogOps Intelligence Platform ${tag}
### Zero-Leak AI Incident Analytics Platform for Enterprise Infrastructure

- **Zero-Leak filtr Redaction & Rehydration Core**: Automatic interception of PII, internal IPs, and database credentials before model egress.
- **10 Enterprise Production Parsers**: Oracle WebLogic, Apache Kafka, Kubernetes Pods, PostgreSQL/MySQL, AWS CloudWatch, Redis, Nginx, Apache HTTPD, Windows Event, and Jenkins CI/CD.
- **ELK Community Edition Auto-Harvester**: Scheduled and on-demand Elasticsearch log harvesting and Logstash forwarder integration.
- **Standalone Offline Container Package**: Includes prebuilt Docker images and deployment manifests."

        if gh release view "${tag}" --repo "${REPO_SLUG}" >/dev/null 2>&1; then
            info "Release ${tag} already exists. Uploading/updating assets..."
            gh release upload "${tag}" "${tarball_path}" "${sha_path}" --repo "${REPO_SLUG}" --clobber
        else
            info "Creating new release ${tag} on ${REPO_SLUG}..."
            gh release create "${tag}" "${tarball_path}" "${sha_path}" \
                --repo "${REPO_SLUG}" \
                --title "LogOps Platform ${tag} — Zero-Leak SRE Analytics" \
                --notes "${notes}"
        fi

        success "Release published: ${BOLD}https://github.com/${REPO_SLUG}/releases/tag/${tag}${NC}"
        return 0
    fi

    # Fallback to direct curl API with token
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

    info "Finding release ${tag} on ${REPO_SLUG}..."
    local check_rel
    check_rel=$(curl -s -H "Authorization: Bearer ${token}" "https://api.github.com/repos/${REPO_SLUG}/releases/tags/${tag}" || true)
    local rel_id
    rel_id=$(echo "${check_rel}" | grep '"id":' | head -n 1 | sed -E 's/.*: *([0-9]+).*/\1/' || true)

    if [ -z "${rel_id}" ]; then
        info "Creating release ${tag} via GitHub REST API..."
        local create_rel
        create_rel=$(curl -s -X POST \
            -H "Authorization: Bearer ${token}" \
            -H "Content-Type: application/json" \
            "https://api.github.com/repos/${REPO_SLUG}/releases" \
            -d "{\"tag_name\":\"${tag}\",\"name\":\"LogOps Platform ${tag}\",\"body\":\"LogOps Zero-Leak Platform Release ${tag}\"}")
        rel_id=$(echo "${create_rel}" | grep '"id":' | head -n 1 | sed -E 's/.*: *([0-9]+).*/\1/' || true)
    fi

    if [ -z "${rel_id}" ]; then
        error "Failed to create or find release ${tag} on ${REPO_SLUG}."
        return 1
    fi

    info "Uploading ${tarball_name} to release ${tag}..."
    local upload_url="https://uploads.github.com/repos/${REPO_SLUG}/releases/${rel_id}/assets?name=${tarball_name}"
    curl -s -X POST \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/gzip" \
        --data-binary "@${tarball_path}" \
        "${upload_url}" >/dev/null

    success "Uploaded ${tarball_name} to https://github.com/${REPO_SLUG}/releases/tag/${tag}"
}

# -----------------------------------------------------------------------------
# 7. Complete Deployment Pipeline (Update Repo + Build Images + Publish)
# -----------------------------------------------------------------------------
full_deployment_pipeline() {
    banner
    echo -e "${BOLD}${CYAN}=== Starting End-to-End LogOps Deployment Pipeline ===${NC}"
    echo ""
    
    local ver
    ver="$(get_current_version)"
    echo -e "Target Version: ${BOLD}${GREEN}v${ver}${NC}"
    echo -e "Target Repo:    ${BOLD}${CYAN}${REPO_URL}${NC}"
    echo ""

    echo -ne "${BOLD}Do you want to bump version first? (y/N): ${NC}"
    read -r bump_choice
    if [[ "${bump_choice}" =~ ^[Yy]$ ]]; then
        bump_version
        ver="$(get_current_version)"
    fi

    # Step 1: Update GitHub Repository
    info "[Step 1/3] Updating and pushing repository to ${REPO_URL}..."
    update_repo "Release v${ver}: Zero-Leak LogOps AI Diagnostic Platform"

    # Step 2: Build Deployment Images
    info "[Step 2/3] Building container images and exporting deployment tarball..."
    build_package "${ver}"

    # Step 3: Publish GitHub Release
    echo -ne "${BOLD}Publish release and upload assets to GitHub? (Y/n): ${NC}"
    read -r pub_choice
    if [[ ! "${pub_choice}" =~ ^[Nn]$ ]]; then
        info "[Step 3/3] Publishing release v${ver} to ${REPO_URL}..."
        publish_release "${ver}"
    fi

    success "End-to-End Deployment Pipeline completed successfully!"
}

# -----------------------------------------------------------------------------
# 8. Clean Up
# -----------------------------------------------------------------------------
cleanup() {
    echo ""
    echo -e "${BOLD}${CYAN}=== LogOps Artifact Clean Up ===${NC}"
    echo "Cleaning LogOps runtime logs and old offline tarballs..."
    rm -f "${SCRIPT_DIR}"/logops-docker-*.tar.gz*
    rm -f "${LOGOPS_DIR}/server/server.log"
    success "Cleaned LogOps package archives and server logs."
}

# -----------------------------------------------------------------------------
# 9. Runtime Management Wrapper
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
${BOLD}LogOps Platform — Administration & Deployment Utility${NC}
Target GitHub Repository: ${CYAN}${REPO_URL}${NC}

Usage: ./admin-logops.sh [COMMAND] [OPTIONS]

REPOSITORY & DEPLOYMENT COMMANDS:
    update-repo | push [msg]    Stage, commit, and push all updates to ${REPO_URL}
    build [version]             Build Docker images and export deployment tarball & SHA256
    push-images [version]       Push built container images to ghcr.io or Docker Hub
    publish | release [version] Create GitHub release on ${REPO_SLUG} with tarball assets
    ship | pipeline             Execute complete pipeline: Push Repo -> Build Images -> Release
    version [patch|minor|major] Increment semantic version in server/package.json & index.html

RUNTIME MANAGEMENT COMMANDS:
    status                      Show container state, ports, bridge, and ELK harvester status
    deploy | enable             Deploy & launch LogOps container via docker compose
    stop | disable              Stop and remove LogOps container
    restart                     Restart LogOps container independently with zero impact on filtr
    bridge                      Verify Zero-Leak data redaction & rehydration link with filtr
    test                        Test LogOps REST health API endpoint
    config                      Interactively configure FILTR_URL, LOGOPS_PORT, and LLM engine
    clean                       Remove old tarballs and local runtime logs
    logs                        Tail live platform container logs
    help                        Show this command reference guide

EXAMPLES:
    ./admin-logops.sh                   # Launch interactive administration menu
    ./admin-logops.sh update-repo       # Commit and push updates to https://github.com/anandprabhusk/logops
    ./admin-logops.sh build             # Build deployment Docker images and offline tarball
    ./admin-logops.sh ship              # End-to-end: Push repo, build images, and publish release
    ./admin-logops.sh status            # View container and bridge status
    ./admin-logops.sh deploy            # Deploy LogOps platform container
EOF
}

# -----------------------------------------------------------------------------
# Interactive Menu
# -----------------------------------------------------------------------------
interactive_menu() {
    while true; do
        banner
        show_status
        echo -e "${BOLD}Repository & Deployment Operations:${NC}"
        echo "  1) 📊 Refresh Status & Diagnostics"
        echo "  2) 🏷️  Version Management & Semantic Bump"
        echo "  3) 🚀 Update GitHub Repository (${REPO_SLUG})"
        echo "  4) 📦 Build Container Images for Deployment"
        echo "  5) 🚢 Push Container Images to Registry (ghcr.io / Docker Hub)"
        echo "  6) 🌐 Publish Release & Assets to GitHub (${REPO_SLUG})"
        echo "  7) ⚡ Full End-to-End Pipeline (Update Repo + Build Images + Release)"
        echo ""
        echo -e "${BOLD}Local Container Runtime Operations:${NC}"
        echo "  8) 🚀 Deploy / Start LogOps Platform Container"
        echo "  9) 🔄 Restart LogOps (Zero impact on filtr)"
        echo "  10) 🛑 Stop LogOps Platform Container"
        echo "  11) 🛡️ Verify filtr Redaction & Rehydration Bridge"
        echo "  12) 🔍 Test LogOps REST Health API"
        echo "  13) ⚙️ Configure filtr URL & LLM Settings (.env)"
        echo "  14) 🧹 Clean Old Tarballs & Logs"
        echo "  15) 📋 Tail Live Container Logs"
        echo "  0) Exit"
        echo ""
        echo -ne "${BOLD}Enter choice [0-15]: ${NC}"
        read -r choice
        case "${choice}" in
            1) ;;
            2) bump_version ;;
            3) update_repo ;;
            4) build_package ;;
            5) push_images ;;
            6) publish_release ;;
            7) full_deployment_pipeline ;;
            8) manage_runtime enable ;;
            9) manage_runtime restart ;;
            10) manage_runtime disable ;;
            11) manage_runtime bridge ;;
            12) manage_runtime test ;;
            13) manage_runtime config ;;
            14) cleanup ;;
            15) manage_runtime logs ;;
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
    update-repo|push|sync)
        shift
        update_repo "$@"
        ;;
    build|package|build-images)
        shift
        build_package "$@"
        ;;
    push-images)
        shift
        push_images "$@"
        ;;
    publish|release)
        shift
        publish_release "$@"
        ;;
    ship|pipeline|deploy-all)
        full_deployment_pipeline
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
