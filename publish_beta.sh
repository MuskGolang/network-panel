#!/usr/bin/env bash
set -euo pipefail

IMAGE_LOCAL="${IMAGE_LOCAL:-network-panel:latest}"
IMAGE_REMOTE="${IMAGE_REMOTE:-24802117/network-panel:beta}"
DOCKER_TARGET="${DOCKER_TARGET:-final-local}"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

retry_cmd() {
  local max_retry="$1"
  shift
  local n=1
  until "$@"; do
    if [ "$n" -ge "$max_retry" ]; then
      return 1
    fi
    n=$((n + 1))
    echo "命令失败，${n}/${max_retry} 次重试: $*"
    sleep 2
  done
}

ensure_frontend_target() {
  if [ "$DOCKER_TARGET" = "final-local" ] && [ ! -d "vite-frontend-v2/dist" ]; then
    echo "未找到 vite-frontend-v2/dist，自动切换到 final（容器内构建前端）"
    DOCKER_TARGET="final"
  fi
}

mirror_pull_and_tag() {
  local mirror="$1"
  local img="$2"
  local mirror_ref="${mirror}/library/${img}"
  echo "尝试镜像站拉取: ${mirror_ref}"
  docker pull "${mirror_ref}"
  docker tag "${mirror_ref}" "${img}"
}

warmup_base_images_from_mirror() {
  local mirrors=(
    "docker.m.daocloud.io"
    "docker.1ms.run"
  )
  local images=(
    "debian:12-slim"
    "golang:1.25-bookworm"
  )
  local mirror
  local img
  for mirror in "${mirrors[@]}"; do
    local ok=1
    for img in "${images[@]}"; do
      if ! mirror_pull_and_tag "$mirror" "$img"; then
        ok=0
        break
      fi
    done
    if [ "$ok" -eq 1 ]; then
      echo "镜像站预热成功: ${mirror}"
      return 0
    fi
  done
  return 1
}

build_image() {
  ensure_frontend_target
  echo "开始构建镜像: target=${DOCKER_TARGET}"
  docker build --pull=false --target "${DOCKER_TARGET}" -t "${IMAGE_LOCAL}" .
}

build_with_fallback() {
  if build_image; then
    return 0
  fi

  echo "首次构建失败，尝试镜像站预拉取基础镜像后重试..."
  if warmup_base_images_from_mirror; then
    if build_image; then
      return 0
    fi
  else
    echo "镜像站预热失败，继续尝试 legacy builder..."
  fi

  echo "切换 legacy builder 重试构建（DOCKER_BUILDKIT=0）..."
  ensure_frontend_target
  env DOCKER_BUILDKIT=0 docker build --pull=false --target "${DOCKER_TARGET}" -t "${IMAGE_LOCAL}" .
}

push_image() {
  docker tag "${IMAGE_LOCAL}" "${IMAGE_REMOTE}"
  retry_cmd 3 docker push "${IMAGE_REMOTE}"
}

build_with_fallback
push_image
echo "发布完成: ${IMAGE_REMOTE}"
