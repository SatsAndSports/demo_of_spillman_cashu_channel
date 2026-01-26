#!/bin/bash
# Run Spilman channel tests in Docker
#
# Usage:
#   ./scripts/docker-test.sh           # Show help
#   ./scripts/docker-test.sh cdk       # CDK tests only
#   ./scripts/docker-test.sh nutmix    # NutMix tests (native PostgreSQL in container)
#   ./scripts/docker-test.sh all       # All tests
#   ./scripts/docker-test.sh build     # Just build the image
#
# Docker layer caching handles rebuilds automatically.
#
# Build includes:
#   - All committed files at HEAD
#   - Uncommitted modifications to tracked files (via git stash create)
# Build does NOT include:
#   - Untracked files (files never added to git)
#   - Files in .gitignore

set -e

IMAGE_NAME="cdk-test"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$REPO_ROOT"

build_image() {
    # Use git stash create to include uncommitted changes to tracked files.
    # If working tree is clean, stash create returns empty, so we fall back to HEAD.
    STASH_COMMIT=$(git stash create)
    echo "Building test image from ${STASH_COMMIT:-HEAD}..."
    git archive --format=tar "${STASH_COMMIT:-HEAD}" | docker build -f scripts/Dockerfile.test -t "$IMAGE_NAME" -
}

case "${1:-help}" in
    build)
        build_image
        ;;
    cdk)
        build_image
        echo "Running CDK tests..."
        docker run --rm "$IMAGE_NAME" make test-python-parallel-cdk test-go-parallel-cdk
        ;;
    nutmix)
        build_image
        echo "Running NutMix tests (native mode)..."
        docker run --rm "$IMAGE_NAME" make test-python-parallel-nutmix-native test-go-parallel-nutmix-native
        ;;
    all)
        build_image
        echo "Running all tests..."
        docker run --rm "$IMAGE_NAME" make test-python-parallel-cdk test-go-parallel-cdk \
                 test-python-parallel-nutmix-native test-go-parallel-nutmix-native
        ;;
    *)
        echo "Usage: $0 [cdk|nutmix|all|build]"
        echo ""
        echo "Commands:"
        echo "  cdk      Run tests with CDK mint"
        echo "  nutmix   Run tests with NutMix mint (native PostgreSQL in container)"
        echo "  all      Run all tests"
        echo "  build    Just build the Docker image"
        exit 1
        ;;
esac
