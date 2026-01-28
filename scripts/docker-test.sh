#!/bin/bash
# Run Spilman channel tests in Docker
#
# Usage:
#   ./scripts/docker-test.sh           # Show help
#   ./scripts/docker-test.sh cdk       # CDK tests only
#   ./scripts/docker-test.sh nutmix    # NutMix tests (native PostgreSQL in container)
#   ./scripts/docker-test.sh all       # All tests
#   ./scripts/docker-test.sh build     # Just build the image
#   ./scripts/docker-test.sh clean     # Remove lingering test containers
#
# Test containers are labeled with 'com.cdk.spilman-test=true' for easy cleanup.
# The script will warn you about lingering containers before running new tests.
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

LABEL="com.cdk.spilman-test=true"

cd "$REPO_ROOT"

check_lingering() {
    LINGERING=$(docker ps -q --filter "label=$LABEL")
    if [ -n "$LINGERING" ]; then
        echo "⚠️  WARNING: Lingering test containers detected from previous runs:"
        docker ps --filter "label=$LABEL" \
            --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.RunningFor}}"
        echo ""
        echo "To clean them up, run:"
        echo "  $0 clean"
        echo ""
        return 1
    fi
    return 0
}

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
        check_lingering || true
        echo "Running CDK tests..."
        docker run --rm --label "$LABEL" "$IMAGE_NAME" make test-python-parallel-cdk test-go-parallel-cdk
        ;;
    nutmix)
        build_image
        check_lingering || true
        echo "Running NutMix tests (native mode)..."
        docker run --rm --label "$LABEL" "$IMAGE_NAME" make test-python-parallel-nutmix-native test-go-parallel-nutmix-native
        ;;
    all)
        build_image
        check_lingering || true
        echo "Running all tests..."
        docker run --rm --label "$LABEL" "$IMAGE_NAME" make test-python-parallel-cdk test-go-parallel-cdk \
                 test-python-parallel-nutmix-native test-go-parallel-nutmix-native
        ;;
    clean)
        LINGERING=$(docker ps -q --filter "label=$LABEL")
        if [ -z "$LINGERING" ]; then
            echo "No lingering test containers found."
        else
            echo "Removing test containers:"
            docker ps --filter "label=$LABEL" \
                --format "table {{.ID}}\t{{.Names}}\t{{.RunningFor}}"
            docker rm -f $LINGERING
            echo "Cleaned up."
        fi
        ;;
    *)
        echo "Usage: $0 [cdk|nutmix|all|build|clean]"
        echo ""
        echo "Commands:"
        echo "  cdk      Run tests with CDK mint"
        echo "  nutmix   Run tests with NutMix mint (native PostgreSQL in container)"
        echo "  all      Run all tests"
        echo "  build    Just build the Docker image"
        echo "  clean    Remove lingering test containers"
        exit 1
        ;;
esac
