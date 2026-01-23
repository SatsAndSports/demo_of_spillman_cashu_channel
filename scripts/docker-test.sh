#!/bin/bash
# Run Spilman channel tests in Docker
#
# Usage:
#   ./scripts/docker-test.sh           # Show help
#   ./scripts/docker-test.sh cdk       # CDK tests only
#   ./scripts/docker-test.sh nutmix    # NutMix tests (requires nutmix-mint image)
#   ./scripts/docker-test.sh all       # All tests
#   ./scripts/docker-test.sh build     # Just build the image
#
# Docker layer caching handles rebuilds automatically.
# Only git-tracked files at HEAD are included.

set -e

IMAGE_NAME="cdk-test"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$REPO_ROOT"

build_image() {
    echo "Building test image from git HEAD..."
    git archive --format=tar HEAD | docker build -f scripts/Dockerfile.test -t "$IMAGE_NAME" -
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
        echo "Running NutMix tests..."
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$IMAGE_NAME" \
            make test-python-parallel-nutmix test-go-parallel-nutmix
        ;;
    all)
        build_image
        echo "Running all tests..."
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$IMAGE_NAME" \
            make test-python-parallel-cdk test-go-parallel-cdk \
                 test-python-parallel-nutmix test-go-parallel-nutmix
        ;;
    *)
        echo "Usage: $0 [cdk|nutmix|all|build]"
        echo ""
        echo "Commands:"
        echo "  cdk      Run tests with CDK mint"
        echo "  nutmix   Run tests with NutMix mint (requires Docker socket + nutmix-mint image)"
        echo "  all      Run all tests"
        echo "  build    Just build the Docker image"
        exit 1
        ;;
esac
