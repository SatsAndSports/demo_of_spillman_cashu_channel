#!/bin/bash
# Run Spilman channel tests in Docker
#
# Usage:
#   ./scripts/docker-test.sh           # CDK tests only (default)
#   ./scripts/docker-test.sh cdk       # CDK tests only
#   ./scripts/docker-test.sh nutmix    # NutMix tests (requires nutmix-mint image)
#   ./scripts/docker-test.sh all       # All tests
#   ./scripts/docker-test.sh build     # Just build the image
#
# The image is automatically rebuilt when git HEAD changes.
# Only git-tracked files at HEAD are included in the build.

set -e

IMAGE_NAME="cdk-test"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$REPO_ROOT"

# Get current git HEAD
CURRENT_HEAD=$(git rev-parse HEAD)

# Check if image exists and get the HEAD it was built from
get_image_head() {
    docker inspect "$IMAGE_NAME" --format '{{index .Config.Labels "git.head"}}' 2>/dev/null || echo ""
}

build_image() {
    echo "Building test image from git HEAD ($CURRENT_HEAD)..."
    git archive HEAD | docker build \
        -f scripts/Dockerfile.test \
        --label "git.head=$CURRENT_HEAD" \
        -t "$IMAGE_NAME" \
        -
    echo "Build complete."
}

needs_rebuild() {
    local image_head
    image_head=$(get_image_head)
    
    if [ -z "$image_head" ]; then
        echo "Image does not exist, building..."
        return 0
    fi
    
    if [ "$image_head" != "$CURRENT_HEAD" ]; then
        echo "HEAD changed ($image_head -> $CURRENT_HEAD), rebuilding..."
        return 0
    fi
    
    return 1
}

# Handle build command
if [ "${1:-}" = "build" ]; then
    build_image
    exit 0
fi

# Auto-rebuild if needed
if needs_rebuild; then
    build_image
fi

# Run tests
case "${1:-cdk}" in
    cdk)
        echo "Running CDK tests..."
        docker run --rm "$IMAGE_NAME" make test-python-parallel-cdk test-go-parallel-cdk
        ;;
    nutmix)
        echo "Running NutMix tests..."
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$IMAGE_NAME" \
            make test-python-parallel-nutmix test-go-parallel-nutmix
        ;;
    all)
        echo "Running all tests..."
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$IMAGE_NAME" \
            make test-python-parallel-cdk test-go-parallel-cdk \
                 test-python-parallel-nutmix test-go-parallel-nutmix
        ;;
    *)
        echo "Usage: $0 [cdk|nutmix|all|build]"
        echo ""
        echo "Commands:"
        echo "  cdk      Run tests with CDK mint (default)"
        echo "  nutmix   Run tests with NutMix mint (requires Docker socket + nutmix-mint image)"
        echo "  all      Run all tests"
        echo "  build    Just build the Docker image"
        echo ""
        echo "The image auto-rebuilds when git HEAD changes."
        echo "Current HEAD: $CURRENT_HEAD"
        echo "Image HEAD:   $(get_image_head)"
        exit 1
        ;;
esac
