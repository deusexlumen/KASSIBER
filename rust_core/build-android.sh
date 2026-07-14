#!/usr/bin/env bash
set -euo pipefail
echo "=== KASSIBER Android Build ==="
if ! command -v cargo-ndk &> /dev/null; then
    echo "Installing cargo-ndk..."
    cargo install cargo-ndk
fi
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/26.1.10909125}"
declare -a ABIS=("armeabi-v7a" "arm64-v8a" "x86_64")
cd "$(dirname "$0")"
cargo build --release
JNILIBS_DIR="../android/app/src/main/jniLibs"
mkdir -p "$JNILIBS_DIR"
for i in "${!ABIS[@]}"; do
    ABI="${ABIS[$i]}"
    echo "=== Building for $ABI ==="
    cargo ndk -t "$ABI" -o "$JNILIBS_DIR" build --release --manifest-path kassiber-ffi/Cargo.toml
    echo "  $ABI complete"
done
echo "=== Build Summary ==="
for ABI in "${ABIS[@]}"; do
    SO_PATH="$JNILIBS_DIR/$ABI/libkassiber_ffi.so"
    if [ -f "$SO_PATH" ]; then
        SIZE=$(du -h "$SO_PATH" | cut -f1)
        echo "  $ABI: $SIZE"
    else
        echo "  $ABI: MISSING!"
    fi
done
echo "=== Build complete ==="
