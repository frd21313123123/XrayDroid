#!/usr/bin/env bash
# Сборка APK: Rust-библиотека (cargo-ndk) + Gradle.
# Нужны: Android SDK (platform 35, build-tools 35), NDK r27, JDK 17+, cargo-ndk.
set -euo pipefail
cd "$(dirname "$0")"
: "${ANDROID_HOME:=${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
export ANDROID_HOME ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)}"
export ANDROID_JAR="${ANDROID_JAR:-$(ls -d "$ANDROID_HOME"/platforms/android-* | sort -V | tail -1)/android.jar}"
TARGETS="${TARGETS:-arm64-v8a armeabi-v7a x86_64}"
args=()
for t in $TARGETS; do args+=(-t "$t"); done
cargo ndk "${args[@]}" --platform 26 -o android/app/src/main/jniLibs build --release -p xd-app --lib
cd android
GRADLE="${GRADLE:-gradle}"
"$GRADLE" --no-daemon assembleRelease
ls -la app/build/outputs/apk/release/
