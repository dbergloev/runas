#!/bin/bash

echo "Building PAM"
RUSTFLAGS="-l pam" cargo build --release --features use_pam || exit 1
mv target/release/runas target/release/runas.pam

echo ""
echo "Building Shadow"
cargo build --release || exit 1
mv target/release/runas target/release/runas.shadow

echo ""
echo "Building Run0"
RUSTFLAGS="-l pam" cargo build --release --features use_pam,use_run0 || exit 1
mv target/release/runas target/release/runas.run0
