#!/bin/bash

echo "Building PAM"
RUSTFLAGS="-l pam" cargo build --release --features use_pam || exit 1
mv -f target/release/runas target/release/runas.pam 2>/dev/null

echo ""
echo "Building Shadow"
cargo build --release || exit 1
mv -f target/release/runas target/release/runas.shadow 2>/dev/null

echo ""
echo "Building ScopeX"
RUSTFLAGS="-l pam" cargo build --release --features use_pam,backend_scopex || exit 1
mv -f target/release/runas target/release/runas.scopex 2>/dev/null

echo ""
echo "Building Run0"
RUSTFLAGS="-l pam" cargo build --release --features use_pam,backend_run0 || exit 1
mv -f target/release/runas target/release/runas.run0 2>/dev/null

