#!/bin/bash
set -e
cargo build --release
./target/release/homepage "$@"
