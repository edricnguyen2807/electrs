#!/bin/bash
set -eux
cd `dirname $0`

cargo fmt --all
cargo build --all  --release
#--features "metrics_process"
NETWORK=$1
shift

DB=${DB-./db}
export RUST_LOG=${RUST_LOG-electrs=INFO}
target/release/electrs --network $NETWORK --conf=./config.toml --db-dir $DB --daemon-dir $HOME/.bitcoin $*

# use SIGINT to quit
