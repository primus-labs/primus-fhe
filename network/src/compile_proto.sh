#!/bin/bash
protoc --rust_out=. --grpc_out=. --plugin=protoc-gen-grpc=$(which grpc_rust_plugin) *.proto
