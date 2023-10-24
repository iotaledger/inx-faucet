#!/bin/bash
pushd ../tools/gendoc

# determine current inx-faucet version tag
commit_hash=$(git rev-parse --short HEAD)

BUILD_TAGS=rocksdb
BUILD_LD_FLAGS="-s -w -X=github.com/iotaledger/inx-faucet/components/app.Version=${commit_hash}"

go run -tags ${BUILD_TAGS} -ldflags "${BUILD_LD_FLAGS}" main.go

popd
