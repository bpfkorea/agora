# Agora

[Docker Hub image](https://hub.docker.com/r/bpfk/agora)

![Github CI](https://github.com/bosagora/agora/actions/workflows/main.yml/badge.svg)
[![codecov](https://codecov.io/gh/bosagora/agora/branch/v0.x.x/graph/badge.svg)](https://codecov.io/gh/bosagora/agora)
[![License](https://img.shields.io/github/license/bosagora/agora)](LICENSE)
[![Documentation](https://img.shields.io/badge/Docs-Github%20Pages-blue)](https://bosagora.github.io/agora/)

Node implementation for BOA CoinNet

# Docker usage

We provide a public build of this repository (see above).
The easiest way to get agora is to run `docker pull bpfk/agora`.

The `Dockerfile` lives at the root of this repository,
so one can run `docker build -t agora .` to build it.
Note that you need to initialize submodules (`git submodule update --init`)
before you first build agora.

For a test run, try:
```console
docker run -p 127.0.0.1:4000:2826/tcp -v `pwd`/doc/:/agora/etc/ agora -c etc/config.example.yaml
```
This will start a node with the example config file,
and make the port locally accessible (See http://127.0.0.1:4000/) .

# Building on POSIX

## Dependencies

You need a recent C++ compiler (g++ with N4387 fixed), a recent (>=1.26.0) version of the LDC compiler, and `dub`.
On Linux, we recommend gcc-9. On OSX, the latest `llvm` package available on Homebrew.

Additionally, the following are dependencies:
- `libsodium`:  Development library
- `pkg-config`: For DUB to find the correct `sqlite3` and other system libraries
- `openssl`:    Binary (to detect the version) and development library
- `sqlite3`:    Development library
- `zlib`:       Development library
- `wasmer`:     Web Assembly Engine - [Install](https://github.com/wasmerio/wasmer-install#readme)

Additionally, on OSX, `PKG_CONFIG_PATH` needs to be properly set to pick up `sqlite3` and `openssl`.
Provided you installed those packages via `brew`, you can run the following command prior to building:
```console
export PKG_CONFIG_PATH="/usr/local/opt/sqlite/lib/pkgconfig:/usr/local/opt/openssl@1.1/lib/pkgconfig"
```
Since this setting does not persist, we recommend you follow Homebrew's instructions
and add it to your `.bashrc`, `.zshrc`, etc...

## Build instructions

```console
# Install the LDC compiler (you might want to use a newer version)
curl https://dlang.org/install.sh | bash -s ldc-1.26.0
# Add LDC to the $PATH
source ~/dlang/ldc-1.26.0/activate
# Clone this repository
git clone https://github.com/bosagora/agora.git
# Use the git root as working directory
cd agora/
# Initialize and update the list of submodules
git submodule update --init
# Build the application
dub build --skip-registry=all
# Build & run the tests
dub test --skip-registry=all
```

## Running tests

Agora comes with plenty of tests. Take a look at the CI configuration for an exact list.
At the moment, the three main ways to run the test are:
- `dub test`: Test the consensus protocol and runs all the unittests
- `rdmd tests/runner.d`: Run a serie of simple integrations tests
- `ci/system_integration_test.d`: Run a full-fledged system integration test, including building the docker image.

## Running single test node using TESTNET GenesisBlock
- `rm -rfv .single && dub run -- -c devel/config-single.yaml` : Run a single node for testing purposes

# Debugging memory usage

Agora integrates its own GC in [agora.utils.gc.GC](source/agora/utils/gc/), which is mostly a copy of
[the default D garbage collector](https://github.com/dlang/druntime/blob/84db3c620dfe1b17e63645a64b55ddffd455bad5/src/core/internal/gc/impl/conservative/gc.d).

This GC comes with a [Tracy](https://github.com/wolfpld/tracy) integration,
allowing one to monitor what and where memory is allocated and freed.
It is not enabled by default, but can be by starting agora with `--DRT-gcopt="gc:tracking-conservative"` or
`--DRT-gcopt="gc:tracking-precise"` if you wish to use the precise GC.

For example:
```shell
$ ./build/agora --DRT-gcopt="gc:tracking-conservative" -c /etc/agora.conf
```
