#!/usr/bin/env sh

set -eu

RUNNER_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)

GHIDRA_INSTALL_DIR=$1
shift

GHIDRA_SCRIPTS_DIR=$1
GHIDRA_SCRIPTS_BUILD_DIR=$GHIDRA_SCRIPTS_DIR/bin/default
mkdir -p "$GHIDRA_SCRIPTS_BUILD_DIR"
shift

TESTS=$1
shift

classpath() {
  {
    find "$GHIDRA_INSTALL_DIR" "$RUNNER_DIR/../lib" -type f -iname '*.jar'
    find "$GHIDRA_SCRIPTS_BUILD_DIR" -type f -iname '*.class' -exec dirname {} \; | sort -u
  } | paste -sd :
}

GHIDRA_SCRIPTS_CLASSPATH=$(classpath)
export \
  GHIDRA_SCRIPTS_BUILD_DIR \
  GHIDRA_SCRIPTS_CLASSPATH \
  GHIDRA_SCRIPTS_DIR \
  RUNNER_DIR
make -f "$RUNNER_DIR/Makefile"

exec java \
  -classpath "$GHIDRA_SCRIPTS_CLASSPATH" \
  -XX:+ShowCodeDetailsInExceptionMessages \
  "$@" \
  org.junit.platform.console.ConsoleLauncher \
  execute \
  --config junit.platform.stacktrace.pruning.enabled=false \
  --disable-banner \
  --exclude-engine junit-vintage \
  --exclude-engine junit-platform-suite \
  --fail-if-no-tests \
  --select-class "$TESTS"
