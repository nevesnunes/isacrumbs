#!/usr/bin/env sh

set -eu

GHIDRA_INSTALL_DIR=$1
shift
GHIDRA_SCRIPTS_DIR=$1
shift
TESTS=$1
shift

classpath() {
  {
    find "$GHIDRA_INSTALL_DIR" -type f -iname '*.jar'
    find "$GHIDRA_SCRIPTS_DIR/bin" -type f -iname '*.class' -exec dirname {} \; | sort -u
    find '../lib' -type f -iname '*.jar'
  } | paste -sd :
}

exec java \
  -classpath "$(classpath)" \
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
