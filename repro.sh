#!/bin/bash

function banner() {
    echo "**********************************************************************"
    echo "* $1"
    echo "**********************************************************************"
}

function die() {
    echo "*** $1"
    exit 1;
}

build_mode=Debug
build_mode_flag="--$(tr A-Z a-z <<<${build_mode})"
jsc_path="$(realpath "WebKitBuild/${build_mode}/bin/jsc")"
gdb_log_file="$(realpath ./gdb-trace)"
jsc_log_file="$(realpath ./jsc-trace)"

if true; then # set to false to disable GDB
   function invoke_jsc() {
       TERM=screen gdb \
           -ex "set logging file ${log_file}" \
           -ex "set logging overwrite on" \
           -ex "set logging on" \
           -ex "set environment WTF_DATA_LOG_FILENAME=${jsc_log_file}" \
           -ex "r" \
           --args "$jsc_path" "$@"
   }
else
    function invoke_jsc() {
        "$jsc_path" "$@"
    }
fi;

banner "building JSC"

./Tools/Scripts/build-webkit "${build_mode_flag}" --jsc-only || die "build failed"

banner "cleaning old JSC logs"

rm ./jsc-trace.*.txt

banner "attempting reproduction"

( cd JSTests/wasm/gc; \
  set -x; \
  invoke_jsc \
      --useRandomizingExecutableIslandAllocation=true \
      --useDFGJIT=true \
      --thresholdForJITAfterWarmUp=1 \
      --thresholdForJITSoon=1 \
      --thresholdForOptimizeAfterWarmUp=1 \
      --thresholdForOptimizeAfterLongWarmUp=1 \
      --thresholdForOptimizeSoon=1 \
      \
      --thresholdForOMGOptimizeAfterWarmUp=20 \
      --thresholdForOMGOptimizeSoon=20 \
      --maximumEvalCacheableSourceLength=150000 \
      --useEagerCodeBlockJettisonTiming=true \
      --repatchBufferingCountdown=0 \
      \
      --verboseDFGBytecodeParsing=1 \
      --useBaselineJIT=false \
      --useLLInt=false \
      --forceUnlinkedDFG=1 \
      --verboseOSR=1 \
      --dumpDisassembly=1 \
      --logJIT=1 \
      -m crash.js )
