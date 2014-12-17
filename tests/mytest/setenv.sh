#!/bin/bash
testname="$1"
SOURCE="${BASH_SOURCE[0]}"
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
if [ -n "$testname" ]; then
  echo "$testname"
  export SCRIPT_DIR=$DIR
  source ${SCRIPT_DIR}/${testname}.cnf
fi
#eof
