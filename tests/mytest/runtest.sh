#!/bin/bash
TEST_CASE_OUTPUT=""

run_test_case()
{
  declare _test_case=$1
  declare _script=${_test_case}.sh
  TEST_CASE_OUTPUT=$( ( bash ${SCRIPT_DIR}/$_script ) 2>&1 )
}

run_test_suite()
{
  declare _suite=$1
  #declare _array_ref=TEST_SUITE_${_suite}[@]
  declare _var_ref=_TEST_SUITE_${_suite}
  declare -a _array=( ${!_var_ref} )
  declare _test_case
  declare -i _i=0
  declare -i _tc_ret
  declare -i _tc_ok=0
  declare -i _tc_fail=0
  echo "running test suite: $test_suite ..."
  #for _test_case in "${!_array_ref}"; do
  for _test_case in ${_array[@]}; do
    if [ -n "$TESTCASE" -a "$TESTCASE" != "$_test_case" ]; then
      continue
    fi
    echo -n "running test case: $_test_case ..."
    run_test_case "$_test_case"
    _tc_ret=$?
    if (( _tc_ret != 0 )); then
      ((_tc_fail++))
      echo "FAIL"
      echo "==detail==
$TEST_CASE_OUTPUT
==
"
    else
      ((_tc_ok++))
      echo "OK"
    fi
    ((_i++))
  done
  if ((_tc_ok == _i)); then
    echo "PASS: ($_tc_ok/$_i) $_suite"
  else
    echo "NOT PASS: ($_tc_ok/$_i) $_suite"
  fi
}

run_test_suites()
{
  declare i=0
  declare array_len=${#TEST_SUITES[@]}
  declare test_suite
  declare -i run=1
  for ((i=0; i<$array_len; i++)); do
    test_suite=${TEST_SUITES[$i]}
    if [ -n "$TESTSUITE" -a "$TESTSUITE" != "$test_suite" ]; then
      continue
    fi
    run_test_suite "$test_suite"
  done
}


# main entry

DIRNAME=$(dirname $0)
PROGNAME=runtest.sh

usage()
{
  cat <<EOF
Usage: $PROGNAME --execute --testsuite=...|--testcase=...
EOF
}

SHORT_OPTS="h"
LONG_OPTS="execute testsuite: testcase: autostart: test:"
[ $# -gt 0 ] && ARGS=$(getopt -n$PROGNAME -o "$SHORT_OPTS" -l "$LONG_OPTS" -- "$@") || { usage; exit 1; }
eval set -- "$ARGS"
while [ $# -gt 0 ]; do
  case "$1" in
    -h) usage; exit 0 ;;
  
    --execute) REAL_RUN=1 ;;
    --testsuite) TESTSUITE=$2; shift ;;
    --testcase) TESTCASE=$2; shift ;;
    --autostart)
      if [ "$2" = "N" -o "$2" = "n" ]; then
        export AUTOSTART=N
      else
        export AUTOSTART=Y
      fi
      shift
      ;;
    --test)
      echo "source ${DIRNAME}/setenv.sh \"$2\""
      source ${DIRNAME}/setenv.sh "$2"
      shift
      ;; 

    --) shift
      break ;;
    #bad options
    -*) usage; exit 1 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

declare -a TEST_SUITES=( $_TEST_SUITES )
#declare -a TEST_SUITE_account_auth=( $_TEST_SUITE_account_auth    )
#declare -a TEST_SUITE_user_conn_limit=( $_TEST_SUITE_user_conn_limit )
#declare -a TEST_SUITE_conn_multiplex=( $_TEST_SUITE_conn_multiplex  )
#declare -a TEST_SUITE_conn_context=( $_TEST_SUITE_conn_context    )
#declare -a TEST_SUITE_bk_async_con=( $_TEST_SUITE_bk_async_con    )
#declare -a TEST_SUITE_rw_ro_service=( $_TEST_SUITE_rw_ro_service   )
#declare -a TEST_SUITE_load_balance=( $_TEST_SUITE_load_balance    )
#declare -a TEST_SUITE_stress=( $_TEST_SUITE_stress )
#declare -a TEST_SUITE_bug_test=( $_TEST_SUITE_bug_test )
#declare -a TEST_SUITE_admin_mange=( $_TEST_SUITE_admin_mange )

if [ "$REAL_RUN" = 1 ]; then
  run_test_suites
fi


#eof
