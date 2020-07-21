#!/bin/sh
# integration_test DOA (dead-or-alive) test

. ./tester_help_func.sh

INTEGRATION_TEST="./*integration_tests"

# Log file name must have the test script name with .log suffix (for BuildBot tester to know it when copying to its log)
if [[ -z $TEST_BASENAME ]]; then TEST_BASENAME=`basename $0 .sh`; fi
export LOG_FNAME=logs/$TEST_BASENAME.log
TESTS_LOG_BASENAME=logs/$TEST_BASENAME.test
# Test sequence (main)
start_log


DRIVER_LOAD_FILE_NAME="load_pal_driver.sh"
if [[ -f $DRIVER_LOAD_FILE_NAME ]]; then
        ./$DRIVER_LOAD_FILE_NAME "load";
fi
sync


for name in $INTEGRATION_TEST; do
    exec_test " $name" "$name"
done

if [[ -f $DRIVER_LOAD_FILE_NAME ]]; then
        ./$DRIVER_LOAD_FILE_NAME "unload";
fi

# Test summary
gen_test_summary
exit ${TEST_FAIL_CNT}
