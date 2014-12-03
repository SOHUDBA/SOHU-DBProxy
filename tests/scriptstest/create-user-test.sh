#/bin/bash
TEST_PROGRAM=$1

declare -i _tc_ok=0
declare -i _tc_total=17

#-----------------------------------------------------------#
# missing parameter. 4 testcases;
#-----------------------------------------------------------#
result=$(bash $TEST_PROGRAM -u 'fanzhen'@'1.2.3.4' -p1234 2>&1)
if [[ "$result" =~ "grant error" ]]; then 
  ((_tc_ok++))
fi

result=$(bash $TEST_PROGRAM -u 'fanzhen'@'1.2.3.4' -g "select on *.*" 2>&1)
if [[ "$result" =~ "password error" ]]; then 
  ((_tc_ok++))
fi

result=$(bash $TEST_PROGRAM -p1234 -g "select on *.*" 2>&1)
if [[ "$result" =~ "user error" ]]; then 
  ((_tc_ok++))
fi

result=$(bash $TEST_PROGRAM -u 'fanzhen'@'1.2.3.4' -p --grant="create on test.*" 2>&1)
if [[ "$result" =~ "grant error" ]]; then 
  ((_tc_ok++))
fi

#-----------------------------------------------------------#
# bad user format. 2 testcases;
#-----------------------------------------------------------#
result=$(bash $TEST_PROGRAM -u 'fanzhen' -p1234 -g "select on *.*" 2>&1)
if [[ "$result" =~ "user error" ]]; then 
  ((_tc_ok++))
fi

result=$(bash $TEST_PROGRAM -u 'fanzhen'%'1.2.3.4' -p1234 -g "select on *.*" 2>&1)
if [[ "$result" =~ "user error" ]]; then
  ((_tc_ok++))
fi

#-----------------------------------------------------------#
# bad ip format. 6 testcases;
#-----------------------------------------------------------#
result=$(bash $TEST_PROGRAM -u 'xxxxx'@'x.x.x.x' -pxxxx -g "select on *.*" 2>&1)
if [[ "$result" =~ "ip format error" ]]; then 
  ((_tc_ok++))
fi

result=$(bash $TEST_PROGRAM -u 'xxxx'@'x.x.x.x' -pxxx -g "select on *.*" 2>&1)
if [[ "$result" =~ "ip format error" ]]; then 
  ((_tc_ok++))
fi

result=$(bash $TEST_PROGRAM -u 'xxxx'@'x.x.x.x' -pxxx -g "select on *.*" 2>&1)
if [[ "$result" =~ "ip format error" ]]; then 
  ((_tc_ok++))
fi

result=$(bash $TEST_PROGRAM -u 'fanzhen'@'%' -p1234 -g "select on *.*" 2>&1)
if [[ "$result" =~ "ip format error" ]]; then 
  ((_tc_ok++))
fi

result=$(bash $TEST_PROGRAM -u 'xxxx'@'10.%' -pxxx -g "select on *.*" 2>&1)
if [[ "$result" =~ "ip format error" ]]; then 
  ((_tc_ok++))
fi

result=$(bash $TEST_PROGRAM -u 'xxxx'@'10.10.%' -pxxxx -g "select on *.*" 2>&1)
if [[ "$result" =~ "ip format error" ]]; then 
  ((_tc_ok++))
fi

#-----------------------------------------------------------#
# backend error. 2 testcases;
#-----------------------------------------------------------#
result=$(bash $TEST_PROGRAM -u 'fanzhen'@'X.X.X.%' -p1234 -g "select1 on *.*" 2>&1)
if [[ "$result" =~ "Create user on backend failed" ]]; then 
  ((_tc_ok++))
fi

result=$(bash $TEST_PROGRAM -u 'fanzhen'@'X.X.X.%' -p1234 -g "select, insert1 on *.*" 2>&1)
if [[ "$result" =~ "Create user on backend failed" ]]; then 
  ((_tc_ok++))
fi

#-----------------------------------------------------------#
# proxy error: proxy down or admin port doesn't listen. 0 testcases;
#-----------------------------------------------------------#

#-----------------------------------------------------------#
# succeed. 3 testcases;
#-----------------------------------------------------------#
result=$(bash $TEST_PROGRAM -u 'fanzhen'@'X.X.%.%' -p1234 -g "select on *.*" 2>&1)
if [[ "$result" =~ "Create user on proxy succeed" ]]; then 
  ((_tc_ok++))
fi

result=$(bash $TEST_PROGRAM -u 'fanzhen'@'X.X.X.%' -p1234 -g "select, insert, update, delete on *.*" 2>&1)
if [[ "$result" =~ "Create user on proxy succeed" ]]; then 
  ((_tc_ok++))
fi

result=$(bash $TEST_PROGRAM -u 'fanzhen123'@'X.X.X.%' -p1234 -g "select, insert, update, delete on test.*" 2>&1)
if [[ "$result" =~ "Create user on proxy succeed" ]]; then 
  ((_tc_ok++))
fi

echo "============================================================"
echo "total testcases: $_tc_total"
echo "passed testcases: $_tc_ok"
echo -n "failed testcases: " 
echo $(($_tc_total-$_tc_ok))
echo "============================================================"
