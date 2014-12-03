#!/bin/bash

MYSQL=mysql
MYSQL_PROXY_RW_PORT=8889
MYSQL_PROXY_ADMIN_PORT=8888
loop_count=10
conn_limit=$(($loop_count+100))
min_conn=$(($loop_count+50))
$MYSQL -h 127.0.0.1 -P $MYSQL_PROXY_ADMIN_PORT -uadtest -padtest -ABs -e "setmultiplex --flag=off; setconnlimit --username=test --hostip=X.X.X.% --port-type=ro --conn-limit=$conn_limit;"
echo ...start...
(
for ((i=1;i<=$loop_count;i++)); do
  sleep_time=$(($i+5))
  $MYSQL -h X.X.X.X -P $MYSQL_PROXY_RW_PORT -u test -ptest test -ABs -e "select sleep(40), $i" &
done
) | wc -l >/dev/null 2>&1 &

echo ...all $loop_count clients execute query...
sleep 3

echo ...show proxy processlist...

t=$(
(
(
$MYSQL -h 127.0.0.1 -P $MYSQL_PROXY_ADMIN_PORT -uadtest -padtest -ABs -e "ShowProxyProcesslist;"
) | wc -l 
) 2>&1
)

ret=0
if [ "$t" = $loop_count ]; then
  echo "testcase passed"
  echo "expected result: \"$loop_count\""
  echo "actual result: \"$t\""
  ret=0
else
  echo "testcase failed"
  echo "expected result: \"$loop_count\""
  echo "actual result: \"$t\""
  ret=1
fi
echo ...end...


exit $ret
#eof
