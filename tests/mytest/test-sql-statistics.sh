#!/bin/bash

MYSQL=mysql
MYSQL_PROXY_RW_PORT=8889
MYSQL_PROXY_ADMIN_PORT=8888
loop_count=5
for ((i=1;i<=$loop_count;i++)); do
  $MYSQL -h X.X.X.X -P $MYSQL_PROXY_RW_PORT -u test -ptest test -ABs -e "select $i" &
  $MYSQL -h X.X.X.X -P $MYSQL_PROXY_RW_PORT -u test -ptest test1 -ABs -e "select $i" &
  $MYSQL -h X.X.X.X -P $MYSQL_PROXY_RW_PORT -u test -ptest test2 -ABs -e "select $i" &
  $MYSQL -h X.X.X.X -P $MYSQL_PROXY_RW_PORT -u test1 -ptest11 test -ABs -e "select $i" &
  $MYSQL -h X.X.X.X -P $MYSQL_PROXY_RW_PORT -u test1 -ptest11 test1 -ABs -e "select $i" &
  $MYSQL -h X.X.X.X -P $MYSQL_PROXY_RW_PORT -u test1 -ptest11 test2 -ABs -e "select $i" &
done >/dev/null 2>&1 &
wait

#eof
