#!/bin/bash

MYSQL=mysql
MYSQL_PROXY_RW_PORT=8889
MYSQL_PROXY_ADMIN_PORT=8888
loop_count=120000
for ((i=1;i<=$loop_count;i++)); do
  table=table$i
  $MYSQL -h X.X.X.X -P $MYSQL_PROXY_RW_PORT -u test -ptest test -ABs -e "select $i from $table" &
done >/dev/null 2>&1 &
wait

#eof
