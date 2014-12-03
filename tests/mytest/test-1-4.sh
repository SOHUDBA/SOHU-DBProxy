#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

#####预置条件是：127.0.0.1没有访问权限 #######

#####先删除用户test -test(内存删除)
#####
mysql_cmd="$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e"
del_sql="DelUser --username=test --hostip=%.%.%.% --save-option=mem"
$mysql_cmd "$del_sql"

t=$(
(
$MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest -ABs -e "select 1"
) 2>&1
)
r="ERROR 3006 (HY000): client ip is not allowed"
ret=0
if [ "$t" = "$r" ]; then
  ret=0
else
  echo "expected result: \"$r\""
  echo "actual result: \"$t\""
  ret=1
fi


bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof
