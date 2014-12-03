#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh
### 测试在admin 端口执行command --help（-h） 不会产生core dump ######
mysql_cmd="$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e"

expect_result="ERROR 3026 (42000) at line 1: admin command syntax error"

test_sql1="addbackend --help"
###### 执行测试 ######
ret=$($mysql_cmd "$test_sql1" 2>&1)
if [ "$expect_result" != "$ret ];then
   echo "expected ret:$expect_result"
   echo "actual ret:$ret"
   exit 1
fi

test_sql2="addbackend -h"
###### 执行测试 ######
ret=$($mysql_cmd "$test_sql2" 2>&1)
if [ "$expect_result" != "$ret ];then
   echo "expected ret:$expect_result"
   echo "actual ret:$ret"
   exit 1
fi

ret=0

bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof
