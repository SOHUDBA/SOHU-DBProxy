#!/bin/bash
# this is added to test bug character_set_results 可否为NULL的bug
bash $SCRIPT_DIR/start_proxy.sh

#### 1. 该用例用于测试恢复character_set_results为NULL时，DBProxy会core dump的bug ####
#### 连接服用开启 #######

### 1. 预置条件 ######
mysql_cmd="$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e"
set_sql="SetMultiplexSwitch --flag=on"
$mysql_cmd "$set_sql"
_r=$?
if [ $_r != 0 ];then
	echo "set Multiplex on error"
	exit 1
fi

### 2. 执行测试 #######
$MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -test -ABs -e "set character_set_results = NULL;system sleep 1;show variables like '%set%'" 1>/dev/null 2>&1

_r=$?
ret=0
if [ "x$_r" = "x0" ]; then
  ret=0
else
  echo "expected result: 0"
  echo "actual result: \"$_r\""
  ret=1
fi


bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof
