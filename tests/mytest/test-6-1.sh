#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

#### 写端口测试 #######
#### 用户连接限制数 >=10 ######
#### 1 设置预设条件 ######

### 1.1 添加用户 #####
mysql_cmd="$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e"
check_sql="showusers"
_r=$($mysql_cmd $check_sql|grep proxy|grep $MYSQL_PROXY_WORKER_IP|wc -l)
if [ $_r = 0 ];then
	$mysql_cmd "AddUser --username=test --passwd=test --hostip=$MYSQL_PROXY_WORKER_IP"
	if [ $? != 0 ];then
		echo "add user error"
		exit 1
	fi
fi

### 1.2 设置账号连接限制 #######
$mysql_cmd "SetConnLimit --username=test --port-type=rw --hostip=$MYSQL_PROXY_WORKER_IP --conn-limit=0;"
### 1.3 设置最小连接数
$mysql_cmd "SetPoolConfig --username=test --port-type=rw --max-conn=20 --min-conn=5 --save-option=mem"

t=$(
(
(
PORT=$MYSQL_PROXY_RW_PORT
for i in {1..10}; do
$MYSQL -h $MYSQL_PROXY_WORKER_IP -P $PORT -u test -ptest -ABs -e "show variables like 'wsrep_node_address'" &
done
) | sort | uniq -c | sed 's/\t/ /g;s/^[[:space:]]*//'
) 2>&1
)
r="10 wsrep_node_address X.X.X.X:5010"
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
