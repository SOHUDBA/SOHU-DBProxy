#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh
## 该测试用例是测试连接限制，
## 测试的预制条件是：用户test的连接限制数是3
## 预期结果是： 我们可以建立3个连接

####### 1. 设置预置条件 #########

####### 1.1 检查添加账号 #########
mysql_cmd="$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e"
check_sql="showusers"
_r=$($mysql_cmd $check_sql|grep proxy|grep $MYSQL_PROXY_WORKER_IP|wc -l)
if [ $_r = 0 ];then
	$mysql_cmd "AddUser --username=test --passwd=test --hostip=$MYSQL_PROXY_WORKER_IP"
	if [ $? != 0 ];then
		echo "add user error"
	fi
fi

####### 1.2 设置账号连接限制 #######
$mysql_cmd "SetConnLimit --username=test --port-type=rw --hostip=$MYSQL_PROXY_WORKER_IP --conn-limit=3;"

####### 2. 跑测试用例 #########
t=$(
(
(
for i in {1..3}; do
$MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest -ABs -e "select sleep(2), $i" &
done
) | sort -k2n | wc -l
) 2>&1
)

####### 3. 检车结果是否正确，设置脚本退出码 #####
r="3" #正确的结果
ret=0  #测试脚本退出码，若ret为0，标志测试成功；反之，测试失败
if [ "$t" = "$r" ]; then
  ret=0
else
  echo "expected result: \"$r\""
  echo "actual result: \"$t\""
  ret=1
fi


bash $SCRIPT_DIR/stop_proxy.sh

###### 4. 退出测试 ######
###### 测试调度脚本是通过判断，shell脚本的退出状态来判断测试用例成功与否的 #########
exit $ret
#eof
