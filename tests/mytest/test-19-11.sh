#!/bin/bash

###
### 1. 测试事务或prepare中连接被kill，客户端可以感知
### 2. 上下文恢复失败，客户端可以感知
### 3. 第一条语句是select row_count() 或 selectfound_rows() 会返回错误，客户端可以感知
### 4. 语句过长客户端可以感知
###

bash $SCRIPT_DIR/start_proxy.sh

# 事务被kill的情景测试
expect_res="ERROR 3086 (30080): connection was killed for none query execution for long time in transaction or prepare. Will drop query of this time!"
r=0
$MYSQL -h -P $MYSQL_PROXY_ADMIN_PORT -utest -ptest -ABs -e ""
# prepare被kill的情景测试

# 上下文恢复失败的情景测试

# 第一条语句是select row_count() 或 selectfound_rows() 的情景测试

# 语句过长的情景测试
# 现在默认的语句长度是64M

t=0
for i in {1..10}
do
  $MYSQL -h 127.0.0.1 -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "showusers" 1>/dev/null 2>&1
  _t=$?
  ((t=t+_t))
done
r="0"
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
