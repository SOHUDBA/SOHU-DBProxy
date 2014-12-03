#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

#### 测试协议级字符集上下文恢复 #######
#### 测试预置条件： 连接复用开启，用户连接限制数 >=2 ######
#### 1 设置预设条件 ######

#### 1.1 开启连接复用 #####
mysql_cmd="$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e"
set_sql="SetMultiplexSwitch --flag=on"
$mysql_cmd "$set_sql"
_r=$?
if [ $_r != 0 ];then
	echo "set Multiplex on error"
	exit 1
fi

### 1.2 添加用户 #####
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

### 1.3 设置账号连接限制 #######
$mysql_cmd "SetConnLimit --username=test --port-type=rw --hostip=$MYSQL_PROXY_WORKER_IP --conn-limit=0;"


t=$(
(
perl <<'EOF'
#!perl -w
use strict;
use warnings;
use DBI;
use DBD::mysql;
use Time::HiRes;
my $db = "d1";
my $user = "test";
my $pass = "test";
my $host = $ENV{"MYSQL_PROXY_WORKER_IP"};
my $port = $ENV{"MYSQL_PROXY_RW_PORT"};
my $myid_sql = "select connection_id()";
my $my_char_cli_sql = "show variables like 'character_set_client'";
my $my_char_con_sql = "show variables like 'character_set_connection'";
my $my_char_res_sql = "show variables like 'character_set_results'";
my $dsn = "DBI:mysql:host=$host;port=$port";

# init pool
my $dbh_t0 = DBI->connect($dsn, $user, $pass, {'RaiseError' => 1});
$dbh_t0->do("set autocommit=0");
my ( $myid ) = $dbh_t0->selectrow_array($myid_sql);
my $ids_sql="select id from information_schema.processlist where user='$user'";
my $prc_sql="select count(*) from information_schema.processlist where user='$user'";
my $ids = $dbh_t0->selectall_arrayref($ids_sql, {Slice => {}});
print "my thread id $myid\n";
#foreach my $id (@$ids) {
#  my $real_id = $id->{id};
#  if ($real_id != $myid) {
#    print "kill thread id $real_id\n";
#    $dbh_t0->do("kill $real_id");
#  }
#}
#my ( $count ) = $dbh_t0->selectrow_array($prc_sql);
#$dbh_t0->disconnect();
#($count == 1) or die print("pool size bigger than 1!\n");
EOF

A="select 'thread_id', connection_id();
show variables where variable_name in
 ('character_set_client'
 ,'character_set_connection'
 ,'character_set_results')
"
R1=$($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest \
--default-character-set=gbk -ABs -e "$A" 2>&1)
sleep 0.1
R2=$($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest \
--default-character-set=utf8 -ABs -e "$A" 2>&1)
sleep 0.1
R3=$($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test  -ptest \
--default-character-set=gbk -ABs -e "$A" 2>&1)

echo "$R1"
echo "$R2"
echo "$R3"

R1_thr=$(echo "$R1"|grep "^thread_id"|awk '{print $2}')
R1_cli=$(echo "$R1"|grep "^character_set_client"|awk '{print $2}')
R1_con=$(echo "$R1"|grep "^character_set_connection"|awk '{print $2}')
R1_res=$(echo "$R1"|grep "^character_set_results"|awk '{print $2}')

R2_thr=$(echo "$R2"|grep "^thread_id"|awk '{print $2}')
R2_cli=$(echo "$R2"|grep "^character_set_client"|awk '{print $2}')
R2_con=$(echo "$R2"|grep "^character_set_connection"|awk '{print $2}')
R2_res=$(echo "$R2"|grep "^character_set_results"|awk '{print $2}')

R3_thr=$(echo "$R3"|grep "^thread_id"|awk '{print $2}')
R3_cli=$(echo "$R3"|grep "^character_set_client"|awk '{print $2}')
R3_con=$(echo "$R3"|grep "^character_set_connection"|awk '{print $2}')
R3_res=$(echo "$R3"|grep "^character_set_results"|awk '{print $2}')

#if [ "$R1_thr" != "$R2_thr" -o "$R1_thr" != "$R3_thr" ]; then
#  echo "thread id changed"
#  exit 1
#fi

if [ "$R1_cli" == "$R2_cli" -o "$R1_cli" != "$R3_cli" ]; then
  echo "character_set_client changed"
  exit 1
fi

if [ "$R1_con" == "$R2_con" -o "$R1_con" != "$R3_con" ]; then
  echo "character_set_connection changed"
  exit 1
fi

if [ "$R1_res" == "$R2_res" -o "$R1_res" != "$R3_res" ]; then
  echo "character_set_results changed"
  exit 1
fi

exit 0
) 2>&1
)
ret=$?
if ((ret != 0)); then
  echo "actual result: \"$t\""
fi

bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof
