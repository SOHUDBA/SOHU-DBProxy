#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

#### 测试语句级字符集上下文恢复 #######
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

# connection one
my $dbh1 = DBI->connect($dsn, $user, $pass, {'RaiseError' => 1});
$dbh1->do("set character_set_client=gbk");
$dbh1->do("set character_set_connection=gbk");
$dbh1->do("set character_set_results=gbk");
my ( $varname11, $my_char_cli1 ) = $dbh1->selectrow_array($my_char_cli_sql);
my ( $varname12, $my_char_con1 ) = $dbh1->selectrow_array($my_char_con_sql);
my ( $varname13, $my_char_res1 ) = $dbh1->selectrow_array($my_char_res_sql);
my ( $myid1 ) = $dbh1->selectrow_array($myid_sql);
print "1\t$myid1\t$my_char_cli1\t$my_char_con1\t$my_char_res1\n";
Time::HiRes::usleep 15000;

# connection two
my $dbh2 = DBI->connect($dsn, $user, $pass, {'RaiseError' => 1});
$dbh2->do("set character_set_client=utf8");
$dbh2->do("set character_set_connection=utf8");
$dbh2->do("set character_set_results=utf8");
my ( $varname21, $my_char_cli2 ) = $dbh2->selectrow_array($my_char_cli_sql);
my ( $varname22, $my_char_con2 ) = $dbh2->selectrow_array($my_char_con_sql);
my ( $varname23, $my_char_res2 ) = $dbh2->selectrow_array($my_char_res_sql);
my ( $myid2 ) = $dbh2->selectrow_array($myid_sql);
print "2\t$myid2\t$my_char_cli2\t$my_char_con2\t$my_char_res2\n";
Time::HiRes::usleep 15000;

# connection one again
$dbh1->do("select 1");
my ( $varname31, $my_char_cli3 ) = $dbh1->selectrow_array($my_char_cli_sql);
my ( $varname32, $my_char_con3 ) = $dbh1->selectrow_array($my_char_con_sql);
my ( $varname33, $my_char_res3 ) = $dbh1->selectrow_array($my_char_res_sql);
my ( $myid3 ) = $dbh1->selectrow_array($myid_sql);
print "1\t$myid3\t$my_char_cli3\t$my_char_con3\t$my_char_res3\n";

$dbh1->disconnect();
$dbh2->disconnect();

my $ret = 1;
$ret = ($my_char_cli1 eq $my_char_cli3) ? 0 : 1;
$ret = ($my_char_con1 eq $my_char_con3) ? 0 : 1;
$ret = ($my_char_res1 eq $my_char_res3) ? 0 : 1;
if ($ret == 0) {
  print "charset restored\n";
} else {
  print "charset not restored\n";
}
exit($ret);
EOF
) 2>&1
)
ret=$?
if ((ret != 0)); then
  echo "actual result: \"$t\""
fi

bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof

