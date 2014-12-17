#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

###### 连接1prepare(语句级)超时，连接不复用，超时连接关闭，新建连接 #######
#### 这个已经在test-18-3.sh中测试了 ######
#### 预设条件：连接服用开启，用户连接线指数大于等于2
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
my $query = "select connection_id()";
my $dsn = "DBI:mysql:database=$db;host=$host;port=$port";

# init pool
my $dbh_t0 = DBI->connect($dsn, $user, $pass, {'RaiseError' => 1});
my $count = 1;
for (my $j=0; $j<3; $j++) {
  my $prc_sql="select count(*) from information_schema.processlist where user='$user'";
  ( $count ) = $dbh_t0->selectrow_array($prc_sql);
  if ($count <= 1) {
    print("pool size must be 2 connections at least\n");
    my $dbh_t1 = DBI->connect($dsn, $user, $pass, {'RaiseError' => 1});
     $dbh_t1->do("select 1");
    $dbh_t1->disconnect();
  } else {
    last;
  }
}
$dbh_t0->disconnect();
($count > 1) or die print("pool size less than 2!\n");

# connection one
my $dbh1 = DBI->connect($dsn, $user, $pass, {'RaiseError' => 1});
$dbh1->do("prepare s1 from 'select 1'");
my ( $id1 ) = $dbh1->selectrow_array($query);
print "1\t$id1\n";
Time::HiRes::usleep 21000000;

# connection two
my $dbh2 = DBI->connect($dsn, $user, $pass, {'RaiseError' => 1});
my $query2 = "select count(*) from information_schema.processlist
 where user='$user' and id=$id1";
my ( $id1_cnt ) = $dbh2->selectrow_array($query2);
if ($id1_cnt != 0) {
  print "connection 1 is not timeout\n";
  exit 1;
} else {
  print "connection 1 is timeout\n";
}

my $ret=1;
for (my $i = 0; $i < 10; $i++)
{
  my ( $id2 ) = $dbh2->selectrow_array($query);
  print "2\t$id2\n";
  Time::HiRes::usleep 15000;
  if ($id2 == $id1)
  {
    $ret=0;
    last;
  }
}

#$dbh1->do("deallocate prepare s1");
$dbh1->disconnect();
$dbh2->disconnect();
if ($ret == 0) {
  print "connection reused\n";
} else {
  print "connection not reused\n";
}
exit(!$ret);
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
