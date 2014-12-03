#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

#### 测试协议级 DB上下文可被正确恢复 #######
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
my $db1 = "d1";
my $db2 = "test";
my $user = "test";
my $pass = "test";
my $host = $ENV{"MYSQL_PROXY_WORKER_IP"};
my $port = $ENV{"MYSQL_PROXY_RW_PORT"};
my $myid_sql = "select connection_id()";
my $mydb_sql = "select schema()";
my $dsn = "DBI:mysql:host=$host;port=$port";
my $dsn1 = "DBI:mysql:database=$db1;host=$host;port=$port";
my $dsn2 = "DBI:mysql:database=$db2;host=$host;port=$port";

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
my $dbh1 = DBI->connect($dsn1, $user, $pass, {'RaiseError' => 1});
my ( $mydb1 ) = $dbh1->selectrow_array($mydb_sql);
my ( $myid1 ) = $dbh1->selectrow_array($myid_sql);
print "1\t$myid1\t$mydb1\n";
Time::HiRes::usleep 15000;

# connection two
my $dbh2 = DBI->connect($dsn2, $user, $pass, {'RaiseError' => 1});
my ( $mydb2 ) = $dbh2->selectrow_array($mydb_sql);
my ( $myid2 ) = $dbh2->selectrow_array($myid_sql);
print "2\t$myid2\t$mydb2\n";
Time::HiRes::usleep 15000;

# connection one again
my ( $mydb3 ) = $dbh1->selectrow_array($mydb_sql);
my ( $myid3 ) = $dbh1->selectrow_array($myid_sql);
print "1\t$myid3\t$mydb3\n";

my $ret = ($mydb1 eq "d1") ? ( ($mydb1 eq $mydb3) ? 0 : 1 ) : 1;
$dbh1->disconnect();
$dbh2->disconnect();
if ($ret == 0) {
  print "context restored\n";
} else {
  print "context not restored\n";
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
