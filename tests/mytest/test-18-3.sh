#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh
### 该测试用例实现对处于prepare中空闲连接超时的处理 ######
### 需要连接复用开启

### 1. 预置条件 ######
mysql_cmd="$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e"
set_sql="SetMultiplexSwitch --flag=on"
$mysql_cmd "$set_sql"
_r=$?
if [ $_r != 0 ];then
	echo "set Multiplex on error"
	exit 1
fi
### 2. 开始测试 #######
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
my $query1 = "PREPARE statement_1 FROM 'select 1'";
my $query2 = "select 1";
my $ret = 0;
my $dsn = "DBI:mysql:database=$db;host=$host;port=$port";
my $dbh_t0;
# init pool
eval {
        $dbh_t0 = DBI->connect($dsn, $user, $pass, {'RaiseError' => 0});
        $dbh_t0->do($query1);
        # sleep 足够长的时间
        Time::HiRes::usleep 60000000;
        $dbh_t0->do($query2) || die $dbh_t0->errstr;
};
if ($@) {
        #if ("$@" eq "DBD::mysql::db do failed: ERROR 3086 (30080): connection was killed for none query execution for long time in transaction or prepare. Will drop query of this time!")
        #{
        #       $ret = 0;
        #}
        #else 
        #{
        #       $ret = 1;
        print $@;
        #}
}
$dbh_t0->disconnect();

#if ($ret == 0) {
#  print "connection reused\n";
#} else {
#  print "connection not reused\n";
#}
exit($ret);
EOF
) 2>/dev/null
)
#### 3。对比测试结果 #########
if [[ X"$t" == X"connection was killed for none query execution for long time in transaction or prepare. Will drop query of this time"* ]];then
        ret=0
else
        ret=1
fi

if ((ret != 0)); then
  echo "actual result: \"$t\""
fi

bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof
