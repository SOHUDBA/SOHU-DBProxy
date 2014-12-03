#!/bin/bash

MYSQL_PROXY_RO_LB=lc bash $SCRIPT_DIR/start_proxy.sh

#### 读端口最小连接数负载均衡压力测试 #######
#### 用户连接限制数 没有限制  ######
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
$mysql_cmd "SetConnLimit --username=test --port-type=ro --hostip=$MYSQL_PROXY_WORKER_IP --conn-limit=0;"
### 1.3 设置连接池的大小
$mysql_cmd "SetPoolConfig --username=test --port-type=ro --max-conn=2000 --min-conn=100 --save-option=mem"

t=$(
(
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
my $port = $ENV{"MYSQL_PROXY_RO_PORT"};
my $my_sql = "show variables like 'wsrep_node_address'";
my $dsn = "DBI:mysql:host=$host;port=$port";

my @childs;
for ( my $count = 1; $count <= 20; $count++) {
  my $pid = fork();
  if ($pid) {
    # parent
    print "pid is $pid, parent $$\n";
    push(@childs, $pid);
  } elsif ($pid == 0) {
    # child
    &sub1;
    exit 0;
  } else {
    die "couldnt fork: $!\n";
  }
}
foreach (@childs) {
  my $tmp = waitpid($_, 0);
  print "done with pid $tmp\n";
}

sub sub1 {
  my $dbh1 = DBI->connect($dsn, $user, $pass, {'RaiseError' => 1});
  sleep(2);
  for (my $i = 0; $i < 500; $i++ )
  {
    my ( $key, $value ) = $dbh1->selectrow_array($my_sql);
    print STDERR "backend=$value\n";
    Time::HiRes::usleep 15000;
  }
  $dbh1->disconnect();
}

EOF
) 2>&1 | grep "^backend=" | sort | uniq -c
) 2>&1
)
declare -i t_1_no=0
declare -i t_2_no=0
t_1_no=$(echo "$t" | grep "X.X.X.X:5020" | awk '{print $1}')
t_2_no=$(echo "$t" | grep "X.X.X.X:5030" | awk '{print $1}')
if (( ( t_1_no + t_2_no == 10000 ) && ( t_1_no <= 5500 || t_1_no >= 4500 ) && ( t_2_no <= 5500 || t_2_no >= 4500 ) )); then
    ret=0
else
  echo "actual result: \"$t\""
  ret=1
fi


bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof

