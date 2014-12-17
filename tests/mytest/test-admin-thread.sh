#!/bin/bash

MYSQL=mysql
MYSQL_PROXY_ADMIN_PORT=8888
LOG_FILE=/DATA/work/fanzhen/proxy.log
loop_count=100
sed '/"using thread"/d' $LOG_FILE > $LOG_FILE
for ((i=1;i<=$loop_count;i++)); do
  $MYSQL -h 127.0.0.1 -P $MYSQL_PROXY_ADMIN_PORT -uadtest -padtest -ABs -e "proxyhelp;showusers;" &
done >/dev/null
wait
cat $LOG_FILE |grep "using thread"|awk '
BEGIN{str="";error_count=0} {
  if (NR==1) {
    str=$NF
  } else { 
	  if (str!=$NF){error_count++} 
	}
}
END {
  printf("admin thread_name is %s\n", str)
  if(error_count!=0) {print "testcase failed"}
  else {print "testcase passed"}
}'

#eof
