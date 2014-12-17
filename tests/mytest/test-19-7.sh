#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

t=0
for i in {1..100}
do
  for j in {1..20}
  do
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest -ABs -e "select * from d1.t1 limit 1;" 1>/dev/null 2>&1)&
  done
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "adduser" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "adduser --username=root" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "adduser --username=root --passwd=root" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "adduser --username=root --passwd=root --hsotip=11111111" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "showusers" 1>/dev/null 2>&1)&
  #($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "adduser --username=proxytemp --passwd=proxytemp --hostip=X.X.X.X" 1>/dev/null 2>&1)&
  #($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "deluser --username=proxytemp" 1>/dev/null 2>&1)&
  _t=$?
  ((t=t+_t))
done
wait
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
