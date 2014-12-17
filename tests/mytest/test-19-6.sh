#!/bin/bash
exit 0
bash $SCRIPT_DIR/start_proxy.sh

t=0
for i in {1..100}
do
  for j in {1..20}
  do
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest -ABs -e "select * from d1.t1 limit 1;" 1>/dev/null 2>&1)&
  done
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e "addbackends" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e "addbackends --backend" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e "addbackends --backend=X.X.X.X:3401" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e "addbackends --backend=X.X.X.X:3401 --bktype=rw" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e "setbkoffline --backend=X.X.X.X:3402" 1>/dev/null 2>&1)
  sleep 1
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e "setbkonline --backend=X.X.X.X:3402" 1>/dev/null 2>&1)
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
