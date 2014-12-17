#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

t=0
for i in {1..1000}
do
  $MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u$MYSQL_PROXY_ADMIN_USER -p$MYSQL_PROXY_ADMIN_PASSWD -ABs -e "showbackends" 1>/dev/null 2>&1
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
