#!/bin/bash
# this is added to test bug character_set_results 可否为NULL的bug
bash $SCRIPT_DIR/start_proxy.sh


$MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest -ABs -e "set character_set_results = NULL;system sleep 1;show variables like '%set%'" 1>/dev/null 2>&1

_r=$?
ret=0
if [ "x$_r" = "x0" ]; then
  ret=0
else
  echo "expected result: 0"
  echo "actual result: \"$_r\""
  ret=1
fi


bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof