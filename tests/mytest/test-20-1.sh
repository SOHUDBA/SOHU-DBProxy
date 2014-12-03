#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

time ( for i in {1..20000}; do $MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest -ABs -e "show variables like 'wsrep_node_address'" & done; ) | sort | uniq -c
time ( for i in {1..20000}; do $MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RO_PORT -u test -ptest -ABs -e "show variables like 'wsrep_node_address'" & done; ) | sort | uniq -c

bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof
