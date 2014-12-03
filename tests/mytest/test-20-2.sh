#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

$MYSQL_HOME/bin/mysqlslap -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest \
--create-schema=d2 --auto-generate-sql --iterations=1 --concurrency=100 \
--auto-generate-sql-load-type=mixed --auto-generate-sql-write-number=100

$MYSQL_HOME/bin/mysqlslap -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest \
--create-schema=d2 --auto-generate-sql --iterations=1 --concurrency=100 \
--auto-generate-sql-load-type=update --auto-generate-sql-write-number=100

#$MYSQL_HOME/bin/mysqlslap -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest \
#--create-schema=d2 --auto-generate-sql --iterations=1 --concurrency=100 \
#--auto-generate-sql-load-type=key --auto-generate-sql-unique-query-number=50

$MYSQL_HOME/bin/mysqlslap -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest \
--create-schema=d2 --auto-generate-sql --iterations=1 --concurrency=100 \
--auto-generate-sql-load-type=write --auto-generate-sql-write-number=100 --auto-generate-sql-unique-write-number=10

$MYSQL_HOME/bin/mysqlslap -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest \
--create-schema=d2 --auto-generate-sql --iterations=1 --concurrency=100 \
--auto-generate-sql-load-type=write --auto-generate-sql-write-number=100 --auto-generate-sql-unique-write-number=50 --commit=10

bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof
