#!/bin/bash

if [ "$AUTO_START" = "N" ]; then
  exit 0
fi

if [ "$START_TYPE" = "dev" ]; then
  for f in $MYSQL_PROXY_HOME/plugins/{proxy,admin}/.libs/lib*.so; do
    cp -f $f $MYSQL_PROXY_HOME/plugins/
  done
  PLUGIN_DIR=$MYSQL_PROXY_HOME/plugins/
elif [ "$START_TYPE" = "prod" ]; then
  PLUGIN_DIR=$MYSQL_PROXY_HOME/lib/mysql-proxy/plugins/
fi

if [ "$MYSQL_PROXY_MULTIPLEX" = "N" ]; then
  MYSQL_PROXY_FLAG_MULTIPLEX="--proxy-connect-no-multiplex"
else
  MYSQL_PROXY_FLAG_MULTIPLEX=""
fi

MYSQL_PROXY_LOG=$MYSQL_PROXY_HOME/proxy.log
MYSQL_PROXY_OUT=$MYSQL_PROXY_HOME/proxy.out
> $MYSQL_PROXY_LOG

BACKENDS=$(
for MP_BK in $MYSQL_PROXY_RW_BACKEND; do
  echo " --proxy-backend-addresses=$MP_BK "
done
for MP_BK in $MYSQL_PROXY_RO_BACKEND; do
  echo " --proxy-read-only-backend-addresses=$MP_BK "
done
)
CMD="
$MYSQL_PROXY
--pid-file=$MYSQL_PROXY_PID_FILE
--plugin-dir=$PLUGIN_DIR
--plugins=proxy
--rw-address=0.0.0.0:$MYSQL_PROXY_RW_PORT
--ro-address=0.0.0.0:$MYSQL_PROXY_RO_PORT
--plugins=admin
--admin-address=127.0.0.1:$MYSQL_PROXY_ADMIN_PORT
--admin-password=adtest
--admin-username=adtest
--log-level=debug
--log-file=$MYSQL_PROXY_LOG
--proxy-rw-load-balance-algorithm=$MYSQL_PROXY_RW_LB
--proxy-ro-load-balance-algorithm=$MYSQL_PROXY_RO_LB
--event-threads=4
--config-xml=$MYSQL_PROXY_CONFIG_FILE
--dbproxy-collation=utf8_general_ci
"

if [ "$RUNNING_ON_VALGRIND" = "Y" ]; then
  V="--tool=memcheck --leak-check=full --show-reachable=yes -v"
  V="--tool=memcheck --leak-check=full -v"
  G_SLICE=always-malloc G_DEBUG=gc-friendly \
  valgrind $V $CMD --running-on-valgrind >$MYSQL_PROXY_OUT 2>&1 &
  CHILD_PID=$$
else
  $CMD >$MYSQL_PROXY_OUT 2>&1 &
  CHILD_PID=$$
fi


STARTED=0
if [ -n "$MYSQL_PROXY_START_NO_WAIT" ]; then
  echo "start proxy $CHILD_PID"
else
  echo -n "start proxy $CHILD_PID "
  for ((i=0; i<=20; i++)); do
    if head -n2000 $MYSQL_PROXY_LOG | grep -q "DBProxy Server is ready for accepting client's request."; then
      STARTED=1
      break
    fi
    sleep 1
    echo -n "."
  done
  if [ $STARTED = 0 ]; then
    echo " fail"
  else
    echo " ok"
  fi
fi
sleep 1
