#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH
PROGNAME0="dbproxy_backend_keepalive"
VERSION=1.0.0
DIR=$(dirname $0)
LOGDIR=/var/log/keepalived
CURRENT_DATE=$(date '+%Y%m%d')
LOG=$LOGDIR/${PROGNAME0}-${CURRENT_DATE}.log
exec 3>&1 4>&2 >>$LOG 2>&1
if ! ps -ef | grep -v grep | grep -q "/dbproxy_backend.sh"; then
  echo "$(date '+%Y-%m-%d %H:%M:%S.%N') dbproxy_backend.sh is not running"
  $DIR/dbproxy_backend.sh "$@" </dev/null &
else
  echo "$(date '+%Y-%m-%d %H:%M:%S.%N') dbproxy_backend.sh is running"
fi
exec 1>&3 3>&- 2>&4 4>&-
#EOF
