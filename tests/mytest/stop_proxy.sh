#!/bin/bash

if [ "$AUTO_START" = "N" ]; then
  exit 0
fi

count_of_pid()
{
  declare _pid=$1
  declare _count
  _count=$(ps -ef|awk '{if($2=="'"$_pid"'") print $2}'|wc -l)
  if [ -z "$_count" ]; then
    _count=0
  fi
  echo "$_count"
}
check_and_kill_pid()
{
  declare _pid=$1
  declare _retry=$2
  declare _i=0
  for (( i=0; i<$_retry; i++)); do
    if [ $(count_of_pid $_pid) != "0" ]; then
      kill $_pid
      sleep 1
    else
      return 0
    fi 
  done
  return 1
}
check_and_kill_pid_force()
{
  declare _pid=$1
  declare _retry=$2
  if ! check_and_kill_pid $_pid $_retry; then
    kill -9 $_pid
  fi 
}

declare -a array_pid=($(cat $MYSQL_PROXY_PID_FILE))
declare -i array_len=${#array_pid[@]}

#kill process
for (( i=0; i<${array_len}; i++ )); do
  pid=${array_pid[$i]}
  echo -n "stop proxy $pid "
  kill $pid
done

#check if process exists, kill it if necessary
for (( i=0; i<${array_len}; i++ )); do
  pid=${array_pid[$i]}
  echo -n "."
  check_and_kill_pid_force $pid 3
  echo " done"
done

#clean pid file
>$MYSQL_PROXY_PID_FILE

for f in $MYSQL_PROXY_HOME/plugins/{proxy,admin}/.libs/lib*.so; do
  rm -f $MYSQL_PROXY_HOME/plugins/$f
done

#eof
