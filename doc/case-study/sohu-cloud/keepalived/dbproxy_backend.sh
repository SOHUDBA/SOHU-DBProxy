#!/bin/bash


## Convenience Variables

PROGNAME="dbproxy_backend.sh"
PROGNAME0="dbproxy_backend"
VERSION=1.0.0
DIR=$(dirname $0)
LOGDIR=/var/log/keepalived
CURRENT_DATE=$(date '+%Y%m%d')
LOG=$LOGDIR/${PROGNAME0}-${CURRENT_DATE}.log
declare -i log_seq=0
declare -i log_level=2
declare -ir LOG_LEVEL_DEBUG=3
declare -ir LOG_LEVEL_MESSAGE=2
declare -ir LOG_LEVEL_ERROR=1

declare -ri MIN_DISK_FREE_SPACE_KB=$((20*1024))
declare -ri MAX_RETETION_DAYS_FOR_LOG=30


##
# "UserKnownHostsFile=/dev/null" is not needed
# @notice ConnectTimeout should far less than checking script's interval
SSH="ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 -n"
KEEPALIVED_CONF=/etc/keepalived/keepalived.conf



## Convenience Functions

##### 日志 #####
##
# 初始化日志
# 操作：检查磁盘空间，删除历史日志
# @return 1 失败
logger_init() {
  declare -i avaiKB=0
  declare f
  [ ! -d "$LOGDIR" ] && mkdir -p "$LOGDIR"
  avaiKB=$(df -kP "$LOGDIR" | tail -n 1 | awk '{print $4}')
  if (( avaiKB <= MIN_DISK_FREE_SPACE_KB )); then
    logger_error "available disk space is insufficient. $avaiKB"
    return 1
  fi
  find $LOGDIR -maxdepth 1 -type f -name "${PROGNAME0}-????????.log" -mtime +$MAX_RETETION_DAYS_FOR_LOG -print | \
  while read f; do
    logger_message "delete $f"
  done
  true
}

##
# echo with timestamp, functionality names...
# @param $@ text strings to echo
logger() {
  declare _level=$1
  shift
  ((log_seq++))
  if ((log_seq >= 10000)); then
    log_seq=0
  fi
  declare _hex=$(printf "%x" "$log_seq")
  declare s
  while IFS='' read -r s; do
    echo "$(date '+%Y-%m-%d %H:%M:%S.%N') [${BASH_SOURCE[1]##*/}:${BASH_LINENO[1]}:${FUNCNAME[2]} $$:${_hex}] $_level: $s"
  done <<<"$@"
}

logger_debug() {
  if ((log_level>=LOG_LEVEL_DEBUG)); then
    logger "DEBUG" "$@"
  fi
}
logger_message() {
  if ((log_level>=LOG_LEVEL_MESSAGE)); then
    logger "MESSAGE" "$@"
  fi
}
logger_error() {
  if ((log_level>=LOG_LEVEL_ERROR)); then
    logger "ERROR" "$@"
  fi
}


usage()
{
  cat <<EOF
Usage: $PROGNAME --verb=VERB OPTIONS ...
  --verb={watch}

watch:
  --verb=watch
  --vi=VRRP_INSTANCE | --vip=VIRTUAL_IP_ADDRESS
  --mphome=MYSQL-PROXY_HOME Optional. /opt/sohu/dbproxy by default
  --if=INTERFACE_DEV Optional.
  --gw=GATEWAY_ADDRESS Optional.

EOF
}



##### 缺省值 #####
##
# 根据vip设置vi缺省值
opt_set_default_get_vi_by_vip()
{
  declare -r _vip=$1
  declare _vi
  declare _vip_last
  _vip_last=$(echo "$_vip" | awk -F. '{print $4}')
  _vi="vi_dbproxy_${_vip_last}"
  echo "$_vi"
}

##
# 根据vi取得vip缺省值
opt_set_default_get_vip_by_vi()
{
  declare -r _vi=$1
  declare _vip
  _vip=$(
  sed '/^[[:space:]]*#/d' $KEEPALIVED_CONF | \
  awk '
{
  if ($0 ~ /^[[:space:]]*vrrp_instance[[:space:]]+'"$_vi"'[[:space:]]*{[[:space:]]*$/) {
    I=1;
    while (I>0) {
      getline
      if ($0 ~ /}/) I--
      if ($0 ~ /{/) I++
      if ($0 ~ /^[[:space:]]*virtual_ipaddress[[:space:]]*{[[:space:]]*$/) {
        J=1;
        while (J>0) {
          getline
          if ($0 ~ /}/) {I--;J--}
          if ($0 ~ /{/) {I++;J++}
          if (J==1) {
            print $1
          }
        }
      }
    }
  }
}
' | head -n1)
  echo "$_vip"
}

##
# 设置mphome缺省值
opt_set_default_get_mphome()
{
  echo "/opt/sohu/dbproxy"
}

##
# 设置if缺省值
opt_set_default_get_if()
{
  declare _if
  _if=$(ip -4 -o link show | awk '$9=="UP"{print $2}' | head -n1)
  _if=${_if%:}
  echo "$_if"
}
opt_set_default_get_if_by_vi()
{
  declare -r _vi=$1
  declare _if
  _if=$(
  sed '/^[[:space:]]*#/d' $KEEPALIVED_CONF | \
  awk '
{
  if ($0 ~ /^[[:space:]]*vrrp_instance[[:space:]]+'"$_vi"'[[:space:]]*{[[:space:]]*$/) {
    I=1;
    while (I>0) {
      getline
      if ($0 ~ /}/) I--
      if ($0 ~ /{/) I++
      if ($0 ~ /^[[:space:]]*interface[[:space:]]+/) {
        print $2
      }
    }
  }
}
')
  echo "$_if"
}

##
# 设置gw缺省值
opt_set_default_get_gw_by_if()
{
  declare -r _if="$1"
  declare _gw
  if [ -n "$_if" ]; then
    _gw=$(ip -4 route list dev "$_if" | awk '/^default / {print $3}')
  else
    _gw=$(ip -4 route list default | awk '/^default / {print $3}')
  fi
  echo "$_gw"
}


##
# 设置选项的缺省值
opt_set_default()
{
  if [ -z "$opt_vi" -a -n "$opt_vip" ]; then
    opt_vi=$(opt_set_default_get_vi_by_vip "$opt_vip")
  fi

  if [ -n "$opt_vi" -a -z "$opt_vip" ]; then
    opt_vip=$(opt_set_default_get_vip_by_vi "$opt_vi")
  fi

  if [ -z "$opt_mphome" ]; then
    opt_mphome=$(opt_set_default_get_mphome)
  fi

  if [ -z "$opt_if" ]; then
    opt_if=$(opt_set_default_get_if_by_vi "$opt_vi")
  fi

  if [ -z "$opt_gw" ]; then
    opt_gw=$(opt_set_default_get_gw_by_if "$opt_if")
  fi

  return
}



##### 检查 #####
opt_sanity_check_validation_vi()
{
  declare _vi=$1
  if [[ ! ( $_vi =~ ^vi_dbproxy_[[:digit:]]+$ ) ]]; then
    return 1
  fi
}

opt_sanity_check_validation_verb()
{
  declare _verb=$1
  case "$_verb" in
    watch) ;;
    testcase) ;;
    *) return 1 ;;
  esac
  return 0
}


##
# 检查vip和vi是否匹配
# 操作：检查vip和vi最后一位字段是否一致
# @return 0 匹配
# @return !0 不匹配
opt_sanity_check_vip_vi_matchable()
{
  declare -r _vip=$1
  declare -r _vi=$2
  declare _vip_last
  declare _vi_last
  _vip_last=$(echo "$_vip" | awk -F. '{print $4}')
  _vi_last=$(echo "$_vi" | awk -F_ '{print $3}')
  if [ "$_vip_last" != "$_vi_last" ]; then
    return 1
  fi
}

opt_sanity_check_existence_vi()
{
  declare _vi=$1
  if ! grep -q '^[[:space:]]*vrrp_instance[[:space:]]\+'"${_vi}"'[[:space:]]*{[[:space:]]*$' $KEEPALIVED_CONF; then
    return 1
  fi
}

opt_sanity_check_existence_vip_by_vi()
{
  declare _vip=$1
  declare _vi=$2
  if ! opt_set_default_get_vip_by_vi "$_vi" | grep -q "$_vip"; then
    return 1
  fi
}

opt_sanity_check_existence_mphome()
{
  declare _mphome=$1
  if [ ! -d "$_mphome" ]; then
    return 1
  fi
}

opt_sanity_check_existence_if()
{
  declare _if=$1
  if ! ip -4 -o link show | awk '{print $2}' | grep -q "${_if}:"; then
    return 1
  fi
}

opt_sanity_check_existence_gw()
{
  declare _gw=$1
  return 0
}

##
# 检查命令行输入的选项是否正确
opt_sanity_check()
{
  declare -i invalid_opt=0
  declare -i error_opt=0

  #检查参数是否合法
  if [ -z "$opt_vi" -a -z "$opt_vip" ]; then
    logger_error "--vi or --vip not specified"
    invalid_opt=1
  fi
  if [ -z "$opt_verb" ]; then
    logger_error "--verb not specified"
    invalid_opt=1
  fi

  if ! opt_sanity_check_validation_vi "$opt_vi"; then
    logger_error "--vi is invalid: $opt_vi"
    invalid_opt=1
  fi

  if ! opt_sanity_check_validation_verb "$opt_verb"; then
    logger_error "--verb is invalid: $opt_verb"
    invalid_opt=1
  fi
  if [ -z "$opt_if" ]; then
    logger_error "--if is invalid: $opt_if"
    invalid_opt=1
  fi

  if [ $invalid_opt -ne 0 ]; then
    return $invalid_opt
  fi

  #检查参数值是否存在
  if ! opt_sanity_check_vip_vi_matchable "$opt_vip" "$opt_vi"; then
    logger_error "vip and vi is not matchable: $opt_vip $opt_vi"
    error_opt=1
  fi

  if ! opt_sanity_check_existence_vi "$opt_vi"; then
    logger_error "vi not exist: $opt_vi"
    error_opt=1
  fi
  if ! opt_sanity_check_existence_vip_by_vi "$opt_vip" "$opt_vi"; then
    logger_error "vip not exist: $opt_vip"
    error_opt=1
  fi

  if ! opt_sanity_check_existence_mphome "$opt_mphome"; then
    logger_error "mphome not exist: $opt_mphome"
    error_opt=1
  fi

  if ! opt_sanity_check_existence_gw "$opt_gw"; then
    logger_error "gw not exist: $opt_gw"
    error_opt=1
  fi

  if [ $error_opt -ne 0 ]; then
    return $error_opt
  fi

  return 0
}



##### 和高可用相关的操作 #####
##
# 检查进程号是否存在
# @param $1 进程号
# @return 0 存在
# @return !0 不存在
isRunning() {
  #ps -ef | awk '$2=="'"$1"'"'
  kill -s 0 "$1" 2>/dev/null
}

##
# 检查IP地址是否存在
# @param $1 IP地址
# @return 0 存在 
# @return !0 不存在
hasIPAddress() {
  ip -o a s | grep -w "$1" >/dev/null 2>&1
}

##
# 检查虚IP是否有效
# 操作：通过虚IP地址ping网关
# @param $1 网关地址
# @param $2 虚IP地址
# @return 0 成功
# @return !0 失败
ping_gw_by_vip()
{
  declare -r _gw=$1
  declare -r _vip=$2
  declare -i _rc
  declare _ping_out
  _ping_out=$( ping -I $_vip -n -q -W 2 -c 2 $_gw 2>&1 )
  _rc=$?
  if ((_rc!=0)); then
    logger_message "ping: $_rc \"$_ping_out\""
  fi
  return $_rc
}


##
# 检查DBProxy连通性
check_dbproxy_connect()
{
  logger_debug "${FUNCNAME[0]}()"
  declare _result
  _result=$( mysql --host="$MP_ADMIN_IP" --port="$MP_ADMIN_PORT" --user="$MP_ADMIN_USER" --password="$MP_ADMIN_PWD" -ABs -e "" 2>&1 )
  if (($? != 0)); then
    logger_error "dbproxy connect error: ${MP_ADMIN_USER}@${MP_ADMIN_IP}:${MP_ADMIN_PORT}: $_result"
    return 1
  fi
  logger_debug "dbproxy connect ok: ${MP_ADMIN_USER}@${MP_ADMIN_IP}:${MP_ADMIN_PORT}"
  return 0
}
##
# 检查SSH连通性
check_ssh_connect()
{
  logger_debug "${FUNCNAME[0]}()"
  declare -r _address=$1
  declare _ip
  declare _result
  _ip=${_address%:*}
  _result=$( $SSH root@$_ip ":" 2>&1 )
  if (($? != 0)); then
    logger_error "ssh connect error: root@${_ip}: $_result"
    return 1
  fi
  logger_debug "ssh connect ok: root@${_ip}"
  return 0
}
##
# 检查MySQL连通性
check_mysql_connect()
{
  logger_debug "${FUNCNAME[0]}()"
  declare -r _address=$1
  declare _ip
  declare _port
  declare _result
  _ip=${_address%:*}
  _port=${_address#*:}
  _result=$( $SSH root@$_ip "mysql --host=127.0.0.1 --port=$_port --user=root -e ''" 2>&1 )
  if (($? != 0)); then
    logger_error "mysql connect error: root@${_address}: $_result"
    return 1
  fi
  logger_debug "mysql connect ok: root@${_address}"
  return 0
}



##
# 取得DBProxy参数
proxy_conf()
{
  declare -r _cnf_file=$opt_mphome/etc/mysql-proxy.cnf
  if [ ! -r "$_cnf_file" ]; then
    logger_error "cnf not found: $_cnf_file"
    return 1
  fi
  MP_ADMIN_ADDRESS=$(sed -n '/^admin-address=/s/^admin-address=//p' $_cnf_file)
  MP_ADMIN_IP=${MP_ADMIN_ADDRESS%:*}
  MP_ADMIN_PORT=${MP_ADMIN_ADDRESS#*:}
  MP_ADMIN_USER=$(sed -n '/^admin-username=/s/^admin-username=//p' $_cnf_file)
  MP_ADMIN_PWD=$(sed -n '/^admin-password=/s/^admin-password=//p' $_cnf_file)
  if [ -n "$MP_ADMIN_IP" -a -n "$MP_ADMIN_PORT" -a -n "$MP_ADMIN_USER" -a -n "$MP_ADMIN_PWD" ]; then
    return 0
  else
    logger_error "dbproxy cnf: ip=$MP_ADMIN_IP port=$MP_ADMIN_PORT user=$MP_ADMIN_USER pwd=$MP_ADMIN_PWD"
    return 1
  fi
}




##
# 设置数据库读写或者只读
# 通过SSH远程登录，连接本地数据库，因此需要SSH自动登录和root@127.0.0.1的权限
#
set_read_only()
{
  logger_debug "${FUNCNAME[0]}()"
  declare -r _address=$1
  declare -r _read_only=$2
  declare _read_only_flag=1
  declare _result
  declare _before_read_only
  declare _before_read_only_flag
  declare _after_read_only
  declare _after_read_only_flag
  declare _ip
  declare _port

  _ip=${_address%:*}
  _port=${_address##*:}
  case "$_read_only" in
    on|ON|1|ro|RO) _read_only_flag=1 ;;
    off|OFF|0|rw|RW) _read_only_flag=0 ;;
    *) logger_error "set default _read_only_flag=1"; _read_only_flag=1 ;;
  esac

  # 查看当前read_only状态，如果没变化，直接返回
  _result=$( $SSH root@$_ip "mysql --host=127.0.0.1 --port=$_port --user=root -e \"show global variables like 'read_only'\"" 2>&1 )
  if (($?!=0)); then
    logger_error "read before read_only error: address=$_address: $_result"
    return 1
  fi
  _before_read_only=$(awk '$1=="read_only"{print $2}' <<<"$_result")
  case "$_before_read_only" in
    on|ON|1) _before_read_only_flag=1 ;;
    off|OFF|0) _before_read_only_flag=0 ;;
    *) logger_error "read before read_only invalid: $_before_read_only" ;;
  esac
  if [[ "$_before_read_only_flag" == "$_read_only_flag" ]]; then
    logger_debug "set read_only is unnecessary: address=$_address: before_read_only=$_before_read_only read_only=$_read_only"
    return 0
  fi

  # 设置新的read_only
  _result=$( $SSH root@$_ip "mysql --host=127.0.0.1 --port=$_port --user=root -e 'set global read_only=$_read_only_flag'" 2>&1 )
  if (($?!=0)); then
    logger_error "set read_only error: address=$_address: read_only=$_read_only_flag: $_result"
    return 2
  fi

  # 检查新的read_only是否生效
  _result=$( $SSH root@$_ip "mysql --host=127.0.0.1 --port=$_port --user=root -e \"show global variables like 'read_only'\"" 2>&1 )
  if (($?!=0)); then
    logger_error "read after read_only error: address=$_address: $_result"
    return 3
  fi
  _after_read_only=$(awk '$1=="read_only"{print $2}' <<<"$_result")
  case "$_after_read_only" in
    on|ON|1) _after_read_only_flag=1 ;;
    off|OFF|0) _after_read_only_flag=0 ;;
    *) logger_error "read after read_only invalid: $_after_read_only" ;;
  esac
  if [[ "$_after_read_only_flag" != "$_read_only_flag" ]]; then
    logger_error "set read_only differ: address=$_address: new=${_read_only}:${_read_only_flag} after=${_after_read_only}:${_after_read_only_flag}"
    return 4
  fi

  logger_message "set read_only done: address=$_address: before_read_only=${_before_read_only}:${_before_read_only_flag} new=${_read_only}:${_read_only_flag} after=${_after_read_only}:${_after_read_only_flag}"

  return 0
}

##
# 设置后端的选主权重
# 设置为0，数据库变为从
# 设置为非0，数据库变为主
#
set_backend_role()
{
  logger_debug "${FUNCNAME[0]}()"
  declare -r _address=$1
  declare -r _role=$2
  declare _rw_weight=0
  declare _result
  declare _before_rw_weight
  declare _after_rw_weight
  if [[ $_role =~ ^(m|M) ]]; then
    _rw_weight=2
  else
    _rw_weight=0
  fi

  # 查看当前rw_weight状态，如果没变化，直接返回
  _result=$( mysql --host="$MP_ADMIN_IP" --port="$MP_ADMIN_PORT" --user="$MP_ADMIN_USER" --password="$MP_ADMIN_PWD" -ABs -e showbackends 2>&1 )
  if (($?!=0)); then
    logger_error "read before rw_weight error: address=$_address: $_result"
    return 1
  fi
  _before_rw_weight=$(awk "\$2==\"$_address\"{print \$6}" <<<"$_result")
  if [[ "$_before_rw_weight" == "$_rw_weight" ]]; then
    logger_debug "set rw_weight is unnecessary: address=$_address: before_rw_weight=$_before_rw_weight rw_weight=$_rw_weight"
    return 0
  fi

  # 设置新的rw_weight
  _result=$( mysql --host="$MP_ADMIN_IP" --port="$MP_ADMIN_PORT" --user="$MP_ADMIN_USER" --password="$MP_ADMIN_PWD" -ABs \
    -e "SetBackendParam --backend=$_address --rw-weight=$_rw_weight" 2>&1 )
  if (($? != 0)); then
    logger_error "SetBackendParam error: address=$_address rw_weight=$_rw_weight: $_result"
    return 1
  fi

  # 检查新的rw_weight是否生效
  _result=$( mysql --host="$MP_ADMIN_IP" --port="$MP_ADMIN_PORT" --user="$MP_ADMIN_USER" --password="$MP_ADMIN_PWD" -ABs -e showbackends 2>&1 )
  if (($? != 0)); then
    logger_error "read after rw_weight error: address=$_address: $_result"
    return 2
  fi
  _after_rw_weight=$(awk "\$2==\"$_address\"{print \$6}" <<<"$_result")
  if [[ "$_after_rw_weight" != "$_rw_weight" ]]; then
    logger_error "set rw_weight failed: address=$_address rw_weigth=$_rw_weight after_rw_weight=$_after_rw_weight"
    return 3
  fi

  logger_debug "set rw_weight done: address=$_address rw_weigth=$_rw_weight"
  return 0
}





##
# 连DBProxy，查看后端状态
#
showbackends()
{
  logger_debug "${FUNCNAME[0]}()"
  declare _result=""
  if [[ -z "$SHOWBACKENDS" ]]; then
    _result=$( mysql --host="$MP_ADMIN_IP" --port="$MP_ADMIN_PORT" --user="$MP_ADMIN_USER" --password="$MP_ADMIN_PWD" -ABs -e showbackends 2>&1 )
    if (( $? != 0 )); then
      logger_error "showbackends error: $_result"
      SHOWBACKENDS=""
      return 1
    fi
    logger_debug "showbackens:"
    logger_debug "$_result"
    SHOWBACKENDS=$_result
  else
    logger_debug "showbackends use cache"
  fi
  return 0
}


##
# 连MySQL，查看复制状态
#
showslavestatus()
{
  logger_debug "${FUNCNAME[0]}()"
  declare _address=$1
  declare _ip
  declare _port
  declare _result=""

  if [[ -z "$SHOWSLAVESTATUS" ]]; then
    _ip=${_address%:*}
    _port=${_address##*:}
    _result=$( $SSH root@$_ip "mysql --host=127.0.0.1 --port=$_port --user=root -e \"show slave status\G\"" 2>&1 )
    if (( $? != 0 )); then
      logger_error "showslavestatus error: $_result"
      SHOWSLAVESTATUS=""
      return 1
    fi
    logger_debug "showslavestatus:"
    logger_debug "$_result"
    SHOWSLAVESTATUS=$_result
    SLAVE_IO_RUNNING=$( awk '/ Slave_IO_Running: /{print $2}' <<<"$_result" )
    SLAVE_SQL_RUNNING=$( awk '/ Slave_SQL_Running: /{print $2}' <<<"$_result" )
    SECONDS_BEHIND_MASTER=$( awk '/ Seconds_Behind_Master: /{print $2}' <<<"$_result" )
    LAST_IO_ERRNO=$( awk '/ Last_IO_Errno: /{print $2}' <<<"$_result" )
    LAST_SQL_ERRNO=$( awk '/ Last_SQL_Errno: /{print $2}' <<<"$_result" )
    MASTER_LOG_FILE=$( awk '/ Master_Log_File: /{print $2}' <<<"$_result" )
    READ_MASTER_LOG_POS=$( awk '/ Read_Master_Log_Pos: /{print $2}' <<<"$_result" )
    RELAY_MASTER_LOG_FILE=$( awk '/ Relay_Master_Log_File: /{print $2}' <<<"$_result" )
    EXEC_MASTER_LOG_POS=$( awk '/ Exec_Master_Log_Pos: /{print $2}' <<<"$_result" )
    logger_debug "last_io_errno=$LAST_IO_ERRNO last_sql_errno=$LAST_SQL_ERRNO master_log_file=$MASTER_LOG_FILE \
read_master_log_pos=$READ_MASTER_LOG_POS relay_master_log_file=$RELAY_MASTER_LOG_FILE \
exec_master_log_pos=$EXEC_MASTER_LOG_POS"

  else
    logger_debug "showslavestatus use cache"
  fi
  return 0
}


##
# 查看是否有master down
# 选主权重rw_weight>0表示是master，rw_weight==0表示slave
#
# @global MASTER_DOWN_ADDRESS
# @global MASTER_DOWN_COUNT
# @global MASTER_UP_COUNT
# @return 9 showbackends出错
# @return 0 成功
# @variable MASTER_DOWN_COUNT > 1 有多个master down (不正常)
# @variable MASTER_DOWN_COUNT == 1 有一个master down
# @variable MASTER_DOWN_COUNT == 0 没有master down
#
check_master_down() {
  logger_debug "${FUNCNAME[0]}()"

  declare _master
  declare _master_down
  declare _master_up
  declare -i _rc=0
  MASTER_DOWN_ADDRESS=""
  MASTER_DOWN_COUNT=0
  MASTER_UP_COUNT=0
  if ! showbackends; then
    return 9
  fi

  _master=$( awk '$6 > 0' <<<"$SHOWBACKENDS" )

  _master_down=$( awk '$6 > 0 && tolower($3)=="down"' <<<"$_master" )
  if [[ -z "$_master_down" ]]; then
    MASTER_DOWN_COUNT=0
  else
    MASTER_DOWN_COUNT=$( wc -l <<<"$_master_down" )
  fi

  _master_up=$( awk '$6 > 0 && tolower($3)=="up"' <<<"$_master" )
  if [[ -z "$_master_up" ]]; then
    MASTER_UP_COUNT=0
  else
    MASTER_UP_COUNT=$( wc -l <<<"$_master_up" )
  fi

  if (( MASTER_DOWN_COUNT > 1 )); then
    logger_error "more than 1 master down: $_master_down"
    logger_error "$SHOWBACKENDS"
    _rc=0
    MASTER_DOWN_ADDRESS=$( awk '$6 > 0 && tolower($3)=="down" {print $2}' <<<"$_master_down" | head -n1 )
  elif (( MASTER_DOWN_COUNT == 1 )); then
    logger_error "master down: $_master_down"
    logger_error "$SHOWBACKENDS"
    _rc=0
    MASTER_DOWN_ADDRESS=$( awk '$6 > 0 && tolower($3)=="down" {print $2}' <<<"$_master_down" )
  else
    if (( MASTER_UP_COUNT == 1 )); then
      logger_debug "no master down"
    else
      logger_error "no master up: maybe pending or no master"
      logger_error "$SHOWBACKENDS"
    fi
    _rc=0
  fi
  return $_rc
}


##
# 查看是否有slave up
# 选主权重rw_weight>0表示是master，rw_weight==0表示slave
#
# @global SLAVE_UP_ADDRESS
# @global SLAVE_UP_COUNT
# @return 9 showbackends出错
# @return 0 成功
# @variable SLAVE_UP_COUNT == 2 有多个slave up (中间状态?)
# @variable SLAVE_UP_COUNT == 1 有一个slave up
# @variable SLAVE_UP_COUNT == 0 没有slave up
#
check_slave_up() {
  logger_debug "${FUNCNAME[0]}()"

  declare _slave
  declare _slave_up
  declare -i _rc=0
  SLAVE_UP_ADDRESS=""
  SLAVE_UP_COUNT=0
  if ! showbackends; then
    return 9
  fi
  _slave=$( awk '$6 == 0' <<<"$SHOWBACKENDS" )

  _slave_up=$( awk '$6 == 0 && tolower($3)=="up"' <<<"$_slave" )
  if [[ -z "$_slave_up" ]]; then
    SLAVE_UP_COUNT=0
  else
    SLAVE_UP_COUNT=$( wc -l <<<"$_slave_up" )
  fi

  if (( SLAVE_UP_COUNT > 1 )); then
    logger_error "more than 1 slave up: $_slave_up"
    logger_error "$SHOWBACKENDS"
    _rc=0
    SLAVE_UP_ADDRESS=$( awk '$6 == 0 && tolower($3)=="up" {print $2}' <<<"$_slave_up" )
  elif (( SLAVE_UP_COUNT == 1 )); then
    logger_debug "slave up: $_slave_up"
    _rc=0
    SLAVE_UP_ADDRESS=$( awk '$6 == 0 && tolower($3)=="up" {print $2}' <<<"$_slave_up" )
  else
    logger_error "no slave up"
    logger_error "$SHOWBACKENDS"
    _rc=0
  fi
  return $_rc
}


##
# 检查slave状态，是否符合切换条件
#
# @return 9 show slave status出错
# @return 3 复制正常，延迟等于NULL
# @return 2 复制正常，延迟太大
# @return 8 复制正常，无延迟  Y
# @return 1 复制正常，延迟很小  Y
# @return 5 主库down了，读和应用线程的日志名不一样
# @return 4 主库down了，读和应用线程的日志点差异太大
# @return 7 主库down了，日志点无差异  Y
# @return 0 主库down了，日志点差异很小  Y
# @return 6 复制down了
check_slave_status()
{
  logger_debug "${FUNCNAME[0]}()"

  declare -r _address=$1
  declare -i _r=0
  if ! showslavestatus "$_address"; then
    return 9
  fi

  if [[ "${SLAVE_IO_RUNNING}" == "Yes" && "$SLAVE_SQL_RUNNING" == "Yes" ]]; then
    if [[ -z "$SECONDS_BEHIND_MASTER" || "$SECONDS_BEHIND_MASTER" == "NULL" ]]; then
      logger_error "showslavestatus lag_is_null: $_address ${SLAVE_IO_RUNNING} ${SLAVE_SQL_RUNNING} ${SECONDS_BEHIND_MASTER}"
      _r=3

    # 复制延迟太大
    elif (( SECONDS_BEHIND_MASTER > MAX_LAG_SECONDS )); then
      logger_error "showslavestatus lag_too_big: $_address ${SLAVE_IO_RUNNING} ${SLAVE_SQL_RUNNING} ${SECONDS_BEHIND_MASTER} $MAX_LAG_SECONDS"
      _r=2

    # 复制无延迟
    elif (( SECONDS_BEHIND_MASTER == 0 )); then
      logger_message "showslavestatus no_lag: $_address ${SLAVE_IO_RUNNING} ${SLAVE_SQL_RUNNING} ${SECONDS_BEHIND_MASTER}"
      _r=8

    # 复制正常，延迟很小
    else
      logger_message "showslavestatus lag_small: $_address ${SLAVE_IO_RUNNING} ${SLAVE_SQL_RUNNING} ${SECONDS_BEHIND_MASTER}"
      _r=1

    fi

  # 主库down了，连不上
  elif [[ "${SLAVE_IO_RUNNING}" != "Yes" && "$SLAVE_SQL_RUNNING" == "Yes" \
    && "$SECONDS_BEHIND_MASTER" == "NULL" \
    && "$LAST_IO_ERRNO" == "2003" && "$LAST_SQL_ERRNO" == "0" ]]; then
    logger_message "showslavestatus master_disconnect: $_address ${SLAVE_IO_RUNNING} ${SLAVE_SQL_RUNNING} ${SECONDS_BEHIND_MASTER} ${LAST_IO_ERRNO}"

    # 读和应用线程的日志名不一样
    if [[ "$MASTER_LOG_FILE" != "$RELAY_MASTER_LOG_FILE" ]]; then
      logger_error "showslavestatus sql_thread_lag_file: $_address $MASTER_LOG_FILE $RELAY_MASTER_LOG_FILE"
      _r=5

    # 读和应用线程的日志点差异太大
    elif (( READ_MASTER_LOG_POS - EXEC_MASTER_LOG_POS > MAX_LAG_LOGPOS )); then
      logger_error "showslavestatus sql_thread_lag_pos: $_address $READ_MASTER_LOG_POS $EXEC_MASTER_LOG_POS $MAX_LAG_LOGPOS"
      _r=4

    # 日志点无差异
    elif (( READ_MASTER_LOG_POS == EXEC_MASTER_LOG_POS )); then
      logger_message "showslavestatus sql_thread_no_lag: $_address $READ_MASTER_LOG_POS $EXEC_MASTER_LOG_POS $MAX_LAG_LOGPOS"
      _r=7

    # 日志点差异较小
    else
      logger_message "showslavestatus sql_thread_lag_small: $_address ${SLAVE_IO_RUNNING} ${SLAVE_SQL_RUNNING} ${SECONDS_BEHIND_MASTER}"
      _r=0

    fi

  else
    logger_error "showslavestatus slave_not_running: $_address ${SLAVE_IO_RUNNING} ${SLAVE_SQL_RUNNING} ${SECONDS_BEHIND_MASTER}"
    _r=6

  fi

  return $_r
}

##
# 等日志应用
wait_slave_log()
{
  logger_debug "${FUNCNAME[0]}()"

  declare -r _address=$1
  declare _current_time=$(date "+%s")
  declare _begin_time=$(date "+%s")
  declare _end_time=$(( _begin_time + MAX_WAIT_LOG_SECONDS))
  declare -i _r=0
  declare -i _rc=1

  logger_message "wait log apply: $MAX_WAIT_LOG_SECONDS"
  while (( _current_time < _end_time )); do
    SHOWSLAVESTATUS=""
    check_slave_status "$_address"
    _r=$?
    if (( _r == 7 || _r == 8 )); then
      logger_message "sql thread finished apply log: $_r"
      _rc=0
      break
    else
      logger_debug "sql thread not apply log: $_r"
    fi
    sleep 2
    _current_time=$(date "+%s")
  done
  if (( _r!=7 && _r!=0 && _r!=8 && _r!=1 )); then
    logger_error "sql thread not apply log: $_r"
  fi

  return $_rc
}



#### 故障切换 ####

failover_precheck()
{
  logger_debug "${FUNCNAME[0]}()"
  declare -i _r=0

  logger_debug "checking dbproxy connectivity"
  check_dbproxy_connect || return 1

  logger_debug "checking slave ssh connectivity"
  check_ssh_connect "$SLAVE_UP_ADDRESS" || return 1

  logger_debug "checking slave mysql connectivity"
  check_mysql_connect "$SLAVE_UP_ADDRESS" || return 1

  logger_debug "checking slave status"
  check_slave_status "$SLAVE_UP_ADDRESS"
  _r=$?
  if (( _r != 0 && _r != 1 && _r != 7 && _r != 8 )); then
    logger_error "slave status error: $_r"
    return 1
  fi

  return 0
}
failover_postcheck()
{
  logger_debug "${FUNCNAME[0]}()"
  declare -i _r=0

  logger_debug "checking dbproxy connectivity"
  check_dbproxy_connect || return 1

  logger_debug "checking slave ssh connectivity"
  check_ssh_connect "$SLAVE_UP_ADDRESS" || return 1

  logger_debug "checking slave mysql connectivity"
  check_mysql_connect "$SLAVE_UP_ADDRESS" || return 1

  logger_debug "checking slave status"
  check_slave_status "$SLAVE_UP_ADDRESS"
  _r=$?
  if (( _r != 7 && _r != 8 )); then
    logger_error "slave status error: $_r"
    return 1
  fi

  return 0
}
failover_phase_1()
{
  logger_debug "${FUNCNAME[0]}()"
  declare _s=""
  logger_message "failover_phase_1 begin"

  # 1. 检查连通性，和备库复制状态
  _s="failover_phase_1 step1: precheck"
  logger_message "$_s"
  failover_precheck || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 2. 备库设置为只读
  _s="failover_phase_1 step2: set slave read_only on $SLAVE_UP_ADDRESS"
  logger_message "$_s"
  set_read_only "$SLAVE_UP_ADDRESS" on || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 3. 等待备库应用日志
  _s="failover_phase_1 step3: wait slave log $SLAVE_UP_ADDRESS"
  logger_message "$_s"
  wait_slave_log "$SLAVE_UP_ADDRESS" || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 3. 再次检查连通性，和备库复制状态
  _s="failover_phase_1 step4: postcheck"
  logger_message "$_s"
  failover_postcheck || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  logger_message "failover_phase_1 end"
  return 0
}
failover_phase_2()
{
  logger_debug "${FUNCNAME[0]}()"
  declare _s=""
  logger_message "failover_phase_2 begin"

  # 1. 检查连通性，和备库复制状态
  _s="failover_phase_2 step1: precheck"
  logger_message "$_s"
  failover_precheck || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 2. 备库设置为只读
  _s="failover_phase_2 step2: set slave read_only on $SLAVE_UP_ADDRESS"
  logger_message "$_s"
  set_read_only "$SLAVE_UP_ADDRESS" on || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 3. 等待备库应用日志
  _s="failover_phase_2 step3: wait slave log $SLAVE_UP_ADDRESS"
  logger_message "$_s"
  wait_slave_log "$SLAVE_UP_ADDRESS" || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 4. 主库的选主权重设置为0
  _s="failover_phase_2 step4: set role master to slave $MASTER_DOWN_ADDRESS"
  logger_message "$_s"
  set_backend_role "$MASTER_DOWN_ADDRESS" slave || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 5. 备库的选主权重设置为2
  _s="failover_phase_2 step5: set role slave to master $SLAVE_UP_ADDRESS"
  logger_message "$_s"
  set_backend_role "$SLAVE_UP_ADDRESS" master || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 6. 备库设置为可读写
  _s="failover_phase_2 step6: set new master read_only off $SLAVE_UP_ADDRESS"
  logger_message "$_s"
  set_read_only "$SLAVE_UP_ADDRESS" off || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 7. 再次检查连通性，和备库复制状态
  _s="failover_phase_2 step7: postcheck"
  logger_message "$_s"
  failover_postcheck || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  logger_message "failover_phase_2 end"
  return 0
}



#### 重新选主 ####

election_precheck()
{
  logger_debug "${FUNCNAME[0]}()"
  declare -i _r=0
  declare _slave

  logger_debug "checking dbproxy connectivity"
  check_dbproxy_connect || return 1
  logger_message "checking dbproxy connectivity: ok"

  while read _slave; do
    logger_debug "checking slave ssh connectivity: $_slave"
    check_ssh_connect "$_slave" || return 1
    logger_message "checking slave ssh connectivity: $_slave: ok"

    logger_debug "checking slave mysql connectivity: $_slave"
    check_mysql_connect "$_slave" || return 1
    logger_message "checking slave mysql connectivity: $_slave: ok"

    logger_debug "checking slave status"
    check_slave_status "$_slave"
    _r=$?
    if (( _r != 0 && _r != 1 && _r != 7 && _r != 8 )); then
      logger_error "checking slave status: error: $_slave $_r"
      return 1
    fi
    logger_message "checking slave status: ok: $_slave $_r"
  done <<<"$SLAVE_UP_ADDRESS"

  return 0
}
election_postcheck()
{
  logger_debug "${FUNCNAME[0]}()"
  declare -i _r=0
  declare _new_master="$1"
  declare _new_slave="$2"
  declare _slave

  logger_debug "checking dbproxy connectivity"
  check_dbproxy_connect || return 1
  logger_message "checking dbproxy connectivity: ok"

  while read _slave; do
    logger_debug "checking slave ssh connectivity: $_slave"
    check_ssh_connect "$_slave" || return 1
    logger_message "checking slave ssh connectivity: $_slave: ok"

    logger_debug "checking slave mysql connectivity: $_slave"
    check_mysql_connect "$_slave" || return 1
    logger_message "checking slave mysql connectivity: $_slave: ok"
  done <<<"$SLAVE_UP_ADDRESS"

  logger_debug "checking slave status: $_slave $_r"
  check_slave_status "$_new_master"
  _r=$?
  if (( _r != 7 && _r != 8 )); then
    logger_error "checking slave status: $_slave $_r: error"
    return 1
  fi
  logger_message "checking slave status: $_slave $_r: ok"

  return 0
}
election_phase_1()
{
  logger_debug "${FUNCNAME[0]}()"
  declare _s=""
  declare _slave
  declare _new_master
  declare _new_slave

  logger_message "election_phase_1 begin"

  # 1. 检查连通性，和备库复制状态
  _s="election_phase_1 step1: precheck"
  logger_message "$_s"
  election_precheck || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 2. 备库设置为只读
  _s="election_phase_1 step2: set slave read_only on"
  logger_message "$_s"
  while read _slave; do
    logger_message "$_s $_slave"
    set_read_only "$_slave" on || { logger_error "$_s $_slave: error"; return 1; }
    logger_message "$_s $_slave: done"
  done <<<"$SLAVE_UP_ADDRESS"
  logger_message "$_s: done"

  # 3. 选第一个备库作为主库(其实不可能有多个备库，必须是一主一从)
  _new_master=$(echo "$SLAVE_UP_ADDRESS" | head -n1)
  _new_slave=$(echo "$SLAVE_UP_ADDRESS" | tail -n+2)
  logger_message "election_phase_1 step3: new master $_new_master"
  logger_message "election_phase_1 step3: new slave $_new_slave"

  # 4. 等待(选出的那个备库)新主库应用日志
  _s="election_phase_1 step4: wait slave log $_new_master"
  logger_message "$_s"
  wait_slave_log "$_new_master" || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 5. 再次检查连通性，和新主库复制状态
  _s="election_phase_1 step5: postcheck $_new_master $_new_slave"
  logger_message "$_s"
  election_postcheck "$_new_master" "$_new_slave" || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  logger_message "election_phase_1 end"

  return 0
}
election_phase_2()
{
  logger_debug "${FUNCNAME[0]}()"
  declare _s=""
  declare _slave
  declare _new_master
  declare _new_slave

  logger_message "election_phase_2 begin"

  # 1. 检查连通性，和备库复制状态
  _s="election_phase_2 step1: precheck"
  logger_message "$_s"
  election_precheck || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 2. 备库设置为只读
  _s="election_phase_2 step2: set slave read_only on"
  logger_message "$_s"
  while read _slave; do
    logger_message "$_s $_slave"
    set_read_only "$_slave" on || { logger_error "$_s $_slave: error"; return 1; }
    logger_message "$_s $_slave: done"
  done <<<"$SLAVE_UP_ADDRESS"
  logger_message "$_s: done"

  # 3. 选第一个备库作为主库(其实不可能有多个备库，只能支持一主一从的结构)
  _new_master=$(echo "$SLAVE_UP_ADDRESS" | head -n1)
  _new_slave=$(echo "$SLAVE_UP_ADDRESS" | tail -n+2)
  logger_message "election_phase_2 step3: new master $_new_master"
  logger_message "election_phase_2 step3: new slave $_new_slave"

  # 4. 等待(选出的那个备库)新主库应用日志
  _s="election_phase_2 step4: wait slave log $_new_master"
  logger_message "$_s"
  wait_slave_log "$_new_master" || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 5. 新主库的选主权重设置为2
  _s="election_phase_2 step5: set role slave to master $_new_master"
  logger_message "$_s"
  set_backend_role "$_new_master" master || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 6. 新主库的设置为读写
  _s="election_phase_2 step6: set new master read_only off $_new_master"
  logger_message "$_s"
  set_read_only "$_new_master" off || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  # 7. 再次检查连通性，和新主库复制状态
  _s="election_phase_2 step7: postcheck $_new_master $_new_slave"
  logger_message "$_s"
  election_postcheck "$_new_master" "$_new_slave" || { logger_error "$_s: error"; return 1; }
  logger_message "$_s: done"

  logger_message "election_phase_2 end"

  return 0
}

set_state()
{
  logger_debug "set_state from $STATE to $1"
  OLD_STATE=$STATE
  STATE=$1
}
clear_state()
{
  STATE=""
  OLD_STATE=""
}
reset_state()
{
  clear_state
  set_state "$@"
}

##
# 检查后端的状态
#  1. vertical: slave,  horizontal: master
#  s\m        up    down    pending    unknown
#  up         -     fo      -          -
#  down       -     -       -          -
#  pending    -     -       -          -
#  unknown    -     -       -          -
#
#  2. vertical: slave,  horizontal: slave
#  s\s        up    down    pending    unknown
#  up         el    -       -          -
#  down       -     -       -          -
#  pending    -     -       -          -
#  unknown    -     -       -          -
watch_backend_status()
{
  logger_debug "${FUNCNAME[0]}()"
  declare -i _master_down=0
  declare -i _slave_up=0

  reset_state "CHECK"

  while ((1==1)); do

    logger_debug "STATE=$STATE"
    case "$STATE" in

    "CHECK")
      SHOWBACKENDS=""
      check_master_down
      _master_down=$?
      check_slave_up
      _slave_up=$?

      if (( _master_down == 0 && _slave_up == 0 )); then
        if (( MASTER_UP_COUNT > 0 )); then
          # 正常
          if (( MASTER_UP_COUNT == 1 && MASTER_DOWN_COUNT == 0 && SLAVE_UP_COUNT == 1 )); then
            logger_debug "normal: $MASTER_UP_COUNT master up, $MASTER_DOWN_COUNT master down, $SLAVE_UP_COUNT slave up"
            set_state "END"
          else
            logger_debug "normal two: $MASTER_UP_COUNT master up, $MASTER_DOWN_COUNT master down, $SLAVE_UP_COUNT slave up"
            set_state "END"
          fi

        # 2个都是slave，都是up。需要从中重新选一个master
        # (2个库都是从库，选一个做主库)
        elif (( MASTER_DOWN_COUNT == 0 && SLAVE_UP_COUNT > 1 )); then
          logger_message "2 up slaves, re-election a master"
          logger_message "$SHOWBACKENDS"
          if [[ "$OLD_STATE" == "ELECTION_PHASE_1" ]]; then
            set_state "ELECTION_PHASE_2"
          else
            set_state "ELECTION_PHASE_1"
          fi

        # 1个master down了，另 1个slave 是up的。开始切换
        # (主库down了，切到备库)
        elif (( MASTER_DOWN_COUNT == 1 && SLAVE_UP_COUNT == 1 )); then
          logger_message "1 master down, 1 slave up, failover"
          logger_message "$SHOWBACKENDS"
          if [[ "$OLD_STATE" == "FAILOVER_PHASE_1" ]]; then
            set_state "FAILOVER_PHASE_2"
          else
            set_state "FAILOVER_PHASE_1"
          fi

        # 正常
        elif (( MASTER_DOWN_COUNT == 0 && SLAVE_UP_COUNT == 1 )); then
          logger_debug "normal three: $MASTER_UP_COUNT master up, $MASTER_DOWN_COUNT master down, $SLAVE_UP_COUNT slave up"
          set_state "END"

        else
          logger_error "master slave error: $MASTER_UP_COUNT master up, $MASTER_DOWN_COUNT master down, $SLAVE_UP_COUNT slave up"
          logger_error "MASTER_DOWN_ADDRESS=$MASTER_DOWN_ADDRESS"
          logger_error "SLAVE_UP_ADDRESS=$SLAVE_UP_ADDRESS"
          logger_error "$SHOWBACKENDS"
          set_state "ERROR"
        fi
      else
        logger_error "check master slave error: m return $_master_down s return $_slave_up"
        set_state "ERROR"
      fi
      ;;

    # phase 1: 检查和等待应用日志
    "FAILOVER_PHASE_1")
      if ! failover_phase_1; then
        logger_error "failover_phase_1: error"
        set_state "ERROR"
      else
        set_state "CHECK"
      fi
      ;;
    # phase 2: phase 1 + 切到备库
    "FAILOVER_PHASE_2")
      if ! failover_phase_2; then
        logger_error "failover_phase_2: error"
        set_state "ERROR"
      else
        set_state "END"
      fi
      ;;

    # phase 1: 检查和等待应用日志
    "ELECTION_PHASE_1")
      if ! election_phase_1; then
        logger_error "election_phase_1: error"
        set_state "ERROR"
      else
        set_state "CHECK"
      fi
      ;;
    # phase 2: phase 1 + 切换到新主库
    "ELECTION_PHASE_2")
      if ! election_phase_2; then
        logger_error "election_phase_2: error"
        set_state "ERROR"
      else
        set_state "END"
      fi
      ;;

    "ERROR")
      logger_error "error end"
      break
      ;;
    "END")
      logger_debug "good end"
      break
      ;;

    *)
      logger_debug "default to check"
      set_state "CHECK"
      ;;

    esac

    sleep 0.1
  done

  if [[ "$OLD_STATE" == "ERROR" || "STATE" == "ERROR" ]]; then
    logger_error "state error: $OLD_STATE"
    clear_state
    return 1
  else
    clear_state
    return 0
  fi
}


##
# 设置读写、选主权重
#
# 1. 设置读写 set rw/ro
#       up   down  pending  unknown
#  ro   o    -     -        -
#  rw   w    -     -        -
#
# 2. 设置选主权重 set master/slave
#       up   down  pending  unknown
#  ro   s    s     s        -
#  rw   m    -     -        -
#
set_properties()
{
  logger_debug "${FUNCNAME[0]}()"

  declare _backend
  declare _backend_address
  declare _backend_status
  declare _backend_type
  declare _backend_rw_weight
  declare -i _rc=0

  SHOWBACKENDS=""
  if ! showbackends; then
    return 9
  fi

  while read _backend; do
    _backend_address=$( awk '{print $2}' <<<"$_backend" )
    _backend_status=$( awk '{print $3}' <<<"$_backend" )
    _backend_type=$( awk '{print $4}' <<<"$_backend" )
    _backend_rw_weight=$( awk '{print $6}' <<<"$_backend" )
    logger_debug "backend addr=$_backend_address status=$_backend_status type=$_backend_type weight=$_backend_rw_weight"

    if [[ "$_backend_status" != "up" ]]; then
      logger_message "backend not up: addr=$_backend_address status=$_backend_status type=$_backend_type weight=$_backend_rw_weight"
      continue
    fi

    # 1. 设置读写
    if [[ "$_backend_status" == "up" ]]; then
      if [[ "$_backend_type" == "rw" ]]; then
        logger_debug "set backend read write: addr=$_backend_address status=$_backend_status type=$_backend_type weight=$_backend_rw_weight"
        set_read_only "$_backend_address" off
      elif [[ "$_backend_type" == "ro" ]]; then
        logger_debug "set backend read only: addr=$_backend_address status=$_backend_status type=$_backend_type weight=$_backend_rw_weight"
        set_read_only "$_backend_address" on
      fi
    fi

    # 2. 设置选主权重
    if [[ "$_backend_type" == "ro" && ( "$_backend_status" == "up" || "$_backend_status" == "down" || "$_backend_status" == "pending" ) ]]; then
      logger_debug "set backend slave: addr=$_backend_address status=$_backend_status type=$_backend_type weight=$_backend_rw_weight"
      set_backend_role "$_backend_address" slave
    elif [[ "$_backend_type" == "rw" && "$_backend_status" == "up" ]]; then
      logger_debug "set backend master: addr=$_backend_address status=$_backend_status type=$_backend_type weight=$_backend_rw_weight"
      set_backend_role "$_backend_address" master
    fi
  done <<<"$SHOWBACKENDS"

  return $_rc
}

##
# Keepalived MASTER上执行
# 1. 主库设置读写，从库设置只读
# 2. 检查后端状态
# 2.1. 如果主库宕了，切到从库
# 2.2. 如果都是从库，随便选出一个主库
watch()
{
  logger_debug "${FUNCNAME[0]}()"
  while ((1==1)); do

    if [[ -f "$0.cnf.reload" ]]; then
      logger_message "reload cnf: $0.cnf"
      rm -f "$0.cnf.reload"
      [[ -r "$0.cnf" ]] && source $0.cnf
    fi

    if hasIPAddress $opt_vip; then
      if ping_gw_by_vip $opt_gw $opt_vip; then
        logger_message "ping vip ok, it is a real master"
        if check_dbproxy_connect; then
          logger_debug "check proxy connect ok"
          # 1. 设置读写
          set_properties
          # 2. 故障切换
          watch_backend_status
          # 3. 设置读写
          set_properties
        else
          logger_error "check proxy connect failed"
        fi
      else
        logger_error "ping vip failed, it is a false master"
      fi
    else
      logger_message "has no vip $opt_vip, it is a backup"
    fi
    logger_debug "watcher sleep $WATCH_SLEEP_INTERVAL"
    sleep $WATCH_SLEEP_INTERVAL
  done
}


test_showbackends()
{
  logger_debug "${FUNCNAME[0]}()"

  declare _backend
  declare _backend_address
  declare _backend_status
  declare _backend_type
  declare _backend_rw_weight
  declare -i _rc=0

  SHOWBACKENDS=""
  if ! showbackends; then
    return 9
  fi

  while read _backend; do
    _backend_address=$( awk '{print $2}' <<<"$_backend" )
    _backend_status=$( awk '{print $3}' <<<"$_backend" )
    _backend_type=$( awk '{print $4}' <<<"$_backend" )
    _backend_rw_weight=$( awk '{print $6}' <<<"$_backend" )
    logger_debug "backend addr=$_backend_address status=$_backend_status type=$_backend_type weight=$_backend_rw_weight"
    declare _result
    declare _ip
    declare _port
    _ip=${_backend_address%:*}
    _port=${_backend_address##*:}
    _result=$( $SSH root@$_ip "mysql --host=127.0.0.1 --port=$_port --user=root -e \"select @@hostname\"" 2>&1 )
    logger_debug "$_result"

  done <<<"$SHOWBACKENDS"

  return $_rc
}
testcase()
{
  logger_debug "${FUNCNAME[0]}()"
  test_showbackends
}


## Main entrance

# 1. 读取命令行参数
saved_opts="$@"
SHORT_OPTS="hV"
LONG_OPTS="help version verb: vip: vi: mphome: gw: if: "
[ $# -gt 0 ] && ARGS=$(getopt -n$PROGNAME -o "$SHORT_OPTS" -l "$LONG_OPTS" -- "$@") || { usage; exit 1; }
eval set -- "$ARGS"
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0;;
    -V|--version) echo "$PROGNAME $VERSION"; exit 0 ;;
    --verb) opt_verb=$2; shift ;;
    --vip) opt_vip=$2; shift ;;
    --vi) opt_vi=$2; shift ;;
    --mphome) opt_mphome=$2; shift ;;
    --gw) opt_gw=$2; shift ;;
    --if) opt_if=$2; shift ;;
    --) shift
      break ;;
    #bad options
    -*) usage; exit 1 ;;
    *) usage; exit 1 ;;
  esac
  shift
done

# 2. 初始化日志
logger_init || { exit 1; }
exec 3>&1 4>&2 >>$LOG 2>&1
logger_message "begin"
logger_message "$0 $saved_opts"

# 3. 加载配置文件，设置默认值
[[ -f "$0.cnf.reload" ]] && rm -f "$0.cnf.reload"
[[ -r "$0.cnf" ]] && source $0.cnf
MAX_LAG_SECONDS=${MAX_LAG_SECONDS:-60}
MAX_LAG_LOGPOS=${MAX_LAG_LOGPOS:-5000}
WATCH_SLEEP_INTERVAL=${WATCH_SLEEP_INTERVAL:-10}
MAX_WAIT_LOG_SECONDS=${MAX_WAIT_LOG_SECONDS:-30}
WAIT_LOG_INTERVAL=${WAIT_LOG_INTERVAL:-2}
log_level=${log_level:-2}

# 3. 设置参数默认值，检查有效性
opt_set_default
opt_sanity_check || exit 1

# 4. 读取DBProxy配置文件
declare MP_ADMIN_ADDRESS
declare MP_ADMIN_IP
declare MP_ADMIN_PORT
declare MP_ADMIN_USER
declare MP_ADMIN_PWD
proxy_conf || { logger_error "read dbproxy cnf error: $_cnf_file"; exit 1; }

# 5. 进入watch死循环
case "$opt_verb" in
  "watch") watch ;;
  "failover") ;;
  "switchover") ;;
  "testcase") testcase ;;
esac

# watch永远不会到这里
logger_message "end"

exec 1>&3 3>&- 2>&4 4>&-


#eof
