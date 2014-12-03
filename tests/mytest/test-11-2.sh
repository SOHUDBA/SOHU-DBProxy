#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

##### 配置文件应该存在  ##########
	
if [ -z $MYSQL_PROXY_CONFIG_FILE -o ! -f $MYSQL_PROXY_CONFIG_FILE ];then
	echo "config file:$MYSQL_PROXY_CONFIG_FILE not exist"
	exit 1
fi

mysql_admin="$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e"

show_listen="showlistenaddr"

###### 将 rw 监听端口全部删除 ######

listeners=$($mysql_admin "$show_listen"|grep rw |awk '{print $2}'|sed 's/,/\n/g'|grep -E -v '^$'|sed ':a; N;s/\n/,/;t a')

####### 删除所有的监听端口 并确保释放掉ip;port#########
#for listen_ad in ${listeners/,/ };do
#	$mysql_admin "dellistenaddr --backend=$listen_ad --bktype=rw" >/dev/null 2>&1
#	if [ $? -ne 0 ];then
#		echo "listen address: $listen_ad deleted error"
#		exit 1
#	fi
#	host=${listen_ad/:*}
#	port=${listen_ad#*:}
#	telnet $host $port >/dev/null 2>&1
#done

####### 确认配置文件中rw_addresses对应的值为空格 ######
#num=$(grep '<rw_addresses> </rw_addresses>' $MYSQL_PROXY_CONFIG_FILE|wc -l)
#if [ $num -eq 0 ];then
#	echo "there should be a <rw_addresses> </rw_addresses> "
#	exit 1
#fi

if [ -z $listeners ];then
	echo "no rw addresses configed"
	exit 1
fi

for listen_ad in ${listeners/,/ };do
	$mysql_admin "addlistenaddr --backend=$listen_ad --bktype=rw" >/dev/null 2>&1
	if [ $? -eq 0 ];then
		echo "listen address: $listen_ad should readded error"
		exit 1
	fi
done

ret=0


bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof
