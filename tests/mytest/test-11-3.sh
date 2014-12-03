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

##### 监听端口大于等于2 ##########

num=$(echo "$listeners"|awk -F',' '{print $0}'|wc -l)
if ((num<2));then
	#echo "there should be 2 or more listen addresses, will add 2"
	ip_add="127.0.0.1:7766,127.0.0.1:7767"
	for listen_ad in ${ip_add/,/ };do
		$mysql_admin "addlistenaddr --backend=$listen_ad --bktype=rw" >/dev/null 2>&1
		if [ $? -ne 0 ];then
			echo "listen address: $listen_ad added error"
			exit 1
		fi
	done
fi

##### 删除第一个监听ip地址  ##############
listeners=$($mysql_admin "$show_listen"|grep rw |awk '{print $2}'|sed 's/,/\n/g'|grep -E -v '^$'|sed ':a; N;s/\n/,/;t a')
first_addr=${listeners//,*}

$mysql_admin "dellistenaddr --backend=$first_addr --bktype=rw" >/dev/null 2>&1
if [ $? -ne 0 ];then
	echo "listen addr:$first_addr deleted error"
	exit 1
fi

host=${first_addr/:*}
port=${first_addr#*:}

telnet $host $port >/dev/null 2>&1

err=0
##### 确认内存中为监听地址的取值和配置文件中监听地址取值是正确的 #####
listeners=$($mysql_admin "$show_listen"|grep rw |awk '{print $2}'|grep -E '^ |^,')
if [ ! -z $listeners ];then
	err=1
fi
listeners=$(grep 'rw_addresses' $MYSQL_PROXY_CONFIG_FILE|awk -F'>' '{print $2}'|awk -F'<' '{print $1}'|grep -E '^ |^,')
if [ ! -z $listeners ];then
	err=$((err+1))
fi

##### 将删除的端口添加进来 ##############
$mysql_admin "addlistenaddr --backend=$first_addr --bktype=rw" >/dev/null 2>&1

##### 将为了测试添加的测试端口删除 #########
if ((num<2));then
	echo "we should delete ip:ports added for test"
	ip_add="127.0.0.1:7766,127.0.0.1:7767"
	for listen_ad in ${ip_add/,/ };do
		$mysql_admin "dellistenaddr --backend=$listen_ad --bktype=rw" >/dev/null 2>&1
		if [ $? -ne 0 ];then
			echo "listen address: $listen_ad added error"
			exit 1
		fi
		
		host=${listen_ad/:*}
		port=${listen_ad#*:}

		telnet $host $port >/dev/null 2>&1
	done
fi

ret=$err
expect=0

if [ $ret -ne $expect ];then
	ret=1
	echo "expect: $expect, actual:$ret"
fi

bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof
