#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

t=0
for i in {1..10}
do
	for j in {1..20}
	do
		($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest -ABs -e "select * from d1.t1 limit 1;" 1>/dev/null 2>&1)&
		
		$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "deluser --username=test1" 1>/dev/null 2>&1
		
		$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e ' adduser --username=test1 --passwd="a1^*&*&\\\"" --hostip=%.%.%.%;' 1>/dev/null 2>&1
		if [ "$?" -ne "0" ];then
			exit 1
		fi
		$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "deluser --username=test1" 1>/dev/null 2>&1
		
		$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e ' adduser --username=test1 --passwd="\\dsfaf###---\\\"" --hostip=%.%.%.%;' 1>/dev/null 2>&1
		if [ "$?" -ne "0" ];then
			exit 1
		fi
		$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "deluser --username=test1" 1>/dev/null 2>&1
	
		$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e ' adduser --username=test1 --passwd="jhsdfj\"\\!--" --hostip=%.%.%.%;' 1>/dev/null 2>&1
		if [ "$?" -ne "0" ];then
			exit 1
		fi
		$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "deluser --username=test1" 1>/dev/null 2>&1
		
		$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e ' adduser --username=test1 --passwd="s%^dsah\\" --hostip=%.%.%.%;' 1>/dev/null 2>&1
		if [ "$?" -ne "0" ];then
			exit 1
		fi
		$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "deluser --username=test1" 1>/dev/null 2>&1
		
	done
	
	($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e " SetMultiplex --flag=off;" 1>/dev/null 2>&1)&
	#设置sql限制列表
	($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e " ShowMultiplex;" 1>/dev/null 2>&1)&
	
	$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "deluser --username=test1" 1>/dev/null 2>&1
	
	$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e " adduser --username=test1 --passwd=abcd --hostip=%.%.%.%;" 1>/dev/null 2>&1
	if [ "$?" -eq "0" ];then
		exit 1
	fi
	
	$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e " adduser --username=test1 --passwd='abcd' --hostip=%.%.%.%;" 1>/dev/null 2>&1
	if [ "$?" -ne "0" ];then
		exit 1
	fi
	
	if [ ! -f $MYSQL_PROXY_CONFIG_FILE ];then
		echo "config file:$MYSQL_PROXY_CONFIG_FILE not exist"
		exit 1
	fi
	
	pwd=$(cat $MYSQL_PROXY_CONFIG_FILE|awk 'BEGIN{found=0};{if($0~/test1/){found=1}; if(found==1 && $0~/password/){found=0; print $0}}'|awk -F'>' '{print $2}'|awk -F'<' '{print $1}')

	if [ "x$pwd" = "x" -o "x$pwd" != "xabcd" ];then
		echo "password in $MYSQL_PROXY_CONFIG_FILE for test1 is wrong"
		exit 1;	
	fi
	
	$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "deluser --username=test1" 1>/dev/null 2>&1
	
	$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e " adduser --username=test1 --passwd='\'a\\\\bcd\"' --hostip=%.%.%.%;" 1>/dev/null 2>&1
	if [ "$?" -ne "0" ];then
		exit 1
	fi
	
	$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "deluser --username=test1" 1>/dev/null 2>&1
	
	
	$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e " adduser --username=test1 --passwd='a#--bcd' --hostip=%.%.%.%;" 1>/dev/null 2>&1
	if [ "$?" -ne "0" ];then
		exit 1
	fi
	
	if [ ! -f $MYSQL_PROXY_CONFIG_FILE ];then
		echo "config file:$MYSQL_PROXY_CONFIG_FILE not exist"
		exit 1
	fi
	
	pwd=$(cat $MYSQL_PROXY_CONFIG_FILE|awk 'BEGIN{found=0};{if($0~/test1/){found=1}; if(found==1 && $0~/password/){found=0; print $0}}'|awk -F'>' '{print $2}'|awk -F'<' '{print $1}')

	if [ "x$pwd" = "x" -o "x$pwd" != "xa#--bcd" ];then
		echo "password in $MYSQL_PROXY_CONFIG_FILE for test1 is wrong"
		exit 1;	
	fi
	
	$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "deluser --username=test1" 1>/dev/null 2>&1
	
	$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e ' adduser --username=test1 --passwd="a\"b\"cd" --hostip=%.%.%.%;' 1>/dev/null 2>&1
	if [ "$?" -ne "0" ];then
		exit 1
	fi

	if [ ! -f $MYSQL_PROXY_CONFIG_FILE ];then
		echo "config file:$MYSQL_PROXY_CONFIG_FILE not exist"
		exit 1
	fi
	
	pwd=$(cat $MYSQL_PROXY_CONFIG_FILE|awk 'BEGIN{found=0};{if($0~/test1/){found=1}; if(found==1 && $0~/password/){found=0; print $0}}'|awk -F'>' '{print $2}'|awk -F'<' '{print $1}')

	if [ "x$pwd" = "x" -o "x$pwd" != "xa\"b\"cd" ];then
		echo "password in $MYSQL_PROXY_CONFIG_FILE for test1 is wrong"
		exit 1;	
	fi
	
	$MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "deluser --username=test1" 1>/dev/null 2>&1
	
	for j in {1..20}
	do
		($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest -ABs -e "select * from d1.t1 limit 1;" 1>/dev/null 2>&1)&
	done
	
	_t=$?
	((t=t+_t))
done
wait
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
