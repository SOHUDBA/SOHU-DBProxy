#!/bin/bash
echo "=== $0: install binary ==="

install_proxy()
{
  [ -f $PROXY_HOME/bin/mysql-proxyd ] && $PROXY_HOME/bin/mysql-proxyd stop
  mkdir -p /opt/sohu && \
  wget -q -O - $LATEST_BINARY |\
  tar -C /opt/sohu -zxf - && \
  $PROXY_HOME/bin/mysql-proxyd init
}


MYSQL_NAME=Percona-Server-5.5.29-rel30.0-451.Linux.x86_64
MYSQL_HOME=/DATA/app/$MYSQL_NAME
MYSQL_HOME2=/usr/local/$MYSQL_NAME
MYSQL_INSTALLER=ftp://x.x.x.x/pub/software/unix/MySQL/Percona/5.5/binary/x86_64/$MYSQL_NAME.tar.gz
install_mysql()
{
  if [ -d $MYSQL_HOME -a -x $MYSQL_HOME/bin/mysqld ]; then
    :
  else
    rm -rf $MYSQL_HOME
    wget -O - $MYSQL_INSTALLER | tar -C /opt/sohu -zxf -
  fi
  [ -h $MYSQL_HOME2 ] && rm -f $MYSQL_HOME2
  ln -sf $MYSQL_HOME $MYSQL_HOME2
}

source ./deploy_setenv.sh && \
install_mysql && \
install_proxy

#eof
