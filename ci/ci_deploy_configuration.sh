#!/bin/bash
echo "=== $0: install customized configurations ==="

source ./deploy_setenv.sh

#rsync -avP ./pxc_check_status ${PROXY_HOME}/bin/
#rsync -avP ./mysql-proxy.cnf ${PROXY_HOME}/etc/
#rsync -avP ./mysql-proxy.xml ${PROXY_HOME}/etc/
[ -f ${PROXY_HOME}/bin/pxc_check_status ] && chmod +x ${PROXY_HOME}/bin/pxc_check_status
[ -f ${PROXY_HOME}/bin/mysql_check_status ] && chmod +x ${PROXY_HOME}/bin/mysql_check_status
[ -f ${PROXY_HOME}/etc/mysql-proxy.cnf ] && chmod 0660 ${PROXY_HOME}/etc/mysql-proxy.cnf
[ -f ${PROXY_HOME}/etc/mysql-proxy.xml ] && chmod 0660 ${PROXY_HOME}/etc/mysql-proxy.xml
true

#eof
