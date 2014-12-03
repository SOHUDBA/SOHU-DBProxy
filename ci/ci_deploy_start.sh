#!/bin/bash
echo "=== $0: start proxy ==="

source ./deploy_setenv.sh

cd $PROXY_HOME/var/log/ && \
$PROXY_HOME/bin/mysql-proxyd start

#eof
