#!/bin/bash
echo "=== $0: init ==="

cat >./deploy_setenv.sh <<'EOF'
LOCAL_HOSTIP=$(getent hosts $(hostname) | awk '{print $1}' | head -n 1)
export LOCAL_HOSTIP
export PACKAGE_NAME=dbproxy
export PACKAGE_VERSION=$(tr -d '\n' < VERSION)
export PROXY_HOME=/opt/sohu/${PACKAGE_NAME}

OS_RELEASE=$(lsb_release -r | grep "^Release:" | awk '{print $2}' | cut -d. -f1)
export OS_RELEASE="el${OS_RELEASE}"

export LATEST_BINARY=ftp://x.x.x.x/pub/software/unix/MySQL/Proxy/dbproxy/build/${PACKAGE_VERSION}/latest/${PACKAGE_NAME}-${PACKAGE_VERSION}-bin.${OS_RELEASE}.tar.gz
EOF


#eof
