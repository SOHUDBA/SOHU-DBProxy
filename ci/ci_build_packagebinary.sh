#!/bin/bash
echo "=== $0: make a binary distribution ==="

source ./build_setenv.sh && \
PACKAGE=${PACKAGE_NAME}-${PACKAGE_VERSION} && \
(
rm -rf ${PACKAGE}-3rd_party/ && \
wget -q -O - ftp://x.x.x.x/pub/software/unix/MySQL/Proxy/dbproxy/build/3rd_party/mysql-proxy-0.8.0-3rd_party.${OS_RELEASE}.tar.gz |\
tar -zxf - && \
rsync -avP mysql-proxy-0.8.0-3rd_party/* ${PACKAGE}-bin/ && \
cp -pv ${PACKAGE}-src/scripts/{mysql-proxy,zabbix_agentd}.cnf.sample \
  ${PACKAGE}-src/scripts/mysql-proxy.xml.sample \
  ${PACKAGE}-bin/etc/ && \
cp -pv ${PACKAGE}-src/{ChangeLog,COPYING,NEWS,README,VERSION,REVISION} ${PACKAGE}-bin/ && \
(
  PATCHELF=/DATA/app/patchelf-0.7/bin/patchelf
  PH=/opt/sohu/${PACKAGE_NAME}
  RPATH_NEW="$PH/lib:$PH/lib/libevent:$PH/lib/glib:$PH/lib/mysql"
  if [ -x "$PATCHELF" ]; then
    cd ${PACKAGE}-bin/bin
    $PATCHELF --set-rpath $RPATH_NEW ./mysql-proxy
    $PATCHELF --set-rpath $RPATH_NEW ./mysql-binlog-dump
    $PATCHELF --set-rpath $RPATH_NEW ./mysql-myisam-dump
  else
    echo "patchelf not found: $PATCHELF"
  fi
) && \
mv ${PACKAGE}-bin ${PACKAGE_NAME}
tar -zcvf ${PACKAGE}-bin.${OS_RELEASE}.tar.gz ${PACKAGE_NAME}/
)

#eof
