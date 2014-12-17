#!/bin/bash
echo "=== $0: make a source code distribution ==="

source ./build_setenv.sh && \
PACKAGE=${PACKAGE_NAME}-${PACKAGE_VERSION} && \
sh ./autogen.sh && \
bash ./configure --prefix=${MYSQL_PROXY_INSTALL_PATH} --with-mysql=${MYSQL_INSTALL_PATH}/bin/mysql_config && \
make clean && \
make && \
make dist && \
(
rm -rf ${PACKAGE} ${PACKAGE}-src.tar.gz && \
tar -zxf ${PACKAGE}.tar.gz && \
mv -v ${PACKAGE} ${PACKAGE}-src && \
tar -zcf ${PACKAGE}-src.${OS_RELEASE}.tar.gz ${PACKAGE}-src && \
test -f ${PACKAGE}-src.${OS_RELEASE}.tar.gz
)

#eof
