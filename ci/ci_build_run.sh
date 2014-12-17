#!/bin/bash
echo "=== $0: build and unittest ==="

source ./build_setenv.sh && \
PACKAGE=${PACKAGE_NAME}-${PACKAGE_VERSION} && \
(
cd ${PACKAGE}-src && \
bash ./configure --prefix=${MYSQL_PROXY_INSTALL_PATH}  --with-mysql=${MYSQL_INSTALL_PATH}/bin/mysql_config && \
make clean && \
make && \
#(cd tests/unit && make check) && \
rm -rf ${PACKAGE}-bin/ && \
make install && \
cd ..
)

#eof
