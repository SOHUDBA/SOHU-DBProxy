make clean

export GLIB_INSTALL_PATH=/data/soft/glib
export LIBEVENT_INSTALL_PATH=/data/soft/libevent
export OPENSSL_INSTALL_PATH=/usr
export LIBXML2_INSTALL_PATH=/usr
export LIBXML2_LIBS="-L${OPENSSL_INSTALL_PATH}/lib64 -lxml2"
export LIBXML2_CFLAGS="-I${OPENSSL_INSTALL_PATH}/include/libxml2"
export PKG_CONFIG_PATH="${GLIB_INSTALL_PATH}/lib/pkgconfig"
export PKG_CONFIG_LIBDIR="${GLIB_INSTALL_PATH}/lib"
export GLIB_CFLAGS="-I${GLIB_INSTALL_PATH}/include/glib-2.0 -I${GLIB_INSTALL_PATH}/lib/glib-2.0/include"
export GLIB_LIBS="-L${GLIB_INSTALL_PATH}/lib -lglib-2.0"
export GMODULE_CFLAGS="$GLIB_CFLAGS"
export GMODULE_LIBS="-L${GLIB_INSTALL_PATH}/lib -lgmodule-2.0"
export GTHREAD_CFLAGS="$GLIB_CFLAGS"
export GTHREAD_LIBS="-L${GLIB_INSTALL_PATH}/lib -lgthread-2.0"
export CFLAGS="-I${LIBEVENT_INSTALL_PATH}/include -g -Wall -Wextra"
export CPPFLAGS="-I${LIBEVENT_INSTALL_PATH}/include -g"
export LDFLAGS="-L${LIBEVENT_INSTALL_PATH}/lib -L${GLIB_INSTALL_PATH}/lib -lm"
export OPENSSL_LIBS="-L${OPENSSL_INSTALL_PATH}/lib64 -lcrypto"
export OPENSSL_CFLAGS="-I${OPENSSL_INSTALL_PATH}/include"


export MYSQL_INSTALL_PATH=/usr
export MYSQL_PROXY_INSTALL_PATH=/data/soft/dbproxy


sh autogen.sh

bash ./configure --prefix=${MYSQL_PROXY_INSTALL_PATH} --with-mysql=${MYSQL_INSTALL_PATH}/bin/mysql_config

make && make install && mkdir -p ${MYSQL_PROXY_INSTALL_PATH}/var/log && \
cp -r ./etc ${MYSQL_PROXY_INSTALL_PATH}/etc && chmod 600 ${MYSQL_PROXY_INSTALL_PATH}/etc/mysql-proxy.cnf
