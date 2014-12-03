#!/bin/bash
echo "=== $0: init ==="

cat >./build_setenv.sh <<'EOF'
export WORK_DIR=.

export LANG=C

export PACKAGE_NAME="dbproxy"
export PACKAGE_VERSION=$(tr -d '\n' < VERSION)

export MYSQL_PROXY_INSTALL_PATH=$(pwd)/${PACKAGE_NAME}-${PACKAGE_VERSION}-bin

export GLIB_INSTALL_PATH=/DATA/app/glib-2.34.3
export LIBEVENT_INSTALL_PATH=/DATA/app/libevent-2.0.21-stable
#export LIBEVENT_INSTALL_PATH=/DATA/app/libevent-2.0.21-stable-debug
#export LIBEVENT_INSTALL_PATH=/DATA/app/libevent-2.1.3-alpha
#export LUA_INSTALL_PATH=/DATA/app/lua-5.1.5
export MYSQL_INSTALL_PATH=/usr/local/Percona-Server-5.1.68-rel14.5-513.Linux.x86_64
export OPENSSL_INSTALL_PATH=/usr
export LIBXML2_INSTALL_PATH=/usr

export PKG_CONFIG_PATH="${GLIB_INSTALL_PATH}/lib/pkgconfig"
export PKG_CONFIG_LIBDIR="${GLIB_INSTALL_PATH}/lib"
export GLIB_CFLAGS="-I${GLIB_INSTALL_PATH}/include/glib-2.0 -I${GLIB_INSTALL_PATH}/lib/glib-2.0/include"
export GLIB_LIBS="-L${GLIB_INSTALL_PATH}/lib -lglib-2.0"
export GMODULE_CFLAGS="$GLIB_CFLAGS"
export GMODULE_LIBS="-L${GLIB_INSTALL_PATH}/lib -lgmodule-2.0"
export GTHREAD_CFLAGS="$GLIB_CFLAGS"
export GTHREAD_LIBS="-L${GLIB_INSTALL_PATH}/lib -lgthread-2.0"
#export LUA_CFLAGS="-I${LUA_INSTALL_PATH}/include"
#export LUA_LIBS="-L${LUA_INSTALL_PATH}/lib -llua -ldl"
export OPENSSL_LIBS="-L${OPENSSL_INSTALL_PATH}/lib64 -lcrypto"
export OPENSSL_CFLAGS="-I${OPENSSL_INSTALL_PATH}/include"
export LIBXML2_LIBS="-L${OPENSSL_INSTALL_PATH}/lib64 -lxml2"
export LIBXML2_CFLAGS="-I${OPENSSL_INSTALL_PATH}/include/libxml2"

EXTRA_FLAGS=""
EXTRA_FLAGS="$EXTRA_FLAGS -Wall -Wextra"
EXTRA_FLAGS="$EXTRA_FLAGS -g -O0" 
#EXTRA_FLAGS="$EXTRA_FLAGS -DDEBUG_CONN_POOL"
#接下来测试-pg 参数对dbproxy性能的影响
#EXTRA_FLAGS="$EXTRA_FLAGS -pg"
#为 perf除错增加
EXTRA_FLAGS="$EXTRA_FLAGS -fno-omit-frame-pointer -ggdb"
export EXTRA_FLAGS
export CFLAGS="-I${LIBEVENT_INSTALL_PATH}/include $EXTRA_FLAGS"
export CPPFLAGS="-I${LIBEVENT_INSTALL_PATH}/include $EXTRA_FLAGS"
export LDFLAGS="-L${LIBEVENT_INSTALL_PATH}/lib -L${GLIB_INSTALL_PATH}/lib -lm $EXTRA_FLAGS"

export PATH=/DATA/app/autotools/bin:/usr/kerberos/sbin:/usr/kerberos/bin:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
#export LD_LIBRARY_PATH=/DATA/app/lua-5.1.5/lib

ulimit -c unlimited

unset G_SLICE G_DEBUG
#export G_SLICE=always-malloc
#export G_DEBUG=gc-friendly

OS_RELEASE=$(lsb_release -r | grep "^Release:" | awk '{print $2}' | cut -d. -f1)
export OS_RELEASE="el${OS_RELEASE}"

EOF


source ./build_setenv.sh && \
echo "${PACKAGE_NAME}-${PACKAGE_VERSION} ${BUILD_ID}-${BUILD_NUMBER}-${SVN_REVISION} ${OS_RELEASE}" >REVISION


#eof
