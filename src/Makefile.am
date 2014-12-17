#  $%BEGINLICENSE%$
#  Copyright (c) 2007, 2012, Oracle and/or its affiliates. All rights reserved.
# 
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License as
#  published by the Free Software Foundation; version 2 of the
#  License.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
#  02110-1301  USA
# 
#  $%ENDLICENSE%$
#luaextdir = ${pkglibdir}/lua
plugindir = ${pkglibdir}/plugins


BUILD_CPPFLAGS =  $(MYSQL_CFLAGS) $(GLIB_CFLAGS) $(GMODULE_CFLAGS) $(GTHREAD_CFLAGS) $(OPENSSL_CFLAGS) $(LIBXML2_CFLAGS)
BUILD_CFLAGS   =   -DPLUGINDIR="\"$(plugindir)\""  -DEXEC_PREFIX="\"$(exec_prefix)\""
BUILD_LDADD    = $(GLIB_LIBS) $(GMODULE_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) libmysql-chassis.la $(GTHREAD_LIBS)  libmysql-proxy.la libmysql-chassis-glibext.la $(MYSQL_LIBS) libmysql-chassis-regex.la

BUILT_SOURCES =
if USE_WRAPPER_SCRIPT
## we are self-contained
## put all the binaries into a "hidden" location, the wrapper scripts are in ./scripts/
libexec_PROGRAMS = mysql-binlog-dump mysql-proxy mysql-myisam-dump
else
bin_PROGRAMS            = mysql-binlog-dump mysql-myisam-dump mysql-proxy
endif

mysql_proxy_SOURCES		= mysql-proxy-cli.c
mysql_proxy_CPPFLAGS	= $(BUILD_CPPFLAGS)
mysql_proxy_CFLAGS		= $(BUILD_CFLAGS)
mysql_proxy_LDADD		= $(BUILD_LDADD)

mysql_binlog_dump_SOURCES	= mysql-binlog-dump.c
mysql_binlog_dump_CPPFLAGS	= $(BUILD_CPPFLAGS)
mysql_binlog_dump_CFLAGS	= $(BUILD_CFLAGS)
mysql_binlog_dump_LDADD		= $(BUILD_LDADD)

mysql_myisam_dump_SOURCES	= mysql-myisam-dump.c
mysql_myisam_dump_CPPFLAGS	= $(BUILD_CPPFLAGS)
mysql_myisam_dump_CFLAGS	= $(BUILD_CFLAGS)
mysql_myisam_dump_LDADD		= $(BUILD_LDADD)

lib_LTLIBRARIES = 

# functionality extending what's currently in glib
lib_LTLIBRARIES += libmysql-chassis-glibext.la
libmysql_chassis_glibext_la_SOURCES = \
	glib-ext.c \
	glib-ext-ref.c

libmysql_chassis_glibext_la_LDFLAGS  = -export-dynamic -no-undefined -dynamic
libmysql_chassis_glibext_la_CPPFLAGS = $(MYSQL_CFLAGS) $(GLIB_CFLAGS) $(GMODULE_CFLAGS)
libmysql_chassis_glibext_la_LIBADD   = $(GLIB_LIBS)

# functionality extending what's currently in libxml
lib_LTLIBRARIES += libmysql-chassis-libxmlext.la
libmysql_chassis_libxmlext_la_SOURCES = \
	libxml-ext.c 

libmysql_chassis_libxmlext_la_LDFLAGS  = -export-dynamic -no-undefined -dynamic
libmysql_chassis_libxmlext_la_CPPFLAGS = $(MYSQL_CFLAGS) $(GLIB_CFLAGS) $(GMODULE_CFLAGS) $(LIBXML2_CFLAGS)
libmysql_chassis_libxmlext_la_LIBADD   = $(GLIB_LIBS) $(LIBXML2_LIBS)

# library implementing timing functionality
lib_LTLIBRARIES += libmysql-chassis-timing.la
libmysql_chassis_timing_la_SOURCES = \
	chassis-timings.c \
	chassis-gtimeval.c \
	my_rdtsc.c

libmysql_chassis_timing_la_LDFLAGS  = -export-dynamic -no-undefined -dynamic
libmysql_chassis_timing_la_CPPFLAGS = $(MYSQL_CFLAGS) $(GLIB_CFLAGS) $(GMODULE_CFLAGS)
libmysql_chassis_timing_la_LIBADD   = $(GLIB_LIBS) libmysql-chassis-glibext.la
if USE_SUNCC_ASSEMBLY
libmysql_chassis_timing_la_CPPFLAGS += \
	$(top_srcdir)/src/my_timer_cycles.il
endif

## added by DBA
## begin
lib_LTLIBRARIES += libmysql-chassis-lb-wrr.la
libmysql_chassis_lb_wrr_la_SOURCES = \
	lb_wrr.c
libmysql_chassis_lb_wrr_la_LDFLAGS  = -export-dynamic -no-undefined -dynamic
libmysql_chassis_lb_wrr_la_CPPFLAGS = $(GLIB_CFLAGS) $(GMODULE_CFLAGS)
libmysql_chassis_lb_wrr_la_LIBADD   = $(GLIB_LIBS)
## end

lib_LTLIBRARIES += libmysql-chassis-regex.la
libmysql_chassis_regex_la_SOURCES = \
	chassis-regex.c
libmysql_chassis_regex_la_LDFLAGS  = -export-dynamic -no-undefined -dynamic
libmysql_chassis_regex_la_CPPFLAGS = $(GLIB_CFLAGS)
libmysql_chassis_regex_la_LIBADD   = $(GLIB_LIBS)

#lib_LTLIBRARIES += libnetwork-connection-scaler.la
#libnetwork_connection_scaler_la_SOURCES = \
#	network-connection-scaler.c
#libnetwork_connection_scaler_la_LDFLAGS  = -export-dynamic -no-undefined -dynamic
#libnetwork_connection_scaler_la_CPPFLAGS = $(GLIB_CFLAGS)
#libnetwork_connection_scaler_la_LIBADD   = $(GLIB_LIBS)


## the core library
lib_LTLIBRARIES += libmysql-chassis.la
libmysql_chassis_la_SOURCES = \
	chassis-plugin.c \
	chassis-log.c \
	chassis-mainloop.c \
	chassis-event-thread.c \
	chassis-keyfile.c \
	chassis-path.c \
	chassis-filemode.c \
	chassis-limits.c \
	chassis-shutdown-hooks.c \
	chassis-frontend.c \
	chassis-options.c \
	chassis-unix-daemon.c \
	chassis-win32-service.c \
	chassis-config-xml-admin.c


libmysql_chassis_la_LDFLAGS  = -export-dynamic -no-undefined -dynamic
libmysql_chassis_la_CPPFLAGS = $(MYSQL_CFLAGS) $(EVENT_CFLAGS) $(GLIB_CFLAGS)  $(GMODULE_CFLAGS) $(GTHREAD_CFLAGS) $(LIBXML2_CFLAGS) -DPLUGINDIR="\"$(plugindir)\""  -DEXEC_PREFIX="\"$(exec_prefix)\""
libmysql_chassis_la_LIBADD   = $(EVENT_LIBS)   $(GLIB_LIBS)   $(GMODULE_LIBS) $(GTHREAD_LIBS) $(LIBXML2_LIBS) libmysql-chassis-timing.la libmysql-chassis-glibext.la libmysql-chassis-regex.la libmysql-chassis-libxmlext.la

## modified by sohu-inc.com
## 将词法分析的部分拿到了src中，将其作为一个基础模块

## mysql_la 应该是用来在lua 脚本中使用的不需要在这里编译
#mysql_la_SOURCES  = \
#	mysql-proto.c \
#	mysql-password.c \
#	sql-tokenizer.l \
#	sql-tokenizer-tokens.c \
#	sql-tokenizer-keywords.c \
#	sql-tokenizer-lua.c 
## get libtool to build a shared-lib
#mysql_la_CPPFLAGS = ${LUA_CFLAGS} ${GLIB_CFLAGS} -I${top_srcdir}/src/ ${MYSQL_CFLAGS} -I${top_builddir}/lib/
#mysql_la_LDFLAGS  = $(AM_LDFLAGS) -module -avoid-version
#mysql_la_LIBADD   = ${GLIB_LIBS} ${top_builddir}/src/libmysql-proxy.la

lib_LTLIBRARIES += libsql-tokenizer.la
libsql_tokenizer_la_SOURCES = \
	sql-tokenizer.l \
	sql-tokenizer-tokens.c \
	sql-tokenizer-keywords.c \
	network-sql-normalization.c
libsql_tokenizer_la_CPPFLAGS = $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(OPENSSL_CFLAGS)
libsql_tokenizer_la_LDFLAGS  = $(AM_LDFLAGS) -export-dynamic -no-undefined -dynamic
libsql_tokenizer_la_LIBADD   = $(GLIB_LIBS) $(OPENSSL_LIBS)

DISTCLEANFILES = \
	sql-tokenizer.c \
	sql-tokenizer-keywords.c

noinst_PROGRAMS=sql-tokenizer-gen

sql_tokenizer_gen_SOURCES=\
	sql-tokenizer-gen.c \
	sql-tokenizer-tokens.c

sql_tokenizer_gen_CPPFLAGS=${GLIB_CFLAGS} -I${srcdir}
sql_tokenizer_gen_LDADD=${GLIB_LIBS}

sql-tokenizer.c: sql-tokenizer-keywords.c

sql-tokenizer-keywords.c: sql-tokenizer-gen
	${builddir}/sql-tokenizer-gen > ${builddir}/sql-tokenizer-keywords.c


## modified by sohu-inc.com
## 添加了对zabbix socket 的封装
lib_LTLIBRARIES += libmysql-proxy.la
libmysql_proxy_la_SOURCES = \
	network-packet.c \
	network-mysqld.c \
	network-mysqld-t.c \
	network-mysqld-proto.c \
	network-mysqld-binlog.c \
	network-mysqld-packet.c \
	network_mysqld_type.c \
	network_mysqld_proto_binary.c \
	network-mysqld-masterinfo.c \
	network-mysql-error.c \
	network-conn-pool.c  \
	network-connection-state.c \
	network-queue.c \
	network-asn1.c \
	network-spnego.c \
	network-socket.c \
	network-zabbix-socket.c \
	network-zabbix-agentd.c \
	network-address.c \
	network-injection.c \
	network-backend.c \
	network-connection-scaler.c \
	network-detection-event-thread.c \
	network-backend-status-updater.c \
	network-mysqld-async-con.c \
	network-security-sqlmode.c \
	network-para-exec-limit.c \
	network-para-exec-process.c \
	network-dura-exec-limit.c \
	network-dura-exec-process.c \
	network-sql-statistics.c \
	network-inbytes-statistic.c \
	network-outbytes-statistic.c \
	network-query-rate.c \
	network-check-DMLsql.c \
	network-dml-statistic.c \
	slow-query-log.c

libmysql_proxy_la_LDFLAGS  = -export-dynamic -no-undefined -dynamic
libmysql_proxy_la_CPPFLAGS = $(MYSQL_CFLAGS) $(GLIB_CFLAGS)  $(GMODULE_CFLAGS) $(LIBXML2_CFLAGS) -I$(top_srcdir)/lib/ -I$(top_srcdir)/src/
libmysql_proxy_la_LIBADD   = $(EVENT_LIBS) $(GLIB_LIBS) $(GMODULE_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) libmysql-chassis.la libmysql-chassis-timing.la libmysql-chassis-glibext.la \
	$(MYSQL_LIBS) \
	libmysql-chassis-regex.la \
	libmysql-chassis-lb-wrr.la \
	libsql-tokenizer.la

## should be packaged, but not installed
noinst_HEADERS=\
	network-debug.h \
	sql-tokenizer.h \
	sql-tokenizer-keywords.h 

include_HEADERS=\
	network-mysqld.h \
	network-mysqld-t.h \
	network-mysqld-proto.h \
	network-mysqld-binlog.h \
	network-mysqld-packet.h \
	network_mysqld_type.h \
	network_mysqld_proto_binary.h \
	network-mysqld-masterinfo.h \
	network-mysql-error.h \
	network-conn-pool.h \
	network-connection-state.h \
	network-queue.h \
	network-socket.h \
	network-address.h \
	network-asn1.h \
	network-spnego.h \
	network-packet.h \
	sys-pedantic.h \
	chassis-plugin.h \
	chassis-log.h \
	chassis-keyfile.h \
	chassis-mainloop.h \
	chassis-path.h \
	chassis-filemode.h \
	chassis-limits.h \
	chassis-event-thread.h \
	chassis-gtimeval.h \
	glib-ext.h \
	glib-ext-ref.h \
	string-len.h \
	network-injection.h \
	chassis-shutdown-hooks.h \
	chassis-exports.h \
	network-exports.h \
	network-backend.h \
	disable-dtrace.h \
	chassis-timings.h \
	chassis-frontend.h \
	chassis-options.h \
	chassis-win32-service.h \
	chassis-unix-daemon.h \
	my_rdtsc.h \
	lb_wrr.h \
	chassis-regex.h \
	network-connection-scaler.h \
	network-zabbix-socket.h \
	network-zabbix-agentd.h \
	network-detection-event-thread.h \
	network-backend-status-updater.h \
	network-mysqld-async-con.h \
	sql-tokenizer.h \
	sql-tokenizer-keywords.h \
	network-sql-normalization.h \
	network-security-sqlmode.h \
	network-sql-statistics.h \
	libxml-ext.h \
	chassis-config-xml-admin.h \
	network-para-exec-limit.h \
	network-para-exec-process.h \
	network-dura-exec-limit.h \
	network-dura-exec-process.h \
	slow-query-log.h \
	network-inbytes-statistic.h \
	network-outbytes-statistic.h \
	network-check-DMLsql.h \
	network-dml-statistic.h \
	network-query-rate.h
	
if ENABLE_DTRACE

BUILT_SOURCES += proxy-dtrace-provider.h
nodist_libmysql_proxy_la_SOURCES = proxy-dtrace-provider.h
CLEANFILES = proxy-dtrace-provider.h

proxy-dtrace-provider.h: Makefile
	$(DTRACE) -h -s $(top_srcdir)/src/proxy-dtrace-provider.d -o $(top_builddir)/src/proxy-dtrace-provider.h

## Solaris DTrace needs to perform some link time operations at probe sites.
## On OS X this is performed automagically (and dtrace(1M) doesn't even have -G)
if OS_SOLARIS

proxy-dtrace-provider.o: proxy-dtrace-provider.h $(libmysql_proxy_la_OBJECTS)
	$(DTRACE) -G -s $(top_srcdir)/src/proxy-dtrace-provider.d -o $(top_builddir)/src/proxy-dtrace-provider.o \
	    $(libmysql_proxy_la_OBJECTS:%.lo=.libs/%.o)


libmysql_proxy_la_LIBADD += proxy-dtrace-provider.o
endif

endif

## for now test-latency uses macros with var-args which isn't supported on
## some compilers. Include the source in tar.gz, but don't build it by default
# noinst_PROGRAMS=test-latency 
# test_latency_SOURCES=test-latency.c
# test_latency_CPPFLAGS= $(MYSQL_INCLUDE) $(GLIB_CFLAGS)
# test_latency_LDADD= $(MYSQL_LIBS) $(GLIB_LIBS)

EXTRA_DIST=test-latency.c proxy-dtrace-provider.d CMakeLists.txt my_timer_cycles.il \
libxml-ext.c libxml-ext.h
