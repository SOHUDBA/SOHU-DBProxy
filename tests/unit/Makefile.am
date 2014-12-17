#  $%BEGINLICENSE%$
#  Copyright (c) 2009, 2011, Oracle and/or its affiliates. All rights reserved.
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



TESTS=\
	check_sql_tokenizer \
	check_mysqld_proto \
	check_plugin \
	check_loadscript \
	check_chassis_log \
	t_network_socket \
	t_network_queue \
	t_network_address \
	t_network_backend \
	t_network_injection \
	t_network_mysqld_packet \
	t_network_mysqld_type \
	t_network_mysqld_masterinfo \
	t_chassis_timings \
	t_chassis_shutdown_hooks \
	check_chassis_filemode \
	check_chassis_path \
	mytest_ip_range_create_from_str \
	check_lb_wrr \
	t_plugin_proxy_loadbalance \
	t_network_connection_scaler \
	check_glib_ext
	

t_chassis_shutdown_hooks_SOURCES = t_chassis_shutdown_hooks.c \
	$(top_srcdir)/src/chassis-shutdown-hooks.c \
	$(top_srcdir)/src/glib-ext.c

t_chassis_shutdown_hooks_CPPFLAGS = \
	-I$(top_srcdir)/src/ $(GLIB_CFLAGS) -I$(top_srcdir) \
	$(MYSQL_CFLAGS)

t_chassis_shutdown_hooks_LDADD = $(GLIB_LIBS) $(GTHREAD_LIBS)




check_chassis_filemode_SOURCES = check_chassis_filemode.c \
	$(top_srcdir)/src/chassis-filemode.c

check_chassis_filemode_CPPFLAGS = \
	-I$(top_srcdir)/src/ $(GLIB_CFLAGS) -I$(top_srcdir) \
	$(MYSQL_CFLAGS)

check_chassis_filemode_LDADD = $(GLIB_LIBS) $(GTHREAD_LIBS)

check_sql_tokenizer_SOURCES  = check_sql_tokenizer.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/glib-ext.c

check_sql_tokenizer_CPPFLAGS = -I$(top_srcdir)/lib/ $(GLIB_CFLAGS) -I$(top_srcdir)/src/
check_sql_tokenizer_LDADD    = $(GLIB_LIBS)

DISTCLEANFILES = \
	sql-tokenizer.c

check_mysqld_proto_SOURCES  = \
	check_mysqld_proto.c \
	$(top_srcdir)/src/network-mysqld-binlog.c \
	$(top_srcdir)/src/network-packet.c \
	$(top_srcdir)/src/network-mysqld-proto.c \
	$(top_srcdir)/src/glib-ext.c

check_mysqld_proto_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)
check_mysqld_proto_LDADD    = $(GLIB_LIBS)

t_network_mysqld_type_SOURCES  = \
	t_network_mysqld_type.c \
	$(top_srcdir)/src/network_mysqld_type.c \
	$(top_srcdir)/src/glib-ext.c

t_network_mysqld_type_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) 
t_network_mysqld_type_LDADD    = $(GLIB_LIBS)  $(EVENT_LIBS)


t_network_mysqld_packet_SOURCES  = \
	t_network_mysqld_packet.c \
	$(top_srcdir)/src/network-mysqld-packet.c \
	$(top_srcdir)/src/network-packet.c \
	$(top_srcdir)/src/network-mysqld-proto.c \
	$(top_srcdir)/src/network_mysqld_type.c \
	$(top_srcdir)/src/network_mysqld_proto_binary.c \
	$(top_srcdir)/src/network-queue.c \
	$(top_srcdir)/src/network-socket.c \
	$(top_srcdir)/src/network-address.c \
	$(top_srcdir)/src/glib-ext.c

t_network_mysqld_packet_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)  $(LIBXML2_CFLAGS)
t_network_mysqld_packet_LDADD    = $(GLIB_LIBS)  $(EVENT_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis.la $(top_builddir)/src/libmysql-chassis-regex.la \
$(top_builddir)/src/libmysql-proxy.la $(top_builddir)/src/libmysql-chassis-libxmlext.la

t_chassis_timings_SOURCES  = \
	t_chassis_timings.c \
	$(top_srcdir)/src/chassis-timings.c \
	$(top_srcdir)/src/glib-ext.c \
	$(top_srcdir)/src/my_rdtsc.c 

t_chassis_timings_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) 
t_chassis_timings_LDADD    = $(GLIB_LIBS)
if USE_SUNCC_ASSEMBLY
t_chassis_timings_CPPFLAGS += \
	${top_srcdir}/src/my_timer_cycles.il
endif




check_plugin_SOURCES  = check_plugin.c $(top_srcdir)/src/chassis-plugin.c
check_plugin_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(GMODULE_CFLAGS) $(LIBXML2_CFLAGS)
check_plugin_LDADD    = $(GLIB_LIBS) $(GMODULE_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-libxmlext.la

check_chassis_log_SOURCES  = check_chassis_log.c 
check_chassis_log_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(GMODULE_CFLAGS)
check_chassis_log_LDADD    = $(GLIB_LIBS) $(GMODULE_LIBS) $(top_builddir)/src/libmysql-chassis.la $(top_builddir)/src/libmysql-proxy.la

check_loadscript_SOURCES  = check_loadscript.c  
check_loadscript_CPPFLAGS = -I$(top_srcdir)/src/  $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(GMODULE_CFLAGS)
check_loadscript_LDADD    = $(GLIB_LIBS) $(GMODULE_LIBS) $(GTHREAD_LIBS) 

t_network_socket_SOURCES  = \
	t_network_socket.c \
	$(top_srcdir)/src/glib-ext.c \
	$(top_srcdir)/src/network-packet.c \
	$(top_srcdir)/src/network-mysqld-proto.c \
	$(top_srcdir)/src/network-mysqld-packet.c \
	$(top_srcdir)/src/network_mysqld_type.c \
	$(top_srcdir)/src/network_mysqld_proto_binary.c \
	$(top_srcdir)/src/network-address.c \
	$(top_srcdir)/src/network-queue.c \
	$(top_srcdir)/src/network-socket.c

t_network_socket_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(GMODULE_CFLAGS) $(EVENT_CFLAGS)  $(LIBXML2_CFLAGS)
t_network_socket_LDADD    = $(GLIB_LIBS) $(GMODULE_LIBS) $(GTHREAD_LIBS) $(EVENT_LIBS)  $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la $(top_builddir)/src/libmysql-chassis-libxmlext.la

t_network_queue_SOURCES  = \
	t_network_queue.c \
	$(top_srcdir)/src/glib-ext.c \
	$(top_srcdir)/src/network-queue.c

t_network_queue_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(GMODULE_CFLAGS) $(EVENT_CFLAGS)  $(LIBXML2_CFLAGS)
t_network_queue_LDADD    = $(GLIB_LIBS) $(GMODULE_LIBS) $(GTHREAD_LIBS) $(EVENT_LIBS)  $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-libxmlext.la

t_network_address_SOURCES  = \
	t_network_address.c \
	$(top_srcdir)/src/glib-ext.c \
	$(top_srcdir)/src/network-address.c 

t_network_address_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(GMODULE_CFLAGS) $(EVENT_CFLAGS) $(LIBXML2_CFLAGS)
t_network_address_LDADD    = $(GLIB_LIBS) $(GMODULE_LIBS) $(GTHREAD_LIBS) $(EVENT_LIBS)  $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-libxmlext.la


check_chassis_path_SOURCES = \
	check_chassis_path.c \
	$(top_srcdir)/src/chassis-log.c \
	$(top_srcdir)/src/chassis-mainloop.c \
	$(top_srcdir)/src/chassis-shutdown-hooks.c \
	$(top_srcdir)/src/chassis-event-thread.c \
	$(top_srcdir)/src/chassis-plugin.c \
	$(top_srcdir)/src/chassis-path.c \
	$(top_srcdir)/src/glib-ext.c \
	$(top_srcdir)/src/my_rdtsc.c \
	$(top_srcdir)/src/chassis-timings.c
check_chassis_path_CPPFLAGS = -I$(top_srcdir)/src $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(GMODULE_CFLAGS)  $(LIBXML2_CFLAGS)
check_chassis_path_LDADD    = $(GLIB_LIBS) $(GMODULE_LIBS) $(EVENT_LIBS) $(GTHREAD_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-regex.la \
$(top_builddir)/src/libmysql-proxy.la $(top_builddir)/src/libmysql-chassis-libxmlext.la
if USE_SUNCC_ASSEMBLY
check_chassis_path_CPPFLAGS += \
	${top_srcdir}/src/my_timer_cycles.il
endif


t_network_backend_SOURCES  = \
	t_network_backend.c \
	$(top_srcdir)/src/chassis-timings.c \
	$(top_srcdir)/src/glib-ext.c \
	$(top_srcdir)/src/network-backend.c \
	$(top_srcdir)/src/network-packet.c \
	$(top_srcdir)/src/network-mysqld-proto.c \
	$(top_srcdir)/src/network-mysqld-packet.c \
	$(top_srcdir)/src/network_mysqld_type.c \
	$(top_srcdir)/src/network_mysqld_proto_binary.c \
	$(top_srcdir)/src/network-conn-pool.c \
	$(top_srcdir)/src/network-address.c \
	$(top_srcdir)/src/network-queue.c \
	$(top_srcdir)/src/network-socket.c \
	$(top_srcdir)/src/my_rdtsc.c

t_network_backend_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(GMODULE_CFLAGS) $(EVENT_CFLAGS)  $(LIBXML2_CFLAGS)
t_network_backend_LDADD    = $(GLIB_LIBS) $(GMODULE_LIBS) $(GTHREAD_LIBS) $(EVENT_LIBS)  $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-libxmlext.la $(top_builddir)/src/libmysql-chassis.la \
 	$(top_builddir)/src/libmysql-proxy.la $(top_builddir)/src/libmysql-chassis-libxmlext.la
if USE_SUNCC_ASSEMBLY
t_network_backend_CPPFLAGS += \
	${top_srcdir}/src/my_timer_cycles.il
endif

t_network_mysqld_masterinfo_SOURCES  = \
	t_network_mysqld_masterinfo.c \
	$(top_srcdir)/src/glib-ext.c \
	$(top_srcdir)/src/network-packet.c \
	$(top_srcdir)/src/network-mysqld-proto.c \
	$(top_srcdir)/src/network-mysqld-masterinfo.c 

t_network_mysqld_masterinfo_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(GMODULE_CFLAGS) $(EVENT_CFLAGS)
t_network_mysqld_masterinfo_LDADD    = $(GLIB_LIBS) $(GMODULE_LIBS) $(GTHREAD_LIBS) $(EVENT_LIBS)

t_network_injection_SOURCES  = \
	t_network_injection.c \
	$(top_srcdir)/src/glib-ext.c \
	$(top_srcdir)/src/network-packet.c \
	$(top_srcdir)/src/network-mysqld-proto.c \
	$(top_srcdir)/src/network-mysqld-packet.c \
	$(top_srcdir)/src/network_mysqld_type.c \
	$(top_srcdir)/src/network_mysqld_proto_binary.c \
	$(top_srcdir)/src/network-injection.c \
	$(top_srcdir)/src/my_rdtsc.c \
	$(top_srcdir)/src/chassis-timings.c

t_network_injection_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(GMODULE_CFLAGS) $(EVENT_CFLAGS)  $(LIBXML2_CFLAGS)
t_network_injection_LDADD    = $(GLIB_LIBS) $(GMODULE_LIBS) $(GTHREAD_LIBS) $(EVENT_LIBS)  $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-regex.la \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la
if USE_SUNCC_ASSEMBLY
t_network_injection_CPPFLAGS += \
	${top_srcdir}/src/my_timer_cycles.il
endif

TESTS += t_chassis_keyfile
t_chassis_keyfile_SOURCES = \
	t_chassis_keyfile.c \
	$(top_srcdir)/src/chassis-keyfile.c \
	$(top_srcdir)/src/chassis-path.c
t_chassis_keyfile_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(GMODULE_CFLAGS) $(EVENT_CFLAGS) 
t_chassis_keyfile_LDADD    = $(GLIB_LIBS) $(GMODULE_LIBS) $(GTHREAD_LIBS) $(EVENT_LIBS)

TESTS += t_network_spnego
t_network_spnego_SOURCES = \
	t_network_spnego.c \
	$(top_srcdir)/src/network-spnego.c \
	$(top_srcdir)/src/network-asn1.c \
	$(top_srcdir)/src/network-packet.c \
	$(top_srcdir)/src/network-mysqld-proto.c \
	$(top_srcdir)/src/glib-ext.c
t_network_spnego_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)
t_network_spnego_LDADD    = $(GLIB_LIBS)

TESTS += t_network_asn1
t_network_asn1_SOURCES = \
	t_network_asn1.c \
	$(top_srcdir)/src/network-asn1.c \
	$(top_srcdir)/src/network-packet.c \
	$(top_srcdir)/src/network-mysqld-proto.c \
	$(top_srcdir)/src/glib-ext.c
t_network_asn1_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)
t_network_asn1_LDADD    = $(GLIB_LIBS)

TESTS += mytest_ip_range_create_from_str
mytest_ip_range_create_from_str_SOURCES = \
	mytest_ip_range_create_from_str.c \
	$(top_srcdir)/src/chassis-mainloop.c
mytest_ip_range_create_from_str_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_ip_range_create_from_str_LDADD    = $(GLIB_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis.la $(top_builddir)/src/libmysql-chassis-regex.la \
 $(top_builddir)/src/libmysql-proxy.la $(top_builddir)/src/libmysql-chassis-libxmlext.la

#TESTS += check_lb_wrr
check_lb_wrr_SOURCES = \
	check_lb_wrr.c
check_lb_wrr_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(GTHREAD_CFLAGS)
check_lb_wrr_LDADD = $(GLIB_LIBS) $(GTHREAD_LIBS) $(top_builddir)/src/libmysql-chassis-lb-wrr.la

t_plugin_proxy_loadbalance_SOURCES = \
	$(top_srcdir)/src/network-backend.c \
	t_plugin_proxy_loadbalance.c
t_plugin_proxy_loadbalance_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(GTHREAD_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
t_plugin_proxy_loadbalance_LDADD = $(GLIB_LIBS) $(GTHREAD_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-lb-wrr.la \
	$(top_builddir)/src/libmysql-proxy.la $(top_builddir)/src/libmysql-chassis-libxmlext.la


t_network_connection_scaler_SOURCES = \
	$(top_srcdir)/src/network-connection-scaler.c \
	t_network_connection_scaler.c
t_network_connection_scaler_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(GTHREAD_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
t_network_connection_scaler_LDADD = $(GLIB_LIBS) $(GTHREAD_LIBS) $(LIBXML2_LIBS)\
	$(top_builddir)/src/libmysql-chassis.la \
	$(top_builddir)/src/libmysql-proxy.la \
	$(top_builddir)/src/libmysql-chassis-libxmlext.la

#t_network_backends_addi_SOURCES = \
#	$(top_srcdir)/src/network-backend.c \
#	t_network_backends_addi.c
#t_network_backends_addi_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(GTHREAD_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
#t_network_backends_addi_LDADD = $(GLIB_LIBS) $(GTHREAD_LIBS) $(LIBXML2_LIBS)\
#	$(top_builddir)/src/libmysql-chassis.la \
#	$(top_builddir)/src/libmysql-chassis-lb-wrr.la \
#	$(top_builddir)/src/libmysql-proxy.la \
#	$(top_builddir)/src/libmysql-chassis-libxmlext.la


#test_libevent_SOURCE = test_libevent.c
#test_libevent_CPPFLAGS = $(GLIB_CFLAGS) $(GTHREAD_CFLAGS) -I$(top_srcdir)/src/ 
#test_libevent_LDADD = $(GLIB_LIBS) $(GTHREAD_LIBS) $(EVENT_LIBS) $(top_builddir)/src/libmysql-chassis.la \
# $(top_builddir)/src/libmysql-proxy.la

## end




TESTS += mytest_user_info_check
mytest_user_info_check_SOURCES = \
	mytest_user_info_check.c \
	$(top_srcdir)/src/chassis-mainloop.c
mytest_user_info_check_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS)  $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_user_info_check_LDADD    = $(GLIB_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis.la $(top_builddir)/src/libmysql-chassis-regex.la \
$(top_builddir)/src/libmysql-proxy.la $(top_builddir)/src/libmysql-chassis-libxmlext.la

TESTS += mytest_ip_check
mytest_ip_check_SOURCES = \
	mytest_ip_check.c \
	$(top_srcdir)/src/chassis-regex.c
mytest_ip_check_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_ip_check_LDADD    = $(GLIB_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-regex.la $(top_builddir)/src/libmysql-chassis.la \
 $(top_builddir)/src/libmysql-proxy.la $(top_builddir)/src/libmysql-chassis-libxmlext.la
 
TESTS += mytest_ip_range_get
mytest_ip_range_get_SOURCES = \
	mytest_ip_range_get.c \
	$(top_srcdir)/src/chassis-regex.c
mytest_ip_range_get_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS)  $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_ip_range_get_LDADD    = $(GLIB_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-regex.la $(top_builddir)/src/libmysql-chassis.la \
 $(top_builddir)/src/libmysql-proxy.la  $(top_builddir)/src/libmysql-chassis-libxmlext.la

TESTS += mytest_regex_for_character_set
mytest_regex_for_character_set_SOURCES = \
	mytest_regex_for_character_set.c \
	$(top_srcdir)/src/chassis-regex.c
mytest_regex_for_character_set_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(LIBXML2_CFLAGS)
mytest_regex_for_character_set_LDADD    = $(GLIB_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-regex.la $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

TESTS += mytest_packet_creation_and_append
mytest_packet_creation_and_append_SOURCES = \
	mytest_packet_creation_and_append.c \
	$(top_srcdir)/src/network-mysqld-packet.c \
	$(top_srcdir)/src/network-mysqld-proto.c \
	$(top_srcdir)/src/network_mysqld_type.c \
	$(top_srcdir)/src/network_mysqld_proto_binary.c \
	$(top_srcdir)/src/chassis-regex.c
mytest_packet_creation_and_append_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_packet_creation_and_append_LDADD    = $(GLIB_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-regex.la $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

TESTS += mytest_conn_status_check
mytest_conn_status_check_SOURCES = \
	mytest_conn_status_check.c \
	$(top_srcdir)/src/network-socket.c \
	$(top_srcdir)/src/network-conn-pool.c \
	$(top_srcdir)/src/network-address.c \
	$(top_srcdir)/src/network-queue.c \
	$(top_srcdir)/src/network-mysqld-packet.c \
	$(top_srcdir)/src/network-mysqld-proto.c \
	$(top_srcdir)/src/network_mysqld_type.c \
	$(top_srcdir)/src/network_mysqld_proto_binary.c
mytest_conn_status_check_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS) $(EVENT_CFLAGS) $(LIBXML2_CFLAGS)
mytest_conn_status_check_LDADD    = $(GLIB_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(EVENT_LIBS)\
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added sohu-inc.com
TESTS += mytest_zabbix_socket
mytest_zabbix_socket_SOURCES = \
	mytest_zabbix_socket.c \
	$(top_srcdir)/src/network-zabbix-socket.c \
	$(top_srcdir)/src/network-mysqld-proto.c \
	$(top_srcdir)/src/network_mysqld_proto_binary.c \
	$(top_srcdir)/src/network-packet.c \
	$(top_srcdir)/src/network-queue.c \
	$(top_srcdir)/src/network-address.c \
	$(top_srcdir)/src/network-socket.c \
	$(top_srcdir)/src/network_mysqld_type.c \
	$(top_srcdir)/src/network-mysqld-packet.c \
	$(top_srcdir)/src/chassis-mainloop.c
mytest_zabbix_socket_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(EVENT_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_zabbix_socket_LDADD    = $(GLIB_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-regex.la \
$(EVENT_LIBS) \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added sohu-inc.com
TESTS += mytest_zabbix_agentd
mytest_zabbix_agentd_SOURCES = \
	mytest_zabbix_agentd.c \
	$(top_srcdir)/src/chassis-mainloop.c \
	$(top_srcdir)/src/network-zabbix-socket.c \
	$(top_srcdir)/src/network-zabbix-agentd.c \
	$(top_srcdir)/src/network-mysqld-proto.c \
	$(top_srcdir)/src/network_mysqld_proto_binary.c \
	$(top_srcdir)/src/network-packet.c \
	$(top_srcdir)/src/network-queue.c \
	$(top_srcdir)/src/network-address.c \
	$(top_srcdir)/src/network-backend.c \
	$(top_srcdir)/src/network-conn-pool.c \
	$(top_srcdir)/src/lb_wrr.c \
	$(top_srcdir)/src/network_mysqld_type.c \
	$(top_srcdir)/src/network-mysqld-packet.c \
	$(top_srcdir)/src/network-socket.c \
	$(top_srcdir)/src/network-detection-event-thread.c \
	$(top_srcdir)/src/network-mysqld.c
mytest_zabbix_agentd_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(EVENT_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)\
-I$(top_srcdir)/lib/
mytest_zabbix_agentd_LDADD    = $(GLIB_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-regex.la \
$(EVENT_LIBS) \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added sohu-inc.com
#TESTS += mytest_zabbix_detect_thread
#mytest_zabbix_detect_thread_SOURCES = \
#	mytest_zabbix_detect_thread.c \
#	$(top_srcdir)/src/chassis-mainloop.c \
#	$(top_srcdir)/src/network-zabbix-socket.c \
#	$(top_srcdir)/src/network-zabbix-agentd.c \
#	$(top_srcdir)/src/network-detection-event-thread.c \
#	$(top_srcdir)/src/network-mysqld-proto.c \
#	$(top_srcdir)/src/network_mysqld_proto_binary.c \
#	$(top_srcdir)/src/network-packet.c \
#	$(top_srcdir)/src/network-queue.c \
#	$(top_srcdir)/src/network-address.c \
#	$(top_srcdir)/src/network-backend.c \
#	$(top_srcdir)/src/network-conn-pool.c \
#	$(top_srcdir)/src/lb_wrr.c \
#	$(top_srcdir)/src/network_mysqld_type.c \
#	$(top_srcdir)/src/network-mysqld-packet.c \
#	$(top_srcdir)/src/network-socket.c
#mytest_zabbix_detect_thread_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(EVENT_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
#mytest_zabbix_detect_thread_LDADD    = $(GLIB_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
#$(top_builddir)/src/libmysql-chassis-regex.la \
#$(EVENT_LIBS) \
#$(top_builddir)/src/libmysql-chassis.la \
#$(top_builddir)/src/libmysql-proxy.la \
#$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added sohu-inc.com
TESTS += mytest_zabbix_update_backend_status
mytest_zabbix_update_backend_status_SOURCES = \
	mytest_zabbix_update_backend_status.c
mytest_zabbix_update_backend_status_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(EVENT_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_zabbix_update_backend_status_LDADD    = $(GLIB_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-regex.la \
$(EVENT_LIBS) \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added sohu-inc.com
TESTS += mytest_admin_command_test_add_or_del
mytest_admin_command_test_add_or_del_SOURCES = \
	mytest_admin_command_test_add_or_del.c \
	$(top_srcdir)/plugins/admin/admin-plugin.c \
	$(top_srcdir)/src/network-security-sqlmode.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/network-sql-normalization.c \
	$(top_srcdir)/src/network-query-rate.c \
	$(top_srcdir)/src/network-inbytes-statistic.c \
	$(top_srcdir)/src/network-outbytes-statistic.c \
	$(top_srcdir)/src/glib-ext.c \
	$(top_srcdir)/src/glib-ext-ref.c
mytest_admin_command_test_add_or_del_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(EVENT_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_admin_command_test_add_or_del_LDADD    = $(GLIB_LIBS) ${OPENSSL_LIBS} $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(EVENT_LIBS) \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added sohu-inc.com
TESTS += mytest_admin_command_test_setonline_offline
mytest_admin_command_test_setonline_offline_SOURCES = \
	mytest_admin_command_test_setonline_offline.c \
	$(top_srcdir)/plugins/admin/admin-plugin.c \
	$(top_srcdir)/src/network-security-sqlmode.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/network-query-rate.c \
	$(top_srcdir)/src/network-inbytes-statistic.c \
	$(top_srcdir)/src/network-outbytes-statistic.c \
	$(top_srcdir)/src/network-sql-normalization.c
mytest_admin_command_test_setonline_offline_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(EVENT_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_admin_command_test_setonline_offline_LDADD    = $(GLIB_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-regex.la \
$(EVENT_LIBS) \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added sohu-inc.com
TESTS += mytest_admin_command_test_user_op
mytest_admin_command_test_user_op_SOURCES = \
	mytest_admin_command_test_user_op.c \
	$(top_srcdir)/plugins/admin/admin-plugin.c \
	$(top_srcdir)/src/network-security-sqlmode.c \
	$(top_srcdir)/src/network-query-rate.c \
	$(top_srcdir)/src/network-inbytes-statistic.c \
	$(top_srcdir)/src/network-outbytes-statistic.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/network-sql-normalization.c
mytest_admin_command_test_user_op_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(EVENT_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_admin_command_test_user_op_LDADD    = $(GLIB_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-regex.la \
$(EVENT_LIBS) \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added sohu-inc.com
TESTS += mytest_admin_command_conn_limit
mytest_admin_command_conn_limit_SOURCES = \
	mytest_admin_command_conn_limit.c \
	$(top_srcdir)/plugins/admin/admin-plugin.c \
	$(top_srcdir)/src/network-query-rate.c \
	$(top_srcdir)/src/network-inbytes-statistic.c \
	$(top_srcdir)/src/network-outbytes-statistic.c \
	$(top_srcdir)/src/network-security-sqlmode.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/network-sql-normalization.c
mytest_admin_command_conn_limit_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(EVENT_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_admin_command_conn_limit_LDADD    = $(GLIB_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-regex.la \
$(EVENT_LIBS) \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la


## added sohu-inc.com
TESTS += mytest_admin_command_poolconfig
mytest_admin_command_poolconfig_SOURCES = \
	mytest_admin_command_poolconfig.c \
	$(top_srcdir)/plugins/admin/admin-plugin.c \
	$(top_srcdir)/src/network-security-sqlmode.c \
	$(top_srcdir)/src/network-query-rate.c \
	$(top_srcdir)/src/network-inbytes-statistic.c \
	$(top_srcdir)/src/network-outbytes-statistic.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/network-sql-normalization.c
mytest_admin_command_poolconfig_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(EVENT_CFLAGS) $(MYSQL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_admin_command_poolconfig_LDADD    = $(GLIB_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-regex.la \
$(EVENT_LIBS) \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added by sohu-inc.com
TESTS += mytest_sql_normalization
mytest_sql_normalization_SOURCES = \
	mytest_sql_normalization.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/network-sql-normalization.c
mytest_sql_normalization_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)  $(OPENSSL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_sql_normalization_LDADD    = $(GLIB_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added by sohu-inc.com
TESTS += mytest_sql_security_manage
mytest_sql_security_manage_SOURCES = \
	mytest_sql_security_manage.c \
	$(top_srcdir)/src/network-security-sqlmode.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/network-sql-normalization.c
mytest_sql_security_manage_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)  $(LIBXML2_CFLAGS)
mytest_sql_security_manage_LDADD    = $(GLIB_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libsql-tokenizer.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added sohu-inc.com
TESTS += mytest_admin_command_test_sqlrule_manage
mytest_admin_command_test_sqlrule_manage_SOURCES = \
	mytest_admin_command_test_sqlrule_manage.c \
	$(top_srcdir)/plugins/admin/admin-plugin.c \
	$(top_srcdir)/src/network-security-sqlmode.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/network-query-rate.c \
	$(top_srcdir)/src/network-inbytes-statistic.c \
	$(top_srcdir)/src/network-outbytes-statistic.c \
	$(top_srcdir)/src/network-sql-normalization.c
mytest_admin_command_test_sqlrule_manage_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(EVENT_CFLAGS) $(MYSQL_CFLAGS)  $(LIBXML2_CFLAGS)
mytest_admin_command_test_sqlrule_manage_LDADD    = $(GLIB_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-regex.la \
$(EVENT_LIBS) \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added by sohu-inc.com
TESTS += mytest_sql_statistics
mytest_sql_statistics_SOURCES = \
	mytest_sql_statistics.c \
	$(top_srcdir)/src/network-sql-normalization.c \
	$(top_srcdir)/src/network-sql-statistics.c
mytest_sql_statistics_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)  $(LIBXML2_CFLAGS) $(EVENT_CFLAGS)
mytest_sql_statistics_LDADD    = $(GLIB_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(EVENT_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libsql-tokenizer.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

check_glib_ext_SOURCES = check_glib_ext.c $(top_builddir)/src/glib-ext.c
check_glib_ext_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS)
check_glib_ext_LDADD = $(GLIB_LIBS)

TESTS += mytest_master_elect
mytest_master_elect_SOURCES = mytest_master_elect.c \
	$(top_srcdir)/src/chassis-log.c \
	$(top_srcdir)/src/network-backend.c \
	$(top_srcdir)/src/network-backend-status-updater.c
mytest_master_elect_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)  $(LIBXML2_CFLAGS)
mytest_master_elect_LDADD    = $(GLIB_LIBS) $(top_builddir)/src/libmysql-chassis.la $(top_builddir)/src/libmysql-proxy.la $(top_builddir)/src/libmysql-chassis-libxmlext.la

TESTS += mytest_adjust_backend
mytest_adjust_backend_SOURCES = mytest_adjust_backend.c \
	$(top_srcdir)/src/chassis-log.c \
	$(top_srcdir)/src/network-backend.c \
	$(top_srcdir)/src/network-detection-event-thread.c
mytest_adjust_backend_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)  $(LIBXML2_CFLAGS)
mytest_adjust_backend_LDADD    = $(GLIB_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis.la $(top_builddir)/src/libmysql-proxy.la $(top_builddir)/src/libmysql-chassis-libxmlext.la


TESTS += t_network_mysql_error
t_network_mysql_error_SOURCES = t_network_mysql_error.c \
	$(top_srcdir)/src/chassis-log.c
t_network_mysql_error_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)  $(LIBXML2_CFLAGS)
t_network_mysql_error_LDADD    = $(GLIB_LIBS) $(top_builddir)/src/libmysql-chassis.la $(top_builddir)/src/libmysql-proxy.la

## added sohu-inc.com
TESTS += mytest_para_limit_process_check
mytest_para_limit_process_check_SOURCES = \
	mytest_para_limit_process_check.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/network-sql-normalization.c \
	$(top_srcdir)/src/network-para-exec-limit.c \
	$(top_srcdir)/src/network-para-exec-process.c
mytest_para_limit_process_check_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)  $(OPENSSL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_para_limit_process_check_LDADD    = $(GLIB_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

TESTS += t_chassis_limits
t_chassis_limits_SOURCES = t_chassis_limits.c \
	$(top_srcdir)/src/chassis-limits.c
t_chassis_limits_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS)
t_chassis_limits_LDADD    = $(GLIB_LIBS)

TESTS += t_network_connection_state
t_network_connection_state_SOURCES = t_network_connection_state.c \
	$(top_srcdir)/src/network-connection-state.c \
	$(top_srcdir)/src/chassis-log.c
t_network_connection_state_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS)
t_network_connection_state_LDADD    = $(GLIB_LIBS) $(top_builddir)/src/libmysql-chassis-timing.la

## added sohu-inc.com
TESTS += mytest_admin_command_test_para_limit
mytest_admin_command_test_para_limit_SOURCES = \
	mytest_admin_command_test_para_limit.c \
	$(top_srcdir)/plugins/admin/admin-plugin.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/network-sql-normalization.c \
	$(top_srcdir)/src/network-para-exec-limit.c \
	$(top_srcdir)/src/network-query-rate.c \
	$(top_srcdir)/src/network-inbytes-statistic.c \
	$(top_srcdir)/src/network-outbytes-statistic.c \
	$(top_srcdir)/src/network-para-exec-process.c
mytest_admin_command_test_para_limit_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)  $(OPENSSL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_admin_command_test_para_limit_LDADD    = $(GLIB_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-regex.la \
$(EVENT_LIBS) \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added sohu-inc.com
TESTS += mytest_admin_command_test_dura_limit
mytest_admin_command_test_dura_limit_SOURCES = \
	mytest_admin_command_test_dura_limit.c \
	$(top_srcdir)/plugins/admin/admin-plugin.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/network-sql-normalization.c \
	$(top_srcdir)/src/network-dura-exec-limit.c \
	$(top_srcdir)/src/network-query-rate.c \
	$(top_srcdir)/src/network-inbytes-statistic.c \
	$(top_srcdir)/src/network-outbytes-statistic.c \
	$(top_srcdir)/src/network-dura-exec-process.c
mytest_admin_command_test_dura_limit_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)  $(OPENSSL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_admin_command_test_dura_limit_LDADD    = $(GLIB_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-regex.la \
$(EVENT_LIBS) \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

## added sohu-inc.com
TESTS += mytest_admin_command_test_listen_op
mytest_admin_command_test_listen_op_SOURCES = \
	mytest_admin_command_test_listen_op.c \
	$(top_srcdir)/plugins/admin/admin-plugin.c \
	$(top_srcdir)/src/sql-tokenizer.l \
	$(top_srcdir)/src/sql-tokenizer-tokens.c \
	$(top_srcdir)/src/sql-tokenizer-keywords.c \
	$(top_srcdir)/src/network-sql-normalization.c
mytest_admin_command_test_listen_op_CPPFLAGS = -I$(top_srcdir)/src/ $(GLIB_CFLAGS) $(MYSQL_CFLAGS)  $(OPENSSL_CFLAGS) $(LIBXML2_CFLAGS)
mytest_admin_command_test_listen_op_LDADD    = $(GLIB_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(top_builddir)/src/libmysql-chassis-glibext.la \
$(top_builddir)/src/libmysql-chassis-regex.la \
$(EVENT_LIBS) \
$(top_builddir)/src/libmysql-chassis.la \
$(top_builddir)/src/libmysql-proxy.la \
$(top_builddir)/src/libmysql-chassis-libxmlext.la

check_PROGRAMS=$(TESTS)

EXTRA_DIST = CMakeLists.txt \
test_libevent.c \
test_config.xml

## remove the test-output
distclean-local:
	rm -f ${builddir}/test-*.txt ${builddir}/core.* ${builddir}/vgcore.*
