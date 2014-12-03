if USE_WRAPPER_SCRIPT
## create wrappers for all the binaries defined in src/Makefile
bin_SCRIPTS             = mysql-binlog-dump mysql-myisam-dump mysql-proxy mysql-proxyd

CLEANFILES = $(bin_SCRIPTS)

else

bin_SCRIPTS = mysql-proxyd setup create-user pxc_check_status mysql_check_status
CLEANFILES = $(bin_SCRIPTS)
#dist_bin_SCRIPTST = mysql-proxy.cnf.sample zabbix_agentd.sample pcx_check_status.sample
EXTRA_DIST = mysql-proxy.cnf.sample zabbix_agentd.cnf.sample mysql-proxy.xml.sample

endif

