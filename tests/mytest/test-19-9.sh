#!/bin/bash

bash $SCRIPT_DIR/start_proxy.sh

t=0
for i in {1..5}
do
  for j in {1..20}
  do
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest -ABs -e "select * from d1.t1 where intcol1 in (100669, 63299708);" 1>/dev/null 2>&1)&
  done

  #设置sql限制列表
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "showsqlfilter;" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -uadtest -padtest -ABs -e "addsqlfilter --username=proxy2 --filter-sql='select * from t1 where intcol1 in (100669)' --database=d1 --filter-type=single --filter-action=block;" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "showsqlfilter;" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669, 63299708);" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RO_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669);" 1>/dev/null 2>&1)&

  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -uadtest -padtest -ABs -e "addsqlfilter --username=proxy2 --filter-sql='select * from t1 where intcol1 in (100669)' --database=d1 --filter-type=template --filter-action=block;" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "showsqlfilter;" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669, 63299708);" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RO_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669);" 1>/dev/null 2>&1)&


  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -uadtest -padtest -ABs -e "setfilteraction --username=proxy2 --database=d1 --filter-sql='select * from t1 where intcol1 in (100669)' --filter-type=single --filter-action=warning;" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 limit 1;" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "showsqlfilter;" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669, 63299708);" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RO_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669);" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669, 'A');" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RO_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in ('aaaaa');" 1>/dev/null 2>&1)&

  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -uadtest -padtest -ABs -e "setfilteraction --username=proxy2 --database=d1 --filter-sql='select * from t1 where intcol1 in (100669, 63299708);' --filter-type=template --filter-action=warning;" 1>/dev/null 2>&1)&

  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "showsqlfilter;" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669, 63299708);" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RO_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669);" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669, 'A');" 1>/dev/null 2>&1)&
  ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RO_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in ('aaaaa');" 1>/dev/null 2>&1)&

  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -uadtest -padtest -ABs -e "setfilteraction --username=proxy2 --database=d1 --filter-sql='select * from t1 limit 1' --filter-type=single --filter-action=block;" 1>/dev/null 2>&1)&

  for j in {1..20}
  do
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 limit 1;" 1>/dev/null 2>&1)&
  done

  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -u adtest -padtest -ABs -e "showsqlfilter;" 1>/dev/null 2>&1)&

  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -uadtest -padtest -ABs -e "setfilterswitch --username=proxy2 --database=d1 --filter-sql='select * from t1 limit 1' --filter-type=single --filter-disabled=true;" 1>/dev/null 2>&1)&

  for j in {1..20}
  do
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 limit 1;" 1>/dev/null 2>&1)&
  done

  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -uadtest -padtest -ABs -e "delsqlfilter --username=proxy2 --filter-sql='select * from t1 where intcol1 in (100669)' --database=d1 --filter-type=single;" 1>/dev/null 2>&1)&

  for j in {1..20}
  do
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 limit 1;" 1>/dev/null 2>&1)&
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669, 63299708);" 1>/dev/null 2>&1)&
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RO_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669);" 1>/dev/null 2>&1)&
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669, 'A');" 1>/dev/null 2>&1)&
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RO_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in ('aaaaa');" 1>/dev/null 2>&1)&
  done

  ($MYSQL -h $MYSQL_PROXY_ADMIN_IP -P $MYSQL_PROXY_ADMIN_PORT -uadtest -padtest -ABs -e "delsqlfilter --username=proxy2 --filter-sql='select * from t1 where intcol1 in (100669)' --database=d1 --filter-type=template;" 1>/dev/null 2>&1)&

  for j in {1..20}
  do
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 limit 1;" 1>/dev/null 2>&1)&
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669, 63299708);" 1>/dev/null 2>&1)&
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RO_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669);" 1>/dev/null 2>&1)&
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RW_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in (100669, 'A');" 1>/dev/null 2>&1)&
    ($MYSQL -h $MYSQL_PROXY_WORKER_IP -P $MYSQL_PROXY_RO_PORT -u test -ptest d1 -ABs -e "select * from t1 where intcol1 in ('aaaaa');" 1>/dev/null 2>&1)&
  done

  _t=$?
  ((t=t+_t))
done
wait
r="0"
ret=0
if [ "$t" = "$r" ]; then
  ret=0
else
  echo "expected result: \"$r\""
  echo "actual result: \"$t\""
  ret=1
fi


bash $SCRIPT_DIR/stop_proxy.sh

exit $ret
#eof
