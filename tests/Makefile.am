SUBDIRS = unit suite mytest

EXTRA_DIST = CMakeLists.txt gtester-to-junit.xslt

noinst_PROGRAMS = c-api-burst

c_api_burst_SOURCES = c-api-burst.c
c_api_burst_LDFLAGS = ${MYSQL_LIBS} ${GTHREAD_LIBS}
c_api_burst_CPPFLAGS = ${MYSQL_CFLAGS} ${GTHREAD_CFLAGS}
