SUBDIRS=base bugs

TESTS_ENVIRONMENT = \
	MYSQL_TEST_BIN="${MYSQL_TEST_BIN}" \
	@DYNLIB_PATH_VAR@="${top_builddir}/src/.libs/:${@DYNLIB_PATH_VAR@}" \
	MYSQL_PROXY_VERSION="${PACKAGE_VERSION}" \
	top_builddir=${top_builddir} \
	builddir=${builddir} \
	srcdir=${srcdir}/ \
	BUILD_OS=${build} 
TESTS=base

#check_PROGRAMS=lua-runner

#lua_runner_SOURCES=lua_runner.c
#lua_runner_LDFLAGS=${LUA_LDFLAGS}
#lua_runner_LDADD=${LUA_LIBS}
#lua_runner_CFLAGS=${LUA_CFLAGS}




clean-local:
	-find . -type f -name "*.log" -exec rm {} \;
