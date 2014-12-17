# $%BEGINLICENSE%$
# $%ENDLICENSE%$

MACRO(CHASSIS_PLUGIN_INSTALL _plugin_name)
	IF(NOT WIN32)
		INSTALL(TARGETS ${_plugin_name}
			DESTINATION lib/mysql-proxy/plugins)
	ELSE(NOT WIN32)
		## on win32 the chassis plugins gets prefixed with plugin- and end up in bin/
		GET_TARGET_PROPERTY(built_location ${_plugin_name} LOCATION)
		STRING(REPLACE "$(OutDir)" "${CMAKE_BUILD_TYPE}" built_location ${built_location})
		INSTALL(FILES ${built_location}
			DESTINATION bin/
			RENAME plugin-${_plugin_name}${CMAKE_SHARED_LIBRARY_SUFFIX}
		)
		## install the .pdb too
		IF(CMAKE_BUILD_TYPE MATCHES "RelWithDebInfo")
			STRING(REPLACE ${CMAKE_SHARED_LIBRARY_SUFFIX} ".pdb" pdb_location ${built_location})
			INSTALL(FILES
				${pdb_location}
				DESTINATION bin
			)
		ENDIF()
	ENDIF(NOT WIN32)
ENDMACRO(CHASSIS_PLUGIN_INSTALL _plugin_name)

