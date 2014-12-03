/*
 * network-zabbix-agentd.h
 *
 *  Created on: 2013-6-24
 *      Author: jinxuanhou
 */

#ifndef NETWORK_ZABBIX_AGENTD_H_
#define NETWORK_ZABBIX_AGENTD_H_

#include "network-backend.h"
#include "network-zabbix-socket.h"
/**
 * @author 这里我们实现dbproxy 与 zabbix agentd 通信状态机处理
 */

typedef enum backend_result_check_status_t{
	BACKEND_CHECK_UP = 0,
	BACKEND_CHECK_DOWN = 1,
	BACKEND_CHECK_NOTSUPPORT = 2,
	BACKEND_CHECK_RESULT_ERROR = 3
} backend_result_check_status_t;

typedef struct {
	int bk_errno;
	GString *bk_status;
	GString *bk_errmsg;
} backend_result;

NETWORK_API backend_result *backend_result_new();
NETWORK_API void backend_result_free(backend_result *result);
NETWORK_API void backend_result_set(const char *str, backend_result *ret);
NETWORK_API backend_result_check_status_t network_zabbix_result_process(GString *result, backend_result *bk_result); /**< 主要是处理能正常从zabbix获取脚本结果的情况 */

NETWORK_API void network_zabbix_con_handle(int event_fd, short events, void *user_data);
#endif /* NETWORK_ZABBIX_AGENTD_H_ */
