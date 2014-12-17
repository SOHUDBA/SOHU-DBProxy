/*
 * network-zabbix-agentd.c
 *
 *  Created on: 2013-6-24
 *      Author: jinxuanhou
 */
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <glib.h>
#include "event.h"

#include "network-zabbix-socket.h"
#include "network-zabbix-agentd.h"

#define ZABBIX_HEADER_LEN 5
#define ZABBIX_LENGTH_LEN 8
#define ZABBIX_RESULT_NOTSUPPORT "ZBX_NOTSUPPORTED"
#define ZABBIX_RESULT_REG "errno=\\d+;status=[^;]*;errmsg=[^;]*"

#define C(str) str, sizeof(str) - 1

static GRegex *ret_regex = NULL;

/**
 * @author sohu-inc.com
 * 构建backend_result 变量
 * @return
 */
backend_result *backend_result_new() {
	backend_result *result = NULL;
	result = g_new0(backend_result, 1);
	result->bk_errno = 0;
	result->bk_errmsg = g_string_new(NULL);
	result->bk_status = g_string_new(NULL);
	return result;
}

/**
 * @author sohu-inc.com
 * 销毁变量
 * @param result
 */
void backend_result_free(backend_result *result) {
	if (!result)
		return;
	result->bk_errno = 0;
	if (result->bk_errmsg) {
		g_string_free(result->bk_errmsg, TRUE);
		result->bk_errmsg = NULL;
	}
	if (result->bk_status) {
		g_string_free(result->bk_status, TRUE);
		result->bk_status = NULL;
	}
	g_free(result);
}

/** 获取 xxxx=AA 格式的AA，并转换成整数 */
static int get_protocol_int(const char *str, int *bk_errno) {

	if (str) {
		const char *tmp = str;
		while ('\0' != *tmp && '=' != *tmp) {
			tmp++;
		}
		if ('\0' != *tmp) {
			tmp++;
		}
		*bk_errno = atoi(tmp);
	}
	return 0;
}

/** 获取 xxxx=ccc 的ccc字段，作为字符串 */
static int get_protocol_string(const char *str, GString *msg) {
	if (str) {
		const char *tmp = str;
		while ('\0' != *tmp && '=' != *tmp) {
			tmp++;
		}
		if ('\0' != *tmp) {
                        tmp++;
                }
		if (msg) {
			g_string_truncate(msg, 0);
			g_string_append(msg, tmp);
		}
	}
	return 0;
}

/**
 * @suho-inc.com
 * 用str串里面的内容设置 ret的变量
 * @param str
 * @param ret
 */
void backend_result_set(const char *str, backend_result *ret) {
	if (!str)
		return;

	gchar ** array = g_strsplit(str, ";", 3);
	int index = 0;
	char *tmp = NULL;

	/** 处理bk_errno 的值 */
	if (NULL != (tmp = array[index++])) {
		if (0 == g_ascii_strncasecmp(tmp, C("errno"))) {
			get_protocol_int(tmp, &(ret->bk_errno));
		}
	}

	/** 处理status的值 */
	if (NULL != (tmp = array[index++])) {
		if (0 == g_ascii_strncasecmp(tmp, C("status"))) {
			g_string_truncate(ret->bk_status, 0);
			get_protocol_string(tmp, ret->bk_status);
		}
	}

	/** 处理errmsg */
	if (NULL != (tmp = array[index])) {
		if (0 == g_ascii_strncasecmp(tmp, C("errmsg"))) {
			g_string_truncate(ret->bk_errmsg, 0);
			get_protocol_string(tmp, ret->bk_errmsg);
		}
	}

	g_strfreev (array);
	array = NULL;
}

/**
 * @author sohu-inc.com
 * 主要是处理能正常从zabbix获取脚本结果的情况
 * @param result 检测脚本返回的后端检测的状态
 * @param bk_result
 * @return
 */
backend_result_check_status_t network_zabbix_result_process(GString *result,
		backend_result *bk_result) {
	backend_result_check_status_t ret;
	if (!result || !result->str)
		return BACKEND_CHECK_RESULT_ERROR;

	if (0 == result->len)
		return BACKEND_CHECK_RESULT_ERROR;

	if (0 == g_strcmp0(result->str, ZABBIX_RESULT_NOTSUPPORT))
		return BACKEND_CHECK_NOTSUPPORT;

	if (!ret_regex) {
		g_message("[%s]: why  global variable still null", G_STRLOC);
		ret_regex = g_regex_new(ZABBIX_RESULT_REG,
	            0,
	            0,
	            NULL);
	}

	GMatchInfo *match_info = NULL;

	g_regex_match(ret_regex, result->str, 0, &match_info);

	if (g_match_info_matches (match_info)) {
		/** 处理匹配出来的符合约定的格式的返回结果 */
		gchar *ret_str = g_match_info_fetch (match_info, 0);
		backend_result_set(ret_str, bk_result);
		if (0 == bk_result->bk_errno) {
			ret = BACKEND_CHECK_UP;
		} else {
			ret = BACKEND_CHECK_DOWN;
		}
		if (ret_str) {
			g_free(ret_str);
		}
	} else {
		/** 返回的结果不符合约定的格式 */
		ret = BACKEND_CHECK_RESULT_ERROR;
	}
	g_match_info_free(match_info);
	//g_regex_unref(); //全局变量？能够大家共用吗？
	return ret;
}


/**
 * @author sohu-inc.com
 * dbproxy 与 zabbix agentd 间socket通信的状态处理函数
 * @param event_fd
 * @param events
 * @param user_data
 */
void network_zabbix_con_handle(int event_fd, short events, void *user_data) {
	zabbix_socket *sock = NULL;

	g_assert(user_data);
	sock = (zabbix_socket *)user_data;
	g_assert(event_fd == sock->fd);

	if (-1 == event_fd && events != 0) {
		g_error("[%s]: fd == -1, how can this happen? Yes, when we start call status detection?", G_STRLOC);
	}

	if (EV_READ == events) {
		g_debug("[%s]: SOCKET = %d got event: EV_READ. con_state is: %s",
				G_STRLOC,
				event_fd,
				zabbix_con_state_name(sock->state));
		int b = -1;

		if (ioctl(sock->fd, FIONREAD, &b)) {
			g_debug("[%s]: ioctl execute error, we will close the socket.error message is：%s",
					G_STRLOC,
					g_strerror(errno));
			/**
			 * 
			 * @note 接下来该如何设置socket的状态？我们会暂时认为socket的状态是有问题的，将socket的状态设置为出错
			 */
			// sock->is_over = TRUE; /**< 该字段的设置只有在状态为ZABBIX_CON_STATE_CLOSE_CONNECT时设置*/
			// sock->is_success = FALSE; 
			/**
			 * 这个这里可以不用设置,只有在经历六个完整的读写阶段我们才认为dbproxy与zabbix.
			 * 只有在ZABBIX_CON_STATE_READ_RESULT成功执行之后才会设置sock->is_success,
			 * 其他均不需要单独的设置
			 */
			sock->exit_status = ZABBIX_STATUS_MACHINE_NETWORK_ERROR;
			sock->state = ZABBIX_CON_STATE_CLOSE_CONNECT;
		} else if (0 != b) {
			//sock->to_read = b;
			g_debug("[%s]: there are %d byte to read for SOCKET = %d",
					G_STRLOC,
					sock->to_read,
					sock->fd);
		} else { /**< for Linux: zabbix agentd 关闭了dbproxy与他的连接*/
			g_debug("[%s]: zabbix agentd have closed the connection. we will deaolloc the memory.",
					G_STRLOC);
			/**< 接下来我们来设置socket的状态*/
			if (sock->state != ZABBIX_CON_STATE_CLOSE_CONNECT) {
				//说明dbproxy这边还是希望能够发送数据或读取结果的（中间状态时，zabbix端关闭连接都是不正常的）
				sock->exit_status = ZABBIX_STATUS_MACHINE_SERVER_CLOSE_CON;
			}
			sock->state = ZABBIX_CON_STATE_CLOSE_CONNECT;
		}
	} else if (EV_TIMEOUT == events) {
		if (sock->state != ZABBIX_CON_STATE_INIT) {
			g_debug("[%s]: socket = %d got event: EV_TIMEOUT. state of connection is: %s",
					G_STRLOC,
					sock->fd,
					zabbix_con_state_name(sock->state));
			sock->exit_status = ZABBIX_STATUS_MACHINE_TIMEOUT;
			sock->state = ZABBIX_CON_STATE_CLOSE_CONNECT;
		}
	} else if (EV_WRITE == events) {
		g_debug("[%s]: socket = %d got event: EV_WRITE. state of connection is: %s",
				G_STRLOC,
				sock->fd,
				zabbix_con_state_name(sock->state));
	}

/**
 * @note 为了能够知道我们需要将事件注册到哪个event_base上面，我们需要在zabbix_socket中保存处理该socket
 *       thread指针，如果不这样的话可能不太好弄。这里如何获取到event_base一定要解决好！！！！
 */
/*
#define WAIT_FOR_EVENT(ev_struct, ev_type, timeout) \
	event_set(&(ev_struct->event), ev_struct->fd, ev_type, network_zabbix_con_handle, user_data); \
	event_base_set(ev_struct->event_base_thread, &(ev_struct->event)); \
	event_add(&(ev_struct->event), timeout);
*/
#define WAIT_FOR_EVENT(ev_struct, ev_type, timeout) \
	event_assign(&(ev_struct->event), ev_struct->thread_event_base, ev_struct->fd, ev_type, network_zabbix_con_handle, user_data); \
	event_add(&(ev_struct->event), timeout);

	zabbix_con_state ostate;
	do {
		struct timeval timeout;
		ostate = sock->state;

		switch (sock->state) {
		case ZABBIX_CON_STATE_INIT: {
			/**
			 * @note 这个状态我们用于连接的创建，主要是考虑到异步连接的建立，
			 * 		   一般connect第一次返回的为-1，errno 为E_NET_INPROGRESS，需要等待fd写就绪
			 *       会将sock的状态设置为ZABBIX_CON_STATE_WRITE_HEAD
			 */
			zabbix_socket_retval_t ret_t = zabbix_agent_connect_dispatch(sock);
			switch (ret_t) {
			case ZABBIX_SOCKET_SUCCESS:
				// socket 连接创建成功
				g_debug(
						"[%s]: connect to zabbix agentd success, go on with status checking",
						G_STRLOC);
				sock->state = ZABBIX_CON_STATE_WRITE_HEAD;
				break;
			case ZABBIX_SOCKET_ERROR_RETRY:
				g_debug(
						"[%s]: socket have not been ready for write when initialization",
						G_STRLOC);
				timeout.tv_sec = sock->write_timeout_seconds;
				timeout.tv_usec = 0;
				WAIT_FOR_EVENT(sock, EV_WRITE, &timeout)
				;
				return;
			default:
				// socket 连接创建失败
				g_message(
						"[%s]: connect to zabbix agentd error, we will skip status checking this round",
						G_STRLOC);
				sock->exit_status = ZABBIX_STATUS_MACHINE_NETWORK_ERROR;
				sock->state = ZABBIX_CON_STATE_CLOSE_CONNECT;
				break;
			}
			break;
		}
		case ZABBIX_CON_STATE_WRITE_HEAD: {
			/**
			 * 该状态负责向zabbix_agent发送头数据包
			 * 可能会有三个状态：成功、重试或错误
			 */
			switch (zabbix_agent_write_head(sock)) {
			case ZABBIX_SOCKET_SUCCESS:
				sock->state = ZABBIX_CON_STATE_WRITE_LENGTH;
				break;
			case ZABBIX_SOCKET_WAIT_FOR_EVENT:
				g_debug("[%s]: write head need retry.", G_STRLOC);
				timeout.tv_sec = sock->write_timeout_seconds;
				timeout.tv_usec = 0;
				WAIT_FOR_EVENT(sock, EV_WRITE, &timeout)
				;
				return;
			case ZABBIX_SOCKET_ERROR_RETRY:
			case ZABBIX_SOCKET_ERROR:
				g_critical("[%s]: write head packet to zabbix agentd error.",
						G_STRLOC);
				/**
				 * head数据包写错误，将状态机是否正常运行状态设置为FALSE;
				 * 同时将状态机的退出状态设置为网络错误。
				 */
				sock->exit_status = ZABBIX_STATUS_MACHINE_NETWORK_ERROR;
				sock->state = ZABBIX_CON_STATE_CLOSE_CONNECT;
				break;
			}
			break;
		}
		case ZABBIX_CON_STATE_WRITE_LENGTH: {
			/**
			 * 该状态负责向zabbix agent 发送数据的长度
			 */
			guint64 len = 0;
			g_assert(sock->cmd);
			g_assert(sock->cmd->len > 0);
			len = (guint64)(sock->cmd->len);
			switch (zabbix_agent_write_length(sock, len)) {
			case ZABBIX_SOCKET_SUCCESS:
				sock->state = ZABBIX_CON_STATE_WRITE_CMD;
				break;
			case ZABBIX_SOCKET_WAIT_FOR_EVENT:
				g_debug("[%s]: write command length need retry.", G_STRLOC);
				timeout.tv_sec = sock->write_timeout_seconds;
				timeout.tv_usec = 0;
				WAIT_FOR_EVENT(sock, EV_WRITE, &timeout)
				;
				return;
			case ZABBIX_SOCKET_ERROR_RETRY:
			case ZABBIX_SOCKET_ERROR:
				g_critical("[%s]: write length packet to zabbix agentd error.",
						G_STRLOC);
				/**
				 * 长度数据包写错误，将状态机是否正常运行状态设置为FALSE;
				 * 同时将状态机的退出状态设置为网络错误。
				 */
				sock->exit_status = ZABBIX_STATUS_MACHINE_NETWORK_ERROR;
				sock->state = ZABBIX_CON_STATE_CLOSE_CONNECT;
				break;
			}
			break;
		}
		case ZABBIX_CON_STATE_WRITE_CMD: {
			/**
			 * 该状态负责向zabbix agent 发送实际的请求数据包
			 */
			g_assert(sock->cmd);
			g_assert(sock->cmd->str);
			switch (zabbix_agent_write_cmd(sock, sock->cmd->str)) {
			case ZABBIX_SOCKET_SUCCESS:
				sock->to_read = ZABBIX_HEADER_LEN;
				sock->state = ZABBIX_CON_STATE_READ_HEAD;
				break;
			case ZABBIX_SOCKET_WAIT_FOR_EVENT:
				g_debug("[%s]: write command need retry.", G_STRLOC);
				timeout.tv_sec = sock->write_timeout_seconds;
				timeout.tv_usec = 0;
				WAIT_FOR_EVENT(sock, EV_WRITE, &timeout)
				;
				return;
			case ZABBIX_SOCKET_ERROR_RETRY:
			case ZABBIX_SOCKET_ERROR:
				g_critical("[%s]: write command packet to zabbix agentd error.",
						G_STRLOC);
				/**
				 * 命令数据包写错误，将状态机是否正常运行状态设置为FALSE;
				 * 同时将状态机的退出状态设置为网络错误。
				 */
				sock->exit_status = ZABBIX_STATUS_MACHINE_NETWORK_ERROR;
				sock->state = ZABBIX_CON_STATE_CLOSE_CONNECT;
				break;
			}
			break;
		}
		case ZABBIX_CON_STATE_READ_HEAD: {
			/**
			 * 实现对从zabbix agent 读取头数据包
			 * 同时会将读取的数据truncate掉
			 */
			switch (zabbix_agent_read_head(sock)) {
			case ZABBIX_SOCKET_SUCCESS:
				/**
				 * @note 需要检查确保读取的是"ZBXD \1"
				 */
				sock->to_read = ZABBIX_LENGTH_LEN;
				g_string_truncate(sock->result, 0);
				sock->state = ZABBIX_CON_STATE_READ_LENGTH;
				break;
			case ZABBIX_SOCKET_WAIT_FOR_EVENT:
				g_debug("[%s]: read head packet need retry.", G_STRLOC);
				timeout.tv_sec = sock->read_timeout_seconds;
				timeout.tv_usec = 0;
				WAIT_FOR_EVENT(sock, EV_READ, &timeout)
				;
				return;
			case ZABBIX_SOCKET_ERROR_RETRY:
			case ZABBIX_SOCKET_ERROR:
				g_critical("[%s]: read head packet from zabbix agentd error.",
						G_STRLOC);
				/**
				 * head数据包读取错误，将状态机是否正常运行状态设置为FALSE;
				 * 同时将状态机的退出状态设置为网络错误。
				 */
				sock->exit_status = ZABBIX_STATUS_MACHINE_NETWORK_ERROR;
				sock->state = ZABBIX_CON_STATE_CLOSE_CONNECT;
				break;
			}
			break;
		}
		case ZABBIX_CON_STATE_READ_LENGTH: {
			/**
			 * 实现对从zabbix agent 读取头数据包
			 */
			switch (zabbix_agent_read_length(sock)) {
			case ZABBIX_SOCKET_SUCCESS:
				/**
				 * @note 需要将读取的8字节的网络小端数据串转换成数字,然后设置下一次需要读的数据长度。
				 *       注意：当数字为0时，就不需要从数据库端读取数据了。我们认为此时状态机可以关闭了。
				 *       但是是错误的退出
				 */
				if (0 == sock->expected_len) {
					g_critical(
							"[%s]: zabbix will none result any more, please check the plugin.",
							G_STRLOC);
					sock->exit_status = ZABBIX_STATUS_MACHINE_NO_RESULT;
					sock->state = ZABBIX_CON_STATE_CLOSE_CONNECT;
				} else {
					sock->to_read = (gint) (sock->expected_len);
					g_string_truncate(sock->result, 0);
					sock->state = ZABBIX_CON_STATE_READ_RESULT;
				}
				break;
			case ZABBIX_SOCKET_WAIT_FOR_EVENT:
				g_debug("[%s]: read length packet need retry.", G_STRLOC);
				timeout.tv_sec = sock->read_timeout_seconds;
				timeout.tv_usec = 0;
				WAIT_FOR_EVENT(sock, EV_READ, &timeout)
				;
				return;
			case ZABBIX_SOCKET_ERROR_RETRY:
			case ZABBIX_SOCKET_ERROR:
				g_critical("[%s]: read length packet from zabbix agentd error.",
						G_STRLOC);
				/**
				 * 数据长度读取错误，将状态机是否正常运行状态设置为FALSE;
				 * 同时将状态机的退出状态设置为网络错误。
				 */
				sock->exit_status = ZABBIX_STATUS_MACHINE_NETWORK_ERROR;
				sock->state = ZABBIX_CON_STATE_CLOSE_CONNECT;
				break;
			}
			break;
		}
		case ZABBIX_CON_STATE_READ_RESULT: {
			/**
			 * 该状态从zabbix_agent读取sock->expected_len长度的数据,
			 * 读取成功会将状态机的完成状态设置为TRUE,并且只有这个状态会将其状态设置为TRUE
			 */
			switch (zabbix_agent_read_result(sock, sock->to_read)) {
			case ZABBIX_SOCKET_SUCCESS:
				/**
				 * 读取成功需要将执行的状态设置为成功，
				 * 并将状态机的退出状态置为：ZABBIX_STATUS_MACHINE_SUCCESS
				 */
				sock->exit_status = ZABBIX_STATUS_MACHINE_SUCCESS;
				sock->state = ZABBIX_CON_STATE_CLOSE_CONNECT;
				break;
			case ZABBIX_SOCKET_WAIT_FOR_EVENT:
				g_debug("[%s]: read result packet need retry.", G_STRLOC);
				timeout.tv_sec = sock->read_timeout_seconds;
				timeout.tv_usec = 0;
				WAIT_FOR_EVENT(sock, EV_READ, &timeout)
				;
				return;
			case ZABBIX_SOCKET_ERROR_RETRY:
			case ZABBIX_SOCKET_ERROR:
				g_critical("[%s]: read length packet from zabbix agentd error.",
						G_STRLOC);
				/**
				 * 结果读取错误，将状态机是否正常运行状态设置为FALSE;
				 * 同时将状态机的退出状态设置为网络错误。
				 */
				sock->exit_status = ZABBIX_STATUS_MACHINE_NETWORK_ERROR;
				sock->state = ZABBIX_CON_STATE_CLOSE_CONNECT;
				break;
			}
			break;
		}
		case ZABBIX_CON_STATE_CLOSE_CONNECT: {
			/**
			 * 该状态负责设置将socket的状态机结束标志设置为TRUE
			 * 同时会关闭socket连接，并将状态初始化
			 */
			sock->is_over = TRUE;
			zabbix_agent_close(sock);
			break;
		}
		} /*end of switch*/
	} while (ostate != sock->state);

	g_debug("[%s]: left zabbix agentd commit protocol at state: %s. Process over:%s.",
			G_STRLOC, zabbix_con_state_name(sock->state),
			sock->is_over? "YES":"NO");
	return;
}



/*eof*/
