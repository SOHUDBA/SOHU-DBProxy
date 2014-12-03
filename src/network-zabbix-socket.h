/*
 * network-zabbix-socket.h
 *
 *  Created on: 2013-6-24
 *      Author: jinxuanhou
 */

#ifndef NETWORK_ZABBIX_SOCKET_H_
#define NETWORK_ZABBIX_SOCKET_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
/**
 * event.h needs struct timeval and doesn't include sys/time.h itself
 */
#include <sys/time.h>
#endif

#include <sys/types.h>      /** u_char */
#ifndef _WIN32
#include <sys/socket.h>     /** struct sockaddr */

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>     /** struct sockaddr_in */
#endif
#include <netinet/tcp.h>

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>         /** struct sockaddr_un */
#endif

/**
 * use closesocket() to close sockets to be compatible with win32
 */
#define closesocket(x) close(x)
#else
#include <winsock2.h>
#include <Ws2tcpip.h>
#endif

#include <glib.h>
#include <event.h>

#include "network-exports.h"
#include "network-address.h"
#include "network-queue.h"
#include "network-backend.h"

#define ZBX_TCP_ERROR -1 /**< socket通信过程中出现错误 */
#define ZBX_SOCK_ERROR -1 /**< socket建立、关闭等socket操作的错误 */

/**<zabbix socket buffer的长度 */
#define ZBX_STAT_BUF_LEN 1024

/**
 * dbproxy 与 zabbix agentd通信异常的错误类型
 */
typedef enum {
	ZABBIX_TCP_ERR_NETWORK = 1,
	ZABBIX_TCP_ERR_TIMEOUT = 2,
	ZABBIX_TCP_ERR_UNSUPPORT = 3
} zabbix_tcp_errors;

typedef enum {
	ZABBIX_SOCKET_SUCCESS,
	ZABBIX_SOCKET_WAIT_FOR_EVENT, /**< 等待socket可读或可写  */
	ZABBIX_SOCKET_ERROR,
	ZABBIX_SOCKET_ERROR_RETRY
} zabbix_socket_retval_t;

typedef enum {
	ZABBIX_STATUS_MACHINE_SUCCESS = 0,
	ZABBIX_STATUS_MACHINE_TIMEOUT = 1,
	ZABBIX_STATUS_MACHINE_NETWORK_ERROR = 2,
	ZABBIX_STATUS_MACHINE_SERVER_CLOSE_CON = 3,
	ZABBIX_STATUS_MACHINE_NO_RESULT = 4
} zabbix_status_machine_exit_t;

// dbproxy 与 zabbix agentd 的通信的连接的状态
typedef enum {
	ZABBIX_CON_STATE_INIT = 0,
	ZABBIX_CON_STATE_WRITE_HEAD = 1,
	ZABBIX_CON_STATE_WRITE_LENGTH = 2,
	ZABBIX_CON_STATE_WRITE_CMD = 3,
	ZABBIX_CON_STATE_READ_HEAD = 4,
	ZABBIX_CON_STATE_READ_LENGTH = 5,
	ZABBIX_CON_STATE_READ_RESULT = 6,
	ZABBIX_CON_STATE_CLOSE_CONNECT = 7
} zabbix_con_state;

/**
 * dbproxy 与 zabbix agentd通信的socket结构体
 */
typedef struct {
	int fd;             /**< socket-fd */
	network_address *dst; /**< getpeername() */
	int socket_type; /**< SOCK_STREAM or SOCK_DGRAM for now */

	gchar buf_stat[ZBX_STAT_BUF_LEN]; /**< dbproxy 与 zabbix agentd数据传输的缓存，\
										为了借用mysql-proxy本身的socket操作函数暂时不用该结构 */

	struct event event;
	struct event_base *thread_event_base;
	zabbix_con_state state; /**< 该socket与zabbix agent交互所处的状态 */

	GString *cmd; /**< 要发送的数据命令包括： key[参数列表]*/
	network_queue *send_queue; /**< 缓存将要发送的数据，包括head包、长度数据包或命令数据包 */
	GString *result; /**< 用于存储从zabbix agentd读取的数据可能为：header、length、真实的返回数据 */
	gint to_read; /**< 需要读取的数据的长度 */
	guint64 expected_len; /**< 需要读的的字节的长度 */

	gboolean is_over; /**<用于标志是否正常走完了通信的全部流程  */
	/**
	 * 程序从状态机退出的状态，只要是三次成功写入、三次成功的读出即可正常退出状态机。
	 * 此时状态即为确定的，反之超时、返回结果不全，就认为是失败的设置错误状态为供上层使用
	 */
	zabbix_status_machine_exit_t exit_status;

	guint write_timeout_seconds; /*写等待事件的超时时间*/
	guint read_timeout_seconds; /*读等待事件的超时时间*/

} zabbix_socket;


NETWORK_API const char *zabbix_con_state_name(zabbix_con_state state); /**< 通过con state获得其所处的状态的名称 */

NETWORK_API int zabbix_letoh_guint64(GString *packet, guint64 *data); /**< 负责将一个小端的8位网络字符串转换成机器数字 */

/**< zabbix agentd 对外提供的功能函数，包括连接建立、读写数据、连接释放等 */
NETWORK_API zabbix_socket *zabbix_socket_new(void);
NETWORK_API void zabbix_socket_free(zabbix_socket *sock);
NETWORK_API void zabbix_socket_set_thread_event_base(zabbix_socket *sock, struct event_base *thread_event_base);
NETWORK_API void zabbix_socket_reset(zabbix_socket *sock); /**< 在socket通信结束后，对该socket的状态进行复位 */
NETWORK_API void zabbix_socket_set_timeout(zabbix_socket *sock, guint timeout);

NETWORK_API zabbix_socket_retval_t zabbix_agent_connect_dispatch(
		zabbix_socket *zabbix_agent); /**< 根据情况选择对socket的适当的操作,
									   * fd = -1时, 建立新的连接
									   * fd != -1时，查看socket的状态
									   */
NETWORK_API zabbix_socket_retval_t zabbix_agent_connect(zabbix_socket *zabbix_agent); /**< 创建与zabbix agentd的连接 */
NETWORK_API zabbix_socket_retval_t zabbix_agent_connect_finish(zabbix_socket *zabbix_agent); /**< 做异步连接的收尾工作：如将errno设置为0， */

NETWORK_API zabbix_socket_retval_t zabbix_agent_write(zabbix_socket *zabbix_agent); /**< 向zabbix agent 对应的socket中写入send_queue中的数据*/
NETWORK_API zabbix_socket_retval_t zabbix_agent_write_head(zabbix_socket *zabbix_agent); /**< 将与zabbix agent通讯的zabbix head数据包append到sock的send_queue中 */
NETWORK_API zabbix_socket_retval_t zabbix_agent_write_length(zabbix_socket *zabbix_agent, guint64 length); /**< 将command 数据包的长度(8字节)添加到send_queue中 */
NETWORK_API zabbix_socket_retval_t zabbix_agent_write_cmd(zabbix_socket *zabbix_agent, const char *cmd); /**< 将key[参数列表]添加到send_queue中 */
NETWORK_API zabbix_socket_retval_t zabbix_agent_read(zabbix_socket *zabbix_agent); /**< 从zabbix agent 对应的socket中读取数据至recv_queue*/
NETWORK_API zabbix_socket_retval_t zabbix_agent_read_head(zabbix_socket *zabbix_agent); /**< 读取zabbix 通信的头数据包 */
NETWORK_API gboolean zabbix_head_is_valid(zabbix_socket *zabbix_agent); /**<  判定socket中字符串是否是真正的包头数据 */
NETWORK_API zabbix_socket_retval_t zabbix_agent_read_length(zabbix_socket *zabbix_agent); /**< 读取zabbix agentd 返回结果的长度 */
NETWORK_API zabbix_socket_retval_t zabbix_agent_read_result(zabbix_socket *zabbix_agent, gint len); /**< 读取zabbix agentd 返回的数据结果 */

NETWORK_API void zabbix_agent_close(zabbix_socket *zabbix_agent); /**< 将zabbix_agent对应的socket关闭 */

NETWORK_API void zabbix_socket_set_agentd_address(zabbix_socket *sock, const gchar *addr, guint port);
NETWORK_API void zabbix_socket_set_agentd_cmd(zabbix_socket *sock, const gchar *key,
		const gchar *addr, guint port, const gchar *user, const gchar *pwd);


#endif /* NETWORK_ZABBIX_SOCKET_H_ */
