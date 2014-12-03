/*
 * network-zabbix-socket.c
 *
 *  Created on: 2013-6-24
 *      Author: jinxuanhou
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _WIN32
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h> /* writev */

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_FILIO_H
/**
 * required for FIONREAD on solaris
 */
#include <sys/filio.h>
#endif

#include <arpa/inet.h> /** inet_ntoa */
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <netdb.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <io.h>
#define ioctl ioctlsocket
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifdef HAVE_WRITEV
#define USE_BUFFERED_NETIO
#else
#undef USE_BUFFERED_NETIO
#endif

#ifdef _WIN32
#define E_NET_CONNRESET WSAECONNRESET
#define E_NET_CONNABORTED WSAECONNABORTED
#define E_NET_WOULDBLOCK WSAEWOULDBLOCK
#define E_NET_INPROGRESS WSAEINPROGRESS
#else
#define E_NET_CONNRESET ECONNRESET
#define E_NET_CONNABORTED ECONNABORTED
#define E_NET_INPROGRESS EINPROGRESS
#if EWOULDBLOCK == EAGAIN
/**
 * some system make EAGAIN == EWOULDBLOCK which would lead to a
 * error in the case handling
 *
 * set it to -1 as this error should never happen
 */
#define E_NET_WOULDBLOCK -1
#else
#define E_NET_WOULDBLOCK EWOULDBLOCK
#endif
#endif

#include <glib.h>

#include "network-mysqld-proto.h"
#include "network-mysqld-packet.h"
#include "string-len.h"
#include "glib-ext.h"

#include "network-zabbix-socket.h"

#define ZABBIX_HEADER_DATA		"ZBXD"
#define ZABBIX_HEADER_VERSION	"\1"
#define ZABBIX_HEADER			"ZBXD\1"
#define ZABBIX_HEADER_LEN		5
#define ZABBIX_LENGTH_LEN		8

/**
 * @author sohu-inc.com
 * 获取不同状态对应的名字
 * @param state 状态变量
 * @return
 */
const char *zabbix_con_state_name(zabbix_con_state state) {
	switch (state) {
	case ZABBIX_CON_STATE_INIT: return "ZABBIX_CON_STATE_INIT";
	case ZABBIX_CON_STATE_WRITE_HEAD: return "ZABBIX_CON_STATE_WRITE_HEAD";
	case ZABBIX_CON_STATE_WRITE_LENGTH: return "ZABBIX_CON_STATE_WRITE_LENGTH";
	case ZABBIX_CON_STATE_WRITE_CMD: return "ZABBIX_CON_STATE_WRITE_CMD";
	case ZABBIX_CON_STATE_READ_HEAD: return "ZABBIX_CON_STATE_READ_HEAD";
	case ZABBIX_CON_STATE_READ_LENGTH: return "ZABBIX_CON_STATE_READ_LENGTH";
	case ZABBIX_CON_STATE_READ_RESULT: return "ZABBIX_CON_STATE_READ_RESULT";
	case ZABBIX_CON_STATE_CLOSE_CONNECT: return "ZABBIX_CON_STATE_CLOSE_CONNECT";
	}

	return "unknown";
}

/**
 * @author sohu-inc.com
 * 向zabbix agentd 发送send_queue 中的数据
 * @param con
 * @param send_chunks
 * @return
 */
static zabbix_socket_retval_t network_socket_write_send(zabbix_socket *con, int send_chunks) {
	/* send the whole queue */

	GList *chunk;

	if (send_chunks == 0) return ZABBIX_SOCKET_SUCCESS;

	for (chunk = con->send_queue->chunks->head; chunk; ) {
		GString *s = chunk->data;
		gssize len;

		g_assert(con->send_queue->offset < s->len);

		if (con->socket_type == SOCK_STREAM) {
			len = send(con->fd, s->str + con->send_queue->offset, s->len - con->send_queue->offset, 0);
		} else {
			len = sendto(con->fd, s->str + con->send_queue->offset, s->len - con->send_queue->offset, 0, &(con->dst->addr.common), con->dst->len);
		}
		if (-1 == len) {
#ifdef _WIN32
			errno = WSAGetLastError();
#endif
			switch (errno) {
			case E_NET_WOULDBLOCK:
			case EAGAIN:
				return ZABBIX_SOCKET_WAIT_FOR_EVENT;
			case EPIPE:
			case E_NET_CONNRESET:
			case E_NET_CONNABORTED:
				/** remote side closed the connection */
				return ZABBIX_SOCKET_ERROR;
			default:
				g_message("%s: send(%s, %"G_GSIZE_FORMAT") failed: %s",
						G_STRLOC,
						con->dst->name->str,
						s->len - con->send_queue->offset,
						g_strerror(errno));
				return ZABBIX_SOCKET_ERROR;
			}
		} else if (len == 0) {
			return ZABBIX_SOCKET_ERROR;
		}

		con->send_queue->offset += len;

		if (con->send_queue->offset == s->len) {
			g_string_free(s, TRUE);

			g_queue_delete_link(con->send_queue->chunks, chunk);
			con->send_queue->offset = 0;

			if (send_chunks > 0 && --send_chunks == 0) break;

			chunk = con->send_queue->chunks->head;
		} else {
			return ZABBIX_SOCKET_WAIT_FOR_EVENT;
		}
	}

	return ZABBIX_SOCKET_SUCCESS;
}

/**
 * @author sohu-inc.com
 * 将sock对应的与zabbix agentd之间的连接设置为非阻塞
 * @param sock 要处理的socket变量
 * @return
 */
static zabbix_socket_retval_t zabbix_socket_set_non_blocking(zabbix_socket *sock) {
	int ret;
#ifdef _WIN32
	int ioctlvar;

	ioctlvar = 1;
	ret = ioctlsocket(sock->fd, FIONBIO, &ioctlvar);
#else
	ret = fcntl(sock->fd, F_SETFL, O_NONBLOCK | O_RDWR);
#endif
	if (ret != 0) {
#ifdef _WIN32
		errno = WSAGetLastError();
#endif
		g_critical("%s.%d: set_non_blocking() failed: %s (%d)",
				__FILE__, __LINE__,
				g_strerror(errno), errno);
		return ZABBIX_SOCKET_ERROR;
	}
	return ZABBIX_SOCKET_SUCCESS;
}

/**
 * @author sohu-inc.com
 * 创建并初始化zabbix_socket实例
 */
zabbix_socket *zabbix_socket_new(void) {
	zabbix_socket * sock = g_new0(zabbix_socket, 1);

	sock->fd = -1;
	sock->dst = network_address_new();
	sock->socket_type = SOCK_STREAM;

	sock->thread_event_base = NULL;
	sock->state = ZABBIX_CON_STATE_INIT;

	sock->cmd = g_string_new(NULL);
	sock->send_queue = network_queue_new();
	sock->result = g_string_new(NULL);
	sock->to_read = 0;
	sock->expected_len = 0;

	sock->is_over = FALSE;

	sock->exit_status = ZABBIX_STATUS_MACHINE_NO_RESULT;
	return sock;
}

/**
 * @author sohu-inc.com
 * 释放zabbix socket变量的内存
 * @param sock
 */
void zabbix_socket_free(zabbix_socket *sock) {
	if (!sock)
		return;

	if (-1 != sock->fd) {
		closesocket(sock->fd);
		sock->fd = -1;
	}
	if (sock->dst != NULL) {
		network_address_free(sock->dst);
		sock->dst = NULL;
	}

	if (sock->cmd != NULL) {
		g_string_free(sock->cmd, TRUE);
		sock->cmd = NULL;
	}
	if (sock->send_queue != NULL) {
		network_queue_free(sock->send_queue);
		sock->send_queue = NULL;
	}
	if (sock->result != NULL) {
		g_string_free(sock->result, TRUE);
		sock->result = NULL;
	}

	g_free(sock);
}

void zabbix_socket_set_thread_event_base(zabbix_socket *sock, struct event_base *thread_event_base) {
	sock->thread_event_base = thread_event_base;
}

/**
 * @author sohu-inc.com
 * 将socket通讯的状态复位
 * @param sock
 */
void zabbix_socket_reset(zabbix_socket *sock) {
	g_assert(sock);

	sock->state = ZABBIX_CON_STATE_INIT; // 初始状态是建立连接

	if (g_queue_get_length(sock->send_queue->chunks) > 0) {
		GString *packet = NULL;
		while ((packet = g_queue_pop_head(sock->send_queue->chunks))) {
			g_string_free(packet, TRUE);
		}
		sock->send_queue->len = 0;
		sock->send_queue->offset = 0;
	}
	if (sock->result) {
		g_string_truncate(sock->result, 0);
	}
	sock->to_read = 0;
	sock->expected_len = 0;

	sock->is_over = FALSE;
	sock->fd = -1;

	sock->exit_status = ZABBIX_STATUS_MACHINE_NO_RESULT;
}

void zabbix_socket_set_timeout(zabbix_socket *sock, guint timeout) {
	sock->write_timeout_seconds = timeout;
	sock->read_timeout_seconds = timeout;
}


/**
 * @author sohu-inc.com
 * 判定与zabbix 的连接是否成功，并回复errno
 * @param zabbix_agent
 * @return
 */
zabbix_socket_retval_t zabbix_agent_connect_finish(zabbix_socket *zabbix_agent) {
	int so_error = 0;
	network_socklen_t so_error_len = sizeof(so_error);

	/**
	 * we might get called a 2nd time after a connect() == EINPROGRESS
	 */
	if (getsockopt(zabbix_agent->fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len)) {
		/* getsockopt failed */
		g_critical("%s: getsockopt(%s) failed: %s (%d)",
				G_STRLOC,
				zabbix_agent->dst->name->str, g_strerror(errno), errno);
		return ZABBIX_SOCKET_ERROR;
	}

	switch (so_error) {
	case 0:
		return ZABBIX_SOCKET_SUCCESS;
	default:
		errno = so_error;
		return ZABBIX_SOCKET_ERROR_RETRY;
	}
}

/**
 * @author sohu-inc.com
 * @param zabbix_agent
 * @return
 */
zabbix_socket_retval_t zabbix_agent_connect(zabbix_socket *zabbix_agent) {
	g_return_val_if_fail(zabbix_agent->dst, ZABBIX_SOCKET_ERROR); /* our _new() allocated it already */
	g_return_val_if_fail(zabbix_agent->dst->name->len, ZABBIX_SOCKET_ERROR); /* we want to use the ->name in the error-msgs */
	g_return_val_if_fail(zabbix_agent->fd < 0, ZABBIX_SOCKET_ERROR); /* we already have a valid fd, we don't want to leak it */
	g_return_val_if_fail(zabbix_agent->socket_type == SOCK_STREAM, ZABBIX_SOCKET_ERROR);

	/**
	 * 创建一个指向zabbix_agent->dst的socket
	 * 如果设置的zabbix_agentd->dst为空, socket()失败并返回unsupported错误
	 */
	if (-1 == (zabbix_agent->fd = socket(zabbix_agent->dst->addr.common.sa_family, zabbix_agent->socket_type, 0))) {
#ifdef _WIN32
		errno = WSAGetLastError();
#endif
		g_critical("%s.%d: socket(%s) failed: %s (%d)",
				__FILE__, __LINE__,
				zabbix_agent->dst->name->str, g_strerror(errno), errno);
		return ZABBIX_SOCKET_ERROR;
	}

	/**
	 * 我们需要将socket 设置为非阻塞
	 */
	zabbix_socket_set_non_blocking(zabbix_agent);

	if (-1 == connect(zabbix_agent->fd, &zabbix_agent->dst->addr.common, zabbix_agent->dst->len)) {
#ifdef _WIN32
		errno = WSAGetLastError();
#endif
		/**
		 * in most TCP cases we connect() will return with
		 * EINPROGRESS ... 3-way handshake
		 */
		switch (errno) {
		case E_NET_INPROGRESS:
		case E_NET_WOULDBLOCK: /* win32 uses WSAEWOULDBLOCK */
			return ZABBIX_SOCKET_ERROR_RETRY;
		default:
			g_critical("%s.%d: connect(%s) failed: %s (%d)",
					__FILE__, __LINE__,
					zabbix_agent->dst->name->str,
					g_strerror(errno), errno);
			return ZABBIX_SOCKET_ERROR;
		}
	}

	// 连接完成之后即可以进行接下来的数据交互
	//network_socket_connect_setopts(zabbix_agent);
	return ZABBIX_SOCKET_SUCCESS;
}
/**
 * @author sohu-inc.com
 * 根据情况选择对socket的适当的操作:
 * fd = -1时, 建立新的连接;fd != -1时，查看socket的状态
 * @param zabbix_agent
 * @return
 */
zabbix_socket_retval_t zabbix_agent_connect_dispatch(
		zabbix_socket *zabbix_agent) {
	if (-1 != zabbix_agent->fd) {
		// 说明已经有了对应的连接fd
		switch (zabbix_agent_connect_finish(zabbix_agent)) {
		case ZABBIX_SOCKET_SUCCESS:
			break;
		case ZABBIX_SOCKET_ERROR:
		case ZABBIX_SOCKET_ERROR_RETRY:
			g_debug("[%s]: socket connect error, after wait for event",
					G_STRLOC);
			return ZABBIX_SOCKET_ERROR;
		default:
			g_assert_not_reached();
			break;
		}
		// 没有对应的fd,会重新建立新的连接
		return ZABBIX_SOCKET_SUCCESS;
	}

	return zabbix_agent_connect(zabbix_agent);

}

/**
 * @author sohu-inc.com
 * @param zabbix_agent
 * @return
 */
zabbix_socket_retval_t zabbix_agent_write(zabbix_socket *zabbix_agent) {
	return network_socket_write_send(zabbix_agent, -1);
}

/**
 * @author sohu-inc.com
 * 将与zabbix agent通讯的zabbix head数据包append到sock的send_queue中，并写入到socket中
 * @param zabbix_agent
 * @return
 */
zabbix_socket_retval_t zabbix_agent_write_head(zabbix_socket *zabbix_agent) {
	GString *packet = g_string_new(NULL);
	g_string_append_len(packet, ZABBIX_HEADER, ZABBIX_HEADER_LEN);
	network_queue_append(zabbix_agent->send_queue, packet);
	return zabbix_agent_write(zabbix_agent);
}

/**
 * @author sohu-inc.com
 * 将command 数据包的长度(8字节)添加到send_queue中，并写入到socket中
 * @param zabbix_agent
 * @return
 */
zabbix_socket_retval_t zabbix_agent_write_length(zabbix_socket *zabbix_agent, guint64 length) {
	GString *packet = g_string_new(NULL);
	network_mysqld_proto_append_int64(packet, length);
	network_queue_append(zabbix_agent->send_queue, packet);
	return zabbix_agent_write(zabbix_agent);
}

/**
 * @author sohu-inc.com
 * 将key[参数列表]添加到send_queue中，并写入到socket中
 * @param zabbix_agent
 * @return
 */
zabbix_socket_retval_t zabbix_agent_write_cmd(zabbix_socket *zabbix_agent, const char *cmd) {
	GString *packet = g_string_new(cmd);
	network_queue_append(zabbix_agent->send_queue, packet);
	return zabbix_agent_write(zabbix_agent);
}

/**
 * @author sohu-inc.com
 * @param zabbix_agent
 * @return
 */
zabbix_socket_retval_t zabbix_agent_read(zabbix_socket *zabbix_agent) {
	gssize len;

	if (zabbix_agent->to_read > 0) {
		GString *packet = g_string_sized_new(zabbix_agent->to_read);

		if (zabbix_agent->socket_type == SOCK_STREAM) {
			len = recv(zabbix_agent->fd, packet->str, zabbix_agent->to_read, 0);
		} else {
			/* UDP */
			network_socklen_t dst_len = sizeof(zabbix_agent->dst->addr.common);
			len = recvfrom(zabbix_agent->fd, packet->str, zabbix_agent->to_read, 0, &(zabbix_agent->dst->addr.common), &(dst_len));
			zabbix_agent->dst->len = dst_len;
		}
		if (-1 == len) {
#ifdef _WIN32
			errno = WSAGetLastError();
#endif
			switch (errno) {
			case E_NET_CONNABORTED:
			case E_NET_CONNRESET: /** nothing to read, let's let ioctl() handle the close for us */
			case E_NET_WOULDBLOCK: /** the buffers are empty, try again later */
			case EAGAIN:
				if (packet != NULL) {
					g_string_free(packet, TRUE);
					packet = NULL;
				}
				return ZABBIX_SOCKET_WAIT_FOR_EVENT;
			default:
				if (packet != NULL) {
                                        g_string_free(packet, TRUE);
                                        packet = NULL;
                                }
				g_debug("%s: recv() failed: %s (errno=%d)", G_STRLOC, g_strerror(errno), errno);
				return ZABBIX_SOCKET_ERROR;
			}
		} else if (len == 0) {
			/**
			 * connection close
			 *
			 * let's call the ioctl() and let it handle it for use
			 */
			if (packet != NULL) {
				g_string_free(packet, TRUE);
                                packet = NULL;
			}
			return ZABBIX_SOCKET_WAIT_FOR_EVENT;
		}

		zabbix_agent->to_read -= len;
#if 0
		zabbix_agent->recv_queue_raw->offset = 0; /* offset into the first packet */
#endif
		packet->len = len;
		g_string_append_len(zabbix_agent->result, packet->str, packet->len);
		if (packet != NULL) {
			g_string_free(packet, TRUE);
			packet = NULL;
		}
	}

	return ZABBIX_SOCKET_SUCCESS;
}

/**
 * 
 * 读取zabbix 通信的头数据包
 * @param zabbix_agent
 * @return
 */
zabbix_socket_retval_t zabbix_agent_read_head(zabbix_socket *zabbix_agent) {
	g_assert(zabbix_agent->to_read == ZABBIX_HEADER_LEN); //header 数据包必须一次读完
	zabbix_socket_retval_t ret = zabbix_agent_read(zabbix_agent);

	//需要校验读取的头数据包是正确的
	if (ret == ZABBIX_SOCKET_SUCCESS) {
		if (!zabbix_head_is_valid(zabbix_agent)) {
			ret = ZABBIX_SOCKET_ERROR;
			g_debug("[%s]: get header success but header is incorrect.", G_STRLOC);
		}
	}

	return ret;
}

gboolean zabbix_head_is_valid(zabbix_socket *zabbix_agent) {
	int ret = TRUE;

	if (!zabbix_agent) {
		ret = FALSE;
	} else {
		if (!zabbix_agent->result) {
			ret = FALSE;
		} else if (zabbix_agent->result->len != ZABBIX_HEADER_LEN) {
			ret = FALSE;
			g_message("[%s]: header length: %d is not correct, should be %d", G_STRLOC, (int)(zabbix_agent->result->len), (int)ZABBIX_HEADER_LEN);
		} else if (0 != g_strcmp0(zabbix_agent->result->str, ZABBIX_HEADER)) {
			ret = FALSE;
			g_message("[%s]: header content: %s is not correct, should be %s", G_STRLOC, zabbix_agent->result->str, ZABBIX_HEADER);
		}
	}

	return ret;
}

int zabbix_letoh_guint64(GString *packet, guint64 *data) {
	if (!packet || packet->len != 8)
		return -1;

	*data = 0; // reset
	unsigned char	buf[8];

	memset(buf, 0, sizeof(buf));
	memcpy(buf, packet->str, sizeof(buf));

	*data  = (guint64)buf[7];	*data <<= 8;
	*data |= (guint64)buf[6];	*data <<= 8;
	*data |= (guint64)buf[5];	*data <<= 8;
	*data |= (guint64)buf[4];	*data <<= 8;
	*data |= (guint64)buf[3];	*data <<= 8;
	*data |= (guint64)buf[2];	*data <<= 8;
	*data |= (guint64)buf[1];	*data <<= 8;
	*data |= (guint64)buf[0];

	return 0;
}

/**
 * @author sohu-inc.com
 * 读取zabbix agentd 返回结果的长度
 * @param zabbix_agent
 * @return
 */
zabbix_socket_retval_t zabbix_agent_read_length(zabbix_socket *zabbix_agent) {
	g_assert(zabbix_agent->to_read == ZABBIX_LENGTH_LEN); //结果长度数据包也必须一次读完
	zabbix_socket_retval_t ret = zabbix_agent_read(zabbix_agent);

	// 将读取的数据包转换成 guint64
	if (ret == ZABBIX_SOCKET_SUCCESS) {
		int err = 0;
		err = zabbix_letoh_guint64(zabbix_agent->result, &(zabbix_agent->expected_len));
		if (0 != err) {
			g_critical("[%s]: get result length error, why the read returns success?", G_STRLOC);
			ret = ZABBIX_SOCKET_ERROR;
		}
	}

	return ret;
}

/**
 * @author sohu-inc.com
 * 读取zabbix agentd 返回的数据结果
 * @param zabbix_agent
 * @return
 */
zabbix_socket_retval_t zabbix_agent_read_result(zabbix_socket *zabbix_agent, gint len) {
	g_assert(zabbix_agent->to_read == len); /**@fixme warning: comparison between signed and unsigned*/
	return zabbix_agent_read(zabbix_agent);
}

/**
 * @author sohu-inc.com
 * 负责将zabbix_agent对应的socket关闭。不对socket其他的结构回收
 * @param zabbix_agent
 */
void zabbix_agent_close(zabbix_socket *zabbix_agent) {
	if (!zabbix_agent)
		return ;

	if (-1 != zabbix_agent->fd) {
		closesocket(zabbix_agent->fd);
		zabbix_agent->fd = -1;
	}

}

void zabbix_socket_set_agentd_address(zabbix_socket *sock, const gchar *addr, guint port) {
	GString *addr_str = NULL;

	g_assert(sock);
	g_assert(addr);

	addr_str = g_string_new(NULL);
	g_string_printf(addr_str, "%s:%d", addr, port);
	network_address_set_address(sock->dst, addr_str->str);
	g_string_free(addr_str, TRUE);
	addr_str = NULL;

	return;
}

void zabbix_socket_set_agentd_cmd(zabbix_socket *sock, const gchar *key,
		const gchar *addr, guint port, const gchar *user, const gchar *pwd) {
	g_assert(sock);
	g_assert(key);
	g_assert(addr);
	g_assert(user);
	g_assert(pwd);

	g_string_truncate(sock->cmd, 0);
	g_string_printf(sock->cmd, "%s[%s,%d,%s,%s]", key, addr, port, user, pwd);

	return;
}

/*eof*/
