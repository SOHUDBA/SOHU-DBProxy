/* $%BEGINLICENSE%$
 Copyright (c) 2007, 2011, Oracle and/or its affiliates. All rights reserved.

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 of the
 License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 02110-1301  USA

 $%ENDLICENSE%$ */
 

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

#include "network-debug.h"
#include "network-socket.h"
#include "network-mysqld-proto.h"
#include "network-mysqld-packet.h"
#include "string-len.h"
#include "glib-ext.h"
#include "chassis-regex.h"

#ifndef DISABLE_DEPRECATED_DECL
network_socket *network_socket_init() {
	return network_socket_new();
}
#endif

network_socket *network_socket_new() {
	network_socket *s;
	
	s = g_new0(network_socket, 1);

	s->send_queue = network_queue_new();
	s->recv_queue = network_queue_new();
	s->recv_queue_raw = network_queue_new();

	s->default_db = g_string_new(NULL);
	s->fd           = -1;
	s->socket_type  = SOCK_STREAM; /* let's default to TCP */
	s->packet_id_is_reset = TRUE;

	s->src = network_address_new();
	s->dst = network_address_new();

	s->charset = 0x21; //default utf8
	s->autocommit = 1;
	s->ip_region = NULL;
	s->ip = NULL;

	s->character_set_client = g_string_new(NULL);
	s->character_set_connection = g_string_new(NULL);
	s->character_set_database = g_string_new(NULL);
	s->character_set_results = g_string_new(NULL);
	s->character_set_server = g_string_new(NULL);
	s->collection_connect = g_string_new(NULL);

	return s;
}

void network_socket_free(network_socket *s) {
	if (!s) return;

	network_queue_free(s->send_queue);
	network_queue_free(s->recv_queue);
	network_queue_free(s->recv_queue_raw);

	if (s->response) network_mysqld_auth_response_free(s->response);
	if (s->challenge) network_mysqld_auth_challenge_free(s->challenge);

	network_address_free(s->dst);
	network_address_free(s->src);

	if (s->event.ev_base) { /* if .ev_base isn't set, the event never got added */
		event_del(&(s->event));
	}

	if (s->fd != -1) {
		closesocket(s->fd);
	}

	g_string_free(s->default_db, TRUE);

	if(s->ip != NULL) {
		ip_range_free(s->ip);
		s->ip = NULL;
	}

	if(s->ip_region) {
		g_free(s->ip_region);
		s->ip_region = NULL;
	}

	if (s->character_set_client != NULL) {
		g_string_free(s->character_set_client, TRUE);
		s->character_set_client = NULL;
	}
	if (s->character_set_connection != NULL) {
		g_string_free(s->character_set_connection, TRUE);
		s->character_set_connection = NULL;
	}
	if (s->character_set_database != NULL) {
		g_string_free(s->character_set_database, TRUE);
		s->character_set_database = NULL;
	}
	if (s->character_set_results != NULL) {
		g_string_free(s->character_set_results, TRUE);
		s->character_set_results = NULL;
	}
	if (s->character_set_server != NULL) {
		g_string_free(s->character_set_server, TRUE);
		s->character_set_server = NULL;
	}
	if (s->collection_connect != NULL) {
		g_string_free(s->collection_connect, TRUE);
		s->collection_connect = NULL;
	}

	g_free(s);
}

/**
 * portable 'set non-blocking io'
 *
 * @param sock    a socket
 * @return        NETWORK_SOCKET_SUCCESS on success, NETWORK_SOCKET_ERROR on error
 */
network_socket_retval_t network_socket_set_non_blocking(network_socket *sock) {
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
		return NETWORK_SOCKET_ERROR;
	}
	return NETWORK_SOCKET_SUCCESS;
}

/**
 * accept a connection
 *
 * event handler for listening connections
 *
 * @param srv    a listening socket 
 * 
 */
network_socket *network_socket_accept(network_socket *srv) {
	network_socket *client;

	g_return_val_if_fail(srv, NULL);
	g_return_val_if_fail(srv->socket_type == SOCK_STREAM, NULL); /* accept() only works on stream sockets */

	client = network_socket_new();

	if (-1 == (client->fd = accept(srv->fd, &client->src->addr.common, &(client->src->len)))) {
		network_socket_free(client);

		return NULL;
	}

	network_socket_set_non_blocking(client);

	if (network_address_refresh_name(client->src)) {
		network_socket_free(client);
		return NULL;
	}

	/* the listening side may be INADDR_ANY, let's get which address the client really connected to */
	if (-1 == getsockname(client->fd, &client->dst->addr.common, &(client->dst->len))) {
		network_address_reset(client->dst);
	} else if (network_address_refresh_name(client->dst)) {
		network_address_reset(client->dst);
	}

	return client;
}

static network_socket_retval_t network_socket_connect_setopts(network_socket *sock) {
#ifdef WIN32
	char val = 1;	/* Win32 setsockopt wants a const char* instead of the UNIX void*...*/
#else
	int val = 1;
#endif
	/**
	 * set the same options as the mysql client 
	 */
#ifdef IP_TOS
	val = 8;
	setsockopt(sock->fd, IPPROTO_IP,     IP_TOS, &val, sizeof(val));
#endif
	val = 1;
	setsockopt(sock->fd, IPPROTO_TCP,    TCP_NODELAY, &val, sizeof(val) );
	val = 1;
	setsockopt(sock->fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val) );

	/* the listening side may be INADDR_ANY, let's get which address the client really connected to */
	if (-1 == getsockname(sock->fd, &sock->src->addr.common, &(sock->src->len))) {
		g_debug("%s: getsockname() failed: %s (%d)",
				G_STRLOC,
				g_strerror(errno),
				errno);
		network_address_reset(sock->src);
	} else if (network_address_refresh_name(sock->src)) {
		g_debug("%s: network_address_refresh_name() failed",
				G_STRLOC);
		network_address_reset(sock->src);
	}

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * finish the non-blocking connect()
 *
 * sets 'errno' as if connect() would have failed
 *
 */
network_socket_retval_t network_socket_connect_finish(network_socket *sock) {
	int so_error = 0;
	network_socklen_t so_error_len = sizeof(so_error);

	/**
	 * we might get called a 2nd time after a connect() == EINPROGRESS
	 */
#ifdef _WIN32
	/* need to cast to get rid of the compiler warning. otherwise identical to the UNIX version below. */
	if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, (char*)&so_error, &so_error_len)) {
		errno = WSAGetLastError();
#else
	if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len)) {
#endif
		/* getsockopt failed */
		g_critical("%s: getsockopt(%s) failed: %s (%d)", 
				G_STRLOC,
				sock->dst->name->str, g_strerror(errno), errno);
		return NETWORK_SOCKET_ERROR;
	}

	switch (so_error) {
	case 0:
		network_socket_connect_setopts(sock);

		return NETWORK_SOCKET_SUCCESS;
	default:
		errno = so_error;

		return NETWORK_SOCKET_ERROR_RETRY;
	}
}

/**
 * connect a socket
 *
 * the sock->addr has to be set before 
 * 
 * @param sock    a socket 
 * @return        NETWORK_SOCKET_SUCCESS on connected, NETWORK_SOCKET_ERROR on error, NETWORK_SOCKET_ERROR_RETRY for try again
 * @see network_address_set_address()
 */
network_socket_retval_t network_socket_connect(network_socket *sock) {
	g_return_val_if_fail(sock->dst, NETWORK_SOCKET_ERROR); /* our _new() allocated it already */
	g_return_val_if_fail(sock->dst->name->len, NETWORK_SOCKET_ERROR); /* we want to use the ->name in the error-msgs */
	g_return_val_if_fail(sock->fd < 0, NETWORK_SOCKET_ERROR); /* we already have a valid fd, we don't want to leak it */
	g_return_val_if_fail(sock->socket_type == SOCK_STREAM, NETWORK_SOCKET_ERROR);

	/**
	 * create a socket for the requested address
	 *
	 * if the dst->addr isn't set yet, socket() will fail with unsupported type
	 */
	if (-1 == (sock->fd = socket(sock->dst->addr.common.sa_family, sock->socket_type, 0))) {
#ifdef _WIN32
		errno = WSAGetLastError();
#endif
		g_critical("%s.%d: socket(%s) failed: %s (%d)", 
				__FILE__, __LINE__,
				sock->dst->name->str, g_strerror(errno), errno);
		return NETWORK_SOCKET_ERROR;
	}

	/**
	 * make the connect() call non-blocking
	 *
	 */
	network_socket_set_non_blocking(sock);

	if (-1 == connect(sock->fd, &sock->dst->addr.common, sock->dst->len)) {
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
			return NETWORK_SOCKET_ERROR_RETRY;
		default:
			g_critical("%s.%d: connect(%s) failed: %s (%d)", 
					__FILE__, __LINE__,
					sock->dst->name->str,
					g_strerror(errno), errno);
			return NETWORK_SOCKET_ERROR;
		}
	}

	network_socket_connect_setopts(sock);

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * connect a socket
 *
 * the con->dst->addr has to be set before 
 * 
 * @param con    a socket 
 * @return       NETWORK_SOCKET_SUCCESS on connected, NETWORK_SOCKET_ERROR on error
 *
 * @see network_address_set_address()
 */
network_socket_retval_t network_socket_bind(network_socket * con) {
	/* WIN32:      int setsockopt(SOCKET s, int level, int optname, const char *optval, int optlen);
	 * HPUX:       int setsockopt(int s,    int level, int optname, const void *optval, int optlen);
	 * all others: int setsockopt(int s,    int level, int optname, const void *optval, socklen_t optlen);
	 */
#ifdef WIN32
#define SETSOCKOPT_OPTVAL_CAST (const char *)
#else
#define SETSOCKOPT_OPTVAL_CAST (void *)
#endif

	g_return_val_if_fail(con->fd < 0, NETWORK_SOCKET_ERROR); /* socket is already bound */
	g_return_val_if_fail((con->socket_type == SOCK_DGRAM) || (con->socket_type == SOCK_STREAM), NETWORK_SOCKET_ERROR);

	if (con->socket_type == SOCK_STREAM) {
		g_return_val_if_fail(con->dst, NETWORK_SOCKET_ERROR);
		g_return_val_if_fail(con->dst->name->len > 0, NETWORK_SOCKET_ERROR);

		if (-1 == (con->fd = socket(con->dst->addr.common.sa_family, con->socket_type, 0))) {
			g_critical("%s: socket(%s) failed: %s (%d)", 
					G_STRLOC,
					con->dst->name->str,
					g_strerror(errno), errno);
			return NETWORK_SOCKET_ERROR;
		}

		if (con->dst->addr.common.sa_family == AF_INET || 
		    con->dst->addr.common.sa_family == AF_INET6) {
			/* TCP_NODELAY  is int on unix, BOOL on win32 */
			/* SO_REUSEADDR is int on unix, BOOL on win32 */
#ifdef WIN32
			BOOL val;
#else
			int val;
#endif

			val = 1;
			if (0 != setsockopt(con->fd, IPPROTO_TCP, TCP_NODELAY, SETSOCKOPT_OPTVAL_CAST &val, sizeof(val))) {
				g_critical("%s: setsockopt(%s, IPPROTO_TCP, TCP_NODELAY) failed: %s (%d)", 
						G_STRLOC,
						con->dst->name->str,
						g_strerror(errno), errno);
				return NETWORK_SOCKET_ERROR;
			}
		
			if (0 != setsockopt(con->fd, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPT_OPTVAL_CAST &val, sizeof(val))) {
				g_critical("%s: setsockopt(%s, SOL_SOCKET, SO_REUSEADDR) failed: %s (%d)", 
						G_STRLOC,
						con->dst->name->str,
						g_strerror(errno), errno);
				return NETWORK_SOCKET_ERROR;
			}
		}

		if (con->dst->addr.common.sa_family == AF_INET6) {
#ifdef IPV6_V6ONLY
			/* disable dual-stack IPv4-over-IPv6 sockets
			 *
			 * ... if it is supported:
			 * - Linux
			 * - Windows
			 * - Mac OS X
			 * - FreeBSD
			 * - Solaris 10 and later
			 *
			 * no supported on:
			 * - Solaris 9 and earlier
			 */

			/* IPV6_V6ONLY is int on unix, DWORD on win32 */
#ifdef WIN32
			DWORD val;
#else
			int val;
#endif

			val = 0;
			if (0 != setsockopt(con->fd, IPPROTO_IPV6, IPV6_V6ONLY, SETSOCKOPT_OPTVAL_CAST &val, sizeof(val))) {
				g_critical("%s: setsockopt(%s, IPPROTO_IPV6, IPV6_V6ONLY) failed: %s (%d)", 
						G_STRLOC,
						con->dst->name->str,
						g_strerror(errno), errno);
				return NETWORK_SOCKET_ERROR;
			}
#endif
		}


		if (-1 == bind(con->fd, &con->dst->addr.common, con->dst->len)) {
			g_critical("%s: bind(%s) failed: %s (%d)", 
					G_STRLOC,
					con->dst->name->str,
					g_strerror(errno), errno);
			return NETWORK_SOCKET_ERROR;
		}

		if (con->dst->addr.common.sa_family == AF_INET &&
		    con->dst->addr.ipv4.sin_port == 0) {
			struct sockaddr_in a;
			socklen_t          a_len = sizeof(a);

			if (0 != getsockname(con->fd, (struct sockaddr *)&a, &a_len)) {
				g_critical("%s: getsockname(%s) failed: %s (%d)", 
						G_STRLOC,
						con->dst->name->str,
						g_strerror(errno), errno);
				return NETWORK_SOCKET_ERROR;
			}
			con->dst->addr.ipv4.sin_port  = a.sin_port;
		} else if (con->dst->addr.common.sa_family == AF_INET6 &&
		           con->dst->addr.ipv6.sin6_port == 0) {
			struct sockaddr_in6 a;
			socklen_t          a_len = sizeof(a);

			if (0 != getsockname(con->fd, (struct sockaddr *)&a, &a_len)) {
				g_critical("%s: getsockname(%s) failed: %s (%d)", 
						G_STRLOC,
						con->dst->name->str,
						g_strerror(errno), errno);
				return NETWORK_SOCKET_ERROR;
			}
			con->dst->addr.ipv6.sin6_port  = a.sin6_port;
		}

		if (-1 == listen(con->fd, 128)) {
			g_critical("%s: listen(%s, 128) failed: %s (%d)",
					G_STRLOC,
					con->dst->name->str,
					g_strerror(errno), errno);
			return NETWORK_SOCKET_ERROR;
		}
	} else {
		/* UDP sockets bind the ->src address */
		g_return_val_if_fail(con->src, NETWORK_SOCKET_ERROR);
		g_return_val_if_fail(con->src->name->len > 0, NETWORK_SOCKET_ERROR);

		if (-1 == (con->fd = socket(con->src->addr.common.sa_family, con->socket_type, 0))) {
			g_critical("%s: socket(%s) failed: %s (%d)", 
					G_STRLOC,
					con->src->name->str,
					g_strerror(errno), errno);
			return NETWORK_SOCKET_ERROR;
		}

		if (-1 == bind(con->fd, &con->src->addr.common, con->src->len)) {
			g_critical("%s: bind(%s) failed: %s (%d)", 
					G_STRLOC,
					con->src->name->str,
					g_strerror(errno), errno);
			return NETWORK_SOCKET_ERROR;
		}
	}

	con->dst->can_unlink_socket = TRUE;
	return NETWORK_SOCKET_SUCCESS;
}

/**
 * read a data from the socket
 *
 * @param sock the socket
 */
network_socket_retval_t network_socket_read(network_socket *sock) {
	gssize len;

	if (sock->to_read > 0) {
		GString *packet = g_string_sized_new(sock->to_read);

		g_queue_push_tail(sock->recv_queue_raw->chunks, packet);

		if (sock->socket_type == SOCK_STREAM) {
			len = recv(sock->fd, packet->str, sock->to_read, 0);
		} else {
			/* UDP */
			network_socklen_t dst_len = sizeof(sock->dst->addr.common);
			len = recvfrom(sock->fd, packet->str, sock->to_read, 0, &(sock->dst->addr.common), &(dst_len));
			sock->dst->len = dst_len;
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
				return NETWORK_SOCKET_WAIT_FOR_EVENT;
			default:
				g_debug("%s: recv() failed: %s (errno=%d)", G_STRLOC, g_strerror(errno), errno);
				return NETWORK_SOCKET_ERROR;
			}
		} else if (len == 0) {
			/**
			 * connection close
			 *
			 * let's call the ioctl() and let it handle it for use
			 */
			return NETWORK_SOCKET_WAIT_FOR_EVENT;
		}

		sock->to_read -= len;
		sock->recv_queue_raw->len += len;
#if 0
		sock->recv_queue_raw->offset = 0; /* offset into the first packet */
#endif
		packet->len = len;
	}

	return NETWORK_SOCKET_SUCCESS;
}

#ifdef HAVE_WRITEV
/**
 * write data to the socket
 *
 */
static network_socket_retval_t network_socket_write_writev(network_socket *con, int send_chunks) {
	/* send the whole queue */
	GList *chunk;
	struct iovec *iov;
	gint chunk_id;
	gint chunk_count;
	gssize len;
	int os_errno;
	gint max_chunk_count;

	if (send_chunks == 0) return NETWORK_SOCKET_SUCCESS;

	chunk_count = send_chunks > 0 ? send_chunks : (gint)con->send_queue->chunks->length;
	
	if (chunk_count == 0) return NETWORK_SOCKET_SUCCESS;

	max_chunk_count = sysconf(_SC_IOV_MAX);

	if (max_chunk_count < 0) { /* option is unknown */
#if defined(UIO_MAXIOV)
		max_chunk_count = UIO_MAXIOV; /* as defined in POSIX */
#elif defined(IOV_MAX)
		max_chunk_count = IOV_MAX; /* on older Linux'es */
#else
		g_assert_not_reached(); /* make sure we provide a work-around in case sysconf() fails on us */
#endif
	}

	chunk_count = chunk_count > max_chunk_count ? max_chunk_count : chunk_count;

	g_assert_cmpint(chunk_count, >, 0); /* make sure it is never negative */

	iov = g_new0(struct iovec, chunk_count);

	for (chunk = con->send_queue->chunks->head, chunk_id = 0; 
	     chunk && chunk_id < chunk_count; 
	     chunk_id++, chunk = chunk->next) {
		GString *s = chunk->data;
	
		if (chunk_id == 0) {
			g_assert(con->send_queue->offset < s->len);

			iov[chunk_id].iov_base = s->str + con->send_queue->offset;
			iov[chunk_id].iov_len  = s->len - con->send_queue->offset;
		} else {
			iov[chunk_id].iov_base = s->str;
			iov[chunk_id].iov_len  = s->len;
		}
	}

	len = writev(con->fd, iov, chunk_count);
	os_errno = errno;

	g_free(iov);

	if (-1 == len) {
		switch (os_errno) {
		case E_NET_WOULDBLOCK:
		case EAGAIN:
			return NETWORK_SOCKET_WAIT_FOR_EVENT;
		case EPIPE:
		case E_NET_CONNRESET:
		case E_NET_CONNABORTED:
			/** remote side closed the connection */
			return NETWORK_SOCKET_ERROR;
		default:
			g_message("%s.%d: writev(%s, ...) failed: %s", 
					__FILE__, __LINE__, 
					con->dst->name->str, 
					g_strerror(errno));
			return NETWORK_SOCKET_ERROR;
		}
	} else if (len == 0) {
		return NETWORK_SOCKET_ERROR;
	}

	con->send_queue->offset += len;
	con->send_queue->len    -= len;

	/* check all the chunks which we have sent out */
	for (chunk = con->send_queue->chunks->head; chunk; ) {
		GString *s = chunk->data;

		if (con->send_queue->offset >= s->len) {
			con->send_queue->offset -= s->len;
#ifdef NETWORK_DEBUG_TRACE_IO
			/* to trace the data we sent to the socket, enable this */
			g_debug_hexdump(G_STRLOC, S(s));
#endif
			g_string_free(s, TRUE);
			
			g_queue_delete_link(con->send_queue->chunks, chunk);

			chunk = con->send_queue->chunks->head;
		} else {
			return NETWORK_SOCKET_WAIT_FOR_EVENT;
		}
	}

	return NETWORK_SOCKET_SUCCESS;
}
#endif

/**
 * write data to the socket
 *
 * use a loop over send() to be compatible with win32
 */
static network_socket_retval_t network_socket_write_send(network_socket *con, int send_chunks) {
	/* send the whole queue */
	GList *chunk;

	if (send_chunks == 0) return NETWORK_SOCKET_SUCCESS;

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
				return NETWORK_SOCKET_WAIT_FOR_EVENT;
			case EPIPE:
			case E_NET_CONNRESET:
			case E_NET_CONNABORTED:
				/** remote side closed the connection */
				return NETWORK_SOCKET_ERROR;
			default:
				g_message("%s: send(%s, %"G_GSIZE_FORMAT") failed: %s", 
						G_STRLOC, 
						con->dst->name->str, 
						s->len - con->send_queue->offset, 
						g_strerror(errno));
				return NETWORK_SOCKET_ERROR;
			}
		} else if (len == 0) {
			return NETWORK_SOCKET_ERROR;
		}

		con->send_queue->offset += len;

		if (con->send_queue->offset == s->len) {
			g_string_free(s, TRUE);
			
			g_queue_delete_link(con->send_queue->chunks, chunk);
			con->send_queue->offset = 0;

			if (send_chunks > 0 && --send_chunks == 0) break;

			chunk = con->send_queue->chunks->head;
		} else {
			return NETWORK_SOCKET_WAIT_FOR_EVENT;
		}
	}

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * write a content of con->send_queue to the socket
 *
 * @param con         socket to read from
 * @param send_chunks number of chunks to send, if < 0 send all
 *
 * @returns NETWORK_SOCKET_SUCCESS on success, NETWORK_SOCKET_ERROR on error and NETWORK_SOCKET_WAIT_FOR_EVENT if the call would have blocked 
 */
network_socket_retval_t network_socket_write(network_socket *con, int send_chunks) {
	if (con->socket_type == SOCK_STREAM) {
#ifdef HAVE_WRITEV
		return network_socket_write_writev(con, send_chunks);
#else
		return network_socket_write_send(con, send_chunks);
#endif
	} else {
		return network_socket_write_send(con, send_chunks);
	}
}

network_socket_retval_t network_socket_to_read(network_socket *sock) {
	int b = -1;

#ifdef SO_NREAD
	/* on MacOS X ioctl(..., FIONREAD) returns _more_ than what we have in the queue */
	if (sock->socket_type == SOCK_DGRAM) {
		network_socklen_t b_len = sizeof(b);

		if (0 != getsockopt(sock->fd, SOL_SOCKET, SO_NREAD, &b, &b_len)) {
			g_critical("%s: getsockopt(%d, SO_NREAD, ...) failed: %s (%d)",
					G_STRLOC,
					sock->fd,
					g_strerror(errno), errno);
			return NETWORK_SOCKET_ERROR;
		} else if (b < 0) {
			g_critical("%s: getsockopt(%d, SO_NREAD, ...) succeeded, but is negative: %d",
					G_STRLOC,
					sock->fd,
					b);

			return NETWORK_SOCKET_ERROR;
		} else {
			sock->to_read = b;
			return NETWORK_SOCKET_SUCCESS;
		}
	}
#endif

	if (0 != ioctl(sock->fd, FIONREAD, &b)) {
		g_critical("%s: ioctl(%d, FIONREAD, ...) failed: %s (%d)",
				G_STRLOC,
				sock->fd,
				g_strerror(errno), errno);
		return NETWORK_SOCKET_ERROR;
	} else if (b < 0) {
		g_critical("%s: ioctl(%d, FIONREAD, ...) succeeded, but is negative: %d",
				G_STRLOC,
				sock->fd,
				b);

		return NETWORK_SOCKET_ERROR;
	} else {
		sock->to_read = b;
		return NETWORK_SOCKET_SUCCESS;
	}

}

/**
 * 检查(服务器)端套接字连接是否已断开
 *
 * @return TRUE:disconnected FALSE:connected
 */
gboolean detect_server_socket_disconnect(network_socket *sock) {
	int fd = -1;
//	int b = -1;
	int r;

	g_assert(sock);

	fd = sock->fd;

	/**
	 *
	 * 情况1. 单独使用ioctl(FIONREAD)，两种情况都是return 0, bytesAvai 0, errno 0，所以不能用ioctl作为判断依据
	 * 情况2. 单独用recv(MSG_PEEK)，可以得到正确结果，正常连接返回return=-1 errno=11，断开连接返回return=0 errno=0（后来测试不一样了，见下）
	 * 情况3. 先执行recv，再执行ioctl，结果见下，但第二个ioctl执行后errno没改变？所以用2.即 recv(MSG_PEEK)
	 *
	 *
	 * 情况3：
	 * 正常的连接
	 * 2013-07-19 20:06:52: (debug) [network-socket.c:875]: detect socket disconnect: recv(271, ..., MSG_PEEK ...) return -1, errno 11
	 * 2013-07-19 20:06:52: (debug) [network-socket.c:888]: detect socket disconnect: ioctl(271, FIONREAD, ...) return 0, bytesAvai 0, errno 11
	 * 服务端正常断开 (kill thread_id)
	 * 2013-07-19 20:07:02: (debug) [network-socket.c:875]: detect socket disconnect: recv(272, ..., MSG_PEEK ...) return 0, errno 0
	 * 2013-07-19 20:07:02: (debug) [network-socket.c:888]: detect socket disconnect: ioctl(272, FIONREAD, ...) return 0, bytesAvai 0, errno 0
	 *
	 * 情况2：
	 * 正常：
	 *   return=-1 errno=11
	 * kill断开：
	 *   很久以前测试好像是：return=0 errno=0
	 *   但后来测试是：return=0 errno=11
	 *   原因不清
	 */

	char buf[1];
	r = recv(fd, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);
	if (r != -1 || errno != EAGAIN) {
		g_debug(
				"[%s]: detect socket disconnect: recv(%d, ..., MSG_PEEK ...) return %d, errno %d",
				G_STRLOC, fd, r, errno);
	}
	if (r == -1) {
		switch (errno) {
		case EAGAIN:
		case E_NET_WOULDBLOCK:
			/**r == -1 && errno = EAGAIN ,非阻塞套接字连接正常，没有读到数据*/
			return FALSE;
		default:
			break;
		}
	} else if (errno == 0) {
		if (r == 0) {
			/** r == 0 && errno == 0 ，服务端断开返回一个0字节的包  。 不确认此情况，后来再kill thread测试没重现 */
			g_critical("[%s]: received a zero length packet. maybe (Linux) server side closed on use. fd=%d", G_STRLOC, fd);
			return TRUE;
		} else {
			/*貌似从来没发生过这种情况，所以也认为是异常情况，应该需要断开此连接*/
			g_critical("recv(%d, ..., MSG_PEEK, ...) said there is something to read, oops: %d", fd, r);
			return TRUE;
		}
	} else if (r == 0) {
		switch (errno) {
		case EAGAIN:
		case E_NET_WOULDBLOCK:
			/**r == 0 && errno = EAGAIN , 数据库服务器端kill thread_id，proxy端观察到发生此情况*/
			g_debug("[%s]: (Linux) server side closed on use. fd=%d", G_STRLOC, fd);
			return TRUE;
		default:
			break;
		}
	}
	g_critical("recv(%d, ..., MSG_PEEK, ...) failed: return %d errno %d", fd, r, errno);
	return TRUE;

	/**
	 * check how much data there is to read
	 *
	 * ioctl()
	 * - returns 0 if connection is closed
	 * - or -1 and ECONNRESET on solaris
	 *   or -1 and EPIPE on HP/UX
	 */
#if 0
	r = ioctl(fd, FIONREAD, &b);
//	g_debug(
//			"[%s]: detect socket disconnect: ioctl(%d, FIONREAD, ...) return %d, bytesAvai %d, errno %d",
//			G_STRLOC, fd, r, b, errno);
	if (r !=0 || b != 0) {
		g_debug(
				"[%s]: detect socket disconnect: ioctl(%d, FIONREAD, ...) return %d, bytesAvai %d, errno %d",
				G_STRLOC, fd, r, b, errno);
	}
	if (r != 0) {
		switch (errno) {
		case E_NET_CONNRESET: /* solaris 断开 */
			g_debug("[%s]: (solaris) server side closed on use. fd=%d", G_STRLOC, fd);
			return TRUE;
		case EPIPE: /* hp/ux 断开 */
			g_debug("[%s]: (hp/ux) server side closed on use. fd=%d", G_STRLOC, fd);
			return TRUE;
		default:
			g_critical("ioctl(%d, FIONREAD, ...) failed: %d", fd, errno);
			break;
		}
	} else if (b != 0) {
		g_critical("ioctl(%d, FIONREAD, ...) said there is something to read, oops: %d", fd, b);
	} else { /* Linux */
		switch (errno) {
		case EAGAIN:
		case E_NET_WOULDBLOCK:
			/** r == 0 && bytes == 0 && errno == EAGAIN(11)，非阻塞套接字没有读到数据，表明连接正常*/
			return FALSE;
		case 0:
			/** r == 0 && bytes == 0 && errno == 0，服务端断开返回一个0字节的包，说明连接已断开 */
			g_debug("[%s]: (Linux) server side closed on use. fd=%d", G_STRLOC, fd);
			return TRUE;
		}
	}
	/**默认连接正常*/
	return FALSE;
#endif

}
