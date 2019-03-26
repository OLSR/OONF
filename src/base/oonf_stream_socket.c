
/*
 * The olsr.org Optimized Link-State Routing daemon version 2 (olsrd2)
 * Copyright (c) 2004-2015, the olsr.org team - see HISTORY file
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */

/**
 * @file
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <oonf/libcommon/autobuf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_stream_socket.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_fd.h>
#include <oonf/base/os_interface.h>
#include <oonf/base/os_system.h>

/* Definitions */
#define LOG_STREAM _oonf_stream_socket_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _stream_close(struct oonf_stream_session *session);
int _apply_managed(struct oonf_stream_managed *managed);
static int _apply_managed_socket(
  int af_type, struct oonf_stream_managed *managed, struct oonf_stream_socket *stream, struct os_interface *os_if);
static void _cb_parse_request(struct oonf_socket_entry *);
static struct oonf_stream_session *_create_session(struct oonf_stream_socket *stream_socket, struct os_fd *sock,
  const struct netaddr *remote_addr, const union netaddr_socket *remote_socket);
static void _cb_parse_connection(struct oonf_socket_entry *entry);

static void _cb_timeout_handler(struct oonf_timer_instance *);
static int _cb_interface_listener(struct os_interface_listener *listener);

/* list of olsr stream sockets */
static struct list_entity _stream_head;

/* server socket */
static struct oonf_class _connection_cookie = { .name = "stream socket connection",
  .size = sizeof(struct oonf_stream_session) };

static struct oonf_timer_class _connection_timeout = {
  .name = "stream socket timout",
  .callback = _cb_timeout_handler,
};

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_SOCKET_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_OS_FD_SUBSYSTEM,
  OONF_OS_INTERFACE_SUBSYSTEM,
  OONF_OS_SYSTEM_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_stream_socket_subsystem = {
  .name = OONF_STREAM_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_stream_socket_subsystem);

/**
 * Initialize the stream socket handlers
 * @return always returns 0
 */
static int
_init(void) {
  oonf_class_add(&_connection_cookie);
  oonf_timer_add(&_connection_timeout);
  list_init_head(&_stream_head);
  return 0;
}

/**
 * Cleanup all resources allocated be stream socket handlers
 */
static void
_cleanup(void) {
  struct oonf_stream_socket *comport;

  while (!list_is_empty(&_stream_head)) {
    comport = list_first_element(&_stream_head, comport, _node);

    oonf_stream_remove(comport, true);
  }

  oonf_class_remove(&_connection_cookie);
  oonf_timer_remove(&_connection_timeout);
}

/**
 * Flush all data in outgoing buffer of a stream socket
 * @param con pointer to stream socket
 */
void
oonf_stream_flush(struct oonf_stream_session *con) {
  oonf_socket_set_write(&con->scheduler_entry, true);
}

/**
 * Add a new stream socket to the scheduler
 * @param stream_socket pointer to stream socket struct with
 *   initialized config
 * @param local pointer to local ip/port of socket, port must be 0 if
 *   this shall be an outgoing socket
 * @return -1 if an error happened, 0 otherwise
 */
int
oonf_stream_add(struct oonf_stream_socket *stream_socket, const union netaddr_socket *local) {
  struct netaddr_str buf;

  /* server socket not necessary for outgoing connections */
  if (netaddr_socket_get_port(local) != 0) {
    /* Init socket */
    if (os_fd_getsocket(&stream_socket->scheduler_entry.fd, local, true, 0, NULL, LOG_STREAM)) {
      goto add_stream_error;
    }

    /* show that we are willing to listen */
    if (os_fd_listen(&stream_socket->scheduler_entry.fd, 1) == -1) {
      OONF_WARN(LOG_STREAM, "tcp socket listen failed for %s: %s (%d)\n", netaddr_socket_to_string(&buf, local),
        strerror(errno), errno);
      goto add_stream_error;
    }
    stream_socket->scheduler_entry.name = stream_socket->socket_name;
    stream_socket->scheduler_entry.process = _cb_parse_request;

    snprintf(stream_socket->socket_name, sizeof(stream_socket->socket_name), "tcp-server: %s",
      netaddr_socket_to_string(&buf, local));
    oonf_socket_add(&stream_socket->scheduler_entry);
    oonf_socket_set_read(&stream_socket->scheduler_entry, true);
  }
  memcpy(&stream_socket->local_socket, local, sizeof(stream_socket->local_socket));

  if (stream_socket->config.memcookie == NULL) {
    stream_socket->config.memcookie = &_connection_cookie;
  }
  if (stream_socket->config.allowed_sessions == 0) {
    stream_socket->config.allowed_sessions = 10;
  }
  if (stream_socket->config.maximum_input_buffer == 0) {
    stream_socket->config.maximum_input_buffer = 65536;
  }

  list_init_head(&stream_socket->session);
  list_add_tail(&_stream_head, &stream_socket->_node);

  return 0;

add_stream_error:
  oonf_socket_remove(&stream_socket->scheduler_entry);
  os_fd_close(&stream_socket->scheduler_entry.fd);
  return -1;
}

/**
 * Remove a stream socket from the scheduler
 * @param stream_socket pointer to socket
 * @param force true if socket will be closed immediately,
 *   false if scheduler should wait until outgoing buffers are empty
 */
void
oonf_stream_remove(struct oonf_stream_socket *stream_socket, bool force) {
  if (stream_socket->busy && !force) {
    stream_socket->remove = true;
    return;
  }

  if (!list_is_node_added(&stream_socket->_node)) {
    return;
  }

  oonf_stream_close_all_sessions(stream_socket);
  list_remove(&stream_socket->_node);

  oonf_socket_remove(&stream_socket->scheduler_entry);
  os_fd_close(&stream_socket->scheduler_entry.fd);

  if (stream_socket->config.cleanup_socket) {
    stream_socket->config.cleanup_socket(stream_socket);
  }
}

/**
 * Closes all client connections of a stream socket, does not close the local
 * socket itself.
 * @param stream_socket stream socket
 */
void
oonf_stream_close_all_sessions(struct oonf_stream_socket *stream_socket) {
  struct oonf_stream_session *session, *ptr;

  if (!list_is_node_added(&stream_socket->_node)) {
    return;
  }

  list_for_each_element_safe(&stream_socket->session, session, node, ptr) {
    if (abuf_getlen(&session->out) == 0 && !session->busy) {
      /* close everything that doesn't need to send data anymore */
      oonf_stream_close(session);
    }
  }
  return;
}

/**
 * Create an outgoing stream socket.
 * @param stream_socket pointer to stream socket
 * @param remote pointer to address of remote TCP server
 * @return pointer to stream session, NULL if an error happened.
 */
struct oonf_stream_session *
oonf_stream_connect_to(struct oonf_stream_socket *stream_socket, const union netaddr_socket *remote) {
  struct oonf_stream_session *session;
  struct os_fd sock;
  struct netaddr remote_addr;
  bool wait_for_connect = false;
  struct netaddr_str nbuf1;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf2;
#endif

  OONF_DEBUG(LOG_STREAM, "Connect TCP socket from %s to %s",
    netaddr_socket_to_string(&nbuf1, &stream_socket->local_socket), netaddr_socket_to_string(&nbuf2, remote));

  if (os_fd_getsocket(&sock, &stream_socket->local_socket, true, 0, NULL, LOG_STREAM)) {
    return NULL;
  }

  if (os_fd_connect(&sock, remote)) {
    if (errno == ECONNREFUSED) {
      /* Don't produce a warning for an failed outgoing TCP connection */
      OONF_INFO(LOG_STREAM, "TCP connection to %s refused: %s (%d)",
        netaddr_socket_to_string(&nbuf1, remote), strerror(errno), errno);
      goto connect_to_error;
    }
    else if (errno != EINPROGRESS) {
      OONF_WARN(LOG_STREAM, "Cannot connect outgoing tcp connection to %s: %s (%d)",
        netaddr_socket_to_string(&nbuf1, remote), strerror(errno), errno);
      goto connect_to_error;
    }
    wait_for_connect = true;
  }

  netaddr_from_socket(&remote_addr, remote);
  session = _create_session(stream_socket, &sock, &remote_addr, remote);
  if (session) {
    session->wait_for_connect = wait_for_connect;
    return session;
  }

  /* fall through */
connect_to_error:
  os_fd_close(&stream_socket->scheduler_entry.fd);
  return NULL;
}

/**
 * Reset the session timeout of a TCP session
 * @param con pointer to stream session
 * @param timeout timeout in milliseconds
 */
void
oonf_stream_set_timeout(struct oonf_stream_session *con, uint64_t timeout) {
  if (oonf_clock_get_absolute(timeout) > oonf_timer_get_due(&con->timeout) + timeout/5) {
    oonf_timer_set(&con->timeout, timeout);
  }
}

/**
 * Close a TCP stream session
 * @param session pointer to stream session
 */
void
oonf_stream_close(struct oonf_stream_session *session) {
  if (session->busy) {
    /* remove the session later */
    session->removed = true;
    return;
  }
  _stream_close(session);
}

/**
 * Initialized a managed TCP stream
 * @param managed pointer to initialized managed stream
 */
void
oonf_stream_add_managed(struct oonf_stream_managed *managed) {
  if (managed->config.allowed_sessions == 0) {
    managed->config.allowed_sessions = 10;
  }
  if (managed->config.maximum_input_buffer == 0) {
    managed->config.maximum_input_buffer = 65536;
  }
  if (managed->config.session_timeout == 0) {
    managed->config.session_timeout = 120000;
  }
  if (managed->config.acl == NULL) {
    managed->config.acl = &managed->_managed_config.acl;
  }

  managed->_if_listener.if_changed = _cb_interface_listener;
  managed->_if_listener.name = managed->_managed_config.interface;
}

/**
 * Apply a configuration to a stream. Will reset both ACLs
 * and socket ports/bindings.
 * @param managed pointer to managed stream
 * @param config pointer to stream config
 * @return -1 if an error happened, 0 otherwise.
 */
int
oonf_stream_apply_managed(struct oonf_stream_managed *managed, struct oonf_stream_managed_config *config) {
  bool if_changed;
  int result;

  if_changed = strcmp(config->interface, managed->_managed_config.interface) != 0 ||
               !list_is_node_added(&managed->_if_listener._node);

  oonf_stream_copy_managed_config(&managed->_managed_config, config);

  if (managed->config.memcookie == NULL) {
    managed->config.memcookie = &_connection_cookie;
  }

  /* set back pointers */
  managed->socket_v4.managed = managed;
  managed->socket_v6.managed = managed;

  /* handle change in interface listener */
  if (if_changed) {
    /* interface changed, remove old listener if necessary */
    os_interface_remove(&managed->_if_listener);

    /* create new interface listener */
    os_interface_add(&managed->_if_listener);
  }

  OONF_DEBUG(LOG_STREAM, "Apply changes for managed socket (if %s) with port %d",
    config->interface == NULL || config->interface[0] == 0 ? "any" : config->interface, config->port);

  result = _apply_managed(managed);
  if (result) {
    /* did not work, trigger interface handler to try later again */
    os_interface_trigger_handler(&managed->_if_listener);
  }
  return result;
}

/**
 * Remove a managed TCP stream
 * @param managed pointer to managed stream
 * @param force true if socket will be closed immediately,
 *   false if scheduler should wait until outgoing buffers are empty
 */
void
oonf_stream_remove_managed(struct oonf_stream_managed *managed, bool force) {
  os_interface_remove(&managed->_if_listener);

  oonf_stream_remove(&managed->socket_v4, force);
  oonf_stream_remove(&managed->socket_v6, force);
  os_interface_remove(&managed->_if_listener);
  oonf_stream_free_managed_config(&managed->_managed_config);
}

/**
 * Closes all connections of a managed socket, but not the socket itself
 * @param managed managed stream socket
 */
void
oonf_stream_close_all_managed_sessions(struct oonf_stream_managed *managed) {
  oonf_stream_close_all_sessions(&managed->socket_v4);
  oonf_stream_close_all_sessions(&managed->socket_v6);
}

/**
 * Free dynamically allocated parts of managed stream configuration
 * @param config packet configuration
 */
void
oonf_stream_free_managed_config(struct oonf_stream_managed_config *config) {
  netaddr_acl_remove(&config->acl);
  netaddr_acl_remove(&config->bindto);
}

/**
 * copies a stream managed configuration object
 * @param dst Destination
 * @param src Source
 */
void
oonf_stream_copy_managed_config(struct oonf_stream_managed_config *dst, struct oonf_stream_managed_config *src) {
  oonf_stream_free_managed_config(dst);

  memcpy(dst, src, sizeof(*dst));

  memset(&dst->acl, 0, sizeof(dst->acl));
  netaddr_acl_copy(&dst->acl, &src->acl);

  memset(&dst->bindto, 0, sizeof(dst->bindto));
  netaddr_acl_copy(&dst->bindto, &src->bindto);
}

/**
 * Close a TCP stream
 * @param session tcp stream session
 */
static void
_stream_close(struct oonf_stream_session *session) {
  if (session->stream_socket->config.cleanup_session) {
    session->stream_socket->config.cleanup_session(session);
  }

  oonf_timer_stop(&session->timeout);

  session->stream_socket->session_counter--;
  list_remove(&session->node);

  oonf_socket_remove(&session->scheduler_entry);
  os_fd_close(&session->scheduler_entry.fd);

  abuf_free(&session->in);
  abuf_free(&session->out);

  oonf_class_free(session->stream_socket->config.memcookie, session);
}

/**
 * Apply the stored settings of a managed socket
 * @param managed pointer to managed stream
 * @return -1 if an error happened, 0 otherwise
 */
int
_apply_managed(struct oonf_stream_managed *managed) {
  struct os_interface *bind_socket_to_if = NULL;

  /* get interface */
  if (!managed->_if_listener.data->flags.any) {
    bind_socket_to_if = managed->_if_listener.data;
  }

  if (_apply_managed_socket(AF_INET, managed, &managed->socket_v4, bind_socket_to_if)) {
    return -1;
  }

  if (os_system_is_ipv6_supported()) {
    if (_apply_managed_socket(AF_INET6, managed, &managed->socket_v6, bind_socket_to_if)) {
      return -1;
    }
  }
  return 0;
}

/**
 * Apply new configuration to a managed stream socket
 * @param af_type address type to bind socket to
 * @param managed pointer to managed stream
 * @param stream pointer to TCP stream to configure
 * @return -1 if an error happened, 0 otherwise.
 */
static int
_apply_managed_socket(
  int af_type, struct oonf_stream_managed *managed, struct oonf_stream_socket *stream, struct os_interface *data) {
  struct netaddr_acl *bind_ip_acl;
  const struct netaddr *bind_ip;
  union netaddr_socket sock;
  struct netaddr_str buf;

  bind_ip_acl = &managed->_managed_config.bindto;

  /* Get address the unicast socket should bind on */
  if (data != NULL && !data->flags.up) {
    bind_ip = NULL;
  }
  else if (data != NULL && netaddr_get_address_family(data->if_linklocal_v6) == af_type &&
           netaddr_acl_check_accept(bind_ip_acl, data->if_linklocal_v6)) {
    bind_ip = data->if_linklocal_v6;
  }
  else {
    bind_ip = os_interface_get_bindaddress(af_type, bind_ip_acl, data);
  }
  if (!bind_ip) {
    oonf_stream_remove(stream, true);
    return 0;
  }
  if (netaddr_socket_init(&sock, bind_ip, managed->_managed_config.port, data == NULL ? 0 : data->index)) {
    OONF_WARN(LOG_STREAM, "Cannot create managed socket address: %s/%u", netaddr_to_string(&buf, bind_ip),
      managed->_managed_config.port);
    return -1;
  }

  if (list_is_node_added(&stream->_node)) {
    if (memcmp(&sock, &stream->local_socket, sizeof(sock)) == 0) {
      /* nothing changed, just copy configuration */
      memcpy(&stream->config, &managed->config, sizeof(stream->config));
      return 0;
    }

    oonf_stream_remove(stream, true);
  }

  /* copy configuration */
  memcpy(&stream->config, &managed->config, sizeof(stream->config));
  if (stream->config.memcookie == NULL) {
    stream->config.memcookie = &_connection_cookie;
  }

  if (oonf_stream_add(stream, &sock)) {
    return -1;
  }

  return 0;
}

/**
 * Handle incoming server socket event from socket scheduler.
 * @param entry socket entry for event parsing
 */
static void
_cb_parse_request(struct oonf_socket_entry *entry) {
  struct oonf_stream_socket *stream;
  union netaddr_socket remote_socket;
  struct netaddr remote_addr;
  struct os_fd sock;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf1, buf2;
#endif

  if (!oonf_socket_is_read(entry)) {
    return;
  }

  stream = container_of(entry, typeof(*stream), scheduler_entry);

  if (os_fd_accept(&sock, &entry->fd, &remote_socket)) {
    OONF_WARN(LOG_STREAM, "accept() call returned error: %s (%d)", strerror(errno), errno);
    return;
  }

  netaddr_from_socket(&remote_addr, &remote_socket);
  if (stream->config.acl) {
    if (!netaddr_acl_check_accept(stream->config.acl, &remote_addr)) {
      OONF_DEBUG(LOG_STREAM, "Access from %s to socket %s blocked because of ACL",
        netaddr_to_string(&buf1, &remote_addr), netaddr_socket_to_string(&buf2, &stream->local_socket));
      os_fd_close(&sock);
      return;
    }
  }
  _create_session(stream, &sock, &remote_addr, &remote_socket);
}

/**
 * Configure a TCP session socket
 * @param stream_socket pointer to stream socket
 * @param sock pointer to socket filedescriptor
 * @param remote_addr pointer to remote address
 * @return pointer to new stream session, NULL if an error happened.
 */
static struct oonf_stream_session *
_create_session(struct oonf_stream_socket *stream_socket, struct os_fd *sock, const struct netaddr *remote_addr,
  const union netaddr_socket *remote_socket) {
  struct oonf_stream_session *session;
  struct netaddr_str nbuf1, nbuf2;

  /* put socket into non-blocking mode */
  if (os_fd_set_nonblocking(sock)) {
    OONF_WARN(LOG_STREAM, "Cannot set socket %d nonblocking: %s (%d)", os_fd_get_fd(sock), strerror(errno), errno);
    return NULL;
  }

  session = oonf_class_malloc(stream_socket->config.memcookie);
  if (session == NULL) {
    OONF_WARN(LOG_STREAM, "Cannot allocate memory for comport session");
    return NULL;
  }

  if (abuf_init(&session->in)) {
    OONF_WARN(LOG_STREAM, "Cannot allocate memory for comport session");
    goto parse_request_error;
  }
  if (abuf_init(&session->out)) {
    OONF_WARN(LOG_STREAM, "Cannot allocate memory for comport session");
    goto parse_request_error;
  }

  os_fd_copy(&session->scheduler_entry.fd, sock);
  session->scheduler_entry.name = session->socket_name;
  session->scheduler_entry.process = _cb_parse_connection;
  session->send_first = stream_socket->config.send_first;
  session->stream_socket = stream_socket;

  session->remote_address = *remote_addr;
  session->remote_socket = *remote_socket;

  /* generate socket name */
  snprintf(session->socket_name, sizeof(session->socket_name), "tcp: %s,%s",
    netaddr_socket_to_string(&nbuf1, &stream_socket->local_socket),
    netaddr_socket_to_string(&nbuf2, &session->remote_socket));

  if (stream_socket->session_counter < stream_socket->config.allowed_sessions) {
    /* create active session */
    session->state = STREAM_SESSION_ACTIVE;
    stream_socket->session_counter++;
  }
  else {
    /* too many sessions */
    if (stream_socket->config.create_error) {
      stream_socket->config.create_error(session, STREAM_SERVICE_UNAVAILABLE);
    }
    session->state = STREAM_SESSION_SEND_AND_QUIT;
  }

  session->timeout.class = &_connection_timeout;
  if (stream_socket->config.session_timeout) {
    oonf_timer_start(&session->timeout, stream_socket->config.session_timeout);
  }

  oonf_socket_add(&session->scheduler_entry);
  oonf_socket_set_read(&session->scheduler_entry, true);
  oonf_socket_set_write(&session->scheduler_entry, true);

  if (stream_socket->config.init_session) {
    if (stream_socket->config.init_session(session)) {
      goto parse_request_error;
    }
  }

  OONF_DEBUG(LOG_STREAM, "Got connection through socket %d with %s.\n", os_fd_get_fd(sock),
    netaddr_to_string(&nbuf1, remote_addr));

  list_add_tail(&stream_socket->session, &session->node);
  return session;

parse_request_error:
  abuf_free(&session->in);
  abuf_free(&session->out);
  oonf_class_free(stream_socket->config.memcookie, session);

  return NULL;
}

/**
 * Handle TCP session timeout
 * @param ptr timer instance that fired
 */
static void
_cb_timeout_handler(struct oonf_timer_instance *ptr) {
  struct oonf_stream_session *session;

  session = container_of(ptr, struct oonf_stream_session, timeout);
  oonf_stream_close(session);
}

/**
 * Handle events for TCP session from network scheduler
 * @param entry socket entry to be parsed
 */
static void
_cb_parse_connection(struct oonf_socket_entry *entry) {
  struct oonf_stream_session *session;
  struct oonf_stream_socket *s_sock;
  int len;
  char buffer[1024];
  struct netaddr_str buf;

  session = container_of(entry, typeof(*session), scheduler_entry);
  s_sock = session->stream_socket;

  OONF_DEBUG(LOG_STREAM, "Parsing connection of socket %d\n", os_fd_get_fd(&entry->fd));

  /* mark session and s_sock as busy */
  session->busy = true;
  s_sock->busy = true;

  if (session->wait_for_connect) {
    if (oonf_socket_is_write(entry)) {
      int value;

      if (os_fd_get_socket_error(&entry->fd, &value)) {
        OONF_WARN(LOG_STREAM, "getsockopt failed: %s (%d)", strerror(errno), errno);
        session->state = STREAM_SESSION_CLEANUP;
      }
      else if (value == ECONNREFUSED) {
        /* Don't produce a warning for an failed outgoing TCP connection */
        OONF_INFO(LOG_STREAM, "TCP connection to %s refused: %s (%d)",
            netaddr_socket_to_string(&buf, &session->remote_socket), strerror(value), value);
        session->state = STREAM_SESSION_CLEANUP;
      }
      else if (value != 0) {
        OONF_WARN(LOG_STREAM, "Connection to %s failed: %s (%d)",
          netaddr_socket_to_string(&buf, &session->remote_socket), strerror(value), value);
        session->state = STREAM_SESSION_CLEANUP;
      }
      else {
        session->wait_for_connect = false;
      }
    }
  }

  if (session->wait_for_connect) {
    session->busy = false;
    s_sock->busy = false;
    return;
  }

  /* read data if necessary */
  if (session->state == STREAM_SESSION_ACTIVE && oonf_socket_is_read(entry)) {
    len = os_fd_recvfrom(&entry->fd, buffer, sizeof(buffer), NULL, 0);
    if (len > 0) {
      OONF_DEBUG(LOG_STREAM, "  recv returned %d\n", len);
      if (abuf_memcpy(&session->in, buffer, len)) {
        /* out of memory */
        OONF_WARN(LOG_STREAM, "Out of memory for comport session input buffer");
        session->state = STREAM_SESSION_CLEANUP;
      }
      else if (abuf_getlen(&session->in) > s_sock->config.maximum_input_buffer) {
        /* input buffer overflow */
        if (s_sock->config.create_error) {
          s_sock->config.create_error(session, STREAM_REQUEST_TOO_LARGE);
        }
        session->state = STREAM_SESSION_SEND_AND_QUIT;
      }
      else {
        /* got new input block, reset timeout */
        oonf_stream_set_timeout(session, s_sock->config.session_timeout);
      }
    }
    else if (len < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
      /* error during read */
      OONF_WARN(LOG_STREAM, "Error while reading from communication stream with %s: %s (%d)\n",
        netaddr_to_string(&buf, &session->remote_address), strerror(errno), errno);
      session->state = STREAM_SESSION_CLEANUP;
    }
    else if (len == 0) {
      /* external s_sock closed */
      session->state = STREAM_SESSION_SEND_AND_QUIT;

      /* still call callback once more */
      session->state = s_sock->config.receive_data(session);

      /* switch off read events */
      oonf_socket_set_read(entry, false);
    }
  }

  if (session->state == STREAM_SESSION_ACTIVE && s_sock->config.receive_data != NULL &&
      (abuf_getlen(&session->in) > 0 || session->send_first)) {
    session->state = s_sock->config.receive_data(session);
    session->send_first = false;
  }

  /* send data if necessary */
  if (session->state != STREAM_SESSION_CLEANUP && abuf_getlen(&session->out) > 0) {
    if (oonf_socket_is_write(entry)) {
      len = os_fd_sendto(&entry->fd, abuf_getptr(&session->out), abuf_getlen(&session->out), NULL, false);

      if (len > 0) {
        OONF_DEBUG(LOG_STREAM, "  send returned %d\n", len);
        abuf_pull(&session->out, len);
        oonf_stream_set_timeout(session, s_sock->config.session_timeout);
      }
      else if (len < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
        OONF_WARN(LOG_STREAM, "Error while writing to communication stream with %s: %s (%d)\n",
          netaddr_to_string(&buf, &session->remote_address), strerror(errno), errno);
        session->state = STREAM_SESSION_CLEANUP;
      }
    }
    else {
      OONF_DEBUG(LOG_STREAM, "  activating output in scheduler\n");
      oonf_socket_set_write(&session->scheduler_entry, true);
    }
  }

  /* send file if necessary */
  if (session->state == STREAM_SESSION_SEND_AND_QUIT && abuf_getlen(&session->out) == 0 &&
      os_fd_is_initialized(&session->copy_fd)) {
    if (oonf_socket_is_write(entry)) {
      len = os_fd_sendfile(
        &entry->fd, &session->copy_fd, session->copy_bytes_sent, session->copy_total_size - session->copy_bytes_sent);
      if (len <= 0) {
        OONF_WARN(LOG_STREAM, "Error while copying file to output stream (%d/%d): %s (%d)", os_fd_get_fd(&entry->fd),
          os_fd_get_fd(&session->copy_fd), strerror(errno), errno);
        session->state = STREAM_SESSION_CLEANUP;
      }
      else {
        session->copy_bytes_sent += len;
      }
    }
  }

  /* check for buffer underrun */
  if (session->state == STREAM_SESSION_ACTIVE && abuf_getlen(&session->out) == 0 &&
      s_sock->config.buffer_underrun != NULL) {
    session->state = s_sock->config.buffer_underrun(session);
  }

  if (abuf_getlen(&session->out) == 0 && session->copy_bytes_sent == session->copy_total_size) {
    /* nothing to send anymore */
    OONF_DEBUG(LOG_STREAM, "  deactivating output in scheduler\n");
    oonf_socket_set_write(&session->scheduler_entry, false);
    if (session->state == STREAM_SESSION_SEND_AND_QUIT) {
      session->state = STREAM_SESSION_CLEANUP;
    }
  }

  session->busy = false;
  s_sock->busy = false;

  /* end of connection ? */
  if (session->state == STREAM_SESSION_CLEANUP || session->removed) {
    OONF_DEBUG(LOG_STREAM, "  cleanup\n");

    /* clean up connection by calling cleanup directly */
    _stream_close(session);

    /* session object will not be valid anymore after this point */
  }

  /* lazy socket removal */
  if (s_sock->remove) {
    oonf_stream_remove(s_sock, false);
  }
  return;
}

/**
 * Callbacks for events on the interface
 * @param interf os interface listener that fired
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_interface_listener(struct os_interface_listener *interf) {
  struct oonf_stream_managed *managed;
  int result;

  /* calculate managed socket for this event */
  managed = container_of(interf, struct oonf_stream_managed, _if_listener);

  result = _apply_managed(managed);

  OONF_DEBUG(LOG_STREAM, "Result from interface %s triggered socket reconfiguration: %d", interf->name, result);

  return result;
}
