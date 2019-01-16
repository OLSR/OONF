
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

#ifndef OONF_STREAM_SOCKET_H_
#define OONF_STREAM_SOCKET_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/autobuf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>

#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_socket.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_interface.h>

/*! subsystem identifier */
#define OONF_STREAM_SUBSYSTEM "stream_socket"

/**
 * TCP session states
 */
enum oonf_stream_session_state
{
  /*! tcp session has not been initialized */
  STREAM_SESSION_INACTIVE,

  /*! tcp session is active */
  STREAM_SESSION_ACTIVE,

  /*! tcp session will send its current buffer content and terminate */
  STREAM_SESSION_SEND_AND_QUIT,

  /*! tcp session will terminate */
  STREAM_SESSION_CLEANUP,
};

/**
 * generic stream errors useful for HTTP and telnet
 */
enum oonf_stream_errors
{
  /*! remote endpoint is not permitted to use service */
  STREAM_REQUEST_FORBIDDEN = 403,

  /*! input buffer overflow */
  STREAM_REQUEST_TOO_LARGE = 413,

  /*! too many incoming sessions */
  STREAM_SERVICE_UNAVAILABLE = 503,
};

/**
 * TCP stream socket
 */
struct oonf_stream_session {
  /*! ip addr of peer */
  struct netaddr remote_address;

  /*! full socket (ip, port, maybe interface) of peer */
  union netaddr_socket remote_socket;

  /**
   * output buffer, anything inside will be written to the peer as
   * soon as possible
   */
  struct autobuf out;

  /**
   * file input descriptor for file upload
   *
   * will only be used in SEND_AND_QUIT state if out buffer is empty
   */
  struct os_fd copy_fd;

  /*! name of socket */
  char socket_name[sizeof(struct netaddr_str) * 2 + 10];

  /*! number of bytes already copied in file upload */
  size_t copy_bytes_sent;

  /*! total number of bytes to copy for file upload */
  size_t copy_total_size;

  /*! hook into list of tcp sessions of TCP socket */
  struct list_entity node;

  /*! backpointer to the stream socket */
  struct oonf_stream_socket *stream_socket;

  /*! scheduler handler for the session */
  struct oonf_socket_entry scheduler_entry;

  /*! timer for handling session timeout */
  struct oonf_timer_instance timeout;

  /*! input buffer for session */
  struct autobuf in;

  /**
   * true if session user want to send before receiving anything. Will trigger
   * an empty read even as soon as session is connected
   */
  bool send_first;

  /*! true if session is still waiting for initial handshake to finish */
  bool wait_for_connect;

  /*! session event is just busy in scheduler */
  bool busy;

  /*! session has been remove while being busy */
  bool removed;

  /*! state of the session */
  enum oonf_stream_session_state state;
};

/**
 * Configuration of a stream socket
 */
struct oonf_stream_config {
  /**
   * memory cookie to allocate struct for tcp session
   * the first part of this memory will be a tcp_steam_session!
   */
  struct oonf_class *memcookie;

  /*! number of simultaneous sessions (default 10) */
  int allowed_sessions;

  /**
   * Timeout of the socket. A session will be closed if it does not
   * send or receive data for timeout milliseconds.
   */
  uint64_t session_timeout;

  /*! maximum allowed size of input buffer (default 65536) */
  size_t maximum_input_buffer;

  /**
   * true if the socket wants to send data before it receives anything.
   * This will trigger an size 0 read event as soon as the socket is connected
   */
  bool send_first;

  /*! only clients that match the acl (if set) can connect */
  struct netaddr_acl *acl;

  /**
   * Callback to notify that a new session has been created
   * @param session stream session
   * @return -1 if an error happened, 0 otherwise
   */
  int (*init_session)(struct oonf_stream_session *session);

  /**
   * Callback to notify that a stream session will be terminated
   * @param session stream session
   */
  void (*cleanup_session)(struct oonf_stream_session *session);

  /**
   * Callback to notify that the socket has been terminated
   * @param socket terminated stream socket
   */
  void (*cleanup_socket)(struct oonf_stream_socket *stream_socket);

  /**
   * Callback to notify that an error happened and the user might
   * want to put an error message in the output buffer.
   * @param session stream session
   * @param error tcp stream error code
   */
  void (*create_error)(struct oonf_stream_session *session, enum oonf_stream_errors error);

  /**
   * Callback that is called every times no data has been written
   * into the input buffer
   * @param stream stream session
   * @return stream session status code
   */
  enum oonf_stream_session_state (*receive_data)(struct oonf_stream_session *stream);

  /*
   * Called when we could write to the buffer but it is empty
   */
  /**
   * Callback to notify that the user asked scheduler to write
   * data, but outgoing buffer is empty
   * @param session stream session
   * @return stream session status code
   */
  enum oonf_stream_session_state (*buffer_underrun)(struct oonf_stream_session *session);
};

/**
 * Represents a TCP server socket or a configuration for a set of outgoing
 * TCP streams.
 */
struct oonf_stream_socket {
  /*! hook into global list of TCP sockets */
  struct list_entity _node;

  /*! local address/port of socket */
  union netaddr_socket local_socket;

  /*! list of open sessions of this socket */
  struct list_entity session;

  /*! scheduler for handling server socket */
  struct oonf_socket_entry scheduler_entry;

  /*! configuration of server socket */
  struct oonf_stream_config config;

  /*! optional back pointer for managed tcp sockets */
  struct oonf_stream_managed *managed;

  /*! name of socket */
  char socket_name[sizeof(struct netaddr_str) + 14];

  /*! number of currently active sessions */
  int32_t session_counter;

  /*! true if socket is currently busy in scheduler */
  bool busy;

  /*! true if socket should be removed */
  bool remove;

  /*! true if socket should be removed when output buffer is empty */
  bool remove_when_finished;
};

/**
 * configuration of a managed dualstack TCP server socket
 */
struct oonf_stream_managed_config {
  /*! access control for IP addresses allowed to access the socket */
  struct netaddr_acl acl;

  /*! interface to bind to socket to, empty string for "all interfaces" */
  char interface[IF_NAMESIZE];

  /*! ACL for selecting the address to bind the socket to */
  struct netaddr_acl bindto;

  /*! port number for TCP server socket, 0 for random port */
  int32_t port;
};

/**
 * managed dualstack TCP server socket
 */
struct oonf_stream_managed {
  /*! stream socket for IPv4 */
  struct oonf_stream_socket socket_v4;

  /*! stream socket for IPv6 */
  struct oonf_stream_socket socket_v6;

  /*! configuration for both stream sockets */
  struct oonf_stream_config config;

  /*! configuration of managed socket */
  struct oonf_stream_managed_config _managed_config;

  /*! listener to interface the socket is bound to */
  struct os_interface_listener _if_listener;
};

EXPORT int oonf_stream_add(struct oonf_stream_socket *, const union netaddr_socket *local);
EXPORT void oonf_stream_remove(struct oonf_stream_socket *, bool force);
EXPORT void oonf_stream_close_all_sessions(struct oonf_stream_socket *stream_socket);
EXPORT struct oonf_stream_session *oonf_stream_connect_to(
  struct oonf_stream_socket *, const union netaddr_socket *remote);
EXPORT void oonf_stream_flush(struct oonf_stream_session *con);

EXPORT void oonf_stream_set_timeout(struct oonf_stream_session *con, uint64_t timeout);
EXPORT void oonf_stream_close(struct oonf_stream_session *con);

EXPORT void oonf_stream_add_managed(struct oonf_stream_managed *);
EXPORT int oonf_stream_apply_managed(struct oonf_stream_managed *, struct oonf_stream_managed_config *);
EXPORT void oonf_stream_remove_managed(struct oonf_stream_managed *, bool force);
EXPORT void oonf_stream_close_all_managed_sessions(struct oonf_stream_managed *managed);
EXPORT void oonf_stream_copy_managed_config(
  struct oonf_stream_managed_config *dst, struct oonf_stream_managed_config *src);
EXPORT void oonf_stream_free_managed_config(struct oonf_stream_managed_config *config);

#endif /* OONF_STREAM_SOCKET_H_ */
