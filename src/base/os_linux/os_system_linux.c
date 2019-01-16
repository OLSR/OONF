
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

/* must be first because of a problem with linux/rtnetlink.h */
#include <sys/socket.h>

/* and now the rest of the includes */
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/string.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_socket.h>
#include <oonf/base/oonf_class.h>

#include <oonf/base/os_linux/os_system_linux.h>
#include <oonf/base/os_system.h>

#include <stdio.h>

#ifndef SOL_NETLINK
/*! socket netlink type */
#define SOL_NETLINK 270
#endif

/* Definitions */
#define LOG_OS_SYSTEM _oonf_os_system_subsystem.logging

enum {
  NETLINK_MESSAGE_BLOCK_SIZE = 4096,
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static struct os_system_netlink_socket *_add_protocol(int32_t protocol);
static void _remove_protocol(struct os_system_netlink_socket *nl_socket);

static void _cb_handle_netlink_timeout(struct oonf_timer_instance *);
static void _netlink_handler(struct oonf_socket_entry *entry);

/* static buffers for receiving/sending a netlink message */
static struct sockaddr_nl _netlink_nladdr = {
  .nl_family = AF_NETLINK,
  .nl_pid    = 0,
  .nl_groups = 0,
};

static void *_netlink_rcv_buffer = NULL;
static size_t _netlink_rcv_size = 0;

static struct iovec _netlink_rcv_iov = {
  .iov_base = NULL,
  .iov_len  = 0
};

static struct msghdr _netlink_rcv_msg = { 
  .msg_name         = &_netlink_nladdr,
  .msg_namelen      = sizeof(_netlink_nladdr),
  .msg_iov          = &_netlink_rcv_iov,
  .msg_iovlen       = 1,
  .msg_control      = NULL,
  .msg_controllen   = 0,
  .msg_flags        = 0
};

static struct nlmsghdr _netlink_hdr_done = {
  .nlmsg_len = sizeof(struct nlmsghdr),
  .nlmsg_type = NLMSG_DONE, 
  .nlmsg_flags = 0,
};
static struct iovec _netlink_send_iov[32];

static struct msghdr _netlink_send_msg = {
  .msg_name       = &_netlink_nladdr, 
  .msg_namelen    = sizeof(_netlink_nladdr), 
  .msg_iov        = _netlink_send_iov,
  .msg_iovlen     = ARRAYSIZE(_netlink_send_iov),
  .msg_control    = NULL,
  .msg_controllen = 0,
  .msg_flags      = 0
};

/* netlink timeout handling */
static struct oonf_timer_class _netlink_timer = {
  .name = "netlink feedback timer",
  .callback = _cb_handle_netlink_timeout,
};

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_SOCKET_SUBSYSTEM,
  OONF_CLASS_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_os_system_subsystem = {
  .name = OONF_OS_SYSTEM_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_os_system_subsystem);

/* tracking of used netlink sequence numbers */
static uint32_t _seq_used = 0;

/* global ioctl sockets for ipv4 and ipv6 */
static int _ioctl_v4, _ioctl_v6;

/* tree of netlink protocols */
static struct avl_tree _netlink_protocol_tree;

static struct oonf_class _netlink_protocol_class = {
  .name = "netlink protocol",
  .size = sizeof(struct os_system_netlink_socket),
};

/**
 * Initialize os-specific subsystem
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  _netlink_rcv_buffer = calloc(NETLINK_MESSAGE_BLOCK_SIZE, 1);
  if (!_netlink_rcv_buffer) {
    return -1;
  }
  _netlink_rcv_size = NETLINK_MESSAGE_BLOCK_SIZE;
  
  _ioctl_v4 = socket(AF_INET, SOCK_DGRAM, 0);
  if (_ioctl_v4 == -1) {
    OONF_WARN(LOG_OS_SYSTEM, "Cannot open ipv4 ioctl socket: %s (%d)", strerror(errno), errno);
    free(_netlink_rcv_buffer);
    return -1;
  }

  _ioctl_v6 = socket(AF_INET6, SOCK_DGRAM, 0);
  if (_ioctl_v6 == -1) {
    OONF_INFO(LOG_OS_SYSTEM, "Node is not IPv6 capable");
  }

  oonf_timer_add(&_netlink_timer);
  avl_init(&_netlink_protocol_tree, avl_comp_int32, false);
  oonf_class_add(&_netlink_protocol_class);
  return 0;
}

/**
 * Cleanup os-specific subsystem
 */
static void
_cleanup(void) {
  struct os_system_netlink_socket *nlp, *nlp_it;

  avl_for_each_element_safe(&_netlink_protocol_tree, nlp, _node, nlp_it) {
    _remove_protocol(nlp);
  }
  oonf_class_remove(&_netlink_protocol_class);
  oonf_timer_remove(&_netlink_timer);
  close(_ioctl_v4);
  if (_ioctl_v6 != -1) {
    close(_ioctl_v6);
  }
  free(_netlink_rcv_buffer);
}

/**
 * @return true if IPv6 is supported, false otherwise
 */
bool
os_system_linux_is_ipv6_supported(void) {
  return _ioctl_v6 != -1;
}

/**
 * @param v1 first version number part
 * @param v2 second version number part
 * @param v3 third version number part
 * @return true if linux kernel is at least a specific version
 */
bool
os_system_linux_is_minimal_kernel(int v1, int v2, int v3) {
  struct utsname uts;
  char *next;
  int first = 0, second = 0, third = 0;

  memset(&uts, 0, sizeof(uts));
  if (uname(&uts)) {
    OONF_WARN(LOG_OS_SYSTEM, "Error, could not read kernel version: %s (%d)\n", strerror(errno), errno);
    return false;
  }

  first = strtol(uts.release, &next, 10);
  /* check for linux 3.x */
  if (first > v1) {
    return true;
  }
  else if (first < v1) {
    return false;
  }

  if (*next != '.') {
    goto kernel_parse_error;
  }

  second = strtol(next + 1, &next, 10);
  if (second > v2) {
    return true;
  }
  if (second < v2) {
    return false;
  }
  if (*next != '.') {
    goto kernel_parse_error;
  }

  third = strtol(next + 1, NULL, 10);
  return third >= v3;

kernel_parse_error:
  OONF_WARN(LOG_OS_SYSTEM, "Error, cannot parse kernel version: %s\n", uts.release);
  return false;
}

/**
 * Returns an operation system socket for ioctl usage
 * @param af_type address family type
 * @return socket file descriptor, -1 if not surrported
 */
int
os_system_linux_linux_get_ioctl_fd(int af_type) {
  switch (af_type) {
    case AF_INET:
      return _ioctl_v4;
    case AF_INET6:
      return _ioctl_v6;
    default:
      return -1;
  }
}

/**
 * Open a new bidirectional netlink socket
 * @param nl pointer to initialized netlink socket handler
 * @param protocol protocol id (NETLINK_ROUTING for example)
 * @return -1 if an error happened, 0 otherwise
 */
int
os_system_linux_netlink_add(struct os_system_netlink *nl, int protocol) {
  size_t i;
  nl->nl_socket = _add_protocol(protocol);
  if (!nl->nl_socket) {
    return -1;
  }
  
  for (i = 0; i < nl->multicast_count; i++) {
    if (setsockopt(os_fd_get_fd(&nl->nl_socket->nl_socket.fd),
        SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &nl->multicast[i], sizeof(nl->multicast[i]))) {
      OONF_WARN(nl->used_by->logging, "Netlink '%s': could not join mc group: %d", 
                nl->name, nl->multicast[i]);
      return -1;
    }
  }
  
  list_add_tail(&nl->nl_socket->handlers, &nl->_node);
  return 0;
}

/**
 * Close a netlink socket handler
 * @param nl pointer to handler
 */
void
os_system_linux_netlink_remove(struct os_system_netlink *nl) {
  struct os_system_netlink_socket *nl_socket;
  nl_socket = nl->nl_socket;

  list_remove(&nl->_node);
  if (!list_is_empty(&nl_socket->handlers)) {
    return;
  }
  _remove_protocol(nl_socket);
}

/**
 * Add a netlink message to the outgoign queue of a handler
 * @param nl pointer to netlink handler
 * @param nl_hdr pointer to netlink message
 */
void
os_system_linux_netlink_send(struct os_system_netlink *nl, struct os_system_netlink_message *msg) {
  struct os_system_netlink_socket *nl_socket;
  struct nlmsghdr *hdr;
  
  nl_socket = nl->nl_socket;
  hdr = msg->message;
  OONF_ASSERT(msg->message, LOG_OS_SYSTEM, "no netlink message");
  _seq_used = (_seq_used + 1) & INT32_MAX;
  if (_seq_used == 0) {
    _seq_used++;
  }

  /* initialize os_system header */
  msg->dump = (hdr->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP;
  msg->originator = nl;
  msg->result = -1;

  /* finish netlink header */
  hdr->nlmsg_seq = _seq_used;
  hdr->nlmsg_pid = nl_socket->pid;
  hdr->nlmsg_flags |= NLM_F_ACK;

  OONF_DEBUG_HEX(nl->used_by->logging, hdr, hdr->nlmsg_len, 
                 "Netlink '%s': Append message (type=%u, len=%u, seq=%u, pid=%u, flags=0x%04x)", 
                 nl->name, hdr->nlmsg_type, hdr->nlmsg_len, hdr->nlmsg_seq, hdr->nlmsg_pid, hdr->nlmsg_flags);

  /* trigger write */
  if (list_is_empty(&nl_socket->buffered_messages) && list_is_empty(&nl_socket->sent_messages)) {
    oonf_socket_set_write(&nl_socket->nl_socket, true);
  }
  list_add_tail(&nl->nl_socket->buffered_messages, &msg->_node);
}

/**
 * Add an attribute to a netlink message
 * @param nl pinter to os netlink handler
 * @param nlmsg pointer to netlink header
 * @param type type of netlink attribute
 * @param data pointer to data of netlink attribute
 * @param len length of data of netlink attribute
 * @return -1 if netlink message got too large, 0 otherwise
 */
int
os_system_linux_netlink_addreq(struct os_system_netlink_message *nl_msg, int type, const void *data, int len) {
  struct nlmsghdr *hdr;
  struct nlattr *nl_attr;
  size_t aligned_msg_len, aligned_attr_len;

  hdr = nl_msg->message;

  /* calculate aligned length of message and new attribute */
  aligned_msg_len = NLMSG_ALIGN(hdr->nlmsg_len);
  aligned_attr_len = NLMSG_ALIGN(NLA_HDRLEN + len);

  if (aligned_msg_len + aligned_attr_len > nl_msg->max_length) {
    OONF_WARN(LOG_OS_SYSTEM, "Netlink '%s:' message got too large!", nl_msg->originator->name);
    return -1;
  }

  nl_attr = (struct nlattr *)((void *)((char *)hdr + aligned_msg_len));
  nl_attr->nla_type = type;
  nl_attr->nla_len = aligned_attr_len;

  /* fix length of netlink message */
  hdr->nlmsg_len = aligned_msg_len + aligned_attr_len;

  if (len) {
    memcpy((char *)nl_attr + NLA_HDRLEN, data, len);
  }
  return 0;
}

/**
* Add new protocol instance of netlink socket
* @param protocol protocol id
* @return pointer to new netlink protocol, NULL if failed to allocate
*/
static struct os_system_netlink_socket *
_add_protocol(int32_t protocol) {
  struct os_system_netlink_socket *nl_sock;
  static uint32_t socket_id = 0;
  struct sockaddr_nl addr;
  int recvbuf;
  int fd;

  nl_sock = avl_find_element(&_netlink_protocol_tree, &protocol, nl_sock, _node);
  if (nl_sock) {
    return nl_sock;
  }
  
  nl_sock = oonf_class_malloc(&_netlink_protocol_class);
  if (!nl_sock) {
    return NULL;
  }

  fd = socket(PF_NETLINK, SOCK_RAW, protocol);
  if (fd < 0) {
    OONF_WARN(LOG_OS_SYSTEM, "Cannot open netlink socket type %d: %s (%d)",
              protocol, strerror(errno), errno);
    goto os_add_netlink_fail;
  }

  if (os_fd_init(&nl_sock->nl_socket.fd, fd)) {
    OONF_WARN(LOG_OS_SYSTEM, "Netlink %d: Could not initialize socket representation", protocol);
    goto os_add_netlink_fail;
  }
  nl_sock->in = calloc(1, NETLINK_MESSAGE_BLOCK_SIZE);
  if (nl_sock->in == NULL) {
    OONF_WARN(LOG_OS_SYSTEM, "Netlink type %d: Not enough memory for input buffer", protocol);
    goto os_add_netlink_fail;
  }
  nl_sock->in_max_len = NETLINK_MESSAGE_BLOCK_SIZE;

  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;
  addr.nl_pid = (((uint32_t)getpid()) & ((1u<<22)-1)) + (socket_id << 22);
  nl_sock->pid = addr.nl_pid;
  socket_id++;

#if defined(SO_RCVBUF)
  recvbuf = 65536;
  if (setsockopt(nl_sock->nl_socket.fd.fd, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf))) {
    OONF_WARN(LOG_OS_SYSTEM,
    "Netlink type %d: Cannot setup receive buffer size for socket: %s (%d)\n",
    protocol, strerror(errno), errno);
  }
#endif

  if (bind(nl_sock->nl_socket.fd.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    OONF_WARN(LOG_OS_SYSTEM, "Netlink type %d: Could not bind socket: %s (%d)", protocol, strerror(errno), errno);
    goto os_add_netlink_fail;
  }

  nl_sock->nl_socket.name = "os_system_netlink";
  nl_sock->nl_socket.process = _netlink_handler;
  oonf_socket_add(&nl_sock->nl_socket);
  oonf_socket_set_read(&nl_sock->nl_socket, true);

  nl_sock->timeout.class = &_netlink_timer;

  OONF_DEBUG(LOG_OS_SYSTEM, "Netlink type %d: Bound netlink socket pid %u",
            protocol, addr.nl_pid);

  nl_sock->netlink_type = protocol;
  nl_sock->_node.key = &nl_sock->netlink_type;
  avl_insert(&_netlink_protocol_tree, &nl_sock->_node);

  list_init_head(&nl_sock->buffered_messages);
  list_init_head(&nl_sock->sent_messages);
  list_init_head(&nl_sock->handlers);
  return nl_sock;

os_add_netlink_fail:
  os_fd_invalidate(&nl_sock->nl_socket.fd);
  if (fd != -1) {
    close(fd);
  }
  free(nl_sock->in);
  return NULL;
}

/**
* Remove netlink protocol instance
* @param nl_socket netlink protocol instance
*/
static void 
_remove_protocol(struct os_system_netlink_socket *nl_socket) {
  if (os_fd_is_initialized(&nl_socket->nl_socket.fd)) {
    oonf_socket_remove(&nl_socket->nl_socket);

    os_fd_close(&nl_socket->nl_socket.fd);
  }
  free(nl_socket->in);
  avl_remove(&_netlink_protocol_tree, &nl_socket->_node);
  oonf_class_free(&_netlink_protocol_class, nl_socket);
}

/**
 * Handle timeout of netlink acks
 * @param ptr timer instance that fired
 */
static void
_cb_handle_netlink_timeout(struct oonf_timer_instance *ptr) {
  struct os_system_netlink_socket *nl_socket;
  struct os_system_netlink_message *msg, *msg_it;
  
  nl_socket = container_of(ptr, struct os_system_netlink_socket, timeout);

  list_for_each_element_safe(&nl_socket->sent_messages, msg, _node, msg_it) {
    if (msg->originator->cb_error) {
      msg->originator->cb_error(msg);
    }
    list_remove(&msg->_node);
  }
  
  oonf_socket_set_write(&nl_socket->nl_socket, !list_is_empty(&nl_socket->buffered_messages));
}

static void
/**
* Collects a block of non-dumping (or a single dumping query) and sends them out
* to the kernel netlink subsystem
* @param nl_socket netlink protocol instance
*/
_send_netlink_messages(struct os_system_netlink_socket *nl_socket) {
  struct os_system_netlink_message *nl_msg, *nl_msg_it;
  size_t i, count, size;
  struct nlmsghdr *nl_hdr;
  ssize_t ret;
  int err;
  if (!list_is_empty(&nl_socket->sent_messages)) {
    /* still messages in transit */
    return;
  }
  if (list_is_empty(&nl_socket->buffered_messages)) {
    oonf_socket_set_write(&nl_socket->nl_socket, false);
    return;
  }
 
  count = 0;
  size = _netlink_hdr_done.nlmsg_len;

  nl_msg = list_first_element(&nl_socket->buffered_messages, nl_msg, _node);
  do {
    _netlink_send_iov[count].iov_base = nl_msg->message;
    _netlink_send_iov[count].iov_len = nl_msg->message->nlmsg_len;

    OONF_INFO(LOG_OS_SYSTEM, "Sending netlink message from %s with seq %d",
              nl_msg->originator->name, nl_msg->message->nlmsg_seq);

    /* move to sent list */
    list_remove(&nl_msg->_node);
    list_add_tail(&nl_socket->sent_messages, &nl_msg->_node);
    count++;
    size += nl_msg->message->nlmsg_len;

    if (nl_msg->dump) {
      /* no aggregation of dump netlink commands */
      break;
    }

    nl_msg = list_first_element(&nl_socket->buffered_messages, nl_msg, _node);
  } while (!list_is_empty(&nl_socket->buffered_messages)
      && count < ARRAYSIZE(_netlink_send_iov)-1
      && !nl_msg->dump
      && size + nl_msg->message->nlmsg_len < NETLINK_MESSAGE_BLOCK_SIZE);

  /* fix IO vector */
  if (count > 1) {
    for (i=0; i<count; i++) {
      nl_hdr = _netlink_send_iov[i].iov_base;
      nl_hdr->nlmsg_flags |= NLM_F_MULTI;
    }
    _netlink_send_iov[count].iov_base = &_netlink_hdr_done;
    _netlink_send_iov[count].iov_len = sizeof(_netlink_hdr_done);
  }
  _netlink_send_msg.msg_iovlen = count;
  
  if ((ret = sendmsg(os_fd_get_fd(&nl_socket->nl_socket.fd), &_netlink_send_msg, MSG_DONTWAIT)) <= 0) {
    /* a transmission error happened */
    err = errno;
#if EAGAIN == EWOULDBLOCK
    if (err != EAGAIN) {
#else
    if (err != EAGAIN && err != EWOULDBLOCK) {
#endif
      /* something serious happened */
      OONF_WARN(LOG_OS_SYSTEM,
        "Netlink '%d': Cannot send data (%" PRINTF_SIZE_T_SPECIFIER " bytes): %s (%d)",
        nl_socket->netlink_type, size, strerror(err), err);

      /* report error */
      list_for_each_element_safe(&nl_socket->sent_messages, nl_msg, _node,  nl_msg_it) {
        list_remove(&nl_msg->_node);
        nl_msg->result = err;
        if (nl_msg->originator->cb_error) {
          nl_msg->originator->cb_error(nl_msg);
        }
      }
    }
    else {
      /* just try again later, shuffle messages back to transmission queue */
      list_for_each_element_reverse_safe(&nl_socket->sent_messages, nl_msg, _node,  nl_msg_it) {
        list_remove(&nl_msg->_node);
        list_add_head(&nl_socket->buffered_messages, &nl_msg->_node);
      }
    }
  }
  else {
    OONF_DEBUG(LOG_OS_SYSTEM, "Netlink '%d': Sent %"PRINTF_SSIZE_T_SPECIFIER" bytes "
                              "(%"PRINTF_SIZE_T_SPECIFIER" messages in transit)", 
               nl_socket->netlink_type, size, count);

    /* start feedback timer */
    oonf_timer_set(&nl_socket->timeout, OS_SYSTEM_NETLINK_TIMEOUT);
  }
}

/**
* Find a netlink message in transfer with a specific sequence number
* @param nl_socket netlink protocol instance
* @param seqno netlink sequence number
* @return netlink message, NULL if not found
*/
static struct os_system_netlink_message *
_find_matching_message(struct os_system_netlink_socket *nl_socket, uint32_t seqno) {
  struct os_system_netlink_message *nl_msg;

  list_for_each_element(&nl_socket->sent_messages, nl_msg, _node) {
    if (nl_msg->message->nlmsg_seq == seqno) {
      return nl_msg;
    }
  }
  return NULL;
}

/**
 * Handler for incoming netlink messages
 * @param entry OONF socket entry creating the callback
 */
static void
_netlink_handler(struct oonf_socket_entry *entry) {
  struct os_system_netlink_socket *nl_socket;
  struct os_system_netlink_message *nl_msg;
  struct os_system_netlink *nl_handler;
  struct nlmsghdr *nh;
  struct nlmsgerr *err;
  ssize_t ret;
  size_t len, i;
  int flags;

  nl_socket = container_of(entry, typeof(*nl_socket), nl_socket);
  if (oonf_socket_is_write(entry)) {
    _send_netlink_messages(nl_socket);
  }

  if (!oonf_socket_is_read(entry)) {
    return;
  }

  /* handle incoming messages */
  _netlink_rcv_msg.msg_flags = 0;
  flags = MSG_PEEK;

netlink_rcv_retry:
  _netlink_rcv_iov.iov_base = _netlink_rcv_buffer;
  _netlink_rcv_iov.iov_len = _netlink_rcv_size;

  if ((ret = recvmsg(entry->fd.fd, &_netlink_rcv_msg, MSG_DONTWAIT | flags)) < 0) {
#if EAGAIN == EWOULDBLOCK
    if (errno != EAGAIN) {
#else
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
#endif
      OONF_WARN(LOG_OS_SYSTEM, "Netlink '%d' recvmsg error: %s (%d)\n", nl_socket->netlink_type, strerror(errno), errno);
    }
    else {
      oonf_socket_set_read(&nl_socket->nl_socket, true);
    }
    return;
  }

  /* not enough buffer space ? */
  if (_netlink_rcv_size < (size_t)ret || (_netlink_rcv_msg.msg_flags & MSG_TRUNC) != 0) {
    void *ptr;

    ret = ret / NETLINK_MESSAGE_BLOCK_SIZE;
    ret++;
    ret *= NETLINK_MESSAGE_BLOCK_SIZE;

    ptr = realloc(_netlink_rcv_buffer, ret);
    if (!ptr) {
      OONF_WARN(LOG_OS_SYSTEM,
        "Netlink '%d': Not enough memory to increase input buffer to %" PRINTF_SSIZE_T_SPECIFIER,
        nl_socket->netlink_type, ret);
      return;
    }
    OONF_INFO(LOG_OS_SYSTEM,
      "Netlink '%d': increased input buffer to %" PRINTF_SSIZE_T_SPECIFIER,
      nl_socket->netlink_type, ret);
    _netlink_rcv_buffer = ptr;
    _netlink_rcv_size = ret;
    goto netlink_rcv_retry;
  }
  if (flags) {
    /* it worked, not remove the message from the queue */
    flags = 0;
    goto netlink_rcv_retry;
  }

  OONF_DEBUG_HEX(LOG_OS_SYSTEM, _netlink_rcv_buffer, ret, 
                 "Netlink '%d': recv data(bytes=%" PRINTF_SSIZE_T_SPECIFIER ")",
                 nl_socket->netlink_type, ret);

  /* loop through netlink headers */
  len = (size_t)ret;
  for (nh = _netlink_rcv_buffer; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
    OONF_DEBUG(LOG_OS_SYSTEM, "Netlink '%d': recv msg(type=%u, len=%u, seq=%u, pid=%u, flags=0x%04x)\n", 
               nl_socket->netlink_type, nh->nlmsg_type, nh->nlmsg_len, nh->nlmsg_seq, nh->nlmsg_pid, nh->nlmsg_flags);

    switch (nh->nlmsg_type) {
      case NLMSG_NOOP:
        break;

      case NLMSG_DONE:
        /* End of a multipart netlink message reached */
        nl_msg = _find_matching_message(nl_socket, nh->nlmsg_seq);
        if (nl_msg && nl_msg->dump) {
          list_remove(&nl_msg->_node);
          nl_msg->originator->cb_done(nl_msg);
        }
        break;

      case NLMSG_ERROR:
        /* Feedback for async netlink message */
        err = (struct nlmsgerr *)NLMSG_DATA(nh);
        nl_msg = _find_matching_message(nl_socket, err->msg.nlmsg_seq);
        if (nl_msg) {
          list_remove(&nl_msg->_node);

          if (err->error < 0) {
            nl_msg->result = -err->error;
          }
          else {
            nl_msg->result = err->error;
          }

          if (err->error == 0) {
            nl_msg->originator->cb_done(nl_msg);
          }
          else {
            nl_msg->originator->cb_error(nl_msg);
          }
        }
        break;

      default:
        nl_msg = _find_matching_message(nl_socket, nh->nlmsg_seq);
        if (nl_msg != NULL && nl_msg->originator->nl_socket->pid == nh->nlmsg_pid && nl_msg->dump) {
          /* this is a response to a netlink dump */
          nl_msg->originator->cb_response(nl_msg, nh);
        }
        else {
          /* this seems to be multicast */
          list_for_each_element(&nl_socket->handlers, nl_handler, _node) {
            for (i=0; i<nl_handler->multicast_count; i++) {
              if (nl_handler->multicast[i] == nh->nlmsg_type) {
                nl_handler->cb_multicast(nl_handler, nh);
                break;
              }
            }
          }
        }
        break;
    }
  }

  /* reset timeout if necessary */
  if (list_is_empty(&nl_socket->sent_messages)) {
    oonf_timer_stop(&nl_socket->timeout);
  }
  oonf_socket_set_write(&nl_socket->nl_socket, 
      list_is_empty(&nl_socket->sent_messages) && !list_is_empty(&nl_socket->buffered_messages));
}
