
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

#ifndef OS_SYSTEM_LINUX_DATA_H_
#define OS_SYSTEM_LINUX_DATA_H_

struct os_system_netlink_message;
struct os_system_netlink_socket;
struct os_system_netlink;

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_socket_data.h>
#include <oonf/base/oonf_timer.h>

/*! default timeout for netlink messages */
#define OS_SYSTEM_NETLINK_TIMEOUT 1000

/**
 * Message for transfer to netlink subsystem
 */
struct os_system_netlink_message {
  /* object guard for debugging */
  OONF_CLASS_GUARD_PREFIX;

  /*! pointer to buffer with netlink message */
  struct nlmsghdr *message;

  /*! maximum allowed length of netlink message */
  size_t max_length;
  
  /*! backlink to creater of message */
  struct os_system_netlink *originator;

  /*! error code received by message, 0 if okay, -1 if no response */
  int result;

  /*! true if this is a netlink tree dump */
  bool dump;

  /*! hook into list of messages, either buffered or sent */
  struct list_entity _node;

  /* object guard for debugging */
  OONF_CLASS_GUARD_SUFFIX;
};

/**
 * Centralized socket for all users of a certain netlink family type
 */
struct os_system_netlink_socket {
  /* object guard for debugging */
  OONF_CLASS_GUARD_PREFIX;

  /*! NETLINK_xxx type socket */
  int32_t netlink_type;
  
  /*! list of netlink messages that should be sent to the socket */
  struct list_entity buffered_messages;
  
  /*! list of netlink messages that have been sent to the socket but not acked */
  struct list_entity sent_messages;
  
  /*! list of netlink socket handlers */
  struct list_entity handlers;
  
  /* netlink socket handler */
  struct oonf_socket_entry nl_socket;
  
  /* pid value of socket */
  uint32_t pid;
  
  /*! buffer for incoming netlink message processing */
  struct nlmsghdr *in;

  /*! maximum length of buffer for netlink message */
  size_t in_max_len;

  /*! netlink timeout handler */
  struct oonf_timer_instance timeout;
  
  /*! hook into tree of netlink socket */
  struct avl_node _node;

  /* object guard for debugging */
  OONF_CLASS_GUARD_SUFFIX;
};
/**
 * Linux netlink handler
 */
struct os_system_netlink {
  /* object guard for debugging */
  OONF_CLASS_GUARD_PREFIX;

  /*! name of netlink handler */
  const char *name;

  /* list of multicast groups this handler requires */
  const uint32_t *multicast_groups;

  /*! number of multicast groups this handler requires */
  size_t multicast_group_count;

  /* list of multicast groups this handler requires */
  const uint32_t *multicast_messages;

  /*! number of multicast groups this handler requires */
  size_t multicast_message_count;

  /* reference to os system netlink multiplexer */
  struct os_system_netlink_socket *nl_socket;

  /*! subsystem that uses this netlink handler */
  struct oonf_subsystem *used_by;

  /**
   * Callback to handle incoming message from the kernel
   * @param nl pointer to this struct
   * @param msg netlink message that triggered this received message
   * @param hdr netlink message header received
   */
  void (*cb_response)(struct os_system_netlink_message *msg, struct nlmsghdr *hdr);

  /**
   * Callback to handle incoming message from the kernel
   * @param nl pointer to this struct
   * @param handler netlink hander that want to receive the multicast
   * @param hdr netlink message header received
   */
  void (*cb_multicast)(struct os_system_netlink *handler, struct nlmsghdr *hdr);

  /**
   * Callback to handle error message of kernel
   * @param nl pointer to this struct
   * @param msg netlink message that was not sucessfully handled by kernel
   */
  void (*cb_error)(struct os_system_netlink_message *msg);

  /**
   * Callback to notify that a netlink message has been processed
   * @param nl pointer to this struct
   * @param msg netlink message that was sucessfully handled by kernel
   */
  void (*cb_done)(struct os_system_netlink_message *msg);
  
  /*! hook into list of handlers for netlink protocol */
  struct list_entity _node;

  /* object guard for debugging */
  OONF_CLASS_GUARD_SUFFIX;
};
#endif /* OS_SYSTEM_LINUX_DATA_H_ */

