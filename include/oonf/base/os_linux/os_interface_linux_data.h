
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

#ifndef OS_INTERFACE_LINUX_DATA_H_
#define OS_INTERFACE_LINUX_DATA_H_

struct os_interface_address_change_internal;
struct os_interface_internal;

#include <oonf/oonf.h>
#include <oonf/base/os_linux/os_system_linux_data.h>

enum
{
  /*! interval until an interface change trigger will be activated again */
  OS_INTERFACE_CHANGE_TRIGGER_INTERVAL = 200,
};

#define OS_INTERFACE_ANY "any"

/**
 * define scope of address on interface
 */
enum os_addr_scope
{
  /* linklocal scope */
  OS_ADDR_SCOPE_LINK = RT_SCOPE_LINK,
  /*! global scope */
  OS_ADDR_SCOPE_GLOBAL = RT_SCOPE_UNIVERSE,
};

/**
 * linux specifc data for changing an interface address
 */
struct os_interface_address_change_internal {
  /*! hook into list of IP address change handlers */
  struct list_entity _node;

  struct os_system_netlink_message msg;
  
  /* (well aligned) buffer for netlink message */
  uint64_t nl_buffer[256/sizeof(uint64_t)];
};

struct os_interface_internal {
  /**
   * true if this interface should not be initialized as a mesh interface
   * even if used as one. This means the user have to do all the
   * os configuration itself.
   */
  bool ignore_mesh;

  /**
   * usage counter to keep track of the number of users on
   * this interface who want to send mesh traffic
   */
  uint32_t mesh_counter;

  /**
   * original value of IP spoof filter before changed to mesh state
   */
  char _original_ip_spoof;

  /**
   * original value of ip redirect before changed to mesh state
   */
  char _original_icmp_redirect;

  /**
   * true if the interface has been configured, keep a copy around
   */
  bool configured;
};

#endif /* OS_INTERFACE_LINUX_DATA_H_ */
