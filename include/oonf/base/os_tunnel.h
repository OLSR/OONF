
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

#ifndef OS_TUNNEL_H_
#define OS_TUNNEL_H_

struct os_tunnel;

#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>

/*! subsystem identifier */
#define OONF_OS_TUNNEL_SUBSYSTEM "os_tunnel"

/* include os-specific headers */
#if defined(__linux__)
#include <oonf/base/os_linux/os_tunnel_linux_data.h>
#else
#error "Unknown operation system"
#endif

enum os_tunnel_type
{
  OS_TUNNEL_IPV4,
  OS_TUNNEL_IPV6,
  OS_TUNNEL_GRE,
};

struct os_tunnel_parameter {
  /*! name of the tunnel interface */
  char tunnel_if[IF_NAMESIZE];

  /*! inner type of data used by the tunnel */
  enum os_tunnel_type inner_type;

  /*! interface the tunnel is bound to, can be empty */
  char base_if[IF_NAMESIZE];

  /*! local IP address of the tunnel */
  struct netaddr local;

  /*! remote IP address of the tunnel */
  struct netaddr remote;

  /*! true that tunnel should inherit TOS (if possible) */
  bool inhert_tos;

  /*! true that tunnel should inherit the flowlabel (if possible) */
  bool inhert_flowlabel;

  /*! IP ttl of tunnel, 0 to inherit TTL (if possible) */
  uint8_t tunnel_ttl;
};

struct os_tunnel {
  /*! configuration data of tunnel */
  struct os_tunnel_parameter p;

  /*! tunnel interface index */
  unsigned if_index;

  /*! hook into global tree of tunnels */
  struct avl_node _node;

  /*! os specific tunnel data */
  struct os_tunnel_internal _internal;
};

static INLINE int os_tunnel_add(struct os_tunnel *);
static INLINE int os_tunnel_remove(struct os_tunnel *);

/* include os-specific headers */
#if defined(__linux__)
#include <oonf/base/os_linux/os_tunnel_linux.h>
#else
#error "Unknown operation system"
#endif

#endif /* OS_TUNNEL_H_ */
