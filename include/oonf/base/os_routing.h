
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

#ifndef OS_ROUTING_H_
#define OS_ROUTING_H_

struct os_route;
struct os_route_listener;
struct os_route_str;
struct os_route_key;
struct os_route_listener;

#include <stdio.h>
#include <sys/time.h>

#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libconfig/cfg.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/base/os_interface.h>
#include <oonf/base/os_system.h>

/* include os-specific headers */
#if defined(__linux__)
#include <oonf/base/os_linux/os_routing_linux_data.h>
#else
#error "Unknown operation system"
#endif

/*! subsystem identifier */
#define OONF_OS_ROUTING_SUBSYSTEM "os_routing"

/* make sure default values for routing are there */
#ifndef RTPROT_UNSPEC
/*! unspecified routing protocol */
#define RTPROT_UNSPEC 0
#endif
#ifndef RT_TABLE_UNSPEC
/*! unspecified routing table */
#define RT_TABLE_UNSPEC 0
#endif


/**
 * Struct for text representation of a route
 */
struct os_route_str {
  /*! text buffer for maximum length of representation */
  char buf[
    /* header */
    1 +
    /* src-ip */
    8 +
    sizeof(struct netaddr_str)
    /* gw */
    + 4 +
    sizeof(struct netaddr_str)
    /* dst [type] */
    + 5 +
    sizeof(struct netaddr_str)
    /* src-prefix */
    + 12 +
    sizeof(struct netaddr_str)
    /* metric */
    + 7 +
    11
    /* table, protocol */
    + 6 + 4 + 9 + 4 + 3 + IF_NAMESIZE + 2 + 10 +
    2
    /* footer and 0-byte */
    + 2];
};

/**
 * types of kernel routes
 */
enum os_route_type
{
  OS_ROUTE_UNDEFINED,
  OS_ROUTE_UNICAST,
  OS_ROUTE_LOCAL,
  OS_ROUTE_BROADCAST,
  OS_ROUTE_ANYCAST,
  OS_ROUTE_MULTICAST,
  OS_ROUTE_THROW,
  OS_ROUTE_UNREACHABLE,
  OS_ROUTE_PROHIBIT,
  OS_ROUTE_BLACKHOLE,
  OS_ROUTE_NAT,
  OS_ROUTE_ALL,
  OS_ROUTE_COUNT
};

/**
 * Creates a cfg_schema_entry for a parameter that can be choosen
 * from the os routing types
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param args variable list of additional arguments
 */
#define CFG_VALIDATE_OS_ROUTING_TYPE_KEY(p_name, p_def, p_help, args...)                                                    \
  CFG_VALIDATE_CHOICE_CB_ARG(p_name, p_def, p_help, os_routing_cfg_get_rttype, OS_ROUTE_COUNT, NULL, ##args)

/**
 * Creates a cfg_schema_entry for a parameter that can be choosen
 * from the os routing types and be mapped to an os_route_type
 * @param p_reference reference to instance of struct
 * @param p_field name of field in the struct for the parameter,
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param args variable list of additional arguments
 */
#define CFG_MAP_OS_ROUTING_TYPE_KEY(p_reference, p_field, p_name, p_def, p_help, args...)                                                    \
  CFG_MAP_CHOICE_CB_ARG(p_reference, p_field, p_name, p_def, p_help, os_routing_cfg_get_rttype, OS_ROUTE_COUNT, NULL, ##args)

/**
 * key of a route, both source and destination prefix
 */
struct os_route_key {
  /*! destination prefix of route */
  struct netaddr dst;

  /*! source prefix of route */
  struct netaddr src;
};

struct os_route_parameter {
  /*! address family */
  unsigned char family;

  /*! type of route */
  enum os_route_type type;

  /*! combination of source and destination */
  struct os_route_key key;

  /*! gateway and destination */
  struct netaddr gw;

  /*! source IP that should be used for outgoing IP packets of this route */
  struct netaddr src_ip;

  /*! metric of the route */
  int metric;

  /*! routing table protocol */
  int32_t table;

  /*! routing routing protocol */
  unsigned char protocol;

  /*! index of outgoing interface */
  unsigned int if_index;
};

/**
 * Handler for changing a route in the kernel
 * or querying the route status
 */
struct os_route {
  /*! parameters of route, separate to make it easy to compare routes */
  struct os_route_parameter p;

  /*! used for delivering feedback about netlink commands */
  struct os_route_internal _internal;

  /**
   * Callback triggered when the route has been set
   * @param route this route object
   * @param error -1 if an error happened, 0 otherwise
   */
  void (*cb_finished)(struct os_route *route, int error);

  /**
   * Callback triggered for each route found in the FIB
   * @param filter this route object used to filter the
   *   data from the kernel
   * @param route kernel route that matches the filter
   */
  void (*cb_get)(struct os_route *filter, struct os_route *route);
};

/**
 * Listener for kernel route changes
 */
struct os_route_listener {
  /*! used for delivering feedback about netlink commands */
  struct os_route_listener_internal _internal;

  /**
   * Callback triggered when a route changes in the kernel
   * @param route changed route
   * @param set true if route has been set/changed,
   *   false if it has been removed
   */
  void (*cb_get)(const struct os_route *route, bool set);
};

/* prototypes for all os_routing functions */
static INLINE bool os_routing_supports_source_specific(int af_family);
static INLINE int os_routing_set(struct os_route *, bool set, bool del_similar);
static INLINE int os_routing_query(struct os_route *);
static INLINE void os_routing_interrupt(struct os_route *);
static INLINE bool os_routing_is_in_progress(struct os_route *);

static INLINE void os_routing_listener_add(struct os_route_listener *);
static INLINE void os_routing_listener_remove(struct os_route_listener *);

static INLINE const char *os_routing_to_string(struct os_route_str *buf, const struct os_route_parameter *route_param);

static INLINE void os_routing_init_wildcard_route(struct os_route *);

static INLINE void os_routing_init_half_os_route_key(
  struct netaddr *any, struct netaddr *specific, const struct netaddr *source);

static INLINE void os_routing_init_sourcespec_prefix(struct os_route_key *prefix, const struct netaddr *destination);
static INLINE void os_routing_init_sourcespec_src_prefix(struct os_route_key *prefix, const struct netaddr *source);

/* AVL comparators are a special case so we don't do the INLINE trick here */
EXPORT int os_routing_avl_cmp_route_key(const void *, const void *);

EXPORT const char *os_routing_cfg_get_rttype(size_t index, const void *unused);

/**
 * Convert route key into string
 * @param buf target string buffer
 * @param key route key
 */
static INLINE const char *
os_routing_key_to_string(struct os_route_str *buf, const struct os_route_key *key) {
    struct netaddr_str buf1, buf2;
    buf->buf[0] = 0;
    snprintf(buf->buf, sizeof(*buf), "[dst=%s/src=%s]", netaddr_to_string(&buf1, &key->dst), netaddr_to_string(&buf2, &key->src));
    return buf->buf;
}

/* include os-specific headers */
#if defined(__linux__)
#include <oonf/base/os_linux/os_routing_linux.h>
#else
#error "Unknown operation system"
#endif

#endif /* OS_ROUTING_H_ */
