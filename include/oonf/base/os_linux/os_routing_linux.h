
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

#ifndef OS_ROUTING_LINUX_H_
#define OS_ROUTING_LINUX_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/list.h>
#include <oonf/base/os_system.h>
#include <oonf/base/os_linux/os_routing_linux_data.h>

#include <oonf/base/os_generic/os_routing_generic_init_half_route_key.h>
#include <oonf/base/os_generic/os_routing_generic_rt_to_string.h>

EXPORT bool os_routing_linux_supports_source_specific(int af_family);
EXPORT int os_routing_linux_set(struct os_route *, bool set, bool del_similar);
EXPORT int os_routing_linux_query(struct os_route *);
EXPORT void os_routing_linux_interrupt(struct os_route *);
EXPORT bool os_routing_linux_is_in_progress(struct os_route *);

EXPORT void os_routing_linux_listener_add(struct os_route_listener *);
EXPORT void os_routing_linux_listener_remove(struct os_route_listener *);

EXPORT const char *os_routing_linux_to_string(struct os_route_str *buf, const struct os_route_parameter *route_param);

EXPORT void os_routing_linux_init_wildcard_route(struct os_route *);

/**
 * Check if kernel supports source-specific routing
 * @param af_family address family
 * @return true if source-specific routing is supported for
 *   address family
 */
static INLINE bool
os_routing_supports_source_specific(int af_family) {
  return os_routing_linux_supports_source_specific(af_family);
}

/**
 * Update an entry of the kernel routing table. This call will only trigger
 * the change, the real change will be done as soon as the netlink socket is
 * writable.
 * @param route data of route to be set/removed
 * @param set true if route should be set, false if it should be removed
 * @param del_similar true if similar routes that block this one should be
 *   removed.
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_routing_set(struct os_route *route, bool set, bool del_similar) {
  return os_routing_linux_set(route, set, del_similar);
}

/**
 * Request all routing data of a certain address family
 * @param route pointer to routing filter
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_routing_query(struct os_route *route) {
  return os_routing_linux_query(route);
}

/**
 * Stop processing of a routing command
 * @param route pointer to os_route
 */
static INLINE void
os_routing_interrupt(struct os_route *route) {
  os_routing_linux_interrupt(route);
}

/**
 * @param route os route
 * @return true if route is being processed by the kernel,
 *   false otherwise
 */
static INLINE bool
os_routing_is_in_progress(struct os_route *route) {
  return os_routing_linux_is_in_progress(route);
}

/**
 * Add routing change listener
 * @param listener routing change listener
 */
static INLINE void
os_routing_listener_add(struct os_route_listener *listener) {
  os_routing_linux_listener_add(listener);
}

/**
 * Remove routing change listener
 * @param listener routing change listener
 */
static INLINE void
os_routing_listener_remove(struct os_route_listener *listener) {
  os_routing_linux_listener_remove(listener);
}

/**
 * Initializes a route with default values. Will zero all
 * other fields in the struct.
 * @param route route to be initialized
 */
static INLINE void
os_routing_init_wildcard_route(struct os_route *route) {
  return os_routing_linux_init_wildcard_route(route);
}

/**
 * Print OS route to string buffer
 * @param buf pointer to string buffer
 * @param route_param route parameters
 * @return pointer to string buffer, NULL if an error happened
 */
static INLINE const char *
os_routing_to_string(struct os_route_str *buf, const struct os_route_parameter *route_param) {
  return os_routing_generic_rt_to_string(buf, route_param);
}

/**
 * Copy one address to 'specific', fill the other one with the
 * fitting IP_ANY value
 * @param any buffer for IP_ANY
 * @param specific buffer for source
 * @param source source IP value to copy
 */
static INLINE void
os_routing_init_half_os_route_key(struct netaddr *any, struct netaddr *specific, const struct netaddr *source) {
  return os_routing_generic_init_half_os_route_key(any, specific, source);
}

/**
 * Initialize a source specific route key with a destination.
 * Overwrites the source prefix with the IP_ANY of the
 * corresponding address family
 * @param prefix target source specific route key
 * @param destination destination prefix
 */
static INLINE void
os_routing_init_sourcespec_prefix(struct os_route_key *prefix, const struct netaddr *destination) {
  os_routing_generic_init_half_os_route_key(&prefix->src, &prefix->dst, destination);
}

/**
 * Initialize a source specific route key with a source.
 * Overwrites the destination prefix with the IP_ANY of the
 * corresponding address family
 * @param prefix target source specific route key
 * @param source source prefix
 */
static INLINE void
os_routing_init_sourcespec_src_prefix(struct os_route_key *prefix, const struct netaddr *source) {
  os_routing_init_half_os_route_key(&prefix->dst, &prefix->src, source);
}

#endif /* OS_ROUTING_LINUX_H_ */
