
/*
 * The olsr.org Optimized Link-State Routing daemon version 2 (olsrd2)
 * Copyright (c) 2004-2019, the olsr.org team - see HISTORY file
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

#ifndef OONF_DNS_SD_H_
#define OONF_DNS_SD_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>

#define OONF_DNS_SD_SUBSYSTEM "dns_sd"

enum {
  /*! maximum length of DNS service discovery prefix */
  DNS_SD_PREFIX_LENGTH = 64,
};

struct dns_sd_prefix {
  /*! DNS service discovery prefix */
  char dns_prefix[DNS_SD_PREFIX_LENGTH];

  /*! binary flag used for prefix detection in context */
  uint64_t _flag;

  /*! usage counter of sd_prefix */
  uint32_t _usage;

  /*! node for tree in sd context */
  struct avl_node _node;
};

struct dns_sd_context_key {
  /*! name of interface this IP belongs to */
  char interface[IF_NAMESIZE];

  /*! IP address that was queried about services */
  struct netaddr ip;
};

struct dns_sd_context {
  /*! primary key for DNS-SD context */
  struct dns_sd_context_key key;

  /*! hostname of the context IP */
  char *hostname;

  /*! cache which includes all sd_prefixes that are available for this l2 neighbor */
  uint64_t available;

  /*! cache which includes all sd_prefixes that are unavailable for this l2 neighbor */
  uint64_t unavailable;

  /*! tree of all prefix results for this context */
  struct avl_tree _service_tree;

  /*! list of neighbors in the working queue */
  struct list_entity _working_node;

  /*! tree node for global list of DNS-SD results */
  struct avl_node _global_node;
};

struct dns_sd_service_key {
  /*! hostname of the target with the service */
  const char *hostname;

  /*! prefix this service result belongs to */
  struct dns_sd_prefix *prefix;
};

struct dns_sd_service {
  /*! unique key for service in the context */
  struct dns_sd_service_key key;

  /*! port number of service */
  uint16_t port;

  /*! weight factor of service */
  uint16_t weight;

  /*! priority factor of service */
  uint16_t priority;

  /*! IPv4 address to connect to service */
  struct netaddr ipv4;

  /*! IPv6 address to connect to service */
  struct netaddr ipv6;

  /*! node of DNS-SD context tree */
  struct avl_node _node;
};

enum dns_sd_prefix_status {
  DNS_SD_PREFIX_STATE_UNKNOWN,
  DNS_SD_PREFIX_AVAILABLE,
  DNS_SD_PREFIX_UNAVAILABLE,
};

EXPORT struct dns_sd_prefix *dns_sd_add(const char *prefix);
EXPORT void dns_sd_remove(struct dns_sd_prefix *);
EXPORT struct avl_tree *dns_sd_get_prefix_tree(void);
EXPORT struct avl_tree *dns_sd_get_context_tree(void);
EXPORT struct dns_sd_context *dns_sd_context_get(
  const char *interface, const struct netaddr *ip);

/**
 * Gets a specific prefix/hostname combination from a sd context
 * @param context sd context
 * @param hostname of service
 * @param prefix sd prefix
 * @return dns sd service, NULL if not there
 */
static INLINE struct dns_sd_service *
dns_sd_service_get(struct dns_sd_context *context, const char *hostname, struct dns_sd_prefix *prefix) {
  struct dns_sd_service *service;
  struct dns_sd_service_key key = { .hostname = hostname, .prefix = prefix };

  return avl_find_element(&context->_service_tree, &key, service, _node);
}

/**
 * Gets the status of a specific prefix in a DNS SD service
 * @param prefix dns sd prefix
 * @param context dns sd context
 * @returns service available, unavailable or unknown (query in progress)
 */
static INLINE enum dns_sd_prefix_status
dns_sd_context_has_prefix(struct dns_sd_prefix *prefix, struct dns_sd_context *context) {
  if ((context->available & prefix->_flag) != 0) {
    return DNS_SD_PREFIX_AVAILABLE;
  }
  if ((context->unavailable & prefix->_flag) != 0) {
    return DNS_SD_PREFIX_UNAVAILABLE;
  }
  return DNS_SD_PREFIX_STATE_UNKNOWN;
}

#endif
