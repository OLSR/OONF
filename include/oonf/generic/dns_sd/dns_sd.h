/**
 * Copyright (C) 2019 Fraunhofer FKIE
 *
 * @author         Henning Rogge
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
  DNS_SD_PREFIX_LENGTH = 64,
};

struct dns_sd_prefix {
  char dns_prefix[DNS_SD_PREFIX_LENGTH];

  uint64_t _flag;
  uint32_t _usage;

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

static INLINE struct dns_sd_service *
dns_sd_service_get(struct dns_sd_context *context, const char *hostname, struct dns_sd_prefix *prefix) {
  struct dns_sd_service *service;
  struct dns_sd_service_key key = { .hostname = hostname, .prefix = prefix };

  return avl_find_element(&context->_service_tree, &key, service, _node);
}

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
