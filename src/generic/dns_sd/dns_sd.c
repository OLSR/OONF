/**
 * Copyright (C) 2016 Fraunhofer FKIE
 *
 * @author         Henning Rogge
 */

/**
 * @file
 */

#include <errno.h>
#include <string.h>

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/string.h>
#include <oonf/libcore/oonf_subsystem.h>

#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_telnet.h>
#include <oonf/base/oonf_viewer.h>
#include <oonf/base/os_interface.h>

#include <oonf/generic/dns_query/dns_query.h>
#include <oonf/generic/dns_sd/dns_sd_intern.h>
#include <oonf/generic/dns_sd/dns_sd.h>

/* definitions */
#define LOG_DNS_SD _dns_sd_subsystem.logging

struct _dns_sd_config {
  struct strarray prefix;
};

enum sndsd_cfg {
  CFG_PREFIX
};

/* keys used for dnssd telnet command */
#define KEY_CONTEXT_IF     "ctx_if"
#define KEY_CONTEXT_IP     "ctx_ip"
#define KEY_CONTEXT_HOST   "ctx_host"
#define KEY_SERVICE_HOST   "service_host"
#define KEY_SERVICE_PREFIX "service_prefix"
#define KEY_SERVICE_PORT   "service_port"
#define KEY_SERVICE_PRIO   "service_priority"
#define KEY_SERVICE_WEIGHT "service_weight"
#define KEY_SERVICE_IPV4   "service_ipv4"
#define KEY_SERVICE_IPV6   "service_ipv6"

/* prototypes */
static int _init(void);
static void _cleanup(void);

static struct dns_sd_context *_add_sd_context(const char *ifname, const struct netaddr *ip);
static void _remove_sd_context(struct dns_sd_context *context);
static struct dns_sd_service *_add_sd_service(
  struct dns_sd_context *context, struct dns_sd_prefix *prefix, const char *hostname);
static void _remove_sd_service(struct dns_sd_context *, struct dns_sd_service *service);

static void _start_next_query(void);
static void _cb_a_result(struct oonf_dns_query *, struct dns_a *response);
static void _cb_aaaa_result(struct oonf_dns_query *, struct dns_aaaa *response);
static void _cb_srv_result(struct oonf_dns_query *, struct dns_srv *response);
static void _cb_ptr_result(struct oonf_dns_query *, struct dns_ptr *response);
static void _cb_query_done(struct oonf_dns_query *, bool timeout);

static enum oonf_telnet_result _cb_dnssd_cmd(struct oonf_telnet_data *con);
static enum oonf_telnet_result _cb_dnssd_help(struct oonf_telnet_data *con);
static int _cb_create_text_context(struct oonf_viewer_template *);
static int _cb_create_text_service(struct oonf_viewer_template *);
static int _cb_create_text_prefix(struct oonf_viewer_template *);
static void _initialize_context_values(struct dns_sd_context *);
static void _initialize_service_values(struct dns_sd_service *);

static void _cb_l2neighip_added(void *);
static int _avl_comp_sd_context(const void *k1, const void *k2);
static int _avl_comp_sd_service(const void *k1, const void *k2);
static void _cb_config_changed(void);

/* telnet interface  variables */
static char _value_ctx_if[IF_NAMESIZE];
static struct netaddr_str _value_ctx_ip;
static char _value_ctx_host[512];
static char _value_service_host[512];
static char _value_service_prefix[DNS_SD_PREFIX_LENGTH];
static char _value_service_port[6];
static char _value_service_priority[6];
static char _value_service_weight[6];
static struct netaddr_str _value_service_ipv4;
static struct netaddr_str _value_service_ipv6;

static struct abuf_template_data_entry _tde_context_key[] = {
  { KEY_CONTEXT_IF, _value_ctx_if, true },
  { KEY_CONTEXT_IP, _value_ctx_ip.buf, true },
};
static struct abuf_template_data_entry _tde_context[] = {
  { KEY_CONTEXT_HOST, _value_ctx_host, true },
};
static struct abuf_template_data_entry _tde_service_key[] = {
  { KEY_SERVICE_HOST, _value_service_host, true },
  { KEY_SERVICE_PREFIX, _value_service_prefix, true },
};
static struct abuf_template_data_entry _tde_service[] = {
  { KEY_SERVICE_PORT, _value_service_port, false },
  { KEY_SERVICE_PRIO, _value_service_priority, false },
  { KEY_SERVICE_WEIGHT, _value_service_weight, false },
  { KEY_SERVICE_IPV4, _value_service_ipv4.buf, true },
  { KEY_SERVICE_IPV6, _value_service_ipv6.buf, true },
};
static struct abuf_template_data_entry _tde_prefix_key[] = {
  { KEY_SERVICE_PREFIX, _value_service_prefix, true },
};

static struct abuf_template_data _td_context[] = {
  { _tde_context_key, ARRAYSIZE(_tde_context_key) },
  { _tde_context, ARRAYSIZE(_tde_context) },
};
static struct abuf_template_data _td_service[] = {
  { _tde_context_key, ARRAYSIZE(_tde_context_key) },
  { _tde_context, ARRAYSIZE(_tde_context) },
  { _tde_service_key, ARRAYSIZE(_tde_service_key) },
  { _tde_service, ARRAYSIZE(_tde_service) },
};
static struct abuf_template_data _td_prefix[] = {
  { _tde_prefix_key, ARRAYSIZE(_tde_prefix_key) },
};

static struct oonf_viewer_template _templates[] = {
  {
    .data = _td_context,
    .data_size = ARRAYSIZE(_td_context),
    .json_name = "context",
    .cb_function = _cb_create_text_context,
  },
  {
    .data = _td_service,
    .data_size = ARRAYSIZE(_td_service),
    .json_name = "service",
    .cb_function = _cb_create_text_service,
  },
  {
    .data = _td_prefix,
    .data_size = ARRAYSIZE(_td_prefix),
    .json_name = "prefix",
    .cb_function = _cb_create_text_prefix,
  },
};

static struct abuf_template_storage _template_storage;

static struct oonf_telnet_command _dnssd_cmd =
  TELNET_CMD("dnssd", _cb_dnssd_cmd, "", .help_handler = _cb_dnssd_help);

/* configuration */
static struct cfg_schema_entry _dns_sd_entries[] = {
  [CFG_PREFIX] = CFG_MAP_STRINGLIST(_dns_sd_config, prefix, "prefix", "", "Prefix for DNS service lookup"),
};

static struct cfg_schema_section _dns_sd_section = {
  .type = OONF_DNS_SD_SUBSYSTEM,
  .cb_delta_handler = _cb_config_changed,
  .entries = _dns_sd_entries,
  .entry_count = ARRAYSIZE(_dns_sd_entries),
};

static struct _dns_sd_config _config;

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_LAYER2_SUBSYSTEM,
  OONF_OS_INTERFACE_SUBSYSTEM,
  OONF_DNS_QUERY_SUBSYSTEM,
  OONF_TELNET_SUBSYSTEM,
  OONF_VIEWER_SUBSYSTEM,
};
static struct oonf_subsystem _dns_sd_subsystem = {
  .name = OONF_DNS_SD_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OONF dns service-discovery plugin",
  .author = "Henning Rogge",

  .cfg_section = &_dns_sd_section,

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_dns_sd_subsystem);

/* storage for sd prefixes */
static struct oonf_class _sd_prefix_class = {
  .name = "sd prefix",
  .size = sizeof(struct dns_sd_prefix),
};

/* storage for sd context */
static struct oonf_class _sd_context_class = {
  .name = "sd context",
  .size = sizeof(struct dns_sd_context),
};

/* storage for sd service */
static struct oonf_class _sd_service_class = {
  .name = "sd result",
  .size = sizeof(struct dns_sd_service),
};

/* tree of prefixes */
static struct avl_tree _prefix_tree;

/* tree of known context */
static struct avl_tree _context_tree;

/* used binary flags for prefixes */
static uint64_t _used_flags = 0;

/* callback defintiion for layer2 neighbor ips */
struct oonf_class_extension _l2neighip_ext = {
  .ext_name = "dns sd",
  .class_name = LAYER2_CLASS_NEIGHBOR_ADDRESS,

  .cb_add = _cb_l2neighip_added,
};

/* DNS query in progress */
static struct dns_sd_query _dns;

/* list of l2 entities that want a DNS update */
static struct list_entity _update_list;

/* tree of all dns-sd contexts */
static struct avl_tree _context_tree;

/**
 * Constructor for dns sd plugin
 * @return always 0
 */
static int
_init(void) {
  oonf_class_extension_add(&_l2neighip_ext);
  oonf_class_add(&_sd_prefix_class);
  oonf_class_add(&_sd_context_class);
  oonf_class_add(&_sd_service_class);

  oonf_telnet_add(&_dnssd_cmd);
  avl_init(&_prefix_tree, avl_comp_strcasecmp, false);
  avl_init(&_context_tree, _avl_comp_sd_context, false);
  list_init_head(&_update_list);

  memset(&_dns, 0, sizeof(_dns));
  _dns.dns.cb.a_result = _cb_a_result;
  _dns.dns.cb.aaaa_result = _cb_aaaa_result;
  _dns.dns.cb.ptr_result = _cb_ptr_result;
  _dns.dns.cb.srv_result = _cb_srv_result;
  _dns.dns.cb_done = _cb_query_done;
  _dns.dns.query = _dns.name;
  _dns.dns.dns_client = &_dns.client;
  _dns.dns.dns_server = &_dns.server;
  return 0;
}

/**
 * Destructor of dns sd plugin
 */
static void
_cleanup(void) {
  struct dns_sd_prefix *prefix, *p_it;

  avl_for_each_element_safe(&_prefix_tree, prefix, _node, p_it) {
    dns_sd_remove(prefix);
  }

  oonf_telnet_remove(&_dnssd_cmd);
  oonf_class_extension_remove(&_l2neighip_ext);
  oonf_class_remove(&_sd_prefix_class);
  oonf_class_remove(&_sd_context_class);
  oonf_class_remove(&_sd_service_class);
}

/**
 * Add a DNS prefix to the list to query
 * @param name of DNS prefix
 */
struct dns_sd_prefix *
dns_sd_add(const char *name) {
  struct dns_sd_prefix *prefix;
  uint64_t i;

  prefix = avl_find_element(&_prefix_tree, name, prefix, _node);
  if (!prefix) {
    if (_used_flags == ~0ull) {
      OONF_WARN(LOG_DNS_SD, "Maximum number of active service discovery strings reached");
      return NULL;
    }

    prefix = oonf_class_malloc(&_sd_prefix_class);
    if (!prefix) {
      return NULL;
    }

    /* add to tree */
    strscpy(prefix->dns_prefix, name, sizeof(prefix->dns_prefix));
    prefix->_node.key = prefix->dns_prefix;
    avl_insert(&_prefix_tree, &prefix->_node);

    /* acquire new flag */
    for (i=0; i<63; i++) {
      if ((_used_flags & (1ull<<i)) == 0) {
        prefix->_flag = 1ull<<i;
        _used_flags |= prefix->_flag;
        break;
      }
    }
    OONF_ASSERT(prefix->_flag, LOG_DNS_SD, "Could not aquire a DNS_SD flag");
  }

  /* increase usage counter */
  prefix->_usage++;

  return prefix;
}

/**
 * Remove a DNS prefix from the list to query
 * @param prefix DNS prefix
 */
void
dns_sd_remove(struct dns_sd_prefix *prefix) {
  struct dns_sd_context *context, *c_it;
  struct dns_sd_service *service, *s_it;

  if (prefix->_usage > 1) {
    prefix->_usage--;
    return;
  }

  avl_for_each_element_safe(&_context_tree, context, _global_node, c_it) {
    if (dns_sd_context_has_prefix(prefix, context) == DNS_SD_PREFIX_AVAILABLE) {
      context->available &= ~prefix->_flag;
      context->unavailable &= ~prefix->_flag;

      avl_for_each_element_safe(&context->_service_tree, service, _node, s_it) {
        if (service->key.prefix == prefix) {
          _remove_sd_service(context, service);
        }
      }
    }
  }

  _used_flags &= ~(prefix->_flag);
  avl_remove(&_prefix_tree, &prefix->_node);
  oonf_class_free(&_sd_prefix_class, prefix);
}

/**
 * Get a DNS context
 * @param interface interface name of context
 * @param ip host IP address of context (base for reverse DNS query)
 * @return DNS sd context
 */
struct dns_sd_context *
dns_sd_context_get(const char *interface, const struct netaddr *ip) {
  struct dns_sd_context *context;
  struct dns_sd_context_key key;

  memset(&key, 0, sizeof(key));
  strscpy(key.interface, interface, sizeof(key.interface));
  memcpy(&key.ip, ip, sizeof(key.ip));
  return avl_find_element(dns_sd_get_context_tree(), &key, context, _global_node);
}

/**
 * @return DNS prefix tree
 */
struct avl_tree *
dns_sd_get_prefix_tree(void) {
  return &_prefix_tree;
}

/**
 * @return DNS context tree
 */
struct avl_tree *
dns_sd_get_context_tree(void) {
  return &_context_tree;
}

/**
 * Create a new DNS sd context
 * @param ifname interface name for context
 * @param ip IP address of context
 * @return DNS sd context, NULL if out of memory
 */
static struct dns_sd_context *
_add_sd_context(const char *ifname, const struct netaddr *ip) {
  struct dns_sd_context *context;
  struct dns_sd_context_key key;

  memset(&key, 0, sizeof(key));
  strscpy(key.interface, ifname, sizeof(key.interface));
  memcpy(&key.ip, ip, sizeof(key.ip));

  context = avl_find_element(&_context_tree, &key, context, _global_node);
  if (context) {
    return context;
  }

  context = oonf_class_malloc(&_sd_context_class);
  if (!context) {
    return NULL;
  }

  memcpy(&context->key, &key, sizeof(key));

  context->_global_node.key = &context->key;
  avl_insert(&_context_tree, &context->_global_node);

  avl_init(&context->_service_tree, _avl_comp_sd_service, false);
  return context;
}

/**
 * Remove an existing DNS sd context
 * @param context DNS sd context
 */
static void
_remove_sd_context(struct dns_sd_context *context) {
  struct dns_sd_service *service, *s_it;

  avl_for_each_element_safe(&context->_service_tree, service, _node, s_it) {
    _remove_sd_service(context, service);
  }

  avl_remove(&_context_tree, &context->_global_node);
  oonf_class_free(&_sd_context_class, context);
}

/**
 * Create a new DNS sd service
 * @param prefix registered DNS sd prefix
 * @param hostname hostname of service
 * @return DNS sd service, NULL if out of memory
 */
static struct dns_sd_service *
_add_sd_service(struct dns_sd_context *context,
    struct dns_sd_prefix *prefix, const char *hostname) {
  struct dns_sd_service *service;
  struct dns_sd_service_key key;

  memset(&key, 0, sizeof(key));
  key.hostname = hostname;
  key.prefix = prefix;

  service = avl_find_element(&context->_service_tree, &key, service, _node);
  if (service) {
    return service;
  }

  service = oonf_class_malloc(&_sd_service_class);
  if (!service) {
    return NULL;
  }

  service->key.hostname = strdup(hostname);
  service->key.prefix = prefix;

  service->_node.key = &service->key;
  avl_insert(&context->_service_tree, &service->_node);

  return service;
}

/**
 * Remove an existing DNS sd service
 * @param context DNS sd context
 */
static void
_remove_sd_service(struct dns_sd_context *context, struct dns_sd_service *service) {
  free ((char *)service->key.hostname);
  avl_remove(&context->_service_tree, &service->_node);
  oonf_class_free(&_sd_service_class, service);

  if (context->_service_tree.count == 0) {
    _remove_sd_context(context);
  }
}

/**
 * Initialize a reverse DNS query
 * @param dns dns query to initialize
 * @param ip IP address the query is about
 * @return 0 if initialization was successful, -1 otherwise
 */
static int
_get_rdns_arpa_name(struct dns_sd_query *dns, struct netaddr *ip) {
  static const char HEX[]="0123456789abcdef";
  const uint8_t *bin;
  char *name;
  int i;

  bin = netaddr_get_binptr(ip);
  if (netaddr_get_address_family(ip) == AF_INET) {
    // 4.4.8.8.in-addr.arpa
    snprintf(dns->name, sizeof(dns->name), "%u.%u.%u.%u.in-addr.arpa",
        bin[3], bin[2], bin[1], bin[0]);
    return 0;
  }
  if (netaddr_get_address_family(ip) == AF_INET6) {
    // b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
    name = dns->name;
    for (i=15; i>=0; i--) {
      *name++ = HEX[bin[i] >> 4];
      *name++ = '.';
      *name++ = HEX[bin[i] & 0x0f];
      *name++ = '.';
    }
    strscpy(name, "ip6.arpa", 10);
    return 0;
  }
  return -1;
}

/**
 * Trigger the next DNS query for a DNS context
 * @param dns dns sd query
 * @return 0 if query was triggere, -1 otherwise
 */
static int
_work_on_l2neigh_addr(struct dns_sd_query *dns) {
  const struct os_interface_ip *if_ip;
  struct dns_sd_prefix *sd_prefix;
  struct os_interface *os_if;
  struct netaddr dns_ip;
  uint64_t done;

#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  OONF_DEBUG(LOG_DNS_SD, "Work on l2neigh_addr: %s", netaddr_to_string(&nbuf, &dns->context->key.ip));

  if (!list_is_node_added(&dns->context->_working_node)) {
    /* node is not in update-list anymore */
    return -1;
  }

  /* set DNS client address */
  netaddr_from_socket(&dns_ip, &dns->server);
  os_if = os_interface_get(dns->context->key.interface);
  if (!os_if) {
    OONF_WARN(LOG_DNS_SD, "No os itnerface data for '%s'", dns->context->key.interface);
    list_remove(&dns->context->_working_node);
    return -1;
  }
  if_ip = os_interface_get_prefix_from_dst(&dns_ip, os_if);
  if (!if_ip) {
    OONF_WARN(LOG_DNS_SD, "No fitting IP address for DNS server on interface %s",
              dns->context->key.interface);
    list_remove(&dns->context->_working_node);
    return -1;
  }
  netaddr_socket_init(&dns->client, &if_ip->address, 0,
      netaddr_socket_get_scope(&dns->server));

  if (!dns->context->hostname) {
    /* get hostname */
    if (_get_rdns_arpa_name(&_dns, &dns->context->key.ip)) {
      list_remove(&dns->context->_working_node);
      return -1;
    }

    dns->prefix = NULL;
    if (dns_query_ptr(&_dns.dns)) {
      list_remove(&dns->context->_working_node);
      return -1;
    }
    return 0;
  }

  /* search for first unknown service entry */
  done = dns->context->available | dns->context->unavailable;
  avl_for_each_element(&_prefix_tree, sd_prefix, _node) {
    if ((done & sd_prefix->_flag) == 0) {
      strscpy(dns->name, sd_prefix->dns_prefix, sizeof(dns->name));
      strscat(dns->name, dns->context->hostname, sizeof(dns->name));

      dns->prefix = sd_prefix;
      memset(&dns->srv_result, 0, sizeof(dns->srv_result));
      if (dns_query_srv(&_dns.dns)) {
      list_remove(&dns->context->_working_node);
        return -1;
      }
      return 0;
    }
  }
  list_remove(&dns->context->_working_node);
  return -1;
}

/**
 * start a new DNS sd query for the next context in queue
 */
static void
_start_next_query(void) {
  struct dns_sd_context *context;
  struct oonf_layer2_net *l2net;
  const union netaddr_socket *sock_ptr;

  OONF_DEBUG(LOG_DNS_SD, "start next query");
  while (!list_is_empty(&_update_list)) {
    OONF_DEBUG(LOG_DNS_SD, "loop");
    context = list_first_element(&_update_list, context, _working_node);

    /* get DNS server socket */
    l2net = oonf_layer2_net_get(context->key.interface);
    if (!l2net) {
      /* no external DNS server */
      OONF_WARN(LOG_DNS_SD, "No DNS server available for l2 interface '%s'", l2net->name);
      list_remove(&context->_working_node);
      continue;
    }

    sock_ptr = oonf_layer2_data_get_socket(&l2net->data[OONF_LAYER2_NET_IPV6_REMOTE_DNS]);
    if (!sock_ptr || netaddr_socket_is_unspec(sock_ptr)) {
      sock_ptr = oonf_layer2_data_get_socket(&l2net->data[OONF_LAYER2_NET_IPV4_REMOTE_DNS]);
      if (!sock_ptr || netaddr_socket_is_unspec(sock_ptr)) {
        /* no external DNS server */
        OONF_WARN(LOG_DNS_SD, "No DNS server available for l2 interface '%s'", l2net->name);

        list_remove(&context->_working_node);
        continue;
      }
      memcpy(&_dns.server, sock_ptr, sizeof(_dns.server));
    }
    else {
      /* set interface index for IPv6 */
      memcpy(&_dns.server, sock_ptr, sizeof(_dns.server));
      _dns.server.v6.sin6_scope_id = l2net->if_listener.data->index;
    }

    _dns.context = context;
    if (!_work_on_l2neigh_addr(&_dns)) {
      OONF_DEBUG(LOG_DNS_SD, "Query started");
      return;
    }
    /* query in progress */
    OONF_DEBUG(LOG_DNS_SD, "Work failed");
  }
}

/**
 * Add a new DNS context to the working queue, start new DNS query if
 * the queue was empty
 * @param ifname interface name of context
 * @param ip IP address of context
 */
static void
_enqueue_dns_query(const char *ifname, const struct netaddr *ip) {
  struct dns_sd_context *context;
  bool in_progress;

  context = _add_sd_context(ifname, ip);
  if (!context) {
    return;
  }

  if (list_is_node_added(&context->_working_node)) {
    /* node is already in update list */
    return;
  }

  /* update list is not empty means a query is ongoing */
  in_progress = !list_is_empty(&_update_list);

  /* put new address into waiting list */
  list_add_tail(&_update_list, &context->_working_node);
  if (in_progress) {
    return;
  }
  _start_next_query();
}

/**
 * Handle result of DNS A result (of DNS SRV query)
 * @param q dns query
 * @param response DNS A response
 */
static void
_cb_a_result(struct oonf_dns_query *q, struct dns_a *response) {
  struct dns_sd_query *dnssd_q;
  struct netaddr *addr;

  if (q->dns_type != DNS_T_SRV) {
    return;
  }

  dnssd_q = container_of(q, struct dns_sd_query, dns);
  if (dnssd_q->srv_result.service) {
    addr = &dnssd_q->srv_result.service->ipv4;
  }
  else {
    addr = &dnssd_q->srv_result.ipv4;
  }
  netaddr_from_binary(addr, &response->addr, 4, AF_INET);
}

/**
 * Handle result of DNS AAAA result (of DNS SRV query)
 * @param q dns query
 * @param response DNS AAAA response
 */
static void
_cb_aaaa_result(struct oonf_dns_query *q, struct dns_aaaa *response) {
  struct dns_sd_query *dnssd_q;
  struct netaddr *addr;

  if (q->dns_type != DNS_T_SRV) {
    return;
  }

  dnssd_q = container_of(q, struct dns_sd_query, dns);
  if (dnssd_q->srv_result.service) {
    addr = &dnssd_q->srv_result.service->ipv6;
  }
  else {
    addr = &dnssd_q->srv_result.ipv6;
  }
  netaddr_from_binary(addr, &response->addr, 16, AF_INET6);
}

/**
 * Handle result of DNS SRV result
 * @param q dns query
 * @param response DNS SRV response
 */
static void
_cb_srv_result(struct oonf_dns_query *q, struct dns_srv *response) {
  struct dns_sd_service *service;
  struct dns_sd_query *dnssd_q;

  dnssd_q = container_of(q, struct dns_sd_query, dns);
  if (dnssd_q->context != NULL && dnssd_q->prefix != NULL) {
    /* neighbor and prefix are still available */
    dnssd_q->context->available |= dnssd_q->prefix->_flag;

    service = _add_sd_service(dnssd_q->context, dnssd_q->prefix, response->target);
    if (service) {
      dnssd_q->srv_result.service = service;

      service->port = response->port;
      service->weight = response->weight;
      service->priority = response->priority;

      if (!netaddr_is_unspec(&dnssd_q->srv_result.ipv4)) {
        memcpy(&service->ipv4, &dnssd_q->srv_result.ipv4, sizeof(service->ipv4));
      }
      if (!netaddr_is_unspec(&dnssd_q->srv_result.ipv6)) {
        memcpy(&service->ipv6, &dnssd_q->srv_result.ipv6, sizeof(service->ipv6));
      }
    }
  }
}

/**
 * Handle result of DNS PTR result
 * @param q dns query
 * @param response DNS PTR response
 */
static void
_cb_ptr_result(struct oonf_dns_query *q, struct dns_ptr *response) {
  struct dns_sd_query *dnssd_q;

  dnssd_q = container_of(q, struct dns_sd_query, dns);
  if (dnssd_q->context) {
    /* neighbor is still available */
    if (!dnssd_q->context->hostname) {
      dnssd_q->context->hostname = strdup(response->host);
    }
  }
}

/**
 * Callback for handling end of a DNS query
 * @param q dns query
 * @param timeout true if a timeout happened, false if query was finished
 */
static void
_cb_query_done(struct oonf_dns_query *q, bool timeout) {
  struct dns_sd_query *dnssd_q;
  struct dns_sd_service *service;
#ifdef OONF_LOG_INFO
  struct netaddr_str nbuf1, nbuf2;
#endif

  OONF_DEBUG(LOG_DNS_SD, "query done callback");

  dnssd_q = container_of(q, struct dns_sd_query, dns);
  if (!dnssd_q->context) {
    // trigger next query */
    _start_next_query();
    return;
  }
  if (dnssd_q->dns.dns_type == DNS_T_SRV && !dnssd_q->prefix) {
    // trigger next query */
    list_remove(&dnssd_q->context->_working_node);
    _start_next_query();
    return;
  }

  service = dnssd_q->srv_result.service;
  if (dnssd_q->dns.dns_type == DNS_T_SRV && service != NULL) {
    if (!netaddr_is_unspec(&service->ipv4)) {
      OONF_INFO(LOG_DNS_SD, "SRV result for %s: [%s]:%u w=%u p=%u",
          netaddr_to_string(&nbuf1, &dnssd_q->context->key.ip),
          netaddr_to_string(&nbuf2, &service->ipv4),
          service->port,
          service->weight,
          service->priority);
    }
    if (!netaddr_is_unspec(&service->ipv6)) {
      OONF_INFO(LOG_DNS_SD, "SRV result for %s: [%s]:%u w=%u p=%u",
          netaddr_to_string(&nbuf1, &dnssd_q->context->key.ip),
          netaddr_to_string(&nbuf2, &service->ipv6),
          service->port,
          service->weight,
          service->priority);
    }
  }
  if (timeout) {
    list_remove(&dnssd_q->context->_working_node);
  }
  else if (dns_query_get_type(q) == DNS_T_PTR) {
    /* host query is done */
    if (!dnssd_q->context->hostname) {
      list_remove(&dnssd_q->context->_working_node);
    }
  }
  else if (dns_query_get_type(q) == DNS_T_SRV) {
    /* got service record */
    dnssd_q->context->unavailable |= dnssd_q->prefix->_flag;
  }

  /* trigger next query */
  if (_work_on_l2neigh_addr(&_dns)) {
    _start_next_query();
  }
}

/**
 * Callback for dnssd telnet command
 * @param con telnet connection
 * @return telnet result
 */
static enum oonf_telnet_result
_cb_dnssd_cmd(struct oonf_telnet_data *con) {
  return oonf_viewer_telnet_handler(
    con->out, &_template_storage, OONF_DNS_SD_SUBSYSTEM, con->parameter, _templates, ARRAYSIZE(_templates));
}

/**
 * Callback for dnssd telnet help command
 * @param con telnet connection
 * @return telnet result
 */
static enum oonf_telnet_result
_cb_dnssd_help(struct oonf_telnet_data *con) {
  return oonf_viewer_telnet_help(
    con->out, OONF_DNS_SD_SUBSYSTEM, con->parameter, _templates, ARRAYSIZE(_templates));
}

/**
 * Create text output for DNS sd context
 * @param template viewer template
 * @return always 0
 */
static int
_cb_create_text_context(struct oonf_viewer_template *template) {
  struct dns_sd_context *context;

  avl_for_each_element(&_context_tree, context, _global_node) {
    _initialize_context_values(context);
    oonf_viewer_output_print_line(template);
  }
  return 0;
}

/**
 * Create text output for DNS sd service
 * @param template viewer template
 * @return always 0
 */
static int
_cb_create_text_service(struct oonf_viewer_template *template) {
  struct dns_sd_context *context;
  struct dns_sd_service *service;

  avl_for_each_element(&_context_tree, context, _global_node) {
    _initialize_context_values(context);

    avl_for_each_element(&context->_service_tree, service, _node) {
      _initialize_service_values(service);
      oonf_viewer_output_print_line(template);
    }
  }
  return 0;
}

/**
 * Create text output for DNS sd prefix
 * @param template viewer template
 * @return always 0
 */
static int
_cb_create_text_prefix(struct oonf_viewer_template *template) {
  struct dns_sd_prefix *prefix;

  avl_for_each_element(&_prefix_tree, prefix, _node) {
    strscpy(_value_service_prefix, prefix->dns_prefix, sizeof(_value_service_prefix));
    oonf_viewer_output_print_line(template);
  }
  return 0;
}

/**
 * Initialize output buffers for DNS sd context
 * @param context DNS sd context
 */
static void
_initialize_context_values(struct dns_sd_context *context) {
  strscpy(_value_ctx_if, context->key.interface, IF_NAMESIZE);
  netaddr_to_string(&_value_ctx_ip, &context->key.ip);
  if (context->hostname) {
    strscpy(_value_ctx_host, context->hostname, sizeof(_value_ctx_host));
  }
  else {
    _value_ctx_host[0] = 0;
  }
}

/**
 * Initialize output buffers for DNS sd service
 * @param service DNS sd service
 */
static void
_initialize_service_values(struct dns_sd_service *service) {
  strscpy(_value_service_host, service->key.hostname, sizeof(_value_service_host));
  strscpy(_value_service_prefix, service->key.prefix->dns_prefix, sizeof(_value_service_prefix));
  snprintf(_value_service_port, sizeof(_value_service_port), "%u", service->port);
  snprintf(_value_service_priority, sizeof(_value_service_priority), "%u", service->priority);
  snprintf(_value_service_weight, sizeof(_value_service_weight), "%u", service->weight);
  netaddr_to_string(&_value_service_ipv4, &service->ipv4);
  netaddr_to_string(&_value_service_ipv6, &service->ipv6);
}

/**
 * Callback for handling new layer2 neighbor IPs
 * @param ptr layer2 neighbor IP object
 */
static void
_cb_l2neighip_added(void *ptr) {
  struct oonf_layer2_neighbor_address *l2neigh_addr = ptr;

  switch (netaddr_get_address_family(&l2neigh_addr->ip)) {
    case AF_INET:
    case AF_INET6:
      if (netaddr_is_host(&l2neigh_addr->ip)) {
        _enqueue_dns_query(l2neigh_addr->l2neigh->network->name, &l2neigh_addr->ip);
      }
      break;
    default:
      break;
  }
}

/**
 * AVL comparator for DNS sd context
 * @param k1 key 1
 * @param k2 key 2
 * @return see memcmp()
 */
static int
_avl_comp_sd_context(const void *k1, const void *k2) {
  const struct dns_sd_context_key *ck1 = k1;
  const struct dns_sd_context_key *ck2 = k2;

  return memcmp(ck1, ck2, sizeof(*ck1));
}

/**
 * AVL comparator for DNS sd service
 * @param k1 key 1
 * @param k2 key 2
 * @return see memcmp()
 */
static int
_avl_comp_sd_service(const void *k1, const void *k2) {
  const struct dns_sd_service_key *sk1 = k1;
  const struct dns_sd_service_key *sk2 = k2;
  int diff;

  diff = strcmp(sk1->hostname, sk2->hostname);
  if (diff) {
    return diff;
  }
  return strcmp(sk1->prefix->dns_prefix, sk2->prefix->dns_prefix);
}

/**
 * Callback for configuration changes
 */
static void
_cb_config_changed(void) {
  struct dns_sd_prefix *sd_prefix;
  struct cfg_entry *entry;
  const char *ptr;

  if (cfg_schema_tobin(&_config, _dns_sd_section.post, _dns_sd_entries, ARRAYSIZE(_dns_sd_entries))) {
    OONF_WARN(LOG_DNS_SD, "Could not convert " OONF_DNS_SD_SUBSYSTEM " config to bin");
    return;
  }

  /* and new (and existing) prefixes */
  strarray_for_each_element(&_config.prefix, ptr) {
    dns_sd_add(ptr);
  }

  if (_dns_sd_section.pre) {
    entry = cfg_db_get_entry(_dns_sd_section.pre, _dns_sd_entries[CFG_PREFIX].key.entry);
    if (entry) {
      /* remove old (and existing) prefixes */
      strarray_for_each_element(&_config.prefix, ptr) {
        sd_prefix = avl_find_element(&_prefix_tree, ptr, sd_prefix, _node);
        OONF_ASSERT (sd_prefix != NULL, LOG_DNS_SD, "to be removed SD prefix was not there");
        dns_sd_remove(sd_prefix);
      }
    }
  }
}
