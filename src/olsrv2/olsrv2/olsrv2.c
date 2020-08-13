
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

#include <errno.h>

#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_rfc5444.h>
#include <oonf/base/oonf_telnet.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_interface.h>

#include <oonf/nhdp/nhdp/nhdp_interfaces.h>

#include <oonf/olsrv2/olsrv2/olsrv2.h>
#include <oonf/olsrv2/olsrv2/olsrv2_lan.h>
#include <oonf/olsrv2/olsrv2/olsrv2_originator.h>
#include <oonf/olsrv2/olsrv2/olsrv2_reader.h>
#include <oonf/olsrv2/olsrv2/olsrv2_tc.h>
#include <oonf/olsrv2/olsrv2/olsrv2_writer.h>

/* definitions */

/*! configuration option for locally attached networks */
#define _LOCAL_ATTACHED_NETWORK_KEY "lan"

/**
 * Default values for locally attached network parameters
 */
enum _lan_option_defaults
{
  LAN_DEFAULT_DOMAIN = 0,   //!< LAN_DEFAULT_DOMAIN
  LAN_DEFAULT_METRIC = 1,   //!< LAN_DEFAULT_METRIC
  LAN_DEFAULT_DISTANCE = 2, //!< LAN_DEFAULT_DISTANCE
};

/*! locally attached network option for source-specific prefix */
#define LAN_OPTION_SRC "src="

/*! locally attached network option for outgoing metric */
#define LAN_OPTION_METRIC "metric="

/*! locally attached network option for domain */
#define LAN_OPTION_DOMAIN "domain="

/*! locally attached network option for hopcount distance */
#define LAN_OPTION_DIST "dist="

/**
 * olsrv2 plugin config
 */
struct _config {
  /*! topology control interval */
  uint64_t tc_interval;

  /*! topology control validity */
  uint64_t tc_validity;

  /*! olsrv2 f_hold_time */
  uint64_t f_hold_time;

  /*! olsrv2 p_hold_time */
  uint64_t p_hold_time;

  /*! olsrv2 factor of a_hold_time in terms of tc_intervals */
  uint64_t a_hold_time_factor;

  /*! decides NHDP routable status */
  bool nhdp_routable;

  /*! IP filter for routable addresses */
  struct netaddr_acl routable_acl;

  /*! IP filter for valid originator */
  struct netaddr_acl originator_acl;
};

/**
 * Additional parameters of a single locally attached network
 */
struct _lan_data {
  /*! extension domain of LAN */
  int32_t ext;

  /*! source prefix */
  struct netaddr source_prefix;

  /*! olsrv2 metric */
  uint32_t metric;

  /*! routing metric (distance) */
  uint32_t dist;
};

/* prototypes */
static void _early_cfg_init(void);
static int _init(void);
static void _initiate_shutdown(void);
static void _cleanup(void);

static void _cb_generate_tc(struct oonf_timer_instance *);

static void _update_originator(int af_family);
static int _cb_if_event(struct os_interface_listener *);

static void _cb_cfg_olsrv2_changed(void);
static void _cb_cfg_domain_changed(void);

/* subsystem definition */
static struct cfg_schema_entry _rt_domain_entries[] = {
  CFG_MAP_BOOL(olsrv2_routing_domain, use_srcip_in_routes, "srcip_routes", "true",
    "Set the source IP of IPv4-routes to a fixed value."),
  CFG_MAP_INT32_MINMAX(
    olsrv2_routing_domain, protocol, "protocol", "100", "Protocol number to be used in routing table", 0, 1, 254),
  CFG_MAP_INT32_MINMAX(olsrv2_routing_domain, table, "table", "254", "Routing table number for routes", 0, 1, 65535),
  CFG_MAP_INT32_MINMAX(
    olsrv2_routing_domain, distance, "distance", "2", "Metric Distance to be used in routing table", 0, 1, 255),
  CFG_MAP_BOOL(
    olsrv2_routing_domain, source_specific, "source_specific", "true", "This domain uses IPv6 source specific routing"),
};

static struct cfg_schema_section _rt_domain_section = {
  CFG_NHDP_SCHEMA_DOMAIN_SECTION_INIT,

  .cb_delta_handler = _cb_cfg_domain_changed,
  .entries = _rt_domain_entries,
  .entry_count = ARRAYSIZE(_rt_domain_entries),
};

static struct cfg_schema_entry _olsrv2_entries[] = {
  CFG_MAP_CLOCK_MIN(_config, tc_interval, "tc_interval", "5.0", "Time between two TC messages", 100),
  CFG_MAP_CLOCK_MIN(_config, tc_validity, "tc_validity", "300.0", "Validity time of a TC messages", 100),
  CFG_MAP_CLOCK_MIN(_config, f_hold_time, "forward_hold_time", "300.0", "Holdtime for forwarding set information", 100),
  CFG_MAP_CLOCK_MIN(
    _config, p_hold_time, "processing_hold_time", "300.0", "Holdtime for processing set information", 100),
  CFG_MAP_INT64_MINMAX(_config, a_hold_time_factor, "advertisement_hold_time_factor", "3",
    "Holdtime for TC advertisements as a factor of TC interval time", false, 1, 255),
  CFG_MAP_BOOL(_config, nhdp_routable, "nhdp_routable", "no",
    "Decides if NHDP interface addresses"
    " are routed to other nodes. 'true' means the 'routable_acl' parameter"
    " will be matched to the addresses to decide."),
  CFG_MAP_ACL_V46(_config, routable_acl, "routable_acl", OLSRV2_ROUTABLE_IPV4 OLSRV2_ROUTABLE_IPV6 ACL_DEFAULT_ACCEPT,
    "Filter to decide which addresses are considered routable"),
  CFG_MAP_ACL_V46(_config, originator_acl, "originator",
    OLSRV2_ORIGINATOR_IPV4 OLSRV2_ORIGINATOR_IPV6 ACL_DEFAULT_ACCEPT,
    "Filter for router originator addresses (ipv4 and ipv6)"
    " from the interface addresses. Olsrv2 will prefer routable addresses"
    " over linklocal addresses and addresses from loopback over other interfaces."),
};

static struct cfg_schema_section _olsrv2_section = {
  .type = CFG_OLSRV2_SECTION,
  .cb_delta_handler = _cb_cfg_olsrv2_changed,
  .entries = _olsrv2_entries,
  .entry_count = ARRAYSIZE(_olsrv2_entries),
  .next_section = &_rt_domain_section,
};

static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_RFC5444_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_OS_INTERFACE_SUBSYSTEM,
  OONF_NHDP_SUBSYSTEM,
};
static struct oonf_subsystem _olsrv2_subsystem = {
  .name = OONF_OLSRV2_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .early_cfg_init = _early_cfg_init,
  .init = _init,
  .cleanup = _cleanup,
  .initiate_shutdown = _initiate_shutdown,
  .cfg_section = &_olsrv2_section,
};
DECLARE_OONF_PLUGIN(_olsrv2_subsystem);

/*! last time a TC was advertised because of MPR or LANs */
static uint64_t _unadvertised_tc_count;

static struct _config _olsrv2_config;

/* timer for TC generation */
static struct oonf_timer_class _tc_timer_class = {
  .name = "TC generation",
  .periodic = true,
  .callback = _cb_generate_tc,
};

static struct oonf_timer_instance _tc_timer = {
  .class = &_tc_timer_class,
};

/* global interface listener */
static struct os_interface_listener _if_listener = {
  .name = OS_INTERFACE_ANY,
  .if_changed = _cb_if_event,
};

/* global variables */
static struct oonf_rfc5444_protocol *_protocol;

static bool _generate_tcs = true;

/* TC settings overwrite */
static uint64_t _overwrite_tc_interval;
static uint64_t _overwrite_tc_validity;

/* Additional logging sources, not static because used by other source files! */
enum oonf_log_source LOG_OLSRV2;
enum oonf_log_source LOG_OLSRV2_R;
enum oonf_log_source LOG_OLSRV2_ROUTING;
enum oonf_log_source LOG_OLSRV2_W;

/**
 * Initialize additional logging sources for NHDP
 */
static void
_early_cfg_init(void) {
  LOG_OLSRV2 = _olsrv2_subsystem.logging;
  LOG_OLSRV2_R = oonf_log_register_source(OONF_OLSRV2_SUBSYSTEM "_r");
  LOG_OLSRV2_W = oonf_log_register_source(OONF_OLSRV2_SUBSYSTEM "_w");
  LOG_OLSRV2_ROUTING = oonf_log_register_source(OONF_OLSRV2_SUBSYSTEM "_routing");
}

/**
 * Initialize OLSRV2 subsystem
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  _protocol = oonf_rfc5444_get_default_protocol();

  if (olsrv2_writer_init(_protocol)) {
    return -1;
  }

  if (olsrv2_routing_init()) {
    olsrv2_writer_cleanup();
    oonf_rfc5444_remove_protocol(_protocol);
    return -1;
  }

  /* activate interface listener */
  os_interface_add(&_if_listener);

  /* activate the rest of the olsrv2 protocol */
  olsrv2_lan_init();
  olsrv2_originator_init();
  olsrv2_reader_init(_protocol);
  olsrv2_tc_init();

  /* initialize timer */
  oonf_timer_add(&_tc_timer_class);

  return 0;
}

/**
 * Begin shutdown by deactivating reader and writer. Also flush all routes
 */
static void
_initiate_shutdown(void) {
  olsrv2_writer_cleanup();
  olsrv2_reader_cleanup();
  olsrv2_routing_initiate_shutdown();
}

/**
 * Cleanup OLSRV2 subsystem
 */
static void
_cleanup(void) {
  /* remove interface listener */
  os_interface_remove(&_if_listener);

  /* cleanup configuration */
  netaddr_acl_remove(&_olsrv2_config.routable_acl);
  netaddr_acl_remove(&_olsrv2_config.originator_acl);

  /* cleanup all parts of olsrv2 */
  olsrv2_routing_cleanup();
  olsrv2_originator_cleanup();
  olsrv2_tc_cleanup();
  olsrv2_lan_cleanup();

  /* free protocol instance */
  _protocol = NULL;
}

/**
 * @return interval between two tcs
 */
uint64_t
olsrv2_get_tc_interval(void) {
  if (_overwrite_tc_interval) {
    return _overwrite_tc_interval;
  }
  return _olsrv2_config.tc_interval;
}

/**
 * @return validity of the local TCs
 */
uint64_t
olsrv2_get_tc_validity(void) {
  if (_overwrite_tc_validity) {
    return _overwrite_tc_validity;
  }
  return _olsrv2_config.tc_validity;
}

/**
 * @param addr NHDP address to be checked
 * @return true if address should be routed, false otherwise
 */
bool
olsrv2_is_nhdp_routable(struct netaddr *addr) {
  if (!_olsrv2_config.nhdp_routable) {
    return false;
  }
  return olsrv2_is_routable(addr);
}

/**
 * @param addr address to be checked
 * @return true if address should be routed, false otherwise
 */
bool
olsrv2_is_routable(struct netaddr *addr) {
  return netaddr_acl_check_accept(&_olsrv2_config.routable_acl, addr);
}

/**
 * default implementation for rfc5444 processing handling according
 * to MPR settings.
 * @param context RFC5444 tlvblock reader context
 * @param vtime validity time for duplicate entry data
 * @return true if TC should be processed, false otherwise
 */
bool
olsrv2_mpr_shall_process(struct rfc5444_reader_tlvblock_context *context, uint64_t vtime) {
  enum oonf_duplicate_result dup_result;
  bool process;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  /* check if message has originator and sequence number */
  if (!context->has_origaddr || !context->has_seqno) {
    OONF_DEBUG(LOG_OLSRV2,
      "Do not process message type %u,"
      " originator or sequence number is missing!",
      context->msg_type);
    return false;
  }

  /* check forwarding set */
  dup_result = oonf_duplicate_entry_add(&_protocol->processed_set, context->msg_type, &context->orig_addr,
    context->seqno, vtime + _olsrv2_config.f_hold_time);
  process = oonf_duplicate_is_new(dup_result);

  OONF_DEBUG(LOG_OLSRV2,
    "Do %sprocess message type %u from %s"
    " with seqno %u (dupset result: %u)",
    process ? "" : "not ", context->msg_type, netaddr_to_string(&buf, &context->orig_addr), context->seqno, dup_result);
  return process;
}

/**
 * default implementation for rfc5444 forwarding handling according
 * to MPR settings.
 * @param context RFC5444 reader context
 * @param source_address source address of RFC5444 message
 * @param vtime validity time of message information
 * @return true if message was forwarded, false otherwise
 */
bool
olsrv2_mpr_shall_forwarding(
  struct rfc5444_reader_tlvblock_context *context, struct netaddr *source_address, uint64_t vtime) {
  struct nhdp_interface *interf;
  struct nhdp_laddr *laddr;
  struct nhdp_neighbor *neigh;
  enum oonf_duplicate_result dup_result;
  bool forward;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  /* check if message has originator and sequence number */
  if (!context->has_origaddr || !context->has_seqno) {
    OONF_DEBUG(LOG_OLSRV2,
      "Do not forward message type %u,"
      " originator or sequence number is missing!",
      context->msg_type);
    return false;
  }

  /* check input interface */
  if (_protocol->input.interface == NULL) {
    OONF_DEBUG(LOG_OLSRV2, "Do not forward because input interface is not set");
    return false;
  }

  /* check input source address */
  if (!source_address) {
    OONF_DEBUG(LOG_OLSRV2, "Do not forward because input source is not set");
    return false;
  }

  /* check if this is coming from the unicast receiver */
  if (strcmp(_protocol->input.interface->name, RFC5444_UNICAST_INTERFACE) == 0) {
    return false;
  }

  /* check forwarding set */
  dup_result = oonf_duplicate_entry_add(&_protocol->forwarded_set, context->msg_type, &context->orig_addr,
    context->seqno, vtime + _olsrv2_config.f_hold_time);
  if (!oonf_duplicate_is_new(dup_result)) {
    OONF_DEBUG(LOG_OLSRV2,
      "Do not forward message type %u from %s"
      " with seqno %u (dupset result: %u)",
      context->msg_type, netaddr_to_string(&buf, &context->orig_addr), context->seqno, dup_result);
    return false;
  }

  /* get NHDP interface */
  interf = nhdp_interface_get(_protocol->input.interface->name);
  if (interf == NULL) {
    OONF_DEBUG(LOG_OLSRV2,
      "Do not forward because NHDP does not handle"
      " interface '%s'",
      _protocol->input.interface->name);
    return false;
  }

  /* get NHDP link address corresponding to source */
  laddr = nhdp_interface_get_link_addr(interf, source_address);
  if (laddr == NULL) {
    OONF_DEBUG(LOG_OLSRV2,
      "Do not forward because source IP %s is"
      " not a direct neighbor",
      netaddr_to_string(&buf, source_address));
    return false;
  }

  if (netaddr_get_address_family(&context->orig_addr) == netaddr_get_address_family(source_address)) {
    /* get NHDP neighbor */
    neigh = laddr->link->neigh;
  }
  else if (laddr->link->dualstack_partner) {
    /* get dualstack NHDP neighbor */
    neigh = laddr->link->dualstack_partner->neigh;
  }
  else {
    OONF_DEBUG(LOG_OLSRV2,
      "Do not forward because this is a dualstack"
      " message, but the link source %s is not dualstack capable",
      netaddr_to_string(&buf, source_address));
    return false;
  }

  /* forward if this neighbor has selected us as a flooding MPR */
  forward = laddr->link->local_is_flooding_mpr && neigh->symmetric > 0;
  OONF_DEBUG(LOG_OLSRV2,
    "Do %sforward message type %u from %s"
    " with seqno %u (%s/%u)",
    forward ? "" : "not ", context->msg_type, netaddr_to_string(&buf, &context->orig_addr), context->seqno,
    laddr->link->local_is_flooding_mpr ? "true" : "false", neigh->symmetric);
  return forward;
}

/**
 * Switches the automatic generation of TCs on and off
 * @param generate true if TCs should be generated every OLSRv2 TC interval,
 *   false otherwise
 */
void
olsrv2_generate_tcs(bool generate) {
  uint64_t interval;

  interval = _overwrite_tc_interval;
  if (!interval) {
    interval = _olsrv2_config.tc_interval;
  }
  if (generate && !oonf_timer_is_active(&_tc_timer)) {
    oonf_timer_set(&_tc_timer, interval);
  }
  else if (!generate && oonf_timer_is_active(&_tc_timer)) {
    oonf_timer_stop(&_tc_timer);
  }
}

uint64_t
olsrv2_set_tc_interval(uint64_t interval) {
  uint64_t old;

  old = _overwrite_tc_interval;
  _overwrite_tc_interval = interval;
  return old;
}

uint64_t
olsrv2_set_tc_validity(uint64_t interval) {
  uint64_t old;

  old = _overwrite_tc_validity;
  _overwrite_tc_validity = interval;
  return old;
}

/**
 * Callback to trigger normal tc generation with timer
 * @param ptr timer instance that fired
 */
static void
_cb_generate_tc(struct oonf_timer_instance *ptr __attribute__((unused))) {
  if (nhdp_domain_node_is_mpr() || !avl_is_empty(olsrv2_lan_get_tree())) {
    _unadvertised_tc_count = 0;
  }
  else {
    _unadvertised_tc_count++;
  }

  if (_unadvertised_tc_count <= _olsrv2_config.a_hold_time_factor) {
    olsrv2_writer_send_tc();
  }
}

static uint32_t
_get_addr_priority(const struct netaddr *addr) {
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  if (!netaddr_acl_check_accept(&_olsrv2_config.originator_acl, addr)) {
    /* does not match the acl */
    OONF_DEBUG(LOG_OLSRV2, "check priority for %s: 0 (not in ACL)", netaddr_to_string(&nbuf, addr));
    return 0;
  }

  if (netaddr_get_address_family(addr) == AF_INET) {
    if (netaddr_is_in_subnet(&NETADDR_IPV4_LINKLOCAL, addr)) {
      /* linklocal */
      OONF_DEBUG(LOG_OLSRV2, "check priority for %s: 1 (linklocal)", netaddr_to_string(&nbuf, addr));
      return 1;
    }

    /* routable */
    OONF_DEBUG(LOG_OLSRV2, "check priority for %s: 2 (routable)", netaddr_to_string(&nbuf, addr));
    return 2;
  }

  if (netaddr_get_address_family(addr) == AF_INET6) {
    if (netaddr_is_in_subnet(&NETADDR_IPV6_LINKLOCAL, addr)) {
      /* linklocal */
      OONF_DEBUG(LOG_OLSRV2, "check priority for %s: 1 (linklocal)", netaddr_to_string(&nbuf, addr));
      return 1;
    }

    /* routable */
    OONF_DEBUG(LOG_OLSRV2, "check priority for %s: 2 (routable)", netaddr_to_string(&nbuf, addr));
    return 2;
  }

  /* unknown */
  OONF_DEBUG(LOG_OLSRV2, "check priority for %s: 0 (unknown)", netaddr_to_string(&nbuf, addr));

  return 0;
}

/**
 * Check if current originators are still valid and
 * lookup new one if necessary.
 */
static void
_update_originator(int af_family) {
  const struct netaddr *originator;
  struct nhdp_interface *nhdp_if;
  struct os_interface_listener *if_listener;
  struct netaddr new_originator;
  struct os_interface_ip *ip;
  uint32_t new_priority;
  uint32_t old_priority;
  uint32_t priority;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  OONF_DEBUG(LOG_OLSRV2, "Updating OLSRV2 %s originator", af_family == AF_INET ? "ipv4" : "ipv6");

  originator = olsrv2_originator_get(af_family);

  old_priority = 0;
  new_priority = 0;

  netaddr_invalidate(&new_originator);

  avl_for_each_element(nhdp_interface_get_tree(), nhdp_if, _node) {
    if_listener = nhdp_interface_get_if_listener(nhdp_if);

    /* check if originator is still valid */
    avl_for_each_element(&if_listener->data->addresses, ip, _node) {
      if (netaddr_get_address_family(&ip->address) == af_family) {
        priority = _get_addr_priority(&ip->address) * 4;
        if (priority == 0) {
          /* not useful */
          continue;
        }

        if (if_listener->data->flags.loopback) {
          priority += 2;
        }
        if (netaddr_cmp(originator, &ip->address) == 0) {
          old_priority = priority + 1;
        }

        if (priority > old_priority && priority > new_priority) {
          memcpy(&new_originator, &ip->address, sizeof(new_originator));
          new_priority = priority;
        }
      }
    }
  }

  if (new_priority > old_priority) {
    OONF_DEBUG(LOG_OLSRV2, "Set originator to %s", netaddr_to_string(&buf, &new_originator));
    olsrv2_originator_set(&new_originator);
  }
}

/**
 * Callback for interface events
 * @param if_listener interface listener
 * @return always 0
 */
static int
_cb_if_event(struct os_interface_listener *if_listener __attribute__((unused))) {
  _update_originator(AF_INET);
  _update_originator(AF_INET6);
  return 0;
}

/**
 * Callback fired when olsrv2 section changed
 */
static void
_cb_cfg_olsrv2_changed(void) {
  if (cfg_schema_tobin(&_olsrv2_config, _olsrv2_section.post, _olsrv2_entries, ARRAYSIZE(_olsrv2_entries))) {
    OONF_WARN(LOG_OLSRV2, "Cannot convert OLSRV2 configuration.");
    return;
  }

  /* set tc timer interval */
  if (_generate_tcs && _overwrite_tc_interval == 0) {
    oonf_timer_set(&_tc_timer, _olsrv2_config.tc_interval);
  }

  /* check if we have to change the originators */
  _update_originator(AF_INET);
  _update_originator(AF_INET6);
}

/**
 * Callback fired when domain section changed
 */
static void
_cb_cfg_domain_changed(void) {
  struct olsrv2_routing_domain rtdomain;
  struct nhdp_domain *domain;
  char *error = NULL;
  int ext;

  ext = strtol(_rt_domain_section.section_name, &error, 10);
  if (error != NULL && *error != 0) {
    /* illegal domain name */
    return;
  }

  if (ext < 0 || ext > 255) {
    /* name out of range */
    return;
  }

  domain = nhdp_domain_add(ext);
  if (domain == NULL) {
    return;
  }

  memset(&rtdomain, 0, sizeof(rtdomain));
  if (cfg_schema_tobin(&rtdomain, _rt_domain_section.post, _rt_domain_entries, ARRAYSIZE(_rt_domain_entries))) {
    OONF_WARN(LOG_OLSRV2, "Cannot convert OLSRV2 routing domain parameters.");
    return;
  }

  olsrv2_routing_set_domain_parameter(domain, &rtdomain);
}
