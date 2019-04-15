
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

#define _GNU_SOURCE

/* must be first because of a problem with linux/netlink.h */
#include <sys/socket.h>

/* and now the rest of the includes */
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <netlink/attr.h>
#include <netlink/msg.h>
#include <sys/uio.h>

#include <oonf/libcommon/autobuf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/libcommon/string.h>

#include <oonf/libconfig/cfg.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_interface.h>
#include <oonf/base/os_system.h>

#include <oonf/generic/nl80211_listener/genl_get_family.h>
#include <oonf/generic/nl80211_listener/nl80211_get_interface.h>
#include <oonf/generic/nl80211_listener/nl80211_get_mpp.h>
#include <oonf/generic/nl80211_listener/nl80211_get_station_dump.h>
#include <oonf/generic/nl80211_listener/nl80211_get_survey.h>
#include <oonf/generic/nl80211_listener/nl80211_get_wiphy.h>
#include <oonf/generic/nl80211_listener/nl80211_listener.h>
#include <oonf/generic/nl80211_listener/nl80211.h>

/* definitions */

/**
 * nl80211 configuration
 */
struct _nl80211_config {
  /*! interval between two series of netlink probes */
  uint64_t interval;

  /*! true if plugin should set multicast rate in the l2 db */
  bool report_multicast_rate;
};

/**
 * definition of a query to the nl80211 subsystem
 */
struct _nl80211_query {
  /*! netlink command that should be queried later */
  uint8_t cmd;

  /**
   * Callback to send query
   * @param nl_msg netlink message
   * @param hdr generic message header
   * @param interf netlink interface
   */
  void (*send)(
    struct os_system_netlink_message *nl_msg, struct genlmsghdr *hdr, struct nl80211_if *interf);

  /**
   * Callback to process incoming netlink data
   * @param interf netlink interface
   * @param hdr netlink message header
   */
  void (*process)(struct nl80211_if *interf, struct nlmsghdr *hdr);

  /**
   * Finalize the processing of the netlink query
   * @param interf netlink interface
   */
  void (*finalize)(struct nl80211_if *interf);
};

/**
 * Index number for nl80211 configuration entries
 */
enum _nl80211_cfg_idx
{
  IDX_INTERVAL,
  IDX_INTERFACES,
  IDX_MC_RATE,
};

/**
 * index numbers for netlink queries done by listener
 */
enum _if_query
{
  QUERY_START = 0,       //!< QUERY_START
  QUERY_GET_IF = 0,      //!< QUERY_GET_IF
  QUERY_GET_WIPHY = 1,   //!< QUERY_GET_WIPHY
  QUERY_GET_SURVEY = 2,  //!< QUERY_GET_SURVEY
  QUERY_GET_MPP = 3,     //!< QUERY_GET_MPP
  QUERY_GET_STATION = 4, //!< QUERY_GET_STATION
  QUERY_END = 5,         //!< QUERY_END

  QUERY_GET_FAMILY = 6, //!< QUERY_GET_FAMILY

  QUERY_COUNT, //!< QUERY_COUNT
};

/* prototypes */
static void _early_cfg_init(void);
static int _init(void);
static void _cleanup(void);

static struct nl80211_if *_nl80211_if_get(const char *name);
static struct nl80211_if *_nl80211_if_add(const char *name);
static void _nl80211_if_remove(struct nl80211_if *);

static void _cb_config_changed(void);
static void _cb_if_config_changed(void);

static void _cb_transmission_event(struct oonf_timer_instance *);
static void _trigger_next_netlink_query(void);

static void _cb_nl_response(struct os_system_netlink_message* nl_msg, struct nlmsghdr* hdr);
static void _cb_nl_feedback(struct os_system_netlink_message *nl);

/* configuration */
static struct cfg_schema_section _if_section = {
  CFG_OSIF_SCHEMA_INTERFACE_SECTION_INIT,

  .cb_delta_handler = _cb_if_config_changed,
  .entries = NULL,
  .entry_count = 0,
};

static struct cfg_schema_entry _nl80211_entries[] = {
  [IDX_INTERVAL] = CFG_MAP_CLOCK_MIN(
    _nl80211_config, interval, "interval", "1.0", "Interval between two linklayer information updates", 100),
  [IDX_INTERFACES] = CFG_VALIDATE_PRINTABLE_LEN(
    "if", "", "List of additional interfaces to read nl80211 data from", IF_NAMESIZE, .list = true),
  [IDX_MC_RATE] = CFG_MAP_BOOL(_nl80211_config, report_multicast_rate, "report_mc_rate", "false",
    "Activate to write the multicast/broadcast speed into the layer2 database"),
};

static struct cfg_schema_section _nl80211_section = {
  .type = OONF_NL80211_LISTENER_SUBSYSTEM,
  .cb_delta_handler = _cb_config_changed,
  .entries = _nl80211_entries,
  .entry_count = ARRAYSIZE(_nl80211_entries),
  .next_section = &_if_section,
};

static struct _nl80211_config _config;

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_LAYER2_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_OS_INTERFACE_SUBSYSTEM,
  OONF_OS_SYSTEM_SUBSYSTEM,
};

static struct oonf_subsystem _nl80211_listener_subsystem = {
  .name = OONF_NL80211_LISTENER_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OONF nl80211 listener plugin",
  .author = "Henning Rogge",

  .cfg_section = &_nl80211_section,

  .early_cfg_init = _early_cfg_init,
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_nl80211_listener_subsystem);

enum oonf_log_source LOG_NL80211;

/* netlink specific data */
static struct os_system_netlink _netlink_handler = {
  .name = "nl80211 listener",
  .used_by = &_nl80211_listener_subsystem,
  .cb_response = _cb_nl_response,
  .cb_error = _cb_nl_feedback,
  .cb_done = _cb_nl_feedback,
};

/* buffer for outgoing netlink message */
static uint32_t _nl_msgbuffer[UIO_MAXIOV / sizeof(uint32_t)];
static struct nlmsghdr *_nl_msg = (void *)_nl_msgbuffer;
static struct os_system_netlink_message os_nl_msg = {
  .message = (void *)_nl_msgbuffer,
  .max_length = sizeof(_nl_msgbuffer),
  .originator = &_netlink_handler,
};

/* netlink nl80211 identification */
static uint32_t _nl80211_id = 0;
static uint32_t _nl80211_multicast_group = 0;

/* layer2 metadata */
static struct oonf_layer2_origin _layer2_updated_origin = {
  .name = "nl80211 updated",
  .proactive = true,
  .priority = OONF_LAYER2_ORIGIN_RELIABLE + 1,
};
static struct oonf_layer2_origin _layer2_data_origin = {
  .name = "nl80211",
  .proactive = true,
  .priority = OONF_LAYER2_ORIGIN_RELIABLE,
};

/* current query data */
static struct nl80211_if *_current_query_if = NULL;
static enum _if_query _current_query_number = QUERY_START;
static bool _current_query_in_progress = false;

/* timer for generating netlink requests */
static struct oonf_timer_class _transmission_timer_info = {
  .name = "nl80211 listener timer",
  .callback = _cb_transmission_event,
  .periodic = true,
};

static struct oonf_timer_instance _transmission_timer = { .class = &_transmission_timer_info };

/* nl80211_if handling */
static struct avl_tree _nl80211_if_tree;

static struct oonf_class _nl80211_if_class = {
  .name = "nl80211 if",
  .size = sizeof(struct nl80211_if),
};

static const struct _nl80211_query _if_query_ops[QUERY_COUNT] = {
  [QUERY_GET_IF] =
    {
      NL80211_CMD_NEW_INTERFACE,
      nl80211_send_get_interface,
      nl80211_process_get_interface_result,
      NULL,
    },
  [QUERY_GET_WIPHY] =
    {
      NL80211_CMD_NEW_WIPHY,
      nl80211_send_get_wiphy,
      nl80211_process_get_wiphy_result,
      nl80211_finalize_get_wiphy,
    },
  [QUERY_GET_SURVEY] =
    {
      NL80211_CMD_NEW_SURVEY_RESULTS,
      nl80211_send_get_survey,
      nl80211_process_get_survey_result,
      NULL,
    },
  [QUERY_GET_MPP] =
    {
      NL80211_CMD_NEW_MPATH,
      nl80211_send_get_mpp,
      nl80211_process_get_mpp_result,
      NULL,
    },
  [QUERY_GET_STATION] =
    {
      NL80211_CMD_NEW_STATION,
      nl80211_send_get_station_dump,
      nl80211_process_get_station_dump_result,
      NULL,
    },
};

static void
_early_cfg_init(void) {
  LOG_NL80211 = _nl80211_listener_subsystem.logging;
}

/**
 * Constructor of plugin
 * @return 0 if initialization was successful, -1 otherwise
 */
static int
_init(void) {
  if (os_system_linux_netlink_add(&_netlink_handler, NETLINK_GENERIC)) {
    return -1;
  }

  /* initialize nl80211 if storage system */
  oonf_class_add(&_nl80211_if_class);
  avl_init(&_nl80211_if_tree, avl_comp_strcasecmp, false);

  /* get layer2 origin */
  oonf_layer2_origin_add(&_layer2_updated_origin);
  oonf_layer2_origin_add(&_layer2_data_origin);

  oonf_timer_add(&_transmission_timer_info);
  return 0;
}

/**
 * Destructor of plugin
 */
static void
_cleanup(void) {
  struct nl80211_if *interf, *it_if;
  avl_for_each_element_safe(&_nl80211_if_tree, interf, _node, it_if) {
    _nl80211_if_remove(interf);
  }
  oonf_layer2_origin_remove(&_layer2_updated_origin);
  oonf_layer2_origin_remove(&_layer2_data_origin);

  oonf_timer_stop(&_transmission_timer);
  oonf_timer_remove(&_transmission_timer_info);
  os_system_linux_netlink_remove(&_netlink_handler);
}

/**
 * Add a layer2 destination to the database
 * @param l2neigh layer2 neighbor
 * @param dstmac destination mac address
 * @return layer2 destination
 */
struct oonf_layer2_destination *
nl80211_add_dst(struct oonf_layer2_neigh *l2neigh, const struct netaddr *dstmac) {
  struct oonf_layer2_destination *dst;

  dst = oonf_layer2_destination_add(l2neigh, dstmac, &_layer2_updated_origin);
  if (dst->origin == &_layer2_data_origin) {
    dst->origin = &_layer2_updated_origin;
  }
  return dst;
}

/**
 * Change a layer2 network setting
 * @param l2net pointer to layer2 network
 * @param idx index of setting
 * @param value new value
 * @param scaling fixpoint integer arithmetics scaling
 * @return true if value changed, false otherwise
 */
bool
nl80211_change_l2net_data(struct oonf_layer2_net *l2net, enum oonf_layer2_network_index idx,
    int64_t value, int64_t scaling) {
  return oonf_layer2_data_set_int64(&l2net->data[idx], &_layer2_updated_origin,
      oonf_layer2_net_metadata_get(idx), value, scaling);
}

/**
 * Change a layer2 network neighbor default setting
 * @param l2net pointer to layer2 network
 * @param idx index of setting
 * @param value new value
 * @return true if value changed, false otherwise
 */
bool
nl80211_change_l2net_neighbor_default(
  struct oonf_layer2_net *l2net, enum oonf_layer2_neighbor_index idx, int64_t value, int64_t scaling) {
  return oonf_layer2_data_set_int64(&l2net->neighdata[idx], &_layer2_updated_origin,
      oonf_layer2_neigh_metadata_get(idx), value, scaling);
}

/**
 * Cleanup all data generated by this listener from a layer2 neighbor,
 * but do not commit data
 * @param l2neigh pointer to layer2 neighbor
 */
void
nl80211_cleanup_l2neigh_data(struct oonf_layer2_neigh *l2neigh) {
  oonf_layer2_neigh_cleanup(l2neigh, &_layer2_data_origin);
}

/**
 * Change a layer2 neighbor setting
 * @param l2neigh pointer to layer2 neighbor
 * @param idx index of setting
 * @param value new value
 * @return true if value changed, false otherwise
 */
bool
nl80211_change_l2neigh_data(struct oonf_layer2_neigh *l2neigh, enum oonf_layer2_neighbor_index idx,
    int64_t value, int64_t scaling) {
  return oonf_layer2_data_set_int64(&l2neigh->data[idx], &_layer2_updated_origin,
      oonf_layer2_neigh_metadata_get(idx), value, scaling);
}

/**
 * @return true if plugin should create a broadcast entry neighbor
 */
bool
nl80211_create_broadcast_neighbor(void) {
  return _config.report_multicast_rate;
}

/**
 * Get a nl80211 interface from tree
 * @param name interface name
 * @return nl80211 interface, NULL if not found
 */
static struct nl80211_if *
_nl80211_if_get(const char *name) {
  struct nl80211_if *interf;

  return avl_find_element(&_nl80211_if_tree, name, interf, _node);
}

/**
 * Add a nl80211 interface to the tree
 * @param name interface name
 * @return nl80211 interface, NULL if out of memory
 */
static struct nl80211_if *
_nl80211_if_add(const char *name) {
  struct nl80211_if *interf;

  interf = _nl80211_if_get(name);
  if (interf) {
    return interf;
  }

  interf = oonf_class_malloc(&_nl80211_if_class);
  if (!interf) {
    return NULL;
  }

  /* initialize avl node */
  strscpy(interf->name, name, IF_NAMESIZE);
  interf->_node.key = interf->name;

  /* initialize l2net */
  interf->l2net = oonf_layer2_net_add(interf->name);
  if (!interf->l2net) {
    oonf_class_free(&_nl80211_if_class, interf);
    return NULL;
  }

  /* initialize interface listener */
  interf->if_listener.name = interf->name;
  if (!os_interface_add(&interf->if_listener)) {
    oonf_layer2_net_remove(interf->l2net, &_layer2_data_origin);
    oonf_layer2_net_remove(interf->l2net, &_layer2_updated_origin);
    oonf_class_free(&_nl80211_if_class, interf);
    return NULL;
  }

  /* initialize interface */
  interf->wifi_phy_if = -1;

  OONF_DEBUG(LOG_NL80211, "Add if %s", name);
  avl_insert(&_nl80211_if_tree, &interf->_node);
  return interf;
}

/**
 * Remove a nl80211 interface from tree
 * @param interf nl80211 interface
 */
static void
_nl80211_if_remove(struct nl80211_if *interf) {
  avl_remove(&_nl80211_if_tree, &interf->_node);
  os_interface_remove(&interf->if_listener);
  oonf_class_free(&_nl80211_if_class, interf);
}

/**
 * Update configuration of interface section
 */
static void
_cb_if_config_changed(void) {
  struct nl80211_if *interf;
  const char *ifname;
  char ifbuf[IF_NAMESIZE];

  ifname = cfg_get_phy_if(ifbuf, _if_section.section_name);
  if (_if_section.pre == NULL) {
    interf = _nl80211_if_add(ifname);
    if (interf) {
      interf->_if_section = true;
    }
  }

  if (_if_section.post == NULL) {
    interf = _nl80211_if_get(ifname);
    if (interf) {
      interf->_if_section = false;
      if (!interf->_nl80211_section) {
        _nl80211_if_remove(interf);
      }
    }
  }
}

/**
 * Transmit the next netlink command to nl80211
 * @param ptr timer instance that fired
 */
static void
_cb_transmission_event(struct oonf_timer_instance *ptr __attribute__((unused))) {
  if (!_current_query_in_progress) {
    _trigger_next_netlink_query();
  }
}

/**
 * Send a netlink message to the nl80211 subsystem
 * @param interf nl80211 interface for message
 * @param query query id
 */
static void
_send_netlink_message(struct nl80211_if *interf, enum _if_query query) {
  struct genlmsghdr *hdr;

  memset(&_nl_msgbuffer, 0, sizeof(_nl_msgbuffer));

  /* generic netlink initialization */
  _nl_msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
  _nl_msg->nlmsg_flags = NLM_F_REQUEST;

  /* request nl80211 identifier */
  if (query == QUERY_GET_FAMILY) {
    /* request nl80211 identifier */
    _nl_msg->nlmsg_type = GENL_ID_CTRL;
  }
  else {
    _nl_msg->nlmsg_type = _nl80211_id;
  }

  hdr = NLMSG_DATA(_nl_msg);

  if (query < QUERY_END) {
    OONF_DEBUG(LOG_NL80211, "Get query %d for interface %s", query, interf->name);
  }

  if (query == QUERY_GET_FAMILY) {
    genl_send_get_family(_nl_msg, hdr);
  }
  else if (_if_query_ops[query].send) {
    _if_query_ops[query].send(&os_nl_msg, hdr, interf);
  }

  os_system_linux_netlink_send(&_netlink_handler, &os_nl_msg);
}

/**
 * Proceed to next query
 */
static void
_get_next_query(void) {
  if (avl_is_empty(&_nl80211_if_tree)) {
    OONF_DEBUG(LOG_NL80211, "No nl80211 interfaces");
    _current_query_if = NULL;
    return;
  }

  /* no query left to do? start again at the first */
  if (!_current_query_if) {
    /* start with first interface and query */
    _current_query_if = avl_first_element(&_nl80211_if_tree, _current_query_if, _node);
    _current_query_number = QUERY_START;
    _current_query_in_progress = true;
  }
  else {
    /* next query */
    _current_query_number++;

    if (_current_query_number == QUERY_END) {
      /* commit interface data */
      if (_current_query_if->ifdata_changed) {
        /* set fixed flags for nl80211 data */
        oonf_layer2_data_set_bool(
          &_current_query_if->l2net->data[OONF_LAYER2_NET_MCS_BY_PROBING], &_layer2_updated_origin, NULL, true);

        /* cleanup old data and relable new one, then commit everything */
        oonf_layer2_net_cleanup(_current_query_if->l2net, &_layer2_data_origin, true);
        oonf_layer2_net_relabel(_current_query_if->l2net, &_layer2_data_origin, &_layer2_updated_origin);
        oonf_layer2_net_commit(_current_query_if->l2net);
        _current_query_if->ifdata_changed = false;
      }

      _current_query_if = avl_next_element_safe(&_nl80211_if_tree, _current_query_if, _node);
      _current_query_number = QUERY_START;
    }
  }
}

/**
 * Trigger the next netlink query
 */
static void
_trigger_next_netlink_query(void) {
  if (!_nl80211_id || !_nl80211_multicast_group) {
    if (_current_query_in_progress) {
      /* wait for the next timer */
      _current_query_in_progress = false;
      return;
    }

    /* first we need to get the ID and multicast group */
    OONF_DEBUG(LOG_NL80211, "Get nl80211 family and multicast id");
    _current_query_in_progress = true;
    _send_netlink_message(NULL, QUERY_GET_FAMILY);
    return;
  }

  /* calculate next interface/query, ignore interfaces that are down */
  do {
    _get_next_query();
  } while (_current_query_if && !_current_query_if->if_listener.data->flags.up);

  if (!_current_query_if) {
    /* done with this series of queries, wait for next timer */
    OONF_INFO(LOG_NL80211, "All queries done for all interfaces");
    _current_query_in_progress = false;
    return;
  }

  OONF_INFO(LOG_NL80211, "Sending query %u to interface %s", _current_query_number, _current_query_if->name);
  _send_netlink_message(_current_query_if, _current_query_number);
}

/**
 * Parse an incoming netlink message from the kernel
 * @param hdr pointer to netlink message
 */
static void
_cb_nl_response(struct os_system_netlink_message *nl_msg __attribute__((unused)), struct nlmsghdr *hdr) {
  struct genlmsghdr *gen_hdr;

  gen_hdr = NLMSG_DATA(hdr);
  if (hdr->nlmsg_type == GENL_ID_CTRL && gen_hdr->cmd == CTRL_CMD_NEWFAMILY) {
    genl_process_get_family_result(hdr, &_nl80211_id, &_nl80211_multicast_group);
    return;
  }

  if (hdr->nlmsg_type != _nl80211_id) {
    OONF_WARN(LOG_NL80211, "Unhandled netlink message type: %u", hdr->nlmsg_type);
    return;
  }

  if (gen_hdr->cmd != _if_query_ops[_current_query_number].cmd) {
    OONF_INFO(LOG_NL80211, "Received Nl80211 command %u for query %u (should be %u)", gen_hdr->cmd,
      _current_query_number, _if_query_ops[_current_query_number].cmd);
  }
  else if (_if_query_ops[_current_query_number].process) {
    OONF_DEBUG(LOG_NL80211, "Received Nl80211 command %u for query %u", gen_hdr->cmd, _current_query_number);
    _current_query_if->l2net->if_type = OONF_LAYER2_TYPE_WIRELESS;
    _if_query_ops[_current_query_number].process(_current_query_if, hdr);
  }
}

/**
 * Callback triggered when a netlink message failes
 * @param seq sequence number
 * @param error error code
 */
static void
_cb_nl_feedback(struct os_system_netlink_message *nlmsg __attribute__((unused))) {
  OONF_INFO(LOG_NL80211, "seq %u: Result %d",
            nlmsg->message->nlmsg_seq, nlmsg->result);
  if (_nl80211_id && _nl80211_multicast_group) {
    if (_if_query_ops[_current_query_number].finalize) {
      _if_query_ops[_current_query_number].finalize(_current_query_if);
    }
    _trigger_next_netlink_query();
  }
}

/**
 * Update configuration of nl80211-listener plugin
 */
static void
_cb_config_changed(void) {
  const struct const_strarray *array;
  struct nl80211_if *interf;
  const char *str;

  if (cfg_schema_tobin(&_config, _nl80211_section.post, _nl80211_entries, ARRAYSIZE(_nl80211_entries))) {
    OONF_WARN(LOG_NL80211, "Could not convert " OONF_NL80211_LISTENER_SUBSYSTEM " config to bin");
    return;
  }

  /* set transmission timer */
  oonf_timer_set_ext(&_transmission_timer, 1, _config.interval);

  /* mark old interfaces for removal */
  array = cfg_db_get_schema_entry_value(_nl80211_section.pre, &_nl80211_entries[IDX_INTERFACES]);
  if (array && strarray_get_count_c(array) > 0) {
    strarray_for_each_element(array, str) {
      interf = _nl80211_if_get(str);
      if (interf) {
        interf->_remove = !interf->_if_section;
        interf->_nl80211_section = false;
      }
    }
  }

  /* create new interfaces and remove mark */
  array = cfg_db_get_schema_entry_value(_nl80211_section.post, &_nl80211_entries[IDX_INTERFACES]);
  if (array && strarray_get_count_c(array) > 0) {
    strarray_for_each_element(array, str) {
      interf = _nl80211_if_add(str);
      if (interf) {
        /* mark for removal */
        interf->_remove = false;
        interf->_nl80211_section = true;
      }
    }
  }

  array = cfg_db_get_schema_entry_value(_nl80211_section.pre, &_nl80211_entries[IDX_INTERFACES]);
  if (array && strarray_get_count_c(array) > 0) {
    strarray_for_each_element(array, str) {
      interf = _nl80211_if_get(str);
      if (interf && interf->_remove) {
        _nl80211_if_remove(interf);
      }
    }
  }
}
