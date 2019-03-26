
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

#include <oonf/libcommon/autobuf.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/template.h>

#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_clock.h>
#include <oonf/base/oonf_telnet.h>
#include <oonf/base/oonf_viewer.h>

#include <oonf/nhdp/nhdp/nhdp.h>
#include <oonf/nhdp/nhdp/nhdp_domain.h>
#include <oonf/olsrv2/olsrv2/olsrv2.h>
#include <oonf/olsrv2/olsrv2/olsrv2_lan.h>
#include <oonf/olsrv2/olsrv2/olsrv2_originator.h>
#include <oonf/olsrv2/olsrv2/olsrv2_routing.h>
#include <oonf/olsrv2/olsrv2/olsrv2_tc.h>

#include <oonf/olsrv2/olsrv2info/olsrv2info.h>

/* definitions */
#define LOG_OLSRV2INFO olsrv2_olsrv2info_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

static enum oonf_telnet_result _cb_olsrv2info(struct oonf_telnet_data *con);
static enum oonf_telnet_result _cb_olsrv2info_help(struct oonf_telnet_data *con);

static void _initialize_originator_values(int af_type);
static void _initialize_old_originator_values(struct olsrv2_originator_set_entry *);
static void _initialize_domain_values(struct nhdp_domain *domain);
static void _initialize_domain_link_metric_values(struct nhdp_domain *domain, uint32_t);
static void _initialize_domain_distance(uint8_t);
static void _initialize_lan_values(struct olsrv2_lan_entry *);
static void _initialize_node_values(struct olsrv2_tc_node *);
static void _initialize_attached_network_values(struct olsrv2_tc_attachment *edge);
static void _initialize_edge_values(struct olsrv2_tc_edge *edge);
static void _initialize_route_values(struct olsrv2_routing_entry *route);

static int _cb_create_text_originator(struct oonf_viewer_template *);
static int _cb_create_text_old_originator(struct oonf_viewer_template *);
static int _cb_create_text_lan(struct oonf_viewer_template *);
static int _cb_create_text_node(struct oonf_viewer_template *);
static int _cb_create_text_attached_network(struct oonf_viewer_template *);
static int _cb_create_text_edge(struct oonf_viewer_template *);
static int _cb_create_text_route(struct oonf_viewer_template *);

/*
 * list of template keys and corresponding buffers for values.
 *
 * The keys are API, so they should not be changed after published
 */

/*! template key for originator IP */
#define KEY_ORIGINATOR "originator"

/*! template key for former originator IP */
#define KEY_OLD_ORIGINATOR "old_originator"

/*! template key for former originator validity time */
#define KEY_OLD_ORIGINATOR_VTIME "old_originator_vtime"

/*! template key for nhdp domain */
#define KEY_DOMAIN "domain"

/*! template key for metric name */
#define KEY_DOMAIN_METRIC "domain_metric"

/*! template key for incoming human readable metric */
#define KEY_DOMAIN_METRIC_IN "domain_metric_in"

/*! template key for outgoing human readable metric */
#define KEY_DOMAIN_METRIC_OUT "domain_metric_out"

/*! template key for incoming numeric metric */
#define KEY_DOMAIN_METRIC_IN_RAW "domain_metric_in_raw"

/*! template key for outgoing numeric metric */
#define KEY_DOMAIN_METRIC_OUT_RAW "domain_metric_out_raw"

/*! template key for route distance */
#define KEY_DOMAIN_DISTANCE "domain_distance"

/*! template key for hopcount of a routing path */
#define KEY_DOMAIN_PATH_HOPS "domain_path_hops"

/*! template key for local attached network destination prefix */
#define KEY_LAN_DST "lan"

/*! template key for local attached network source prefix */
#define KEY_LAN_SRC "lan_src"

/*! template key for node IP */
#define KEY_NODE "node"

/*! template key for node validity time */
#define KEY_NODE_VTIME "node_vtime"

/*! template key for current node answer set number */
#define KEY_NODE_ANSN "node_ansn"

/*! template key for nodes that exist because of HELLOs or foreign TCs */
#define KEY_NODE_VIRTUAL "node_virtual"

/*! template key for nodes that are direct neighbors */
#define KEY_NODE_NEIGHBOR "node_neighbor"

/*! template key for attached network destination prefix*/
#define KEY_ATTACHED_NET "attached_net"

/*! template key for attached network source prefix */
#define KEY_ATTACHED_NET_SRC "attached_net_src"

/*! template key for attached network answer set number */
#define KEY_ATTACHED_NET_ANSN "attached_net_ansn"

/*! template key for edge destination */
#define KEY_EDGE "edge"

/*! template key for edge answer set number */
#define KEY_EDGE_ANSN "edge_ansn"

/*! template key for route source ip */
#define KEY_ROUTE_SRC_IP "route_src_ip"

/*! template key for route gateway IP */
#define KEY_ROUTE_GW "route_gw"

/*! template key for route destination prefix */
#define KEY_ROUTE_DST "route_dst"

/*! template key for route source prefix */
#define KEY_ROUTE_SRC_PREFIX "route_src_prefix"

/*! template key for route metric */
#define KEY_ROUTE_METRIC "route_metric"

/*! template key for routing table */
#define KEY_ROUTE_TABLE "route_table"

/*! template key for routing protocol */
#define KEY_ROUTE_PROTO "route_proto"

/*! template key for route interface name */
#define KEY_ROUTE_IF "route_if"

/*! template key for route interface index */
#define KEY_ROUTE_IFINDEX "route_ifindex"

/*! template key for the last hop before the route destination */
#define KEY_ROUTE_LASTHOP "route_lasthop"

/*
 * buffer space for values that will be assembled
 * into the output of the plugin
 */
static struct netaddr_str _value_originator;

static struct netaddr_str _value_old_originator;
static struct isonumber_str _value_old_originator_vtime;

static char _value_domain[4];
static char _value_domain_metric[NHDP_DOMAIN_METRIC_MAXLEN];
static struct nhdp_metric_str _value_domain_metric_out;
static char _value_domain_metric_out_raw[12];
static char _value_domain_distance[4];
static char _value_domain_path_hops[4];

static struct netaddr_str _value_lan_dst;
static struct netaddr_str _value_lan_src;

static struct netaddr_str _value_node;
static struct isonumber_str _value_node_vtime;
static char _value_node_ansn[6];
static char _value_node_virtual[TEMPLATE_JSON_BOOL_LENGTH];
static char _value_node_neighbor[TEMPLATE_JSON_BOOL_LENGTH];

static struct netaddr_str _value_attached_net_dst;
static struct netaddr_str _value_attached_net_src;
static char _value_attached_net_ansn[6];

static struct netaddr_str _value_edge;
static char _value_edge_ansn[6];

static struct netaddr_str _value_route_dst;
static struct netaddr_str _value_route_gw;
static struct netaddr_str _value_route_src_ip;
static struct netaddr_str _value_route_src_prefix;
static char _value_route_metric[12];
static char _value_route_table[4];
static char _value_route_proto[4];
static char _value_route_if[IF_NAMESIZE];
static char _value_route_ifindex[12];
static struct netaddr_str _value_route_lasthop;

/* definition of the template data entries for JSON and table output */
static struct abuf_template_data_entry _tde_originator[] = {
  { KEY_ORIGINATOR, _value_originator.buf, true },
};

static struct abuf_template_data_entry _tde_old_originator[] = {
  { KEY_OLD_ORIGINATOR, _value_old_originator.buf, true },
  { KEY_OLD_ORIGINATOR_VTIME, _value_old_originator_vtime.buf, false },
};

static struct abuf_template_data_entry _tde_domain[] = {
  { KEY_DOMAIN, _value_domain, true },
};

static struct abuf_template_data_entry _tde_domain_metric_out[] = {
  { KEY_DOMAIN_METRIC, _value_domain_metric, true },
  { KEY_DOMAIN_METRIC_OUT, _value_domain_metric_out.buf, true },
  { KEY_DOMAIN_METRIC_OUT_RAW, _value_domain_metric_out_raw, false },
};

static struct abuf_template_data_entry _tde_domain_lan_distance[] = {
  { KEY_DOMAIN_DISTANCE, _value_domain_distance, false },
};

static struct abuf_template_data_entry _tde_domain_path_hops[] = {
  { KEY_DOMAIN_PATH_HOPS, _value_domain_path_hops, false },
};

static struct abuf_template_data_entry _tde_lan[] = {
  { KEY_LAN_DST, _value_lan_dst.buf, true },
  { KEY_LAN_SRC, _value_lan_src.buf, true },
};

static struct abuf_template_data_entry _tde_node_key[] = {
  { KEY_NODE, _value_node.buf, true },
};

static struct abuf_template_data_entry _tde_node[] = {
  { KEY_NODE, _value_node.buf, true },
  { KEY_NODE_ANSN, _value_node_ansn, false },
  { KEY_NODE_VTIME, _value_node_vtime.buf, false },
  { KEY_NODE_VIRTUAL, _value_node_virtual, true },
  { KEY_NODE_NEIGHBOR, _value_node_neighbor, true },
};

static struct abuf_template_data_entry _tde_attached_net[] = {
  { KEY_ATTACHED_NET, _value_attached_net_dst.buf, true },
  { KEY_ATTACHED_NET_SRC, _value_attached_net_src.buf, true },
  { KEY_ATTACHED_NET_ANSN, _value_attached_net_ansn, false },
};

static struct abuf_template_data_entry _tde_edge[] = {
  { KEY_EDGE, _value_edge.buf, true },
  { KEY_EDGE_ANSN, _value_edge_ansn, false },
};

static struct abuf_template_data_entry _tde_route[] = {
  { KEY_ROUTE_DST, _value_route_dst.buf, true },
  { KEY_ROUTE_GW, _value_route_gw.buf, true },
  { KEY_ROUTE_SRC_IP, _value_route_src_ip.buf, true },
  { KEY_ROUTE_SRC_PREFIX, _value_route_src_prefix.buf, true },
  { KEY_ROUTE_METRIC, _value_route_metric, false },
  { KEY_ROUTE_TABLE, _value_route_table, false },
  { KEY_ROUTE_PROTO, _value_route_proto, false },
  { KEY_ROUTE_IF, _value_route_if, true },
  { KEY_ROUTE_IFINDEX, _value_route_ifindex, false },
  { KEY_ROUTE_LASTHOP, _value_route_lasthop.buf, true },
};

static struct abuf_template_storage _template_storage;

/* Template Data objects (contain one or more Template Data Entries) */
static struct abuf_template_data _td_orig[] = {
  { _tde_originator, ARRAYSIZE(_tde_originator) },
};
static struct abuf_template_data _td_old_orig[] = {
  { _tde_old_originator, ARRAYSIZE(_tde_old_originator) },
};
static struct abuf_template_data _td_lan[] = {
  { _tde_lan, ARRAYSIZE(_tde_lan) },
  { _tde_domain, ARRAYSIZE(_tde_domain) },
  { _tde_domain_metric_out, ARRAYSIZE(_tde_domain_metric_out) },
  { _tde_domain_lan_distance, ARRAYSIZE(_tde_domain_lan_distance) },
};
static struct abuf_template_data _td_node[] = {
  { _tde_node, ARRAYSIZE(_tde_node) },
};
static struct abuf_template_data _td_attached_net[] = {
  { _tde_node_key, ARRAYSIZE(_tde_node_key) },
  { _tde_attached_net, ARRAYSIZE(_tde_attached_net) },
  { _tde_domain, ARRAYSIZE(_tde_domain) },
  { _tde_domain_metric_out, ARRAYSIZE(_tde_domain_metric_out) },
  { _tde_domain_lan_distance, ARRAYSIZE(_tde_domain_lan_distance) },
};
static struct abuf_template_data _td_edge[] = {
  { _tde_node_key, ARRAYSIZE(_tde_node_key) },
  { _tde_edge, ARRAYSIZE(_tde_edge) },
  { _tde_domain, ARRAYSIZE(_tde_domain) },
  { _tde_domain_metric_out, ARRAYSIZE(_tde_domain_metric_out) },
};
static struct abuf_template_data _td_route[] = {
  { _tde_route, ARRAYSIZE(_tde_route) },
  { _tde_domain, ARRAYSIZE(_tde_domain) },
  { _tde_domain_metric_out, ARRAYSIZE(_tde_domain_metric_out) },
  { _tde_domain_path_hops, ARRAYSIZE(_tde_domain_path_hops) },
};

/* OONF viewer templates (based on Template Data arrays) */
static struct oonf_viewer_template _templates[] = { {
                                                      .data = _td_orig,
                                                      .data_size = ARRAYSIZE(_td_orig),
                                                      .json_name = "originator",
                                                      .cb_function = _cb_create_text_originator,
                                                    },
  {
    .data = _td_old_orig,
    .data_size = ARRAYSIZE(_td_old_orig),
    .json_name = "old_originator",
    .cb_function = _cb_create_text_old_originator,
  },
  {
    .data = _td_lan,
    .data_size = ARRAYSIZE(_td_lan),
    .json_name = "lan",
    .cb_function = _cb_create_text_lan,
  },
  {
    .data = _td_node,
    .data_size = ARRAYSIZE(_td_node),
    .json_name = "node",
    .cb_function = _cb_create_text_node,
  },
  {
    .data = _td_attached_net,
    .data_size = ARRAYSIZE(_td_attached_net),
    .json_name = "attached_network",
    .cb_function = _cb_create_text_attached_network,
  },
  {
    .data = _td_edge,
    .data_size = ARRAYSIZE(_td_edge),
    .json_name = "edge",
    .cb_function = _cb_create_text_edge,
  },
  {
    .data = _td_route,
    .data_size = ARRAYSIZE(_td_route),
    .json_name = "route",
    .cb_function = _cb_create_text_route,
  } };

/* telnet command of this plugin */
static struct oonf_telnet_command _telnet_commands[] = {
  TELNET_CMD(OONF_OLSRV2INFO_SUBSYSTEM, _cb_olsrv2info, "", .help_handler = _cb_olsrv2info_help),
};

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_NHDP_SUBSYSTEM,
  OONF_OLSRV2_SUBSYSTEM,
};
static struct oonf_subsystem olsrv2_olsrv2info_subsystem = {
  .name = OONF_OLSRV2INFO_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OLSRv2 olsrv2 info plugin",
  .author = "Henning Rogge",
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(olsrv2_olsrv2info_subsystem);

/**
 * Initialize plugin
 * @return always returns 0
 */
static int
_init(void) {
  oonf_telnet_add(&_telnet_commands[0]);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  oonf_telnet_remove(&_telnet_commands[0]);
}

/**
 * Callback for the telnet command of this plugin
 * @param con pointer to telnet session data
 * @return telnet result value
 */
static enum oonf_telnet_result
_cb_olsrv2info(struct oonf_telnet_data *con) {
  return oonf_viewer_telnet_handler(
    con->out, &_template_storage, OONF_OLSRV2INFO_SUBSYSTEM, con->parameter, _templates, ARRAYSIZE(_templates));
}

/**
 * Callback for the help output of this plugin
 * @param con pointer to telnet session data
 * @return telnet result value
 */
static enum oonf_telnet_result
_cb_olsrv2info_help(struct oonf_telnet_data *con) {
  return oonf_viewer_telnet_help(
    con->out, OONF_OLSRV2INFO_SUBSYSTEM, con->parameter, _templates, ARRAYSIZE(_templates));
}

/**
 * Initialize the value buffers for an originator entry
 * @param af_type address family of originator
 */
static void
_initialize_originator_values(int af_type) {
  netaddr_to_string(&_value_originator, olsrv2_originator_get(af_type));
}

/**
 * Initialize the value buffer for old originator entries
 * @param entry originator set entry
 */
static void
_initialize_old_originator_values(struct olsrv2_originator_set_entry *entry) {
  netaddr_to_string(&_value_old_originator, &entry->originator);

  oonf_timer_to_string(&_value_old_originator_vtime, &entry->_vtime);
}

/**
 * Initialize the value buffers for a NHDP domain
 * @param domain NHDP domain
 */
static void
_initialize_domain_values(struct nhdp_domain *domain) {
  snprintf(_value_domain, sizeof(_value_domain), "%u", domain->ext);
  strscpy(_value_domain_metric, domain->metric->name, sizeof(_value_domain_metric));
}

/**
 * Initialize the value buffers for a metric value
 * @param domain NHDP domain
 * @param metric raw metric value
 */
static void
_initialize_domain_link_metric_values(struct nhdp_domain *domain, uint32_t metric) {
  nhdp_domain_get_link_metric_value(&_value_domain_metric_out, domain, metric);

  snprintf(_value_domain_metric_out_raw, sizeof(_value_domain_metric_out_raw), "%u", metric);
}

/**
 * Initialize the value buffers for a metric value
 * @param domain NHDP domain
 * @param metric raw metric value
 */
static void
_initialize_domain_path_metric_values(struct nhdp_domain *domain, uint32_t metric, uint8_t hopcount) {
  nhdp_domain_get_path_metric_value(&_value_domain_metric_out, domain, metric, hopcount);

  snprintf(_value_domain_metric_out_raw, sizeof(_value_domain_metric_out_raw), "%u", metric);
}

/**
 * Initialize the value buffer for the hopcount value for routes
 * @param distance hopcount value
 */
static void
_initialize_domain_distance(uint8_t distance) {
  snprintf(_value_domain_distance, sizeof(_value_domain_distance), "%u", distance);
}

/**
 * Initialize the value buffer for the path hopcount
 * @param path_hops path distance
 */
static void
_initialize_domain_path_hops(uint8_t path_hops) {
  snprintf(_value_domain_path_hops, sizeof(_value_domain_path_hops), "%u", path_hops);
}

/**
 * Initialize the value buffer for a LAN entry
 * @param lan OLSRv2 LAN entry
 */
static void
_initialize_lan_values(struct olsrv2_lan_entry *lan) {
  netaddr_to_string(&_value_lan_dst, &lan->prefix.dst);
  netaddr_to_string(&_value_lan_src, &lan->prefix.src);
}

/**
 * Initialize the value buffers for an OLSRv2 node
 * @param node OLSRv2 node
 */
static void
_initialize_node_values(struct olsrv2_tc_node *node) {
  netaddr_to_string(&_value_node, &node->target.prefix.dst);

  oonf_timer_to_string(&_value_node_vtime, &node->_validity_time);

  snprintf(_value_node_ansn, sizeof(_value_node_ansn), "%u", node->ansn);

  strscpy(_value_node_virtual, json_getbool(!oonf_timer_is_active(&node->_validity_time)), sizeof(_value_node_virtual));
  strscpy(_value_node_neighbor, json_getbool(node->direct_neighbor), sizeof(_value_node_neighbor));
}

/**
 * Initialize the value buffers for an OLSRv2 attached network
 * @param edge attached network edge
 */
static void
_initialize_attached_network_values(struct olsrv2_tc_attachment *edge) {
  netaddr_to_string(&_value_attached_net_dst, &edge->dst->target.prefix.dst);
  netaddr_to_string(&_value_attached_net_src, &edge->dst->target.prefix.src);

  snprintf(_value_attached_net_ansn, sizeof(_value_attached_net_ansn), "%u", edge->ansn);
}

/**
 * Initialize the value buffers for an OLSRv2 edge
 * @param edge OLSRv2 edge
 */
static void
_initialize_edge_values(struct olsrv2_tc_edge *edge) {
  netaddr_to_string(&_value_edge, &edge->dst->target.prefix.dst);

  snprintf(_value_edge_ansn, sizeof(_value_edge_ansn), "%u", edge->ansn);
}

/**
 * Initialize the value buffers for a OLSRv2 route
 * @param route OLSRv2 routing entry
 */
static void
_initialize_route_values(struct olsrv2_routing_entry *route) {
  netaddr_to_string(&_value_route_dst, &route->route.p.key.dst);
  netaddr_to_string(&_value_route_gw, &route->route.p.gw);
  netaddr_to_string(&_value_route_src_ip, &route->route.p.src_ip);
  netaddr_to_string(&_value_route_src_prefix, &route->route.p.key.src);

  snprintf(_value_route_metric, sizeof(_value_route_metric), "%u", route->route.p.metric);
  snprintf(_value_route_table, sizeof(_value_route_table), "%u", route->route.p.table);
  snprintf(_value_route_proto, sizeof(_value_route_proto), "%u", route->route.p.protocol);

  if_indextoname(route->route.p.if_index, _value_route_if);
  snprintf(_value_route_ifindex, sizeof(_value_route_ifindex), "%u", route->route.p.if_index);

  netaddr_to_string(&_value_route_lasthop, &route->last_originator);
}

/**
 * Displays the known data about each NHDP interface.
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_old_originator(struct oonf_viewer_template *template) {
  struct olsrv2_originator_set_entry *entry;

  avl_for_each_element(olsrv2_originator_get_tree(), entry, _node) {
    _initialize_old_originator_values(entry);

    /* generate template output */
    oonf_viewer_output_print_line(template);
  }
  return 0;
}

/**
 * Display the originator addresses of the local node
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_originator(struct oonf_viewer_template *template) {
  /* generate template output */
  _initialize_originator_values(AF_INET);
  oonf_viewer_output_print_line(template);

  /* generate template output */
  _initialize_originator_values(AF_INET6);
  oonf_viewer_output_print_line(template);

  return 0;
}

/**
 * Display all locally attached networks
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_lan(struct oonf_viewer_template *template) {
  struct olsrv2_lan_entry *lan;
  struct nhdp_domain *domain;

  avl_for_each_element(olsrv2_lan_get_tree(), lan, _node) {
    _initialize_lan_values(lan);

    list_for_each_element(nhdp_domain_get_list(), domain, _node) {
      if (olsrv2_lan_get_domaindata(domain, lan)->active) {
        _initialize_domain_values(domain);
        _initialize_domain_link_metric_values(domain, olsrv2_lan_get_domaindata(domain, lan)->outgoing_metric);
        _initialize_domain_distance(olsrv2_lan_get_domaindata(domain, lan)->distance);

        oonf_viewer_output_print_line(template);
      }
    }
  }
  return 0;
}

/**
 * Display all known OLSRv2 nodes
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_node(struct oonf_viewer_template *template) {
  struct olsrv2_tc_node *node;

  avl_for_each_element(olsrv2_tc_get_tree(), node, _originator_node) {
    _initialize_node_values(node);

    oonf_viewer_output_print_line(template);
  }
  return 0;
}

/**
 * Display all known OLSRv2 attached networks
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_attached_network(struct oonf_viewer_template *template) {
  struct olsrv2_tc_node *node;
  struct olsrv2_tc_attachment *attached;
  struct nhdp_domain *domain;

  avl_for_each_element(olsrv2_tc_get_tree(), node, _originator_node) {
    _initialize_node_values(node);

    if (olsrv2_tc_is_node_virtual(node)) {
      continue;
    }

    avl_for_each_element(&node->_attached_networks, attached, _src_node) {
      _initialize_attached_network_values(attached);

      list_for_each_element(nhdp_domain_get_list(), domain, _node) {
        _initialize_domain_values(domain);
        _initialize_domain_link_metric_values(domain, olsrv2_tc_attachment_get_metric(domain, attached));
        _initialize_domain_distance(olsrv2_tc_attachment_get_distance(domain, attached));

        oonf_viewer_output_print_line(template);
      }
    }
  }
  return 0;
}

/**
 * Display all known OLSRv2 edges
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_edge(struct oonf_viewer_template *template) {
  struct olsrv2_tc_node *node;
  struct olsrv2_tc_edge *edge;
  struct nhdp_domain *domain;
  uint32_t metric;

  avl_for_each_element(olsrv2_tc_get_tree(), node, _originator_node) {
    _initialize_node_values(node);

    if (olsrv2_tc_is_node_virtual(node)) {
      continue;
    }
    avl_for_each_element(&node->_edges, edge, _node) {
      if (edge->virtual) {
        continue;
      }

      _initialize_edge_values(edge);

      list_for_each_element(nhdp_domain_get_list(), domain, _node) {
        metric = olsrv2_tc_edge_get_metric(domain, edge);
        if (metric <= RFC7181_METRIC_MAX) {
          _initialize_domain_values(domain);
          _initialize_domain_link_metric_values(domain, metric);

          oonf_viewer_output_print_line(template);
        }
      }
    }
  }
  return 0;
}

/**
 * Display all current entries of the OLSRv2 routing table
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_route(struct oonf_viewer_template *template) {
  struct olsrv2_routing_entry *route;
  struct nhdp_domain *domain;

  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    _initialize_domain_values(domain);

    avl_for_each_element(olsrv2_routing_get_tree(domain), route, _node) {
      _initialize_domain_path_metric_values(domain, route->path_cost, route->path_hops);
      _initialize_domain_path_hops(route->path_hops);
      _initialize_route_values(route);

      oonf_viewer_output_print_line(template);
    }
  }
  return 0;
}
