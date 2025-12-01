
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

#ifndef OLSRV2_ROUTING_H_
#define OLSRV2_ROUTING_H_

#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>

#include <oonf/base/os_routing.h>

#include <oonf/nhdp/nhdp/nhdp.h>
#include <oonf/nhdp/nhdp/nhdp_db.h>
#include <oonf/nhdp/nhdp/nhdp_domain.h>

/*! minimum time between two dijkstra calculations in milliseconds */
enum
{
  OLSRv2_DIJKSTRA_RATE_LIMITATION = 1000
};

/**
 * representation of a node in the dijkstra tree
 */
struct olsrv2_dijkstra_node {
  /*! hook into the working list of the dijkstra */
  struct avl_node _node;

  /*! total path cost */
  uint32_t path_cost;

  /*! path hops to the target */
  uint8_t path_hops;

  /*! hopcount to be inserted into the route */
  uint8_t distance;

  /*! originator address of the router responsible for the prefix */
  const struct netaddr *originator;

  /*! pointer to nhpd neighbor that represents the first hop */
  struct nhdp_neighbor *first_hop;

  /**
   * address of the last originator in the routing tree before
   * the destination
   */
  const struct netaddr *last_originator;

  /*! true if route is single-hop */
  bool single_hop;

  /*! true if this node is ourself */
  bool local;

  /*! true if node already has been processed */
  bool done;
};

/**
 * representation of one target in the routing entry set
 */
struct olsrv2_routing_entry {
  /*! Settings for the kernel route */
  struct os_route route;

  /*! nhdp domain of route */
  struct nhdp_domain *domain;

  /*! path cost to reach the target */
  uint32_t path_cost;

  /*! path hops to the target */
  uint8_t path_hops;

  /*! originator of node that announced the route */
  struct netaddr originator;

  /*! originator address of next hop */
  struct netaddr next_originator;

  /*! originator of last hop before target */
  struct netaddr last_originator;

  /**
   * true if the entry represents a route that should be in the kernel,
   * false if the entry should be removed from the kernel
   */
  bool set;

  /*! true if this route is being processed by the kernel at the moment */
  bool in_processing;

  /*! old values of route before current dijstra run */
  struct os_route_parameter _old;

  /*! hook into working queues */
  struct list_entity _working_node;

  /*! global node */
  struct avl_node _node;
};

/**
 * routing domain specific parameters
 */
struct olsrv2_routing_domain {
  /*! true if IPv4 routes should set a source IP */
  bool use_srcip_in_routes;

  /*! protocol number for routes */
  int protocol;

  /*! routing table number for routes */
  int32_t table;

  /*! metric value that should be used for routes */
  int distance;

  /*! domain uses source specific routing */
  bool source_specific;
};

/**
 * A filter that can modify or drop the result of the Dijkstra algorithm
 */
struct olsrv2_routing_filter {
  /**
   * callback for routing filter, return false to drop route modification.
   * filter can modify all parameters of the route.
   * @param domain NHDP domain
   * @param route_param operation system route parameters
   * @return true if route should still be set/removed, false if it should be ignored
   */
  bool (*filter)(struct nhdp_domain *domain, struct os_route_parameter *route_param, bool set);

  /*! node to hold all routing filters together */
  struct list_entity _node;
};

int olsrv2_routing_init(void);
void olsrv2_routing_initiate_shutdown(void);
void olsrv2_routing_cleanup(void);

void olsrv2_routing_dijkstra_node_init(struct olsrv2_dijkstra_node *, const struct netaddr *originator);

EXPORT uint16_t olsrv2_routing_get_ansn(void);
EXPORT void olsrv2_routing_force_ansn_increment(uint16_t increment);

EXPORT void olsrv2_routing_set_domain_parameter(struct nhdp_domain *domain, struct olsrv2_routing_domain *parameter);

EXPORT void olsrv2_routing_domain_changed(struct nhdp_domain *domain, bool autoupdate_ansn);
EXPORT void olsrv2_routing_force_update(bool skip_wait);
EXPORT void olsrv2_routing_trigger_update(void);

EXPORT void olsrv2_routing_freeze_routes(bool freeze);

EXPORT const struct olsrv2_routing_domain *olsrv2_routing_get_parameters(struct nhdp_domain *);

EXPORT struct avl_tree *olsrv2_routing_get_tree(struct nhdp_domain *domain);
EXPORT struct list_entity *olsrv2_routing_get_filter_list(void);

/**
 * Add a routing filter to the dijkstra processing list
 * @param filter pointer to routing filter
 */
static INLINE void
olsrv2_routing_filter_add(struct olsrv2_routing_filter *filter) {
  list_add_tail(olsrv2_routing_get_filter_list(), &filter->_node);
}

/**
 * Remove a routing filter from the dijkstra processing list
 * @param filter pointer to routing filter
 */
static INLINE void
olsrv2_routing_filter_remove(struct olsrv2_routing_filter *filter) {
  list_remove(&filter->_node);
}

#endif /* OLSRV2_ROUTING_SET_H_ */
