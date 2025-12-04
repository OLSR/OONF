
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

#ifndef OLSRV2_TC_H_
#define OLSRV2_TC_H_

#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>

#include <oonf/base/oonf_timer.h>

#include <oonf/nhdp/nhdp/nhdp.h>
#include <oonf/nhdp/nhdp/nhdp_domain.h>

#include <oonf/olsrv2/olsrv2/olsrv2.h>
#include <oonf/olsrv2/olsrv2/olsrv2_routing.h>

/**
 * target types of olsrv2 edges
 */
enum olsrv2_target_type
{
  /*! target is another olsrv2 node */
  OLSRV2_NODE_TARGET,

  /*! target is just an address */
  OLSRV2_ADDRESS_TARGET,

  /*! target is an attached network */
  OLSRV2_NETWORK_TARGET,
};

/*! memory class for olsrv2 nodes */
#define OLSRV2_CLASS_TC_NODE "olsrv2 tc node"

/*! memory class for olsrv2 edges */
#define OLSRV2_CLASS_TC_EDGE "olsrv2 tc edge"

/*! memory class for olsrv2 attached networks */
#define OLSRV2_CLASS_ATTACHED "olsrv2 tc attached network"

/*! memory class for olsrv2 endpoints */
#define OLSRV2_CLASS_ENDPOINT "olsrv2 tc attached network endpoint"

struct olsrv2_tc_edge;

/**
 * represents a target that can be reached through a tc node.
 *
 * Might be another tc node, a neighbor address or an attached
 * network.
 */
struct olsrv2_tc_target {
  /*! address or prefix of this node of the topology graph */
  struct os_route_key prefix;

  /*! type of target */
  enum olsrv2_target_type type;

  /*! internal data for dijkstra run */
  struct olsrv2_dijkstra_node _dijkstra;
};

/**
 * represents a tc node which might be connected to other
 * nodes and endpoints.
 */
struct olsrv2_tc_node {
  /*! substructure to define target for Dijkstra Algorithm */
  struct olsrv2_tc_target target;

  /*! answer set number */
  uint16_t ansn;

  /*! reported interval time */
  uint64_t interval_time;

  /*! true if node has to be kept alive because of HELLOs */
  bool direct_neighbor;

  /*! node has announced it can do source specific routing */
  bool source_specific;

  /*! true if node has source specific attached networks per domain */
  bool ss_attached_networks[NHDP_MAXIMUM_DOMAINS];

  /*! time until this node has to be removed */
  struct oonf_timer_instance _validity_time;

  /*! tree of olsrv2_tc_edges */
  struct avl_tree _edges;

  /*! tree of olsrv2_tc_attached_networks */
  struct avl_tree _attached_networks;

  /*! node for tree of tc_nodes */
  struct avl_node _originator_node;
};

/**
 * represents an edge between two tc nodes
 */
struct olsrv2_tc_edge {
  /*! pointer to source of edge */
  struct olsrv2_tc_node *src;

  /*! pointer to destination of edge */
  struct olsrv2_tc_node *dst;

  /*! pointer to inverse edge */
  struct olsrv2_tc_edge *inverse;

  /*! link cost of edge */
  uint32_t cost[NHDP_MAXIMUM_DOMAINS];

  /*! answer set number which set this edge */
  uint16_t ansn;

  /**
   * true if this link is only virtual
   * (it only exists because the inverse edge was received).
   */
  bool virtual;

  /*! node for tree of source node */
  struct avl_node _node;
};

/**
 * represents a connection from a tc node to
 * an endpoint, either a neighbor address or an attached network
 */
struct olsrv2_tc_attachment {
  /*! pointer to source of edge */
  struct olsrv2_tc_node *src;

  /*! pointer to destination of edge */
  struct olsrv2_tc_endpoint *dst;

  /*! link cost of edge */
  uint32_t cost[NHDP_MAXIMUM_DOMAINS];

  /*! distance to attached network */
  uint8_t distance[NHDP_MAXIMUM_DOMAINS];

  /*! answer set number which set this edge */
  uint16_t ansn;

  /*! node for tree of source node */
  struct avl_node _src_node;

  /*! node for tree of endpoint nodes */
  struct avl_node _endpoint_node;
};

/**
 * Represents an endpoint of the Dijkstra graph, which
 * does not spawn new edges of the graph.
 *
 * Might be a neighbor address or an attached network
 */
struct olsrv2_tc_endpoint {
  /*! substructure to define target for Dijkstra Algorithm */
  struct olsrv2_tc_target target;

  /*! tree of attached networks */
  struct avl_tree _attached_networks;

  /*! node for global tree of endpoints */
  struct avl_node _node;
};

void olsrv2_tc_init(void);
void olsrv2_tc_cleanup(void);

EXPORT struct olsrv2_tc_node *olsrv2_tc_node_add(struct netaddr *, uint64_t vtime, uint16_t ansn);
EXPORT void olsrv2_tc_node_remove(struct olsrv2_tc_node *);

EXPORT struct olsrv2_tc_edge *olsrv2_tc_edge_add(struct olsrv2_tc_node *, struct netaddr *);
EXPORT bool olsrv2_tc_edge_remove(struct olsrv2_tc_edge *);

EXPORT struct olsrv2_tc_attachment *olsrv2_tc_endpoint_add(struct olsrv2_tc_node *, struct os_route_key *, bool mesh);
EXPORT void olsrv2_tc_endpoint_remove(struct olsrv2_tc_attachment *);

void olsrv2_tc_trigger_change(struct olsrv2_tc_node *);

EXPORT struct avl_tree *olsrv2_tc_get_tree(void);
EXPORT struct avl_tree *olsrv2_tc_get_endpoint_tree(void);

/**
 * @param originator originator address of a tc node
 * @return pointer to tc node, NULL if not found
 */
static INLINE struct olsrv2_tc_node *
olsrv2_tc_node_get(struct netaddr *originator) {
  struct olsrv2_tc_node *node;

  return avl_find_element(olsrv2_tc_get_tree(), originator, node, _originator_node);
}

/**
 * @param node pointer to olsrv2 node
 * @return true if node is virtual
 */
static INLINE bool
olsrv2_tc_is_node_virtual(struct olsrv2_tc_node *node) {
  return !oonf_timer_is_active(&node->_validity_time);
}

/**
 * @param prefix network prefix of tc endpoint, might be source specific
 * @return pointer to tc endpoint, NULL if not found
 */
static INLINE struct olsrv2_tc_endpoint *
olsrv2_tc_endpoint_get(struct os_route_key *prefix) {
  struct olsrv2_tc_endpoint *end;

  return avl_find_element(olsrv2_tc_get_endpoint_tree(), prefix, end, _node);
}

static INLINE uint32_t
olsrv2_tc_attachment_get_metric(struct nhdp_domain *domain, struct olsrv2_tc_attachment *attached) {
  return attached->cost[domain->index];
}

static INLINE uint8_t
olsrv2_tc_attachment_get_distance(struct nhdp_domain *domain, struct olsrv2_tc_attachment *attached) {
  return attached->distance[domain->index];
}

static INLINE uint32_t
olsrv2_tc_edge_get_metric(struct nhdp_domain *domain, struct olsrv2_tc_edge *edge) {
  return edge->cost[domain->index];
}

#endif /* OLSRV2_TC_H_ */
