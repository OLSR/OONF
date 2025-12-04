
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

#ifndef NHDP_DOMAIN_H_
#define NHDP_DOMAIN_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_rfc5444.h>

#include <oonf/nhdp/nhdp/nhdp_db.h>
#include <oonf/nhdp/nhdp/nhdp_interfaces.h>

/*! memory class for nhdp domain */
#define NHDP_CLASS_DOMAIN "nhdp_domain"

struct nhdp_domain;

/**
 * NHDP domain constants
 */
enum
{
  /*! maximum length of metric name */
  NHDP_DOMAIN_METRIC_MAXLEN = 16,

  /*! maximum length of mpr name */
  NHDP_DOMAIN_MPR_MAXLEN = 16,
};

/**
 * Result of a metric calculation based on a layer2 neighbor
 */
enum nhdp_metric_result {
  /*! metric has been calculated normally */
  NHDP_METRIC_OKAY,

  /*! metric has been calculated, but some data has been missing */
  NHDP_METRIC_PARTIAL_DATA,

  /*! metric could not be calculated */
  NHDP_METRIC_NOT_AVAILABLE,
};

/**
 * Buffer for string representation of a linkmetric value
 */
struct nhdp_metric_str {
  /*! buffer for maximum sized text link metric */
  char buf[128];
};

/**
 *  Metric handler for a NHDP domain.
 */
struct nhdp_domain_metric {
  /*! name of linkmetric */
  const char *name;

  /*! minimum metric value*/
  uint32_t metric_minimum;

  /*! maximum metric value */
  uint32_t metric_maximum;

  /*! default incoming link metric for "no default handling" metrics */
  uint32_t incoming_link_start;

  /*! default outgoing link metric for "no default handling" metrics */
  uint32_t outgoing_link_start;

  /*! default incoming 2-hop link metric for "no default handling" metrics */
  uint32_t incoming_2hop_start;

  /*! default outgoing 2-hop link metric for "no default handling" metrics */
  uint32_t outgoing_2hop_start;

  /*! true if metrics should not be handled by nhdp reader/writer */
  bool no_default_handling;

  /*! array of layer2 interface values this metric requires */
  const enum oonf_layer2_network_index *required_l2net_data;

  /*! number of required layer2 interface values */
  size_t required_l2net_count;

  /*! array of layer2 neighbor values this metric requires */
  const enum oonf_layer2_neighbor_index *required_l2neigh_data;

  /*! number of required layer2 neighbor values */
  size_t required_l2neigh_count;

  /**
   * callback to convert link metric into string representation
   * @param buf buffer to put string into
   * @param cost link metric
   * @return pointer to buffer
   */
  const char *(*link_to_string)(struct nhdp_metric_str *buf, uint32_t cost);

  /**
   * callback to convert path metric into string representation
   * @param buf buffer to put string into
   * @param cost path metric
   * @param hopcount hopcount of path
   * @return pointer to buffer
   */
  const char *(*path_to_string)(struct nhdp_metric_str *buf, uint32_t cost, uint8_t hopcount);

  /*! conversion of internal metric data into string */
  /**
   * callback to convert internal metric state into string
   * @param buf buffer to put internal state into
   * @param lnk nhdp link
   * @return pointer to buffer
   */
  const char *(*internal_link_to_string)(struct nhdp_metric_str *buf, struct nhdp_link *lnk);

  /**
   * callback to enable metric
   */
  void (*enable)(void);

  /**
   * callback to disable metric
   */
  void (*disable)(void);

  /**
   * Calculate the metric cost of a link defined by a layer2 neighbor
   * @param domain nhdp domain the metric calculation should be based upon
   * @param metric pointer to target buffer for metric result
   * @param neigh layer2 neighbor
   * @return status of metric calculation
   */
  enum nhdp_metric_result (*cb_get_metric)(struct nhdp_domain *domain, uint32_t *metric, struct oonf_layer2_neigh *neigh);

  /*! reference count */
  int _refcount;

  /*! node for tree of metrics */
  struct avl_node _node;
};

/**
 * MPR handler for a NHDP domain
 */
struct nhdp_domain_mpr {
  /*! name of handler */
  const char *name;

  /**
   * callback to calculate routing MPR set
   * @param domain NHDP domain to update MPR set
   */
  void (*update_routing_mpr)(struct nhdp_domain *domain);

  /**
   * callback to calculate flooding MPR set
   * @param domain NHDP domain used to update flooding MPR set
   */
  void (*update_flooding_mpr)(struct nhdp_domain *domain);

  /**
   * callback to enable mpr
   */
  void (*enable)(void);

  /**
   * callback to disable mpr
   */
  void (*disable)(void);

  /*! reference count */
  int _refcount;

  /*! node for tree of MPR algorithms */
  struct avl_node _node;
};

/**
 * NHDP domain
 *
 * A domain is a topology on the mesh, including its own
 * metric and routing MPR set. Both is transmitted over a
 * specified TLV extension value on MPR and LQ TLVs.
 */
struct nhdp_domain {
  /*! name of metric */
  char metric_name[NHDP_DOMAIN_METRIC_MAXLEN];

  /*! name of MPR algorithm */
  char mpr_name[NHDP_DOMAIN_MPR_MAXLEN];

  /*! pointer to metric definition */
  struct nhdp_domain_metric *metric;

  /*! pointer to mpr definition */
  struct nhdp_domain_mpr *mpr;

  /*! flooding willingness */
  uint8_t local_willingness;

  /*! metric tlv extension */
  uint8_t ext;

  /*! index in the domain array */
  int index;

  /*! true if MPR should be recalculated */
  bool _mpr_outdated;

  /*! temporary storage for willingness processing */
  uint8_t _tmp_willingness;

  /*! storage for the up to four additional link metrics */
  struct rfc5444_writer_tlvtype _metric_addrtlvs[4];

  /*! list of nhdp domains */
  struct list_entity _node;
};

/**
 * listener for NHDP domain updates
 */
struct nhdp_domain_listener {
  /**
   * Callback to inform about a NHDP neighbor MPR update
   * @param domain NHDP domain of which the MPR set changed
   */
  void (*mpr_update)(struct nhdp_domain *domain);

  /**
   * Callback to inform about a NHDP neighbor metric update
   * @param domain NHDP domain of which the metric changed
   */
  void (*metric_update)(struct nhdp_domain *domain);

  /*! hook into global domain updater list */
  struct list_entity _node;
};

/**
 * Postprocessor for NHDP metric changes
 */
struct nhdp_domain_metric_postprocessor {
  /**
   * Callback getting informed about a incoming metric change.
   * @param domain domain the metric changed happened
   * @param lnk nhdp link the metric change happened
   * @param new_metric new metric value
   * @return processed new metric value
   */
  uint32_t (*process_in_metric)(struct nhdp_domain *domain, struct nhdp_link *lnk, uint32_t new_metric);

  /*! hook into global domain metric postprocessor list */
  struct list_entity _node;
};

void nhdp_domain_init(struct oonf_rfc5444_protocol *);
void nhdp_domain_cleanup(void);

EXPORT size_t nhdp_domain_get_count(void);
EXPORT struct nhdp_domain *nhdp_domain_add(uint8_t ext);
EXPORT struct nhdp_domain *nhdp_domain_configure(
  uint8_t ext, const char *metric_name, const char *mpr_name, uint8_t willingness);

EXPORT int nhdp_domain_metric_add(struct nhdp_domain_metric *);
EXPORT void nhdp_domain_metric_remove(struct nhdp_domain_metric *);

EXPORT int nhdp_domain_mpr_add(struct nhdp_domain_mpr *);
EXPORT void nhdp_domain_mpr_remove(struct nhdp_domain_mpr *);

EXPORT void nhdp_domain_listener_add(struct nhdp_domain_listener *);
EXPORT void nhdp_domain_listener_remove(struct nhdp_domain_listener *);

EXPORT void nhdp_domain_metric_postprocessor_add(struct nhdp_domain_metric_postprocessor *);
EXPORT void nhdp_domain_metric_postprocessor_remove(struct nhdp_domain_metric_postprocessor *);
EXPORT struct nhdp_domain *nhdp_domain_get_by_ext(uint8_t);

EXPORT void nhdp_domain_init_link(struct nhdp_link *);
EXPORT void nhdp_domain_init_l2hop(struct nhdp_l2hop *);
EXPORT void nhdp_domain_init_neighbor(struct nhdp_neighbor *);

EXPORT void nhdp_domain_process_metric_linktlv(struct nhdp_domain *, struct nhdp_link *lnk, const uint8_t *value);
EXPORT void nhdp_domain_process_metric_2hoptlv(struct nhdp_domain *d, struct nhdp_l2hop *l2hop, const uint8_t *value);

EXPORT size_t nhdp_domain_process_mprtypes_tlv(
  uint8_t *mprtypes, size_t mprtypes_size, struct rfc5444_reader_tlvblock_entry *tlv);
EXPORT void nhdp_domain_process_mpr_tlv(
  uint8_t *mprtypes, size_t mprtypes_size, struct nhdp_link *, struct rfc5444_reader_tlvblock_entry *tlv);
EXPORT void nhdp_domain_process_willingness_tlv(
  uint8_t *mpr_types, size_t mprtypes_size, struct rfc5444_reader_tlvblock_entry *tlv);
EXPORT void nhdp_domain_store_willingness(struct nhdp_link *);
EXPORT size_t nhdp_domain_encode_mprtypes_tlvvalue(uint8_t *mprtypes, size_t mprtypes_size);
EXPORT size_t nhdp_domain_encode_mpr_tlvvalue(uint8_t *tlvvalue, size_t tlvsize, struct nhdp_link *);
EXPORT size_t nhdp_domain_encode_willingness_tlvvalue(uint8_t *tlvvalue, size_t tlvsize);

EXPORT bool nhdp_domain_set_incoming_metric(
  struct nhdp_domain_metric *metric, struct nhdp_link *lnk, uint32_t metric_in);
EXPORT bool nhdp_domain_recalculate_metrics(struct nhdp_domain *domain, struct nhdp_neighbor *neigh, bool force);
EXPORT enum nhdp_metric_result nhdp_domain_get_metric(struct nhdp_domain *domain, uint32_t *metric, struct oonf_layer2_neigh *neigh);

EXPORT bool nhdp_domain_node_is_mpr(void);
EXPORT void nhdp_domain_delayed_mpr_recalculation(struct nhdp_domain *domain, struct nhdp_neighbor *neigh);
EXPORT void nhdp_domain_recalculate_mpr(void);

EXPORT struct list_entity *nhdp_domain_get_list(void);
EXPORT struct list_entity *nhdp_domain_get_listener_list(void);
EXPORT const struct nhdp_domain *nhdp_domain_get_flooding_domain(void);
EXPORT void nhdp_domain_set_flooding_mpr(const char *mpr_name, uint8_t willingness);
EXPORT const struct nhdp_domain *nhdp_domain_get_flooding_domain(void);

/**
 * @param domain NHDP domain
 * @param lnk NHDP link
 * @return domain data of specified link
 */
static INLINE struct nhdp_link_domaindata *
nhdp_domain_get_linkdata(const struct nhdp_domain *domain, struct nhdp_link *lnk) {
  return &lnk->_domaindata[domain->index];
}

/**
 * @param domain NHDP domain
 * @param neigh NHDP neighbor
 * @return domain data of specified neighbor
 */
static INLINE struct nhdp_neighbor_domaindata *
nhdp_domain_get_neighbordata(const struct nhdp_domain *domain, struct nhdp_neighbor *neigh) {
  return &neigh->_domaindata[domain->index];
}

/**
 * @param domain NHDP domain
 * @param l2hop NHDP twohop neighbor
 * @return domain data of specified twohop neighbor
 */
static INLINE struct nhdp_l2hop_domaindata *
nhdp_domain_get_l2hopdata(const struct nhdp_domain *domain, struct nhdp_l2hop *l2hop) {
  return &l2hop->_domaindata[domain->index];
}

/**
 * @param buf pointer to metric output buffer
 * @param domain pointer to metric domain
 * @param metric raw metric value
 * @return pointer to string representation of metric
 */
static INLINE const char *
nhdp_domain_get_link_metric_value(struct nhdp_metric_str *buf, const struct nhdp_domain *domain, uint32_t metric) {
  return domain->metric->link_to_string(buf, metric);
}

/**
 * @param buf pointer to metric output buffer
 * @param domain pointer to metric domain
 * @param metric raw path metric value
 * @param hopcount path hopcount
 * @return pointer to string representation of metric
 */
static INLINE const char *
nhdp_domain_get_path_metric_value(
  struct nhdp_metric_str *buf, const struct nhdp_domain *domain, uint32_t metric, uint8_t hopcount) {
  return domain->metric->path_to_string(buf, metric, hopcount);
}

/**
 * @param buf pointer to metric output buffer
 * @param metric pointer to metric
 * @param lnk nhdp link
 * @return pointer to string internal representation of metric
 */
static INLINE const char *
nhdp_domain_get_internal_link_metric_value(
  struct nhdp_metric_str *buf, const struct nhdp_domain_metric *metric, struct nhdp_link *lnk) {
  return metric->internal_link_to_string(buf, lnk);
}

#endif /* NHDP_DOMAIN_H_ */
