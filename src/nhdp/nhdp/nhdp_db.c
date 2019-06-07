
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

#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>

#include <oonf/libcore/oonf_logging.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/nhdp/nhdp/nhdp_db.h>
#include <oonf/nhdp/nhdp/nhdp_domain.h>
#include <oonf/nhdp/nhdp/nhdp_hysteresis.h>
#include <oonf/nhdp/nhdp/nhdp_interfaces.h>
#include <oonf/nhdp/nhdp/nhdp_internal.h>

/* Prototypes of local functions */
static void _link_status_now_symmetric(struct nhdp_link *lnk);
static void _link_status_not_symmetric_anymore(struct nhdp_link *lnk);
int _nhdp_db_link_calculate_status(struct nhdp_link *lnk);

static void _cb_link_vtime(struct oonf_timer_instance *);
static void _cb_link_heard(struct oonf_timer_instance *);
static void _cb_link_symtime(struct oonf_timer_instance *);
static void _cb_l2hop_vtime(struct oonf_timer_instance *);
static void _cb_naddr_vtime(struct oonf_timer_instance *);

/* Link status names */
static const char *_LINK_PENDING = "pending";
static const char *_LINK_HEARD = "heard";
static const char *_LINK_SYMMETRIC = "symmetric";
static const char *_LINK_LOST = "lost";

/* memory and timer classes necessary for NHDP */
static struct oonf_class _neigh_info = {
  .name = NHDP_CLASS_NEIGHBOR,
  .size = sizeof(struct nhdp_neighbor),
};

static struct oonf_class _link_info = {
  .name = NHDP_CLASS_LINK,
  .size = sizeof(struct nhdp_link),
};

static struct oonf_class _laddr_info = {
  .name = NHDP_CLASS_LINK_ADDRESS,
  .size = sizeof(struct nhdp_laddr),
};

static struct oonf_class _l2hop_info = {
  .name = NHDP_CLASS_LINK_2HOP,
  .size = sizeof(struct nhdp_l2hop),
};

static struct oonf_class _naddr_info = {
  .name = NHDP_CLASS_NEIGHBOR_ADDRESS,
  .size = sizeof(struct nhdp_naddr),
};

static struct oonf_timer_class _link_vtime_info = {
  .name = "NHDP link vtime",
  .callback = _cb_link_vtime,
};

static struct oonf_timer_class _link_heard_info = {
  .name = "NHDP link heard-time",
  .callback = _cb_link_heard,
};

static struct oonf_timer_class _link_symtime_info = {
  .name = "NHDP link symtime",
  .callback = _cb_link_symtime,
};

static struct oonf_timer_class _naddr_vtime_info = {
  .name = "NHDP neighbor address vtime",
  .callback = _cb_naddr_vtime,
};

static struct oonf_timer_class _l2hop_vtime_info = {
  .name = "NHDP 2hop vtime",
  .callback = _cb_l2hop_vtime,
};

/* global tree of neighbor addresses */
static struct avl_tree _naddr_tree;

/* list of neighbors */
static struct list_entity _neigh_list;

/* tree of neighbors with originator addresses */
static struct avl_tree _neigh_originator_tree;

/* list of links (to neighbors) */
static struct list_entity _link_list;

/* id that will be increased every times the symmetric neighbor set changes */
static uint32_t _neighbor_set_id = 0;

/**
 * Initialize NHDP databases
 */
void
nhdp_db_init(void) {
  avl_init(&_naddr_tree, avl_comp_netaddr, false);
  list_init_head(&_neigh_list);
  avl_init(&_neigh_originator_tree, avl_comp_netaddr, false);
  list_init_head(&_link_list);

  oonf_class_add(&_neigh_info);
  oonf_class_add(&_naddr_info);
  oonf_class_add(&_link_info);
  oonf_class_add(&_laddr_info);
  oonf_class_add(&_l2hop_info);

  oonf_timer_add(&_naddr_vtime_info);
  oonf_timer_add(&_link_vtime_info);
  oonf_timer_add(&_link_heard_info);
  oonf_timer_add(&_link_symtime_info);
  oonf_timer_add(&_l2hop_vtime_info);
}

/**
 * Cleanup NHDP databases
 */
void
nhdp_db_cleanup(void) {
  struct nhdp_neighbor *neigh, *n_it;

  /* remove all neighbors */
  list_for_each_element_safe(&_neigh_list, neigh, _global_node, n_it) {
    nhdp_db_neighbor_remove(neigh);
  }

  /* cleanup all timers */
  oonf_timer_remove(&_l2hop_vtime_info);
  oonf_timer_remove(&_link_symtime_info);
  oonf_timer_remove(&_link_heard_info);
  oonf_timer_remove(&_link_vtime_info);
  oonf_timer_remove(&_naddr_vtime_info);

  /* cleanup all memory cookies */
  oonf_class_remove(&_l2hop_info);
  oonf_class_remove(&_laddr_info);
  oonf_class_remove(&_link_info);
  oonf_class_remove(&_naddr_info);
  oonf_class_remove(&_neigh_info);
}

/**
 * @return new NHDP neighbor without links and addresses,
 *  NULL if out of memory
 */
struct nhdp_neighbor *
nhdp_db_neighbor_add(void) {
  struct nhdp_neighbor *neigh;

  neigh = oonf_class_malloc(&_neigh_info);
  if (neigh == NULL) {
    return NULL;
  }

  OONF_DEBUG(LOG_NHDP, "New Neighbor: 0x%0zx", (size_t)neigh);

  /* initialize trees and lists */
  avl_init(&neigh->_neigh_addresses, avl_comp_netaddr, false);
  avl_init(&neigh->_link_addresses, avl_comp_netaddr, true);
  list_init_head(&neigh->_links);

  /* hook into global neighbor list */
  list_add_tail(&_neigh_list, &neigh->_global_node);

  /* initialize originator node */
  neigh->_originator_node.key = &neigh->originator;

  /* initialize domain data */
  nhdp_domain_init_neighbor(neigh);

  /* trigger event */
  oonf_class_event(&_neigh_info, neigh, OONF_OBJECT_ADDED);
  return neigh;
}

/**
 * Remove NHDP neighbor including links and addresses from db
 * @param neigh nhdp neighbor to be removed
 */
void
nhdp_db_neighbor_remove(struct nhdp_neighbor *neigh) {
  struct nhdp_neighbor_domaindata *neighdata;
  struct nhdp_naddr *naddr, *na_it;
  struct nhdp_link *lnk, *l_it;
  struct nhdp_domain *domain;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif
  bool was_mpr;

  OONF_DEBUG(LOG_NHDP, "Remove Neighbor: 0x%0zx (%s)", (size_t)neigh, netaddr_to_string(&nbuf, &neigh->originator));

  /* trigger event */
  oonf_class_event(&_neigh_info, neigh, OONF_OBJECT_REMOVED);

  /* disconnect from other IP version */
  nhdp_db_neigbor_disconnect_dualstack(neigh);

  /* remove all links */
  list_for_each_element_safe(&neigh->_links, lnk, _neigh_node, l_it) {
    nhdp_db_link_remove(lnk);
  }

  /* remove all neighbor addresses */
  avl_for_each_element_safe(&neigh->_neigh_addresses, naddr, _neigh_node, na_it) {
    nhdp_db_neighbor_addr_remove(naddr);
  }

  /* remove from originator tree if necessary */
  if (netaddr_get_address_family(&neigh->originator) != AF_UNSPEC) {
    avl_remove(&_neigh_originator_tree, &neigh->_originator_node);
  }

  /* check if neighbor was a MPR */
  was_mpr = false;
  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    neighdata = nhdp_domain_get_neighbordata(domain, neigh);
    if (neighdata->neigh_is_mpr) {
      was_mpr = true;
      break;
    }
  }

  if (was_mpr) {
    /* all domains might have changed */
    nhdp_domain_delayed_mpr_recalculation(NULL, neigh);
  }

  /* remove from global list and free memory */
  list_remove(&neigh->_global_node);
  oonf_class_free(&_neigh_info, neigh);
}

/**
 * Set a NHDP neighbor to unsymmetric
 * @param neigh nhdp neighbor
 */
void
nhdp_db_neighbor_set_unsymmetric(struct nhdp_neighbor *neigh) {
  struct nhdp_link *lnk;

  list_for_each_element(&neigh->_links, lnk, _neigh_node) {
    nhdp_db_link_set_unsymmetric(lnk);
  }

  /* trigger event */
  oonf_class_event(&_neigh_info, neigh, OONF_OBJECT_CHANGED);
}

/**
 * Join the links and addresses of two NHDP neighbors
 * @param dst target neighbor which gets all the links and addresses
 * @param src source neighbor which will be removed afterwards
 */
void
nhdp_db_neighbor_join(struct nhdp_neighbor *dst, struct nhdp_neighbor *src) {
  struct nhdp_naddr *naddr, *na_it;
  struct nhdp_link *lnk, *l_it;
  struct nhdp_laddr *laddr, *la_it;

  if (dst == src) {
    return;
  }

  /* fix symmetric link count */
  dst->symmetric += src->symmetric;

  /* move links */
  list_for_each_element_safe(&src->_links, lnk, _neigh_node, l_it) {
    /* more addresses to new neighbor */
    avl_for_each_element_safe(&lnk->_addresses, laddr, _neigh_node, la_it) {
      avl_remove(&src->_link_addresses, &laddr->_neigh_node);
      avl_insert(&dst->_link_addresses, &laddr->_neigh_node);
    }

    /* move interface based originator */
    if (netaddr_get_address_family(&src->originator) != AF_UNSPEC) {
      avl_remove(&lnk->local_if->_link_originators, &lnk->_originator_node);
    }
    lnk->_originator_node.key = &dst->originator;
    if (netaddr_get_address_family(&dst->originator) != AF_UNSPEC) {
      avl_insert(&lnk->local_if->_link_originators, &lnk->_originator_node);
    }

    /* move link to new neighbor */
    list_remove(&lnk->_neigh_node);
    list_add_tail(&dst->_links, &lnk->_neigh_node);
    lnk->neigh = dst;
  }

  /* move neighbor addresses to target */
  avl_for_each_element_safe(&src->_neigh_addresses, naddr, _neigh_node, na_it) {
    /* move address to new neighbor */
    avl_remove(&src->_neigh_addresses, &naddr->_neigh_node);
    avl_insert(&dst->_neigh_addresses, &naddr->_neigh_node);
    naddr->neigh = dst;
  }

  nhdp_db_neighbor_remove(src);
}

/**
 * Adds an address to a nhdp neighbor
 * @param neigh nhdp neighbor
 * @param addr network address
 * @return pointer to neighbor address, NULL if out of memory
 */
struct nhdp_naddr *
nhdp_db_neighbor_addr_add(struct nhdp_neighbor *neigh, const struct netaddr *addr) {
  struct nhdp_naddr *naddr;

  naddr = oonf_class_malloc(&_naddr_info);
  if (naddr == NULL) {
    return NULL;
  }

  /* initialize key */
  memcpy(&naddr->neigh_addr, addr, sizeof(naddr->neigh_addr));
  naddr->_neigh_node.key = &naddr->neigh_addr;
  naddr->_global_node.key = &naddr->neigh_addr;

  /* initialize backward link */
  naddr->neigh = neigh;

  /* initialize timer for lost addresses */
  naddr->_lost_vtime.class = &_naddr_vtime_info;

  /* add to trees */
  avl_insert(&_naddr_tree, &naddr->_global_node);
  avl_insert(&neigh->_neigh_addresses, &naddr->_neigh_node);

  /* trigger event */
  oonf_class_event(&_naddr_info, naddr, OONF_OBJECT_ADDED);

  return naddr;
}

/**
 * Removes a nhdp neighbor address from its neighbor
 * @param naddr neighbor address
 */
void
nhdp_db_neighbor_addr_remove(struct nhdp_naddr *naddr) {
  /* trigger event */
  oonf_class_event(&_naddr_info, naddr, OONF_OBJECT_REMOVED);

  /* remove from trees */
  avl_remove(&_naddr_tree, &naddr->_global_node);
  avl_remove(&naddr->neigh->_neigh_addresses, &naddr->_neigh_node);

  /* stop timer */
  oonf_timer_stop(&naddr->_lost_vtime);

  /* free memory */
  oonf_class_free(&_naddr_info, naddr);
}

/**
 * Moves a nhdp neighbor address to a different neighbor
 * @param neigh nhdp neighbor
 * @param naddr nhdp neighbor address
 */
void
nhdp_db_neighbor_addr_move(struct nhdp_neighbor *neigh, struct nhdp_naddr *naddr) {
  /* remove from old neighbor */
  avl_remove(&naddr->neigh->_neigh_addresses, &naddr->_neigh_node);

  /* add to new neighbor */
  avl_insert(&neigh->_neigh_addresses, &naddr->_neigh_node);

  /* set new backlink */
  naddr->neigh = neigh;
}

/**
 * Sets a new originator address for an NHDP neighbor
 * @param neigh nhdp neighbor
 * @param originator originator address, might be type AF_UNSPEC
 */
void
nhdp_db_neighbor_set_originator(struct nhdp_neighbor *neigh, const struct netaddr *originator) {
  struct nhdp_neighbor *neigh2;
  struct nhdp_link *lnk;

  if (memcmp(&neigh->originator, originator, sizeof(*originator)) == 0) {
    /* same originator, nothing to do */
    return;
  }

  if (netaddr_get_address_family(&neigh->originator) != AF_UNSPEC) {
    /* different originator, remove from tree */
    avl_remove(&_neigh_originator_tree, &neigh->_originator_node);

    list_for_each_element(&neigh->_links, lnk, _neigh_node) {
      /* remove links from interface specific tree */
      avl_remove(&lnk->local_if->_link_originators, &lnk->_originator_node);
    }
  }

  neigh2 = nhdp_db_neighbor_get_by_originator(originator);
  if (neigh2) {
    /* different neighbor has this originator, invalidate it */
    avl_remove(&_neigh_originator_tree, &neigh2->_originator_node);

    list_for_each_element(&neigh2->_links, lnk, _neigh_node) {
      /* remove links from interface specific tree */
      avl_remove(&lnk->local_if->_link_originators, &lnk->_originator_node);
    }

    netaddr_invalidate(&neigh2->originator);
  }

  /* copy originator address into neighbor */
  memcpy(&neigh->originator, originator, sizeof(*originator));

  if (netaddr_get_address_family(originator) != AF_UNSPEC) {
    /* add to tree if new originator is valid */
    avl_insert(&_neigh_originator_tree, &neigh->_originator_node);

    list_for_each_element(&neigh->_links, lnk, _neigh_node) {
      /* remove links from interface specific tree */
      avl_insert(&lnk->local_if->_link_originators, &lnk->_originator_node);
    }
  }

  /* inform everyone */
  oonf_class_event(&_neigh_info, neigh, OONF_OBJECT_CHANGED);

  /* overwrite "old originator" */
  memcpy(&neigh->_old_originator, originator, sizeof(*originator));
}

/**
 * Connect two neighbors as representations of the same node,
 * @param n_ipv4 ipv4 neighbor
 * @param n_ipv6 ipv6 neighbor
 */
void
nhdp_db_neighbor_connect_dualstack(struct nhdp_neighbor *n_ipv4, struct nhdp_neighbor *n_ipv6) {
  if (n_ipv4->dualstack_partner != n_ipv6) {
    nhdp_db_neigbor_disconnect_dualstack(n_ipv4);
    n_ipv4->dualstack_partner = n_ipv6;
  }

  if (n_ipv6->dualstack_partner != n_ipv4) {
    nhdp_db_neigbor_disconnect_dualstack(n_ipv6);
    n_ipv6->dualstack_partner = n_ipv4;
  }
}

/**
 * Disconnects the pointers of a dualstack pair of neighbors
 * @param neigh one of the connected neighbors
 */
void
nhdp_db_neigbor_disconnect_dualstack(struct nhdp_neighbor *neigh) {
  if (neigh->dualstack_partner) {
    neigh->dualstack_partner->dualstack_partner = NULL;
    neigh->dualstack_partner = NULL;
  }
}

/**
 * @return set id of symmetric neighbors, will be increased for
 *   every change.
 */
uint32_t
nhdp_db_neighbor_get_set_id(void) {
  return _neighbor_set_id;
}

/**
 * Insert a new link into a nhdp neighbors database
 * @param neigh neighbor which will get the new link
 * @param local_if local interface through which the link was heard
 * @return new nhdp link, NULL if out of memory
 */
struct nhdp_link *
nhdp_db_link_add(struct nhdp_neighbor *neigh, struct nhdp_interface *local_if) {
  struct nhdp_link *lnk;

  lnk = oonf_class_malloc(&_link_info);
  if (lnk == NULL) {
    return NULL;
  }

  /* hook into interface */
  nhdp_interface_add_link(local_if, lnk);

  /* hook into neighbor */
  list_add_tail(&neigh->_links, &lnk->_neigh_node);
  lnk->neigh = neigh;

  /* hook into global list */
  list_add_tail(&_link_list, &lnk->_global_node);

  /* init local trees */
  avl_init(&lnk->_addresses, avl_comp_netaddr, false);
  avl_init(&lnk->_2hop, avl_comp_netaddr, false);

  /* init timers */
  lnk->sym_time.class = &_link_symtime_info;
  lnk->heard_time.class = &_link_heard_info;
  lnk->vtime.class = &_link_vtime_info;

  /* add to originator tree if set */
  lnk->_originator_node.key = &neigh->originator;
  if (netaddr_get_address_family(&neigh->originator) != AF_UNSPEC) {
    avl_insert(&local_if->_link_originators, &lnk->_originator_node);
  }

  lnk->last_status_change = oonf_clock_getNow();

  /* initialize link domain data */
  nhdp_domain_init_link(lnk);

  /* trigger event */
  oonf_class_event(&_link_info, lnk, OONF_OBJECT_ADDED);

  return lnk;
}

/**
 * Remove a nhdp link from database
 * @param lnk nhdp link to be removed
 */
void
nhdp_db_link_set_unsymmetric(struct nhdp_link *lnk) {
  struct nhdp_l2hop *twohop, *th_it;

  if (lnk->status == NHDP_LINK_SYMMETRIC) {
    _link_status_not_symmetric_anymore(lnk);
  }

  /* stop link timers */
  oonf_timer_stop(&lnk->sym_time);

  /* remove all 2hop addresses */
  avl_for_each_element_safe(&lnk->_2hop, twohop, _link_node, th_it) {
    nhdp_db_link_2hop_remove(twohop);
  }

  /* link status was changed */
  lnk->last_status_change = oonf_clock_getNow();

  /* trigger event */
  oonf_class_event(&_link_info, lnk, OONF_OBJECT_CHANGED);
}

/**
 * Remove a link from the nhdp database
 * @param lnk nhdp link
 */
void
nhdp_db_link_remove(struct nhdp_link *lnk) {
  struct nhdp_laddr *laddr, *la_it;
  struct nhdp_l2hop *twohop, *th_it;

  /* trigger event */
  oonf_class_event(&_link_info, lnk, OONF_OBJECT_REMOVED);

  oonf_timer_stop(&lnk->sym_time);
  oonf_timer_stop(&lnk->heard_time);
  oonf_timer_stop(&lnk->vtime);

  /* disconnect dualstack */
  if (nhdp_db_link_is_dualstack(lnk)) {
    nhdp_db_link_disconnect_dualstack(lnk);
  }

  if (netaddr_get_address_family(&lnk->neigh->originator) != AF_UNSPEC) {
    avl_remove(&lnk->local_if->_link_originators, &lnk->_originator_node);
  }

  /* detach all addresses */
  avl_for_each_element_safe(&lnk->_addresses, laddr, _link_node, la_it) {
    nhdp_db_link_addr_remove(laddr);
  }

  /* remove all 2hop addresses */
  avl_for_each_element_safe(&lnk->_2hop, twohop, _link_node, th_it) {
    nhdp_db_link_2hop_remove(twohop);
  }

  /* unlink */
  nhdp_interface_remove_link(lnk);
  list_remove(&lnk->_neigh_node);

  /* remove from global list */
  list_remove(&lnk->_global_node);

  /* free memory */
  oonf_class_free(&_link_info, lnk);
}

/**
 * Add a network address as a link address to a nhdp link
 * @param lnk nhpd link
 * @param addr network address
 * @return nhdp link address, NULL if out of memory
 */
struct nhdp_laddr *
nhdp_db_link_addr_add(struct nhdp_link *lnk, const struct netaddr *addr) {
  struct nhdp_laddr *laddr;

  laddr = oonf_class_malloc(&_laddr_info);
  if (laddr == NULL) {
    return NULL;
  }

  /* initialize key */
  memcpy(&laddr->link_addr, addr, sizeof(laddr->link_addr));
  laddr->_link_node.key = &laddr->link_addr;
  laddr->_neigh_node.key = &laddr->link_addr;
  laddr->_if_node.key = &laddr->link_addr;

  /* initialize back link */
  laddr->link = lnk;

  /* add to trees */
  avl_insert(&lnk->_addresses, &laddr->_link_node);
  avl_insert(&lnk->neigh->_link_addresses, &laddr->_neigh_node);
  nhdp_interface_add_laddr(laddr);

  /* trigger event */
  oonf_class_event(&_laddr_info, laddr, OONF_OBJECT_ADDED);

  return laddr;
}

/**
 * Removes a nhdp link address from its link
 * @param laddr nhdp link address
 */
void
nhdp_db_link_addr_remove(struct nhdp_laddr *laddr) {
  /* trigger event */
  oonf_class_event(&_laddr_info, laddr, OONF_OBJECT_REMOVED);

  /* remove from trees */
  nhdp_interface_remove_laddr(laddr);
  avl_remove(&laddr->link->_addresses, &laddr->_link_node);
  avl_remove(&laddr->link->neigh->_link_addresses, &laddr->_neigh_node);

  /* free memory */
  oonf_class_free(&_laddr_info, laddr);
}

/**
 * Moves a nhdp link address to a different link
 * @param lnk NHDP link
 * @param laddr NHDP link address
 */
void
nhdp_db_link_addr_move(struct nhdp_link *lnk, struct nhdp_laddr *laddr) {
  /* remove from old link */
  avl_remove(&laddr->link->_addresses, &laddr->_link_node);

  /* add to new neighbor */
  avl_insert(&lnk->_addresses, &laddr->_link_node);

  if (laddr->link->neigh != lnk->neigh) {
    /* remove from old neighbor */
    avl_remove(&laddr->link->neigh->_link_addresses, &laddr->_neigh_node);

    /* add to new neighbor */
    avl_insert(&lnk->neigh->_link_addresses, &laddr->_neigh_node);
  }
  /* set new backlink */
  laddr->link = lnk;
}

/**
 * Adds a network address as a 2-hop neighbor to a nhdp link
 * @param lnk nhdp link
 * @param addr network address
 * @return nhdp link two-hop neighbor
 */
struct nhdp_l2hop *
nhdp_db_link_2hop_add(struct nhdp_link *lnk, const struct netaddr *addr) {
  struct nhdp_l2hop *l2hop;

  l2hop = oonf_class_malloc(&_l2hop_info);
  if (l2hop == NULL) {
    return NULL;
  }

  /* initialize key */
  memcpy(&l2hop->twohop_addr, addr, sizeof(l2hop->twohop_addr));
  l2hop->_link_node.key = &l2hop->twohop_addr;

  /* initialize back link */
  l2hop->link = lnk;

  /* initialize validity timer */
  l2hop->_vtime.class = &_l2hop_vtime_info;

  /* add to link tree */
  avl_insert(&lnk->_2hop, &l2hop->_link_node);

  /* add to interface tree */
  nhdp_interface_add_l2hop(lnk->local_if, l2hop);

  /* initialize metrics */
  nhdp_domain_init_l2hop(l2hop);

  /* trigger event */
  oonf_class_event(&_l2hop_info, l2hop, OONF_OBJECT_ADDED);

  return l2hop;
}

/**
 * Removes a two-hop address from a nhdp link
 * @param l2hop nhdp two-hop link address
 */
void
nhdp_db_link_2hop_remove(struct nhdp_l2hop *l2hop) {
  /* trigger event */
  oonf_class_event(&_l2hop_info, l2hop, OONF_OBJECT_REMOVED);

  /* remove from link tree */
  avl_remove(&l2hop->link->_2hop, &l2hop->_link_node);

  /* remove from interface tree */
  nhdp_interface_remove_l2hop(l2hop);

  /* stop validity timer */
  oonf_timer_stop(&l2hop->_vtime);

  /* free memory */
  oonf_class_free(&_l2hop_info, l2hop);
}

/**
 * Connect two links as representations of the same node,
 * @param l_ipv4 ipv4 link
 * @param l_ipv6 ipv6 link
 */
void
nhdp_db_link_connect_dualstack(struct nhdp_link *l_ipv4, struct nhdp_link *l_ipv6) {
  if (l_ipv4->dualstack_partner != l_ipv6) {
    nhdp_db_link_disconnect_dualstack(l_ipv4);
    l_ipv4->dualstack_partner = l_ipv6;
  }

  if (l_ipv6->dualstack_partner != l_ipv4) {
    nhdp_db_link_disconnect_dualstack(l_ipv6);
    l_ipv6->dualstack_partner = l_ipv4;
  }
}

/**
 * Disconnects the pointers of a dualstack pair of links
 * @param lnk one of the connected links
 */
void
nhdp_db_link_disconnect_dualstack(struct nhdp_link *lnk) {
  if (lnk->dualstack_partner) {
    lnk->dualstack_partner->dualstack_partner = NULL;
    lnk->dualstack_partner = NULL;
  }
}

/**
 * Recalculate the status of a nhdp link and update database
 * if link changed between symmetric and non-symmetric
 * @param lnk nhdp link with (potential) new status
 */
void
nhdp_db_link_update_status(struct nhdp_link *lnk) {
  enum nhdp_link_status old_status;
  bool was_symmetric;

  old_status = lnk->status;
  was_symmetric = lnk->status == NHDP_LINK_SYMMETRIC;

  /* update link status */
  lnk->last_status = lnk->status;
  lnk->status = _nhdp_db_link_calculate_status(lnk);

  /* handle database changes */
  if (was_symmetric && lnk->status != NHDP_LINK_SYMMETRIC) {
    _link_status_not_symmetric_anymore(lnk);
  }
  if (!was_symmetric && lnk->status == NHDP_LINK_SYMMETRIC) {
    _link_status_now_symmetric(lnk);
  }

  /* trigger ip flooding interface settings recalculation */
  if (was_symmetric != (lnk->status == NHDP_LINK_SYMMETRIC)) {
    nhdp_interface_update_status(lnk->local_if);
  }

  if (old_status != lnk->status) {
    /* link status was changed */
    lnk->last_status_change = oonf_clock_getNow();
    nhdp_domain_recalculate_metrics(NULL, lnk->neigh, true);
    nhdp_domain_delayed_mpr_recalculation(NULL, lnk->neigh);

    /* trigger change event */
    oonf_class_event(&_link_info, lnk, OONF_OBJECT_CHANGED);
  }
}

/**
 * @param lnk nhdp link
 * @return name of link status
 */
const char *
nhdp_db_link_status_to_string(struct nhdp_link *lnk) {
  switch (lnk->status) {
    case NHDP_LINK_PENDING:
      return _LINK_PENDING;
    case NHDP_LINK_HEARD:
      return _LINK_HEARD;
    case NHDP_LINK_SYMMETRIC:
      return _LINK_SYMMETRIC;
    default:
      return _LINK_LOST;
  }
}

/**
 * get global list of nhdp neighbors
 * @return neighbor list
 */
struct list_entity *
nhdp_db_get_neigh_list(void) {
  return &_neigh_list;
}

/**
 * get global list of nhdp links
 * @return link list
 */
struct list_entity *
nhdp_db_get_link_list(void) {
  return &_link_list;
}

/**
 * get global tree of nhdp neighbor addresses
 * @return neighbor address tree
 */
struct avl_tree *
nhdp_db_get_naddr_tree(void) {
  return &_naddr_tree;
}

/**
 * get global tree of nhdp originators
 * @return originator tree
 */
struct avl_tree *
nhdp_db_get_neigh_originator_tree(void) {
  return &_neigh_originator_tree;
}

/**
 * Helper function to calculate NHDP link status
 * @param lnk nhdp link
 * @return link status
 */
int
_nhdp_db_link_calculate_status(struct nhdp_link *lnk) {
  const struct netaddr *local_originator;
  const struct os_interface *localif;
  int af_type;

  af_type = netaddr_get_address_family(&lnk->if_addr);
  local_originator = nhdp_get_originator(af_type);
  localif = nhdp_interface_get_if_listener(lnk->local_if)->data;

  /* check for originator collision */
  if (!netaddr_is_unspec(local_originator) && (netaddr_cmp(local_originator, &lnk->if_addr) == 0 ||
                                                netaddr_cmp(local_originator, &lnk->neigh->originator) == 0)) {
    return NHDP_LINK_PENDING;
  }

  /* check for interface address collision */
  if (nhdp_interface_addr_if_get(lnk->local_if, &lnk->if_addr)) {
    return NHDP_LINK_PENDING;
  }

  /* check for MAC collision */
  if (!netaddr_is_unspec(&lnk->remote_mac) && netaddr_cmp(&localif->mac, &lnk->remote_mac) == 0) {
    return NHDP_LINK_PENDING;
  }

  /* calculate link status as described in RFC 6130 */
  if (nhdp_hysteresis_is_pending(lnk)) {
    return NHDP_LINK_PENDING;
  }
  if (nhdp_hysteresis_is_lost(lnk))
    return RFC6130_LINKSTATUS_LOST;
  if (oonf_timer_is_active(&lnk->sym_time))
    return RFC6130_LINKSTATUS_SYMMETRIC;
  if (oonf_timer_is_active(&lnk->heard_time))
    return RFC6130_LINKSTATUS_HEARD;
  return RFC6130_LINKSTATUS_LOST;
}

/**
 * Helper function that handles the case of a link becoming symmetric
 * @param lnk nhdp link
 */
static void
_link_status_now_symmetric(struct nhdp_link *lnk) {
  struct nhdp_naddr *naddr;

  lnk->neigh->symmetric++;

  if (lnk->neigh->symmetric == 1) {
    avl_for_each_element(&lnk->neigh->_neigh_addresses, naddr, _neigh_node) {
      nhdp_db_neighbor_addr_not_lost(naddr);
    }
    _neighbor_set_id++;
  }
}

/**
 * Helper function that handles the case of a link becoming asymmetric
 * @param lnk nhdp link
 */
static void
_link_status_not_symmetric_anymore(struct nhdp_link *lnk) {
  struct nhdp_l2hop *twohop, *twohop_it;
  struct nhdp_naddr *naddr, *na_it;

  /* remove all 2hop neighbors */
  avl_for_each_element_safe(&lnk->_2hop, twohop, _link_node, twohop_it) {
    nhdp_db_link_2hop_remove(twohop);
  }

  lnk->neigh->symmetric--;
  if (lnk->neigh->symmetric == 0) {
    /* mark all neighbor addresses as lost */
    avl_for_each_element_safe(&lnk->neigh->_neigh_addresses, naddr, _neigh_node, na_it) {
      nhdp_db_neighbor_addr_set_lost(naddr, lnk->local_if->n_hold_time);
    }

    _neighbor_set_id++;
  }
}

/**
 * Callback triggered when link validity timer fires
 * @param ptr timer instance that fired
 */
static void
_cb_link_vtime(struct oonf_timer_instance *ptr) {
  struct nhdp_link *lnk;
  struct nhdp_neighbor *neigh;

  lnk = container_of(ptr, struct nhdp_link, vtime);
  OONF_DEBUG(LOG_NHDP, "Link vtime fired: 0x%0zx", (size_t)ptr);

  neigh = lnk->neigh;

  if (lnk->status == NHDP_LINK_SYMMETRIC) {
    _link_status_not_symmetric_anymore(lnk);
  }

  /* remove link from database */
  nhdp_db_link_remove(lnk);

  /* check if neighbor still has links */
  if (list_is_empty(&neigh->_links)) {
    nhdp_db_neighbor_remove(neigh);
  }
}

/**
 * Callback triggered when link heard timer fires
 * @param ptr timer instance that fired
 */
static void
_cb_link_heard(struct oonf_timer_instance *ptr) {
  struct nhdp_link *lnk;

  lnk = container_of(ptr, struct nhdp_link, heard_time);
  OONF_DEBUG(LOG_NHDP, "Link heard fired: 0x%0zx", (size_t)lnk);
  nhdp_db_link_update_status(lnk);
}

/**
 * Callback triggered when link symmetric timer fires
 * @param ptr timer instance that fired
 */
static void
_cb_link_symtime(struct oonf_timer_instance *ptr) {
  struct nhdp_link *lnk;

  lnk = container_of(ptr, struct nhdp_link, sym_time);
  OONF_DEBUG(LOG_NHDP, "Link Symtime fired: 0x%0zx", (size_t)lnk);
  nhdp_db_link_update_status(lnk);
}

/**
 * Callback triggered when nhdp address validity timer fires
 * @param ptr timer instance that fired
 */
static void
_cb_naddr_vtime(struct oonf_timer_instance *ptr) {
  struct nhdp_naddr *naddr;

  naddr = container_of(ptr, struct nhdp_naddr, _lost_vtime);
  OONF_DEBUG(LOG_NHDP, "Neighbor Address Lost fired: 0x%0zx", (size_t)ptr);

  nhdp_db_neighbor_addr_remove(naddr);
}

/**
 * Callback triggered when 2hop valitidy timer fires
 * @param ptr timer instance that fired
 */
static void
_cb_l2hop_vtime(struct oonf_timer_instance *ptr) {
  struct nhdp_l2hop *l2hop;

  l2hop = container_of(ptr, struct nhdp_l2hop, _vtime);

  OONF_DEBUG(LOG_NHDP, "2Hop vtime fired: 0x%0zx", (size_t)ptr);
  nhdp_db_link_2hop_remove(l2hop);
}
