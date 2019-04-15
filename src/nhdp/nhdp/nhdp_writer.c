
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
#include <oonf/libcore/oonf_logging.h>
#include <oonf/base/oonf_rfc5444.h>

#include <oonf/nhdp/nhdp/nhdp.h>
#include <oonf/nhdp/nhdp/nhdp_domain.h>
#include <oonf/nhdp/nhdp/nhdp_interfaces.h>
#include <oonf/nhdp/nhdp/nhdp_internal.h>
#include <oonf/nhdp/nhdp/nhdp_writer.h>

/* constants */
enum
{
  IDX_ADDRTLV_LOCAL_IF,
  IDX_ADDRTLV_LINK_STATUS,
  IDX_ADDRTLV_OTHER_NEIGHB,
  IDX_ADDRTLV_MPR,
};

/* prototypes */
static int _cb_addMessageHeader(struct rfc5444_writer *, struct rfc5444_writer_message *);
static void _cb_addMessageTLVs(struct rfc5444_writer *);
static void _cb_addAddresses(struct rfc5444_writer *);

static void _add_link_address(struct rfc5444_writer *writer, struct rfc5444_writer_content_provider *prv,
  struct nhdp_interface *interf, struct nhdp_naddr *naddr);
static void _add_localif_address(struct rfc5444_writer *writer, struct rfc5444_writer_content_provider *prv,
  struct nhdp_interface *interf, struct nhdp_interface_addr *addr);

static void _write_metric_tlv(struct rfc5444_writer *writer, struct rfc5444_writer_address *addr,
  struct nhdp_neighbor *neigh, struct nhdp_link *lnk, struct nhdp_domain *domain);

/* definition of NHDP writer */
static struct rfc5444_writer_message *_nhdp_message = NULL;

static struct rfc5444_writer_content_provider _nhdp_msgcontent_provider = {
  .msg_type = RFC6130_MSGTYPE_HELLO,
  .addMessageTLVs = _cb_addMessageTLVs,
  .addAddresses = _cb_addAddresses,
};

static struct rfc5444_writer_tlvtype _nhdp_addrtlvs[] = {
  [IDX_ADDRTLV_LOCAL_IF] = { .type = RFC6130_ADDRTLV_LOCAL_IF },
  [IDX_ADDRTLV_LINK_STATUS] = { .type = RFC6130_ADDRTLV_LINK_STATUS },
  [IDX_ADDRTLV_OTHER_NEIGHB] = { .type = RFC6130_ADDRTLV_OTHER_NEIGHB },
  [IDX_ADDRTLV_MPR] = { .type = RFC7181_ADDRTLV_MPR },
};

static struct oonf_rfc5444_protocol *_protocol;

static bool _cleanedup = false;
static bool _add_mac_tlv = true;
static struct nhdp_interface *_nhdp_if = NULL;

/**
 * Initialize nhdp writer
 * @param p rfc5444 protocol
 * @return -1 if an error happened, 0 otherwise
 */
int
nhdp_writer_init(struct oonf_rfc5444_protocol *p) {
  _protocol = p;

  _nhdp_message = rfc5444_writer_register_message(&_protocol->writer, RFC6130_MSGTYPE_HELLO, true);
  if (_nhdp_message == NULL) {
    OONF_WARN(LOG_NHDP_W, "Could not register NHDP Hello message");
    return -1;
  }

  _nhdp_message->addMessageHeader = _cb_addMessageHeader;

  if (rfc5444_writer_register_msgcontentprovider(
        &_protocol->writer, &_nhdp_msgcontent_provider, _nhdp_addrtlvs, ARRAYSIZE(_nhdp_addrtlvs))) {
    OONF_WARN(LOG_NHDP_W, "Count not register NHDP msg contentprovider");
    rfc5444_writer_unregister_message(&_protocol->writer, _nhdp_message);
    return -1;
  }
  return 0;
}

/**
 * Cleanup nhdp writer
 */
void
nhdp_writer_cleanup(void) {
  /* remember we already did shut down the writer */
  _cleanedup = true;

  /* remove pbb writer */
  rfc5444_writer_unregister_content_provider(
    &_protocol->writer, &_nhdp_msgcontent_provider, _nhdp_addrtlvs, ARRAYSIZE(_nhdp_addrtlvs));
  rfc5444_writer_unregister_message(&_protocol->writer, _nhdp_message);
}

/**
 * Send a NHDP Hello through the specified interface. This might result
 * in both an IPv4 and IPv6 message
 * @param ninterf NHDP interface
 */
void
nhdp_writer_send_hello(struct nhdp_interface *ninterf) {
  enum rfc5444_result result;
  struct os_interface_listener *interf;
  struct netaddr_str buf;

  if (_cleanedup) {
    /* do not send more Hellos during shutdown */
    return;
  }

  interf = nhdp_interface_get_if_listener(ninterf);
  if (interf->data->flags.loopback) {
    /* no NHDP on loopback interface */
    return;
  }

  OONF_DEBUG(LOG_NHDP_W, "Sending Hello to interface %s", nhdp_interface_get_name(ninterf));

  nhdp_domain_recalculate_mpr();

  /* store NHDP interface */
  _nhdp_if = ninterf;

  /* send IPv4 (if socket is active) */
  result = oonf_rfc5444_send_if(ninterf->rfc5444_if.interface->multicast4, RFC6130_MSGTYPE_HELLO);
  if (result < 0) {
    OONF_WARN(LOG_NHDP_W, "Could not send NHDP message to %s: %s (%d)",
      netaddr_to_string(&buf, &ninterf->rfc5444_if.interface->multicast4->dst), rfc5444_strerror(result), result);
  }

  /* send IPV6 (if socket is active) */
  result = oonf_rfc5444_send_if(ninterf->rfc5444_if.interface->multicast6, RFC6130_MSGTYPE_HELLO);
  if (result < 0) {
    OONF_WARN(LOG_NHDP_W, "Could not send NHDP message to %s: %s (%d)",
      netaddr_to_string(&buf, &ninterf->rfc5444_if.interface->multicast6->dst), rfc5444_strerror(result), result);
  }
}

/**
 * activates or deactivates the MAC_TLV in the NHDP Hello messages
 * @param active true if MAC_TLV should be present
 */
void
nhdp_writer_set_mac_TLV_state(bool active) {
  _add_mac_tlv = active;
}

/**
 * Callback to initialize the message header for a HELLO message
 * @param writer RFC5444 writer instance
 * @param message RFC5444 message
 */
static int
_cb_addMessageHeader(struct rfc5444_writer *writer, struct rfc5444_writer_message *message) {
  struct oonf_rfc5444_target *target;
  const struct netaddr *originator;
  struct netaddr_str buf;

  if (!message->target_specific) {
    OONF_WARN(LOG_NHDP_W, "non interface-specific NHDP message!");
    return RFC5444_DROP_MESSAGE;
  }

  target = oonf_rfc5444_get_target_from_writer(writer);
  if (target != target->interface->multicast6 && target != target->interface->multicast4) {
    OONF_WARN(LOG_NHDP_W, "Cannot generate unicast nhdp message to %s", netaddr_to_string(&buf, &target->dst));
    return RFC5444_DROP_MESSAGE;
  }

  /* get originator */
  if (writer->msg_addr_len == 4) {
    originator = nhdp_get_originator(AF_INET);
  }
  else {
    originator = nhdp_get_originator(AF_INET6);
  }

  OONF_DEBUG(LOG_NHDP_W, "Generate Hello on interface %s with destination %s", target->interface->name,
    netaddr_to_string(&buf, &target->dst));

  if (originator != NULL && netaddr_get_address_family(originator) != AF_UNSPEC) {
    OONF_DEBUG(LOG_NHDP_W, "Add originator %s", netaddr_to_string(&buf, originator));

    rfc5444_writer_set_msg_header(writer, message, true, false, false, false);
    rfc5444_writer_set_msg_originator(writer, message, netaddr_get_binptr(originator));
  }
  else {
    rfc5444_writer_set_msg_header(writer, message, false, false, false, false);
  }
  return RFC5444_OKAY;
}

/**
 * Callback to add the message TLVs to a HELLO message
 * @param writer RFC5444 writer
 */
static void
_cb_addMessageTLVs(struct rfc5444_writer *writer) {
  uint8_t vtime_encoded, itime_encoded;
  struct oonf_rfc5444_target *target;
  const struct netaddr *v4_originator;
  struct os_interface *os_if;
  uint8_t willingness[NHDP_MAXIMUM_DOMAINS];
  size_t willingness_size;
  uint8_t mprtypes[NHDP_MAXIMUM_DOMAINS];
  uint8_t mprtypes_size;
  struct netaddr_str buf;

  target = oonf_rfc5444_get_target_from_writer(writer);

  OONF_ASSERT(target == target->interface->multicast4 || target == target->interface->multicast6,
                LOG_NHDP_W, "target for NHDP is no interface multicast: %s", netaddr_to_string(&buf, &target->dst));

  itime_encoded = rfc5497_timetlv_encode(_nhdp_if->refresh_interval);
  vtime_encoded = rfc5497_timetlv_encode(_nhdp_if->h_hold_time);

  rfc5444_writer_add_messagetlv(writer, RFC5497_MSGTLV_INTERVAL_TIME, 0, &itime_encoded, sizeof(itime_encoded));
  rfc5444_writer_add_messagetlv(writer, RFC5497_MSGTLV_VALIDITY_TIME, 0, &vtime_encoded, sizeof(vtime_encoded));

  /* generate MPRtypes */
  mprtypes_size = nhdp_domain_encode_mprtypes_tlvvalue(mprtypes, sizeof(mprtypes));
  if (mprtypes_size > 1) {
    rfc5444_writer_add_messagetlv(
      writer, RFC7722_MSGTLV_MPR_TYPES, RFC7722_MSGTLV_MPR_TYPES_EXT, &mprtypes, mprtypes_size);
  }

  /* add willingness for all domains */
  willingness_size = nhdp_domain_encode_willingness_tlvvalue(willingness, sizeof(willingness));
  rfc5444_writer_add_messagetlv(writer, RFC7181_MSGTLV_MPR_WILLING, 0, &willingness, willingness_size);

  /* get v6 originator (might be unspecified) */
  v4_originator = nhdp_get_originator(AF_INET);

  /* add V4 originator to V6 message if available and interface is dualstack */
  if (writer->msg_addr_len == 16 && v4_originator != NULL && netaddr_get_address_family(v4_originator) == AF_INET) {
    rfc5444_writer_add_messagetlv(
      writer, NHDP_MSGTLV_IPV4ORIGINATOR, 0, netaddr_get_binptr(v4_originator), netaddr_get_binlength(v4_originator));
  }

  /* add mac address of local interface */
  os_if = nhdp_interface_get_if_listener(_nhdp_if)->data;

  if (_add_mac_tlv && netaddr_get_address_family(&os_if->mac) == AF_MAC48) {
    rfc5444_writer_add_messagetlv(
      writer, NHDP_MSGTLV_MAC, 0, netaddr_get_binptr(&os_if->mac), netaddr_get_binlength(&os_if->mac));
  }
}

/**
 * Add a rfc5444 address with localif TLV to the stream
 * @param writer RFC5444 writer instance
 * @param prv RFC5444 content provider instance
 * @param interf NHDP interface
 * @param addr NHDP interface address
 */
static void
_add_localif_address(struct rfc5444_writer *writer, struct rfc5444_writer_content_provider *prv,
  struct nhdp_interface *interf, struct nhdp_interface_addr *addr) {
  struct rfc5444_writer_address *address;
  struct netaddr_str buf;
  uint8_t value;
  bool this_if;

  /* check if address of local interface */
  this_if = NULL != avl_find_element(&interf->_if_addresses, &addr->if_addr, addr, _if_node);

  OONF_DEBUG(
    LOG_NHDP_W, "Add %s (%s) to NHDP hello", netaddr_to_string(&buf, &addr->if_addr), this_if ? "this_if" : "other_if");

  /* generate RFC5444 address */
  address = rfc5444_writer_add_address(writer, prv->creator, &addr->if_addr, true);
  if (address == NULL) {
    OONF_WARN(LOG_NHDP_W, "Could not add address %s to NHDP hello", netaddr_to_string(&buf, &addr->if_addr));
    return;
  }

  /* Add LOCALIF TLV */
  if (this_if) {
    value = RFC6130_LOCALIF_THIS_IF;
  }
  else {
    value = RFC6130_LOCALIF_OTHER_IF;
  }
  rfc5444_writer_add_addrtlv(writer, address, &_nhdp_addrtlvs[IDX_ADDRTLV_LOCAL_IF], &value, sizeof(value), true);
}

/**
 * Add a rfc5444 address with link_status or other_neigh TLV to the stream
 * @param writer RFC5444 writer instance
 * @param prv RFC5444 content provider instance
 * @param interf NHDP interface
 * @param naddr NHDP interface address
 */
static void
_add_link_address(struct rfc5444_writer *writer, struct rfc5444_writer_content_provider *prv,
  struct nhdp_interface *interf, struct nhdp_naddr *naddr) {
  struct rfc5444_writer_address *address;
  struct nhdp_domain *domain;
  struct nhdp_laddr *laddr;
  struct netaddr_str buf;
  uint8_t linkstatus, otherneigh_sym;
  uint8_t mprvalue[NHDP_MAXIMUM_DOMAINS];
  size_t len;

  /* initialize flags for default (lost address) address */
  linkstatus = 255;
  otherneigh_sym = 0;

  laddr = nhdp_interface_get_link_addr(interf, &naddr->neigh_addr);
  if (!nhdp_db_neighbor_addr_is_lost(naddr)) {
    if (laddr != NULL && laddr->link->local_if == interf && laddr->link->status != NHDP_LINK_PENDING) {
      linkstatus = laddr->link->status;
    }

    if (naddr->neigh->symmetric > 0 && linkstatus != NHDP_LINK_SYMMETRIC) {
      otherneigh_sym = NHDP_LINK_SYMMETRIC;
    }
  }

  /* generate RFC5444 address */
  address = rfc5444_writer_add_address(writer, prv->creator, &naddr->neigh_addr, false);
  if (address == NULL) {
    OONF_WARN(LOG_NHDP_W, "Could not add address %s to NHDP hello", netaddr_to_string(&buf, &naddr->neigh_addr));
    return;
  }

  if (linkstatus != 255) {
    rfc5444_writer_add_addrtlv(
      writer, address, &_nhdp_addrtlvs[IDX_ADDRTLV_LINK_STATUS], &linkstatus, sizeof(linkstatus), false);

    OONF_DEBUG(LOG_NHDP_W, "Add %s (linkstatus=%d) to NHDP hello", netaddr_to_string(&buf, &naddr->neigh_addr),
      laddr->link->status);
  }

  rfc5444_writer_add_addrtlv(
    writer, address, &_nhdp_addrtlvs[IDX_ADDRTLV_OTHER_NEIGHB], &otherneigh_sym, sizeof(otherneigh_sym), false);

  OONF_DEBUG(
    LOG_NHDP_W, "Add %s (otherneigh=%d) to NHDP hello", netaddr_to_string(&buf, &naddr->neigh_addr), otherneigh_sym);

  /* add MPR tlvs */
  if (laddr != NULL) {
    len = nhdp_domain_encode_mpr_tlvvalue(mprvalue, sizeof(mprvalue), laddr->link);

    if (len) {
      rfc5444_writer_add_addrtlv(writer, address, &_nhdp_addrtlvs[IDX_ADDRTLV_MPR], &mprvalue, len, false);
    }
  }

  /* add linkcost TLVs */
  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    struct nhdp_link *lnk = NULL;
    struct nhdp_neighbor *neigh = NULL;

    OONF_DEBUG(LOG_NHDP_W, "Determine metric status: %d %d %d",
               linkstatus, otherneigh_sym, naddr->neigh->symmetric);
    if (linkstatus == NHDP_LINK_HEARD || linkstatus == NHDP_LINK_SYMMETRIC) {
      lnk = laddr->link;
    }
    if (naddr->neigh->symmetric > 0 &&
        (linkstatus == NHDP_LINK_SYMMETRIC || otherneigh_sym == RFC6130_OTHERNEIGHB_SYMMETRIC)) {
      neigh = naddr->neigh;
    }

    _write_metric_tlv(writer, address, neigh, lnk, domain);
  }
}

/**
 * Write up to four metric TLVs to an address
 * @param writer rfc5444 writer instance
 * @param addr rfc5444 address
 * @param neigh symmetric NHDP neighbor, might be NULL
 * @param lnk symmetric NHDP link, might be NULL
 * @param domain NHDP domain
 */
static void
_write_metric_tlv(struct rfc5444_writer *writer, struct rfc5444_writer_address *addr, struct nhdp_neighbor *neigh,
  struct nhdp_link *lnk, struct nhdp_domain *domain) {
  static const enum rfc7181_linkmetric_flags flags[4] = {
    RFC7181_LINKMETRIC_INCOMING_LINK,
    RFC7181_LINKMETRIC_OUTGOING_LINK,
    RFC7181_LINKMETRIC_INCOMING_NEIGH,
    RFC7181_LINKMETRIC_OUTGOING_NEIGH,
  };
#ifdef OONF_LOG_DEBUG_INFO
  static const char *lq_name[4] = {
    "l_in",
    "l_out",
    "n_in",
    "n_out",
  };
#endif
  struct nhdp_link_domaindata *linkdata;
  struct nhdp_neighbor_domaindata *neighdata;
  struct rfc7181_metric_field metric_encoded[4], tlv_value;
  int i, j, k;
  uint32_t metrics[4] = { 0, 0, 0, 0 };

  if (lnk == NULL && neigh == NULL) {
    /* nothing to do */
    return;
  }

  /* get link metrics if available */
  if (lnk != NULL && (lnk->status == NHDP_LINK_HEARD || lnk->status == NHDP_LINK_SYMMETRIC)) {
    linkdata = nhdp_domain_get_linkdata(domain, lnk);
    metrics[0] = linkdata->metric.in;
    metrics[1] = linkdata->metric.out;
  }

  /* get neighbor metrics if available */
  if (neigh != NULL && neigh->symmetric > 0) {
    neighdata = nhdp_domain_get_neighbordata(domain, neigh);
    metrics[2] = neighdata->metric.in;
    metrics[3] = neighdata->metric.out;
  }

  /* check if metric is infinite */
  for (i = 0; i < 4; i++) {
    if (metrics[i] > RFC7181_METRIC_MAX) {
      metrics[i] = 0;
    }
  }

  /* encode metrics */
  for (i = 0; i < 4; i++) {
    if (metrics[i] > 0) {
      if (rfc7181_metric_encode(&metric_encoded[i], metrics[i])) {
        OONF_WARN(LOG_NHDP_W, "Metric encoding for %u failed", metrics[i]);
        return;
      }
    }
  }

  /* compress four metrics into 1-4 TLVs */
  k = 0;
  for (i = 0; i < 4; i++) {
    /* find first metric value which still must be sent */
    if (metrics[i] == 0) {
      continue;
    }

    /* create value */
    tlv_value = metric_encoded[i];

    /* mark first metric value */
    rfc7181_metric_set_flag(&tlv_value, flags[i]);

    /* mark all metric pair that have the same linkmetric */
    OONF_DEBUG(LOG_NHDP_W, "Add Metric %s (ext %u): 0x%02x%02x (%u)", lq_name[i], domain->ext, tlv_value.b[0],
      tlv_value.b[1], metrics[i]);

    for (j = 3; j > i; j--) {
      if (metrics[j] > 0 && memcmp(&metric_encoded[i], &metric_encoded[j], sizeof(metric_encoded[0])) == 0) {
        rfc7181_metric_set_flag(&tlv_value, flags[j]);
        metrics[j] = 0;

        OONF_DEBUG(LOG_NHDP_W, "Same metrics for %s (ext %u)", lq_name[j], domain->ext);
      }
    }

    /* add to rfc5444 address */
    rfc5444_writer_add_addrtlv(writer, addr, &domain->_metric_addrtlvs[k++], &tlv_value, sizeof(tlv_value), true);
  }
}
/**
 * Callback to add the addresses and address TLVs to a HELLO message
 * @param writer RFC5444 writer instance
 */
void
_cb_addAddresses(struct rfc5444_writer *writer) {
  struct oonf_rfc5444_target *target;

  struct nhdp_interface *interf;
  struct nhdp_interface_addr *addr;
  struct nhdp_naddr *naddr;

  /* have already be checked for message TLVs, so they cannot be NULL */
  target = oonf_rfc5444_get_target_from_writer(writer);
  interf = nhdp_interface_get(target->interface->name);

  /* transmit interface addresses first */
  avl_for_each_element(nhdp_interface_get_address_tree(), addr, _global_node) {
    if (addr->removed) {
      continue;
    }
    if (netaddr_get_address_family(&addr->if_addr) == netaddr_get_address_family(&target->dst)) {
      _add_localif_address(writer, &_nhdp_msgcontent_provider, interf, addr);
    }
  }

  /* then transmit neighbor addresses */
  avl_for_each_element(nhdp_db_get_naddr_tree(), naddr, _global_node) {
    if (netaddr_get_address_family(&naddr->neigh_addr) == netaddr_get_address_family(&target->dst)) {
      _add_link_address(writer, &_nhdp_msgcontent_provider, interf, naddr);
    }
  }
}
