
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

#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_rfc5444.h>

#include <oonf/nhdp/nhdp/nhdp.h>
#include <oonf/nhdp/nhdp/nhdp_db.h>
#include <oonf/nhdp/nhdp/nhdp_domain.h>
#include <oonf/nhdp/nhdp/nhdp_hysteresis.h>
#include <oonf/nhdp/nhdp/nhdp_interfaces.h>
#include <oonf/nhdp/nhdp/nhdp_internal.h>
#include <oonf/nhdp/nhdp/nhdp_reader.h>

/* NHDP message TLV array index */
enum
{
  IDX_TLV_ITIME,
  IDX_TLV_VTIME,
  IDX_TLV_WILLINGNESS,
  IDX_TLV_MPRTYPES,
  IDX_TLV_IPV4ORIG,
  IDX_TLV_MAC,
};

/* NHDP address TLV array index pass 1 */
enum
{
  IDX_ADDRTLV1_LOCAL_IF,
  IDX_ADDRTLV1_LINK_STATUS,
};

/* NHDP address TLV array index pass 2 */
enum
{
  IDX_ADDRTLV2_LOCAL_IF,
  IDX_ADDRTLV2_LINK_STATUS,
  IDX_ADDRTLV2_OTHER_NEIGHB,
  IDX_ADDRTLV2_MPR,
  IDX_ADDRTLV2_LINKMETRIC,
};

/* prototypes */
static void _cleanup_error(void);
static enum rfc5444_result _pass2_process_localif(struct netaddr *addr, uint8_t local_if);
static void _handle_originator(struct rfc5444_reader_tlvblock_context *context);

static enum rfc5444_result _cb_messagetlvs(struct rfc5444_reader_tlvblock_context *context);
static enum rfc5444_result _cb_failed_constraints(struct rfc5444_reader_tlvblock_context *context);

static enum rfc5444_result _cb_addresstlvs_pass1(struct rfc5444_reader_tlvblock_context *context);
static enum rfc5444_result _cb_addresstlvs_pass1_end(struct rfc5444_reader_tlvblock_context *context, bool dropped);

static enum rfc5444_result _cb_addr_pass2_block(struct rfc5444_reader_tlvblock_context *context);
static enum rfc5444_result _cb_msg_pass2_end(struct rfc5444_reader_tlvblock_context *context, bool dropped);

/* definition of the RFC5444 reader components */
static struct rfc5444_reader_tlvblock_consumer _nhdp_message_pass1_consumer = {
  .order = RFC5444_MAIN_PARSER_PRIORITY,
  .msg_id = RFC6130_MSGTYPE_HELLO,
  .block_callback = _cb_messagetlvs,
  .block_callback_failed_constraints = _cb_failed_constraints,
  .end_callback = _cb_addresstlvs_pass1_end,
};

static struct rfc5444_reader_tlvblock_consumer_entry _nhdp_message_tlvs[] = {
  [IDX_TLV_VTIME] = { .type = RFC5497_MSGTLV_VALIDITY_TIME,
    .type_ext = 0,
    .match_type_ext = true,
    .mandatory = true,
    .min_length = 1,
    .max_length = 65535,
    .match_length = true },
  [IDX_TLV_ITIME] = { .type = RFC5497_MSGTLV_INTERVAL_TIME,
    .type_ext = 0,
    .match_type_ext = true,
    .min_length = 1,
    .max_length = 65535,
    .match_length = true },
  [IDX_TLV_WILLINGNESS] = { .type = RFC7181_MSGTLV_MPR_WILLING,
    .type_ext = 0,
    .match_type_ext = true,
    .min_length = 1,
    .max_length = 65535,
    .match_length = true },
  [IDX_TLV_MPRTYPES] = { .type = RFC7722_MSGTLV_MPR_TYPES,
    .type_ext = RFC7722_MSGTLV_MPR_TYPES_EXT,
    .match_type_ext = true,
    .min_length = 1,
    .max_length = NHDP_MAXIMUM_DOMAINS,
    .match_length = true },
  [IDX_TLV_IPV4ORIG] = { .type = NHDP_MSGTLV_IPV4ORIGINATOR,
    .type_ext = 0,
    .match_type_ext = true,
    .min_length = 4,
    .match_length = true },
  [IDX_TLV_MAC] =
    { .type = NHDP_MSGTLV_MAC, .type_ext = 0, .match_type_ext = true, .min_length = 6, .match_length = true },
};

static struct rfc5444_reader_tlvblock_consumer _nhdp_address_pass1_consumer = {
  .order = RFC5444_MAIN_PARSER_PRIORITY,
  .msg_id = RFC6130_MSGTYPE_HELLO,
  .addrblock_consumer = true,
  .block_callback = _cb_addresstlvs_pass1,
  .block_callback_failed_constraints = _cb_failed_constraints,
};

static struct rfc5444_reader_tlvblock_consumer_entry _nhdp_address_pass1_tlvs[] = {
  [IDX_ADDRTLV1_LOCAL_IF] = { .type = RFC6130_ADDRTLV_LOCAL_IF,
    .type_ext = 0,
    .match_type_ext = true,
    .min_length = 1,
    .max_length = 65535,
    .match_length = true },
  [IDX_ADDRTLV1_LINK_STATUS] = { .type = RFC6130_ADDRTLV_LINK_STATUS,
    .type_ext = 0,
    .match_type_ext = true,
    .min_length = 1,
    .max_length = 65535,
    .match_length = true },
};

static struct rfc5444_reader_tlvblock_consumer _nhdp_message_pass2_consumer = {
  .order = RFC5444_MAIN_PARSER_PRIORITY + 1,
  .msg_id = RFC6130_MSGTYPE_HELLO,
  .end_callback = _cb_msg_pass2_end,
  .block_callback_failed_constraints = _cb_failed_constraints,
};

static struct rfc5444_reader_tlvblock_consumer _nhdp_address_pass2_consumer = {
  .order = RFC5444_MAIN_PARSER_PRIORITY + 1,
  .msg_id = RFC6130_MSGTYPE_HELLO,
  .addrblock_consumer = true,
  .block_callback = _cb_addr_pass2_block,
  .block_callback_failed_constraints = _cb_failed_constraints,
};

static struct rfc5444_reader_tlvblock_consumer_entry _nhdp_address_pass2_tlvs[] = {
  [IDX_ADDRTLV2_LOCAL_IF] = { .type = RFC6130_ADDRTLV_LOCAL_IF,
    .type_ext = 0,
    .match_type_ext = true,
    .min_length = 1,
    .max_length = 65535,
    .match_length = true },
  [IDX_ADDRTLV2_LINK_STATUS] = { .type = RFC6130_ADDRTLV_LINK_STATUS,
    .type_ext = 0,
    .match_type_ext = true,
    .min_length = 1,
    .max_length = 65535,
    .match_length = true },
  [IDX_ADDRTLV2_OTHER_NEIGHB] = { .type = RFC6130_ADDRTLV_OTHER_NEIGHB,
    .type_ext = 0,
    .match_type_ext = true,
    .min_length = 1,
    .max_length = 65535,
    .match_length = true },
  [IDX_ADDRTLV2_MPR] = { .type = RFC7181_ADDRTLV_MPR, .min_length = 1, .max_length = 65535, .match_length = true },
  [IDX_ADDRTLV2_LINKMETRIC] = { .type = RFC7181_ADDRTLV_LINK_METRIC, .min_length = 2, .match_length = true },
};

/* nhdp multiplexer/protocol */
static struct oonf_rfc5444_protocol *_protocol = NULL;

/* temporary variables for message parsing */
static struct {
  struct nhdp_interface *localif;
  struct nhdp_neighbor *neighbor;

  struct nhdp_link *link;

  struct netaddr originator_v4;
  struct netaddr mac;

  bool naddr_conflict, laddr_conflict;
  bool link_heard, link_lost;
  bool has_thisif;

  bool originator_in_addrblk;
  uint64_t vtime, itime;

  uint8_t mprtypes[NHDP_MAXIMUM_DOMAINS];
  size_t mprtypes_size;
} _current;

/**
 * Initialize nhdp reader
 * @param p rfc5444 protocol
 */
void
nhdp_reader_init(struct oonf_rfc5444_protocol *p) {
  _protocol = p;

  rfc5444_reader_add_message_consumer(
    &_protocol->reader, &_nhdp_message_pass1_consumer, _nhdp_message_tlvs, ARRAYSIZE(_nhdp_message_tlvs));
  rfc5444_reader_add_message_consumer(
    &_protocol->reader, &_nhdp_address_pass1_consumer, _nhdp_address_pass1_tlvs, ARRAYSIZE(_nhdp_address_pass1_tlvs));
  rfc5444_reader_add_message_consumer(&_protocol->reader, &_nhdp_message_pass2_consumer, NULL, 0);
  rfc5444_reader_add_message_consumer(
    &_protocol->reader, &_nhdp_address_pass2_consumer, _nhdp_address_pass2_tlvs, ARRAYSIZE(_nhdp_address_pass2_tlvs));
}

/**
 * Cleanup nhdp reader
 */
void
nhdp_reader_cleanup(void) {
  rfc5444_reader_remove_message_consumer(&_protocol->reader, &_nhdp_address_pass2_consumer);
  rfc5444_reader_remove_message_consumer(&_protocol->reader, &_nhdp_message_pass2_consumer);
  rfc5444_reader_remove_message_consumer(&_protocol->reader, &_nhdp_address_pass1_consumer);
  rfc5444_reader_remove_message_consumer(&_protocol->reader, &_nhdp_message_pass1_consumer);
}

/**
 * An error happened during processing and the message was dropped.
 * Make sure that there are no uninitialized datastructures left.
 */
static void
_cleanup_error(void) {
  if (_current.link) {
    nhdp_db_link_remove(_current.link);
    _current.link = NULL;
  }

  if (_current.neighbor) {
    nhdp_db_neighbor_remove(_current.neighbor);
    _current.neighbor = NULL;
  }
}

/**
 * Process an address with a LOCAL_IF TLV
 * @param addr pointer to netaddr object with address
 * @param local_if value of LOCAL_IF TLV
 * @return RFC5444 processing result
 */
static enum rfc5444_result
_pass2_process_localif(struct netaddr *addr, uint8_t local_if) {
  struct nhdp_neighbor *neigh;
  struct nhdp_naddr *naddr;
  struct nhdp_link *lnk;
  struct nhdp_laddr *laddr;

  /* make sure link addresses are added to the right link */
  if (local_if == RFC6130_LOCALIF_THIS_IF) {
    laddr = nhdp_interface_get_link_addr(_current.localif, addr);
    if (laddr == NULL) {
      /* create new link address */
      laddr = nhdp_db_link_addr_add(_current.link, addr);
      if (laddr == NULL) {
        return RFC5444_DROP_MESSAGE;
      }
    }
    else {
      /* move to target link if necessary */
      lnk = laddr->link;
      lnk->_process_count--;

      if (lnk != _current.link) {
        nhdp_db_link_addr_move(_current.link, laddr);

        if (lnk->_process_count == 0) {
          /* no address left to process, remove old link */
          nhdp_db_link_remove(lnk);
        }
      }

      /* remove mark from address */
      laddr->_might_be_removed = false;
    }
  }

  /* make sure neighbor addresses are added to the right neighbor */
  naddr = nhdp_db_neighbor_addr_get(addr);
  if (naddr == NULL) {
    /* create new neighbor address */
    naddr = nhdp_db_neighbor_addr_add(_current.neighbor, addr);
    if (naddr == NULL) {
      return RFC5444_DROP_MESSAGE;
    }
  }
  else {
    /* move to target neighbor if necessary */
    neigh = naddr->neigh;
    neigh->_process_count--;

    if (neigh != _current.neighbor) {
      nhdp_db_neighbor_addr_move(_current.neighbor, naddr);

      if (neigh->_process_count == 0) {
        /* no address left to process, remove old neighbor */
        nhdp_db_neighbor_remove(neigh);
      }
    }

    /* remove mark from address */
    naddr->_might_be_removed = false;

    /* mark as not lost */
    nhdp_db_neighbor_addr_not_lost(naddr);
  }

  return RFC5444_OKAY;
}

/**
 * Handle in originator address of NHDP Hello
 */
static void
_handle_originator(struct rfc5444_reader_tlvblock_context *context) {
  struct nhdp_neighbor *neigh;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  OONF_DEBUG(LOG_NHDP_R, "Handle originator %s", netaddr_to_string(&buf, &context->orig_addr));

  neigh = nhdp_db_neighbor_get_by_originator(&context->orig_addr);
  if (!neigh) {
    return;
  }

  if (_current.neighbor == neigh) {
    /* everything is fine, move along */
    return;
  }

  if (_current.neighbor == NULL && !_current.naddr_conflict) {
    /* we take the neighbor selected by the originator */
    _current.neighbor = neigh;
    return;
  }

  if (neigh->_process_count > 0) {
    /* neighbor selected by originator will already be cleaned up */
    return;
  }

  nhdp_db_neighbor_set_originator(neigh, &NETADDR_UNSPEC);
}

/**
 * Handle in HELLO messages and its TLVs
 * @param context tlvblock reader context
 * @return see rfc5444_result enum
 */
static enum rfc5444_result
_cb_messagetlvs(struct rfc5444_reader_tlvblock_context *context) {
  struct rfc5444_reader_tlvblock_entry *tlv;
  struct nhdp_neighbor *neigh;
  struct nhdp_link *lnk;
  int af_type;
#ifdef OONF_LOG_INFO
  struct netaddr_str buf;
#endif

  /*
   * First remove all old session data.
   * Do not put anything that could drop a session before this point,
   * otherwise the cleanup path will run on an outdated session object.
   */
  memset(&_current, 0, sizeof(_current));

  OONF_INFO(LOG_NHDP_R, "Incoming message type %d from %s through %s (addrlen = %u), got message tlvs",
    context->msg_type, netaddr_socket_to_string(&buf, _protocol->input.src_socket), _protocol->input.interface->name,
    context->addr_len);

  switch (context->addr_len) {
    case 4:
      af_type = AF_INET;
      break;
    case 16:
      af_type = AF_INET6;
      break;
    default:
      af_type = 0;
      break;
  }

  if (!oonf_rfc5444_is_interface_active(_protocol->input.interface, af_type)) {
    OONF_DEBUG(LOG_NHDP_R, "We do not handle address length %u on interface %s", context->addr_len,
      _protocol->input.interface->name);
    return RFC5444_DROP_MESSAGE;
  }

  /* remember local NHDP interface */
  _current.localif = nhdp_interface_get(_protocol->input.interface->name);
  if (!_current.localif) {
    /* incoming message through an interface unspecific socket, ignore it */
    return RFC5444_DROP_MESSAGE;
  }

  /* extract originator address */
  if (context->has_origaddr) {
    OONF_DEBUG(LOG_NHDP_R, "Got originator: %s", netaddr_to_string(&buf, &context->orig_addr));
  }

  /*
   * extract validity time and interval time, no vector possible because
   * HELLO is always single-hop
   */
  tlv = _nhdp_message_tlvs[IDX_TLV_VTIME].tlv;
  _current.vtime = rfc5497_timetlv_decode(tlv->single_value[0]);

  if (_nhdp_message_tlvs[IDX_TLV_ITIME].tlv) {
    tlv = _nhdp_message_tlvs[IDX_TLV_ITIME].tlv;
    _current.itime = rfc5497_timetlv_decode(tlv->single_value[0]);
  }

  /* extract mpr types for MT implementation */
  _current.mprtypes_size = nhdp_domain_process_mprtypes_tlv(
    _current.mprtypes, sizeof(_current.mprtypes), _nhdp_message_tlvs[IDX_TLV_MPRTYPES].tlv);

  /* extract willingness into temporary buffers */
  nhdp_domain_process_willingness_tlv(
    _current.mprtypes, _current.mprtypes_size, _nhdp_message_tlvs[IDX_TLV_WILLINGNESS].tlv);

  /* extract v4 originator in dualstack messages */
  if (_nhdp_message_tlvs[IDX_TLV_IPV4ORIG].tlv) {
    if (netaddr_from_binary(
          &_current.originator_v4, _nhdp_message_tlvs[IDX_TLV_IPV4ORIG].tlv->single_value, 4, AF_INET)) {
      /* error, could not parse address */
      return RFC5444_DROP_MESSAGE;
    }

    OONF_DEBUG(LOG_NHDP_R, "Got originator: %s", netaddr_to_string(&buf, &_current.originator_v4));
  }

  /* extract mac address if present */
  if (_nhdp_message_tlvs[IDX_TLV_MAC].tlv) {
    if (netaddr_from_binary(&_current.mac, _nhdp_message_tlvs[IDX_TLV_MAC].tlv->single_value, 6, AF_MAC48)) {
      /* error, could not parse address */
      return RFC5444_DROP_MESSAGE;
    }
  }

  /* clear flags in neighbors */
  list_for_each_element(nhdp_db_get_neigh_list(), neigh, _global_node) {
    neigh->_process_count = 0;
  }

  list_for_each_element(&_current.localif->_links, lnk, _if_node) {
    lnk->_process_count = 0;
  }

  return RFC5444_OKAY;
}

/**
 * Called if the constraints for the tlv block are not valid
 * @param context tlv block reader context
 * @return see rfc5444_result enum
 */
static enum rfc5444_result
_cb_failed_constraints(struct rfc5444_reader_tlvblock_context *context __attribute__((unused))) {
#ifdef OONF_LOG_INFO
  struct netaddr_str nbuf;
#endif

  OONF_INFO(LOG_NHDP_R, "Incoming message type %d from %s through %s (addrlen = %u) failed constraints",
    context->msg_type, netaddr_socket_to_string(&nbuf, _protocol->input.src_socket), _protocol->input.interface->name,
    context->addr_len);
  return RFC5444_DROP_MESSAGE;
}

/**
 * Process addresses of NHDP Hello message to determine link/neighbor status
 * @param context tlv block reader context
 * @return see rfc5444_result enum
 */
static enum rfc5444_result
_cb_addresstlvs_pass1(struct rfc5444_reader_tlvblock_context *context) {
  uint8_t local_if, link_status;
  struct nhdp_naddr *naddr;
  struct nhdp_laddr *laddr;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  local_if = 255;
  link_status = 255;

  if (_nhdp_address_pass1_tlvs[IDX_ADDRTLV1_LOCAL_IF].tlv) {
    local_if = _nhdp_address_pass1_tlvs[IDX_ADDRTLV1_LOCAL_IF].tlv->single_value[0];
    local_if &= RFC6130_LOCALIF_BITMASK;
  }
  if (_nhdp_address_pass1_tlvs[IDX_ADDRTLV1_LINK_STATUS].tlv) {
    link_status = _nhdp_address_pass1_tlvs[IDX_ADDRTLV1_LINK_STATUS].tlv->single_value[0];
    link_status &= RFC6130_LINKSTATUS_BITMASK;
  }

  OONF_DEBUG(LOG_NHDP_R, "Pass 1: address %s, local_if %u, link_status: %u", netaddr_to_string(&nbuf, &context->addr),
    local_if, link_status);

  if (context->has_origaddr && !_current.originator_in_addrblk &&
      netaddr_cmp(&context->addr, &context->orig_addr) == 0) {
    /* originator is inside address block, prevent using it */
    _current.originator_in_addrblk = true;
  }

  if (local_if == RFC6130_LOCALIF_THIS_IF || local_if == RFC6130_LOCALIF_OTHER_IF) {
    /* still no neighbor address conflict, so keep checking */
    naddr = nhdp_db_neighbor_addr_get(&context->addr);
    if (naddr != NULL) {
      OONF_DEBUG(LOG_NHDP_R, "Found neighbor in database");
      naddr->neigh->_process_count++;

      if (!_current.naddr_conflict) {
        if (_current.neighbor == NULL) {
          /* first neighbor, just remember it */
          _current.neighbor = naddr->neigh;
        }
        else if (_current.neighbor != naddr->neigh) {
          /* this is a neighbor address conflict */
          OONF_DEBUG(LOG_NHDP_R, "Conflict between neighbor addresses detected");
          _current.neighbor = NULL;
          _current.naddr_conflict = true;
        }
      }
    }
  }

  if (local_if == RFC6130_LOCALIF_THIS_IF) {
    /* check for link address conflict */
    laddr = nhdp_interface_get_link_addr(_current.localif, &context->addr);
    if (laddr != NULL) {
      OONF_DEBUG(LOG_NHDP_R, "Found link in database");
      laddr->link->_process_count++;

      if (!_current.laddr_conflict) {
        if (_current.link == NULL) {
          /* first link, just remember it */
          _current.link = laddr->link;
        }
        else if (_current.link != laddr->link) {
          /* this is a link address conflict */
          OONF_DEBUG(LOG_NHDP_R, "Conflict between link addresses detected");
          _current.link = NULL;
          _current.laddr_conflict = true;
        }
      }
    }

    /* remember that we had a local_if = THIS_IF address */
    _current.has_thisif = true;
  }

  /* detect if our own node is seen by our neighbor */
  if (link_status != 255 && nhdp_interface_addr_if_get(_current.localif, &context->addr) != NULL) {
    if (link_status == RFC6130_LINKSTATUS_LOST) {
      OONF_DEBUG(LOG_NHDP_R, "Link neighbor lost this node address: %s", netaddr_to_string(&nbuf, &context->addr));
      _current.link_lost = true;
    }
    else {
      OONF_DEBUG(LOG_NHDP_R, "Link neighbor heard this node address: %s", netaddr_to_string(&nbuf, &context->addr));
      _current.link_heard = true;
    }
  }

  /* we do nothing in this pass except for detecting the situation */
  return RFC5444_OKAY;
}

/**
 * Handle end of message for pass1 processing. Create link/neighbor if necessary,
 * mark addresses as potentially lost.
 * @param context tlv block reader context
 * @param dropped true if block was dropped by another callback
 * @return see rfc5444_result enum
 */
static enum rfc5444_result
_cb_addresstlvs_pass1_end(struct rfc5444_reader_tlvblock_context *context, bool dropped) {
  struct nhdp_naddr *naddr;
  struct nhdp_laddr *laddr;

  if (dropped) {
    _cleanup_error();
    return RFC5444_OKAY;
  }

  /* handle originator address */
  if (context->has_origaddr && !_current.originator_in_addrblk &&
      netaddr_get_address_family(&context->orig_addr) != AF_UNSPEC) {
    _handle_originator(context);
  }

  /* allocate neighbor and link if necessary */
  if (_current.neighbor == NULL) {
    OONF_DEBUG(LOG_NHDP_R, "Create new neighbor");
    _current.neighbor = nhdp_db_neighbor_add();
    if (_current.neighbor == NULL) {
      return RFC5444_DROP_MESSAGE;
    }
  }
  else {
    /* mark existing neighbor addresses */
    avl_for_each_element(&_current.neighbor->_neigh_addresses, naddr, _neigh_node) {
      if (netaddr_get_binlength(&naddr->neigh_addr) == context->addr_len) {
        naddr->_might_be_removed = true;
      }
    }
  }

  /* allocate link if necessary */
  if (_current.link == NULL) {
    OONF_DEBUG(LOG_NHDP_R, "Create new link");
    _current.link = nhdp_db_link_add(_current.neighbor, _current.localif);
    if (_current.link == NULL) {
      return RFC5444_DROP_MESSAGE;
    }
  }
  else {
    /* mark existing link addresses */
    avl_for_each_element(&_current.link->_addresses, laddr, _link_node) {
      laddr->_might_be_removed = true;
    }
  }

  /* copy interface address of link */
  memcpy(&_current.link->if_addr, _protocol->input.src_address, sizeof(struct netaddr));

  /* copy mac address */
  if (netaddr_get_address_family(&_current.mac) == AF_MAC48) {
    memcpy(&_current.link->remote_mac, &_current.mac, sizeof(_current.mac));
  }

  if (!_current.has_thisif) {
    struct netaddr addr;

    /* translate like a RFC5444 address */
    if (netaddr_from_binary(&addr, netaddr_get_binptr(_protocol->input.src_address),
          netaddr_get_binlength(_protocol->input.src_address), 0)) {
      return RFC5444_DROP_MESSAGE;
    }

    /* parse as if it would be tagged with a LOCAL_IF = THIS_IF TLV */
    _pass2_process_localif(&addr, RFC6130_LOCALIF_THIS_IF);
  }

  /* remember vtime and itime */
  _current.link->vtime_value = _current.vtime;
  _current.link->itime_value = _current.itime;

  /* update hysteresis */
  nhdp_hysteresis_update(_current.link, context);

  /* handle dualstack information */
  if (context->has_origaddr) {
    if (netaddr_get_address_family(&_current.originator_v4) != AF_UNSPEC) {
      struct nhdp_neighbor *neigh2;
      struct nhdp_link *lnk2;

      neigh2 = nhdp_db_neighbor_get_by_originator(&_current.originator_v4);
      if (neigh2) {
        nhdp_db_neighbor_connect_dualstack(_current.neighbor, neigh2);
      }

      lnk2 = nhdp_interface_link_get_by_originator(_current.localif, &_current.originator_v4);
      if (lnk2) {
        nhdp_db_link_connect_dualstack(_current.link, lnk2);
      }
    }
    else if (netaddr_get_address_family(&context->orig_addr) == AF_INET6 &&
             netaddr_get_address_family(&_current.originator_v4) == AF_UNSPEC) {
      nhdp_db_neigbor_disconnect_dualstack(_current.neighbor);
      nhdp_db_link_disconnect_dualstack(_current.link);
    }
  }

  OONF_DEBUG(LOG_NHDP_R, "pass1 finished");

  return RFC5444_OKAY;
}

/**
 * Process MPR, Willingness and Linkmetric TLVs for local neighbor
 * @param addr address the TLVs are attached to
 */
static void
_process_domainspecific_linkdata(struct netaddr *addr __attribute__((unused))) {
  struct rfc5444_reader_tlvblock_entry *tlv;
  struct nhdp_domain *domain;
  struct nhdp_neighbor_domaindata *neighdata;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif
  /*
   * clear routing mpr, willingness and metric values
   * that should be present in HELLO
   */
  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    neighdata = nhdp_domain_get_neighbordata(domain, _current.neighbor);

    neighdata->local_is_mpr = false;
    neighdata->willingness = 0;
    nhdp_domain_get_linkdata(domain, _current.link)->metric.out = RFC7181_METRIC_INFINITE;
    neighdata->metric.out = RFC7181_METRIC_INFINITE;
  }

  /* process MPR settings of link */
  nhdp_domain_process_mpr_tlv(
    _current.mprtypes, _current.mprtypes_size, _current.link, _nhdp_address_pass2_tlvs[IDX_ADDRTLV2_MPR].tlv);

  /* update out metric with other sides in metric */
  tlv = _nhdp_address_pass2_tlvs[IDX_ADDRTLV2_LINKMETRIC].tlv;
  while (tlv) {
    /* get metric handler */
    domain = nhdp_domain_get_by_ext(tlv->type_ext);
    if (domain != NULL && !domain->metric->no_default_handling) {
      nhdp_domain_process_metric_linktlv(domain, _current.link, tlv->single_value);

      /* extract tlv value */
      OONF_DEBUG(LOG_NHDP_R, "Pass 2: address %s, LQ (ext %u): %02x%02x", netaddr_to_string(&buf, addr), tlv->type_ext,
        tlv->single_value[0], tlv->single_value[1]);
    }

    tlv = tlv->next_entry;
  }
}

/**
 * Process Linkmetric TLVs for twohop neighbor
 * @param l2hop pointer to twohop neighbor
 * @param addr address the TLVs are attached to
 */
static void
_process_domainspecific_2hopdata(struct nhdp_l2hop *l2hop, struct netaddr *addr __attribute__((unused))) {
  struct rfc5444_reader_tlvblock_entry *tlv;
  struct nhdp_domain *domain;
  struct nhdp_l2hop_domaindata *data;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  /* clear metric values that should be present in HELLO */
  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    if (!domain->metric->no_default_handling) {
      data = nhdp_domain_get_l2hopdata(domain, l2hop);
      data->metric.in = RFC7181_METRIC_INFINITE;
      data->metric.out = RFC7181_METRIC_INFINITE;
    }
  }

  /* update 2-hop metric (no direction reversal!) */
  tlv = _nhdp_address_pass2_tlvs[IDX_ADDRTLV2_LINKMETRIC].tlv;
  while (tlv) {
    /* get metric handler */
    domain = nhdp_domain_get_by_ext(tlv->type_ext);
    if (domain != NULL && !domain->metric->no_default_handling) {
      nhdp_domain_process_metric_2hoptlv(domain, l2hop, tlv->single_value);

      OONF_DEBUG(LOG_NHDP_R, "Pass 2: address %s, LQ (ext %u): %02x%02x", netaddr_to_string(&buf, addr), tlv->type_ext,
        tlv->single_value[0], tlv->single_value[1]);
    }

    tlv = tlv->next_entry;
  }
}

/**
 * Second pass for processing the addresses of the NHDP Hello. This one will update
 * the database
 * @param context tlv block reader context
 * @return see rfc5444_result enum
 */
static enum rfc5444_result
_cb_addr_pass2_block(struct rfc5444_reader_tlvblock_context *context) {
  uint8_t local_if, link_status, other_neigh;
  struct nhdp_l2hop *l2hop;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  local_if = 255;
  link_status = 255;
  other_neigh = 255;

  /* read values of TLVs that can only be present once */
  if (_nhdp_address_pass2_tlvs[IDX_ADDRTLV2_LOCAL_IF].tlv) {
    local_if = _nhdp_address_pass2_tlvs[IDX_ADDRTLV2_LOCAL_IF].tlv->single_value[0];
    local_if &= RFC6130_LOCALIF_BITMASK;
  }
  if (_nhdp_address_pass2_tlvs[IDX_ADDRTLV2_LINK_STATUS].tlv) {
    link_status = _nhdp_address_pass2_tlvs[IDX_ADDRTLV2_LINK_STATUS].tlv->single_value[0];
    link_status &= RFC6130_LINKSTATUS_BITMASK;
  }
  if (_nhdp_address_pass2_tlvs[IDX_ADDRTLV2_OTHER_NEIGHB].tlv) {
    other_neigh = _nhdp_address_pass2_tlvs[IDX_ADDRTLV2_OTHER_NEIGHB].tlv->single_value[0];
    other_neigh &= RFC6130_OTHERNEIGHB_SYMMETRIC;
  }
  OONF_DEBUG(LOG_NHDP_R, "Pass 2: address %s, local_if %u, link_status: %u, other_neigh: %u",
    netaddr_to_string(&buf, &context->addr), local_if, link_status, other_neigh);

  if (local_if == RFC6130_LOCALIF_THIS_IF || local_if == RFC6130_LOCALIF_OTHER_IF) {
    /* parse LOCAL_IF TLV */
    _pass2_process_localif(&context->addr, local_if);
  }

  /* handle 2hop-addresses */
  if (link_status != 255 || other_neigh != 255) {
    if (nhdp_interface_addr_if_get(_current.localif, &context->addr) != NULL) {
      _process_domainspecific_linkdata(&context->addr);
    }
    else if (nhdp_interface_addr_global_get(&context->addr) != NULL) {
      OONF_DEBUG(LOG_NHDP_R, "Link neighbor heard this node address: %s", netaddr_to_string(&buf, &context->addr));
    }
    else if (link_status == RFC6130_LINKSTATUS_SYMMETRIC || other_neigh == RFC6130_OTHERNEIGHB_SYMMETRIC) {
      l2hop = ndhp_db_link_2hop_get(_current.link, &context->addr);
      if (l2hop == NULL) {
        /* create new 2hop address */
        l2hop = nhdp_db_link_2hop_add(_current.link, &context->addr);
        if (l2hop == NULL) {
          return RFC5444_DROP_MESSAGE;
        }
      }

      /* remember if 2hop is same interface */
      l2hop->same_interface = link_status == RFC6130_LINKSTATUS_SYMMETRIC;

      /* refresh validity time of 2hop address */
      nhdp_db_link_2hop_set_vtime(l2hop, _current.vtime);

      _process_domainspecific_2hopdata(l2hop, &context->addr);
    }
    else {
      l2hop = ndhp_db_link_2hop_get(_current.link, &context->addr);
      if (l2hop) {
        /* remove 2hop address */
        nhdp_db_link_2hop_remove(l2hop);
      }
    }
  }

  return RFC5444_OKAY;
}

/**
 * Finalize changes of the database and update the status of the link
 * @param context tlv block reader context
 * @param dropped true if context was dropped by a callback
 * @return see rfc5444_result enum
 */
static enum rfc5444_result
_cb_msg_pass2_end(struct rfc5444_reader_tlvblock_context *context, bool dropped) {
  struct nhdp_naddr *naddr;
  struct nhdp_laddr *laddr, *la_it;
  struct nhdp_l2hop *twohop, *twohop_it;
  uint64_t t;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  if (dropped) {
    _cleanup_error();
    return RFC5444_OKAY;
  }

  /* remove leftover link addresses */
  avl_for_each_element_safe(&_current.link->_addresses, laddr, _link_node, la_it) {
    if (laddr->_might_be_removed) {
      nhdp_db_link_addr_remove(laddr);
    }
  }

  /* remove leftover neighbor addresses */
  avl_for_each_element(&_current.neighbor->_neigh_addresses, naddr, _neigh_node) {
    if (naddr->_might_be_removed) {
      /* mark as lost */
      nhdp_db_neighbor_addr_set_lost(naddr, _current.localif->n_hold_time);

      /* section 12.6.1: remove all similar n2 addresses */
      // TODO: not nice, replace with new iteration macro
      twohop_it = avl_find_element(&_current.link->_2hop, &naddr->neigh_addr, twohop_it, _link_node);
      while (twohop_it) {
        twohop = twohop_it;
        twohop_it = avl_next_element_safe(&_current.link->_2hop, twohop_it, _link_node);
        if (twohop_it != NULL && !twohop_it->_link_node.follower) {
          twohop_it = NULL;
        }

        nhdp_db_link_2hop_remove(twohop);
      }
    }
  }

  /* Section 12.5.4: update link */
  if (_current.link_heard) {
    /* Section 12.5.4.1.1: we have been heard, so the link is symmetric */
    nhdp_db_link_set_symtime(_current.link, _current.vtime);

    OONF_DEBUG(LOG_NHDP_R, "Reset link timer for link to %s to %" PRIu64,
      netaddr_to_string(&nbuf, &_current.link->if_addr), _current.vtime);
  }
  else if (_current.link_lost) {
    /* Section 12.5.4.1.2 */
    if (oonf_timer_is_active(&_current.link->sym_time)) {
      OONF_DEBUG(LOG_NHDP_R, "Stop link timer for link to %s", netaddr_to_string(&nbuf, &_current.link->if_addr));

      oonf_timer_stop(&_current.link->sym_time);

      /*
       * the stop timer might have modified to link status, but do not trigger
       * cleanup until this processing is over
       */
      if (_nhdp_db_link_calculate_status(_current.link) == RFC6130_LINKSTATUS_HEARD) {
        nhdp_db_link_set_vtime(_current.link, _current.localif->l_hold_time);
      }
    }
  }

  /* Section 12.5.4.3 */
  t = oonf_timer_get_due(&_current.link->sym_time);
  if (!oonf_timer_is_active(&_current.link->sym_time) || t < _current.vtime) {
    t = _current.vtime;
  }
  oonf_timer_set(&_current.link->heard_time, t);

  /* Section 12.5.4.4: link status pending is not influenced by the code above */
  if (_current.link->status != NHDP_LINK_PENDING) {
    t += _current.localif->l_hold_time;
  }

  /* Section 12.5.4.5 */
  if (!oonf_timer_is_active(&_current.link->vtime) || (int64_t)t > oonf_timer_get_due(&_current.link->vtime)) {
    oonf_timer_set(&_current.link->vtime, t);
  }

  /* overwrite originator of neighbor entry */
  nhdp_db_neighbor_set_originator(_current.neighbor, &context->orig_addr);

  /* copy willingness to permanent storage */
  nhdp_domain_store_willingness(_current.link);

  /* update ip flooding settings */
  nhdp_interface_update_status(_current.localif);

  /* update link status */
  nhdp_db_link_update_status(_current.link);

  /* update link metrics and MPR */
  nhdp_domain_recalculate_metrics(NULL, _current.neighbor, false);
  nhdp_domain_delayed_mpr_recalculation(NULL, _current.neighbor);

  return RFC5444_OKAY;
}
