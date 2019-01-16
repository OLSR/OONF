
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

/*
 * Much of the code of this file originally came from the iw userspace
 * command source code and was adapted for OLSRv2.
 *
 * Copyright (c) 2007, 2008 Johannes Berg
 * Copyright (c) 2007    Andy Lutomirski
 * Copyright (c) 2007    Mike Kershaw
 * Copyright (c) 2008-2009   Luis R. Rodriguez
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _GNU_SOURCE

/* must be first because of a problem with linux/netlink.h */
#include <sys/socket.h>

/* and now the rest of the includes */
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>

#include <oonf/oonf.h>
#include <oonf/base/oonf_clock.h>
#include <oonf/base/os_system.h>

#include <oonf/generic/nl80211_listener/nl80211.h>
#include <oonf/generic/nl80211_listener/nl80211_get_station_dump.h>
#include <oonf/generic/nl80211_listener/nl80211_internal.h>
#include <oonf/generic/nl80211_listener/nl80211_listener.h>

static bool _handle_traffic(struct oonf_layer2_neigh *l2neigh, enum oonf_layer2_neighbor_index idx, uint32_t new_32bit);
static int64_t _get_bitrate(struct nlattr *bitrate_attr);

/**
 * Send a netlink message to get the nl80211 station dump
 * @param nl pointer to netlink handler
 * @param nl_msg pointer to netlink message
 * @param hdr pointer to generic netlink header
 * @param interf nl80211 listener interface
 */
void
nl80211_send_get_station_dump(
  struct os_system_netlink_message *nl_msg, struct genlmsghdr *hdr, struct nl80211_if *interf) {
  int if_index = nl80211_get_if_baseindex(interf);

  hdr->cmd = NL80211_CMD_GET_STATION;
  nl_msg->message->nlmsg_flags |= NLM_F_DUMP;

  /* add interface index to the request */
  os_system_linux_netlink_addreq(nl_msg, NL80211_ATTR_IFINDEX, &if_index, sizeof(if_index));
}

/**
 * Process NL80211_CMD_NEW_STATION message
 * @param interf nl80211 listener interface
 * @param hdr pointer to netlink message header
 */
void
nl80211_process_get_station_dump_result(struct nl80211_if *interf, struct nlmsghdr *hdr) {
  struct oonf_layer2_neigh *l2neigh;
  struct netaddr l2neigh_mac;

  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh;
  struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
  static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
    [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
    [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
    [NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
    [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_TX_RETRIES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
    [NL80211_STA_INFO_STA_FLAGS] = { .minlen = sizeof(struct nl80211_sta_flag_update) },
  };
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  gnlh = nlmsg_data(hdr);

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

  if (!tb[NL80211_ATTR_STA_INFO]) {
    /* station info missing */
    return;
  }
  if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], stats_policy)) {
    /* no nested attributes */
    return;
  }

  if (nl80211_get_if_baseindex(interf) != nla_get_u32(tb[NL80211_ATTR_IFINDEX])) {
    /* wrong interface */
    return;
  }

  netaddr_from_binary(&l2neigh_mac, nla_data(tb[NL80211_ATTR_MAC]), 6, AF_MAC48);

  OONF_DEBUG(LOG_NL80211, "Received Station Dump for %s", netaddr_to_string(&nbuf, &l2neigh_mac));

  l2neigh = oonf_layer2_neigh_add(interf->l2net, &l2neigh_mac);
  if (!l2neigh) {
    /* no memory for l2 neighbor */
    return;
  }

  if (sinfo[NL80211_STA_INFO_INACTIVE_TIME]) {
    oonf_layer2_neigh_set_lastseen(l2neigh,
        oonf_clock_get_absolute(-((int64_t)(nla_get_u32(sinfo[NL80211_STA_INFO_INACTIVE_TIME])))));
  }

  /* byte data is 64 bit */
  if (sinfo[NL80211_STA_INFO_RX_BYTES64]) {
    nl80211_change_l2neigh_data(l2neigh, OONF_LAYER2_NEIGH_RX_BYTES, nla_get_u64(sinfo[NL80211_STA_INFO_RX_BYTES64]),1 );
  }
  if (sinfo[NL80211_STA_INFO_TX_BYTES64]) {
    nl80211_change_l2neigh_data(l2neigh, OONF_LAYER2_NEIGH_TX_BYTES, nla_get_u64(sinfo[NL80211_STA_INFO_TX_BYTES64]), 1);
  }

  /* packet data is only 32 bit */
  if (sinfo[NL80211_STA_INFO_RX_PACKETS]) {
    _handle_traffic(l2neigh, OONF_LAYER2_NEIGH_RX_FRAMES, nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]));
  }
  if (sinfo[NL80211_STA_INFO_TX_PACKETS]) {
    _handle_traffic(l2neigh, OONF_LAYER2_NEIGH_TX_FRAMES, nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]));
  }
  if (sinfo[NL80211_STA_INFO_TX_RETRIES]) {
    _handle_traffic(l2neigh, OONF_LAYER2_NEIGH_TX_RETRIES, nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]));
  }
  if (sinfo[NL80211_STA_INFO_TX_FAILED]) {
    _handle_traffic(l2neigh, OONF_LAYER2_NEIGH_TX_FAILED, nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]));
  }

  /* bitrates are special */
  if (sinfo[NL80211_STA_INFO_TX_BITRATE]) {
    int64_t rate = _get_bitrate(sinfo[NL80211_STA_INFO_TX_BITRATE]);
    if (rate) {
      nl80211_change_l2neigh_data(l2neigh, OONF_LAYER2_NEIGH_TX_BITRATE, rate, 1);
    }
  }
  if (sinfo[NL80211_STA_INFO_RX_BITRATE]) {
    int64_t rate = _get_bitrate(sinfo[NL80211_STA_INFO_RX_BITRATE]);
    if (rate) {
      nl80211_change_l2neigh_data(l2neigh, OONF_LAYER2_NEIGH_RX_BITRATE, rate, 1);
    }
  }

  /* expected throughput is special too */
  if (sinfo[NL80211_STA_INFO_EXPECTED_THROUGHPUT]) {
    int64_t rate;

    rate = nla_get_u32(sinfo[NL80211_STA_INFO_EXPECTED_THROUGHPUT]);

    /* convert in bps */
    nl80211_change_l2neigh_data(l2neigh, OONF_LAYER2_NEIGH_TX_THROUGHPUT, rate * 1024ll, 1);
  }

  /* signal strength is special too */
  if (sinfo[NL80211_STA_INFO_SIGNAL]) {
    int8_t signal;

    signal = nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]);
    nl80211_change_l2neigh_data(l2neigh, OONF_LAYER2_NEIGH_RX_SIGNAL, signal, 1);
  }

  /* remove old data */
  nl80211_cleanup_l2neigh_data(l2neigh);

  /* and commit the changes */
  oonf_layer2_neigh_commit(l2neigh);
}

static bool
_handle_traffic(struct oonf_layer2_neigh *l2neigh, enum oonf_layer2_neighbor_index idx, uint32_t new_32bit) {
  static const uint64_t UPPER_32_MASK = 0xffffffff00000000ull;
  static const uint64_t LOWER_32_MASK = 0x00000000ffffffffull;
  struct oonf_layer2_data *data;
  int64_t old_value, new_value;

  new_value = 0;
  old_value = 0;

  data = &l2neigh->data[idx];
  oonf_layer2_data_read_int64(&old_value, data, 0);

  new_value = old_value & UPPER_32_MASK;
  new_value |= (new_32bit & LOWER_32_MASK);

  OONF_DEBUG(LOG_NL80211, "new32: 0x%08x old: %016" PRIx64 " new: %016" PRIx64, new_32bit, old_value, new_value);

  if (new_value + 0x80000000ll < old_value) {
    /* handle 32bit counter overflow */
    new_value += 0x100000000ll;
    OONF_DEBUG(LOG_NL80211, "Overflow, new: %016" PRIx64, new_value);
  }

  return nl80211_change_l2neigh_data(l2neigh, idx, new_value, 1);
}

static int64_t
_get_bitrate(struct nlattr *bitrate_attr) {
  int rate = 0;
  struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
  static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
    [NL80211_RATE_INFO_BITRATE] = { .type = NLA_U16 },
    [NL80211_RATE_INFO_BITRATE32] = { .type = NLA_U32 },
  };

  if (nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, bitrate_attr, rate_policy)) {
    /* error in parsing bitrate nested arguments */
    return 0;
  }

  if (rinfo[NL80211_RATE_INFO_BITRATE32])
    rate = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]);
  else if (rinfo[NL80211_RATE_INFO_BITRATE])
    rate = nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);

  return 1024ll * 1024ll * rate / 10ll;
}
