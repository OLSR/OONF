
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
#include <oonf/base/os_system.h>

#include <oonf/generic/nl80211_listener/nl80211.h>
#include <oonf/generic/nl80211_listener/nl80211_get_interface.h>
#include <oonf/generic/nl80211_listener/nl80211_listener.h>

static uint64_t _get_bandwidth(uint32_t width);

/**
 * Send a netlink message to get the nl80211 interface information
 * @param nl_msg pointer to netlink message
 * @param hdr pointer to generic netlink header
 * @param interf nl80211 listener interface
 */
void
nl80211_send_get_interface(
  struct os_system_netlink_message *nl_msg, struct genlmsghdr *hdr, struct nl80211_if *interf) {
  int if_index = nl80211_get_if_baseindex(interf);

  hdr->cmd = NL80211_CMD_GET_INTERFACE;

  /* add interface index to the request */
  os_system_linux_netlink_addreq(nl_msg, NL80211_ATTR_IFINDEX, &if_index, sizeof(if_index));
}

/**
 * Process NL80211_CMD_NEW_INTERFACE message
 * @param interf nl80211 listener interface
 * @param hdr pointer to netlink message header
 */
void
nl80211_process_get_interface_result(struct nl80211_if *interf, struct nlmsghdr *hdr) {
  struct genlmsghdr *gnlh;
  struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
  struct oonf_layer2_neigh *l2neigh;
  uint64_t mc_rate;

  gnlh = nlmsg_data(hdr);
  nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

  if (!tb_msg[NL80211_ATTR_IFNAME] || !tb_msg[NL80211_ATTR_WIPHY]) {
    /* no name or no physical interface */
    return;
  }

  interf->wifi_phy_if = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);

  if (tb_msg[NL80211_ATTR_SSID]) {
    char ssid[33];
    int len;

    len = nla_len(tb_msg[NL80211_ATTR_SSID]);
    if (len > (int)sizeof(ssid) - 1) {
      len = sizeof(ssid) - 1;
    }
    memcpy(ssid, nla_data(tb_msg[NL80211_ATTR_SSID]), len);
    ssid[len] = 0;

    if (strcmp(interf->l2net->if_ident, ssid) != 0) {
      strscpy(interf->l2net->if_ident, ssid, sizeof(interf->l2net->if_ident));
      interf->ifdata_changed = true;
    }
  }
  if (tb_msg[NL80211_ATTR_WIPHY_FREQ]) {
    uint64_t freq[2], bandwidth[2];

    freq[0] = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]);
    freq[1] = 0;

    if (tb_msg[NL80211_ATTR_CHANNEL_WIDTH]) {
      bandwidth[0] = _get_bandwidth(nla_get_u32(tb_msg[NL80211_ATTR_CHANNEL_WIDTH]));
    }
    else {
      bandwidth[0] = 0;
    }
    bandwidth[1] = 0;

    if (tb_msg[NL80211_ATTR_CENTER_FREQ1] && tb_msg[NL80211_ATTR_CENTER_FREQ2]) {
      freq[0] = nla_get_u32(tb_msg[NL80211_ATTR_CENTER_FREQ1]);
      freq[1] = nla_get_u32(tb_msg[NL80211_ATTR_CENTER_FREQ2]);

      bandwidth[1] = bandwidth[0];
    }

    /* transform from MHz to Hz*/
    freq[0] *= 1000000ull;
    freq[1] *= 1000000ull;

    interf->ifdata_changed |= nl80211_change_l2net_data(interf->l2net, OONF_LAYER2_NET_FREQUENCY_1, freq[0], 1);
    interf->ifdata_changed |= nl80211_change_l2net_data(interf->l2net, OONF_LAYER2_NET_FREQUENCY_2, freq[1], 1);
    interf->ifdata_changed |= nl80211_change_l2net_data(interf->l2net, OONF_LAYER2_NET_BANDWIDTH_1, bandwidth[0], 1);
    interf->ifdata_changed |= nl80211_change_l2net_data(interf->l2net, OONF_LAYER2_NET_BANDWIDTH_2, bandwidth[1], 1);

    if (bandwidth[0] > 0 && nl80211_create_broadcast_neighbor()) {
      /* calculate multicast rate */
      mc_rate = 6000000ull * 20000000ull / (bandwidth[0] + bandwidth[1]);

      l2neigh = oonf_layer2_neigh_add(interf->l2net, &NETADDR_MAC48_BROADCAST);
      if (l2neigh) {
        nl80211_change_l2neigh_data(l2neigh, OONF_LAYER2_NEIGH_TX_BITRATE, mc_rate, 1);
      }
    }
  }
}

/**
 * Parse nl80211 bandwidth constants and return bandwidth in
 * megahertz. If radio use 80/80 split-channel, the function reports
 * 80 megahertz.
 * @param width bandwidth constant
 * @return bandwidth in hertz
 */
static uint64_t
_get_bandwidth(uint32_t width) {
  switch (width) {
    case NL80211_CHAN_WIDTH_5:
      return 5ull * 1000000ull;
    case NL80211_CHAN_WIDTH_10:
      return 10ull * 1000000ull;
    case NL80211_CHAN_WIDTH_20_NOHT:
      return 20ull * 1000000ull;
    case NL80211_CHAN_WIDTH_20:
      return 20ull * 1000000ull;
    case NL80211_CHAN_WIDTH_40:
      return 40ull * 1000000ull;
    case NL80211_CHAN_WIDTH_80:
      return 80ull * 1000000ull;
    case NL80211_CHAN_WIDTH_80P80:
      return 80ull * 1000000ull;
    case NL80211_CHAN_WIDTH_160:
      return 160ull * 1000000ull;
    default:
      return 0;
  }
}
