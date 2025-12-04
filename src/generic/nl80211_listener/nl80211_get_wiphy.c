
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
#include <oonf/generic/nl80211_listener/nl80211_get_wiphy.h>
#include <oonf/generic/nl80211_listener/nl80211_internal.h>
#include <oonf/generic/nl80211_listener/nl80211_listener.h>

/**
 * object to store rate info table entry
 */
struct rate_info {
  /*! long (800 ns) guard interval */
  uint16_t lgi;

  /*! short (400 ns) guard interval */
  uint16_t sgi;
};

static uint64_t _get_max_bitrate(struct nl80211_if *interf, uint8_t *mcs, bool ht20_sgi, bool ht40_sgi);
static void _process_ht_mcs_array(struct nl80211_if *interf, uint8_t *mcs, bool ht20_sgi, bool ht40_sgi);
static void _process_vht_mcs_array(struct nl80211_if *interf, uint8_t *mcs);

/*
 * raw link speed table for 802.11n MCS indices in 0.1 MBit/s
 * for 20 MHz channels.
 */
static struct rate_info _mcs_table_80211n_20[77] = {
  { 65, 72 },
  { 130, 144 },
  { 195, 217 },
  { 260, 289 },
  { 390, 433 },
  { 520, 578 },
  { 585, 650 },
  { 650, 722 },
  { 130, 144 },
  { 260, 289 },
  { 390, 433 },
  { 520, 578 },
  { 780, 867 },
  { 1040, 1156 },
  { 1170, 1300 },
  { 1300, 1444 },
  { 195, 217 },
  { 390, 433 },
  { 585, 650 },
  { 780, 867 },
  { 1170, 1300 },
  { 1560, 1733 },
  { 1755, 1950 },
  { 1950, 2167 },
  { 260, 289 },
  { 520, 578 },
  { 780, 867 },
  { 1040, 1156 },
  { 1560, 1733 },
  { 2080, 2311 },
  { 2340, 2600 },
  { 2600, 2889 },
  { 0, 0 },
  { 390, 433 },
  { 520, 578 },
  { 650, 722 },
  { 585, 650 },
  { 780, 867 },
  { 975, 1083 },
  { 520, 578 },
  { 650, 722 },
  { 650, 722 },
  { 780, 867 },
  { 910, 1011 },
  { 910, 1011 },
  { 1040, 1156 },
  { 780, 867 },
  { 975, 1083 },
  { 975, 1083 },
  { 1170, 1300 },
  { 1365, 1517 },
  { 1365, 1517 },
  { 1560, 1733 },
  { 650, 722 },
  { 780, 867 },
  { 910, 1011 },
  { 780, 867 },
  { 910, 1011 },
  { 1040, 1156 },
  { 1170, 1300 },
  { 1040, 1156 },
  { 1170, 1300 },
  { 1300, 1444 },
  { 1300, 1444 },
  { 1430, 1589 },
  { 975, 1083 },
  { 1170, 1300 },
  { 1365, 1517 },
  { 1170, 1300 },
  { 1365, 1517 },
  { 1560, 1733 },
  { 1755, 1950 },
  { 1560, 1733 },
  { 1755, 1950 },
  { 1950, 2167 },
  { 1950, 2167 },
  { 2145, 2383 },
};

/*
 * raw link speed table for 802.11n MCS indices in 0.1 MBit/s
 * for 40 MHz channels.
 */
static struct rate_info _mcs_table_80211n_40[77] = {
  { 135, 150 },
  { 270, 300 },
  { 405, 450 },
  { 540, 600 },
  { 810, 900 },
  { 1080, 1200 },
  { 1215, 1350 },
  { 1350, 1500 },
  { 270, 300 },
  { 540, 600 },
  { 810, 900 },
  { 1080, 1200 },
  { 1620, 1800 },
  { 2160, 2400 },
  { 2430, 2700 },
  { 2700, 3000 },
  { 405, 450 },
  { 810, 900 },
  { 1215, 1350 },
  { 1620, 1800 },
  { 2430, 2700 },
  { 3240, 3600 },
  { 3645, 4050 },
  { 4050, 4500 },
  { 540, 600 },
  { 1080, 1200 },
  { 1620, 1800 },
  { 2160, 2400 },
  { 3240, 3600 },
  { 4320, 4800 },
  { 4860, 5400 },
  { 5400, 6000 },
  { 60, 67 },
  { 810, 900 },
  { 1080, 1200 },
  { 1350, 1500 },
  { 1215, 1350 },
  { 1620, 1800 },
  { 2025, 2250 },
  { 1080, 1200 },
  { 1350, 1500 },
  { 1350, 1500 },
  { 1620, 1800 },
  { 1890, 2100 },
  { 1890, 2100 },
  { 2160, 2400 },
  { 1620, 1800 },
  { 2025, 2250 },
  { 2025, 2250 },
  { 2430, 2700 },
  { 2835, 3150 },
  { 2835, 3150 },
  { 3240, 3600 },
  { 1350, 1500 },
  { 1620, 1800 },
  { 1890, 2100 },
  { 1620, 1800 },
  { 1890, 2100 },
  { 2160, 2400 },
  { 2430, 2700 },
  { 2160, 2400 },
  { 2430, 2700 },
  { 2700, 3000 },
  { 2700, 3000 },
  { 2970, 3300 },
  { 2025, 2250 },
  { 2430, 2700 },
  { 2835, 3150 },
  { 2430, 2700 },
  { 2835, 3150 },
  { 3240, 3600 },
  { 3645, 4050 },
  { 3240, 3600 },
  { 3645, 4050 },
  { 4050, 4500 },
  { 4050, 4500 },
  { 4455, 4950 },
};

/**
 * Send a netlink message to get the nl80211 physical capabilities
 * @param nl pointer to netlink handler
 * @param nl_msg pointer to netlink message
 * @param hdr pointer to generic netlink header
 * @param interf nl80211 listener interface
 */
void
nl80211_send_get_wiphy(
  struct os_system_netlink_message *nl_msg, struct genlmsghdr *hdr, struct nl80211_if *interf) {
  /* clear maximum data rates */
  interf->max_rx = 0;
  interf->max_tx = 0;

  hdr->cmd = NL80211_CMD_GET_WIPHY;
  nl_msg->message->nlmsg_flags |= NLM_F_DUMP;

  /* add "split wiphy dump" flag */
  os_system_linux_netlink_addreq(nl_msg, NL80211_ATTR_SPLIT_WIPHY_DUMP, NULL, 0);

  /* add interface index to the request */
  os_system_linux_netlink_addreq(nl_msg, NL80211_ATTR_WIPHY, &interf->wifi_phy_if, sizeof(interf->wifi_phy_if));

  OONF_DEBUG(LOG_NL80211, "Send GET_WIPHY to phydev %d", interf->wifi_phy_if);
}

/**
 * Process NL80211_CMD_GET_WIPHY message
 * @param hdr pointer to netlink message header
 * @param interf nl80211 listener interface
 */
void
nl80211_process_get_wiphy_result(struct nl80211_if *interf, struct nlmsghdr *hdr) {
  struct genlmsghdr *gnlh;
  struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
  struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
  struct nlattr *nl_band;
  bool ht20_sgi, ht40_sgi;
  int rem_band;

  gnlh = nlmsg_data(hdr);

  nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

  if (tb_msg[NL80211_ATTR_WIPHY]) {
    interf->wifi_phy_if = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
  }
  else {
    return;
  }

  ht20_sgi = false;
  ht40_sgi = false;

  if (tb_msg[NL80211_ATTR_WIPHY_BANDS]) {
    nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band) {
      nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);

      if (tb_band[NL80211_BAND_ATTR_HT_CAPA]) {
        uint16_t cap = nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]);

        if ((cap & 32)) {
          ht20_sgi = true;
        }
        if ((cap & 64)) {
          ht40_sgi = true;
        }
      }

      if (tb_band[NL80211_BAND_ATTR_HT_MCS_SET] && nla_len(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]) == 16) {
        _process_ht_mcs_array(interf, nla_data(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]), ht20_sgi, ht40_sgi);
      }

      if (tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]) {
        _process_vht_mcs_array(interf, nla_data(tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]));
      }
    }
  }
}

/**
 * Write data gathered from netlink back into layer2 database
 * @param interf nl80211 listener interface
 */
void
nl80211_finalize_get_wiphy(struct nl80211_if *interf) {
  if (interf->max_rx) {
    OONF_DEBUG(LOG_NL80211, "Maximum rx rate for %s: %" PRId64, interf->name, interf->max_rx);
    interf->ifdata_changed |=
      nl80211_change_l2net_neighbor_default(interf->l2net, OONF_LAYER2_NEIGH_RX_MAX_BITRATE, interf->max_rx, 1);
  }
  if (interf->max_tx) {
    OONF_DEBUG(LOG_NL80211, "Maximum tx rate for %s: %" PRId64, interf->name, interf->max_tx);
    interf->ifdata_changed |=
      nl80211_change_l2net_neighbor_default(interf->l2net, OONF_LAYER2_NEIGH_TX_MAX_BITRATE, interf->max_tx, 1);
  }
}

/**
 * Calculate the maximum bitrate of a layer2 interface based on its
 * ht_mcs_index array and the guard intervals
 * @param interf nl80211 listener interface
 * @param mcs ht mcs index
 * @param ht20_sgi true if ht20 supports short guard interval
 * @param ht40_sgi true if ht40 supports short guard interval
 * @return maximum bitrate in bit/s
 */
static uint64_t
_get_max_bitrate(struct nl80211_if *interf, uint8_t *mcs, bool ht20_sgi, bool ht40_sgi) {
  const struct oonf_layer2_data *data;
  const struct rate_info *rate_info;
  uint64_t max_rate, rate, bandwidth;
  int mcs_bit;
  bool ht20;

  /* get layer2 bandwidth */
  data = &interf->l2net->data[OONF_LAYER2_NET_BANDWIDTH_1];
  if (!oonf_layer2_data_has_value(data)) {
    /* we don't know the bandwidth of the channel */
    return 0;
  }
  bandwidth = oonf_layer2_data_get_int64(data, 1, 0);

  data = &interf->l2net->data[OONF_LAYER2_NET_BANDWIDTH_2];
  bandwidth += oonf_layer2_data_get_int64(data, 1, 0);

  if (bandwidth == 20000000) {
    /* is 20 MHz */
    ht20 = true;
  }
  else if (bandwidth == 40000000) {
    /* is 40 MHz */
    ht20 = false;
  }
  else {
    /* illegal bandwidth for 802.11n */
    return 0;
  }

  max_rate = 0;
  for (mcs_bit = 0; mcs_bit <= 76; mcs_bit++) {
    unsigned int mcs_octet = mcs_bit / 8;
    unsigned int MCS_RATE_BIT = 1 << mcs_bit % 8;

    if ((mcs[mcs_octet] & MCS_RATE_BIT)) {
      OONF_DEBUG(LOG_NL80211, "%s supports rate MCS %d", interf->name, mcs_bit);

      if (ht20) {
        rate_info = &_mcs_table_80211n_20[mcs_bit];
        rate = ht20_sgi ? rate_info->sgi : rate_info->lgi;
      }
      else {
        rate_info = &_mcs_table_80211n_40[mcs_bit];
        rate = ht40_sgi ? rate_info->sgi : rate_info->lgi;
      }

      if (rate > max_rate) {
        max_rate = rate;
      }
    }
  }
  return max_rate;
}

/**
 * Calculate maximum bitrate of a layer2 interface based on its
 * @param interf nl80211 listener interface
 * @param mcs ht mcs index
 * @param ht20_sgi true if ht20 supports short guard interval
 * @param ht40_sgi true if ht40 supports short guard interval
 */
static void
_process_ht_mcs_array(struct nl80211_if *interf, uint8_t *mcs, bool ht20_sgi, bool ht40_sgi) {
  uint64_t max_rx_supp_data_rate;
  uint64_t rate_tx, rate_rx;

  max_rx_supp_data_rate = (mcs[10] | ((mcs[11] & 0x3) << 8));

  rate_tx = 1024ull * 1024ull * _get_max_bitrate(interf, mcs, ht20_sgi, ht40_sgi) / 10ull;

  /*
   * this is a shortcut, because we don't want to deal with different
   * modulations of rx/tx
   */
  if (max_rx_supp_data_rate) {
    rate_rx = 1024ull * 1024ull * max_rx_supp_data_rate;
  }
  else {
    rate_rx = rate_tx;
  }

  if (interf->max_rx < rate_rx) {
    interf->max_rx = rate_rx;
  }
  if (interf->max_tx < rate_tx) {
    interf->max_tx = rate_tx;
  }
}

/**
 * Process vht mcs index for layer2 network
 * @param interf nl80211 listener interface
 * @param mcs vht mcs index
 */
static void
_process_vht_mcs_array(struct nl80211_if *interf, uint8_t *mcs) {
  uint64_t rate;

  /* get rx rate */
  rate = 1024ull * 1024ull * (mcs[4] | (mcs[5] << 8));
  if (interf->max_rx < rate) {
    interf->max_rx = rate;
  }

  /* get rx rate */
  rate = 1024ull * 1024ull * (mcs[6] | (mcs[7] << 8));
  if (interf->max_rx < rate) {
    interf->max_rx = rate;
  }
}
