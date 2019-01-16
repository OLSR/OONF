
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
#include <oonf/generic/nl80211_listener/nl80211_get_survey.h>
#include <oonf/generic/nl80211_listener/nl80211_listener.h>

/**
 * Send a netlink message to get the nl80211 survey dump
 * @param nl pointer to netlink handler
 * @param nl_msg pointer to netlink message
 * @param hdr pointer to generic netlink header
 * @param interf nl80211 listener interface
 */
void
nl80211_send_get_survey(
  struct os_system_netlink_message *nl_msg, struct genlmsghdr *hdr, struct nl80211_if *interf) {
  int if_index = nl80211_get_if_baseindex(interf);

  hdr->cmd = NL80211_CMD_GET_SURVEY;
  nl_msg->message->nlmsg_flags |= NLM_F_DUMP;

  /* add interface index to the request */
  os_system_linux_netlink_addreq(nl_msg, NL80211_ATTR_IFINDEX, &if_index, sizeof(if_index));
}

/**
 * Process NL80211_CMD_NEW_SURVEY_RESULTS message
 * @param interf nl80211 listener interface
 * @param hdr pointer to netlink message header
 */
void
nl80211_process_get_survey_result(struct nl80211_if *interf, struct nlmsghdr *hdr) {
  struct genlmsghdr *gnlh;
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];

  static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
    [NL80211_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
    [NL80211_SURVEY_INFO_NOISE] = { .type = NLA_U8 },
  };

  gnlh = nlmsg_data(hdr);

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

  if (nl80211_get_if_baseindex(interf) != nla_get_u32(tb[NL80211_ATTR_IFINDEX])) {
    /* wrong interface ? */
    return;
  }

  if (!tb[NL80211_ATTR_SURVEY_INFO]) {
    /* no survey data */
    return;
  }

  if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX, tb[NL80211_ATTR_SURVEY_INFO], survey_policy)) {
    /* no nested survey data */
    return;
  }

  if (!sinfo[NL80211_SURVEY_INFO_IN_USE]) {
    /* wrong frequency */
    return;
  }

  if (sinfo[NL80211_SURVEY_INFO_NOISE]) {
    interf->ifdata_changed |= nl80211_change_l2net_data(
      interf->l2net, OONF_LAYER2_NET_NOISE, (int8_t)nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]), 1);
  }

  if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME]) {
    interf->ifdata_changed |= nl80211_change_l2net_data(interf->l2net, OONF_LAYER2_NET_CHANNEL_ACTIVE,
      (int64_t)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME]), 1000);
  }
  if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY]) {
    interf->ifdata_changed |= nl80211_change_l2net_data(interf->l2net, OONF_LAYER2_NET_CHANNEL_BUSY,
      (int64_t)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY]), 1000);
  }
#if 0
  /* I have no clue what this is */
  if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_EXT_BUSY]) {
    interf->ifdata_changed |= nl80211_change_l2net_data(
        interf->l2net, OONF_LAYER2_NET_CHANNEL_BUSYEXT,
            1000000ll * (int64_t)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_EXT_BUSY]));
  }
#endif
  if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_RX]) {
    interf->ifdata_changed |= nl80211_change_l2net_data(interf->l2net, OONF_LAYER2_NET_CHANNEL_RX,
      (int64_t)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_RX]), 1000);
  }
  if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_TX]) {
    interf->ifdata_changed |= nl80211_change_l2net_data(interf->l2net, OONF_LAYER2_NET_CHANNEL_TX,
      (int64_t)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_TX]), 1000);
  }
}
