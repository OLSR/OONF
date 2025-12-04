
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
#include <oonf/generic/nl80211_listener/nl80211_get_mpp.h>
#include <oonf/generic/nl80211_listener/nl80211_internal.h>
#include <oonf/generic/nl80211_listener/nl80211_listener.h>

/**
 * Send a netlink message to get the nl80211 mesh proxy path table
 * @param nl pointer to netlink handler
 * @param nl_msg pointer to netlink message
 * @param hdr pointer to generic netlink header
 * @param interf nl80211 listener interface
 */
void
nl80211_send_get_mpp(
  struct os_system_netlink_message *nl_msg, struct genlmsghdr *hdr, struct nl80211_if *interf) {
  int if_index = nl80211_get_if_baseindex(interf);

  hdr->cmd = NL80211_CMD_GET_MPP;
  nl_msg->message->nlmsg_flags |= NLM_F_DUMP;

  /* add interface index to the request */
  os_system_linux_netlink_addreq(nl_msg, NL80211_ATTR_IFINDEX, &if_index, sizeof(if_index));
}

/**
 * Process NL80211_CMD_NEW_MPATH message
 * @param interf nl80211 listener interface
 * @param hdr pointer to netlink message header
 */
void
nl80211_process_get_mpp_result(struct nl80211_if *interf, struct nlmsghdr *hdr) {
  struct oonf_layer2_destination *l2dst;
  struct oonf_layer2_neigh *l2neigh;
  struct netaddr remote_mac, destination_mac;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf1, nbuf2;
#endif

  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh;

  gnlh = nlmsg_data(hdr);
  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

  if (nl80211_get_if_baseindex(interf) != nla_get_u32(tb[NL80211_ATTR_IFINDEX])) {
    /* wrong interface ? */
    return;
  }

  netaddr_from_binary(&remote_mac, nla_data(tb[NL80211_ATTR_MPATH_NEXT_HOP]), 6, AF_MAC48);
  netaddr_from_binary(&destination_mac, nla_data(tb[NL80211_ATTR_MAC]), 6, AF_MAC48);

  l2neigh = oonf_layer2_neigh_get(interf->l2net, &remote_mac);
  if (!l2neigh) {
    /* don't create a neighbor, just ignore the MPP data */
    return;
  }

  l2dst = nl80211_add_dst(l2neigh, &destination_mac);
  if (!l2dst) {
    return;
  }

  OONF_DEBUG(LOG_NL80211, "Neighbor %s was proxied by mesh node %s", netaddr_to_string(&nbuf1, &destination_mac),
    netaddr_to_string(&nbuf2, &remote_mac));
}
