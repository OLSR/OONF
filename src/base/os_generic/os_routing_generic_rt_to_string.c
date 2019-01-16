
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

#include <oonf/libcommon/netaddr.h>
#include <oonf/base/os_routing.h>

static const char *_route_types[] = {
  [OS_ROUTE_UNDEFINED] = "undefined",
  [OS_ROUTE_UNICAST] = "unicast",
  [OS_ROUTE_LOCAL] = "local",
  [OS_ROUTE_BROADCAST] = "broadcast",
  [OS_ROUTE_ANYCAST] = "anycast",
  [OS_ROUTE_MULTICAST] = "multicast",
  [OS_ROUTE_THROW] = "throw",
  [OS_ROUTE_UNREACHABLE] = "unreachable",
  [OS_ROUTE_PROHIBIT] = "prohibit",
  [OS_ROUTE_BLACKHOLE] = "blackhole",
  [OS_ROUTE_NAT] = "nat",
};

/**
 * Print OS route to string buffer
 * @param buf pointer to string buffer
 * @param route_parameter pointer to route
 * @return pointer to string buffer, NULL if an error happened
 */
const char *
os_routing_generic_rt_to_string(struct os_route_str *buf, const struct os_route_parameter *route_parameter) {
  struct netaddr_str buf1, buf2, buf3, buf4;
  char ifbuf[IF_NAMESIZE];
  int result;
  result = snprintf(buf->buf, sizeof(*buf),
    "'src-ip %s gw %s dst %s %s src-prefix %s metric %d table %u protocol %u if %s (%u)'",
    netaddr_to_string(&buf1, &route_parameter->src_ip), netaddr_to_string(&buf2, &route_parameter->gw),
    _route_types[route_parameter->type], netaddr_to_string(&buf3, &route_parameter->key.dst),
    netaddr_to_string(&buf4, &route_parameter->key.src), route_parameter->metric,
    (unsigned int)(route_parameter->table), (unsigned int)(route_parameter->protocol),
    if_indextoname(route_parameter->if_index, ifbuf), route_parameter->if_index);

  if (result < 0 || result > (int)sizeof(*buf)) {
    return NULL;
  }
  return buf->buf;
}

/**
 * Returns the text name of a routing type. Used for configuration parameter
 * @param idx index of routing type
 * @param unused unused for this selector
 * @return text name of routing type
 */
const char *
os_routing_cfg_get_rttype(size_t idx, const void *unused __attribute__((unused))) {
  static const char *UNKNOWN = "UNKNOWN";
  if (idx >= OS_ROUTE_COUNT) {
    return UNKNOWN;
  }
  return _route_types[idx];
}
