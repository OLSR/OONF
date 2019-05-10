
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

#include <ctype.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/string.h>

static char *_mac_to_string(char *dst, size_t dst_size, const void *bin, size_t bin_size, char separator);
static char *_uuid_to_string(char *dst, size_t dst_size, const void *bin, size_t bin_size);
static int _bin_from_hex(void *bin, size_t bin_size, const char *src, char separator);
static int _uuid_from_string(void *bin, size_t bin_size, const char *src);
static int _subnetmask_to_prefixlen(const char *src);
static int _read_hexdigit(const char c);
static bool _binary_is_in_subnet(const struct netaddr *subnet, const void *bin);

/* predefined network prefixes */

/*! unspecified network address */
const struct netaddr NETADDR_UNSPEC = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_UNSPEC, 0 };

/*! IPv4 default prefix */
const struct netaddr NETADDR_IPV4_ANY = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_INET, 0 };

/*! IPv6 default prefix */
const struct netaddr NETADDR_IPV6_ANY = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_INET6, 0 };

/*! IPv4 NULL address */
const struct netaddr NETADDR_IPV4_BINDTO_ANY = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_INET, 32 };

/*! IPv6 NULL address */
const struct netaddr NETADDR_IPV6_BINDTO_ANY = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_INET6, 128 };

/*! IPv4 multicast prefix */
const struct netaddr NETADDR_IPV4_MULTICAST = { { 224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_INET, 4 };

/*! IPv6 multicast prefix */
const struct netaddr NETADDR_IPV6_MULTICAST = { { 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_INET6, 8 };

/*! IPv4 linklocal prefix */
const struct netaddr NETADDR_IPV4_LINKLOCAL = { { 169, 254, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_INET, 16 };

/*! IPv6 linklocal prefix */
const struct netaddr NETADDR_IPV6_LINKLOCAL = { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_INET6,
  10 };

/*! IPv6 unique local prefix */
const struct netaddr NETADDR_IPV6_ULA = { { 0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_INET6, 7 };

/*! IPv6 routable prefix */
const struct netaddr NETADDR_IPV6_GLOBAL = { { 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_INET6, 3 };

/*! IPv6 ipv4-compatible prefix */
const struct netaddr NETADDR_IPV6_IPV4COMPATIBLE = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_INET6, 96 };

/*! IPv6 ipv4-mapped prefix */
const struct netaddr NETADDR_IPV6_IPV4MAPPED = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 }, AF_INET6,
  96 };

/*! IPv4 loopback prefix */
const struct netaddr NETADDR_IPV4_LOOPBACK_NET = { { 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_INET, 8 };

/*! IPv6 loopback address */
const struct netaddr NETADDR_IPV6_LOOPBACK = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, AF_INET6, 128 };

/*! Ethernet broadcast */
const struct netaddr NETADDR_MAC48_BROADCAST = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
  AF_MAC48, 48 };

/*! Ethernet multicast prefix for IPv4 multicast */
const struct netaddr NETADDR_MAC48_IPV4_MULTICAST = { { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, AF_MAC48, 25 };

/*! Ethernet multicast prefix for IPv4 multicast */
const struct netaddr NETADDR_MAC48_IPV6_MULTICAST = { { 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  }, AF_MAC48, 16 };

/*! socket for binding to any IPv4 address */
const union netaddr_socket NETADDR_SOCKET_IPV4_ANY = { .v4 = {
                                                         .sin_family = AF_INET,
                                                         .sin_port = 0,
                                                         .sin_addr.s_addr = 0,
                                                       } };

/*! socket for binding to any IPv6 address */
const union netaddr_socket NETADDR_SOCKET_IPV6_ANY = { .v6 = {
                                                         .sin6_family = AF_INET6,
                                                         .sin6_port = 0,
                                                         .sin6_addr.s6_addr32 = { 0, 0, 0, 0 },
                                                         .sin6_scope_id = 0,
                                                       } };

                                                       /*! socket for binding to any IPv6 address */
const union netaddr_socket NETADDR_SOCKET_UNSPEC = NETADDR_SOCKET_UNSPEC_INIT;

/* List of predefined address prefixes */
static const struct {
  const char *name;
  const struct netaddr *prefix;
} _known_prefixes[] = {
  { NETADDR_STR_ANY4, &NETADDR_IPV4_ANY },
  { NETADDR_STR_ANY6, &NETADDR_IPV6_ANY },
  { NETADDR_STR_LINKLOCAL4, &NETADDR_IPV4_LINKLOCAL },
  { NETADDR_STR_LINKLOCAL6, &NETADDR_IPV6_LINKLOCAL },
  { NETADDR_STR_ULA, &NETADDR_IPV6_ULA },
};

/**
 * Read the binary representation of an address into a netaddr object
 * @param dst pointer to netaddr object
 * @param binary source pointer
 * @param len length of source buffer
 * @param addr_type address type of source,
 *     0 to autodetect type from length
 * @param prefix_len prefix length of source,
 *     255 for maximum prefix length depending on type
 * @return 0 if successful recognized the address type
 *     of the binary data, -1 otherwise
 */
int
netaddr_from_binary_prefix(struct netaddr *dst, const void *binary, size_t len, uint8_t addr_type, uint8_t prefix_len) {
  memset(dst->_addr, 0, sizeof(dst->_addr));

  if (addr_type != 0) {
    dst->_type = addr_type;
  }
  else {
    switch (len) {
      case 4:
        dst->_type = AF_INET;
        break;
      case 6:
        dst->_type = AF_MAC48;
        break;
      case 8:
        dst->_type = AF_EUI64;
        break;
      case 16:
        dst->_type = AF_INET6;
        break;
      default:
        dst->_type = AF_UNSPEC;
        if (len > 16) {
          len = 16;
        }
        break;
    }
  }

  if (prefix_len == 255) {
    prefix_len = len << 3;
  }

  dst->_prefix_len = prefix_len;
  memcpy(dst->_addr, binary, len);

  return dst->_type == AF_UNSPEC ? -1 : 0;
}

/**
 * Writes a netaddr object into a binary buffer
 * @param dst binary buffer
 * @param src netaddr source
 * @param len length of destination buffer
 * @return 0 if successful read binary data, -1 otherwise
 */
int
netaddr_to_binary(void *dst, const struct netaddr *src, size_t len) {
  uint32_t addr_len;

  addr_len = netaddr_get_maxprefix(src) >> 3;
  if (addr_len == 0 || len < addr_len) {
    /* unknown address type */
    return -1;
  }

  memcpy(dst, src->_addr, addr_len);
  return 0;
}

/**
 * Reads the address and address-type part of an
 * netaddr_socket into a netaddr object
 * @param dst netaddr object
 * @param src netaddr_socket source
 * @return 0 if successful read binary data, -1 otherwise
 */
int
netaddr_from_socket(struct netaddr *dst, const union netaddr_socket *src) {
  memset(dst->_addr, 0, sizeof(dst->_addr));
  if (src->std.sa_family == AF_INET) {
    /* ipv4 */
    memcpy(dst->_addr, &src->v4.sin_addr, 4);
    dst->_prefix_len = 32;
  }
  else if (src->std.sa_family == AF_INET6) {
    /* ipv6 */
    memcpy(dst->_addr, &src->v6.sin6_addr, 16);
    dst->_prefix_len = 128;
  }
  else {
    /* unknown address type */
    dst->_type = AF_UNSPEC;
    return -1;
  }
  dst->_type = (uint8_t)src->std.sa_family;
  return 0;
}

/**
 * Writes the address and address-type of a netaddr object
 * into a netaddr_socket.
 * @param dst pointer to netaddr_socket
 * @param src netaddr source
 * @return 0 if successful read binary data, -1 otherwise
 */
int
netaddr_to_socket(union netaddr_socket *dst, const struct netaddr *src) {
  /* copy address type */
  dst->std.sa_family = src->_type;

  switch (src->_type) {
    case AF_INET:
      /* ipv4 */
      memcpy(&dst->v4.sin_addr, src->_addr, 4);
      break;
    case AF_INET6:
      /* ipv6 */
      memcpy(&dst->v6.sin6_addr, src->_addr, 16);
      break;
    default:
      /* unknown address type */
      return -1;
  }

  /* copy address type */
  dst->std.sa_family = src->_type;
  return 0;
}

/**
 * Append binary address to autobuf
 * @param abuf pointer to target autobuf
 * @param src pointer to source address
 * @return -1 if an error happened, 0 otherwise
 */
int
netaddr_to_autobuf(struct autobuf *abuf, const struct netaddr *src) {
  uint32_t addr_len;

  addr_len = netaddr_get_maxprefix(src) >> 3;
  if (addr_len == 0) {
    /* unknown address type */
    return -1;
  }

  return abuf_memcpy(abuf, src->_addr, addr_len);
}

/**
 * Creates a host address from a netmask and a host number part. This function
 * will copy the netmask and then overwrite the bits after the prefix length
 * with the one from the host number.
 * @param host target buffer
 * @param netmask prefix of result
 * @param number postfix of result
 * @param num_length length of the postfix in bytes
 * @return -1 if an error happened, 0 otherwise
 */
int
netaddr_create_host_bin(struct netaddr *host, const struct netaddr *netmask, const void *number, size_t num_length) {
  size_t host_index, number_index;
  uint8_t host_part_length;
  const uint8_t *number_byte;
  uint8_t mask;

  number_byte = number;

  /* copy netmask with prefixlength max */
  memcpy(host, netmask, sizeof(*netmask));
  host->_prefix_len = netaddr_get_maxprefix(host);

  /* unknown address type */
  if (host->_prefix_len == 0) {
    return -1;
  }

  /* netmask has no host part */
  if (host->_prefix_len == netmask->_prefix_len || num_length == 0) {
    return 0;
  }

  /* calculate starting byte in host and number */
  host_part_length = (host->_prefix_len - netmask->_prefix_len + 7) / 8;
  if (host_part_length > num_length) {
    host_index = host->_prefix_len / 8 - num_length;
    number_index = 0;
  }
  else {
    host_index = netmask->_prefix_len / 8;
    number_index = num_length - host_part_length;

    /* copy bit masked part */
    if ((netmask->_prefix_len & 7) != 0) {
      mask = (255 >> (netmask->_prefix_len & 7));
      host->_addr[host_index] &= (~mask);
      host->_addr[host_index] |= (number_byte[number_index++]) & mask;
      host_index++;
    }
  }

  /* copy bytes */
  memcpy(&host->_addr[host_index], &number_byte[number_index], num_length - number_index);
  return 0;
}

/**
 * Creates the network prefix from a host and a netmask. Both host and
 * netmask must be the same address family.
 * @param prefix target buffer to write prefix into
 * @param host host address
 * @param netmask well formed netmask
 * @param truncate true if host IP should be truncated
 * @return -1 if an error happened, 0 otherwise
 */
int
netaddr_create_prefix(
  struct netaddr *prefix, const struct netaddr *host, const struct netaddr *netmask, bool truncate) {
  int len, maxlen;
  if (host->_type != netmask->_type || host->_type == AF_UNSPEC) {
    return -1;
  }

  /* get address length */
  maxlen = netaddr_get_af_maxprefix(host->_type) / 8;

  /* initialize prefix */
  prefix->_prefix_len = 0;
  prefix->_type = host->_type;

  if (!truncate) {
    memcpy(&prefix->_addr[0], &host->_addr[0], 16);
  }

  for (len = 0; len < maxlen; len++) {
    if (truncate) {
      prefix->_addr[len] = host->_addr[len] & netmask->_addr[len];
    }

    switch (netmask->_addr[len]) {
      case 255:
        len++;
        prefix->_prefix_len += 8;
        break;
      case 254:
        prefix->_prefix_len += 7;
        return 0;
      case 252:
        prefix->_prefix_len += 6;
        return 0;
      case 248:
        prefix->_prefix_len += 5;
        return 0;
      case 240:
        prefix->_prefix_len += 4;
        return 0;
      case 224:
        prefix->_prefix_len += 3;
        return 0;
      case 192:
        prefix->_prefix_len += 2;
        return 0;
      case 128:
        prefix->_prefix_len += 1;
        return 0;
      case 0:
        return 0;
      default:
        return -1;
    }
  }
  return 0;
}

/**
 * Clear the bits outside of the prefix length of an address
 * @param dst trucated destination buffer
 * @param src source IP
 */
void
netaddr_truncate(struct netaddr *dst, const struct netaddr *src) {
  static uint8_t MASK[] = { 0, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };
  int byte_prefix, bit_prefix;

  /* calulate byte/bit part of prefix */
  byte_prefix = src->_prefix_len / 8;
  bit_prefix = src->_prefix_len & 7;

  if (src != dst) {
    /* copy type and prefix length */
    dst->_prefix_len = src->_prefix_len;
    dst->_type = src->_type;

    /* copy constant octets */
    memcpy(dst->_addr, src->_addr, byte_prefix);
  }

  if (bit_prefix) {
    /* modify bitwise */
    dst->_addr[byte_prefix] = src->_addr[byte_prefix] & MASK[bit_prefix];
    byte_prefix++;
  }

  if (byte_prefix < 16) {
    /* zero rest of address */
    memset(&dst->_addr[byte_prefix], 0, 16 - byte_prefix);
  }
}

/**
 * Initialize a netaddr_socket with a netaddr and a port number
 * @param combined pointer to netaddr_socket to be initialized
 * @param addr pointer to netaddr source
 * @param port port number for socket
 * @param if_index interface index for linklocal ipv6 sockets
 * @return 0 if successful read binary data, -1 otherwise
 */
int
netaddr_socket_init(union netaddr_socket *combined, const struct netaddr *addr, uint16_t port, unsigned if_index) {
  /* initialize memory block */
  memset(combined, 0, sizeof(*combined));

  switch (addr->_type) {
    case AF_INET:
      /* ipv4 */
      memcpy(&combined->v4.sin_addr, addr->_addr, 4);
      combined->v4.sin_port = htons(port);
      break;
    case AF_INET6:
      /* ipv6 */
      memcpy(&combined->v6.sin6_addr, addr->_addr, 16);
      combined->v6.sin6_port = htons(port);
      combined->v6.sin6_scope_id = if_index;
      break;
    default:
      /* unknown address type */
      return -1;
  }

  /* copy address type */
  combined->std.sa_family = addr->_type;
  return 0;
}

/**
 * @param sock pointer to netaddr_socket
 * @return pointer to binary address
 */
const uint8_t *
netaddr_socket_get_addr_binptr(const union netaddr_socket *sock) {
  switch (sock->std.sa_family) {
    case AF_INET:
      return (uint8_t *)&sock->v4.sin_addr.s_addr;
    case AF_INET6:
      return (uint8_t *)&sock->v6.sin6_addr;
    default:
      return NULL;
  }
}

/**
 * @param sock pointer to netaddr_socket
 * @return port of socket
 */
uint16_t
netaddr_socket_get_port(const union netaddr_socket *sock) {
  switch (sock->std.sa_family) {
    case AF_INET:
      return ntohs(sock->v4.sin_port);
    case AF_INET6:
      return ntohs(sock->v6.sin6_port);
    default:
      return 0;
  }
}

/**
 * Converts a netaddr into a string
 * @param dst target string buffer
 * @param src netaddr source (can be NULL)
 * @param forceprefix true if a prefix should be appended even with maximum
 *   prefix length, false if only shorter prefixes should be appended
 * @return pointer to target buffer
 */
const char *
netaddr_to_prefixstring(struct netaddr_str *dst, const struct netaddr *src, bool forceprefix) {
  static const char *NONE = "-";
  const char *result = NULL;
  int maxprefix;

  if (!src) {
    return strscpy(dst->buf, NONE, sizeof(*dst));
  }

  maxprefix = netaddr_get_maxprefix(src);
  switch (src->_type) {
    case AF_INET:
      result = inet_ntop(AF_INET, src->_addr, dst->buf, sizeof(*dst));
      break;
    case AF_INET6:
      result = inet_ntop(AF_INET6, src->_addr, dst->buf, sizeof(*dst));
      break;
    case AF_MAC48:
      result = _mac_to_string(dst->buf, sizeof(*dst), src->_addr, 6, ':');
      break;
    case AF_EUI64:
      result = _mac_to_string(dst->buf, sizeof(*dst), src->_addr, 8, '-');
      break;
    case AF_UUID:
      result = _uuid_to_string(dst->buf, sizeof(*dst), src->_addr, 16);
      break;
    case AF_UNSPEC:
      /* fall through */
    default:
      return strscpy(dst->buf, NONE, sizeof(*dst));
  }
  if (forceprefix || src->_prefix_len < maxprefix) {
    /* append prefix */
    snprintf(dst->buf + strlen(result), 5, "/%d", src->_prefix_len);
  }
  return result;
}

/**
 * Generates a netaddr from a string.
 * @param dst pointer to netaddr object
 * @param src pointer to input string
 * @return -1 if an error happened because of an unknown string,
 *   0 otherwise
 */
int
netaddr_from_string(struct netaddr *dst, const char *src) {
  struct netaddr_str buf;
  unsigned int colon_count, minus_count;
  int result;
  int prefix_len;
  bool has_coloncolon, has_point;
  bool last_was_colon;
  char *ptr1, *ptr2, *ptr3;
  size_t i;

  memset(dst, 0, sizeof(*dst));

  if (strcmp(src, "-") == 0) {
    /* unspec */
    netaddr_invalidate(dst);
    return 0;
  }

  /* handle string representations of prefixes */
  for (i = 0; i < ARRAYSIZE(_known_prefixes); i++) {
    if (strcasecmp(src, _known_prefixes[i].name) == 0) {
      memcpy(dst, _known_prefixes[i].prefix, sizeof(*dst));
      return 0;
    }
  }

  colon_count = 0;
  minus_count = 0;
  has_coloncolon = false;
  has_point = false;

  last_was_colon = false;

  result = -1;
  prefix_len = -1;

  /* copy input string in temporary buffer */
  strscpy(buf.buf, src, sizeof(buf));
  ptr1 = buf.buf;

  ptr1 = str_trim(ptr1);

  ptr2 = ptr1;
  while (*ptr2 != 0 && !isspace(*ptr2) && *ptr2 != '/') {
    switch (*ptr2) {
      case ':':
        if (last_was_colon) {
          has_coloncolon = true;
        }
        colon_count++;
        break;

      case '.':
        has_point = true;
        break;

      case '-':
        minus_count++;
        break;

      default:
        break;
    }
    last_was_colon = *ptr2++ == ':';
  }

  if (*ptr2) {
    /* split strings */
    while (isspace(*ptr2))
      *ptr2++ = 0;
    if (*ptr2 == '/') {
      *ptr2++ = 0;
    }
    while (isspace(*ptr2))
      *ptr2++ = 0;

    if (*ptr2 == 0) {
      /* prefixlength is missing */
      dst->_type = AF_UNSPEC;
      return -1;
    }

    /* try to read numeric prefix length */
    prefix_len = (int)strtoul(ptr2, &ptr3, 10);
    if (ptr3 && *ptr3) {
      /* not a numeric prefix length */
      prefix_len = -1;
    }
  }

  /* use dst->prefix_len as storage for maximum prefixlen */
  if ((colon_count == 5 || minus_count == 5) && (colon_count == 0 || minus_count == 0) && !has_point &&
      !has_coloncolon) {
    dst->_type = AF_MAC48;
    dst->_prefix_len = 48;
    if (colon_count > 0) {
      result = _bin_from_hex(dst->_addr, 6, ptr1, ':');
    }
    else {
      result = _bin_from_hex(dst->_addr, 6, ptr1, '-');
    }
  }
  else if (colon_count == 0 && !has_point && minus_count == 7) {
    dst->_type = AF_EUI64;
    dst->_prefix_len = 64;
    dst->_addr[7] = 2;
    result = _bin_from_hex(dst->_addr, 8, ptr1, '-');
  }
  else if (colon_count == 0 && has_point && minus_count == 0) {
    dst->_type = AF_INET;
    dst->_prefix_len = 32;
    result = inet_pton(AF_INET, ptr1, dst->_addr) == 1 ? 0 : -1;

    if (result == 0 && *ptr2 && prefix_len == -1) {
      /* we need a prefix length, but its not a numerical one */
      prefix_len = _subnetmask_to_prefixlen(ptr2);
    }
  }
  else if ((has_coloncolon || colon_count == 7) && minus_count == 0) {
    dst->_type = AF_INET6;
    dst->_prefix_len = 128;
    result = inet_pton(AF_INET6, ptr1, dst->_addr) == 1 ? 0 : -1;
  }
  else if (minus_count == 4 && colon_count == 0 && !has_point) {
    dst->_type = AF_UUID;
    dst->_prefix_len = 128;
    result = _uuid_from_string(dst->_addr, sizeof(dst->_addr), ptr1);
  }

  /* stop if an error happened */
  if (result) {
    dst->_type = AF_UNSPEC;
    return -1;
  }

  if (*ptr2) {
    if (prefix_len < 0 || prefix_len > dst->_prefix_len) {
      /* prefix is too long */
      dst->_type = AF_UNSPEC;
      return -1;
    }

    /* store real prefix length */
    dst->_prefix_len = (uint8_t)prefix_len;
  }
  return 0;
}

/**
 * Converts a netaddr_socket into a string
 * @param dst target string buffer
 * @param src netaddr_socket source
 * @return pointer to target buffer, NULL if an error happened
 */
const char *
netaddr_socket_to_string(struct netaddr_str *dst, const union netaddr_socket *src) {
  struct netaddr_str buf;
  static const char NONE[] = "-";

  if (src->std.sa_family == AF_INET) {
    snprintf(dst->buf, sizeof(*dst), "%s:%d", inet_ntop(AF_INET, &src->v4.sin_addr, buf.buf, sizeof(buf)),
      ntohs(src->v4.sin_port));
  }
  else if (src->std.sa_family == AF_INET6) {
    if (src->v6.sin6_scope_id) {
      char scope_buf[IF_NAMESIZE];

      snprintf(dst->buf, sizeof(*dst), "[%s]:%d%%%s", inet_ntop(AF_INET6, &src->v6.sin6_addr, buf.buf, sizeof(buf)),
        ntohs(src->v6.sin6_port), if_indextoname(src->v6.sin6_scope_id, scope_buf));
    }
    else {
      snprintf(dst->buf, sizeof(*dst), "[%s]:%d", inet_ntop(AF_INET6, &src->v6.sin6_addr, buf.buf, sizeof(buf)),
        ntohs(src->v6.sin6_port));
    }
  }
  else if (src->std.sa_family == 0) {
    strscpy(dst->buf, NONE, sizeof(*dst));
  }
  else {
    snprintf(dst->buf, sizeof(*dst), "\"Unknown socket type: %d\"", src->std.sa_family);
  }

  return dst->buf;
}

/**
 * Converts a socket (<ip>:<port> or [<ip>]:<port> or [<ip>]:<port>%interface)
 * to a network socket
 * @param dst network socket object to store result
 * @param src input string
 * @return 0 if conversion was successful, negative otherwise
 */
int
netaddr_socket_from_string(union netaddr_socket *dst, const char *src) {
  struct netaddr_str nbuf;
  char *ptr1, *ptr2;
  char *ip_start;
  char *port_start;
  char *if_start;
  struct netaddr addr;
  uint32_t port;
  unsigned idx;

  /* copy address so we can modify the string */
  strscpy(nbuf.buf, src, sizeof(nbuf));

  /* get rid of whitespaces */
  ptr1 = str_trim(nbuf.buf);
  if (ptr1[0] == '-' && ptr1[1] == 0) {
    netaddr_socket_invalidate(dst);
    return 0;
  }

  if (ptr1[0] == '[') {
    ptr2 = strchr(ptr1, ']');
    if (!ptr2) {
      return -1;
    }

    /* get ip start */
    ip_start = &ptr1[1];
    *ptr2 = 0;

    ptr1 = &ptr2[1];
  }
  else {
    ip_start = ptr1;
    ptr1 = strchr(ptr1, ':');
    if (!ptr1) {
      return -2;
    }
  }
  /* get port start */
  if (*ptr1 != ':') {
    return -3;
  }
  *ptr1 = 0;
  port_start = &ptr1[1];

  /* get interface start */
  ptr2 = strchr(port_start, '%');
  if (ptr2) {
    *ptr2 = 0;
    if_start =  &ptr2[1];
  }
  else {
    if_start = NULL;
  }

  if (netaddr_from_string(&addr, ip_start)) {
    return -4;
  }
  port = strtoul(port_start, NULL, 10);
  if (port > 65535) {
    return -5;
  }
  if (if_start) {
    idx = if_nametoindex(if_start);
  }
  else {
    idx = 0;
  }

  return netaddr_socket_init(dst, &addr, port, idx) == 0 ? 0 : -6;
}

/**
 * Compares two addresses in network byte order.
 * Address type will be compared last.
 *
 * This function is compatible with the avl comparator
 * prototype.
 * @param k1 address 1
 * @param k2 address 2
 * @return >0 if k1>k2, <0 if k1<k2, 0 otherwise
 */
int
netaddr_avlcmp(const void *k1, const void *k2) {
  return netaddr_cmp(k1, k2);
}

/**
 * Compares two netaddr sockets.
 *
 * This function is compatible with the avl comparator
 * prototype.
 * @param k1 address 1
 * @param k2 address 2
 * @return >0 if k1>k2, <0 if k1<k2, 0 otherwise
 */
int
netaddr_socket_avlcmp(const void *k1, const void *k2) {
  return netaddr_socket_cmp(k1, k2);
}

/**
 * Compares an netaddr object with the address part of
 * a netaddr_socket.
 * @param a1 address
 * @param a2 socket
 * @return >0 if k1>k2, <0 if k1<k2, 0 otherwise
 */
int
netaddr_cmp_to_socket(const struct netaddr *a1, const union netaddr_socket *a2) {
  int result = 0;

  result = (int)a1->_type - (int)a2->std.sa_family;
  if (result) {
    return result;
  }

  if (a1->_type == AF_INET) {
    result = memcmp(a1->_addr, &a2->v4.sin_addr, 4);
  }
  else if (a1->_type == AF_INET6) {
    /* ipv6 */
    result = memcmp(a1->_addr, &a2->v6.sin6_addr, 16);
  }

  if (result) {
    return result;
  }

  return (int)a1->_prefix_len - (a1->_type == AF_INET ? 32 : 128);
}

/**
 * Calculates if a binary address is equals to a netaddr one.
 * @param addr netaddr pointer
 * @param bin pointer to binary address
 * @param len length of binary address
 * @param af family of binary address
 * @param prefix_len prefix length of binary address
 * @return true if matches, false otherwise
 */
bool
netaddr_isequal_binary(const struct netaddr *addr, const void *bin, size_t len, uint16_t af, uint8_t prefix_len) {
  uint32_t addr_len;

  if (addr->_type != af || addr->_prefix_len != prefix_len) {
    return false;
  }

  addr_len = netaddr_get_maxprefix(addr) >> 3;
  if (addr_len != len) {
    return false;
  }

  return memcmp(addr->_addr, bin, addr_len) == 0;
}

/**
 * Checks if a binary address is part of a netaddr prefix.
 * @param subnet netaddr prefix
 * @param bin pointer to binary address
 * @param len length of binary address
 * @param af_family address family of binary address
 * @return true if part of the prefix, false otherwise
 */
bool
netaddr_binary_is_in_subnet(const struct netaddr *subnet, const void *bin, size_t len, uint8_t af_family) {
  if (subnet->_type != af_family || netaddr_get_maxprefix(subnet) != len * 8) {
    return false;
  }
  return _binary_is_in_subnet(subnet, bin);
}

/**
 * Checks if a netaddr object is part of another netaddr prefix.
 * The prefix length of addr is ignored for this comparison.
 * @param subnet netaddr prefix
 * @param addr netaddr object that might be inside the prefix
 * @return true if addr is part of subnet, false otherwise
 */
bool
netaddr_is_in_subnet(const struct netaddr *subnet, const struct netaddr *addr) {
  if (subnet->_type != addr->_type) {
    return false;
  }
  return _binary_is_in_subnet(subnet, addr->_addr);
}

/**
 * Calculates the maximum prefix length of an address type
 * @param af_type address type
 * @return prefix length, 0 if unknown address family
 */
uint8_t
netaddr_get_af_maxprefix(uint32_t af_type) {
  switch (af_type) {
    case AF_INET:
      return 32;
      break;
    case AF_INET6:
      return 128;
    case AF_MAC48:
      return 48;
      break;
    case AF_EUI64:
      return 64;
      break;

    default:
      return 0;
  }
}

#ifdef WIN32
/**
 * Helper function for windows
 * @param dst
 * @param bin
 * @param dst_size
 * @param bin_size
 * @param separator
 * @return
 */
const char *
inet_ntop(int af, const void *src, char *dst, socklen_t cnt) {
  if (af == AF_INET) {
    struct sockaddr_in in;
    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    memcpy(&in.sin_addr, src, sizeof(struct in_addr));
    getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
    return dst;
  }
  else if (af == AF_INET6) {
    struct sockaddr_in6 in;
    memset(&in, 0, sizeof(in));
    in.sin6_family = AF_INET6;
    memcpy(&in.sin6_addr, src, sizeof(struct in_addr6));
    getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);
    return dst;
  }
  return NULL;
}

/**
 * Helper function for windows
 * @param dst
 * @param bin
 * @param dst_size
 * @param bin_size
 * @param separator
 * @return
 */
int
inet_pton(int af, const char *src, void *dst) {
  struct addrinfo hints, *res;
  union netaddr_socket *sock;

  if (af != AF_INET && af != AF_INET6) {
    return -1;
  }

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = af;
  hints.ai_flags = AI_NUMERICHOST;

  if (getaddrinfo(src, NULL, &hints, &res) != 0) {
    return -1;
  }

  if (res == NULL) {
    return 0;
  }

  sock = (union netaddr_socket *)res->ai_addr;
  if (af == AF_INET) {
    memcpy(dst, &sock->v4.sin_addr, 4);
  }
  else {
    memcpy(dst, &sock->v6.sin6_addr, 16);
  }

  freeaddrinfo(res);
  return 1;
}

#endif

/**
 * Converts a binary mac address into a string representation
 * @param dst pointer to target string buffer
 * @param dst_size size of string buffer
 * @param bin pointer to binary source buffer
 * @param bin_size size of binary buffer
 * @param separator character for separating hexadecimal octets,
 *     0 for no separator
 * @return pointer to target buffer, NULL if an error happened
 */
static char *
_mac_to_string(char *dst, size_t dst_size, const void *bin, size_t bin_size, char separator) {
  static const char hex[] = "0123456789abcdef";
  char *last_separator, *_dst;
  const uint8_t *_bin;

  _bin = bin;
  _dst = dst;
  last_separator = dst;

  if (dst_size == 0) {
    return NULL;
  }

  while (bin_size > 0 && dst_size >= 3) {
    *_dst++ = hex[(*_bin) >> 4];
    *_dst++ = hex[(*_bin) & 15];

    /* copy pointer to separator */
    last_separator = _dst;

    /* write separator */
    if (separator) {
      *_dst++ = separator;
      dst_size--;
    }

    /* advance source pointer and decrease remaining length of buffer*/
    _bin++;
    bin_size--;

    /* calculate remaining destination size */
    dst_size -= 2;
  }

  *last_separator = 0;
  return dst;
}

/**
 * Convert a binary UUID into its string representation
 * @param dst pointer to target string buffer
 * @param dst_size size of string buffer
 * @param src pointer to binary source buffer
 * @param src_size size of binary buffer
 * @return pointer to target buffer, NULL if an error happened
 */
static char *
_uuid_to_string(char *dst, size_t dst_size, const void *src, size_t src_size) {
  static const size_t max_group_len[5] = { 8, 4, 4, 4, 12 };
  const char *_src;
  char *_dst;
  size_t i;

  if (src_size != 16) {
    return NULL;
  }
  if (dst_size < 32 + 4 + 1) {
    return NULL;
  }

  _src = src;
  _dst = dst;
  for (i = 0; i < ARRAYSIZE(max_group_len); i++) {
    if (!_mac_to_string(_dst, dst_size, _src, max_group_len[i] / 2, 0)) {
      return NULL;
    }

    _src += (max_group_len[i] / 2);
    _dst += (max_group_len[i]);
    dst_size -= max_group_len[i];

    if (i < ARRAYSIZE(max_group_len) - 1) {
      *_dst++ = '-';
      dst_size--;
    }
  }
  return dst;
}

/**
 * Convert a hex string (with optional separators) into a binary representation
 * @param bin pointer to target binary buffer
 * @param bin_size pointer to size of target buffer
 * @param src pointer to source string
 * @param separator character used to separate octets in source string,
 *     0 for no separator
 * @return number of bytes left in target buffer, -1 if an error happened
 */
static int
_bin_from_hex(void *bin, size_t bin_size, const char *src, char separator) {
  uint8_t *_bin;
  int num, digit_2;

  _bin = bin;

  while (bin_size > 0) {
    num = _read_hexdigit(*src++);
    if (num == -1) {
      return -1;
    }
    digit_2 = _read_hexdigit(*src);
    if (digit_2 >= 0) {
      num = (num << 4) + digit_2;
      src++;
    }
    *_bin++ = (uint8_t)num;

    bin_size--;

    if (*src == 0) {
      return bin_size;
    }
    if (separator) {
      if (*src++ != separator) {
        return -1;
      }
    }
  }
  return -1;
}

/**
 * Convert a string UUID into the binary (16 byte) representation
 * @param bin target buffer
 * @param bin_size size of target buffer
 * @param src UUID string
 * @return -1 if an error happened, 0 otherwise
 */
static int
_uuid_from_string(void *bin, size_t bin_size, const char *src) {
  static const size_t max_group_len[5] = { 8, 4, 4, 4, 12 };
  char buffer[32 + 4 + 1];
  char *current_group, *next_group, *_bin;
  size_t i;

  if (bin_size < 16) {
    return -1;
  }
  if (strlen(src) > 32 + 4) {
    return -1;
  }

  strscpy(buffer, src, sizeof(buffer));

  _bin = bin;
  current_group = buffer;
  for (i = 0; i < ARRAYSIZE(max_group_len); i++) {
    next_group = strchr(current_group, '-');
    if (next_group) {
      /* zero terminate current group */
      *next_group++ = 0;
    }
    else if (i != ARRAYSIZE(max_group_len) - 1) {
      /* not enough components */
      return -1;
    }

    /* check length */
    if (strlen(current_group) != max_group_len[i]) {
      return -1;
    }

    /* parse data, we expect a precise number of hex-numbers */
    if (_bin_from_hex(_bin, max_group_len[i] / 2, current_group, 0)) {
      return -1;
    }

    current_group = next_group;
    _bin = _bin + max_group_len[i] / 2;
  }
  return 0;
}

/**
 * Reads a single hexadecimal digit
 * @param c digit to be read
 * @return integer value (0-15) of digit,
 *   -1 if not a hexadecimal digit
 */
static int
_read_hexdigit(const char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

/**
 * Converts a ipv4 subnet mask into a prefix length.
 * @param src string representation of subnet mask
 * @return prefix length, -1 if source was not a wellformed
 *   subnet mask
 */
static int
_subnetmask_to_prefixlen(const char *src) {
  uint32_t v4, shift;
  int len;

  if (inet_pton(AF_INET, src, &v4) != 1) {
    return -1;
  }

  /* transform into host byte order */
  v4 = ntohl(v4);

  shift = 0xffffffff;
  for (len = 31; len >= 0; len--) {
    if (v4 == shift) {
      return len;
    }
    shift <<= 1;
  }

  /* not wellformed */
  return -1;
}

/**
 * Calculates if a binary address is part of a netaddr prefix.
 * It will assume that the length of the binary address and its
 * address family makes sense.
 * @param subnet netaddr prefix
 * @param bin pointer to binary address
 * @return true if part of the prefix, false otherwise
 */
static bool
_binary_is_in_subnet(const struct netaddr *subnet, const void *bin) {
  size_t byte_length, bit_length;
  const uint8_t *_bin;

  _bin = bin;

  /* split prefix length into whole bytes and bit rest */
  byte_length = subnet->_prefix_len / 8;
  bit_length = subnet->_prefix_len % 8;

  /* compare whole bytes */
  if (memcmp(subnet->_addr, bin, byte_length) != 0) {
    return false;
  }

  /* compare bits if necessary */
  if (bit_length != 0) {
    return (subnet->_addr[byte_length] >> (8 - bit_length)) == (_bin[byte_length] >> (8 - bit_length));
  }
  return true;
}
