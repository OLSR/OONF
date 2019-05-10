
/*
 * The olsr.org Optimized Link-State Routing daemon version 2 (olsrd2)
 * Copyright (c) 2004-2019, the olsr.org team - see HISTORY file
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

#ifndef OONF_DNS_QUERY_H_
#define OONF_DNS_QUERY_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>

#include <oonf/base/oonf_socket.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/dns_query/dns.h>

#define OONF_DNS_QUERY_SUBSYSTEM "dns_query"

enum {
  OONF_DNS_HOSTNAME_LENGTH = 256
};

enum dns_service_query_status {
  DNS_SERVICE_QUERY_SUCCESSFUL,
  DNS_SERVICE_QUERY_NETWORK_ERROR,
  DNS_SERVICE_QUERY_NO_HOSTNAME
};

struct oonf_dns_query {
  /*! DNS server to query */
  union netaddr_socket *dns_server;

  /*! DNS client socket */
  union netaddr_socket *dns_client;

  /*! type of DNS query (e.g. A, AAAA, PTR) */
  enum dns_type dns_type;

  /*! query */
  const char *query;

  /*! name of socket to register with scheduler */
  const char *socket_name;

  /*! function to call when done */
  void (*cb_done)(struct oonf_dns_query *, bool timeout);

  /*! function to call with result */
  struct {
    void (*srv_result)(struct oonf_dns_query *, struct dns_srv *response);
    void (*a_result)(struct oonf_dns_query *, struct dns_a *response);
    void (*aaaa_result)(struct oonf_dns_query *, struct dns_aaaa *response);
    void (*ptr_result)(struct oonf_dns_query *, struct dns_ptr *response);
    void (*any_result)(struct oonf_dns_query *, enum dns_type type, union dns_any *response);
  } cb;

  /*! time until the query will be stopped */
  uint64_t timeout;

  /*! storage for binary query */
  union {
    struct dns_packet packet;
    uint8_t full_length[dns_p_calcsize((512))];
  } _bin_query;

  /*! pointer to store DNS socket */
  struct dns_socket *_dns_socket;

  /*! scheduler entry for DNS socket */
  struct oonf_socket_entry _socket_entry;

  /*! timeout instance for query */
  struct oonf_timer_instance _timeout;
};

int dns_query_do(struct oonf_dns_query *q);

/**
 * Start a DNS SRV query
 * @param q intialized query
 */
static INLINE int
dns_query_srv(struct oonf_dns_query *q) {
  q->dns_type = DNS_T_SRV;
  return dns_query_do(q);
}

/**
 * Start a DNS A query
 * @param q intialized query
 */
static INLINE int
dns_query_a(struct oonf_dns_query *q) {
  q->dns_type = DNS_T_A;
  return dns_query_do(q);
}

/**
 * Start a DNS AAAA query
 * @param q intialized query
 */
static INLINE int
dns_query_aaaa(struct oonf_dns_query *q) {
  q->dns_type = DNS_T_AAAA;
  return dns_query_do(q);
}

/**
 * Start a DNS PTR query
 * @param q intialized query
 */
static INLINE int
dns_query_ptr(struct oonf_dns_query *q) {
  q->dns_type = DNS_T_PTR;
  return dns_query_do(q);
}

/**
 * Get type of DNS query
 * @param q DNS query
 * @returns type
 */
static INLINE enum dns_type
dns_query_get_type(struct oonf_dns_query *q) {
  return q->dns_type;
}

#endif /* IF_NO_MULTICAST_DNS_QUERY_H_ */
