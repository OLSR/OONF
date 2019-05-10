/**
 * Copyright (C) 2019 Fraunhofer FKIE
 *
 * @author         Henning Rogge
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

  enum dns_type dns_type;

  const char *query;

  const char *socket_name;

  /* function to call when done */
  void (*cb_done)(struct oonf_dns_query *, bool timeout);

  /* function to call with result */
  struct {
    void (*srv_result)(struct oonf_dns_query *, struct dns_srv *response);
    void (*a_result)(struct oonf_dns_query *, struct dns_a *response);
    void (*aaaa_result)(struct oonf_dns_query *, struct dns_aaaa *response);
    void (*ptr_result)(struct oonf_dns_query *, struct dns_ptr *response);
    void (*any_result)(struct oonf_dns_query *, enum dns_type type, union dns_any *response);
  } cb;

  uint64_t timeout;

  union {
    struct dns_packet packet;
    uint8_t full_length[dns_p_calcsize((512))];
  } _bin_query;

  struct dns_socket *_dns_socket;
  struct oonf_socket_entry _socket_entry;
  struct oonf_timer_instance _timeout;
};

int dns_query_do(struct oonf_dns_query *q);

static INLINE int
dns_query_srv(struct oonf_dns_query *q) {
  q->dns_type = DNS_T_SRV;
  return dns_query_do(q);
}

static INLINE int
dns_query_a(struct oonf_dns_query *q) {
  q->dns_type = DNS_T_A;
  return dns_query_do(q);
}

static INLINE int
dns_query_aaaa(struct oonf_dns_query *q) {
  q->dns_type = DNS_T_AAAA;
  return dns_query_do(q);
}

static INLINE int
dns_query_ptr(struct oonf_dns_query *q) {
  q->dns_type = DNS_T_PTR;
  return dns_query_do(q);
}

static INLINE enum dns_type
dns_query_get_type(struct oonf_dns_query *q) {
  return q->dns_type;
}

#endif /* IF_NO_MULTICAST_DNS_QUERY_H_ */
