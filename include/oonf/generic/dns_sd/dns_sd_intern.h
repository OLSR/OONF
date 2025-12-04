/**
 * Copyright (C) 2019 Fraunhofer FKIE
 *
 * @author         Henning Rogge
 */

/**
 * @file
 */

#ifndef OONF_DNS_SD_INTERN_H_
#define OONF_DNS_SD_INTERN_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/list.h>

#include <oonf/generic/dns_query/dns_query.h>

struct dns_sd_query {
  struct oonf_dns_query dns;

  union netaddr_socket server;
  union netaddr_socket client;

  struct dns_sd_context *context;

  char name[512];
  struct dns_sd_prefix *prefix;

  struct {
    struct dns_sd_service *service;
    struct netaddr ipv4;
    struct netaddr ipv6;
  } srv_result;
};

#endif /* OONF_DNS_SD_INTERN_H_ */
