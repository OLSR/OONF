
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

#ifndef _DLEP_READER_H_
#define _DLEP_READER_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>

#include <oonf/base/oonf_layer2.h>

#include <oonf/generic/dlep/dlep_extension.h>

int dlep_reader_heartbeat_tlv(uint64_t *interval, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_peer_type(
  char *text, size_t text_length, bool *secured, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_mac_tlv(struct oonf_layer2_neigh_key *lid, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_lid_tlv(struct oonf_layer2_neigh_key *lid, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_lid_length_tlv(uint16_t *length, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_ipv4_tlv(
  struct netaddr *ipv4, bool *add, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_ipv6_tlv(
  struct netaddr *ipv6, bool *add, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_ipv4_subnet_tlv(
  struct netaddr *ipv6, bool *add, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_ipv6_subnet_tlv(
  struct netaddr *ipv6, bool *add, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_ipv4_conpoint_tlv(
  struct netaddr *addr, uint16_t *port, bool *tls, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_ipv6_conpoint_tlv(
  struct netaddr *addr, uint16_t *port, bool *tls, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_ipv4_dns_tlv(
  union netaddr_socket *sock, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_ipv6_dns_tlv(
  union netaddr_socket *sock, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_uint64(
  uint64_t *number, uint16_t tlv_id, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_int64(int64_t *number, uint16_t tlv_id, struct dlep_session *session, struct dlep_parser_value *value);
int dlep_reader_status(enum dlep_status *status, char *text, size_t text_length, struct dlep_session *session,
  struct dlep_parser_value *value);

int dlep_reader_map_identity(struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta,
  struct dlep_session *session, uint16_t dlep_tlv, uint64_t scaling);
int dlep_reader_map_l2neigh_data(
  struct oonf_layer2_data *data, struct dlep_session *session, struct dlep_extension *ext);
int dlep_reader_map_l2net_data(struct oonf_layer2_data *data, struct dlep_session *session, struct dlep_extension *ext);

#endif /* _DLEP_READER_H_ */
