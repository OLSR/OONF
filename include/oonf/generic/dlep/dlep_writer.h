
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

#ifndef DLEP_WRITER_H_
#define DLEP_WRITER_H_

#include <oonf/libcommon/autobuf.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>

#include <oonf/base/oonf_layer2.h>

#include <oonf/generic/dlep/dlep_session.h>

void dlep_writer_start_signal(struct dlep_writer *writer, uint16_t signal_type);
void dlep_writer_add_tlv(struct dlep_writer *writer, uint16_t type, const void *data, uint16_t len);
void dlep_writer_add_tlv2(
  struct dlep_writer *writer, uint16_t type, const void *data1, uint16_t len1, const void *data2, uint16_t len2);
int dlep_writer_finish_signal(struct dlep_writer *writer, enum oonf_log_source source);
void dlep_writer_add_heartbeat_tlv(struct dlep_writer *writer, uint64_t interval);
void dlep_writer_add_peer_type_tlv(struct dlep_writer *writer, const char *peer_type, bool access_control);
int dlep_writer_add_mac_tlv(struct dlep_writer *writer, const struct oonf_layer2_neigh_key *mac_lid);
int dlep_writer_add_lid_tlv(struct dlep_writer *writer, const struct oonf_layer2_neigh_key *mac_lid);
int dlep_writer_add_lid_length_tlv(struct dlep_writer *writer, uint16_t link_id_length);
int dlep_writer_add_ip_tlv(struct dlep_writer *writer, const struct netaddr *ipv4, bool add);
void dlep_writer_add_ipv4_conpoint_tlv(struct dlep_writer *writer, const struct netaddr *addr, uint16_t port, bool tls);
void dlep_writer_add_ipv6_conpoint_tlv(struct dlep_writer *writer, const struct netaddr *addr, uint16_t port, bool tls);
void dlep_writer_add_ipv4_dns_tlv(struct dlep_writer *writer, const union netaddr_socket *sock);
void dlep_writer_add_ipv6_dns_tlv(struct dlep_writer *writer, const union netaddr_socket *sock);
void dlep_writer_add_uint64(struct dlep_writer *writer, uint64_t number, enum dlep_tlvs tlv);
void dlep_writer_add_int64(struct dlep_writer *writer, int64_t number, enum dlep_tlvs tlv);
int dlep_writer_add_status(struct dlep_writer *writer, enum dlep_status status, const char *text);
void dlep_writer_add_supported_extensions(struct dlep_writer *writer, const uint16_t *extensions, uint16_t ext_count);

int dlep_writer_map_identity(struct dlep_writer *writer, struct oonf_layer2_data *data,
  const struct oonf_layer2_metadata *meta, uint16_t tlv, uint16_t length, uint64_t scaling);
int dlep_writer_map_l2neigh_data(
  struct dlep_writer *writer, struct dlep_extension *ext, struct oonf_layer2_data *data, struct oonf_layer2_data *def);
int dlep_writer_map_l2net_data(struct dlep_writer *writer, struct dlep_extension *ext, struct oonf_layer2_data *data);

#endif /* DLEP_WRITER_H_ */
