
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

#ifndef _PROTO_H_
#define _PROTO_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>

#include <oonf/base/oonf_layer2.h>
#include <oonf/generic/dlep/dlep_extension.h>
#include <oonf/generic/dlep/dlep_session.h>

struct dlep_extension *dlep_base_proto_init(void);
void dlep_base_proto_start_local_heartbeat(struct dlep_session *session);
void dlep_base_proto_start_remote_heartbeat(struct dlep_session *session);
void dlep_base_proto_stop_timers(struct dlep_session *session);
enum dlep_status dlep_base_proto_print_status(struct dlep_session *session);
void dlep_base_proto_print_peer_type(struct dlep_session *session);
int dlep_base_proto_process_session_termination(struct dlep_extension *, struct dlep_session *);
int dlep_base_proto_process_session_termination_ack(struct dlep_extension *, struct dlep_session *);
int dlep_base_proto_process_heartbeat(struct dlep_extension *, struct dlep_session *);
int dlep_base_proto_write_mac_only(struct dlep_extension *, struct dlep_session *session,
    const struct oonf_layer2_neigh_key *neigh);

int dlep_base_proto_process_session_update(struct dlep_extension *ext, struct dlep_session *session);
int dlep_base_proto_process_session_update_ack(struct dlep_extension *ext, struct dlep_session *session);

#endif /* _PROTO_H_ */
