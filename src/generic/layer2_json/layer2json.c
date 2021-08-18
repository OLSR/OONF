
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

#include <stdio.h>
#include <jansson.h>

#include <oonf/libcommon/autobuf.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/libcommon/string.h>
#include <oonf/libcommon/template.h>

#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_clock.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_telnet.h>

#include <oonf/generic/layer2_json/layer2_json.h>
#include <oonf/generic/layer2_json/layer2_json_internal.h>

/* definitions */
#define LOG_LAYER2_JSON _oonf_layer2json_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

static enum oonf_telnet_result _cb_layer2json(struct oonf_telnet_data *con);

/* telnet command of this plugin */
static struct oonf_telnet_command _telnet_commands[] = {
  TELNET_CMD(OONF_LAYER2JSON_SUBSYSTEM, _cb_layer2json, "TODO: Help!"),
};

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_CLOCK_SUBSYSTEM,
  OONF_LAYER2_SUBSYSTEM,
  OONF_TELNET_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_layer2json_subsystem = {
  .name = OONF_LAYER2JSON_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OLSRv2 layer2 json plugin",
  .author = "Henning Rogge",
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_layer2json_subsystem);

/**
 * Initialize plugin
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  oonf_telnet_add(&_telnet_commands[0]);
  l2json_import_init(LOG_LAYER2_JSON);
  l2json_export_init(LOG_LAYER2_JSON);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  l2json_export_cleanup();
  l2json_import_cleanup();
  oonf_telnet_remove(&_telnet_commands[0]);
}

/**
 * Callback for the telnet command of this plugin
 * @param con pointer to telnet session data
 * @return telnet result value
 */
static enum oonf_telnet_result
_cb_layer2json(struct oonf_telnet_data *con) {
  const char *second;

  if ((second = str_hasnextword(con->parameter, "import"))) {
    if (l2json_import(con, second)) {
      return TELNET_RESULT_INTERNAL_ERROR;
    }
  }
  if ((second = str_hasnextword(con->parameter, "export"))) {
    if (l2json_export(con)) {
      return TELNET_RESULT_INTERNAL_ERROR;
    }
  }
  if ((second = str_hasnextword(con->parameter, "replace"))) {
    char originname[32];
    const char *third;
    struct oonf_layer2_origin *origin;

    third = str_cpynextword(originname, second, sizeof(originname));
    if (!third) {
        abuf_appendf(con->out, "Error, no origin provided");
        return TELNET_RESULT_ACTIVE;
    }

    origin = oonf_layer2_origin_get(originname);
    if (origin) {
      struct oonf_layer2_net *l2net, *l2net_it;

      avl_for_each_element_safe(oonf_layer2_get_net_tree(), l2net, _node, l2net_it) {
        oonf_layer2_net_remove(l2net, origin);
      }
    }

    if (l2json_import(con, third)) {
      return TELNET_RESULT_INTERNAL_ERROR;
    }
  }

  return 0;
}
