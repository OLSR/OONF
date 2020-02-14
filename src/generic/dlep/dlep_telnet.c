
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

#include <oonf/oonf.h>
#include <oonf/base/oonf_telnet.h>
#include <oonf/base/oonf_viewer.h>

#include <oonf/generic/dlep/dlep.h>
#include <oonf/generic/dlep/dlep_interface.h>
#include <oonf/generic/dlep/dlep_session.h>
#include <oonf/generic/dlep/dlep_internal.h>
#include <oonf/generic/dlep/dlep_telnet.h>

#define SUBCOMMAND_TERMINATE "terminate"

#define KEY_IF_NAME         "if_name"
#define KEY_IF_SOCKET4      "if_socket4"
#define KEY_IF_SOCKET6      "if_socket6"
#define KEY_IF_RADIO        "if_radio"
#define KEY_SESSION_LOCAL   "session_local"
#define KEY_SESSION_REMOTE  "session_remote"
#define KEY_SESSION_UPTIME  "session_uptime"

static enum oonf_telnet_result _cb_dlepinfo_cmd(struct oonf_telnet_data *con);
static enum oonf_telnet_result _cb_dlepinfo_help(struct oonf_telnet_data *con);

static int _cb_create_text_if(struct oonf_viewer_template *);
static int _cb_create_text_session(struct oonf_viewer_template *);
static void _initialize_if_values(struct dlep_if *interf);
static void _initialize_session_values(struct dlep_session *session, bool raw);

/* telnet interface variables */
static char _value_if_name[IF_NAMESIZE];
static struct netaddr_str _value_if_socket4;
static struct netaddr_str _value_if_socket6;
static char _value_if_radio[TEMPLATE_JSON_BOOL_LENGTH];
static struct netaddr_str _value_session_local;
static struct netaddr_str _value_session_remote;
static struct isonumber_str _value_session_uptime;

static struct abuf_template_data_entry _tde_if[] = {
  { KEY_IF_NAME, _value_if_name, true },
  { KEY_IF_RADIO, _value_if_radio, true },
  { KEY_IF_SOCKET4, _value_if_socket4.buf, true },
  { KEY_IF_SOCKET6, _value_if_socket6.buf, true },
};
static struct abuf_template_data_entry _tde_session[] = {
  { KEY_SESSION_LOCAL, _value_session_local.buf, true },
  { KEY_SESSION_REMOTE, _value_session_remote.buf, true },
  { KEY_SESSION_UPTIME, _value_session_uptime.buf, true },
};

static struct abuf_template_data _td_if[] = {
  { _tde_if, ARRAYSIZE(_tde_if) },
};
static struct abuf_template_data _td_session[] = {
  { _tde_if, ARRAYSIZE(_tde_if) },
  { _tde_session, ARRAYSIZE(_tde_session) },
};

static struct oonf_viewer_template _templates[] = {
  {
    .data = _td_if,
    .data_size = ARRAYSIZE(_td_if),
    .json_name = "interface",
    .cb_function = _cb_create_text_if,
  },
  {
    .data = _td_session,
    .data_size = ARRAYSIZE(_td_session),
    .json_name = "session",
    .cb_function = _cb_create_text_session,
  }
};

static struct abuf_template_storage _template_storage;

static struct oonf_telnet_command _dlep_cmd =
  TELNET_CMD("dlepinfo", _cb_dlepinfo_cmd, "",.help_handler = _cb_dlepinfo_help);

/**
 * Initialize DLEP telnet interface
 * @return always 0
 */
int
dlep_telnet_init(void) {
  oonf_telnet_add(&_dlep_cmd);
  return 0;
}

/**
 * Cleanup DLEP telnet interface
 */
void
dlep_telnet_cleanup(void) {
  oonf_telnet_remove(&_dlep_cmd);
}

/**
 * Iterate over all DLEP sessions and terminate them
 */
static void
_terminate_all_dlep_sessions(void) {
  struct dlep_if *interf;
  struct dlep_session *session;

  avl_for_each_element(dlep_if_get_tree(true), interf, _node) {
    avl_for_each_element(&interf->session_tree, session, _node) {
      dlep_session_terminate(session, DLEP_STATUS_OKAY,
        "DLEP session terminated by admin");
    }
  }
  avl_for_each_element(dlep_if_get_tree(false), interf, _node) {
    avl_for_each_element(&interf->session_tree, session, _node) {
      dlep_session_terminate(session, DLEP_STATUS_OKAY,
        "DLEP session terminated by admin");
    }
  }
}

/**
 * Callback for dlepinfo telnet command
 * @param con telnet connection
 * @return telnet result
 */
static enum oonf_telnet_result
_cb_dlepinfo_cmd(struct oonf_telnet_data *con) {
  const char *next;

  if ((next = str_hasnextword(con->parameter, SUBCOMMAND_TERMINATE)) != NULL) {
    if (strcasecmp(next, "true") == 0) {
      _terminate_all_dlep_sessions();
    }
    else {
      abuf_puts(con->out, "Please use the additional boolean parameter 'true' to"
          "terminate all DLEP sessions\n");
      return TELNET_RESULT_ACTIVE;
    }
  }
  return oonf_viewer_telnet_handler(
    con->out, &_template_storage, OONF_DLEP_SUBSYSTEM, con->parameter, _templates, ARRAYSIZE(_templates));
}

/**
 * Callback for dlepinfo telnet help command
 * @param con telnet connection
 * @return telnet result
 */
static enum oonf_telnet_result
_cb_dlepinfo_help(struct oonf_telnet_data *con) {
  enum oonf_telnet_result result;

  result = oonf_viewer_telnet_help(
      con->out, OONF_DLEP_SUBSYSTEM, con->parameter, _templates, ARRAYSIZE(_templates);
  if (result == TELNET_RESULT_ACTIVE) {
    if (con->parameter == NULL || con->parameter[0] == 0
        || strcasecmp(con->parameter, SUBCOMMAND_TERMINATE) == 0) {
      abuf_puts(con->out, SUBCOMMAND_TERMINATE
          ": terminates all running dlep sessions\n");
    }
  }
  return result;
}

/**
 * Create the telnet output for 'dlepinfo interface'
 * @param template viewer template
 * @return always 0
 */
static int
_cb_create_text_if(struct oonf_viewer_template *template) {
  struct dlep_if *interf;

  avl_for_each_element(dlep_if_get_tree(true), interf, _node) {
    _initialize_if_values(interf);
    oonf_viewer_output_print_line(template);
  }
  avl_for_each_element(dlep_if_get_tree(false), interf, _node) {
    _initialize_if_values(interf);
    oonf_viewer_output_print_line(template);
  }
  return 0;
}

/**
 * Create the telnet output for 'dlepinfo session'
 * @param template viewer template
 * @return always 0
 */
static int
_cb_create_text_session(struct oonf_viewer_template *template) {
  struct dlep_if *interf;
  struct dlep_session *session;

  avl_for_each_element(dlep_if_get_tree(true), interf, _node) {
    _initialize_if_values(interf);

    avl_for_each_element(&interf->session_tree, session, _node) {
      _initialize_session_values(session, template->create_raw);
      oonf_viewer_output_print_line(template);
    }
  }
  avl_for_each_element(dlep_if_get_tree(false), interf, _node) {
    _initialize_if_values(interf);

    avl_for_each_element(&interf->session_tree, session, _node) {
      _initialize_session_values(session, template->create_raw);
      oonf_viewer_output_print_line(template);
    }
  }
  return 0;
}

/**
 * Initialize the value buffers for a DLEP interface
 * @param interf DLEP interface
 */
static void
_initialize_if_values(struct dlep_if *interf) {
  strscpy(_value_if_name, interf->l2_ifname, sizeof(_value_if_name));
  netaddr_socket_to_string(&_value_if_socket4, &interf->udp.socket_v4.local_socket);
  netaddr_socket_to_string(&_value_if_socket6, &interf->udp.socket_v6.local_socket);
  strscpy(_value_if_radio, json_getbool(interf->radio), sizeof(_value_if_radio));
}

/**
 * Initialize the value buffers for a DLEP session
 * @param session DLEP session
 * @param raw true to switch numeric values to raw mode, false for ISO prefix mode
 */
static void
_initialize_session_values(struct dlep_session *session, bool raw) {
  netaddr_socket_to_string(&_value_session_local, &session->local_socket);
  netaddr_socket_to_string(&_value_session_remote, &session->remote_socket);
  oonf_clock_toIntervalString_ext(&_value_session_uptime,
      -oonf_clock_get_relative(session->activation_time), raw);
}
