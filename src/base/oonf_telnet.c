
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

#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>

#include <oonf/libconfig/cfg_schema.h>

#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_stream_socket.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/base/oonf_telnet.h>

/* Definitions */
#define LOG_TELNET _oonf_telnet_subsystem.logging

struct _telnet_config {
  struct oonf_stream_managed_config osmc;
  int32_t allowed_sessions;
  uint64_t timeout;
};

/* static function prototypes */
static int _init(void);
static void _cleanup(void);

static int _avl_comp_strcmdword(const void *txt1, const void *txt2);

static void _call_stop_handler(struct oonf_telnet_data *data);
static void _cb_config_changed(void);
static int _cb_telnet_init(struct oonf_stream_session *);
static void _cb_telnet_cleanup(struct oonf_stream_session *);
static void _cb_telnet_create_error(struct oonf_stream_session *, enum oonf_stream_errors);
static enum oonf_stream_session_state _cb_telnet_receive_data(struct oonf_stream_session *);
static enum oonf_telnet_result _telnet_handle_command(struct oonf_telnet_data *);
static struct oonf_telnet_command *_check_telnet_command_acl(
  struct oonf_telnet_data *data, struct oonf_telnet_command *cmd);

static void _cb_telnet_repeat_timer(struct oonf_timer_instance *data);
static enum oonf_telnet_result _cb_telnet_quit(struct oonf_telnet_data *data);
static enum oonf_telnet_result _cb_telnet_help(struct oonf_telnet_data *data);
static enum oonf_telnet_result _cb_telnet_echo(struct oonf_telnet_data *data);
static enum oonf_telnet_result _cb_telnet_repeat(struct oonf_telnet_data *data);
static enum oonf_telnet_result _cb_telnet_timeout(struct oonf_telnet_data *data);

/* configuration of telnet server */
static struct cfg_schema_entry _telnet_entries[] = {
  CFG_MAP_ACL_V46(_telnet_config, osmc.acl, "acl", ACL_DEFAULT_ACCEPT, "Access control list for telnet interface"),
  CFG_MAP_ACL(_telnet_config, osmc.bindto, "bindto",
    "127.0.0.1\0"
    "::1\0" ACL_DEFAULT_REJECT,
    "Allowed addressed to bind telnet socket to"),
  CFG_MAP_INT32_MINMAX(_telnet_config, osmc.port, "port", "2009", "Network port for telnet interface", 0, 1, 65535),
  CFG_MAP_INT32_MINMAX(_telnet_config, allowed_sessions, "allowed_sessions", "3",
    "Maximum number of allowed simultaneous sessions", 0, 3, 1024),
  CFG_MAP_CLOCK(_telnet_config, timeout, "timeout", "120000", "Time until a telnet session is closed when idle"),
};

static struct cfg_schema_section _telnet_section = {
  .type = OONF_TELNET_SUBSYSTEM,
  .mode = CFG_SSMODE_UNNAMED,
  .help = "Settings for the telnet interface",
  .cb_delta_handler = _cb_config_changed,
  .entries = _telnet_entries,
  .entry_count = ARRAYSIZE(_telnet_entries),
};

/* built-in telnet commands */
static struct oonf_telnet_command _builtin[] = {
  TELNET_CMD("quit", _cb_telnet_quit, "Ends telnet session"),
  TELNET_CMD("exit", _cb_telnet_quit, "Ends telnet session"),
  TELNET_CMD("help", _cb_telnet_help, "help: Display the online help text and a list of commands"),
  TELNET_CMD("echo", _cb_telnet_echo, "echo <string>: Prints a string"),
  TELNET_CMD("repeat", _cb_telnet_repeat, "repeat <seconds> <command>: Repeats a telnet command every X seconds"),
  TELNET_CMD("timeout", _cb_telnet_timeout, "timeout <seconds> :Sets telnet session timeout"),
};

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_STREAM_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_telnet_subsystem = {
  .name = OONF_TELNET_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
  .cfg_section = &_telnet_section,
};
DECLARE_OONF_PLUGIN(_oonf_telnet_subsystem);

/* telnet session handling */
static struct oonf_class _telnet_memcookie = {
  .name = "telnet session",
  .size = sizeof(struct oonf_telnet_session),
};
static struct oonf_timer_class _telnet_repeat_timerinfo = {
  .name = "txt repeat timer",
  .callback = _cb_telnet_repeat_timer,
  .periodic = true,
};

static struct oonf_stream_managed _telnet_managed = {
  .config =
    {
      .session_timeout = 120000, /* 120 seconds */
      .allowed_sessions = 3,
      .memcookie = &_telnet_memcookie,
      .init_session = _cb_telnet_init,
      .cleanup_session = _cb_telnet_cleanup,
      .receive_data = _cb_telnet_receive_data,
      .create_error = _cb_telnet_create_error,
    },
};

static struct avl_tree _telnet_cmd_tree;

/**
 * Initialize telnet subsystem
 * @return always returns 0
 */
static int
_init(void) {
  size_t i;

  oonf_class_add(&_telnet_memcookie);
  oonf_timer_add(&_telnet_repeat_timerinfo);

  oonf_stream_add_managed(&_telnet_managed);

  /* initialize telnet commands */
  avl_init(&_telnet_cmd_tree, _avl_comp_strcmdword, false);
  for (i = 0; i < ARRAYSIZE(_builtin); i++) {
    oonf_telnet_add(&_builtin[i]);
  }
  return 0;
}

/**
 * Cleanup all allocated data of telnet subsystem
 */
static void
_cleanup(void) {
  oonf_stream_remove_managed(&_telnet_managed, true);
  oonf_class_remove(&_telnet_memcookie);
}

/**
 * Add a new telnet command to telnet subsystem
 * @param command pointer to initialized telnet command object
 * @return -1 if an error happened, 0 otherwise
 */
int
oonf_telnet_add(struct oonf_telnet_command *command) {
  command->_node.key = command->command;
  if (avl_insert(&_telnet_cmd_tree, &command->_node)) {
    return -1;
  }
  return 0;
}

/**
 * Remove a telnet command from telnet subsystem
 * @param command pointer to telnet command object
 */
void
oonf_telnet_remove(struct oonf_telnet_command *command) {
  avl_remove(&_telnet_cmd_tree, &command->_node);
}

/**
 * Stop a currently running continuous telnet command
 * @param data pointer to telnet data
 * @param print_prompt true to add a new prompt to the output
 */
void
oonf_telnet_stop(struct oonf_telnet_data *data, bool print_prompt) {
  _call_stop_handler(data);
  data->show_echo = true;
  if (print_prompt) {
    abuf_puts(data->out, "> ");
  }
  oonf_telnet_flush_session(data);
}

/**
 * Execute a telnet command.
 * @param cmd pointer to name of command
 * @param para pointer to parameter string
 * @param out buffer for output of command
 * @param remote pointer to address which triggers the execution
 * @return result of telnet command
 */
enum oonf_telnet_result
oonf_telnet_execute(const char *cmd, const char *para, struct autobuf *out, struct netaddr *remote)
{
  struct oonf_telnet_cleanup *handler, *it;
  struct oonf_telnet_session session;
  enum oonf_telnet_result result;

  memset(&session, 0, sizeof(session));
  session.data.command = cmd;
  session.data.parameter = para;
  session.data.out = out;
  session.data.remote = remote;

  list_init_head(&session.data.cleanup_list);

  result = _telnet_handle_command(&session.data);
  _call_stop_handler(&session.data);

  /* call all cleanup handlers */
  list_for_each_element_safe(&session.data.cleanup_list, handler, node, it) {
    /* remove from list first */
    oonf_telnet_remove_cleanup(handler);

    /* after this command the handler pointer might not be valid anymore */
    handler->cleanup_handler(handler);
  }

  return abuf_has_failed(session.data.out) ? TELNET_RESULT_INTERNAL_ERROR : result;
}

/**
 * AVL tree comparator for first word in case insensitive strings.
 * @param ptr1 pointer to string 1
 * @param ptr2 pointer to string 2
 * @return +1 if k1>k2, -1 if k1<k2, 0 if k1==k2
 */
static int
_avl_comp_strcmdword(const void *ptr1, const void *ptr2) {
  const char *txt1 = ptr1;
  const char *txt2 = ptr2;
  int diff;

  do {
    diff = (int)(*txt1) - (int)(*txt2);
    if (diff != 0 || *txt1 == ' ' || *txt2 == ' ') {
      break;
    }
  } while (*txt1++ != 0 && *txt2++ != 0);

  if ((*txt1 == ' ' && *txt2 == 0) || (*txt1 == 0 && *txt2 == ' ')) {
    diff = 0;
  }
  return diff;
}

/**
 * Initialization of incoming telnet session
 * @param session pointer to TCP session
 * @return 0
 */
static int
_cb_telnet_init(struct oonf_stream_session *session) {
  struct oonf_telnet_session *telnet_session;

  /* get telnet session pointer */
  telnet_session = (struct oonf_telnet_session *)session;

  telnet_session->data.show_echo = true;
  telnet_session->data.stop_handler = NULL;
  telnet_session->data.timeout_value = 120000;
  telnet_session->data.out = &telnet_session->session.out;
  telnet_session->data.remote = &telnet_session->session.remote_address;

  list_init_head(&telnet_session->data.cleanup_list);

  return 0;
}

/**
 * Cleanup of telnet session
 * @param session pointer to TCP session
 */
static void
_cb_telnet_cleanup(struct oonf_stream_session *session) {
  struct oonf_telnet_session *telnet_session;
  struct oonf_telnet_cleanup *handler, *it;

  /* get telnet session pointer */
  telnet_session = (struct oonf_telnet_session *)session;

  /* stop continuous commands */
  oonf_telnet_stop(&telnet_session->data, false);

  /* call all cleanup handlers */
  list_for_each_element_safe(&telnet_session->data.cleanup_list, handler, node, it) {
    /* remove from list first */
    oonf_telnet_remove_cleanup(handler);

    /* after this command the handler pointer might not be valid anymore */
    handler->cleanup_handler(handler);
  }
}

/**
 * Create error string for telnet session
 * @param session pointer to TCP stream
 * @param error TCP error code to generate
 */
static void
_cb_telnet_create_error(struct oonf_stream_session *session, enum oonf_stream_errors error) {
  switch (error) {
    case STREAM_REQUEST_TOO_LARGE:
      abuf_puts(&session->out, "Input buffer overflow, ending connection\n");
      break;
    case STREAM_SERVICE_UNAVAILABLE:
      abuf_puts(&session->out, "Telnet service unavailable, too many sessions\n");
      break;
    case STREAM_REQUEST_FORBIDDEN:
    default:
      /* no message */
      break;
  }
}

/**
 * Stop a continuous telnet command
 * @param data pointer to telnet data
 */
static void
_call_stop_handler(struct oonf_telnet_data *data) {
  void (*stop_handler)(struct oonf_telnet_data *);

  if (data->stop_handler) {
    /*
     * make sure that stop_handler is not set anymore when
     * it is called.
     */
    stop_handler = data->stop_handler;
    data->stop_handler = NULL;

    /* call stop handler */
    stop_handler(data);
  }
}

/**
 * Handler for receiving data from telnet session
 * @param session pointer to TCP session
 * @return TCP session state
 */
static enum oonf_stream_session_state
_cb_telnet_receive_data(struct oonf_stream_session *session) {
  struct oonf_telnet_session *telnet_session;
  enum oonf_telnet_result cmd_result;
  bool processedCommand = false;
  bool chainCommands = false;
  char *eol;
  int len;

  /* get telnet session pointer */
  telnet_session = (struct oonf_telnet_session *)session;

  /* loop over input */
  while (abuf_getlen(&session->in) > 0) {
    char *para = NULL, *cmd = NULL, *next = NULL;

    /* search for end of line */
    eol = memchr(abuf_getptr(&session->in), '\n', abuf_getlen(&session->in));
    if (eol) {
      /* terminate line with a 0 */
      if (eol != abuf_getptr(&session->in) && eol[-1] == '\r') {
        eol[-1] = 0;
      }
      *eol++ = 0;
    }
    else if (session->state == STREAM_SESSION_ACTIVE) {
      /* more data might be coming */
      break;
    }

    /* handle line */
    OONF_DEBUG(LOG_TELNET, "Interactive console: %s\n", abuf_getptr(&session->in));
    cmd = abuf_getptr(&session->in);
    processedCommand = true;

    if (cmd[0] == '/') {
      cmd++;
      chainCommands = true;
    }
    while (cmd) {
      len = abuf_getlen(&session->out);

      /* handle difference between multicommand and singlecommand mode */
      if (chainCommands) {
        if (cmd[0] == '/') {
          // double '/' means single command and autoquit
          cmd++;
          next = NULL;
        }
        else {
          next = strchr(cmd, '/');
          if (next) {
            *next++ = 0;
          }
        }
      }
      para = strchr(cmd, ' ');
      if (para != NULL) {
        *para++ = 0;
      }

      /* if we are doing continous output, stop it ! */
      _call_stop_handler(&telnet_session->data);

      if (strlen(cmd) != 0) {
        OONF_DEBUG(LOG_TELNET, "Processing telnet command: '%s' '%s'", cmd, para);

        if (para != NULL && strcmp(para, "help") == 0) {
          /* switch command and parameter to allow "<cmd> help" variant */
          telnet_session->data.command = para;
          telnet_session->data.parameter = cmd;
        }
        else {
          telnet_session->data.command = cmd;
          telnet_session->data.parameter = para;
        }

        cmd_result = _telnet_handle_command(&telnet_session->data);
        if (abuf_has_failed(telnet_session->data.out)) {
          cmd_result = TELNET_RESULT_INTERNAL_ERROR;
        }

        switch (cmd_result) {
          case TELNET_RESULT_ACTIVE:
            break;
          case TELNET_RESULT_CONTINOUS:
            telnet_session->data.show_echo = false;
            break;
          case _TELNET_RESULT_UNKNOWN_COMMAND:
            abuf_setlen(&session->out, len);
            abuf_appendf(&session->out, "Error, unknown command '%s'\n", cmd);
            break;
          case TELNET_RESULT_QUIT:
            return STREAM_SESSION_SEND_AND_QUIT;
          case TELNET_RESULT_INTERNAL_ERROR:
          default:
            /* reset stream */
            abuf_setlen(&session->out, len);
            abuf_appendf(&session->out, "Error in autobuffer during command '%s'.\n", cmd);
            break;
        }
        /* put an empty line behind each command */
        if (!chainCommands && telnet_session->data.show_echo) {
          abuf_puts(&session->out, "\n");
        }
      }
      cmd = next;
    }

    /* remove line from input buffer */
    if (eol) {
      abuf_pull(&session->in, eol - abuf_getptr(&session->in));
    }

    if (chainCommands) {
      /* end of multiple command line */
      return STREAM_SESSION_SEND_AND_QUIT;
    }
  }

  /* reset timeout */
  oonf_stream_set_timeout(session, telnet_session->data.timeout_value);

  /* print prompt */
  if (processedCommand && session->state == STREAM_SESSION_ACTIVE && telnet_session->data.show_echo) {
    abuf_puts(&session->out, "> ");
  }

  return STREAM_SESSION_ACTIVE;
}

/**
 * Helper function to call telnet command handler
 * @param data pointer to telnet data
 * @return telnet command result
 */
static enum oonf_telnet_result
_telnet_handle_command(struct oonf_telnet_data *data) {
  struct oonf_telnet_command *cmd;
#ifdef OONF_LOG_INFO
  struct netaddr_str buf;
#endif
  cmd = avl_find_element(&_telnet_cmd_tree, data->command, cmd, _node);
  if (cmd) {
    cmd = _check_telnet_command_acl(data, cmd);
  }
  if (cmd == NULL) {
    return _TELNET_RESULT_UNKNOWN_COMMAND;
  }

  OONF_INFO(LOG_TELNET, "Executing command from %s: %s %s", netaddr_to_string(&buf, data->remote), data->command,
    data->parameter == NULL ? "" : data->parameter);
  return cmd->handler(data);
}

/**
 * Checks for existing (and allowed) telnet command.
 * Either name or cmd should be NULL, but not both.
 * @param data pointer to telnet data
 * @param cmd pointer to telnet command object
 * @return telnet command object or NULL if not found or forbidden
 */
static struct oonf_telnet_command *
_check_telnet_command_acl(struct oonf_telnet_data *data, struct oonf_telnet_command *cmd) {
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  if (cmd->acl == NULL) {
    return cmd;
  }

  if (!netaddr_acl_check_accept(cmd->acl, data->remote)) {
    OONF_DEBUG(LOG_TELNET, "Blocked telnet command '%s' to '%s' because of acl", cmd->command,
      netaddr_to_string(&buf, data->remote));
    return NULL;
  }
  return cmd;
}

/**
 * Telnet command 'quit'
 * @param data pointer to telnet data
 * @return telnet command result
 */
static enum oonf_telnet_result
_cb_telnet_quit(struct oonf_telnet_data *data __attribute__((unused))) {
  return TELNET_RESULT_QUIT;
}

/**
 * Telnet command 'help'
 * @param data pointer to telnet data
 * @return telnet command result
 */
static enum oonf_telnet_result
_cb_telnet_help(struct oonf_telnet_data *data) {
  struct oonf_telnet_command *cmd;

  if (data->parameter != NULL && data->parameter[0] != 0) {
    cmd = avl_find_element(&_telnet_cmd_tree, data->parameter, cmd, _node);
    if (cmd) {
      cmd = _check_telnet_command_acl(data, cmd);
    }
    if (cmd == NULL) {
      abuf_appendf(data->out, "No help text found for command: %s\n", data->parameter);
      return TELNET_RESULT_ACTIVE;
    }

    if (cmd->help_handler) {
      cmd->help_handler(data);
    }
    else {
      abuf_appendf(data->out, "%s", cmd->help);
    }
    return TELNET_RESULT_ACTIVE;
  }

  abuf_puts(data->out, "Known commands:\n");

  avl_for_each_element(&_telnet_cmd_tree, cmd, _node) {
    if (_check_telnet_command_acl(data, cmd)) {
      abuf_appendf(data->out, "  %s\n", cmd->command);
    }
  }

  abuf_puts(data->out, "Use 'help <command> to see a help text for one command\n");
  return TELNET_RESULT_ACTIVE;
}

/**
 * Telnet command 'echo'
 * @param data pointer to telnet data
 * @return telnet command result
 */
static enum oonf_telnet_result
_cb_telnet_echo(struct oonf_telnet_data *data) {
  if (abuf_appendf(data->out, "%s\n", data->parameter == NULL ? "" : data->parameter) < 0) {
    return TELNET_RESULT_INTERNAL_ERROR;
  }
  return TELNET_RESULT_ACTIVE;
}

/**
 * Telnet command 'timeout'
 * @param data pointer to telnet data
 * @return telnet command result
 */
static enum oonf_telnet_result
_cb_telnet_timeout(struct oonf_telnet_data *data) {
  if (data->parameter == NULL) {
    data->timeout_value = 0;
  }
  else {
    data->timeout_value = (uint32_t)strtoul(data->parameter, NULL, 10) * 1000;
  }
  return TELNET_RESULT_ACTIVE;
}

/**
 * Stop handler for repeating telnet commands
 * @param data pointer to telnet data
 */
static void
_cb_telnet_repeat_stophandler(struct oonf_telnet_data *data) {
  oonf_timer_stop(&data->stop_timer);
  free(data->stop_data[1]);

  data->stop_handler = NULL;
  data->stop_data[0] = NULL;
  data->stop_data[1] = NULL;
  data->stop_data[2] = NULL;
}

/**
 * Timer event handler for repeating telnet commands
 * @param ptr timer instance that fired
 */
static void
_cb_telnet_repeat_timer(struct oonf_timer_instance *ptr) {
  struct oonf_telnet_data *telnet_data;
  struct oonf_telnet_session *session;

  telnet_data = container_of(ptr, struct oonf_telnet_data, stop_timer);

  /* set command/parameter with repeat settings */
  telnet_data->command = telnet_data->stop_data[1];
  telnet_data->parameter = telnet_data->stop_data[2];

  if (_telnet_handle_command(telnet_data) != TELNET_RESULT_ACTIVE) {
    _call_stop_handler(telnet_data);
  }

  /* reconstruct original session pointer */
  session = container_of(telnet_data, struct oonf_telnet_session, data);
  oonf_stream_flush(&session->session);
}

/**
 * Telnet command 'repeat'
 * @param data pointer to telnet data
 * @return telnet command result
 */
static enum oonf_telnet_result
_cb_telnet_repeat(struct oonf_telnet_data *data) {
  int interval = 0;
  char *ptr = NULL;

  if (data->stop_handler) {
    abuf_puts(data->out, "Error, you cannot stack continous output commands\n");
    return TELNET_RESULT_ACTIVE;
  }

  if (data->parameter == NULL || (ptr = strchr(data->parameter, ' ')) == NULL) {
    abuf_puts(data->out, "Missing parameters for repeat\n");
    return TELNET_RESULT_ACTIVE;
  }

  ptr++;

  interval = atoi(data->parameter);
  if (interval < 1) {
    abuf_puts(data->out, "Please specify an interval >= 1\n");
    return TELNET_RESULT_ACTIVE;
  }

  data->stop_timer.class = &_telnet_repeat_timerinfo;
  oonf_timer_start(&data->stop_timer, (uint64_t)MSEC_PER_SEC * interval);

  data->stop_handler = _cb_telnet_repeat_stophandler;
  data->stop_data[1] = strdup(ptr);
  data->stop_data[2] = NULL;

  /* split command/parameter and remember it */
  ptr = strchr(data->stop_data[1], ' ');
  if (ptr != NULL) {
    /* found a parameter */
    *ptr++ = 0;
    data->stop_data[2] = ptr;
  }

  /* start command the first time */
  data->command = data->stop_data[1];
  data->parameter = data->stop_data[2];

  if (_telnet_handle_command(data) != TELNET_RESULT_ACTIVE) {
    _call_stop_handler(data);
  }

  return TELNET_RESULT_CONTINOUS;
}

/**
 * Handler for configuration changes
 */
static void
_cb_config_changed(void) {
  struct _telnet_config config;

  /* generate binary config */
  memset(&config, 0, sizeof(config));
  if (cfg_schema_tobin(&config, _telnet_section.post, _telnet_entries, ARRAYSIZE(_telnet_entries))) {
    /* error in conversion */
    OONF_WARN(LOG_TELNET, "Cannot map telnet config to binary data");
    goto apply_config_failed;
  }

  /* set session parameters */
  _telnet_managed.config.allowed_sessions = config.allowed_sessions;
  _telnet_managed.config.session_timeout = config.timeout;

  if (oonf_stream_apply_managed(&_telnet_managed, &config.osmc)) {
    /* error while updating sockets */
    goto apply_config_failed;
  }

  /* fall through */
apply_config_failed:
  oonf_stream_free_managed_config(&config.osmc);
}
