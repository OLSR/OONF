
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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/types.h>
#include <unistd.h>

#include <oonf/libconfig/cfg_cmd.h>
#include <oonf/libconfig/cfg_db.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_cfg.h>
#include <oonf/libcore/oonf_libdata.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_logging_cfg.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/libcore/os_core.h>

#include <oonf/libcore/oonf_main.h>

/* prototypes */
static int _write_pidfile(const char *);
static void quit_signal_handler(int);
static void hup_signal_handler(int);
static void setup_signalhandler(void);
static int mainloop(int argc, char **argv, const struct oonf_appdata *);
static void parse_early_commandline(int argc, char **argv);
static int parse_commandline(int argc, char **argv, const struct oonf_appdata *, bool reload_only);
static int display_schema(void);

static bool _display_schema, _debug_early, _ignore_unknown;
static char *_schema_name;

static int (*_handle_scheduling)(void) = NULL;
static int (*_handle_unused_argument)(const char *) = NULL;

/**
 * index values for additional command line options
 */
enum argv_short_options
{
  /*! --schema option */
  argv_option_schema = 256,

  /*! --Xearlydebug option */
  argv_option_debug_early,

  /*! --Xignoreunknown */
  argv_option_ignore_unknown,
};

static struct option oonf_options[] = {
#if !defined(REMOVE_HELPTEXT)
  { "help", no_argument, 0, 'h' },
#endif
  { "version", no_argument, 0, 'v' }, { "plugin", required_argument, 0, 'p' }, { "load", required_argument, 0, 'l' },
  { "save", required_argument, 0, 'S' }, { "set", required_argument, 0, 's' }, { "remove", required_argument, 0, 'r' },
  { "get", optional_argument, 0, 'g' }, { "quit", no_argument, 0, 'q' },
  { "schema", optional_argument, 0, argv_option_schema }, { "Xearlydebug", no_argument, 0, argv_option_debug_early },
  { "Xignoreunknown", no_argument, 0, argv_option_ignore_unknown }, { NULL, 0, 0, 0 }
};

#if !defined(REMOVE_HELPTEXT)
static const char *help_text =
  "Mandatory arguments for long options are mandatory for short options too.\n"
  "  -h, --help                             Display this help file\n"
  "  -v, --version                          Display the version string and the included static plugins\n"
  "  -p, --plugin=shared-library            Load a shared library as a plugin\n"
  "  -q, --quit                             Load plugins and validate configuration, then end\n"
  "      --schema                           Display all allowed section types of configuration\n"
  "              =all                       Display all allowed entries in all sections\n"
  "              =section_type              Display all allowed entries of one configuration section\n"
  "              =section_type.key          Display help text for configuration entry\n"
  "  -l, --load=SOURCE                      Load configuration from a SOURCE\n"
  "  -S, --save=TARGET                      Save configuration to a TARGET\n"
  "  -s, --set=section_type.                Add an unnamed section to the configuration\n"
  "           =section_type.key=value       Add a key/value pair to an unnamed section\n"
  "           =section_type[name].          Add a named section to the configuration\n"
  "           =section_type[name].key=value Add a key/value pair to a named section\n"
  "  -r, --remove=section_type.             Remove all sections of a certain type\n"
  "              =section_type.key          Remove a key in an unnamed section\n"
  "              =section_type[name].       Remove a named section\n"
  "              =section_type[name].key    Remove a key in a named section\n"
  "  -g, --get                              Show all section types in database\n"
  "           =section_type.                Show all named sections of a certain type\n"
  "           =section_type.key             Show the value(s) of a key in an unnamed section\n"
  "           =section_type[name].key       Show the value(s) of a key in a named section\n"
  "\n"
  "Expert/Experimental arguments\n"
  "  --Xearlydebug                          Activate debugging output before configuration could be parsed\n"
  "  --Xignoreunknown                       Ignore unknown command line arguments\n"
  "\n"
  "The remainder of the parameters which are no arguments are handled as interface names.\n";
#endif

/**
 * Main program
 * @param argc argument counter
 * @param argv argument vector
 * @param appdata application data
 * @return application return code to shell
 */
int
oonf_main(int argc, char **argv, const struct oonf_appdata *appdata) {
  int return_code;
  int result;

  /* early initialization */
  return_code = 1;

  _schema_name = NULL;
  _display_schema = false;
  _debug_early = false;
  _ignore_unknown = false;

  /* setup signal handler */
  setup_signalhandler();

  /* parse "early" command line arguments */
  parse_early_commandline(argc, argv);

  /* initialize core */
  os_core_init(appdata->app_name);

  /* initialize logger */
  if (oonf_log_init(appdata, _debug_early ? LOG_SEVERITY_DEBUG : LOG_SEVERITY_WARN)) {
    goto oonf_cleanup;
  }

  /* prepare plugin initialization */
  oonf_subsystem_init();

  /* initialize configuration system */
  if (oonf_cfg_init(argc, argv, appdata->default_cfg_handler)) {
    goto oonf_cleanup;
  }

  /* add custom configuration definitions */
  oonf_logcfg_init();

  /* parse command line and read configuration files */
  return_code = parse_commandline(argc, argv, appdata, false);
  if (return_code != -1) {
    /* end OONFd now */
    goto oonf_cleanup;
  }

  /* prepare for an error during initialization */
  return_code = 1;

  /* read global section early */
  if ((result = oonf_cfg_update_globalcfg(true))) {
    OONF_WARN(LOG_MAIN, "Cannot read global configuration section (%d)", result);
    goto oonf_cleanup;
  }

  /* configure logger */
  if (oonf_logcfg_apply(oonf_cfg_get_rawdb())) {
    goto oonf_cleanup;
  }

  /* load plugins */
  if (oonf_cfg_load_subsystems()) {
    goto oonf_cleanup;
  }

  /* show schema if necessary */
  if (_display_schema) {
    return_code = display_schema();
    goto oonf_cleanup;
  }

  /* check if we are root, otherwise stop */
  if (appdata->need_root) {
    if (geteuid() != 0) {
      OONF_WARN(LOG_MAIN, "You must be root(uid = 0) to run %s!\n", appdata->app_name);
      goto oonf_cleanup;
    }
  }

  if (appdata->need_lock && config_global.lockfile != NULL && *config_global.lockfile != 0 &&
      strcmp(config_global.lockfile, "-") != 0) {
    /* create application lock */
    if (os_core_create_lockfile(config_global.lockfile)) {
      OONF_WARN(LOG_MAIN, "Could not acquire application lock '%s'", config_global.lockfile);
      goto oonf_cleanup;
    }
  }

  /* call initialization callbacks of dynamic plugins */
  oonf_cfg_initplugins();

  /* apply configuration */
  if (oonf_cfg_apply()) {
    goto oonf_cleanup;
  }

  if (!oonf_cfg_is_running()) {
    /*
     * maybe the user decided otherwise and pressed CTRL-C
     * or the --quit option was used
     */
    return_code = 0;
    goto oonf_cleanup;
  }

  if (!_handle_scheduling) {
    OONF_WARN(LOG_MAIN, "No event scheduler present");
    return_code = 1;
    goto oonf_cleanup;
  }
  /* see if we need to fork */
  if (config_global.fork && !_display_schema) {
    /* tell main process that we are finished with initialization */
    if (daemon(0, 0) < 0) {
      OONF_WARN(LOG_MAIN, "Could not fork into background: %s (%d)", strerror(errno), errno);
      goto oonf_cleanup;
    }

    if (config_global.pidfile && *config_global.pidfile != 0) {
      if (_write_pidfile(config_global.pidfile)) {
        goto oonf_cleanup;
      }
    }
  }

  /* activate mainloop */
  return_code = mainloop(argc, argv, appdata);

  /* tell plugins shutdown is in progress */
  oonf_subsystem_initiate_shutdown();

  /* wait for 500 ms and process socket events */
  while (!_handle_scheduling())
    ;

oonf_cleanup:
  /* free plugins */
  oonf_cfg_unconfigure_subsystems();
  oonf_subsystem_cleanup();

  /* free logging/config bridge resources */
  oonf_logcfg_cleanup();

  /* free configuration resources */
  oonf_cfg_cleanup();

  /* free logger resources */
  oonf_log_cleanup();

  /* free core resources */
  os_core_cleanup();

  return return_code;
}

/**
 * Set the callback to the central scheduler
 * @param scheduler pointer to scheduler function
 * @return -1 if scheduler is already set
 */
int
oonf_main_set_scheduler(int (*scheduler)(void)) {
  if (_handle_scheduling) {
    return -1;
  }

  _handle_scheduling = scheduler;
  return 0;
}

/**
 * Set a handler for command line parameters that are not used by main()
 * @param parameter_handler pointer to parameter handler function
 * @return -1 if parameter handler is already set
 */
int
oonf_main_set_parameter_handler(int (*parameter_handler)(const char *)) {
  if (_handle_unused_argument) {
    return -1;
  }
  _handle_unused_argument = parameter_handler;
  return 0;
}

/**
 * @return true if event scheduler should return to the mainloop
 */
bool
oonf_main_shall_stop_scheduler(void) {
  return oonf_cfg_is_commit_set() || oonf_cfg_is_reload_set() || !oonf_cfg_is_running();
}

/**
 * Write process ID into file
 * @param filename name/path of pidfile
 * @return -1 if an error happened, 0 otherwise
 */
static int
_write_pidfile(const char *filename) {
  int pid_fd;
  char buffer[16];

  pid_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (pid_fd < 0) {
    OONF_WARN(LOG_MAIN, "Could not open pidfile '%s': %s (%d)", filename, strerror(errno), errno);
    return -1;
  }

  snprintf(buffer, sizeof(buffer), "%d\n", getpid());

  if (write(pid_fd, buffer, strlen(buffer) + 1) < 0) {
    OONF_WARN(
      LOG_MAIN, "Could not write pid %d into pidfile '%s': %s (%d)", getpid(), filename, strerror(errno), errno);
    close(pid_fd);
    return -1;
  }

  close(pid_fd);
  return 0;
}

/**
 * Handle incoming SIGINT signal
 * @param signo unused
 */
static void
quit_signal_handler(int signo __attribute__((unused))) {
  oonf_cfg_exit();
}

/**
 * Handle incoming SIGHUP signal
 * @param signo unused
 */
static void
hup_signal_handler(int signo __attribute__((unused))) {
  oonf_cfg_trigger_reload();
}

/**
 * Mainloop of olsrd
 * @param argc argument counter
 * @param argv argument vector
 * @param appdata OONF appdata
 * @return exit code for olsrd
 */
static int
mainloop(int argc, char **argv, const struct oonf_appdata *appdata) {
  int exit_code = 0;

  OONF_INFO(LOG_MAIN, "Starting %s", appdata->app_name);

  /* enter main loop */
  while (oonf_cfg_is_running()) {
    /* call event scheduler */
    if (_handle_scheduling()) {
      exit_code = 1;
      break;
    }

    /* reload configuration if triggered */
    if (oonf_cfg_is_reload_set()) {
      OONF_INFO(LOG_MAIN, "Reloading configuration");
      if (oonf_cfg_clear_rawdb()) {
        break;
      }
      if (parse_commandline(argc, argv, appdata, true) == -1) {
        if (oonf_cfg_apply()) {
          break;
        }
      }
    }

    /* commit config if triggered */
    if (oonf_cfg_is_commit_set()) {
      OONF_INFO(LOG_MAIN, "Commiting configuration");
      if (oonf_cfg_apply()) {
        break;
      }
    }
  }

  OONF_INFO(LOG_MAIN, "Ending %s", appdata->app_name);
  return exit_code;
}

/**
 * Setup signal handling for olsrd
 */
static void
setup_signalhandler(void) {
  static struct sigaction act;

  memset(&act, 0, sizeof(act));

  /* setup signal handler first */
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;

  act.sa_handler = quit_signal_handler;
  sigaction(SIGINT, &act, NULL);
  sigaction(SIGQUIT, &act, NULL);
  sigaction(SIGILL, &act, NULL);
  sigaction(SIGABRT, &act, NULL);
  sigaction(SIGTERM, &act, NULL);

  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, NULL);
  sigaction(SIGUSR1, &act, NULL);
  sigaction(SIGUSR2, &act, NULL);

  act.sa_handler = hup_signal_handler;
  sigaction(SIGHUP, &act, NULL);
}

static void
parse_early_commandline(int argc, char **argv) {
  int opt, opt_idx;

  opterr = 0;
  while (0 <= (opt = getopt_long(argc, argv, "-", oonf_options, &opt_idx))) {
    switch (opt) {
      case argv_option_debug_early:
        _debug_early = true;
        break;
      case argv_option_ignore_unknown:
        _ignore_unknown = true;
        break;
      default:
        break;
    }
  }
}

/**
 * Parse command line of olsrd
 * @param argc number of arguments
 * @param argv argument vector
 * @param appdata OONF appdata
 * @param reload_only true if only the command line arguments should
 *   be parsed that load a configuration (--set, --remove, --load,
 *   and --format), false for normal full parsing.
 * @return -1 if olsrd should start normally, otherwise olsrd should
 *   exit with the returned number
 */
static int
parse_commandline(int argc, char **argv, const struct oonf_appdata *appdata __attribute((unused)), bool reload_only) {
  struct oonf_subsystem *plugin;
  const char *parameters;
  struct autobuf log;
  struct cfg_db *db;
  int opt, opt_idx, return_code;

  return_code = -1;
  db = oonf_cfg_get_rawdb();

  /* reset getopt_long */
  opt_idx = -1;
  optind = 1;
  opterr = _ignore_unknown ? 0 : -1;

  abuf_init(&log);

  if (reload_only) {
    /* only parameters that load and change configuration data */
    parameters = "-p:l:s:r:f:n";
  }
  else {
    parameters = "-hvp:ql:S:s:r:g::f:n";
  }

  while (return_code == -1 && 0 <= (opt = getopt_long(argc, argv, parameters, oonf_options, &opt_idx))) {
    switch (opt) {
      case 'h':
#if !defined(REMOVE_HELPTEXT)
        abuf_appendf(
          &log, "Usage: %s [OPTION]...\n%s%s%s", argv[0], appdata->help_prefix, help_text, appdata->help_suffix);
#endif
        return_code = 0;
        break;

      case argv_option_debug_early:
      case argv_option_ignore_unknown:
        /* ignore this here */
        break;

      case 'v':
        oonf_log_printversion(&log);
        avl_for_each_element(&oonf_plugin_tree, plugin, _node) {
          if (!oonf_subsystem_is_dynamic(plugin)) {
            abuf_appendf(&log, "Static plugin: %s\n", plugin->name);
          }
        }
        return_code = 0;
        break;
      case 'p':
        if (oonf_cfg_load_subsystem(optarg) == NULL) {
          return_code = 1;
        }
        else {
          cfg_db_add_entry(oonf_cfg_get_rawdb(), CFG_SECTION_GLOBAL, NULL, CFG_GLOBAL_PLUGIN, optarg);
        }
        break;
      case 'q':
        oonf_cfg_exit();
        break;

      case argv_option_schema:
        _schema_name = optarg;
        _display_schema = true;
        break;

      case 'l':
        if (cfg_cmd_handle_load(oonf_cfg_get_instance(), db, optarg, &log)) {
          return_code = 1;
        }
        break;
      case 'S':
        if (cfg_cmd_handle_save(oonf_cfg_get_instance(), db, optarg, &log)) {
          return_code = 1;
        }
        break;
      case 's':
        if (cfg_cmd_handle_set(oonf_cfg_get_instance(), db, optarg, &log)) {
          return_code = 1;
        }
        break;
      case 'r':
        if (cfg_cmd_handle_remove(oonf_cfg_get_instance(), db, optarg, &log)) {
          return_code = 1;
        }
        break;
      case 'g':
        if (cfg_cmd_handle_get(oonf_cfg_get_instance(), db, optarg, &log)) {
          return_code = 1;
        }
        else {
          return_code = 0;
        }
        break;
      case 1:
        /* string that is not part of an option */
        if (_handle_unused_argument) {
          _handle_unused_argument(optarg);
        }
        break;

      case '?':
      default:
        if (!(reload_only || _ignore_unknown)) {
          abuf_appendf(&log, "Unknown parameter: '%c' (%d)\n", opt, opt);
          return_code = 1;
        }
        break;
    }
  }

  while (return_code == -1 && optind < argc) {
    /* handle the end of the command line */
    if (_handle_unused_argument) {
      _handle_unused_argument(argv[optind]);
    }
    optind++;
  }

  if (abuf_getlen(&log) > 0) {
    if (reload_only) {
      OONF_WARN(LOG_MAIN, "Cannot reload configuration.\n%s", abuf_getptr(&log));
    }
    else {
      fputs(abuf_getptr(&log), return_code == 0 ? stdout : stderr);
    }
  }

  abuf_free(&log);

  return return_code;
}

/**
 * Call the handle_schema command to give the user the schema of
 * the configuration including plugins
 * @return -1 if an error happened, 0 otherwise
 */
static int
display_schema(void) {
  struct autobuf log;
  int return_code;

  return_code = 0;

  abuf_init(&log);

  if (cfg_cmd_handle_schema(oonf_cfg_get_rawdb(), _schema_name, &log)) {
    return_code = -1;
  }

  if (abuf_getlen(&log) > 0) {
    fputs(abuf_getptr(&log), stdout);
  }

  abuf_free(&log);

  return return_code;
}
