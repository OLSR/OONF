
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

#ifndef OONF_LOGGING_H_
#define OONF_LOGGING_H_

struct oonf_log_handler_entry;

#include <string.h>
#include <stdlib.h>

#include <oonf/libcommon/autobuf.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcore/oonf_appdata.h>
#include <oonf/libcore/oonf_libdata.h>

/**
 * defines the severity of a logging event
 */
enum oonf_log_severity
{
  LOG_SEVERITY_MIN = 1 << 0,
  LOG_SEVERITY_DEBUG = 1 << 0,
  LOG_SEVERITY_INFO = 1 << 1,
  LOG_SEVERITY_WARN = 1 << 2,
  LOG_SEVERITY_ASSERT = 1 << 3,
  LOG_SEVERITY_MAX = 1 << 3,
};

/*! Defines the builtin sources of a logging event. */
enum oonf_log_source
{
  /*! all logging sources */
  LOG_ALL,

  /*! the 'default' logging source */
  LOG_MAIN,

  /*! logging sources for the core */
  LOG_LOGGING,
  LOG_CONFIG,
  LOG_PLUGINS,
  LOG_SUBSYSTEMS,

  /*! this one must be the last ones of the normal enums ! */
  LOG_CORESOURCE_COUNT,

  /*! maximum number of logging sources supported by API */
  LOG_MAXIMUM_SOURCES = 128,
};

/**
 * Parameters for logging handler call
 */
struct oonf_log_parameters {
  /*! severity of logging event */
  enum oonf_log_severity severity;

  /*! source of logging event */
  enum oonf_log_source source;

  /*! file where the logging event happened */
  const char *file;

  /*! line number where the logging event happened */
  int line;

  /*! logging output */
  char *buffer;

  /*! number of bytes used for the timestamp in the buffer */
  int timeLength;

  /*! number of bytes used for the logging prefix in the buffer */
  int prefixLength;
};

/*
 * macros to check which logging levels are active
 *
 * #ifdef OONF_LOG_DEBUG_INFO
 *   // variable only necessary for logging level debug and info
 *   struct netaddr_str buf;
 * #endif
 *
 *  * #ifdef OONF_LOG_INFO
 *   // variable only necessary for logging level info
 *   struct netaddr_str buf2;
 * #endif
 */

/**
 * these macros should be used to generate OONF logging output
 * the OONF_severity_NH() variants don't print the timestamp/file/line header,
 * which can be used for multiline output.
 *
 * OONF_DEBUG should be used for all output that is only usefull for debugging a specific
 * part of the code. This could be information about the internal progress of a function,
 * state of variables, ...
 *
 * OONF_INFO should be used for all output that does not inform the user about a
 * problem/error in OONF. Examples would be "SPF run triggered" or "Hello package received
 * from XXX.XXX.XXX.XXX".
 *
 * OONF_WARN should be used for all error messages.
 */

#ifndef BASEPATH_LENGTH
#define BASEPATH_LENGTH 0
#endif

#ifdef NDEBUG
#define OONF_DO_ABORT false
#else
#define OONF_DO_ABORT true
#endif

/**
 * Helper macro to define a logging macro
 * @param severity logging severity
 * @param source logging source
 * @param hexptr pointer to buffer that should be hexdumped, NULL if no hexdump
 * @param hexlen length of buffer to be hexdumped, 0 if no hexdump
 * @param condition additional condition for logging
 * @param fail true to call abort after a log message, false to continue
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define _OONF_LOG(severity, source, hexptr, hexlen, condition, fail, format, args...)                                  \
  do {                                                                                                                 \
    if ((condition) && oonf_log_mask_test(log_global_mask, source, severity)) {                                        \
      oonf_log(severity, source, &__FILE__[BASEPATH_LENGTH], __LINE__, hexptr, hexlen, format, ##args);                \
      if (OONF_DO_ABORT && (fail)) { abort(); }                                                                        \
    }                                                                                                                  \
  } while (0)

#ifdef OONF_LOG_DEBUG_INFO
/**
 * Add a DEBUG level logging to the log handlers
 * @param source logging source
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_DEBUG(source, format, args...) _OONF_LOG(LOG_SEVERITY_DEBUG, source, NULL, 0, true, false, format, ##args)

/**
 * Add a DEBUG level logging and a hexdump to the log handlers
 * @param source logging source
 * @param hexptr pointer to buffer that should be hexdumped
 * @param hexlen length of buffer to be hexdumped
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_DEBUG_HEX(source, hexptr, hexlen, format, args...) _OONF_LOG(LOG_SEVERITY_DEBUG, source, hexptr, hexlen, true, false, format, ##args)

/**
 * Checks if a logging source should produce DEBUG level output
 * @param source logging source
 * @return true if DEBUG logging is active for source, false otherwise
 */
#define OONF_TEST_DEBUG(source) oonf_log_mask_test(log_global_mask, source, LOG_SEVERITY_DEBUG)
#else
/**
 * Add a DEBUG level logging to the log handlers
 * @param source logging source
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_DEBUG(source, format, args...) do {} while (0)

/**
 * Add a DEBUG level logging without header to the log handlers
 * @param source logging source
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_DEBUG_NH(source, format, args...) do {} while (0)

/**
 * Add a DEBUG level logging and a hexdump to the log handlers
 * @param source logging source
 * @param hexptr pointer to buffer that should be hexdumped
 * @param hexlen length of buffer to be hexdumped
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_DEBUG_HEX(source, hexptr, hexlen, format, args...) do {} while (0)

/**
 * Checks if a logging source should produce DEBUG level output
 * @param source logging source
 * @return true if DEBUG logging is active for source, false otherwise
 */
#define OONF_TEST_DEBUG(source) false
#endif

#ifdef OONF_LOG_INFO
/**
 * Add a INFO level logging to the log handlers
 * @param source logging source
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_INFO(source, format, args...) _OONF_LOG(LOG_SEVERITY_INFO, source, NULL, 0, true, false, format, ##args)

/**
 * Add a INFO level logging and a hexdump to the log handlers
 * @param source logging source
 * @param hexptr pointer to buffer that should be hexdumped
 * @param hexlen length of buffer to be hexdumped
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_INFO_HEX(source, hexptr, hexlen, format, args...) _OONF_LOG(LOG_SEVERITY_INFO, source, hexptr, hexlen, true, false, format, ##args)

/**
 * Checks if a logging source should produce INFO level output
 * @param source logging source
 * @return true if INFO logging is active for source, false otherwise
 */
#define OONF_TEST_INFO(source) oonf_log_mask_test(log_global_mask, source, LOG_SEVERITY_INFO)
#else
/**
 * Add a INFO level logging to the log handlers
 * @param source logging source
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_INFO(source, format, args...) do {  } while (0)

/**
 * Add a INFO level logging without header to the log handlers
 * @param source logging source
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_INFO_NH(source, format, args...) do {  } while (0)

/**
 * Add a INFO level logging and a hexdump to the log handlers
 * @param source logging source
 * @param hexptr pointer to buffer that should be hexdumped
 * @param hexlen length of buffer to be hexdumped
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_INFO_HEX(source, hexptr, hexlen, format, args...)  do {  } while (0)

/**
 * Checks if a logging source should produce INFO level output
 * @param source logging source
 * @return true if INFO logging is active for source, false otherwise
 */
#define OONF_TEST_INFO(source) false
#endif

/**
 * Add a WARN level logging to the log handlers
 * @param source logging source
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_WARN(source, format, args...) _OONF_LOG(LOG_SEVERITY_WARN, source, NULL, 0, true, false, format, ##args)

/**
 * Add a WARN level logging and a hexdump to the log handlers
 * @param source logging source
 * @param hexptr pointer to buffer that should be hexdumped
 * @param hexlen length of buffer to be hexdumped
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_WARN_HEX(source, hexptr, hexlen, format, args...) _OONF_LOG(LOG_SEVERITY_WARN, source, hexptr, hexlen, true, false, format, ##args)

/**
 * Checks if a logging source should produce WARN level output
 * @param source logging source
 * @return always true
 */
#define OONF_TEST_WARN(source) true

/**
 * Add an ASSERT condition with logging to the log handlers.
 * Will abort after triggering the log output.
 * @param condition assert condition that should be true.
 * @param source logging source
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_ASSERT(condition, source, format, args...) _OONF_LOG(LOG_SEVERITY_ASSERT, source, NULL, 0, !(condition), true, format, ##args)

/**
 * Add an ASSERT condition with logging and a hexdump to the log handlers.
 * Will abort after triggering the log output.
 * @param condition assert condition that should be true.
 * @param source logging source
 * @param hexptr pointer to buffer that should be hexdumped
 * @param hexlen length of buffer to be hexdumped
 * @param format printf style format string
 * @param args variable number of parameters for format string
 */
#define OONF_ASSERT_HEX(condition, source, hexptr, hexlen, format, args...) _OONF_LOG(LOG_SEVERITY_ASSERT, source, hexptr, hexlen, !(condition), true, format, ##args)

/**
 * Definition of a logging handler
 */
struct oonf_log_handler_entry {
  /*! hook into global list of logging handlers */
  struct list_entity _node;

  /**
   * Callback that handles a logging event
   * @param pointer to this structure
   * @param parameters for logging event
   */
  void (*handler)(struct oonf_log_handler_entry *entry, struct oonf_log_parameters *param);

  /*! user_bitmask */
  uint8_t user_bitmask[LOG_MAXIMUM_SOURCES];

  /*! internal copy of user_bitmask */
  uint8_t _processed_bitmask[LOG_MAXIMUM_SOURCES];

  /*! custom data for user */
  void *custom;
};

/**
 * Buffer for text representation of walltime
 */
struct oonf_walltime_str {
  /*! string array for maximum length walltime */
  char buf[14];
};

/**
 * Macro to iterate over all logging severities
 * This macro should be used similar to a for() or while() construct
 * @param sev reference of log_severity variable,
 *   will be used as the iterator variable
 */
#define OONF_FOR_ALL_LOGSEVERITIES(sev) for (sev = LOG_SEVERITY_MIN; sev <= LOG_SEVERITY_MAX; sev <<= 1)

EXPORT extern uint8_t log_global_mask[LOG_MAXIMUM_SOURCES];
EXPORT extern const char *LOG_SOURCE_NAMES[LOG_MAXIMUM_SOURCES];
EXPORT extern const char *LOG_SEVERITY_NAMES[LOG_SEVERITY_MAX + 1];

EXPORT int oonf_log_init(const struct oonf_appdata *, enum oonf_log_severity) __attribute__((warn_unused_result));
EXPORT void oonf_log_cleanup(void);

EXPORT size_t oonf_log_get_max_severitytextlen(void);
EXPORT size_t oonf_log_get_max_sourcetextlen(void);
EXPORT size_t oonf_log_get_sourcecount(void);

EXPORT uint32_t oonf_log_get_warning_count(enum oonf_log_source source);

EXPORT void oonf_log_addhandler(struct oonf_log_handler_entry *);
EXPORT void oonf_log_removehandler(struct oonf_log_handler_entry *);
EXPORT int oonf_log_register_source(const char *name);

EXPORT void oonf_log_updatemask(void);

EXPORT const struct oonf_appdata *oonf_log_get_appdata(void);
EXPORT const struct oonf_libdata *oonf_log_get_libdata(void);
EXPORT void oonf_log_printversion(struct autobuf *abuf);
EXPORT const char *oonf_log_get_walltime(struct oonf_walltime_str *);

EXPORT void oonf_log(enum oonf_log_severity, enum oonf_log_source, const char *, int, const void *, size_t,
  const char *, ...) __attribute__((format(printf, 7, 8)));

EXPORT void oonf_log_stderr(struct oonf_log_handler_entry *, struct oonf_log_parameters *);
EXPORT void oonf_log_syslog(struct oonf_log_handler_entry *, struct oonf_log_parameters *);
EXPORT void oonf_log_file(struct oonf_log_handler_entry *, struct oonf_log_parameters *);

/**
 * Clear a logging mask
 * @param mask pointer to logging mask
 */
static INLINE void
oonf_log_mask_clear(uint8_t *mask) {
  memset(mask, LOG_SEVERITY_WARN | LOG_SEVERITY_ASSERT, LOG_MAXIMUM_SOURCES);
}

/**
 * Copy a logging mask
 * @param dst pointer to target logging mask
 * @param src pointer to source logging mask
 */
static INLINE void
oonf_log_mask_copy(uint8_t *dst, uint8_t *src) {
  memcpy(dst, src, LOG_MAXIMUM_SOURCES);
}

/**
 * Set a field in a logging mask
 * @param mask pointer to logging mask
 * @param src logging source
 * @param sev logging severity
 */
static INLINE void
oonf_log_mask_set(uint8_t *mask, enum oonf_log_source src, enum oonf_log_severity sev) {
  mask[src] |= sev;
}

/**
 * Reset a field in a logging mask
 * @param mask pointer to logging mask
 * @param src logging source
 * @param sev logging severity
 */
static INLINE void
oonf_log_mask_reset(uint8_t *mask, enum oonf_log_source src, enum oonf_log_severity sev) {
  mask[src] &= ~sev;
}

/**
 * Test a field in a logging mask
 * @param mask pointer to logging mask
 * @param src logging source
 * @param sev logging severity
 * @return true if the field was set, false otherwise
 */
static INLINE bool
oonf_log_mask_test(uint8_t *mask, enum oonf_log_source src, enum oonf_log_severity sev) {
  return (mask[src] & sev) != 0;
}

#endif /* OONF_LOGGING_H_ */
