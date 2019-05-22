
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

#ifndef _OONF_CLOCK
#define _OONF_CLOCK

#include <oonf/oonf.h>
#include <oonf/libcommon/isonumber.h>
#include <oonf/libconfig/cfg.h>
#include <oonf/libconfig/cfg_schema.h>

/*! subsystem identifier */
#define OONF_CLOCK_SUBSYSTEM "clock"

/**
 * Clock multiplied constants
 */
enum
{
  /*! number of milliseconds in a second */
  MSEC_PER_SEC = 1000ull,

  /*! number of microseconds in a millisecond */
  USEC_PER_MSEC = 1000ull,
};

/**
 * Creates a cfg_schema_entry for a clock value
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param args variable list of additional arguments
 */
#define CFG_VALIDATE_CLOCK(p_name, p_def, p_help, args...)                                                             \
  CFG_VALIDATE_INT64_MINMAX(p_name, p_def, p_help, 3, false, 0, INT64_MAX, ##args)

/**
 * Creates a cfg_schema_entry for a clock value with defined minimum
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param min minimal allowed clock value
 * @param args variable list of additional arguments
 */
#define CFG_VALIDATE_CLOCK_MIN(p_name, p_def, p_help, min, args...)                                                    \
  CFG_VALIDATE_INT64_MINMAX(p_name, p_def, p_help, 3, false, min, INT64_MAX, ##args)

/**
 * Creates a cfg_schema_entry for a clock value with defined maximum
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param max maximal allowed clock value
 * @param args variable list of additional arguments
 */
#define CFG_VALIDATE_CLOCK_MAX(p_name, p_def, p_help, max, args...)                                                    \
  CFG_VALIDATE_INT64_MINMAX(p_name, p_def, p_help, 3, false, 0, max, ##args)

/**
 * Creates a cfg_schema_entry for a clock value with minimum and maximum
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param min minimal allowed clock value
 * @param max maximal allowed clock value
 * @param args variable list of additional arguments
 */
#define CFG_VALIDATE_CLOCK_MINMAX(p_name, p_def, p_help, min, max, args...)                                            \
  CFG_VALIDATE_INT64_MINMAX(p_name, p_def, p_help, 3, false, min, max, ##args)

/**
 * Creates a cfg_schema_entry for a clock value that
 * can be mapped into a binary struct
 * @param p_reference reference to instance of struct
 * @param p_field name of field in the struct for the parameter,
 *   it must be a string array
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param args variable list of additional arguments
 */
#define CFG_MAP_CLOCK(p_reference, p_field, p_name, p_def, p_help, args...)                                            \
  CFG_MAP_INT64_MINMAX(p_reference, p_field, p_name, p_def, p_help, 3, 0, INT64_MAX, ##args)

/**
 * Creates a cfg_schema_entry for a clock value with minimal value that
 * can be mapped into a binary struct
 * @param p_reference reference to instance of struct
 * @param p_field name of field in the struct for the parameter,
 *   it must be a string array
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param min minimal allowed clock value
 * @param args variable list of additional arguments
 */
#define CFG_MAP_CLOCK_MIN(p_reference, p_field, p_name, p_def, p_help, min, args...)                                   \
  CFG_MAP_INT64_MINMAX(p_reference, p_field, p_name, p_def, p_help, 3, min, INT64_MAX, ##args)

/**
 * Creates a cfg_schema_entry for a clock value with maximal value that
 * can be mapped into a binary struct
 * @param p_reference reference to instance of struct
 * @param p_field name of field in the struct for the parameter,
 *   it must be a string array
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param max maximal allowed clock value
 * @param args variable list of additional arguments
 */
#define CFG_MAP_CLOCK_MAX(p_reference, p_field, p_name, p_def, p_help, max, args...)                                   \
  CFG_MAP_INT64_MINMAX(p_reference, p_field, p_name, p_def, p_help, 3, 0, max, ##args)

/**
 * Creates a cfg_schema_entry for a clock value with minimal
 * and maximal value that can be mapped into a binary struct
 * @param p_reference reference to instance of struct
 * @param p_field name of field in the struct for the parameter,
 *   it must be a string array
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param min minimal allowed clock value
 * @param max maximal allowed clock value
 * @param args variable list of additional arguments
 */
#define CFG_MAP_CLOCK_MINMAX(p_reference, p_field, p_name, p_def, p_help, min, max, args...)                           \
  CFG_MAP_INT64_MINMAX(p_reference, p_field, p_name, p_def, p_help, 3, min, max, ##args)

EXPORT int oonf_clock_update(void) __attribute__((warn_unused_result));

EXPORT uint64_t oonf_clock_getNow(void);

EXPORT const char *oonf_clock_toClockString(struct isonumber_str *, uint64_t);

/**
 * Converts an internal time interval into a string representation with
 * the numbers of seconds (including milliseconds as fractions)
 * @param buf target buffer
 * @param i time value
 * @return pointer to string representation
 */
static INLINE const char *
oonf_clock_toIntervalString_ext(struct isonumber_str *buf, int64_t i, bool raw) {
  return isonumber_from_s64(buf, i, "", 1000, raw);
}

/**
 * Converts an internal time interval into a string representation with
 * the numbers of seconds (including milliseconds as fractions)
 * @param buf target buffer
 * @param i time value
 * @return pointer to string representation
 */
static INLINE const char *
oonf_clock_toIntervalString(struct isonumber_str *buf, int64_t i) {
  return oonf_clock_toIntervalString_ext(buf, i, false);
}

/**
 * Converts a string representation of seconds (including up to three
 * fractional digits for milliseconds) into a 64 bit time value
 * @param result pointer to output buffer
 * @param string string representation of the time value
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
oonf_clock_fromIntervalString(uint64_t *result, const char *string) {
  int64_t t;
  int r;

  r = isonumber_to_s64(&t, string, 1000);
  if (r == 0) {
    *result = t;
  }
  return r;
}

/**
 * Returns a timestamp s seconds in the future
 * @param relative milliseconds until timestamp
 * @return absolute time when event will happen
 */
static INLINE uint64_t
oonf_clock_get_absolute(int64_t relative) {
  return oonf_clock_getNow() + relative;
}

/**
 * Returns the number of milliseconds until the timestamp will happen
 * @param absolute timestamp
 * @return milliseconds until event will happen, negative if it already
 *   happened.
 */
static INLINE int64_t
oonf_clock_get_relative(uint64_t absolute) {
  return (int64_t)absolute - (int64_t)oonf_clock_getNow();
}

/**
 * Checks if a timestamp has already happened
 * @param absolute timestamp
 * @return true if the event already happened, false otherwise
 */
static INLINE bool
oonf_clock_is_past(uint64_t absolute) {
  return absolute < oonf_clock_getNow();
}

#endif

/*
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
