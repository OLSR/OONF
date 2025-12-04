
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

#ifndef OONF_TIMER_H_
#define OONF_TIMER_H_

#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>

#include <oonf/base/oonf_clock.h>

/*! subsystem identifier */
#define OONF_TIMER_SUBSYSTEM "timer"

struct oonf_timer_instance;

/*! timeslice of the scheduler */
#define OONF_TIMER_SLICE 100ull

/**
 * This struct defines a class of timers which have the same
 * type (periodic/non-periodic) and callback.
 */
struct oonf_timer_class {
  /*! node of timerinfo list */
  struct list_entity _node;

  /*! name of this timer class */
  const char *name;

  /**
   * Callback when timer is triggered
   * @param ptr pointer to timer instance that fired
   */
  void (*callback)(struct oonf_timer_instance *ptr);

  /*! true if this is a class of periodic timers */
  bool periodic;

  /*! Number of times the timer is currently running */
  uint32_t _stat_usage;

  /*! Number of times the timer was reset */
  uint32_t _stat_changes;

  /*! number of times the timer fired */
  uint32_t _stat_fired;

  /*! number of times the timer took more than a timeslice */
  uint32_t _stat_long;

  /*! pointer to timer currently in callback */
  struct oonf_timer_instance *_timer_in_callback;

  /*! set to true if the current running timer has been stopped */
  bool _timer_stopped;
};

/**
 * A single timer instance of a timer class
 */
struct oonf_timer_instance {
  /*! node of timer class tree of instances */
  struct avl_node _node;

  /*! backpointer to timer class */
  struct oonf_timer_class *class;

  /*! the jitter expressed in percent */
  uint8_t jitter_pct;

  /*! timeperiod between two timer events for periodical timers */
  uint64_t _period;

  /*! cache random() result for performance reasons */
  unsigned int _random;

  /*! absolute timestamp when timer will fire */
  uint64_t _clock;
};

/* Timers */
EXPORT void oonf_timer_walk(void);

EXPORT void oonf_timer_add(struct oonf_timer_class *ti);
EXPORT void oonf_timer_remove(struct oonf_timer_class *);

EXPORT void oonf_timer_set_ext(struct oonf_timer_instance *timer, uint64_t first, uint64_t interval);
EXPORT void oonf_timer_start_ext(struct oonf_timer_instance *timer, uint64_t first, uint64_t interval);
EXPORT void oonf_timer_stop(struct oonf_timer_instance *);

EXPORT uint64_t oonf_timer_getNextEvent(void);

EXPORT struct list_entity *oonf_timer_get_list(void);

/**
 * @param timer pointer to timer
 * @return true if the timer is running, false otherwise
 */
static INLINE bool
oonf_timer_is_active(const struct oonf_timer_instance *timer) {
  return timer->_clock != 0ull;
}

/**
 * @param timer pointer to timer
 * @return interval between timer events in milliseconds
 */
static INLINE uint64_t
oonf_timer_get_period(const struct oonf_timer_instance *timer) {
  return timer->_period;
}

/**
 * @param timer pointer to timer
 * @return number of milliseconds until timer fires
 */
static INLINE int64_t
oonf_timer_get_due(const struct oonf_timer_instance *timer) {
  return oonf_clock_get_relative(timer->_clock);
}

/**
 * Puts the number of seconds until the timer fires into the output buffer,
 * or "-1" if it has already fired.
 * @param buf target buffer
 * @param timer timer
 * @param raw true to get raw time values, false to use ISO prefixes
 * @return pointer to string representation
 */
static INLINE const char *
oonf_timer_to_string_ext(struct isonumber_str *buf, struct oonf_timer_instance *timer, bool raw) {
  static const char NONE[] = "-1";
  if (!oonf_timer_is_active(timer)) {
    return NONE;
  }
  else {
    return oonf_clock_toIntervalString_ext(buf, oonf_timer_get_due(timer), raw);
  }
}

/**
 * Puts the number of seconds until the timer fires into the output buffer,
 * or "-1" if it has already fired.
 * @param buf target buffer
 * @param timer timer
 * @return pointer to string representation
 */
static INLINE const char *
oonf_timer_to_string(struct isonumber_str *buf, struct oonf_timer_instance *timer) {
  return oonf_timer_to_string_ext(buf, timer, false);
}

/**
 * This is the one stop shop for all sort of timer manipulation.
 * Depending on the passed in parameters a new timer is started,
 * or an existing timer is started or an existing timer is
 * terminated.
 * @param timer timer_entry pointer
 * @param rel_time relative time when the timer should fire
 */
static INLINE void
oonf_timer_set(struct oonf_timer_instance *timer, uint64_t rel_time) {
  oonf_timer_set_ext(timer, rel_time, rel_time);
}

/**
 * Start or restart a new timer.
 * @param timer initialized timer entry
 * @param rel_time relative time when the timer should fire
 */
static INLINE void
oonf_timer_start(struct oonf_timer_instance *timer, uint64_t rel_time) {
  oonf_timer_start_ext(timer, rel_time, rel_time);
}

/**
 * @param tc timer class
 * @return number of timers currently in use
 */
static INLINE uint32_t
oonf_timer_get_usage(struct oonf_timer_class *tc) {
  return tc->_stat_usage;
}

/**
 * @param tc timer class
 * @return number of times the timer was reset
 */
static INLINE uint32_t
oonf_timer_get_changes(struct oonf_timer_class *tc) {
  return tc->_stat_changes;
}

/**
 * @param tc timer class
 * @return number of times the timer was fired
 */
static INLINE uint32_t
oonf_timer_get_fired(struct oonf_timer_class *tc) {
  return tc->_stat_fired;
}

/**
 * @param tc timer class
 * @return number of times the timer took more than a timeslice
 */
static INLINE uint32_t
oonf_timer_get_long(struct oonf_timer_class *tc) {
  return tc->_stat_long;
}

#endif /* OONF_TIMER_H_ */
