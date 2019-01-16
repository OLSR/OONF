
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

#ifndef OONF_DUPLICATE_SET_H_
#define OONF_DUPLICATE_SET_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/base/oonf_timer.h>

/*! subsystem identifier */
#define OONF_DUPSET_SUBSYSTEM "duplicate_set"

/**
 * duplicate set constants
 */
enum
{
  /**
   * number of consecutive 'too old' sequence numbers before
   * algorithm resets
   */
  OONF_DUPSET_MAXIMUM_TOO_OLD = 8
};

/**
 * results of a duplicate check
 */
enum oonf_duplicate_result
{
  /*! much older than cached number */
  OONF_DUPSET_TOO_OLD,

  /*! duplicate */
  OONF_DUPSET_DUPLICATE,

  /*! unknown number within the sliding window */
  OONF_DUPSET_NEW,

  /*! exactly the latest cached number */
  OONF_DUPSET_CURRENT,

  /*! newer than the latest cached number */
  OONF_DUPSET_NEWEST,

  /*! sequence number was the first tested with the duplicate set */
  OONF_DUPSET_FIRST,
};

/**
 * session data for detecting duplicate sequence numbers for addresses
 */
struct oonf_duplicate_set {
  /*! tree of duplicate entries */
  struct avl_tree _tree;

  /*! mask for detecting overflow */
  int64_t _mask;

  /*! comparison limit to detect overflow */
  int64_t _limit;

  /*! offset to fix overflow */
  int64_t _offset;
};

/**
 * Unique key for duplicate entry
 */
struct oonf_duplicate_entry_key {
  /*! address the sequence number referrs to */
  struct netaddr addr;

  /*! message type of sequence number, mostly RFC5444 */
  uint8_t msg_type;
};

/**
 * State of duplicate detection for one unique key
 */
struct oonf_duplicate_entry {
  /*! unique key for duplicate detection */
  struct oonf_duplicate_entry_key key;

  /*! bit buffer for duplicate detection */
  uint64_t history;

  /*! newest received sequence number */
  uint64_t current;

  /*! number of too old consecutive sequence numbers without a newer one */
  uint16_t too_old_count;

  /*! back pointer to duplicate set */
  struct oonf_duplicate_set *set;

  /*! node for tree of duplicate set */
  struct avl_node _node;

  /*! timer for removing outdated duplicate set data */
  struct oonf_timer_instance _vtime;
};

/**
 * bitwidth of duplicate set
 */
enum oonf_dupset_type
{
  /*! 8 bit duplicate set */
  OONF_DUPSET_8BIT,

  /*! 16 bit duplicate set */
  OONF_DUPSET_16BIT,

  /*! 32 bit duplicate set */
  OONF_DUPSET_32BIT,

  /*! 64 bit duplicate set */
  OONF_DUPSET_64BIT,
};

EXPORT void oonf_duplicate_set_add(struct oonf_duplicate_set *, enum oonf_dupset_type type);
EXPORT void oonf_duplicate_set_remove(struct oonf_duplicate_set *);

EXPORT enum oonf_duplicate_result oonf_duplicate_entry_add(
  struct oonf_duplicate_set *, uint8_t msg_type, struct netaddr *, uint64_t seqno, uint64_t vtime);

EXPORT enum oonf_duplicate_result oonf_duplicate_test(
  struct oonf_duplicate_set *, uint8_t msg_type, struct netaddr *, uint64_t seqno);

EXPORT const char *oonf_duplicate_get_result_str(enum oonf_duplicate_result);

/**
 * returns if a sequence number result means it is new
 * @param result sequence number processing result
 * @return true if result was newer than the last one
 */
static INLINE bool
oonf_duplicate_is_new(enum oonf_duplicate_result result) {
  return result == OONF_DUPSET_NEW || result == OONF_DUPSET_NEWEST || result == OONF_DUPSET_FIRST;
}

#endif /* OONF_DUPLICATE_SET_H_ */
