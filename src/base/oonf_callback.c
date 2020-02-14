
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

#include <oonf/oonf.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_callback.h>

/* definitions */
#define LOG_CALLBACK _oonf_callback_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

static struct oonf_subsystem _oonf_callback_subsystem = {
  .name = OONF_CALLBACK_SUBSYSTEM,
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_callback_subsystem);

/* static list of callbacks */
static struct list_entity _callback_list;

/*! static reminder that a callback is running */
static struct oonf_callback *_callback_in_progress;

/**
 * Initialize olsr callback system
 * @return always 0
 */
static int
_init(void) {
  list_init_head(&_callback_list);
  return 0;
}

/**
 * Cleanup existing callback system datastructures
 */
static void
_cleanup(void) {
  struct oonf_callback *cb, *cb_it;

  list_for_each_element_safe(&_callback_list, cb, _node, cb_it) {
    oonf_callback_remove(cb);
  }
}

/**
 * Add a callback to the list
 * @return -1 if an error happened, 0 otherwise
 */
void
oonf_callback_add(struct oonf_callback *cb) {
  OONF_ASSERT(!_callback_in_progress, LOG_CALLBACK,
    "Error, callback %s is trying to add another callback",
    _callback_in_progress->name);

  if (list_is_node_added(&cb->_node)) {
    list_remove(&cb->_node);
  }
  list_add_tail(&_callback_list, &cb->_node);
}

/**
 * Add a callback to the list
 * @return -1 if an error happened, 0 otherwise
 */
void
oonf_callback_remove(struct oonf_callback *cb) {
  if (list_is_node_added(&cb->_node)) {
    list_remove(&cb->_node);
  }
}

/**
 * Call all registered callbacks
 */
void
oonf_callback_walk(void) {
  struct oonf_callback *cb;

  while (!list_is_empty(&_callback_list)) {
    cb = list_first_element(&_callback_list, cb, _node);
    oonf_callback_remove(cb);

    _callback_in_progress = cb;
    cb->cb_trigger(cb);
    _callback_in_progress = NULL;
  }
}

/**
 * @returns list of all callbacks
 */
struct list_entity *
oonf_callback_get_list(void) {
  return &_callback_list;
}
