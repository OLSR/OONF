
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

#ifndef _OONF_CLASS_H
#define _OONF_CLASS_H

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/list.h>

/*! subsystem identifier */
#define OONF_CLASS_SUBSYSTEM "class"

/**
 * Events triggered for memory class members
 */
enum oonf_class_event
{
  /*! an object has changed */
  OONF_OBJECT_CHANGED,

  /*! a new object has been added */
  OONF_OBJECT_ADDED,

  /*! an object will be removed */
  OONF_OBJECT_REMOVED,
};

/**
 * Buffer for text representation of an object
 */
struct oonf_objectkey_str {
  /*! maximum length buffer for text */
  char buf[128];
};

/* storage data for a custom guard */
struct oonf_class_guard {
  const char *name;
  uint32_t id;
};

enum {
  OONF_CLASS_GUARD1 = 0x13572468,
  OONF_CLASS_GUARD2 = 0x75318642
};

/**
 * Prefix to check data for overwriting and type error
 */
struct oonf_class_guard_prefix {
  uint32_t id;
  uint32_t guard1;
};

#ifdef OONF_LOG_DEBUG_INFO
#define OONF_CLASS_GUARD_PREFIX struct oonf_class_guard_prefix __guard_prefix;
#else
#define OONF_CLASS_GUARD_PREFIX
#endif

/**
 * Suffix to check data for overwriting
 */
struct oonf_class_guard_suffix {
  uint32_t guard2;
};

#ifdef OONF_LOG_DEBUG_INFO
#define OONF_CLASS_GUARD_SUFFIX struct oonf_class_guard_suffix __guard_suffix;
#else
#define OONF_CLASS_GUARD_SUFFIX
#endif

/**
 * This structure represents a class of memory object, each with the same size.
 */
struct oonf_class {
  /*! Name of class */
  const char *name;

  /*! Size of memory blocks in bytes */
  size_t size;

  /**
   * minimum number of chunks the allocator will keep
   * in the free list before starting to deallocate one
   */
  uint32_t min_free_count;

  /**
   * Callback to convert object pointer into a human readable string
   * @param buf output buffer for text
   * @param cl oonf class
   * @param ptr pointer to object
   * @return pointer to buffer
   */
  const char *(*to_keystring)(struct oonf_objectkey_str *buf, struct oonf_class *cl, void *ptr);

  /*! Size of class including extensions in bytes */
  size_t total_size;

  /*! List node for classes */
  struct avl_node _node;

  /*! List head for recyclable blocks */
  struct list_entity _free_list;

  /*! extensions of this class */
  struct list_entity _extensions;

  /*! Length of free list */
  uint32_t _free_list_size;

  /*! Stats, resource usage */
  uint32_t _current_usage;

  /*! Stats, allocated memory blocks */
  uint32_t _allocated;

  /*! Stats, recycled memory blocks */
  uint32_t _recycled;

  /*! track debug status of class */
  bool debug;

  /* guard for debugging */
  struct oonf_class_guard class_guard;
};

/**
 * This structure defines a listener that can receive Add/Change/Remove
 * events for a certain class.
 *
 * It can also be used to extend the class with additional memory, as long
 * as no object has been allocated for the class in this moment.
 */
struct oonf_class_extension {
  /*! name of the consumer */
  const char *ext_name;

  /*! name of the provider */
  const char *class_name;

  /*! size of the extension */
  size_t size;

  /*! offset of the extension within the memory block */
  size_t _offset;

  /**
   * Callback to notify that a class object was added
   * @param ptr pointer to object
   */
  void (*cb_add)(void *ptr);

  /**
   * Callback to notify that a class object was changed
   * @param ptr pointer to object
   */
  void (*cb_change)(void *ptr);

  /**
   * Callback to notify that a class object was removed
   * @param ptr pointer to object
   */
  void (*cb_remove)(void *ptr);

  /*! node for hooking the consumer into the provider */
  struct list_entity _node;
};

/* Externals. */
EXPORT void oonf_class_add(struct oonf_class *);
EXPORT void oonf_class_remove(struct oonf_class *);

EXPORT void *oonf_class_malloc(struct oonf_class *) __attribute__((warn_unused_result));
EXPORT void oonf_class_free(struct oonf_class *, void *);
EXPORT void oonf_class_check(struct oonf_class *ci, void *ptr);

EXPORT void oonf_class_guard_add(struct oonf_class_guard *);

EXPORT int oonf_class_extension_add(struct oonf_class_extension *);
EXPORT void oonf_class_extension_remove(struct oonf_class_extension *);

EXPORT void oonf_class_event(struct oonf_class *, void *, enum oonf_class_event);

EXPORT struct avl_tree *oonf_class_get_tree(void);
EXPORT const char *oonf_class_get_event_name(enum oonf_class_event);

/**
 * @param ci pointer to class
 * @return number of blocks currently in use
 */
static INLINE uint32_t
oonf_class_get_usage(struct oonf_class *ci) {
  return ci->_current_usage;
}

/**
 * @param ci pointer to class
 * @return number of blocks currently in free list
 */
static INLINE uint32_t
oonf_class_get_free(struct oonf_class *ci) {
  return ci->_free_list_size;
}

/**
 * @param ci pointer to class
 * @return total number of allocations during runtime
 */
static INLINE uint32_t
oonf_class_get_allocations(struct oonf_class *ci) {
  return ci->_allocated;
}

/**
 * @param ci pointer to class
 * @return total number of allocations during runtime
 */
static INLINE uint32_t
oonf_class_get_recycled(struct oonf_class *ci) {
  return ci->_recycled;
}

/**
 * @param ext extension data structure
 * @param ptr pointer to base block
 * @return pointer to extensions memory block
 */
static INLINE void *
oonf_class_get_extension(struct oonf_class_extension *ext, void *ptr) {
  return ((char *)ptr) + ext->_offset;
}

/**
 * @param ext extension data structure
 * @param ptr pointer to extension block
 * @return pointer to base memory block
 */
static INLINE void *
oonf_class_get_base(struct oonf_class_extension *ext, void *ptr) {
  return ((char *)ptr) - ext->_offset;
}

/**
 * @param ext pointer to class extension
 * @return true if extension is registered
 */
static INLINE bool
oonf_class_is_extension_registered(struct oonf_class_extension *ext) {
  return list_is_node_added(&ext->_node);
}

#ifdef OONF_LOG_DEBUG_INFO
#define oonf_class_guard_init(guard, base) oonf_class_guard_init_ext(guard, &(base)->__guard_prefix, &(base)->__guard_suffix)

static INLINE void
oonf_class_guard_init_ext(struct oonf_class_guard *guard,
    struct oonf_class_guard_prefix *prefix, struct oonf_class_guard_suffix *suffix) {
  prefix->guard1 = OONF_CLASS_GUARD1;
  prefix->id = guard->id;
  suffix->guard2 = OONF_CLASS_GUARD2;
}

#define oonf_class_guard_is_valid(guard, base) oonf_class_guard_is_valid_ext(guard, &(base)->__guard_prefix, &(base)->__guard_suffix)
#define OONF_CLASS_GUARD_ASSERT(guard, base, logging) OONF_ASSERT(oonf_class_guard_is_valid(guard, base), logging, "%s (%u) guard is bad (id=%u, guard1=%08x, guard2=%08x)", (guard)->name, (guard)->id, (base)->__guard_prefix.id, (base)->__guard_prefix.guard1, (base)->__guard_suffix.guard2)

static INLINE bool
oonf_class_guard_is_valid_ext(struct oonf_class_guard *guard,
    struct oonf_class_guard_prefix *prefix, struct oonf_class_guard_suffix *suffix) {
  return prefix->guard1 == OONF_CLASS_GUARD1
      && suffix->guard2 == OONF_CLASS_GUARD2
      && prefix->id == guard->id;
}
#else /* OONF_LOG_DEBUG_INFO */
#define oonf_class_guard_init(guard, base) do {} while(0)
static INLINE void
oonf_class_guard_init_ext(struct oonf_class_guard *guard __attribute__((unused)),
    struct oonf_class_guard_prefix *prefix __attribute__((unused)),
    struct oonf_class_guard_suffix *suffix __attribute__((unused))) {
}
#define oonf_class_guard_is_valid(guard, base) true
#define OONF_CLASS_GUARD_ASSERT(guard, ptr, logging) do {} while(0)

static INLINE bool
oonf_class_guard_is_valid_ext(struct oonf_class_guard *guard __attribute__((unused)),
    struct oonf_class_guard_prefix *prefix __attribute__((unused)),
    struct oonf_class_guard_suffix *suffix __attribute__((unused))) {
  return true;
}

#endif /* OONF_LOG_DEBUG_INFO */

#endif /* _OONF_CLASS_H */
