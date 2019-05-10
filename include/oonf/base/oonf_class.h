
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

#endif /* _OONF_CLASS_H */
