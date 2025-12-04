
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_main.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_callback.h>
#include <oonf/base/oonf_clock.h>
#include <oonf/base/oonf_socket.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_clock.h>
#include <oonf/base/os_fd.h>

/* Definitions */
#define LOG_SOCKET _oonf_socket_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);
static void _initiate_shutdown(void);

static bool _shall_end_scheduler(void);
static int _handle_scheduling(void);

/* time until the scheduler should run */
static uint64_t _scheduler_time_limit;

/* List of all active sockets in scheduler */
static struct list_entity _socket_head;

/* socket event scheduler */
struct os_fd_select _socket_events;

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_CALLBACK_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_OS_FD_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_socket_subsystem = {
  .name = OONF_SOCKET_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
  .initiate_shutdown = _initiate_shutdown,
};
DECLARE_OONF_PLUGIN(_oonf_socket_subsystem);

/**
 * Initialize olsr socket scheduler
 * @return always returns 0
 */
static int
_init(void) {
  if (oonf_main_set_scheduler(_handle_scheduling)) {
    return -1;
  }

  list_init_head(&_socket_head);
  os_fd_event_add(&_socket_events);

  _scheduler_time_limit = ~0ull;
  return 0;
}

/**
 * Cleanup olsr socket scheduler.
 * This will close and free all sockets.
 */
static void
_cleanup(void) {
  struct oonf_socket_entry *entry, *iterator;

  list_for_each_element_safe(&_socket_head, entry, _node, iterator) {
    list_remove(&entry->_node);
    os_fd_close(&entry->fd);
  }

  os_fd_event_remove(&_socket_events);
}

static void
_initiate_shutdown(void) {
  /* stop within 500 ms */
  _scheduler_time_limit = oonf_clock_get_absolute(500);
  OONF_INFO(LOG_SOCKET, "Stop within 500 ms");
}

/**
 * Add a socket handler to the scheduler
 *
 * @param entry pointer to initialized socket entry
 */
void
oonf_socket_add(struct oonf_socket_entry *entry) {
  OONF_DEBUG(LOG_SOCKET, "Adding socket entry %s (%d) to scheduler\n", entry->name, os_fd_get_fd(&entry->fd));

  list_add_before(&_socket_head, &entry->_node);
  os_fd_event_socket_add(&_socket_events, &entry->fd);
}

/**
 * Remove a socket from the socket scheduler
 * @param entry pointer to socket entry
 */
void
oonf_socket_remove(struct oonf_socket_entry *entry) {
  if (list_is_node_added(&entry->_node)) {
    OONF_DEBUG(LOG_SOCKET, "Removing socket entry %s (%d)\n", entry->name, os_fd_get_fd(&entry->fd));

    list_remove(&entry->_node);
    os_fd_event_socket_remove(&_socket_events, &entry->fd);
  }
}

/**
 * @return list of all registered sockets
 */
struct list_entity *
oonf_socket_get_list(void) {
  return &_socket_head;
}

/**
 * @param entry socket entry
 * @param event_read true to enable read events, false to disable
 */
void
oonf_socket_set_read(struct oonf_socket_entry *entry, bool event_read) {
  os_fd_event_socket_read(&_socket_events, &entry->fd, event_read);
}

/**
 * @param entry socket entry
 * @param event_write true to enable write events, false to disable
 */
void
oonf_socket_set_write(struct oonf_socket_entry *entry, bool event_write) {
  os_fd_event_socket_write(&_socket_events, &entry->fd, event_write);
}

/**
 * @return true if scheduler should stop
 */
static bool
_shall_end_scheduler(void) {
  return _scheduler_time_limit == ~0ull && oonf_main_shall_stop_scheduler();
}

/**
 * Handle all incoming socket events and timer events
 * @return -1 if an error happened, 0 otherwise
 */
int
_handle_scheduling(void) {
  struct oonf_socket_entry *sock_entry = NULL;
  struct os_fd *sock;
  uint64_t next_event;
  uint64_t start_time, end_time;
  int i, n;

  while (true) {
    /* Update time since this is much used by the parsing functions */
    if (oonf_clock_update()) {
      return -1;
    }

    if (oonf_clock_getNow() >= _scheduler_time_limit) {
      return -1;
    }

    oonf_callback_walk();
    oonf_timer_walk();

    if (_shall_end_scheduler()) {
      return 0;
    }

    oonf_callback_walk();
    next_event = oonf_timer_getNextEvent();
    if (next_event > _scheduler_time_limit) {
      next_event = _scheduler_time_limit;
    }

    if (os_fd_event_get_deadline(&_socket_events) != next_event) {
      os_fd_event_set_deadline(&_socket_events, next_event);
    }

    do {
      if (_shall_end_scheduler()) {
        return 0;
      }

      n = os_fd_event_wait(&_socket_events);
    } while (n == -1 && errno == EINTR);

    if (n == 0) { /* timeout! */
      return 0;
    }
    if (n < 0) { /* Did something go wrong? */
      OONF_WARN(LOG_SOCKET, "select error: %s (%d)", strerror(errno), errno);
      return -1;
    }

    /* Update time since this is much used by the parsing functions */
    if (oonf_clock_update()) {
      return -1;
    }

    OONF_DEBUG(LOG_SOCKET, "Got %d events", n);

    for (i = 0; i < n; i++) {
      sock = os_fd_event_get(&_socket_events, i);

      if (os_fd_event_is_read(sock) || os_fd_event_is_write(sock)) {
        sock_entry = container_of(sock, typeof(*sock_entry), fd);
        if (sock_entry->process == NULL) {
          continue;
        }

        OONF_DEBUG(LOG_SOCKET, "Socket '%s' (%d) triggered (read=%s, write=%s)", sock_entry->name,
          os_fd_get_fd(&sock_entry->fd), os_fd_event_is_read(sock) ? "true" : "false",
          os_fd_event_is_write(sock) ? "true" : "false");

        /* handle statistics */
        if (os_fd_event_is_read(sock)) {
          sock_entry->_stat_recv++;
        }
        if (os_fd_event_is_write(sock)) {
          sock_entry->_stat_send++;
        }
        os_clock_gettime64(&start_time);
        sock_entry->process(sock_entry);
        os_clock_gettime64(&end_time);

        if (end_time - start_time > OONF_TIMER_SLICE) {
          OONF_WARN(LOG_SOCKET, "Socket '%s' (%d) scheduling took %" PRIu64 " ms", sock_entry->name,
            os_fd_get_fd(&sock_entry->fd), end_time - start_time);
          sock_entry->_stat_long++;
        }
      }
    }
  }
  return 0;
}
