/**
 * Copyright (C) 2016 Fraunhofer FKIE
 *
 * @author         Henning Rogge
 */

/**
 * @file
 */

#include <errno.h>
#include <string.h>

#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcore/oonf_subsystem.h>

#include <oonf/base/oonf_socket.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_fd.h>

#include <oonf/generic/dns_query/dns.h>
#include <oonf/generic/dns_query/dns_query.h>

/* definitions */
#define LOG_DNS_QUERY _dns_query_subsystem.logging

struct _dns_query_config {
  uint64_t timeout;
};

/* prototypes */

static int _init(void);
static void _cleanup(void);

static void _cb_process_dns_query(struct oonf_socket_entry *entry);
static void _cb_dns_timeout(struct oonf_timer_instance *timer);
static void _cb_config_changed(void);

/* timeout for DNS queries */
static struct oonf_timer_class _dns_timeout = {
  .name = "dns query timeout",
  .callback = _cb_dns_timeout
};

/* configuration */
static struct cfg_schema_entry _dns_query_entries[] = {
  CFG_MAP_CLOCK(_dns_query_config, timeout, "timeout", "1.0", "Default DNS query timeout"),
};

static struct cfg_schema_section _dns_query_section = {
  .type = OONF_DNS_QUERY_SUBSYSTEM,
  .cb_delta_handler = _cb_config_changed,
  .entries = _dns_query_entries,
  .entry_count = ARRAYSIZE(_dns_query_entries),
};

static struct _dns_query_config _config;

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_TIMER_SUBSYSTEM,
  OONF_SOCKET_SUBSYSTEM,
};
static struct oonf_subsystem _dns_query_subsystem = {
  .name = OONF_DNS_QUERY_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OONF dns query plugin",
  .author = "Henning Rogge",

  .cfg_section = &_dns_query_section,

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_dns_query_subsystem);

/**
 * constructor of dns query plugin
 * @return always 0
 */
static int
_init(void) {
  oonf_timer_add(&_dns_timeout);
  return 0;
}

/**
 * destructor of dns query plugin
 */
static void
_cleanup(void) {
  oonf_timer_remove(&_dns_timeout);
}

/**
 * Trigger a new DNS query
 * @param q dns query
 * @return 0 if query was triggered, error number otherwise
 */
int
dns_query_do(struct oonf_dns_query *q) {
  int error;

  if (q->timeout == 0) {
    /* use default timeout */
    q->timeout = _config.timeout;
  }
  if (!q->socket_name) {
    q->socket_name = q->query;
  }

  dns_p_init(&q->_bin_query.packet, sizeof(q->_bin_query));
	if ((error = dns_p_push(&q->_bin_query.packet,
      DNS_S_QD, q->query, strlen(q->query), q->dns_type, DNS_C_IN, 0, 0))) {
    OONF_WARN(LOG_DNS_QUERY, "Could not generate DNS query '%s': %s (%d)",
        q->query, dns_strerror(error), error);
    return error;
  }
	dns_header(&q->_bin_query.packet)->rd	= 1;

  /* initialize new DNS query */
  if (!(q->_dns_socket = dns_so_open(&q->dns_client->std, SOCK_DGRAM, dns_opts(), &error))) {
    OONF_WARN(LOG_DNS_QUERY, "Could not open DNS client socket: %s (%d)", dns_strerror(error), error);
    return error;
  }

  /* initiatize socket handling */
  q->_socket_entry.name = q->socket_name;
  q->_socket_entry.process = _cb_process_dns_query;
  os_fd_invalidate(&q->_socket_entry.fd);

  /* initialize timeout */
  q->_timeout.class = &_dns_timeout;
  oonf_timer_start(&q->_timeout, q->timeout);

  /* run first stage DNS query handling */
  _cb_process_dns_query(&q->_socket_entry);

  return 0;
}

/**
 * callback for processing DNS query responses
 * @param entry socket entry
 */
static void
_cb_process_dns_query(struct oonf_socket_entry *entry) {
  struct oonf_dns_query *q;
  struct dns_packet *A;
	struct dns_rr rr;
	union dns_any any;
  int error, events;
  bool specific_callback;
  char buffer[256];
  q = container_of(entry, struct oonf_dns_query, _socket_entry);

  /* reset timeout */
  oonf_timer_set(&q->_timeout, q->timeout);

  OONF_DEBUG(LOG_DNS_QUERY, "continue DNS query %s", q->query);
  A = dns_so_query(q->_dns_socket, &q->_bin_query.packet, &q->dns_server->std, &error);
  if (!A) {
    if (error != EAGAIN) {
      OONF_WARN(LOG_DNS_QUERY, "Error while progressing DNS query: %s (%d)",
          dns_strerror(error), error);
    }
    events = dns_so_events(q->_dns_socket);
    if (!os_fd_is_initialized(&q->_socket_entry.fd)) {
      /* lazy initialization */
      os_fd_init(&q->_socket_entry.fd, dns_so_pollfd(q->_dns_socket));
      oonf_socket_add(&q->_socket_entry);
    }
    oonf_socket_set_read(&q->_socket_entry, (events & DNS_POLLIN) == DNS_POLLIN);
    oonf_socket_set_write(&q->_socket_entry, (events & DNS_POLLOUT) == DNS_POLLOUT);
    OONF_DEBUG(LOG_DNS_QUERY, "Wait for socket event (in=%s, out=%s)",
        (events & DNS_POLLIN) == DNS_POLLIN ? "true" : "false",
        (events & DNS_POLLOUT) == DNS_POLLOUT ? "true" : "false");
    return;
  }

  dns_rr_foreach(&rr, A, .sort = dns_rr_i_packet) {
  	if (rr.section == DNS_S_QD) {
      /* don't parse repeated query */
      continue;
    }

    if ((error = dns_any_parse(dns_any_init(&any, sizeof(any)), &rr, A)) != 0) {
      OONF_WARN(LOG_DNS_QUERY, "Could not parse data of RR type %s (%d): %s (%d)", dns_strtype(rr.type), rr.type, dns_strerror(error), error);
      continue;
    }

    dns_any_print(buffer, sizeof(buffer), &any,rr.type);
    OONF_DEBUG(LOG_DNS_QUERY, "Got RR (%s): %s", dns_strtype(rr.type), buffer);

    specific_callback = false;
    switch (rr.type) {
      case DNS_T_SRV:
        if (q->cb.srv_result) {
          specific_callback = true;
          q->cb.srv_result(q, &any.srv);
        }
        break;
      case DNS_T_A:
        if (q->cb.a_result) {
          specific_callback = true;
          q->cb.a_result(q, &any.a);
        }
        break;
      case DNS_T_AAAA:
        if (q->cb.aaaa_result) {
          specific_callback = true;
          q->cb.aaaa_result(q, &any.aaaa);
        }
        break;
      case DNS_T_PTR:
        if (q->cb.ptr_result) {
          specific_callback = true;
          q->cb.ptr_result(q, &any.ptr);
        }
        break;
      default:
        break;
    }
    if (!specific_callback && q->cb.any_result) {
      q->cb.any_result(q, rr.type, &any);
    }
  }
  dns_so_close(q->_dns_socket);
  oonf_socket_remove(&q->_socket_entry);
  oonf_timer_stop(&q->_timeout);

  /* inform callback last (might cleanup data structure) */
  OONF_DEBUG(LOG_DNS_QUERY, "Query done");
  if (q->cb_done) {
    q->cb_done(q, false);
  }
}

/**
 * Callback for handling DNS timeouts
 * @param timer timer instance
 */
static void
_cb_dns_timeout(struct oonf_timer_instance *timer) {
  struct oonf_dns_query *q;

  q = container_of(timer, struct oonf_dns_query, _timeout);
  dns_so_close(q->_dns_socket);
  oonf_socket_remove(&q->_socket_entry);

  /* inform callback last (might cleanup data structure */
  if (q->cb_done) {
    q->cb_done(q, true);
  }
}

/**
 * Callback for configuration changes
 */
static void
_cb_config_changed(void) {
  if (cfg_schema_tobin(&_config, _dns_query_section.post, _dns_query_entries, ARRAYSIZE(_dns_query_entries))) {
    OONF_WARN(LOG_DNS_QUERY, "Could not convert " OONF_DNS_QUERY_SUBSYSTEM " config to bin");
    return;
  }
}
