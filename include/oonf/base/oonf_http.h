
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

#ifndef OONF_HTTP_H_
#define OONF_HTTP_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/libcommon/string.h>
#include <oonf/base/oonf_stream_socket.h>

/*! subsystem identifier */
#define OONF_HTTP_SUBSYSTEM "http"

/*! HTTP HTML content type */
#define HTTP_CONTENTTYPE_HTML "text/html"

/*! HTTP text content type */
#define HTTP_CONTENTTYPE_TEXT "text/plain"

/**
 * Constants for HTTP subsystem
 */
enum
{
  /*! maximum number of HTTP headers */
  OONF_HTTP_MAX_HEADERS = 16,

  /*! maximum number of GET/POST parameters */
  OONF_HTTP_MAX_PARAMS = 8,

  /*! maximum URI length */
  OONF_HTTP_MAX_URI_LENGTH = 256
};

/**
 * supported HTTP result codes
 */
enum oonf_http_result
{
  HTTP_200_OK = 200,
  HTTP_400_BAD_REQ = 400,
  HTTP_401_UNAUTHORIZED = 401,
  HTTP_403_FORBIDDEN = STREAM_REQUEST_FORBIDDEN,
  HTTP_404_NOT_FOUND = 404,
  HTTP_413_REQUEST_TOO_LARGE = STREAM_REQUEST_TOO_LARGE,
  HTTP_500_INTERNAL_SERVER_ERROR = 500,
  HTTP_501_NOT_IMPLEMENTED = 501,
  HTTP_503_SERVICE_UNAVAILABLE = STREAM_SERVICE_UNAVAILABLE,

  /*! special result to signal start of file transfer */
  HTTP_START_FILE_TRANSFER = 99999,
};

/**
 * HTTP session data
 */
struct oonf_http_session {
  /*! address of remote client */
  struct netaddr *remote;

  /*! HTTP metric (get, post, ...) */
  const char *method;

  /*! HTTP request uri */
  const char *request_uri;

  /*! HTTP request URI with decoded special characters */
  const char *decoded_request_uri;

  /*! HTTP version */
  const char *http_version;

  /* TODO: replace with strarray */
  /*! array of HTTP header field names */
  char *header_name[OONF_HTTP_MAX_HEADERS];

  /*! array of HTTP header field values */
  char *header_value[OONF_HTTP_MAX_HEADERS];

  /*! number of HTTP header fields */
  size_t header_count;

  /*! array of HTTP GET/POST keys */
  char *param_name[OONF_HTTP_MAX_PARAMS];

  /*! array of HTTP GET/POST values */
  char *param_value[OONF_HTTP_MAX_PARAMS];

  /*! number of HTTP GET/POST values */
  size_t param_count;

  /*! content type for answer, NULL means plain/html */
  const char *content_type;

  /*! file descriptor to file that is being downloaded in this session */
  int transfer_fd;

  /*! number of bytes already being downloaded */
  size_t transfer_length;
};

/**
 * HTTP handler for a directory or file
 */
struct oonf_http_handler {
  /*! hook into global http handler tree */
  struct avl_node node;

  /*! path of filename of content */
  const char *site;

  /*! set by oonf_http_add to true if site is a directory */
  bool directory;

  /*! list of base64 encoded name:password combinations */
  struct strarray auth;

  /*! list of IP addresses/ranges this site can be accessed from */
  struct netaddr_acl acl;

  /*! pointer to static content for this handler */
  const char *content;

  /*! length of static content in bytes */
  size_t content_size;

  /**
   * Callback to generate dynamic content
   * This is called if the content variable is NULL.
   * @param out output buffer for content
   * @param session http session object
   * @return http result
   */
  enum oonf_http_result (*content_handler)(struct autobuf *out, struct oonf_http_session *session);
};

EXPORT void oonf_http_add(struct oonf_http_handler *);
EXPORT void oonf_http_remove(struct oonf_http_handler *);

EXPORT const char *oonf_http_lookup_value(char **keys, char **values, size_t count, const char *key);

/**
 * Lookup the value of one http header field.
 * @param session pointer to http session
 * @param key header field name
 * @return header field value or NULL if not found
 */
static INLINE const char *
oonf_http_lookup_header(struct oonf_http_session *session, const char *key) {
  return oonf_http_lookup_value(session->header_name, session->header_value, session->header_count, key);
}

/**
 * Lookup the value of one http request parameter delivered by GET
 * @param session pointer to http session
 * @param key header field name
 * @return parameter value or NULL if not found
 */
static INLINE const char *
oonf_http_lookup_param(struct oonf_http_session *session, const char *key) {
  return oonf_http_lookup_value(session->param_name, session->param_value, session->param_count, key);
}

#endif /* OONF_HTTP_H_ */
