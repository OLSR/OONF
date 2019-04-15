
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

#include <oonf/libcommon/json.h>
#include <oonf/libcommon/autobuf.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/string.h>
#include <oonf/libcommon/template.h>

static void _add_template(struct autobuf *out, bool brackets, struct abuf_template_data *data, size_t data_count);
static void _json_printvalue(struct autobuf *out, const char *txt, bool delimiter);

/**
 * Initialize the JSON session object for creating a nested JSON
 * string output.
 * @param session JSON session
 * @param out output buffer
 */
void
json_init_session(struct json_session *session, struct autobuf *out) {
  memset(session, 0, sizeof(*session));
  session->out = out;
  session->empty = true;
}

/**
 * Starts a new JSON array
 * @param session JSON session
 * @param name name of JSON array
 */
void
json_start_array(struct json_session *session, const char *name) {
  if (!session->empty) {
    abuf_puts(session->out, ",");
    session->empty = true;
  }

  abuf_appendf(session->out, "\"%s\": [", name);
}

/**
 * Ends a JSON array, should be paired with corresponding
 * json_start_array call.
 * @param session JSON session
 */
void
json_end_array(struct json_session *session) {
  /* close session */
  session->empty = false;

  abuf_puts(session->out, "]");
}

/**
 * Starts a new JSON object.
 * @param session JSON session
 * @param name name of object, might be NULL
 */
void
json_start_object(struct json_session *session, const char *name) {
  /* open new session */
  if (!session->empty) {
    abuf_puts(session->out, ",");
    session->empty = true;
  }

  if (name) {
    abuf_appendf(session->out, "\"%s\": {", name);
  }
  else {
    abuf_puts(session->out, "{");
  }
}

/**
 * This function prints a key/value pair to the JSON session.
 * @param session json session
 * @param key name of the JSON key
 * @param string true if the value is a string, false otherwise
 * @param value value to print
 */
void
json_print(struct json_session *session, const char *key, bool string, const char *value) {
  if (!session->empty) {
    abuf_puts(session->out, ",");
  }
  session->empty = false;

  if (key) {
    abuf_appendf(session->out, "\"%s\":", key);
  }
  _json_printvalue(session->out, value, string);
}

/**
 * Ends a JSON object, should be paired with corresponding _start_object
 * call.
 * @param session JSON session
 */
void
json_end_object(struct json_session *session) {
  /* close session */
  session->empty = false;

  abuf_puts(session->out, "}");
}

/**
 * Print the context of an array of autobuf templates
 * as a list of JSON key/value pairs.
 * @param session JSON session
 * @param data autobuffer template data array
 * @param count number of elements in data array
 */
void
json_print_templates(struct json_session *session, struct abuf_template_data *data, size_t count) {
  if (session->empty) {
    session->empty = false;
    abuf_puts(session->out, "\n");
  }
  else {
    abuf_puts(session->out, ",\n");
  }

  _add_template(session->out, false, data, count);
}

/**
 * Converts a key/value list for the template engine into
 * JSON compatible output.
 * @param out output buffer
 * @param brackets true to add surrounding brackets and newlines
 * @param data array of template data
 * @param data_count number of template data entries
 */
static void
_add_template(struct autobuf *out, bool brackets, struct abuf_template_data *data, size_t data_count) {
  bool first;
  size_t i, j;

  if (brackets) {
    abuf_puts(out, "{");
  }

  first = true;
  for (i = 0; i < data_count; i++) {
    for (j = 0; j < data[i].count; j++) {
      if (data[i].data[j].value == NULL) {
        continue;
      }

      if (!first) {
        abuf_puts(out, ",\n");
      }
      else {
        first = false;
      }

      abuf_appendf(out, "\"%s\":", data[i].data[j].key);
      _json_printvalue(out, data[i].data[j].value, data[i].data[j].string);
    }

    if (!first && brackets) {
      abuf_puts(out, "\n");
    }
  }

  if (brackets) {
    abuf_puts(out, "}");
  }
}

/**
 * Prints a string to an autobuffer, using JSON escape rules
 * @param out pointer to output buffer
 * @param txt string to print
 * @param delimiter true if string must be enclosed in quotation marks
 */
static void
_json_printvalue(struct autobuf *out, const char *txt, bool delimiter) {
  const char *ptr;
  bool unprintable;

  if (delimiter) {
    abuf_puts(out, "\"");
  }
  else if (*txt == 0) {
    abuf_puts(out, "0");
  }

  ptr = txt;
  while (*ptr) {
    unprintable = !str_char_is_printable(*ptr);
    if (unprintable || *ptr == '\\' || *ptr == '\"') {
      if (ptr != txt) {
        abuf_memcpy(out, txt, ptr - txt);
      }

      if (unprintable) {
        abuf_appendf(out, "\\u00%02x", (unsigned char)(*ptr++));
      }
      else {
        abuf_appendf(out, "\\%c", *ptr++);
      }
      txt = ptr;
    }
    else {
      ptr++;
    }
  }

  abuf_puts(out, txt);
  if (delimiter) {
    abuf_puts(out, "\"");
  }
}
