
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

#include <oonf/libcommon/autobuf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/string.h>
#include <oonf/libconfig/cfg_db.h>
#include <oonf/libconfig/cfg_schema.h>

#include <oonf/cunit/cunit.h>

#define SECTION_TYPE_1     "type_1"
#define SECTION_TYPE_2     "type_2"

#define NAME_1           "name_1"
#define NAME_2           "name_2"

#define KEY_1            "key_1"
#define KEY_2            "key_2"
#define KEY_3            "key_3"

static void handler_add_section(void);

static struct cfg_db *db_pre = NULL;
static struct cfg_db *db_post = NULL;
static struct autobuf out;

static struct cfg_schema schema;

static struct cfg_schema_entry entries_1[] = {
  CFG_VALIDATE_STRING(KEY_1, "", "help"),
  CFG_VALIDATE_STRING(KEY_2, "", "help"),
  CFG_VALIDATE_STRING(KEY_3, "", "help"),
};

static struct cfg_schema_section handler_1 = {
  .type = SECTION_TYPE_1, .mode = CFG_SSMODE_NAMED,
  .cb_delta_handler = handler_add_section,
  .entries = entries_1,
  .entry_count = ARRAYSIZE(entries_1),
};

static struct const_strarray value_1 = {
  .value = "value_1",
  .length = sizeof("value_1"),
};

static struct const_strarray value_2 = {
  .value = "value_2",
  .length = sizeof("value_2"),
};

static struct const_strarray value_3 = {
  .value = "value_3",
  .length = sizeof("value_3"),
};

static uint32_t callback_counter;
static bool callback_marker[2];

static void
clear_elements(void) {
  if (db_pre) {
    cfg_db_remove(db_pre);
  }
  db_pre = cfg_db_add();
  cfg_db_link_schema(db_pre, &schema);

  if (db_post) {
    cfg_db_remove(db_post);
  }
  db_post = cfg_db_add();
  cfg_db_link_schema(db_post, &schema);

  abuf_clear(&out);

  callback_counter = 0;
  memset(callback_marker, 0, sizeof(callback_marker));
}

static void
test_delta_add_single_section(void) {
  START_TEST();

  handler_1.cb_delta_handler = handler_add_section;

  cfg_db_add_entry(db_post, SECTION_TYPE_1, NAME_1, KEY_1, value_1.value);
  cfg_db_add_entry(db_post, SECTION_TYPE_1, NAME_1, KEY_2, value_2.value);

  CHECK_TRUE(cfg_schema_handle_db_changes(db_pre, db_post) == 0,
      "delta calculation failed");

  CHECK_TRUE(callback_counter == 1, "Callback counter was called %d times", callback_counter);
  END_TEST();
}

static void
handler_add_section(void) {
  callback_counter++;

  CHECK_TRUE(callback_counter == 1, "Callback was called %d times!", callback_counter);
  if (callback_counter > 1) {
    return;
  }
  CHECK_TRUE(handler_1.pre == NULL, "Unknown pre named-section found.");
  CHECK_TRUE(handler_1.post != NULL, "No post named-section found.");

  if (handler_1.post == NULL) {
    return;
  }

  CHECK_TRUE(handler_1.post->name != NULL && strcmp(handler_1.post->name, NAME_1) == 0,
      "Illegal name of changed section: %s", handler_1.post->name);

  CHECK_TRUE( entries_1[0].delta_changed, "Key 1 did not change!");
  CHECK_TRUE( entries_1[1].delta_changed, "Key 2 did not change!");
  CHECK_TRUE(!entries_1[2].delta_changed, "Key 3 did change!");

  CHECK_TRUE(strarray_cmp_c(entries_1[0].post, &value_1) == 0,
      "Unknown post data for key 1: %s", entries_1[0].post->value);
  CHECK_TRUE(strarray_cmp_c(entries_1[1].post, &value_2) == 0,
      "Unknown post data for key 1: %s", entries_1[1].post->value);
}

static void handler_add_two_sections(void);

static void
test_delta_add_two_sections(void) {
  START_TEST();

  handler_1.cb_delta_handler = handler_add_two_sections;

  cfg_db_add_entry(db_post, SECTION_TYPE_1, NAME_1, KEY_1, value_1.value);
  cfg_db_add_entry(db_post, SECTION_TYPE_1, NAME_1, KEY_2, value_2.value);

  cfg_db_add_entry(db_post, SECTION_TYPE_1, NAME_2, KEY_2, value_2.value);
  cfg_db_add_entry(db_post, SECTION_TYPE_1, NAME_2, KEY_3, value_3.value);

  CHECK_TRUE(cfg_schema_handle_db_changes(db_pre, db_post) == 0,
      "delta calculation failed");

  CHECK_TRUE(callback_counter == 2, "Callback counter was called %d times", callback_counter);
  END_TEST();
}

static void
handler_add_two_sections(void) {
  bool n1, n2;

  CHECK_TRUE(callback_counter < 2, "Callback was called %d times!", callback_counter+1);

  callback_counter++;
  if (callback_counter > 2) {
    return;
  }
  CHECK_TRUE(handler_1.pre == NULL, "Unknown pre named-section found.");
  CHECK_TRUE(handler_1.post != NULL, "No post named-section found.");

  if (handler_1.post == NULL) {
    return;
  }

  n1 = handler_1.post->name != NULL && strcmp(handler_1.post->name, NAME_1) == 0;
  n2 = handler_1.post->name != NULL && strcmp(handler_1.post->name, NAME_2) == 0;
  CHECK_TRUE(n1 || n2, "Illegal name of changed section: %s", handler_1.post->name ? handler_1.post->name : "NULL");

  if (n1) {
    CHECK_TRUE(!callback_marker[0], "section with first name triggered twice");
    callback_marker[0] = true;

    CHECK_TRUE( entries_1[0].delta_changed, "Key 1 did not change!");
    CHECK_TRUE( entries_1[1].delta_changed, "Key 2 did not change!");
    CHECK_TRUE(!entries_1[2].delta_changed, "Key 3 did change!");

    CHECK_TRUE(strarray_cmp_c(entries_1[0].post, &value_1) == 0,
        "Unknown post data for key 1: %s", entries_1[0].post->value);
    CHECK_TRUE(strarray_cmp_c(entries_1[1].post, &value_2) == 0,
        "Unknown post data for key 2: %s", entries_1[1].post->value);
  }
  else if (n2) {
    CHECK_TRUE(!callback_marker[1], "section with second name triggered twice");
    callback_marker[1] = true;

    CHECK_TRUE(!entries_1[0].delta_changed, "Key 1 did change!");
    CHECK_TRUE( entries_1[1].delta_changed, "Key 2 did not change!");
    CHECK_TRUE( entries_1[2].delta_changed, "Key 3 did not change!");

    CHECK_TRUE(strarray_cmp_c(entries_1[1].post, &value_2) == 0,
        "Unknown post data for key 2: %s", entries_1[0].post->value);
    CHECK_TRUE(strarray_cmp_c(entries_1[2].post, &value_3) == 0,
        "Unknown post data for key 3: %s", entries_1[1].post->value);
  }
}

static void handler_remove_section(void);

static void
test_delta_remove_single_section(void) {
  START_TEST();

  handler_1.cb_delta_handler = handler_remove_section;

  cfg_db_add_entry(db_pre, SECTION_TYPE_1, NAME_1, KEY_1, value_1.value);
  cfg_db_add_entry(db_pre, SECTION_TYPE_1, NAME_1, KEY_2, value_2.value);

  CHECK_TRUE(cfg_schema_handle_db_changes(db_pre, db_post) == 0,
      "delta calculation failed");

  CHECK_TRUE(callback_counter == 1, "Callback counter was called %d times", callback_counter);
  END_TEST();
}

static void
handler_remove_section(void) {
  callback_counter++;

  CHECK_TRUE(callback_counter == 1, "Callback was called %d times!", callback_counter);
  if (callback_counter > 1) {
    return;
  }
  CHECK_TRUE(handler_1.pre != NULL, "No pre named-section found.");
  CHECK_TRUE(handler_1.post == NULL, "Unknown post named-section found.");

  if (handler_1.pre == NULL) {
    return;
  }

  CHECK_TRUE(handler_1.pre->name != NULL && strcmp(handler_1.pre->name, NAME_1) == 0,
      "Illegal name of changed section: %s", handler_1.pre->name);

  CHECK_TRUE( entries_1[0].delta_changed, "Key 1 did not change!");
  CHECK_TRUE( entries_1[1].delta_changed, "Key 2 did not change!");
  CHECK_TRUE(!entries_1[2].delta_changed, "Key 3 did change!");

  CHECK_TRUE(strarray_cmp_c(entries_1[0].pre, &value_1) == 0,
      "Unknown pre data for key 1: %s", entries_1[0].pre->value);
  CHECK_TRUE(strarray_cmp_c(entries_1[1].pre, &value_2) == 0,
      "Unknown pre data for key 1: %s", entries_1[1].pre->value);
}

static void handler_remove_two_sections(void);

static void
test_delta_remove_two_sections(void) {
  START_TEST();

  handler_1.cb_delta_handler = handler_remove_two_sections;

  cfg_db_add_entry(db_pre, SECTION_TYPE_1, NAME_1, KEY_1, value_1.value);
  cfg_db_add_entry(db_pre, SECTION_TYPE_1, NAME_1, KEY_2, value_2.value);

  cfg_db_add_entry(db_pre, SECTION_TYPE_1, NAME_2, KEY_2, value_2.value);
  cfg_db_add_entry(db_pre, SECTION_TYPE_1, NAME_2, KEY_3, value_3.value);

  CHECK_TRUE(cfg_schema_handle_db_changes(db_pre, db_post) == 0,
      "delta calculation failed");

  CHECK_TRUE(callback_counter == 2, "Callback counter was called %d times", callback_counter);
  END_TEST();
}

static void
handler_remove_two_sections(void) {
  bool n1, n2;

  CHECK_TRUE(callback_counter < 2, "Callback was called %d times!", callback_counter+1);
  callback_counter++;

  if (callback_counter > 2) {
    return;
  }
  CHECK_TRUE(handler_1.pre != NULL, "No pre named-section found.");
  CHECK_TRUE(handler_1.post == NULL, "Unknown post named-section found.");

  if (handler_1.pre == NULL) {
    return;
  }

  n1 = handler_1.pre->name != NULL && strcmp(handler_1.pre->name, NAME_1) == 0;
  n2 = handler_1.pre->name != NULL && strcmp(handler_1.pre->name, NAME_2) == 0;
  CHECK_TRUE(n1 || n2, "Illegal name of changed section: %s", handler_1.pre->name ? handler_1.pre->name : "NULL");

  if (n1) {
    CHECK_TRUE(!callback_marker[0], "section with first name triggered twice");
    callback_marker[0] = true;

    CHECK_TRUE( entries_1[0].delta_changed, "Key 1 did not change!");
    CHECK_TRUE( entries_1[1].delta_changed, "Key 2 did not change!");
    CHECK_TRUE(!entries_1[2].delta_changed, "Key 3 did change!");

    CHECK_TRUE(strarray_cmp_c(entries_1[0].pre, &value_1) == 0,
        "Unknown pre data for key 1: %s", entries_1[0].pre->value);
    CHECK_TRUE(strarray_cmp_c(entries_1[1].pre, &value_2) == 0,
        "Unknown pre data for key 2: %s", entries_1[1].pre->value);
  }
  else if (n2) {
    CHECK_TRUE(!callback_marker[1], "section with second name triggered twice");
    callback_marker[1] = true;

    CHECK_TRUE(!entries_1[0].delta_changed, "Key 1 did change!");
    CHECK_TRUE( entries_1[1].delta_changed, "Key 2 did not change!");
    CHECK_TRUE( entries_1[2].delta_changed, "Key 3 did not change!");

    CHECK_TRUE(strarray_cmp_c(entries_1[1].pre, &value_2) == 0,
        "Unknown pre data for key 2: %s", entries_1[0].pre->value);
    CHECK_TRUE(strarray_cmp_c(entries_1[2].pre, &value_3) == 0,
        "Unknown pre data for key 3: %s", entries_1[1].pre->value);
  }
}

static void handler_modify_section(void);

static void
test_delta_modify_single_section(void) {
  START_TEST();

  handler_1.cb_delta_handler = handler_modify_section;

  cfg_db_add_entry(db_pre, SECTION_TYPE_1, NAME_1, KEY_1, value_2.value);
  cfg_db_add_entry(db_pre, SECTION_TYPE_1, NAME_1, KEY_2, value_3.value);

  cfg_db_add_entry(db_post, SECTION_TYPE_1, NAME_1, KEY_1, value_1.value);
  cfg_db_add_entry(db_post, SECTION_TYPE_1, NAME_1, KEY_2, value_2.value);

  CHECK_TRUE(cfg_schema_handle_db_changes(db_pre, db_post) == 0,
      "delta calculation failed");

  CHECK_TRUE(callback_counter == 1, "Callback counter was called %d times", callback_counter);
  END_TEST();
}

static void
handler_modify_section(void) {
  callback_counter++;

  CHECK_TRUE(callback_counter == 1, "Callback was called %d times!", callback_counter);
  if (callback_counter > 1) {
    return;
  }
  CHECK_TRUE(handler_1.pre != NULL, "No pre named-section found.");
  CHECK_TRUE(handler_1.post != NULL, "No post named-section found.");

  if (handler_1.post == NULL || handler_1.pre == NULL) {
    return;
  }

  CHECK_TRUE(handler_1.pre->name != NULL && strcmp(handler_1.pre->name, NAME_1) == 0,
      "Illegal name of changed pre section: %s", handler_1.pre->name);

  CHECK_TRUE(handler_1.post->name != NULL && strcmp(handler_1.post->name, NAME_1) == 0,
      "Illegal name of changed post section: %s", handler_1.post->name);

  CHECK_TRUE( entries_1[0].delta_changed, "Key 1 did not change!");
  CHECK_TRUE( entries_1[1].delta_changed, "Key 2 did not change!");
  CHECK_TRUE(!entries_1[2].delta_changed, "Key 3 did change!");

  CHECK_TRUE(strarray_cmp_c(entries_1[0].pre, &value_2) == 0,
      "Unknown pre data for key 1: %s", entries_1[0].pre->value);
  CHECK_TRUE(strarray_cmp_c(entries_1[1].pre, &value_3) == 0,
      "Unknown pre data for key 1: %s", entries_1[1].pre->value);

  CHECK_TRUE(strarray_cmp_c(entries_1[0].post, &value_1) == 0,
      "Unknown post data for key 1: %s", entries_1[0].post->value);
  CHECK_TRUE(strarray_cmp_c(entries_1[1].post, &value_2) == 0,
      "Unknown post data for key 1: %s", entries_1[1].post->value);
}

static void handler_modify_two_sections(void);

static void
test_delta_modify_two_sections(void) {
  START_TEST();

  handler_1.cb_delta_handler = handler_modify_two_sections;

  cfg_db_add_entry(db_pre, SECTION_TYPE_1, NAME_1, KEY_1, value_1.value);
  cfg_db_add_entry(db_pre, SECTION_TYPE_1, NAME_1, KEY_2, value_2.value);

  cfg_db_add_entry(db_pre, SECTION_TYPE_1, NAME_2, KEY_2, value_2.value);
  cfg_db_add_entry(db_pre, SECTION_TYPE_1, NAME_2, KEY_3, value_3.value);

  cfg_db_add_entry(db_post, SECTION_TYPE_1, NAME_1, KEY_1, value_2.value);
  cfg_db_add_entry(db_post, SECTION_TYPE_1, NAME_1, KEY_2, value_3.value);

  cfg_db_add_entry(db_post, SECTION_TYPE_1, NAME_2, KEY_2, value_1.value);
  cfg_db_add_entry(db_post, SECTION_TYPE_1, NAME_2, KEY_3, value_2.value);

  CHECK_TRUE(cfg_schema_handle_db_changes(db_pre, db_post) == 0,
      "delta calculation failed");

  CHECK_TRUE(callback_counter == 2, "Callback counter was called %d times", callback_counter);
  END_TEST();
}

static void
handler_modify_two_sections(void) {
  bool n1, n2;

  CHECK_TRUE(callback_counter < 2, "Callback was called %d times!", callback_counter+1);
  callback_counter++;

  if (callback_counter > 2) {
    return;
  }
  CHECK_TRUE(handler_1.pre != NULL, "No pre named-section found.");
  CHECK_TRUE(handler_1.post != NULL, "No post named-section found.");

  if (handler_1.pre == NULL || handler_1.post == NULL) {
    return;
  }

  n1 = handler_1.pre->name != NULL && strcmp(handler_1.pre->name, NAME_1) == 0
      && handler_1.post->name != NULL && strcmp(handler_1.post->name, NAME_1) == 0;
  n2 = handler_1.pre->name != NULL && strcmp(handler_1.pre->name, NAME_2) == 0
      && handler_1.post->name != NULL && strcmp(handler_1.post->name, NAME_2) == 0;
  CHECK_TRUE(n1 || n2, "Illegal name of changed section: %s %s", handler_1.pre->name, handler_1.post->name);

  if (n1) {
    CHECK_TRUE(!callback_marker[0], "section with first name triggered twice");
    callback_marker[0] = true;

    CHECK_TRUE( entries_1[0].delta_changed, "Key 1 did not change!");
    CHECK_TRUE( entries_1[1].delta_changed, "Key 2 did not change!");
    CHECK_TRUE(!entries_1[2].delta_changed, "Key 3 did change!");

    CHECK_TRUE(strarray_cmp_c(entries_1[0].pre, &value_1) == 0,
        "Unknown pre data for key 1: %s", entries_1[0].pre->value);
    CHECK_TRUE(strarray_cmp_c(entries_1[1].pre, &value_2) == 0,
        "Unknown pre data for key 2: %s", entries_1[1].pre->value);

    CHECK_TRUE(strarray_cmp_c(entries_1[0].post, &value_2) == 0,
        "Unknown post data for key 1: %s", entries_1[0].post->value);
    CHECK_TRUE(strarray_cmp_c(entries_1[1].post, &value_3) == 0,
        "Unknown post data for key 2: %s", entries_1[1].post->value);
  }
  else if (n2) {
    CHECK_TRUE(!callback_marker[1], "section with second name triggered twice");
    callback_marker[1] = true;

    CHECK_TRUE(!entries_1[0].delta_changed, "Key 1 did change!");
    CHECK_TRUE( entries_1[1].delta_changed, "Key 2 did not change!");
    CHECK_TRUE( entries_1[2].delta_changed, "Key 3 did not change!");

    CHECK_TRUE(strarray_cmp_c(entries_1[1].pre, &value_2) == 0,
        "Unknown pre data for key 2: %s", entries_1[0].pre->value);
    CHECK_TRUE(strarray_cmp_c(entries_1[2].pre, &value_3) == 0,
        "Unknown pre data for key 3: %s", entries_1[1].pre->value);

    CHECK_TRUE(strarray_cmp_c(entries_1[1].post, &value_1) == 0,
        "Unknown post data for key 2: %s", entries_1[0].post->value);
    CHECK_TRUE(strarray_cmp_c(entries_1[2].post, &value_2) == 0,
        "Unknown post data for key 3: %s", entries_1[1].post->value);
  }
}

int
main(int argc __attribute__ ((unused)), char **argv __attribute__ ((unused))) {
  cfg_schema_add(&schema);
  cfg_schema_add_section(&schema, &handler_1);

  abuf_init(&out);
  BEGIN_TESTING(clear_elements);

  test_delta_add_single_section();
  test_delta_add_two_sections();
  test_delta_remove_single_section();
  test_delta_remove_two_sections();
  test_delta_modify_single_section();
  test_delta_modify_two_sections();

  abuf_free(&out);
  if (db_post) {
    cfg_db_remove(db_post);
  }
  if (db_pre) {
    cfg_db_remove(db_pre);
  }

  return FINISH_TESTING();
}
