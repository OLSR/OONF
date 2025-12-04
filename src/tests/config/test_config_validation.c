
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

#define CFG_SEC "sec"
#define CFG_SECNAME "secname"

const char *choices[] = {
  "choice1", "choice2", "choice3"
};

static struct cfg_db *db = NULL;
static struct autobuf out;

static struct cfg_schema schema;

static struct cfg_schema_entry entries[] = {
  CFG_VALIDATE_STRING_LEN("stringarray", "", "help", 5),
  CFG_VALIDATE_PRINTABLE("printable", "", "help"),
  CFG_VALIDATE_PRINTABLE_LEN("printable_array", "", "help", 5),
  CFG_VALIDATE_CHOICE("choice", "choice1", "help", choices),
  CFG_VALIDATE_INT32("int", "1", "help", 0, false),
  CFG_VALIDATE_INT32_MINMAX("int_minmax", "1", "help", 0, false, -10, 10),
  CFG_VALIDATE_INT32("fractional", "1", "help", 4, false),
  CFG_VALIDATE_INT32_MINMAX("fractional_minmax", "1", "help", 4, false, -100000, 100000),
  CFG_VALIDATE_NETADDR("netaddr", "10.0.0.1", "help", false, false),
  CFG_VALIDATE_NETADDR_HWADDR("mac", "10:aa:00:bb:00:cc", "help", false, false),
  CFG_VALIDATE_NETADDR_MAC48("mac48", "11:bb:cc:dd:ee:ff", "help", false, false),
  CFG_VALIDATE_NETADDR_EUI64("eui64", "00-11-22-33-44-55-66-77", "help", false, false),
  CFG_VALIDATE_NETADDR_V4("ipv4", "10.0.0.2", "help", false, false),
  CFG_VALIDATE_NETADDR_V6("ipv6", "10::1", "help", false, false),
  CFG_VALIDATE_NETADDR_V46("ipv46", "11::0", "help", false, false),
  CFG_VALIDATE_NETADDR("p_netaddr", "10.0.0.0/24", "help", true, false),
  CFG_VALIDATE_NETADDR_HWADDR("p_mac", "10:aa:00:bb:00:cc/24", "help", true, false),
  CFG_VALIDATE_NETADDR_MAC48("p_mac48", "11:bb:cc:dd:ee:ff/24", "help", true, false),
  CFG_VALIDATE_NETADDR_EUI64("p_eui64", "00-11-22-33-44-55-66-77/32", "help", true, false),
  CFG_VALIDATE_NETADDR_V4("p_ipv4", "10.0.0.0/8", "help", true, false),
  CFG_VALIDATE_NETADDR_V6("p_ipv6", "10::1/64", "help", true, false),
  CFG_VALIDATE_NETADDR_V46("p_ipv46", "11::0/32", "help", true, false),
};

static struct cfg_schema_section section = {
  .type = CFG_SEC, .mode = CFG_SSMODE_NAMED,
  .entries = entries,
  .entry_count = ARRAYSIZE(entries),
};

static struct cfg_schema_entry entries2[] = {
  CFG_VALIDATE_INT32_MINMAX("stringarray", "", "help", 0, false, 1, 1000000000),
};

static struct cfg_schema_section section2 = {
  .type = CFG_SEC, .mode = CFG_SSMODE_NAMED,
  .entries = entries2,
  .entry_count = ARRAYSIZE(entries2),
};

static void
clear_elements(void) {
  if (db) {
    cfg_db_remove(db);
  }

  db = cfg_db_add();
  cfg_db_link_schema(db, &schema);
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "stringarray", "abc");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "printable", "printme");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "printable_array", "print");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "choice", "choice2");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "int", "42");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "int_minmax", "-5");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "fractional", "3.1415");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "fractional_minmax", "-3.1415");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "netaddr", "10::1");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "mac", "00:11:22:33:4:5");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "mac48", "a:b:c:d:e:f");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "eui64", "1-2-3-4-5-6-7-8");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "ipv4", "192.168.0.1");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "ipv6", "aa::bb");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "ipv46", "10.0.0.1");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "p_netaddr", "10::1/127");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "p_mac", "00:11:22:33:4:5/12");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "p_mac48", "a:b:c:d:e:f/7");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "p_eui64", "1-2-3-4-5-6-7-8/54");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "p_ipv4", "192.168.0.1/9");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "p_ipv6", "aa::bb/31");
  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "p_ipv46", "10.0.0.1/17");

  abuf_clear(&out);
}

static void
test_validate_success(void) {
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));
  END_TEST();
}

static void
test_validate_stringarray_miss(void) {
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "stringarray", "12345678");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, NULL),
      "validation missed too long string value");
  END_TEST();
}

static void
test_validate_printable_miss(void) {
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "printable", "1234\n5678");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, NULL),
      "validation missed non-printable character");
  END_TEST();
}

static void
test_validate_printable_array_miss(void) {
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "printable_array", "1\n2");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, NULL),
      "validation missed non-printable character");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "printable_array", "12345678");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, NULL),
      "validation missed too long value");

  END_TEST();
}

static void
test_validate_choice_miss(void) {
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "choice", "choice42");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, NULL),
      "validation missed bad choice");

  END_TEST();
}

static void
test_validate_int_miss(void) {
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "int", "b");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, NULL),
      "validation missed bad integer");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "int", "1b");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, NULL),
      "validation missed bad integer");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "int", "1 b");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, NULL),
      "validation missed bad integer");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "int", "0");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, NULL),
      "validation had a false positive");

  END_TEST();
}

static void
test_validate_int_minmax_miss(void) {
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "int_minmax", "11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed int out of range");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "int_minmax", "10");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive (border case)");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "int_minmax", "9");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive inside valid interval");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "int_minmax", "-11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed int out of range");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "int_minmax", "-10");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive (border case)");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "int_minmax", "-9");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive inside valid interval");

  END_TEST();
}

static void
test_validate_fractional_miss(void) {
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "fractional", "b");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, NULL),
      "validation missed bad integer");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "fractional", "3..4");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, NULL),
      "validation missed bad integer");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "fractional", "3.4.5");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, NULL),
      "validation missed bad integer");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "fractional", "0");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, NULL),
      "validation had a false positive");

  END_TEST();
}

static void
test_validate_fractional_minmax_miss(void) {
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "fractional_minmax", "10.0001");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed int out of range");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "fractional_minmax", "10.0000");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive (border case)");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "fractional_minmax", "9.9999");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive inside valid interval");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "fractional_minmax", "-10.0001");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed int out of range");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "fractional_minmax", "-10.0000");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive (border case)");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, "fractional_minmax", "-9.9999");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive inside valid interval");

  END_TEST();
}

static void
test_validate_netaddr_miss(void) {
  const char *key = "netaddr";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6 prefix");

  END_TEST();
}

static void
test_validate_netaddr_mac_miss(void) {
  const char *key = "mac";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6 prefix");

  END_TEST();
}

static void
test_validate_netaddr_mac48_miss(void) {
  const char *key = "mac48";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6 prefix");

  END_TEST();
}

static void
test_validate_netaddr_eui64_miss(void) {
  const char *key = "eui64";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6 prefix");

  END_TEST();
}

static void
test_validate_netaddr_ipv4_miss(void) {
  const char *key = "ipv4";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6 prefix");

  END_TEST();
}

static void
test_validate_netaddr_ipv6_miss(void) {
  const char *key = "ipv6";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6 prefix");

  END_TEST();
}

static void
test_validate_netaddr_ipv46_miss(void) {
  const char *key = "ipv46";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6 prefix");

  END_TEST();
}


static void
test_validate_netaddr_prefix_miss(void) {
  const char *key = "p_netaddr";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv6 prefix");

  END_TEST();
}

static void
test_validate_netaddr_mac_prefix_miss(void) {
  const char *key = "p_mac";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6 prefix");

  END_TEST();
}

static void
test_validate_netaddr_mac48_prefix_miss(void) {
  const char *key = "p_mac48";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6 prefix");

  END_TEST();
}

static void
test_validate_netaddr_eui64_prefix_miss(void) {
  const char *key = "p_eui64";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6 prefix");

  END_TEST();
}

static void
test_validate_netaddr_ipv4_prefix_miss(void) {
  const char *key = "p_ipv4";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6 prefix");

  END_TEST();
}

static void
test_validate_netaddr_ipv6_prefix_miss(void) {
  const char *key = "p_ipv6";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv6 prefix");

  END_TEST();
}

static void
test_validate_netaddr_ipv46_prefix_miss(void) {
  const char *key = "p_ipv46";
  START_TEST();

  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "%s", abuf_getptr(&out));

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "xxxxxxx");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad address");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv4");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv6");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10:00:00:00:00:00/10");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad mac48 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "11-22-33-44-55-66-77-88/11");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad eui64 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10.0.0.1/12");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv4 prefix");

  cfg_db_add_entry(db, CFG_SEC, CFG_SECNAME, key, "10::1/13");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with ipv6 prefix");

  END_TEST();
}

static void
test_validate_double_schema(void) {
  START_TEST();
  cfg_schema_add_section(&schema, &section2);

  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "stringarray", "123");
  CHECK_TRUE(0 == cfg_schema_validate(db, false, false, &out),
      "validation had false positive with double schema");

  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "stringarray", "123456");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad double schema");

  cfg_db_overwrite_entry(db, CFG_SEC, CFG_SECNAME, "stringarray", "abc");
  CHECK_TRUE(0 != cfg_schema_validate(db, false, false, &out),
      "validation missed with bad double schema");

  cfg_schema_remove_section(&schema, &section2);
  END_TEST();
}

int
main(int argc __attribute__ ((unused)), char **argv __attribute__ ((unused))) {
  cfg_schema_add(&schema);
  cfg_schema_add_section(&schema, &section);

  abuf_init(&out);
  BEGIN_TESTING(clear_elements);

  test_validate_success();
  test_validate_stringarray_miss();
  test_validate_printable_miss();
  test_validate_printable_array_miss();
  test_validate_choice_miss();
  test_validate_int_miss();
  test_validate_int_minmax_miss();
  test_validate_fractional_miss();
  test_validate_fractional_minmax_miss();
  test_validate_netaddr_miss();
  test_validate_netaddr_mac_miss();
  test_validate_netaddr_mac48_miss();
  test_validate_netaddr_eui64_miss();
  test_validate_netaddr_ipv4_miss();
  test_validate_netaddr_ipv6_miss();
  test_validate_netaddr_ipv46_miss();
  test_validate_netaddr_prefix_miss();
  test_validate_netaddr_mac_prefix_miss();
  test_validate_netaddr_mac48_prefix_miss();
  test_validate_netaddr_eui64_prefix_miss();
  test_validate_netaddr_ipv4_prefix_miss();
  test_validate_netaddr_ipv6_prefix_miss();
  test_validate_netaddr_ipv46_prefix_miss();

  test_validate_double_schema();

  abuf_free(&out);
  if (db) {
    cfg_db_remove(db);
  }
  cfg_schema_remove_section(&schema, &section);

  return FINISH_TESTING();
}
