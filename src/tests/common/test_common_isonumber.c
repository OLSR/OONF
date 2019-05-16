
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

#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <oonf/libcommon/isonumber.h>
#include <oonf/libcommon/string.h>

#include <oonf/cunit/cunit.h>

static void
clear_elements(void) {
}

static void
test_str_from_isonumber_u64(void) {
  static const char *results[3][5] = {
      { "999", "1.023k", "999.999k", "1.023M",  "1.048M" },
      { "1k", "1.024k", "1M", "1.024M", "1.048M" },
      { "1.001k", "1.025k", "1M", "1.024M", "1.048M" }
  };
  static uint64_t tests[] = { 1000, 1024, 1000*1000, 1000*1024, 1024*1024 };
  struct isonumber_str buf;
  uint64_t diff, scaling;
  size_t i;

  const char *tmp;
  bool correct;

  START_TEST();

  for (scaling = 1; scaling <= 64; scaling *= 4) {
    for (diff=0; diff < 3; diff++) {
      for (i=0; i<5; i++) {
        tmp = isonumber_from_u64(&buf, (tests[i]+diff-1)*scaling, NULL, scaling, false);
        correct = tmp != NULL && strcmp(tmp, results[diff][i]) == 0;

        CHECK_TRUE(tmp != NULL, "isonumber_from_u64(%"PRIu64") is not null",
            tests[i]+diff-1);
        CHECK_TRUE(correct, "isonumber_from_u64(%"PRIu64") = %s should be %s",
        		tests[i]+diff-1, tmp, results[diff][i]);
      }
    }
  }

  END_TEST();
}

static void
test_isonumber_to_u64_from_string(void) {
  static const char *tests[] = {
      "1.0", "1k", "1.024k", "1M", "1.024M", "1.023k"
  };
  static uint64_t results[] = { 1, 1000, 1024, 1000*1000, 1000*1024, 1023 };

  size_t i;
  int64_t scaling;
  uint64_t result;
  int tmp;

  START_TEST();

  for (scaling = 1; scaling <= 64; scaling *= 4) {
    for (i=0; i<ARRAYSIZE(tests); i++) {
      result = 0;
      tmp = isonumber_to_u64(&result, tests[i], scaling);
      CHECK_TRUE(tmp == 0, "isonumber_to_u64(\"%s\") failed", tests[i]);
      if (!tmp) {
        CHECK_TRUE(result == results[i]*scaling, "isonumber_to_u64(\"%s\") != %"PRIu64" (was %"PRIu64")",
            tests[i], results[i]*scaling, result);
      }
    }
  }
  END_TEST();
}

static void
test_isonumber_to_s64_from_string(void) {
  static const char *tests[] = {
       "1k",  "1.024k",  "1M",  "1.024M",  "1.023k",
      "-1k", "-1.024k", "-1M", "-1.024M", "-1.023k",
  };
  static int64_t results[] = {
       1000,  1024,  1000*1000,  1000*1024,  1023,
      -1000, -1024, -1000*1000, -1000*1024, -1023,
  };

  size_t i;

  int64_t result;
  int tmp;

  START_TEST();

  for (i=0; i<ARRAYSIZE(tests); i++) {
    result = 0;
    tmp = isonumber_to_s64(&result, tests[i], 1);
    CHECK_TRUE(tmp == 0, "isonumber_to_u64(\"%s\") failed", tests[i]);
    if (!tmp) {
      CHECK_TRUE(result== results[i], "isonumber_to_u64(\"%s\") != %"PRId64" (was %"PRId64")",
          tests[i], results[i], result);
    }
  }
  END_TEST();
}

static void
test_isonumber_to_s64_from_string_2(void) {
  static const char *tests[] = {
       "1m",  "1.024m",  "1u",  "1.024u",  "1.023m",  "1n",
      "-1m", "-1.024m", "-1u", "-1.024u", "-1.023m", "-1n",
  };
  static int64_t results[] = {
       1000000,  1024000,  1000,  1024,  1023000,  1,
      -1000000, -1024000, -1000, -1024, -1023000, -1,
  };

  size_t i;

  int64_t result;
  int tmp;

  START_TEST();

  for (i=0; i<ARRAYSIZE(tests); i++) {
    result = 0;
    tmp = isonumber_to_s64(&result, tests[i], 1000000000);
    CHECK_TRUE(tmp == 0, "isonumber_to_u64(\"%s\") failed", tests[i]);
    if (!tmp) {
      CHECK_TRUE(result== results[i], "isonumber_to_u64(\"%s\") != %"PRId64" (was %"PRId64")",
          tests[i], results[i], result);
    }
  }
  END_TEST();
}


static void
test_str_from_isonumber_s64(void) {
  static const char *results[3][5] = {
      { "-999", "-1.023k", "-999.999k", "-1.023M",  "-1.048M" },
      { "-1k", "-1.024k", "-1M", "-1.024M", "-1.048M" },
      { "-1.001k", "-1.025k", "-1M", "-1.024M", "-1.048M" }
  };
  static int64_t tests[] = { -1000, -1024, -1000*1000, -1000*1024, -1024*1024 };
  struct isonumber_str buf;
  uint64_t diff;
  size_t i;

  const char *tmp;
  bool correct;

  START_TEST();

  for (diff=0; diff < 3; diff++) {
    for (i=0; i<5; i++) {
      tmp = isonumber_from_s64(&buf, tests[i]-diff+1, NULL, 1, false);
      correct = tmp != NULL && strcmp(tmp, results[diff][i]) == 0;

      CHECK_TRUE(tmp != NULL, "str_to_isonumber_s64(%"PRId64") is not null",
          tests[i]-diff+1);
      CHECK_TRUE(correct, "str_to_isonumber_s64(%"PRId64") = %s should be %s",
          tests[i]-diff+1,
      		tmp, results[diff][i]);
    }
  }

  END_TEST();
}

static void
test_str_from_isonumber_s64_2(void) {
  struct isonumber_str buf;
  START_TEST();

  CHECK_TRUE(
      isonumber_from_s64(&buf,
          5185050545986994176ll, "bit/s", 1, false) != NULL, "test");
  END_TEST();
}


int
main(int argc __attribute__ ((unused)), char **argv __attribute__ ((unused))) {
  BEGIN_TESTING(clear_elements);

  test_str_from_isonumber_u64();
  test_isonumber_to_u64_from_string();
  test_str_from_isonumber_s64();
  test_isonumber_to_s64_from_string();
  test_isonumber_to_s64_from_string_2();
  test_str_from_isonumber_s64_2();

  return FINISH_TESTING();
}
