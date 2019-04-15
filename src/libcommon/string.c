
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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oonf/libcommon/string.h>

static int8_t _hexchar_to_value(char hexchar);
/**
 * @param size minimum size of block
 * @return rounded up block size of STRARRAY_BLOCKSIZE
 */
static INLINE size_t
STRARRAY_MEMSIZE(const size_t size) {
  return (size + STRARRAY_BLOCKSIZE - 1) & (~(STRARRAY_BLOCKSIZE - 1));
}

/**
 * A safer version of strncpy that ensures that the
 * destination string will be null-terminated if its
 * length is greater than 0.
 * @param dest target string buffer
 * @param src source string buffer
 * @param size size of target buffer
 * @return pointer to target buffer
 */
char *
strscpy(char *dest, const char *src, size_t size) {
  if (dest == NULL || src == NULL || size == 0) {
    return dest;
  }

  /* src does not need to be null terminated */
  strncpy(dest, src, size - 1);
  dest[size - 1] = 0;

  return dest;
}

/**
 * A safer version of strncat that ensures that
 * the target buffer will be null-terminated if
 * its size is greater than zero.
 *
 * If the target buffer is already full, it will
 * not be changed.
 * @param dest target string buffer
 * @param src source string buffer
 * @param size size of target buffer
 * @return pointer to target buffer
 */
char *
strscat(char *dest, const char *src, size_t size) {
  size_t l;

  if (dest == NULL || src == NULL || size == 0 || *src == 0) {
    return dest;
  }

  l = strlen(dest);
  if (l < size) {
    strscpy(dest + l, src, size - l);
  }
  return dest;
}

/**
 * Removes leading and trailing whitespaces from a string.
 * @param ptr input string to be modified string-pointer
 * @return pointer to first non-whitespace character in string
 */
char *
str_trim(char *ptr) {
  size_t len;

  if (!ptr) {
    return NULL;
  }

  /* skip leading whitespaces */
  while (isspace(*ptr)) {
    ptr++;
  }

  /* get end of string */
  len = strlen(ptr);
  if (len) {
    /* remove trailing whitespaces */
    while (--len > 0 && isspace(ptr[len])) {
      ptr[len] = 0;
    }
  }
  return ptr;
}

/**
 * Check if a string starts with a certain word. The function
 * is not case sensitive and does NOT modify the input strings.
 * @param buffer pointer to string
 * @param word pointer to the word
 * @return pointer to the string behind the word, NULL if no match
 */
const char *
str_hasnextword(const char *buffer, const char *word) {
  /* sanity check */
  if (buffer == NULL) {
    return NULL;
  }

  /* skip whitespace prefix */
  while (isblank(*buffer)) {
    buffer++;
  }

  while (*word != 0 && *buffer != 0 && !isblank(*buffer) && tolower(*word) == tolower(*buffer)) {
    word++;
    buffer++;
  }

  /* complete match ? */
  if (*word == 0 && (*buffer == 0 || isblank(*buffer))) {
    while (isblank(*buffer)) {
      buffer++;
    }
    return buffer;
  }
  return NULL;
}

/**
 * Copies the next word of a constant stringbuffer into
 * a second buffer.
 * @param dst pointer to target buffer
 * @param src constant source buffer
 * @param len maximum length of copied data
 * @return pointer to next word behind the copied word
 */
const char *
str_cpynextword(char *dst, const char *src, size_t len) {
  size_t i;

  /* sanity check */
  if (src == NULL) {
    *dst = 0;
    return NULL;
  }

  /* skip whitespace prefix */
  while (isblank(*src)) {
    src++;
  }

  /* copy next word */
  i = 0;
  while (*src != 0 && !isblank(*src) && i < len - 1) {
    dst[i++] = *src++;
  }

  /* terminate */
  dst[i] = 0;

  /* skip ahead in src */
  while (isblank(*src)) {
    src++;
  }

  if (*src) {
    /* return next word */
    return src;
  }

  /* end of src */
  return NULL;
}

/**
 * Skips the next word of a constant stringbuffer.
 * @param src constant source buffer
 * @return pointer to next word behind the skipped word
 */
const char *
str_skipnextword(const char *src) {
  /* sanity check */
  if (src == NULL) {
    return NULL;
  }

  /* skip whitespace prefix */
  while (isblank(*src)) {
    src++;
  }

  /* copy next word */
  while (*src != 0 && !isblank(*src)) {
    src++;
  }

  /* skip ahead in src */
  while (isblank(*src)) {
    src++;
  }

  if (*src) {
    /* return next word */
    return src;
  }

  /* end of src */
  return NULL;
}

/**
 * @param src pointer to source string
 * @return number of non-whitespace words separated by whitespaces in string
 */
size_t
str_countwords(const char *src) {
  size_t count = 0;

  /* sanity check */
  if (src != NULL) {
    /* skip whitespace prefix */
    while (isblank(*src)) {
      src++;
    }

    while (src != NULL && *src != 0) {
      count++;

      src = str_skipnextword(src);
    }
  }
  return count;
}

/**
 * Printable is defined as all ascii characters >= 32 except
 * 127 and 255.
 * @param value stringpointer
 * @return true if string only contains printable characters,
 *   false otherwise
 */
bool
str_is_printable(const char *value) {
  const unsigned char *_value;

  _value = (const unsigned char *)value;

  while (*_value) {
    if (!str_char_is_printable(*_value)) {
      return false;
    }
    _value++;
  }
  return true;
}

/**
 * Converts a binary array to a zero terminated hexadecimal text
 * @param buffer target buffer
 * @param buffer_len length of target buffer
 * @param src binary source
 * @param src_len length of binary source
 * @return -1 if an error happened, length of string (without zero byte) otherwise
 */
ssize_t
strhex_from_bin(char *buffer, size_t buffer_len, const uint8_t *src, size_t src_len) {
  static char HEX[] = "0123456789abcdef";
  size_t i, j;
  if (buffer_len < src_len*2+1) {
    return -1;
  }

  for (i=0, j=0; i<src_len; i++) {
    buffer[j++] = HEX[src[i] >> 4];
    buffer[j++] = HEX[src[i] & 0x0f];
  }
  buffer[j] = 0;
  return j;
}

/**
 * Converts a hexadecimal text without any whitespaces to a binary representation
 * @param buffer target binary buffer
 * @param buffer_len length of binary buffer
 * @param src hexadecimal text input
 * @return -1 if an error happened, length of binary buffer otherwise
 */
ssize_t
strhex_to_bin(uint8_t *buffer, size_t buffer_len, const char *src) {
  size_t srclen, i, j;
  int8_t v1, v2;
  srclen = strlen(src);
  if ((srclen & 1) != 0 || buffer_len < srclen/2) {
    return -1;
  }

  for (i=0, j=0; i<srclen; j++) {
    v1 = _hexchar_to_value(src[i++]);
    v2 = _hexchar_to_value(src[i++]);

    if (v1 < 0 || v2 < 0) {
      return -1;
    }
    buffer[j] = (v1 << 4) | v2;
  }
  return j;
}

/**
 * Copy a string array into another array. This overwrites
 * all data in the original array.
 * @param dst destination array
 * @param src source array
 * @return 0 if array was copied, -1 if an error happened
 */
int
strarray_copy(struct strarray *dst, const struct strarray *src) {
  char *ptr;
  size_t block;
  if (src->value == NULL || src->length == 0) {
    memset(dst, 0, sizeof(*dst));
    return 0;
  }

  block = STRARRAY_MEMSIZE(src->length);
  ptr = realloc(dst->value, block);
  if (!ptr) {
    return -1;
  }

  memcpy(ptr, src->value, src->length);
  memset(ptr + src->length, 0, block - src->length);
  dst->length = src->length;
  dst->value = ptr;
  return 0;
}

/**
 * Appends a string to an existing string array. Only use this
 * if the string-array value has been allocated with malloc/calloc.
 * @param array pointer to string array object
 * @param string pointer to string to append
 * @return 0 if string was appended, -1 if an error happened
 */
int
strarray_append(struct strarray *array, const char *string) {
  size_t length, new_length;
  char *ptr;

  length = strlen(string) + 1;

  new_length = array->length + length;
  ptr = realloc(array->value, STRARRAY_MEMSIZE(new_length));
  if (ptr == NULL) {
    return -1;
  }

  memcpy(ptr + array->length, string, length);
  array->value = ptr;
  array->length = new_length;
  return 0;
}

/**
 * Put a string to in front of an existing string array. Only use this
 * if the string-array value has been allocated with malloc/calloc.
 * @param array pointer to string array object
 * @param string pointer to string to append
 * @return 0 if string was appended, -1 if an error happened
 */
int
strarray_prepend(struct strarray *array, const char *string) {
  size_t length, new_length;
  char *ptr;

  length = strlen(string) + 1;

  new_length = array->length + length;
  ptr = realloc(array->value, STRARRAY_MEMSIZE(new_length));
  if (ptr == NULL) {
    return -1;
  }

  memmove(ptr + length, ptr, array->length);
  memcpy(ptr, string, length);
  array->value = ptr;
  array->length = new_length;
  return 0;
}

/**
 * Remove an element from a string array
 * @param array pointer to string array object
 * @param element an element to be removed from the array
 * @param resize array afterwards
 */
void
strarray_remove_ext(struct strarray *array, char *element, bool resize) {
  char *ptr1;
  size_t len;

  /* get length of element to remove */
  len = strlen(element) + 1;
  if (len == array->length) {
    strarray_free(array);
    return;
  }

  /* adjust length */
  array->length -= len;

  /* remove element from memory */
  if (element <= array->value + array->length) {
    memmove(element, element + len, array->length - (element - array->value));
  }

  if (!resize) {
    return;
  }

  /* adjust memory block */
  ptr1 = realloc(array->value, STRARRAY_MEMSIZE(array->length));
  if (ptr1 == NULL) {
    /* just keep the current memory block */
    return;
  }

  /* adjust value pointer to new memory block */
  array->value = ptr1;
}

/**
 * @param array pointer to strarray object
 * @return number of strings in string array
 */
size_t
strarray_get_count(const struct strarray *array) {
  size_t count = 0;
  char *ptr;

  strarray_for_each_element(array, ptr) {
    count++;
  }
  return count;
}

/**
 * @param array pointer to strarray object
 * @param idx position of the requested object inside the array
 * @return string at the specified index, NULL if not found
 */
char *
strarray_get(const struct strarray *array, size_t idx) {
  size_t count = 0;
  char *ptr;

  strarray_for_each_element(array, ptr) {
    if (count == idx) {
      return ptr;
    }
    count++;
  }
  return NULL;
}

/**
 * Compare to stringarrays
 * @param a1 pointer to array 1
 * @param a2 pointer to array 2
 * @return <0 if a1 is 'smaller' than a2, >0 if a1 is 'larger' than a2,
 *   0 if both are the same.
 */
int
strarray_cmp(const struct strarray *a1, const struct strarray *a2) {
  int result;
  size_t min_len;

  if (a1 == NULL || a1->value == NULL) {
    return (a2 == NULL || a2->value == NULL) ? 0 : -1;
  }
  if (a2 == NULL || a2->value == NULL) {
    return 1;
  }

  if (a1->length > a2->length) {
    min_len = a2->length;
  }
  else {
    min_len = a1->length;
  }

  result = memcmp(a1->value, a2->value, min_len);
  if (result == 0) {
    if (a1->length > a2->length) {
      return 1;
    }
    if (a1->length < a2->length) {
      return -1;
    }
  }
  return result;
}

/**
* convert a hexadecimal character (0-9, a-f, A-F) to its decimal value
* @param hexchar hexadecimal character
* @return decimal value, -1 if not hexadecimal
*/
static int8_t
_hexchar_to_value(char hexchar) {
  static char HEX[] = "0123456789abcdefABCDEF";
  const char *ptr;
  int8_t value;

  ptr = strchr(HEX, hexchar);
  if (!ptr) {
    return -1;
  }

  value = ptr - HEX;
  if (value >= 16) {
    value -= 6;
  }
  return value;
}
