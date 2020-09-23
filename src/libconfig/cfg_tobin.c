/*
 * cfg_tobin.c
 *
 *  Created on: 05.10.2017
 *      Author: rogge
 */

#include <errno.h>

#include <oonf/libcommon/bitmap256.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/isonumber.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/libcommon/string.h>

#include <oonf/libconfig/cfg.h>
#include <oonf/libconfig/cfg_tobin.h>

/**
 * Binary converter for string pointers. It will
 * allocate additional memory for the string.
 * See CFG_MAP_STRING() and CFG_MAP_STRING_LEN() macro
 * in cfg_schema.h
 * @param reference pointer to binary output buffer.
 * @param bin_size size of reference memory
 * @param value pointer to value of configuration entry.
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_tobin_strptr(void *reference, size_t bin_size, const struct const_strarray *value) {
  char **ptr;

  if (bin_size != sizeof(*ptr)) {
    return -1;
  }

  ptr = (char **)reference;
  if (*ptr) {
    free(*ptr);
  }

  *ptr = strdup(strarray_get_first_c(value));
  return *ptr == NULL ? -1 : 0;
}

/**
 * Binary converter for string arrays.
 * See CFG_MAP_STRING_ARRAY() macro in cfg_schema.h
 * @param reference pointer to binary output buffer.
 * @param bin_size size of reference memory
 * @param value pointer to value of configuration entry.
 * @param array_size size of the target array
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_tobin_strarray(void *reference, size_t bin_size, const struct const_strarray *value, size_t array_size) {
  char *ptr;

  if (bin_size < array_size) {
    return -1;
  }

  ptr = (char *)reference;

  strscpy(ptr, strarray_get_first_c(value), array_size);
  return 0;
}

/**
 * Binary converter for integers chosen as an index in a predefined
 * string list.
 * See CFG_MAP_CHOICE() macro in cfg_schema.h
 * @param reference pointer to binary output buffer.
 * @param bin_size size of reference memory
 * @param value pointer to value of configuration entry.
 * @param callback callback function providing choices for conversion
 * @param choices_count number of strings in list
 * @param ptr customization pointer for callback
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_tobin_choice(void *reference, size_t bin_size, const struct const_strarray *value,
  const char *(*callback)(size_t idx, const void *ptr), size_t choices_count, const void *ptr) {
  int *result;

  if (bin_size != sizeof(int)) {
    return -1;
  }

  result = (int *)reference;

  *result = cfg_get_choice_index(strarray_get_first_c(value), callback, choices_count, ptr);
  return 0;
}

/**
 * Binary converter for integers.
 * See CFG_VALIDATE_INT*() macro in cfg_schema.h
 * @param reference pointer to binary output buffer.
 * @param bin_size size of reference memory
 * @param value pointer to value of configuration entry.
 * @param fraction number of fractional digits
 * @param int_size size of signed integer to read
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_tobin_int(void *reference, size_t bin_size, const struct const_strarray *value, uint16_t fraction, size_t int_size) {
  int64_t i;
  int result;
  uint64_t j, scaling;

  if (bin_size != int_size) {
    return -1;
  }

  for (j = 0, scaling = 1; j < fraction; j++, scaling*=10);

  result = isonumber_to_s64(&i, strarray_get_first_c(value), NULL, scaling);
  if (result == 0) {
    switch (int_size) {
      case 4:
        *((int32_t *)reference) = i;
        break;
      case 8:
        *((int64_t *)reference) = i;
        break;
      default:
        return -1;
    }
  }
  return result;
}

/**
 * Binary converter for netaddr objects.
 * See CFG_MAP_NETADDR*() macros in cfg_schema.h
 * @param reference pointer to binary output buffer.
 * @param bin_size size of reference memory
 * @param value pointer to value of configuration entry.
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_tobin_netaddr(void *reference, size_t bin_size, const struct const_strarray *value) {
  struct netaddr *ptr;

  if (bin_size != sizeof(*ptr)) {
    return -1;
  }

  ptr = (struct netaddr *)reference;

  return netaddr_from_string(ptr, strarray_get_first_c(value));
}

/**
 * Schema entry binary converter for ACL entries.
 * See CFG_MAP_ACL_*() macros.
 * @param reference pointer to binary output buffer.
 * @param bin_size size of reference memory
 * @param value pointer to value of configuration entry.
 * @return -1 if an error happened, 0 otherwise
 */
int
cfg_tobin_acl(void *reference, size_t bin_size, const struct const_strarray *value) {
  struct netaddr_acl *ptr;

  if (bin_size != sizeof(*ptr)) {
    return -1;
  }

  ptr = (struct netaddr_acl *)reference;
  netaddr_acl_remove(ptr);

  return netaddr_acl_from_strarray(ptr, value);
}

/**
 * Schema entry binary converter for bitmap256 entries.
 * See CFG_MAP_BITMAP256() macros.
 * @param reference pointer to binary output buffer.
 * @param bin_size size of reference memory
 * @param value pointer to value of configuration entry.
 * @return -1 if an error happened, 0 otherwise
 */
int
cfg_tobin_bitmap256(void *reference, size_t bin_size, const struct const_strarray *value) {
  struct bitmap256 *bitmap;
  const char *ptr;
  int idx;

  if (bin_size != sizeof(*bitmap)) {
    return -1;
  }

  bitmap = (struct bitmap256 *)reference;
  memset(bitmap, 0, sizeof(*bitmap));

  strarray_for_each_element(value, ptr) {
    errno = 0;
    if (strcasecmp(ptr, BITMAP256_ALL) == 0) {
      memset(bitmap, 255, sizeof(*bitmap));
    }
    else if (strcasecmp(ptr, BITMAP256_NONE) == 0) {
      memset(bitmap, 0, sizeof(*bitmap));
    }
    else if (*ptr == '-') {
      idx = strtol(&ptr[1], NULL, 10);
      if (!errno) {
        bitmap256_reset(bitmap, idx);
      }
    }
    else {
      idx = strtol(ptr, NULL, 10);
      if (!errno) {
        bitmap256_set(bitmap, idx);
      }
    }
  }
  return 0;
}

/**
 * Binary converter for booleans.
 * See CFG_MAP_BOOL() macro in cfg_schema.h
 * @param reference pointer to binary output buffer.
 * @param bin_size size of reference memory
 * @param value pointer to value of configuration entry.
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_tobin_bool(void *reference, size_t bin_size, const struct const_strarray *value) {
  bool *ptr;

  if (bin_size != sizeof(*ptr)) {
    return -1;
  }

  ptr = (bool *)reference;

  *ptr = cfg_get_bool(strarray_get_first_c(value));
  return 0;
}

/**
 * Binary converter for list of strings.
 * See CFG_MAP_STRINGLIST() macro in cfg_schema.h
 * @param reference pointer to binary output buffer.
 * @param bin_size size of reference memory
 * @param value pointer to value of configuration entry.
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_tobin_stringlist(void *reference, size_t bin_size, const struct const_strarray *value) {
  struct strarray *array;

  if (bin_size != sizeof(*array)) {
    return -1;
  }

  array = (struct strarray *)reference;

  if (!value->value[0]) {
    strarray_init(array);
    return 0;
  }
  return strarray_copy_c(array, value);
}

/**
 * Binary converter for list of space separated tokens.
 * See CFG_MAP_STRINGLIST() macro in cfg_schema.h
 * @param reference pointer to binary output buffer.
 * @param value pointer to value of configuration entry.
 * @param entries pointer to array of configuration entries
 * @param entry_count number of configuration entries
 * @param custom customizer parameters for token conversion
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_tobin_tokens(void *reference, const char *value, struct cfg_schema_entry *entries, size_t entry_count,
  struct cfg_schema_token_customizer *custom) {
  struct const_strarray parameter, *parameter_ptr;
  const char *next_token;
  char buffer[256];
  char *dst;
  size_t i;

  dst = reference;
  next_token = value;

  parameter.value = buffer;
  for (i = 0; i < entry_count - 1; i++) {
    if (!next_token) {
      parameter_ptr = &entries[i].def;
    }
    else {
      next_token = str_cpynextword(buffer, next_token, sizeof(buffer));
      parameter.length = strlen(parameter.value) + 1;
      parameter_ptr = &parameter;
    }

    if (entries[i].cb_to_binary) {
      if (entries[i].cb_to_binary(&entries[i], parameter_ptr, dst + entries[i].bin_offset)) {
        return -1;
      }
    }
  }

  if (next_token) {
    /* we have data for the last entry left */
    i = entry_count - 1;

    parameter.value = next_token;
    parameter.length = strlen(next_token) + 1;

    if (entries[i].cb_to_binary) {
      if (entries[i].cb_to_binary(&entries[i], &parameter, dst + entries[i].bin_offset)) {
        return -1;
      }
    }
  }

  if (custom && custom->cb_tobin) {
    return custom->cb_tobin(entries, entry_count, value, dst);
  }
  return 0;
}
