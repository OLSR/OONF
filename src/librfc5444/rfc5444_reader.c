
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
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/libcommon/bitmap256.h>
#include <oonf/oonf.h>
#include <oonf/librfc5444/rfc5444_api_config.h>
#include <oonf/librfc5444/rfc5444_reader.h>

#if DISALLOW_CONSUMER_CONTEXT_DROP == true
/**
 * Helper function to allow to switch consumer context drop on/off
 * @param value value if context drop is allowed
 * @param def value if context drop is not allowed
 */
#define RFC5444_CONSUMER_DROP_ONLY(value, def) (def)
#else
#define RFC5444_CONSUMER_DROP_ONLY(value, def) (value)
#endif

static int _consumer_avl_comp(const void *k1, const void *k2);
static uint16_t _calc_tlvconsumer_intorder(struct rfc5444_reader_tlvblock_consumer_entry *entry);
static uint16_t _calc_tlvblock_intorder(struct rfc5444_reader_tlvblock_entry *entry);
static int _compare_tlvtypes(
  struct rfc5444_reader_tlvblock_entry *tlv, struct rfc5444_reader_tlvblock_consumer_entry *entry);
static uint8_t _rfc5444_get_u8(const uint8_t **ptr, const uint8_t *end, enum rfc5444_result *result);
static uint16_t _rfc5444_get_u16(const uint8_t **ptr, const uint8_t *end, enum rfc5444_result *result);
static void _free_tlvblock(struct rfc5444_reader *parser, struct avl_tree *entries);
static enum rfc5444_result _parse_tlv(
  struct rfc5444_reader_tlvblock_entry *entry, const uint8_t **ptr, const uint8_t *eob, uint8_t addr_count);
static enum rfc5444_result _parse_tlvblock(struct rfc5444_reader *parser, struct avl_tree *tlvblock, const uint8_t **ptr,
  const uint8_t *eob, uint8_t addr_count);
static enum rfc5444_result _schedule_tlvblock(struct rfc5444_reader_tlvblock_consumer *consumer,
  struct rfc5444_reader_tlvblock_context *context, struct avl_tree *entries, uint8_t idx);
static enum rfc5444_result _parse_addrblock(struct rfc5444_reader_addrblock_entry *addr_entry,
  struct rfc5444_reader_tlvblock_context *tlv_context, const uint8_t **ptr, const uint8_t *eob);
static enum rfc5444_result _handle_message(struct rfc5444_reader *parser, struct rfc5444_reader_tlvblock_context *tlv_context,
  const uint8_t **ptr, const uint8_t *eob);
static struct rfc5444_reader_tlvblock_consumer *_add_consumer(struct rfc5444_reader_tlvblock_consumer *,
  struct avl_tree *consumer_tree, struct rfc5444_reader_tlvblock_consumer_entry *entries, int entrycount);
static void _free_consumer(struct avl_tree *consumer_tree, struct rfc5444_reader_tlvblock_consumer *consumer);
static struct rfc5444_reader_addrblock_entry *_malloc_addrblock_entry(void);
static struct rfc5444_reader_tlvblock_entry *_malloc_tlvblock_entry(void);
static void _free_addrblock_entry(struct rfc5444_reader_addrblock_entry *entry);
static void _free_tlvblock_entry(struct rfc5444_reader_tlvblock_entry *entry);

static uint8_t rfc5444_get_pktversion(uint8_t v);

/**
 * Initalize the context of a parser with default values.
 * @param context pointer to parser context
 */
void
rfc5444_reader_init(struct rfc5444_reader *context) {
  avl_init(&context->packet_consumer, _consumer_avl_comp, true);
  avl_init(&context->message_consumer, _consumer_avl_comp, true);

  if (context->malloc_addrblock_entry == NULL)
    context->malloc_addrblock_entry = _malloc_addrblock_entry;
  if (context->malloc_tlvblock_entry == NULL)
    context->malloc_tlvblock_entry = _malloc_tlvblock_entry;

  if (context->free_addrblock_entry == NULL)
    context->free_addrblock_entry = _free_addrblock_entry;
  if (context->free_tlvblock_entry == NULL)
    context->free_tlvblock_entry = _free_tlvblock_entry;
}

/**
 * Free all memory allocated for a parser context and clear it
 * to be sure that it's not used again.
 * @param context pointer to parser context
 */
void
rfc5444_reader_cleanup(struct rfc5444_reader *context) {
  memset(&context->packet_consumer, 0, sizeof(context->packet_consumer));
  memset(&context->message_consumer, 0, sizeof(context->message_consumer));
}

/**
 * parse a complete rfc5444 packet.
 * @param parser pointer to parser context
 * @param buffer pointer to begin of rfc5444 packet
 * @param length number of bytes in buffer
 * @return RFC5444_OKAY (0) if successful, RFC5444_... otherwise
 */
enum rfc5444_result
rfc5444_reader_handle_packet(struct rfc5444_reader *parser, const uint8_t *buffer, size_t length)
{
  struct rfc5444_reader_tlvblock_context context;
  struct avl_tree entries;
  struct rfc5444_reader_tlvblock_consumer *consumer, *last_started;
  const uint8_t *ptr, *eob;
  bool has_tlv;
  uint8_t first_byte;
  enum rfc5444_result result = RFC5444_OKAY;

  if (length > 65535) {
    return RFC5444_TOO_LARGE;
  }

  /* copy pointer to prevent writing over parameter */
  ptr = buffer;
  eob = buffer + length;

  /* initialize tlv context */
  memset(&context, 0, sizeof(context));
  context.type = RFC5444_CONTEXT_PACKET;
  context.reader = parser;

  /* read header of packet */
  first_byte = _rfc5444_get_u8(&ptr, eob, &result);
  context.pkt_version = rfc5444_get_pktversion(first_byte);
  context.pkt_flags = first_byte & RFC5444_PKT_FLAGMASK;

  if (context.pkt_version != 0) {
    /*
     * bad packet version, do not jump to cleanup_parse packet because
     * we have not allocated any resources at this point
     */
    return RFC5444_UNSUPPORTED_VERSION;
  }

  /* check for sequence number */
  context.has_pktseqno = ((context.pkt_flags & RFC5444_PKT_FLAG_SEQNO) != 0);
  if (context.has_pktseqno) {
    context.pkt_seqno = _rfc5444_get_u16(&ptr, eob, &result);
  }

  if (result != RFC5444_OKAY) {
    /*
     * error during parsing, do not jump to cleanup_parse packet because
     * we have not allocated any resources at this point
     */
    return result;
  }

  /* initialize avl_tree */
  avl_init(&entries, avl_comp_uint32, true);
  last_started = NULL;

  /* check for packet tlv */
  has_tlv = (context.pkt_flags & RFC5444_PKT_FLAG_TLV) != 0;
  if (has_tlv) {
    result = _parse_tlvblock(parser, &entries, &ptr, eob, 0);
    if (result != RFC5444_OKAY) {
      /*
       * error while parsing TLV block, do not jump to cleanup_parse packet because
       * we have not allocated any resources at this point
       */
      return result;
    }
  }

  /* update packet buffer pointer */
  context.pkt_buffer = buffer;
  context.pkt_size = length;

  /* handle packet consumers, call start callbacks */
  avl_for_each_element(&parser->packet_consumer, consumer, _node) {
    last_started = consumer;
    /* this one can drop a packet */
    if (consumer->start_callback != NULL) {
      context.consumer = consumer;
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      result =
#endif
        consumer->start_callback(&context);
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      if (result != RFC5444_OKAY) {
        goto cleanup_parse_packet;
      }
#endif
    }
    /* handle packet tlv consumers */
    if (has_tlv && (consumer->tlv_callback != NULL || consumer->block_callback != NULL)) {
      /* can drop packet */
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      result =
#endif
        _schedule_tlvblock(consumer, &context, &entries, 0);
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      if (result != RFC5444_OKAY) {
        goto cleanup_parse_packet;
      }
#endif
    }
  }

  /* parse messages */
  while (result == RFC5444_OKAY && ptr < eob) {
    /* can drop packet (need to be there for error handling too) */
    result = _handle_message(parser, &context, &ptr, eob);
  }

#if DISALLOW_CONSUMER_CONTEXT_DROP == false
cleanup_parse_packet:
#endif
  /* call end-of-context callback */
  if (!avl_is_empty(&parser->packet_consumer)) {
    avl_for_first_to_element_reverse(&parser->packet_consumer, last_started, consumer, _node) {
      if (consumer->end_callback) {
        context.consumer = consumer;
        consumer->end_callback(&context, result != RFC5444_OKAY);
      }
    }
  }
  _free_tlvblock(parser, &entries);

  /* do not tell caller about packet drop */
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
  if (result == RFC5444_DROP_PACKET) {
    return RFC5444_OKAY;
  }
#endif
  return result;
}

/**
 * Add a packet consumer to the parser
 * @param parser pointer to parser context
 * @param consumer pointer to tlvblock consumer
 * @param entries array of tlvblock_entries
 * @param entrycount number of elements in array
 */
void
rfc5444_reader_add_packet_consumer(struct rfc5444_reader *parser, struct rfc5444_reader_tlvblock_consumer *consumer,
  struct rfc5444_reader_tlvblock_consumer_entry *entries, size_t entrycount) {
  _add_consumer(consumer, &parser->packet_consumer, entries, entrycount);
}

/**
 * Add a message consumer for a single message type to
 * the parser to process the message tlvs
 * @param parser pointer to parser context
 * @param consumer pointer to tlvblock consumer
 * @param entries array of tlvblock_entries
 * @param entrycount number of elements in array
 */
void
rfc5444_reader_add_message_consumer(struct rfc5444_reader *parser, struct rfc5444_reader_tlvblock_consumer *consumer,
  struct rfc5444_reader_tlvblock_consumer_entry *entries, size_t entrycount) {
  _add_consumer(consumer, &parser->message_consumer, entries, entrycount);
}

/**
 * Remove a packet consumer from the parser
 * @param parser pointer to parser context
 * @param consumer pointer to tlvblock consumer
 */
void
rfc5444_reader_remove_packet_consumer(
  struct rfc5444_reader *parser, struct rfc5444_reader_tlvblock_consumer *consumer) {
  assert(!consumer->addrblock_consumer && consumer->msg_id == 0);
  _free_consumer(&parser->packet_consumer, consumer);
}

/**
 * Remove a message/address consumer from the parser
 * @param parser pointer to parser context
 * @param consumer pointer to tlvblock consumer
 */
void
rfc5444_reader_remove_message_consumer(
  struct rfc5444_reader *parser, struct rfc5444_reader_tlvblock_consumer *consumer) {
  _free_consumer(&parser->message_consumer, consumer);
}

/**
 * Comparator for two tlvblock consumers. addrblock_consumer field is
 * used as a tie-breaker if order is the same.
 */
static int
_consumer_avl_comp(const void *k1, const void *k2) {
  const struct rfc5444_reader_tlvblock_consumer *c1 = k1;
  const struct rfc5444_reader_tlvblock_consumer *c2 = k2;

  if (c1->order > c2->order) {
    return 1;
  }
  if (c1->order < c2->order) {
    return -1;
  }
  if (c1->addrblock_consumer && !c2->addrblock_consumer) {
    return 1;
  }
  if (!c1->addrblock_consumer && c2->addrblock_consumer) {
    return -1;
  }
  return 0;
}

/**
 * Calculate internal tlvtype from type and exttype
 * @param entry pointer tlvblock entry
 * @return 256*type + exttype
 */
static uint16_t
_calc_tlvconsumer_intorder(struct rfc5444_reader_tlvblock_consumer_entry *entry) {
  return (((uint16_t)entry->type) << 8) | ((uint16_t)entry->type_ext);
}

/**
 * Calculate internal tlvtype from type and exttype
 * @param entry pointer tlvblock entry
 * @return 256*type + exttype
 */
static uint16_t
_calc_tlvblock_intorder(struct rfc5444_reader_tlvblock_entry *entry) {
  return (((uint16_t)entry->type) << 8) | ((uint16_t)entry->type_ext);
}

/**
 * Checks if a tlvblock consumer entry to a tlvblock entry
 * @param tlv tlvlock entry, might be NULL
 * @param entry tlvblock consumer entry, might be NULL
 * @return <0 if type1<type2, ==0 if type1==type2, >0 if type1>type2
 */
static int
_compare_tlvtypes(struct rfc5444_reader_tlvblock_entry *tlv, struct rfc5444_reader_tlvblock_consumer_entry *entry) {
  if (entry == NULL) {
    if (tlv == NULL) {
      return 0;
    }
    return -1;
  }
  if (tlv == NULL) {
    return 1;
  }

  if (entry->match_type_ext) {
    return (int)tlv->_order - _calc_tlvconsumer_intorder(entry);
  }
  return (int)tlv->type - (int)entry->type;
}

/**
 * helper function to read a single byte from a data stream
 * @param ptr pointer to pointer to begin of datastream, will be
 *   incremented by one if no error happened.
 * @param end pointer to first byte after the datastream
 * @param error pointer to result variable, will be RFC5444_ERROR
 *   if an error happened
 * @return uint8_t value of the next byte
 */
static uint8_t
_rfc5444_get_u8(const uint8_t **ptr, const uint8_t *end, enum rfc5444_result *error) {
  uint8_t result;
  if (*error != RFC5444_OKAY) {
    return 0;
  }
  if (*ptr >= end) {
    *error = RFC5444_END_OF_BUFFER;
    return 0;
  }

  result = **ptr;
  *ptr += 1;
  return result;
}

/**
 * helper function to read a word (2 bytes) from a data stream
 * @param ptr pointer to pointer to begin of datastream, will be
 *   incremented by two if no error happened.
 * @param end pointer to first byte after the datastream
 * @param error pointer to result variable, will be RFC5444_ERROR
 *   if an error happened
 * @return uint16_t value of the next word (network byte order)
 */
static uint16_t
_rfc5444_get_u16(const uint8_t **ptr, const uint8_t *end, enum rfc5444_result *error) {
  return ((uint16_t)_rfc5444_get_u8(ptr, end, error) << 8) | (uint16_t)_rfc5444_get_u8(ptr, end, error);
}

/**
 * free a list of linked tlv_block entries
 * @param entries avl_tree of tlv_block entries
 */
static void
_free_tlvblock(struct rfc5444_reader *parser, struct avl_tree *entries) {
  struct rfc5444_reader_tlvblock_entry *tlv, *ptr;

  avl_remove_all_elements(entries, tlv, node, ptr) {
    parser->free_tlvblock_entry(tlv);
  }
}

/**
 * parse a TLV into a rfc5444_reader_tlvblock_entry and advance the data stream pointer
 * @param entry pointer to rfc5444_reader_tlvblock_entry
 * @param ptr pointer to pointer to begin of datastream, will be
 *   incremented to the first byte after the TLV if no error happened.
 *   Will be set to eob if an error happened.
 * @param eob pointer to first byte after the datastream
 * @param addr_count number of addresses corresponding to tlvblock, 0 if message or
 *   packet tlv
 * @return -1 if an error happened, 0 otherwise
 */
static enum rfc5444_result
_parse_tlv(struct rfc5444_reader_tlvblock_entry *entry, const uint8_t **ptr, const uint8_t *eob, uint8_t addr_count) {
  enum rfc5444_result result = RFC5444_OKAY;
  uint8_t masked, count;

  /* get tlv type (without extension) and flags */
  entry->type = _rfc5444_get_u8(ptr, eob, &result);
  entry->flags = _rfc5444_get_u8(ptr, eob, &result);

  /* check for tlvtype extension */
  if ((entry->flags & RFC5444_TLV_FLAG_TYPEEXT) != 0) {
    /* type extension */
    entry->type_ext = _rfc5444_get_u8(ptr, eob, &result);
  }
  else {
    entry->type_ext = 0;
  }

  /* calculate internal combination of tlv type and extension */
  entry->_order = _calc_tlvblock_intorder(entry);

  /* check for TLV index values */
  masked = entry->flags & (RFC5444_TLV_FLAG_SINGLE_IDX | RFC5444_TLV_FLAG_MULTI_IDX);
  if (masked == 0) {
    entry->index1 = 0;
    entry->index2 = addr_count - 1;
  }
  else if (masked == RFC5444_TLV_FLAG_SINGLE_IDX) {
    entry->index1 = entry->index2 = _rfc5444_get_u8(ptr, eob, &result);
  }
  else if (masked == RFC5444_TLV_FLAG_MULTI_IDX) {
    entry->index1 = _rfc5444_get_u8(ptr, eob, &result);
    entry->index2 = _rfc5444_get_u8(ptr, eob, &result);
  }
  else {
    *ptr = eob;
    return RFC5444_BAD_TLV_IDXFLAGS;
  }

  /* consistency check for index fields */
  if (addr_count > 0 && (entry->index1 >= addr_count || entry->index2 >= addr_count)) {
    *ptr = eob;
    return RFC5444_BAD_TLV_INDEX;
  }

  /* check for length field */
  masked = entry->flags & (RFC5444_TLV_FLAG_VALUE | RFC5444_TLV_FLAG_EXTVALUE);
  if (masked == 0) {
    entry->length = 0;
  }
  else if (masked == RFC5444_TLV_FLAG_VALUE) {
    entry->length = _rfc5444_get_u8(ptr, eob, &result);
  }
  else if (masked == (RFC5444_TLV_FLAG_EXTVALUE | RFC5444_TLV_FLAG_VALUE)) {
    entry->length = _rfc5444_get_u16(ptr, eob, &result);
  }
  else {
    *ptr = eob;
    return RFC5444_BAD_TLV_VALUEFLAGS;
  }

  /* check for multivalue tlv field */
  entry->_multivalue_tlv = (entry->flags & RFC5444_TLV_FLAG_MULTIVALUE) != 0;

  /* not enough bytes left ? */
  if (*ptr + entry->length > eob) {
    *ptr = eob;
    return RFC5444_END_OF_BUFFER;
  }
  if (result != RFC5444_OKAY) {
    *ptr = eob;
    return result;
  }

  /* copy pointer to value */
  if (entry->length == 0) {
    entry->_value = NULL;
    return RFC5444_OKAY;
  }

  entry->_value = *ptr;
  *ptr += entry->length;

  /* handle multivalue TLVs */
  count = entry->index2 - entry->index1 + 1;
  if (count == 1) {
    entry->_multivalue_tlv = false;
  }
  if (!entry->_multivalue_tlv) {
    /* copy internal value pointer if no multivalue tlv */
    entry->single_value = entry->_value;
    return RFC5444_OKAY;
  }

  if ((entry->length % count) != 0) {
    /* bad length for multi value TLV */
    return RFC5444_BAD_TLV_LENGTH;
  }
  entry->length /= count;
  return RFC5444_OKAY;
}

/**
 * parse a TLV block into a list of linked tlvblock_entries.
 * @param tlvblock pointer to avl_tree to store generates tlvblock entries
 * @param ptr pointer to pointer to begin of datastream, will be
 *   incremented to the first byte after the block if no error happened.
 *   Will be set to eob if an error happened.
 * @param eob pointer to first byte after the datastream
 * @param addr_count number of addresses corresponding to tlvblock, 0 if message or
 *   packet tlv * @return -1 if an error happened, 0 otherwise
 */
static enum rfc5444_result
_parse_tlvblock(struct rfc5444_reader *parser, struct avl_tree *tlvblock, const uint8_t **ptr, const uint8_t *eob,
  uint8_t addr_count) {
  enum rfc5444_result result = RFC5444_OKAY;
  struct rfc5444_reader_tlvblock_entry *tlv1 = NULL;
  struct rfc5444_reader_tlvblock_entry entry;
  const uint8_t *end;

  /* get length of TLV block */
  end = (*ptr) + 2;
  end = end + _rfc5444_get_u16(ptr, eob, &result);

  if (end > eob) {
    /* not enough memory for TLV block */
    result = RFC5444_END_OF_BUFFER;
    goto cleanup_parse_tlvblock;
  }

  /* clear static buffer */
  memset(&entry, 0, sizeof(entry));

  /* parse tlvs */
  while (*ptr < end) {
    /* parse next TLV into static buffer */
    result = _parse_tlv(&entry, ptr, eob, addr_count);
    if (result != RFC5444_OKAY) {
      /* error while parsing TLV */
      goto cleanup_parse_tlvblock;
    }

    /* get memory to store TLV block entry */
    tlv1 = parser->malloc_tlvblock_entry();
    if (tlv1 == NULL) {
      /* not enough memory left ! */
      result = RFC5444_OUT_OF_MEMORY;
      goto cleanup_parse_tlvblock;
    }

    /* copy TLV block entry into allocated memory */
    memcpy(tlv1, &entry, sizeof(entry));

    /* put into sorted list */
    tlv1->node.key = &tlv1->_order;
    avl_insert(tlvblock, &tlv1->node);
  }
cleanup_parse_tlvblock:
  if (result != RFC5444_OKAY) {
    _free_tlvblock(parser, tlvblock);
    *ptr = eob;
  }
  return result;
}

/**
 * Call callbacks for parsed TLV blocks
 * @param consumer pointer to first consumer for this message type
 * @param context pointer to context for tlv block
 * @param entries pointer avl_tree of tlv block entries
 * @param idx of current address inside the addressblock, 0 for message tlv block
 * @return RFC5444_TLV_DROP_ADDRESS if the current address should
 *   be dropped for later consumers, RFC5444_TLV_DROP_CONTEXT if
 *   the complete message/package should be dropped for
 *   later consumers, 0 if no error happened
 */
static enum rfc5444_result
_schedule_tlvblock(struct rfc5444_reader_tlvblock_consumer *consumer, struct rfc5444_reader_tlvblock_context *context,
  struct avl_tree *entries, uint8_t idx) {
  struct rfc5444_reader_tlvblock_entry *tlv = NULL, *nexttlv = NULL;
  struct rfc5444_reader_tlvblock_consumer_entry *cons_entry;
  bool constraints_failed;
  enum rfc5444_result result = RFC5444_OKAY;

  constraints_failed = false;

  /* initialize tlv pointers, there must be TLVs */
  if (avl_is_empty(entries)) {
    tlv = NULL;
  }
  else {
    tlv = avl_first_element(entries, tlv, node);
  }

  /* initialize consumer pointer */
  if (list_is_empty(&consumer->_consumer_list)) {
    cons_entry = NULL;
  }
  else {
    cons_entry = list_first_element(&consumer->_consumer_list, cons_entry, _node);
    cons_entry->tlv = NULL;
  }

  /* we are running in parallel through two sorted lists */
  while (cons_entry != NULL || tlv != NULL) {
    bool match = false;
    bool index_match = false;

    if (tlv) {
      index_match = RFC5444_CONSUMER_DROP_ONLY(!bitmap256_get(&tlv->int_drop_tlv, idx), true) && idx >= tlv->index1 &&
                    idx <= tlv->index2;
    }

    /* check index for address blocks */
    if (tlv != NULL && cons_entry != NULL && index_match) {
      /* calculate match between tlv and consumer */
      match = _compare_tlvtypes(tlv, cons_entry) == 0;
    }

    if (index_match && tlv->_multivalue_tlv) {
      size_t offset;

      /* calculate value pointer for multivalue tlv */
      offset = (size_t)(idx - tlv->index1) * tlv->length;
      tlv->single_value = &tlv->_value[offset];
    }

    /* handle tlv_callback first */
    if (index_match && consumer->tlv_callback != NULL) {
      /* call consumer for TLV, can skip tlv, address, message and packet */
      context->consumer = consumer;
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      result =
#endif
        consumer->tlv_callback(tlv, context);
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      if (result == RFC5444_DROP_TLV) {
        /* mark dropped tlv */
        bitmap256_set(&tlv->int_drop_tlv, idx);
        match = false;
        /* do not propagate result */
        result = RFC5444_OKAY;
      }
      else if (result != RFC5444_OKAY) {
        /* stop processing this TLV block/address/message/packet */
        goto cleanup_handle_tlvblock;
      }
#endif
    }

    /* run through both sorted lists until finding a match */
    if (_compare_tlvtypes(tlv, cons_entry) >= 0) {
      constraints_failed |= cons_entry->mandatory && !match;

      if (match) {
        if (cons_entry->match_length &&
            (tlv->length < cons_entry->min_length || tlv->length > cons_entry->max_length)) {
          constraints_failed = true;
        }

        /* this is the last TLV that fits the description... for now */
        tlv->next_entry = NULL;

        if (cons_entry->tlv == NULL) {
          /* it is also the first one we find */
          cons_entry->tlv = tlv;

          if (cons_entry->copy_value != NULL && tlv->length > 0) {
            /* copy value into private buffer */
            uint16_t len = cons_entry->max_length;

            if (tlv->length < len) {
              len = tlv->length;
            }
            memcpy(cons_entry->copy_value, tlv->single_value, len);
          }
        }
        else {
          /* its one of many, put it at the end of the list */
          nexttlv = cons_entry->tlv;
          while (nexttlv->next_entry) {
            nexttlv = nexttlv->next_entry;
          }
          nexttlv->next_entry = tlv;
        }
      }
    }
    if (tlv != NULL && _compare_tlvtypes(tlv, cons_entry) <= 0) {
      /* advance tlv pointer */
      if (avl_is_last(entries, &tlv->node)) {
        tlv = NULL;
      }
      else {
        tlv = avl_next_element(tlv, node);
      }
    }
    if (_compare_tlvtypes(tlv, cons_entry) > 0) {
      constraints_failed |= cons_entry->mandatory && !match;

      /* advance consumer pointer */
      if (list_is_last(&consumer->_consumer_list, &cons_entry->_node)) {
        cons_entry = NULL;
      }
      else {
        cons_entry = list_next_element(cons_entry, _node);
        cons_entry->tlv = NULL;
      }
    }
  }

  /* call consumer for tlvblock */
  if (consumer->block_callback != NULL && !constraints_failed) {
    context->consumer = consumer;
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    result =
#endif
      consumer->block_callback(context);
  }
  else if (consumer->block_callback_failed_constraints != NULL && constraints_failed) {
    context->consumer = consumer;
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    result =
#endif
      consumer->block_callback_failed_constraints(context);
  }
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
  if (result == RFC5444_DROP_TLV) {
    list_for_each_element(&consumer->_consumer_list, cons_entry, _node) {
      if (cons_entry->tlv != NULL && cons_entry->drop) {
        bitmap256_set(&cons_entry->tlv->int_drop_tlv, idx);
        cons_entry->drop = false;
      }
    }

    /* do not propagate tlv drops */
    result = RFC5444_OKAY;
  }
#endif
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
cleanup_handle_tlvblock:
#endif
#if DEBUG_CLEANUP == true
  list_for_each_element(&consumer->_consumer_list, cons_entry, _node) {
    cons_entry->tlv = NULL;
    cons_entry->drop = false;
  }
#endif

  return result;
}

/**
 * parse an address block and put it into an addrblock entry
 * @param addr_entry pointer to rfc5444_reader_addrblock_entry to store the data
 * @param tlv_context pointer to context
 * @param ptr pointer to pointer to begin of datastream, will be
 *   incremented to the first byte after the block if no error happened.
 *   Will be set to eob if an error happened.
 * @param eob pointer to first byte after the datastream
 * @return -1 if an error happened, 0 otherwise
 */
static enum rfc5444_result
_parse_addrblock(struct rfc5444_reader_addrblock_entry *addr_entry, struct rfc5444_reader_tlvblock_context *tlv_context,
  const uint8_t **ptr, const uint8_t *eob) {
  enum rfc5444_result result = RFC5444_OKAY;
  uint8_t flags;
  uint8_t tail_len;
  uint8_t masked;

  /* store start of addr block */
  addr_entry->addr_block_ptr = *ptr;

  /* read addressblock header */
  addr_entry->num_addr = _rfc5444_get_u8(ptr, eob, &result);
  if (addr_entry->num_addr == 0) {
    /* no addresses. */
    return RFC5444_EMPTY_ADDRBLOCK;
  }

  flags = _rfc5444_get_u8(ptr, eob, &result);

  /* initialize head/tail of address */
  memset(&addr_entry->addr, 0, sizeof(addr_entry->addr));
  addr_entry->mid_len = tlv_context->addr_len;

  /* check for head flag */
  if ((flags & RFC5444_ADDR_FLAG_HEAD) != 0) {
    addr_entry->mid_start = _rfc5444_get_u8(ptr, eob, &result);
    if (addr_entry->mid_start < 1 || addr_entry->mid_start >= RFC5444_MAX_ADDRLEN ||
        addr_entry->mid_start >= tlv_context->addr_len) {
      return RFC5444_BAD_ADDR_HEAD_LENGTH;
    }
    if (*ptr + addr_entry->mid_start > eob) {
      /* not enough buffer for head */
      return RFC5444_END_OF_BUFFER;
    }

    /* copy address head into buffer */
    memcpy(addr_entry->addr, *ptr, addr_entry->mid_start);
    addr_entry->mid_len -= addr_entry->mid_start;
    *ptr += addr_entry->mid_start;
  }

  /* check for tail flags */
  masked = flags & (RFC5444_ADDR_FLAG_FULLTAIL | RFC5444_ADDR_FLAG_ZEROTAIL);
  if (masked == RFC5444_ADDR_FLAG_ZEROTAIL) {
    addr_entry->mid_len -= _rfc5444_get_u8(ptr, eob, &result);
  }
  else if (masked == RFC5444_ADDR_FLAG_FULLTAIL) {
    tail_len = _rfc5444_get_u8(ptr, eob, &result);
    if (tail_len < 1 || tail_len >= RFC5444_MAX_ADDRLEN || tail_len >= tlv_context->addr_len) {
      return RFC5444_BAD_ADDR_TAIL_LENGTH;
    }
    if (*ptr + tail_len > eob) {
      /* not enough buffer for head */
      return RFC5444_END_OF_BUFFER;
    }

    /* copy address tail into buffer */
    memcpy(addr_entry->addr + tlv_context->addr_len - tail_len, *ptr, tail_len);
    addr_entry->mid_len -= tail_len;
    *ptr += tail_len;
  }
  else if (masked != 0) {
    return RFC5444_BAD_MSG_TAILFLAGS;
  }

  /* store mid part of addresses */
  addr_entry->mid_src = *ptr;
  *ptr += (addr_entry->mid_len * addr_entry->num_addr);
  if (*ptr > eob) {
    return RFC5444_END_OF_BUFFER;
  }

  /* check for prefix flags */
  masked = flags & (RFC5444_ADDR_FLAG_SINGLEPLEN | RFC5444_ADDR_FLAG_MULTIPLEN);
  if (masked == 0) {
    addr_entry->prefixlen = tlv_context->addr_len * 8;
  }
  else if (masked == RFC5444_ADDR_FLAG_SINGLEPLEN) {
    addr_entry->prefixlen = **ptr;
    *ptr += 1;
  }
  else if (masked == RFC5444_ADDR_FLAG_MULTIPLEN) {
    addr_entry->prefixes = *ptr;
    *ptr += addr_entry->num_addr;
  }
  else {
    return RFC5444_BAD_MSG_PREFIXFLAGS;
  }

  /* check for error */
  if (*ptr > eob) {
    return RFC5444_END_OF_BUFFER;
  }

  /* calculate size of address block */
  addr_entry->addr_block_size = *ptr - addr_entry->addr_block_ptr;
  return result;
}

/**
 * Call start and tlvblock callbacks for message tlv consumer
 * @param consumer pointer to tlvblock consumer object
 * @param tlv_context current tlv context
 * @param tlv_entries pointer to tlventry avltree
 * @return RFC5444_OKAY if no error happend, RFC5444_DROP_ if a
 *   context (message or packet) should be dropped
 */
static enum rfc5444_result
schedule_msgtlv_consumer(struct rfc5444_reader_tlvblock_consumer *consumer,
  struct rfc5444_reader_tlvblock_context *tlv_context, struct avl_tree *tlv_entries) {
  enum rfc5444_result result = RFC5444_OKAY;
  tlv_context->type = RFC5444_CONTEXT_MESSAGE;

  /* call start-of-context callback */
  if (consumer->start_callback) {
    /* could drop tlv, message or packet */
    tlv_context->consumer = consumer;
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    result =
#endif
      consumer->start_callback(tlv_context);
  }

  /* call consumer for message tlv block */
  if (RFC5444_CONSUMER_DROP_ONLY(result == RFC5444_OKAY, true)) {
    /* could drop message or packet */
    result = _schedule_tlvblock(consumer, tlv_context, tlv_entries, 0);
  }
  return result;
}

/**
 * Call callbacks for address tlv consumer
 * @param consumer pointer to tlvblock consumer object
 * @param tlv_context current tlv context
 * @param addr_head pointer to list of address block objects
 * @return RFC5444_OKAY if no error happend, RFC5444_DROP_ if a
 *   context (message or packet) should be dropped
 */
static enum rfc5444_result
schedule_msgaddr_consumer(struct rfc5444_reader_tlvblock_consumer *consumer,
  struct rfc5444_reader_tlvblock_context *tlv_context, struct list_entity *addr_head) {
  struct rfc5444_reader_addrblock_entry *addr;
  enum rfc5444_result result = RFC5444_OKAY;

  tlv_context->type = RFC5444_CONTEXT_ADDRESS;

  /* consume address tlv block(s) */
  /* iterate over all address blocks */
  list_for_each_element(addr_head, addr, list_node) {
    uint8_t i, plen;

    /* initialize byte context */
    tlv_context->addr_block_buffer = addr->addr_block_ptr;
    tlv_context->addr_block_size = addr->addr_block_size;
    tlv_context->addr_tlv_size = addr->addr_tlv_size;

    /* iterate over all addresses in block */
    for (i = 0; i < addr->num_addr; i++) {
      /* test if we should skip this address */
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      if (bitmap256_get(&addr->dropAddr, i)) {
        continue;
      }
#endif

      /* assemble address for context */
      memcpy(&addr->addr[addr->mid_start], &addr->mid_src[addr->mid_len * i], addr->mid_len);

      /* create netaddr */
      if (addr->prefixes) {
        plen = addr->prefixes[i];
      }
      else {
        plen = addr->prefixlen;
      }
      netaddr_from_binary_prefix(&tlv_context->addr, addr->addr, tlv_context->addr_len, 0, plen);

      /* remember index of address */
      tlv_context->addr_index = i;

      /* call start-of-context callback */
      if (consumer->start_callback) {
        /* can drop address, addressblock, message and packet */
        tlv_context->consumer = consumer;
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
        result =
#endif
          consumer->start_callback(tlv_context);
      }

      /* handle tlvblock callbacks */
      if (RFC5444_CONSUMER_DROP_ONLY(result == RFC5444_OKAY, true)) {
        result = _schedule_tlvblock(consumer, tlv_context, &addr->tlvblock, i);
      }

      /* call end-of-context callback */
      if (consumer->end_callback) {
        enum rfc5444_result r;
        tlv_context->consumer = consumer;
        r = consumer->end_callback(tlv_context, result != RFC5444_OKAY);
        if (r > result) {
          result = r;
        }
      }

#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      /* handle result from tlvblock callbacks */
      if (result == RFC5444_DROP_ADDRESS) {
        bitmap256_set(&addr->dropAddr, i);
        result = RFC5444_OKAY;
      }
      else if (result != RFC5444_OKAY) {
        return result;
      }
#endif
    }
  }

  /* remove context pointer */
  tlv_context->addr_block_buffer = NULL;

  return result;
}

/**
 * Call end callbacks for message tlvblock consumer.
 * @param tlv_context context of current tlvblock
 * @param first begin of range of consumers which should be called
 * @param last end of range of consumers which should be called
 * @param result current 'drop context' level
 * @return new 'drop context level'
 */
static enum rfc5444_result
schedule_end_message_cbs(struct rfc5444_reader_tlvblock_context *tlv_context,
  struct rfc5444_reader_tlvblock_consumer *first, struct rfc5444_reader_tlvblock_consumer *last,
  enum rfc5444_result result) {
  struct rfc5444_reader_tlvblock_consumer *consumer;
  enum rfc5444_result r;

  tlv_context->type = RFC5444_CONTEXT_MESSAGE;

  avl_for_element_range_reverse(first, last, consumer, _node) {
    if (consumer->end_callback && !consumer->addrblock_consumer &&
        (consumer->default_msg_consumer || consumer->msg_id == tlv_context->msg_type)) {
      tlv_context->consumer = consumer;
      r = consumer->end_callback(tlv_context, result != RFC5444_OKAY);
      if (r > result) {
        result = r;
      }
    }
  }
  return result;
}
/**
 * parse a message including tlvblocks and addresses,
 * then calls the callbacks for everything inside
 * @param parser pointer to parser context
 * @param tlv_context pointer to tlv context
 * @param ptr pointer to pointer to begin of datastream, will be
 *   incremented to the first byte after the message if no error happened.
 *   Will be set to eob if an error happened.
 * @param eob pointer to first byte after the datastream
 * @return -1 if an error happened, 0 otherwise
 */
static enum rfc5444_result
_handle_message(struct rfc5444_reader *parser, struct rfc5444_reader_tlvblock_context *tlv_context, const uint8_t **ptr,
  const uint8_t *eob) {
  struct avl_tree tlv_entries;
  struct rfc5444_reader_tlvblock_consumer *consumer, *same_order[2];
  struct list_entity addr_head;
  struct rfc5444_reader_addrblock_entry *addr, *safe;
  const uint8_t *start, *end = NULL;
  uint8_t flags;
  uint16_t size;

  enum rfc5444_result result;

  /* initialize variables */
  result = RFC5444_OKAY;
  same_order[0] = same_order[1] = NULL;
  avl_init(&tlv_entries, avl_comp_uint16, true);
  list_init_head(&addr_head);
  tlv_context->_do_not_forward = false;

  /* remember start of message */
  start = *ptr;

  /* parse message header */
  tlv_context->msg_type = _rfc5444_get_u8(ptr, eob, &result);
  flags = _rfc5444_get_u8(ptr, eob, &result);
  size = _rfc5444_get_u16(ptr, eob, &result);

  tlv_context->addr_len = (flags & RFC5444_MSG_FLAG_ADDRLENMASK) + 1;
  tlv_context->msg_flags = (flags & ~RFC5444_MSG_FLAG_ADDRLENMASK);

  /* test for originator address */
  tlv_context->has_origaddr = (flags & RFC5444_MSG_FLAG_ORIGINATOR) != 0;
  if (tlv_context->has_origaddr) {
    if ((*ptr + tlv_context->addr_len) > eob) {
      result = RFC5444_END_OF_BUFFER;
      goto cleanup_parse_message;
    }

    netaddr_from_binary(&tlv_context->orig_addr, *ptr, tlv_context->addr_len, 0);
    *ptr += tlv_context->addr_len;
  }

  /* test for hop limit */
  tlv_context->has_hoplimit = (flags & RFC5444_MSG_FLAG_HOPLIMIT) != 0;
  if (tlv_context->has_hoplimit) {
    tlv_context->hoplimit = _rfc5444_get_u8(ptr, eob, &result);
  }

  /* test for hopcount */
  tlv_context->has_hopcount = (flags & RFC5444_MSG_FLAG_HOPCOUNT) != 0;
  if (tlv_context->has_hopcount) {
    tlv_context->hopcount = _rfc5444_get_u8(ptr, eob, &result);
  }

  /* test for sequence number */
  tlv_context->has_seqno = (flags & RFC5444_MSG_FLAG_SEQNO) != 0;
  if (tlv_context->has_seqno) {
    tlv_context->seqno = _rfc5444_get_u16(ptr, eob, &result);
  }

  /* check for error during header parsing or bad length */
  end = start + size;
  if (end > eob) {
    *ptr = eob;
    result = RFC5444_END_OF_BUFFER;
  }
  if (result != RFC5444_OKAY) {
    goto cleanup_parse_message;
  }

  /* parse message TLV block */
  result = _parse_tlvblock(parser, &tlv_entries, ptr, end, 0);
  if (result != RFC5444_OKAY) {
    /* error while allocating tlvblock data */
    goto cleanup_parse_message;
  }

  /* parse rest of message */
  while (*ptr < end) {
    /* get memory for storing the address block entry */
    addr = parser->malloc_addrblock_entry();
    if (addr == NULL) {
      result = RFC5444_OUT_OF_MEMORY;
      goto cleanup_parse_message;
    }

    /* initialize avl_tree */
    avl_init(&addr->tlvblock, avl_comp_uint16, true);

    /* parse address block... */
    if ((result = _parse_addrblock(addr, tlv_context, ptr, end)) != RFC5444_OKAY) {
      parser->free_addrblock_entry(addr);
      goto cleanup_parse_message;
    }

    /* ... and corresponding tlvblock */
    result = _parse_tlvblock(parser, &addr->tlvblock, ptr, end, addr->num_addr);
    if (result != RFC5444_OKAY) {
      parser->free_addrblock_entry(addr);
      goto cleanup_parse_message;
    }

    /* calculate tlv block size */
    addr->addr_tlv_size = *ptr - addr->addr_block_size - addr->addr_block_ptr;

    list_add_tail(&addr_head, &addr->list_node);
  }

  /* update message pointer */
  tlv_context->msg_buffer = start;
  tlv_context->msg_size = size;

  /* loop through list of message/address consumers */
  avl_for_each_element(&parser->message_consumer, consumer, _node) {
    if (!consumer->default_msg_consumer && consumer->msg_id != tlv_context->msg_type) {
      /* wrong type of message, continue... */
      continue;
    }

    /* remember range of consumers with same order to call end_message() callbacks */
    if (same_order[0] != NULL && consumer->order > same_order[1]->order) {
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      result =
#endif
        schedule_end_message_cbs(tlv_context, same_order[0], same_order[1], result);
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      if (result != RFC5444_OKAY) {
        goto cleanup_parse_message;
      }
#endif
      same_order[0] = NULL;
    }

    if (consumer->addrblock_consumer) {
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      result =
#endif
        schedule_msgaddr_consumer(consumer, tlv_context, &addr_head);
    }
    else {
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      result =
#endif
        schedule_msgtlv_consumer(consumer, tlv_context, &tlv_entries);
      if (same_order[0] == NULL) {
        same_order[0] = consumer;
      }
      same_order[1] = consumer;
    }

#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    if (result != RFC5444_OKAY) {
      break;
    }
#endif
  }

  /* handle last end_message() callback range */
  if (same_order[0] != NULL) {
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    result =
#endif
      schedule_end_message_cbs(tlv_context, same_order[0], same_order[1], result);
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    if (result != RFC5444_OKAY) {
      goto cleanup_parse_message;
    }
#endif
  }

cleanup_parse_message:
  /* cleanup message buffer pointer */
  tlv_context->msg_buffer = NULL;

  /* handle message forwarding */
  if (
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    (result == RFC5444_OKAY || result == RFC5444_DROP_MSG_BUT_FORWARD) &&
#endif
    !tlv_context->_do_not_forward && parser->forward_message != NULL && tlv_context->has_hoplimit) {
    /* check limit */
    if (tlv_context->hoplimit > 1) {
      /* forward message if callback is available */
      tlv_context->type = RFC5444_CONTEXT_MESSAGE;
      parser->forward_message(tlv_context, start, end - start);
    }
  }

  /* free address tlvblocks */
  list_for_each_element_safe(&addr_head, addr, list_node, safe) {
    _free_tlvblock(parser, &addr->tlvblock);
    parser->free_addrblock_entry(addr);
  }

  /* free message tlvblock */
  _free_tlvblock(parser, &tlv_entries);
  *ptr = end;
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
  if (result > RFC5444_OKAY && result != RFC5444_DROP_PACKET) {
    /* do not propagate message/address/tlv drops */
    return RFC5444_OKAY;
  }
#endif
  return result;
}

/**
 * Add a tlvblock consumer to a linked list of consumers.
 * The list is kept sorted by the order of the consumers.
 * @param consumer tlvblock consumer entry
 * @param consumer_tree pointer to tree of consumers
 * @param entries pointer to rfc5444_reader_tlvblock_consumer_entry array
 * @param entrycount number of elements in array
 * @return pointer to rfc5444_reader_tlvblock_consumer,
 *   NULL if an error happened
 */
static struct rfc5444_reader_tlvblock_consumer *
_add_consumer(struct rfc5444_reader_tlvblock_consumer *consumer, struct avl_tree *consumer_tree,
  struct rfc5444_reader_tlvblock_consumer_entry *entries, int entrycount) {
  struct rfc5444_reader_tlvblock_consumer_entry *e;
  int i, o;
  bool set;

  list_init_head(&consumer->_consumer_list);

  /* generate sorted list of entries */
  for (i = 0; i < entrycount; i++) {
    o = _calc_tlvconsumer_intorder(&entries[i]);

    if (i == 0) {
      list_add_tail(&consumer->_consumer_list, &entries[i]._node);
    }
    else {
      set = false;
      list_for_each_element_reverse(&consumer->_consumer_list, e, _node) {
        if (_calc_tlvconsumer_intorder(e) <= o) {
          list_add_after(&e->_node, &entries[i]._node);
          set = true;
          break;
        }
      }
      if (!set) {
        list_add_head(&consumer->_consumer_list, &entries[i]._node);
      }
    }

    if (entries[i].min_length > entries[i].max_length) {
      entries[i].max_length = entries[i].min_length;
    }
  }

  /* insert into global list of consumers */
  consumer->_node.key = consumer;
  avl_insert(consumer_tree, &consumer->_node);
  return consumer;
}

/**
 * Free a rfc5444_reader_tlvblock_consumer and remove it from its linked list
 * @param consumer_tree tree of tlvblock consumers
 * @param consumer rfc5444_reader_tlvblock_consumer
 */
static void
_free_consumer(struct avl_tree *consumer_tree, struct rfc5444_reader_tlvblock_consumer *consumer) {
  /* remove consumer from tree */
  if (avl_is_node_added(&consumer->_node)) {
    avl_remove(consumer_tree, &consumer->_node);
  }
}

/**
 * Internal memory allocation function for addrblock
 * @return pointer to cleared addrblock
 */
static struct rfc5444_reader_addrblock_entry *
_malloc_addrblock_entry(void) {
  return calloc(1, sizeof(struct rfc5444_reader_addrblock_entry));
}

/**
 * Internal memory allocation function for rfc5444_reader_tlvblock_entry
 * @return pointer to cleared rfc5444_reader_tlvblock_entry
 */
static struct rfc5444_reader_tlvblock_entry *
_malloc_tlvblock_entry(void) {
  return calloc(1, sizeof(struct rfc5444_reader_tlvblock_entry));
}

/**
 * Free an addressblock entry
 * @param entry addressblock entry
 */
static void
_free_addrblock_entry(struct rfc5444_reader_addrblock_entry *entry) {
  free(entry);
}

/**
 * Free an tlvblock entry
 * @param entry tlvblock entry
 */
static void
_free_tlvblock_entry(struct rfc5444_reader_tlvblock_entry *entry) {
  free(entry);
}

/**
 * @param v first byte of packet header
 * @return packet header version
 */
static uint8_t
rfc5444_get_pktversion(uint8_t v) {
  return v >> 4;
}
