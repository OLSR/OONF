
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

#ifndef RFC5444_PARSER_H_
#define RFC5444_PARSER_H_

#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/bitmap256.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/librfc5444/rfc5444_context.h>

/**
 * type of context for a rfc5444_reader_tlvblock_context
 */
enum rfc5444_reader_tlvblock_context_type
{
  RFC5444_CONTEXT_PACKET,
  RFC5444_CONTEXT_MESSAGE,
  RFC5444_CONTEXT_ADDRESS
};

/**
 * This struct temporary holds the content of a decoded TLV.
 */
struct rfc5444_reader_tlvblock_entry {
  /*! tree of TLVs */
  struct avl_node node;

  /*! tlv type */
  uint8_t type;

  /*! tlv flags */
  uint8_t flags;

  /*! tlv type extension */
  uint8_t type_ext;

  /*! tlv value length */
  uint16_t length;

  /**
   * pointer to tlv value, NULL if length == 0
   * this pointer is NOT aligned
   */
  const uint8_t *single_value;

  /*! first index of tlv (for address blocks) */
  uint8_t index1;

  /*! last index of tlv (for address blocks) */
  uint8_t index2;

  /**
   * this points to the next tlvblock entry if there is more than one
   * fitting to the current callback (e.g. multiple linkmetric tlvs)
   */
  struct rfc5444_reader_tlvblock_entry *next_entry;

  /*! internal sorting order for types: tlvtype * 256 + exttype */
  uint16_t _order;

  /**
   * pointer to start of value array, can be different from
   * "value" because of multivalue tlvs
   */
  const uint8_t *_value;

  /*! true if this is a multivalue tlv */
  bool _multivalue_tlv;

  /*! internal bitarray to mark tlvs that shall be skipped by the next handler */
  struct bitmap256 int_drop_tlv;
};

/**
 * common context for packet, message and address TLV block
 */
struct rfc5444_reader_tlvblock_context {
  /*! backpointer to reader */
  struct rfc5444_reader *reader;

  /*! pointer to tlvblock consumer */
  struct rfc5444_reader_tlvblock_consumer *consumer;

  /*! applicable for all TLV blocks */
  enum rfc5444_reader_tlvblock_context_type type;

  /*! packet version number */
  uint8_t pkt_version;

  /*! packet flags field */
  uint8_t pkt_flags;

  /*! true if packet has sequence number */
  bool has_pktseqno;

  /*! packet sequence number */
  uint16_t pkt_seqno;

  /*! pointer to binary packet */
  const uint8_t *pkt_buffer;

  /*! size of binary packet */
  size_t pkt_size;

  /* only for message and address TLV blocks */

  /*! message type */
  uint8_t msg_type;

  /*! message flags field */
  uint8_t msg_flags;

  /*! message address length field */
  uint8_t addr_len;

  /*! true if message has hopcount */
  bool has_hopcount;

  /*! message hopcount */
  uint8_t hopcount;

  /*! true if message has hoplimit */
  bool has_hoplimit;

  /*! message hoplimit */
  uint8_t hoplimit;

  /*! true if message has originator */
  bool has_origaddr;

  /*! message originator */
  struct netaddr orig_addr;

  /*! true if message has sequence number */
  bool has_seqno;

  /*! message sequence number */
  uint16_t seqno;

  /*! pointer to binary message */
  const uint8_t *msg_buffer;

  /*! length of binary message */
  size_t msg_size;

  /*! processing callbacks can set this variable to prevent forwarding */
  bool _do_not_forward;

  /* only for address TLV blocks */

  /*! address */
  struct netaddr addr;

  /*! pointer to binary address block */
  const uint8_t *addr_block_buffer;

  /*! address block size */
  size_t addr_block_size;

  /*! address TLV size */
  size_t addr_tlv_size;

  /*! index of address in address block */
  uint8_t addr_index;
};

/**
 * internal representation of a parsed address block
 */
struct rfc5444_reader_addrblock_entry {
  /*! single linked list of address blocks */
  struct list_entity list_node;

  /*! corresponding tlv block */
  struct avl_tree tlvblock;

  /*! number of addresses */
  uint8_t num_addr;

  /*! start index of middle part of address */
  uint8_t mid_start;

  /*! length of middle part of address */
  uint8_t mid_len;

  /**
   * pointer to list of prefixes, NULL if same prefix length
   * for all addresses
   */
  const uint8_t *prefixes;

  /*! pointer to array of middle address parts */
  const uint8_t *mid_src;

  /*! storage for head/tail of address */
  uint8_t addr[RFC5444_MAX_ADDRLEN];

  /*! storage for fixed prefix length */
  uint8_t prefixlen;

  /*! pointer to binary address block data */
  const uint8_t *addr_block_ptr;

  /*! size of address block */
  size_t addr_block_size;

  /*! size of tlv block for addresses */
  size_t addr_tlv_size;

  /*! bitarray to mark addresses that shall be skipped by the next handler */
  struct bitmap256 dropAddr;
};

/**
 * representation of a consumer for a tlv block and context
 */
struct rfc5444_reader_tlvblock_consumer_entry {
  /*! sorted list of consumer entries */
  struct list_entity _node;

  /*! set by the consumer if the entry is mandatory */
  bool mandatory;

  /*! set by the consumer to define the type of the tlv */
  uint8_t type;

  /*! set by the consumer to define the required type extension */
  uint8_t type_ext;

  /*! set by the consumer to require a certain type extension */
  bool match_type_ext;

  /*! set by the consumer to define the minimum length of the TLVs value */
  uint16_t min_length;

  /**
   * set by the consumer to define the maximum length of the TLVs value.
   * If smaller than min_length, this value will be assumed the same as
   * min_length.
   */
  uint16_t max_length;

  /*! set by consumer to activate length checking */
  bool match_length;

  /*! set by the consumer to make the parser copy the TLV value into a private buffer */
  void *copy_value;

  /**
   * set by parser as a pointer to the TLVs data
   * This pointer will only be valid during the runtime of the
   * corresponding callback. Do not copy the pointer into a global
   * variable
   */
  struct rfc5444_reader_tlvblock_entry *tlv;

  /*! set by the consumer callback together with a RFC5444_DROP_TLV to drop this TLV */
  bool drop;
};

/**
 * representation of a tlv block consumer
 */
struct rfc5444_reader_tlvblock_consumer {
  /*! sorted tree of consumers for a packet, message or address tlv block */
  struct avl_node _node;

  /*! order of this consumer */
  int order;

  /*! if true the consumer will be called for all messages */
  bool default_msg_consumer;

  /**
   * message id of message and address consumers, ignored if
   * default_msg_consumer is true
   */
  uint8_t msg_id;

  /*! true if an address block consumer, false if message/packet consumer */
  bool addrblock_consumer;

  /*! List of sorted consumer entries */
  struct list_entity _consumer_list;

  /* consumer for TLVblock context start and end*/
  /**
   * Callback triggered at the start of this context
   * @param context message or address context
   * @return rfc5444 result
   */
  enum rfc5444_result (*start_callback)(struct rfc5444_reader_tlvblock_context *context);

  /**
   * Callback triggered at the start of this context
   * @param context packet, message or address context
   * @param dropped true if the context will be dropped
   * @return rfc5444 result
   */
  enum rfc5444_result (*end_callback)(struct rfc5444_reader_tlvblock_context *context, bool dropped);

  /**
   * Callback triggered once for each tlv in context
   * @param entry tlvblock entry
   * @param context packet, message or address context
   * @return rfc5444 result
   */
  enum rfc5444_result (*tlv_callback)(
    struct rfc5444_reader_tlvblock_entry *entry, struct rfc5444_reader_tlvblock_context *context);

  /**
   * Callback triggered when all requested TLVs have been parser
   * and no constraint was violated.
   * @param context packet, message or address context
   * @return rfc5444 result
   */
  enum rfc5444_result (*block_callback)(struct rfc5444_reader_tlvblock_context *context);
  /**
   * Callback triggered when all requested TLVs have been parser
   * and a constraint was violated.
   * @param context packet, message or address context
   * @return rfc5444 result
   */
  enum rfc5444_result (*block_callback_failed_constraints)(struct rfc5444_reader_tlvblock_context *context);
};

/**
 * representation of the internal state of a rfc5444 parser
 */
struct rfc5444_reader {
  /*! sorted tree of packet consumers */
  struct avl_tree packet_consumer;

  /*! sorted tree of message/addr consumers */
  struct avl_tree message_consumer;

  /**
   * Callback triggered when a message should be forwarded
   * @param context message context
   * @param buffer pointer to message
   * @param length length of message
   */
  void (*forward_message)(struct rfc5444_reader_tlvblock_context *context, const uint8_t *buffer, size_t length);

  /**
   * Callback to allocate a tlvblock entry
   * @return tlvblock entry, NULL if out of memory
   */
  struct rfc5444_reader_tlvblock_entry *(*malloc_tlvblock_entry)(void);

  /**
   * Callback to allocate an addressblock entry
   * @return addressblock entry, NULL if out of memory
   */
  struct rfc5444_reader_addrblock_entry *(*malloc_addrblock_entry)(void);

  /**
   * Free a tlvblock entry
   * @param entry tlvblock entry to free
   */
  void (*free_tlvblock_entry)(struct rfc5444_reader_tlvblock_entry *entry);

  /**
   * Free an addressblock entry
   * @param entry addressblock entry to free
   */
  void (*free_addrblock_entry)(struct rfc5444_reader_addrblock_entry *entry);
};

EXPORT void rfc5444_reader_init(struct rfc5444_reader *);
EXPORT void rfc5444_reader_cleanup(struct rfc5444_reader *);
EXPORT void rfc5444_reader_add_packet_consumer(struct rfc5444_reader *parser,
  struct rfc5444_reader_tlvblock_consumer *consumer, struct rfc5444_reader_tlvblock_consumer_entry *entries,
  size_t entrycount);
EXPORT void rfc5444_reader_add_message_consumer(struct rfc5444_reader *, struct rfc5444_reader_tlvblock_consumer *,
  struct rfc5444_reader_tlvblock_consumer_entry *, size_t entrycount);

EXPORT void rfc5444_reader_remove_packet_consumer(struct rfc5444_reader *, struct rfc5444_reader_tlvblock_consumer *);
EXPORT void rfc5444_reader_remove_message_consumer(struct rfc5444_reader *, struct rfc5444_reader_tlvblock_consumer *);

EXPORT enum rfc5444_result rfc5444_reader_handle_packet(struct rfc5444_reader *parser, const uint8_t *buffer, size_t length);

/**
 * Call to set the do-not-forward flag in message context
 * @param context pointer to message context
 */
static INLINE void
rfc5444_reader_prevent_forwarding(struct rfc5444_reader_tlvblock_context *context) {
  context->_do_not_forward = true;
}

#endif /* RFC5444_PARSER_H_ */
