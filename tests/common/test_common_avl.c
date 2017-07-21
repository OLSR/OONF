
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "common/avl.h"
#include "common/avl_comp.h"
#include "cunit/cunit.h"

struct tree_element {
  uint32_t value;
  struct avl_node node;
};

#define COUNT 6

static struct avl_tree head;
static struct tree_element nodes[COUNT], additional_node1, additional_node2;

static void clear_elements(void) {
  uint32_t i;

  memset(&head, 0, sizeof(head));
  memset(nodes, 0, sizeof(nodes));
  memset(&additional_node1, 0, sizeof(additional_node1));
  memset(&additional_node2, 0, sizeof(additional_node2));

  for (i=0; i<COUNT; i++) {
    nodes[i].value = i+1;
  }
}

static void add_elements(struct tree_element *elements, bool do_random) {
  uint32_t i;
  bool added[COUNT];

  if (do_random) {
    for (i=0; i<COUNT; i++) {
      added[i] = false;
    }

    for (i=0; i<COUNT; i++) {
      int num = rand() % COUNT;

      while (added[num]) {
        num = (num + 1) % COUNT;
      }

      elements[num].node.key = &elements[num].value;
      avl_insert(&head, &elements[num].node);
      added[num] = true;
    }
  }
  else {
    for (i=0; i<COUNT; i++) {
      elements[i].node.key = &elements[i].value;
      avl_insert(&head, &elements[i].node);
    }
  }
}

#if 0
static void print_tree_int(struct tree_element *e, int step) {
  int i;

  for (i=0; i<step; i++) {
    printf("\t");
  }
  printf("%d: balance %d, leader %d\n", e->value, e->node.balance, e->node.leader);

  if (e->node.left) {
    for (i=0; i<step; i++) {
      printf("\t");
    }
    printf("=> left\n");
    print_tree_int(container_of(e->node.left, struct tree_element, node), step+1);
  }
  if (e->node.right) {
    for (i=0; i<step; i++) {
      printf("\t");
    }
    printf("=> right\n");
    print_tree_int(container_of(e->node.right, struct tree_element, node), step+1);
  }
}

static void print_tree(void) {
  printf("Tree count: %d\n", head.count);
  print_tree_int(container_of(head.root, struct tree_element, node), 0);
}
#endif

static uint32_t check_tree_int(const char *name, uint32_t line, struct tree_element *e) {
  struct tree_element *t;
  int left = 0, right = 0;

  if (e->node.parent) {
    CHECK_NAMED_TRUE(e->node.parent->left == &e->node || e->node.parent->right == &e->node,
        name, line, "parent backlink missing for element %d", e->value);

    if (e->node.parent->left == &e->node) {
      t = container_of(e->node.parent, struct tree_element, node);

      CHECK_NAMED_TRUE(e->value < t->value, name, line,
          "Value of parent (%d) <= value of left child (%d)", t->value, e->value);
    }
    if (e->node.parent->right == &e->node) {
      t = container_of(e->node.parent, struct tree_element, node);

      CHECK_NAMED_TRUE(e->value > t->value, name, line,
          "Value of parent (%d) <= value of right child (%d)", t->value, e->value);
    }
  }

  if (e->node.left) {
    t = container_of(e->node.left, struct tree_element, node);
    left = check_tree_int(name, line, t);
  }
  if (e->node.right) {
    t = container_of(e->node.right, struct tree_element, node);
    right = check_tree_int(name, line, t);
  }

  CHECK_NAMED_TRUE(left - right >= -1 && left - right <= 1, name, line,
      "Subtree (%d) unbalanced: left %d, right %d", e->value, left, right);

  if (e->node.balance == 0) {
    CHECK_NAMED_TRUE(left == right, name, line, "Subtree (%d) balance cache wrong (%d): left %d, right %d",
        e->value, e->node.balance, left, right);
  }
  else if (e->node.balance == -1) {
    CHECK_NAMED_TRUE(left - 1== right, name, line, "Subtree (%d) balance cache wrong (%d): left %d, right %d",
        e->value, e->node.balance, left, right);
  }
  else if (e->node.balance == 1) {
    CHECK_NAMED_TRUE(left == right - 1, name, line, "Subtree (%d) balance cache wrong (%d): left %d, right %d",
        e->value, e->node.balance, left, right);
  }
  else {
    CHECK_NAMED_TRUE(false, name, line, "Subtree (%d) with bad balance cache (%d)", e->value, e->node.balance);
  }

  if (left > right) {
    return left + 1;
  }
  else {
    return right + 1;
  }
}

static void check_tree(const char *name, uint32_t line) {
  uint32_t value;
  struct list_entity *ptr;
  struct tree_element *t;

  /* check tree head */
  CHECK_NAMED_TRUE((head.root != NULL) == (head.count > 0), name, line, "No root pointer, but tree not empty");
  CHECK_NAMED_TRUE(head.list_head.next != NULL, name, line, "bad next-iterator");
  CHECK_NAMED_TRUE(head.list_head.prev != NULL, name, line, "bad prev-iterator");
  CHECK_NAMED_TRUE((head.root == NULL) == list_is_empty(&head.list_head), name, line, "iterator list empty, but tree not empty");
  if (head.count == 0 || head.root == NULL
      || head.list_head.next == NULL || head.list_head.prev == NULL || list_is_empty(&head.list_head)) {
    return;
  }

  /* check next-iterator */
  t = container_of(head.list_head.next, struct tree_element, node.list);
  value = t->value;
  for (ptr = head.list_head.next; ptr != NULL && ptr != &head.list_head; ptr = ptr->next) {
    t = container_of(ptr, struct tree_element, node.list);
    CHECK_NAMED_TRUE(t->value >= value, name, line, "next-iterator (%d < %d)", t->value, value);
    value = t->value;
  }
  CHECK_NAMED_TRUE(ptr == &head.list_head, name, line, "next-iterator contained NULL ptr");

  /* check next-iterator */
  t = container_of(head.list_head.prev, struct tree_element, node.list);
  value = t->value;
  for (ptr = head.list_head.prev; ptr != NULL && ptr != &head.list_head; ptr = ptr->prev) {
    t = container_of(ptr, struct tree_element, node.list);
    CHECK_NAMED_TRUE(t->value <= value, name, line, "prev-iterator (%d > %d)", t->value, value);
    value = t->value;
  }
  CHECK_NAMED_TRUE(ptr == &head.list_head, name, line, "prev-iterator contained NULL ptr");

  /* check tree structure */
  check_tree_int(name, line, container_of(head.root, struct tree_element, node));
}

static void test_insert_nondup(bool do_random) {
  START_TEST();
  avl_init(&head, avl_comp_uint32, false);
  add_elements(nodes, do_random);

  CHECK_TRUE(head.count == COUNT, "tree not completely filled");
  check_tree(__func__, __LINE__);
  // print_tree();

  /* try to add duplicate */
  additional_node1.value = nodes[3].value;
  additional_node1.node.key = &additional_node1.value;
  CHECK_TRUE(avl_insert(&head, &additional_node1.node) != 0, "insert duplicate (in non-dup tree) was successful");

  CHECK_TRUE(head.count == COUNT, "tree not completely filled after insert");
  check_tree(__func__, __LINE__);

  END_TEST();
}

static void test_insert_dup(bool do_random) {
  START_TEST();
  avl_init(&head, avl_comp_uint32, true);
  add_elements(nodes, do_random);

  CHECK_TRUE(head.count == COUNT, "tree not completely filled");
  check_tree(__func__, __LINE__);
  // print_tree();

  /* add duplicate */
  additional_node1.value = nodes[3].value;
  additional_node1.node.key = &additional_node1.value;
  CHECK_TRUE(avl_insert(&head, &additional_node1.node) == 0, "insert duplicate (in dup tree) was not successful");

  /* prepare array for check */
  CHECK_TRUE(head.count == COUNT+1, "tree not completely filled after insert");
  check_tree(__func__, __LINE__);
  // print_tree();

  END_TEST();
}

static void test_find(bool do_random) {
  uint32_t i;

  START_TEST();
  avl_init(&head, avl_comp_uint32, true);
  add_elements(nodes, do_random);

  /* search for all existing values */
  for (i=0; i<COUNT; i++) {
    CHECK_TRUE(avl_find(&head, &nodes[i].value) == &nodes[i].node, "node of element %d not found", i);
    CHECK_TRUE(avl_find_element(&head, &nodes[i], &nodes[i], node) == &nodes[i], "element %d not found", i);
  }
  i = 255;
  CHECK_TRUE(avl_find(&head, &i) == NULL, "non-existing element found: %d", i);

  /* add duplicate */
  additional_node1.value = nodes[3].value;
  additional_node1.node.key = &additional_node1.value;
  CHECK_TRUE(avl_insert(&head, &additional_node1.node) == 0, "insert duplicate (in dup tree) was not successful");

  /* search for all existing values in tree with duplicate */
  for (i=0; i<COUNT; i++) {
    CHECK_TRUE(avl_find(&head, &nodes[i].value) != NULL, "element %d not found", i);
  }
  i = 255;
  CHECK_TRUE(avl_find(&head, &i) == NULL, "non-existing element found: %d", i);

  END_TEST();
}

static void test_delete_nondup(bool do_random) {
  START_TEST();

  avl_init(&head, avl_comp_uint32, false);
  add_elements(nodes, do_random);

  avl_remove(&head, &nodes[2].node);
  CHECK_TRUE(head.count == COUNT-1, "tree has wrong count after delete");
  check_tree(__func__, __LINE__);

  END_TEST();
}

static void test_delete_dup(bool do_random) {
  START_TEST();

  avl_init(&head, avl_comp_uint32, true);
  add_elements(nodes, do_random);

  /* add duplicate */
  additional_node1.value = nodes[3].value;
  additional_node1.node.key = &additional_node1.value;
  CHECK_TRUE(avl_insert(&head, &additional_node1.node) == 0, "insert duplicate (in dup tree) was not successful");

  avl_remove(&head, &nodes[3].node);
  CHECK_TRUE(head.count == COUNT, "tree has wrong count after delete of one duplicate");
  check_tree(__func__, __LINE__);

  END_TEST();
}

static void test_greaterequal(bool do_random) {
  uint32_t i;
  START_TEST();

  /* create tree with 1,2,4,5,6 */
  avl_init(&head, avl_comp_uint32, true);
  add_elements(nodes, do_random);
  avl_remove(&head, &nodes[2].node);

  /* find >= 2 */
  i = 2;
  CHECK_TRUE(avl_find_greaterequal(&head, &i) == &nodes[1].node, "node of element >= 2 not found");
  CHECK_TRUE(avl_find_ge_element(&head, &i, &nodes[1], node) == &nodes[1], "element >= 2 not found");

  /* find >= 3 */
  i = 3;
  CHECK_TRUE(avl_find_greaterequal(&head, &i) == &nodes[3].node, "node of element >= 3 not found");
  CHECK_TRUE(avl_find_ge_element(&head, &i, &nodes[3], node) == &nodes[3], "element >= 3 not found");

  /* find >= 4 */
  i = 4;
  CHECK_TRUE(avl_find_greaterequal(&head, &i) == &nodes[3].node, "node of element >= 4 not found");
  CHECK_TRUE(avl_find_ge_element(&head, &i, &nodes[3], node) == &nodes[3], "element >= 4 not found");

  /* find >= 255 */
  i = 255;
  CHECK_TRUE(avl_find_greaterequal(&head, &i) == NULL, "node of element >= 255 found");
  CHECK_TRUE(avl_find_ge_element(&head, &i, &nodes[3], node) == NULL, "element >= 255 found");

  /* add duplicate with value 4 */
  additional_node1.value = 4;
  additional_node1.node.key = &additional_node1.value;
  avl_insert(&head, &additional_node1.node);

  /* find >= 2 */
  i = 2;
  CHECK_TRUE(avl_find_greaterequal(&head, &i) == &nodes[1].node, "node of element >= 2 not found (d)");
  CHECK_TRUE(avl_find_ge_element(&head, &i, &nodes[1], node) == &nodes[1], "element >= 2 not found (d)");

  /* find >= 3 */
  i = 3;
  CHECK_TRUE(avl_find_greaterequal(&head, &i) == &nodes[3].node, "node of element >= 3 not found (d)");
  CHECK_TRUE(avl_find_ge_element(&head, &i, &nodes[3], node) == &nodes[3], "element >= 3 not found (d)");

  /* find >= 4 */
  i = 4;
  CHECK_TRUE(avl_find_greaterequal(&head, &i) == &nodes[3].node, "node of element >= 4 not found (d)");
  CHECK_TRUE(avl_find_ge_element(&head, &i, &nodes[3], node) == &nodes[3], "element >= 4 not found (d)");

  /* find >= 255 */
  i = 255;
  CHECK_TRUE(avl_find_greaterequal(&head, &i) == NULL, "node of element >= 255 found (d)");
  CHECK_TRUE(avl_find_ge_element(&head, &i, &nodes[3], node) == NULL, "element >= 255 found (d)");

  END_TEST();
}

static void test_lessequal(bool do_random) {
  int i;
  START_TEST();

  /* create tree with 1,2,4,5,6 */
  avl_init(&head, avl_comp_uint32, true);
  add_elements(nodes, do_random);
  avl_remove(&head, &nodes[2].node);

  /* find <= 0 */
  i = 0;
  CHECK_TRUE(avl_find_lessequal(&head, &i) == NULL, "node of element <= 0 found");
  CHECK_TRUE(avl_find_le_element(&head, &i, &nodes[3], node) == NULL, "element <= 0 found");

  /* find <= 2 */
  i = 2;
  CHECK_TRUE(avl_find_lessequal(&head, &i) == &nodes[1].node, "node of element <= 2 not found");
  CHECK_TRUE(avl_find_le_element(&head, &i, &nodes[1], node) == &nodes[1], "element <= 2 not found");

  /* find <= 3 */
  i = 3;
  CHECK_TRUE(avl_find_lessequal(&head, &i) == &nodes[1].node, "node of element <= 3 not found");
  CHECK_TRUE(avl_find_le_element(&head, &i, &nodes[1], node) == &nodes[1], "element <= 3 not found");

  /* find <= 4 */
  i = 4;
  CHECK_TRUE(avl_find_lessequal(&head, &i) == &nodes[3].node, "node of element <= 4 not found");
  CHECK_TRUE(avl_find_le_element(&head, &i, &nodes[3], node) == &nodes[3], "element <= 4 not found");

  /* add duplicate with value 4 */
  additional_node1.value = 4;
  additional_node1.node.key = &additional_node1.value;
  avl_insert(&head, &additional_node1.node);

  /* find <= 0 */
  i = 0;
  CHECK_TRUE(avl_find_lessequal(&head, &i) == NULL, "node of element <= 0 found (d)");
  CHECK_TRUE(avl_find_le_element(&head, &i, &nodes[3], node) == NULL, "element <= 0 found (d)");

  /* find <= 2 */
  i = 2;
  CHECK_TRUE(avl_find_lessequal(&head, &i) == &nodes[1].node, "node of element <= 2 not found (d)");
  CHECK_TRUE(avl_find_le_element(&head, &i, &nodes[1], node) == &nodes[1], "element <= 2 not found (d)");

  /* find <= 3 */
  i = 3;
  CHECK_TRUE(avl_find_lessequal(&head, &i) == &nodes[1].node, "node of element <= 3 not found (d)");
  CHECK_TRUE(avl_find_le_element(&head, &i, &nodes[1], node) == &nodes[1], "element <= 3 not found (d)");

  /* find <= 4 */
  i = 4;
  CHECK_TRUE(avl_find_lessequal(&head, &i) == &additional_node1.node, "node of element <= 4 not found correctly (d)");
  CHECK_TRUE(avl_find_le_element(&head, &i, &additional_node1, node) == &additional_node1, "element <= 4 not found correctly (d)");

  END_TEST();
}

static void test_conditions(bool do_random) {
  START_TEST();

  avl_init(&head, avl_comp_uint32, true);
  CHECK_TRUE(avl_is_empty(&head), "tree should be empty");

  add_elements(nodes, do_random);
  CHECK_TRUE(!avl_is_empty(&head), "tree should not be empty");

  CHECK_TRUE(avl_is_first(&head, &nodes[0].node), "element 1 should be first");
  CHECK_TRUE(!avl_is_first(&head, &nodes[1].node), "element 2 should not be first");

  CHECK_TRUE(avl_is_last(&head, &nodes[COUNT-1].node), "element %d should be first", COUNT);
  CHECK_TRUE(!avl_is_last(&head, &nodes[0].node), "element 1 should not be first");

  END_TEST();
}

static void test_element_functions(bool do_random) {
  struct tree_element *e;
  START_TEST();

  avl_init(&head, avl_comp_uint32, true);
  add_elements(nodes, do_random);

  CHECK_TRUE(avl_first_element(&head, e, node) == &nodes[0], "Element 1 should be first");
  CHECK_TRUE(avl_last_element(&head, e, node) == &nodes[COUNT-1], "Element %d should be first", COUNT);

  CHECK_TRUE(avl_next_element(&nodes[0], node) == &nodes[1], "Element 2 is not next of element 1");
  CHECK_TRUE(avl_prev_element(&nodes[2], node) == &nodes[1], "Element 2 is not prev of element 3");
  END_TEST();
}

static void test_for_each_macros(bool do_random) {
  struct tree_element *e;
  int i;

  START_TEST();
  avl_init(&head, avl_comp_uint32, true);
  add_elements(nodes, do_random);

  i = 0;
  avl_for_each_element(&head, e, node) {
    CHECK_TRUE(e == &nodes[i], "for_each iteration %d failed", i);
    i++;
  }
  CHECK_TRUE(i == COUNT, "for_each only had %d of %d iterations", i, COUNT);

  i = 1;
  avl_for_element_range(&nodes[1], &nodes[4], e, node) {
    CHECK_TRUE(e == &nodes[i], "for_element_range iteration %d failed", i);
    i++;
  }
  CHECK_TRUE(i == 5, "for_element_range only had %d of %d iterations", i-1, 4);

  i = 1;
  avl_for_element_to_last(&head, &nodes[1], e, node) {
    CHECK_TRUE(e == &nodes[i], "element_to_last iteration %d failed", i);
    i++;
  }
  CHECK_TRUE(i == COUNT, "element_to_last only had %d of %d iterations", i-1, 5);

  i = 0;
  avl_for_first_to_element(&head, &nodes[4], e, node) {
    CHECK_TRUE(e == &nodes[i], "first_to_element iteration %d failed", i);
    i++;
  }
  CHECK_TRUE(i == 5, "first_to_element only had %d of %d iterations", i-1, 5);
  END_TEST();
}

static void test_for_each_reverse_macros(bool do_random) {
  struct tree_element *e;
  int i,j;

  START_TEST();
  avl_init(&head, avl_comp_uint32, true);
  add_elements(nodes, do_random);

  i = 0;
  j = COUNT - 1;
  avl_for_each_element_reverse(&head, e, node) {
    CHECK_TRUE(e == &nodes[j], "for_each iteration %d failed", i);
    i++;
    j--;
  }
  CHECK_TRUE(i == COUNT, "for_each only had %d of %d iterations", i, COUNT);

  i = 1;
  j = 4;
  avl_for_element_range_reverse(&nodes[1], &nodes[4], e, node) {
    CHECK_TRUE(e == &nodes[j], "for_element_range iteration %d failed", i);
    i++;
    j--;
  }
  CHECK_TRUE(i == 5, "for_element_range only had %d of %d iterations", i-1, 4);

  i = 1;
  j = COUNT - 1;
  avl_for_element_to_last_reverse(&head, &nodes[1], e, node) {
    CHECK_TRUE(e == &nodes[j], "element_to_last iteration %d failed", i);
    i++;
    j--;
  }
  CHECK_TRUE(i == COUNT, "element_to_last only had %d of %d iterations", i-1, 5);

  i = 0;
  j = 4;
  avl_for_first_to_element_reverse(&head, &nodes[4], e, node) {
    CHECK_TRUE(e == &nodes[j], "first_to_element iteration %d failed", i);
    i++;
    j--;
  }
  CHECK_TRUE(i == 5, "first_to_element only had %d of %d iterations", i-1, 5);

  END_TEST();
}

static void test_for_each_save_macro(bool do_random) {
  struct tree_element *e, *ptr;
  int i;

  START_TEST();
  avl_init(&head, avl_comp_uint32, true);
  add_elements(nodes, do_random);

  i = 0;
  avl_for_each_element_safe(&head, e, node, ptr) {
    CHECK_TRUE(e == &nodes[i], "for_each_save iteration %d failed", i);
    avl_remove(&head, &e->node);
    i++;
  }
  CHECK_TRUE(i == COUNT, "for_each_save only had %d of %d iterations", i, COUNT);
  CHECK_TRUE(avl_is_empty(&head), "for_each_save tree not empty after loop with delete");
  END_TEST();
}

static void test_for_each_reverse_save_macro(bool do_random) {
  struct tree_element *e, *ptr;
  int i,j;

  START_TEST();
  avl_init(&head, avl_comp_uint32, true);
  add_elements(nodes, do_random);

  i = 0;
  j = COUNT - 1;
  avl_for_each_element_reverse_safe(&head, e, node, ptr) {
    CHECK_TRUE(e == &nodes[j], "for_each_save iteration %d failed", i);
    avl_remove(&head, &e->node);
    i++;
    j--;
  }
  CHECK_TRUE(i == COUNT, "for_each_save only had %d of %d iterations", i, COUNT);
  CHECK_TRUE(avl_is_empty(&head), "for_each_save tree not empty after loop with delete");
  END_TEST();
}

static void test_remove_all_macro(bool do_random) {
  struct tree_element *e, *ptr;
  uint32_t i;

  START_TEST();
  avl_init(&head, avl_comp_uint32, true);
  add_elements(nodes, do_random);

  i = 0;
  avl_remove_all_elements(&head, e, node, ptr) {
    CHECK_TRUE(e == &nodes[i], "for_each_save iteration %u failed", i);
    i++;
  }
  CHECK_TRUE(i == COUNT, "remove_all only had %u of %u iterations", i, COUNT);
  CHECK_TRUE(avl_is_empty(&head), "remove_all tree not empty after loop with delete");

  check_tree(__func__, __LINE__);

  END_TEST();
}

static void test_for_each_key_macros(void) {
  struct tree_element *e, *p;
  int key;
  uint32_t i;
  int result[4];

  START_TEST();
  avl_init(&head, avl_comp_uint32, true);

  key = 3;
  i = 0;
  avl_for_each_elements_with_key(&head, e, node, p, &key) {
    CHECK_TRUE(false, "elements returned by loop over empty tree");
  }

  /* add node with value 4 (4,4,4) */
  nodes[3].node.key = &nodes[3].value;
  avl_insert(&head, &nodes[3].node);

  /* add first duplicate with value 4 */
  additional_node1.value = 4;
  additional_node1.node.key = &additional_node1.value;
  avl_insert(&head, &additional_node1.node);

  /* add second duplicate with value 4 */
  additional_node2.value = 4;
  additional_node2.node.key = &additional_node2.value;
  avl_insert(&head, &additional_node2.node);

  key = 4;
  result[0] = 0;
  result[1] = 0;
  result[2] = 0;
  result[3] = 0;

  avl_for_each_elements_with_key(&head, e, node, p, &key) {
    if (e == &nodes[3]) {
      result[0]++;
    }
    else if (e == &additional_node1) {
      result[1]++;
    }
    else if (e == &additional_node2) {
      result[2]++;
    }
    else {
      result[3]++;
    }
  }

  CHECK_TRUE(result[0] >= 1, "First node with key=4 not returned");
  CHECK_TRUE(result[0] <= 1, "First node with key=4 returned multiple times");
  CHECK_TRUE(result[1] >= 1, "First node with key=4 not returned");
  CHECK_TRUE(result[1] <= 1, "First node with key=4 returned multiple times");
  CHECK_TRUE(result[2] >= 1, "First node with key=4 not returned");
  CHECK_TRUE(result[2] <= 1, "First node with key=4 returned multiple times");

  CHECK_TRUE(result[3] == 0, "Unknown node returned");

  /* add node with value 3 (3,4,4,4) */
  nodes[2].node.key = &nodes[2].value;
  avl_insert(&head, &nodes[2].node);

  key = 4;
  i = 0;
  result[0] = 0;
  result[1] = 0;
  result[2] = 0;
  result[3] = 0;

  avl_for_each_elements_with_key(&head, e, node, p, &key) {
    if (e == &nodes[3]) {
      result[0]++;
    }
    else if (e == &additional_node1) {
      result[1]++;
    }
    else if (e == &additional_node2) {
      result[2]++;
    }
    else {
      result[3]++;
    }
  }

  CHECK_TRUE(result[0] >= 1, "First node with key=4 not returned");
  CHECK_TRUE(result[0] <= 1, "First node with key=4 returned multiple times");
  CHECK_TRUE(result[1] >= 1, "First node with key=4 not returned");
  CHECK_TRUE(result[1] <= 1, "First node with key=4 returned multiple times");
  CHECK_TRUE(result[2] >= 1, "First node with key=4 not returned");
  CHECK_TRUE(result[2] <= 1, "First node with key=4 returned multiple times");

  CHECK_TRUE(result[3] == 0, "Unknown node returned");

  /* add node with value 5 (3,4,4,4,5) */
  nodes[4].node.key = &nodes[4].value;
  avl_insert(&head, &nodes[4].node);

  key = 4;
  i = 0;
  result[0] = 0;
  result[1] = 0;
  result[2] = 0;
  result[3] = 0;

  avl_for_each_elements_with_key(&head, e, node, p, &key) {
    if (e == &nodes[3]) {
      result[0]++;
    }
    else if (e == &additional_node1) {
      result[1]++;
    }
    else if (e == &additional_node2) {
      result[2]++;
    }
    else {
      result[3]++;
    }
  }

  CHECK_TRUE(result[0] >= 1, "First node with key=4 not returned");
  CHECK_TRUE(result[0] <= 1, "First node with key=4 returned multiple times");
  CHECK_TRUE(result[1] >= 1, "First node with key=4 not returned");
  CHECK_TRUE(result[1] <= 1, "First node with key=4 returned multiple times");
  CHECK_TRUE(result[2] >= 1, "First node with key=4 not returned");
  CHECK_TRUE(result[2] <= 1, "First node with key=4 returned multiple times");

  CHECK_TRUE(result[3] == 0, "Unknown node returned");

  key = 3;
  i = 0;
  avl_for_each_elements_with_key(&head, e, node, p, &key) {
    i++;

    switch (i) {
      case 1:
        CHECK_TRUE(e == &nodes[2], "First node with key=3 not returned first");
        break;
      default:
        CHECK_TRUE(false, "More than one element with key=3 returned");
        break;
    }
  }

  CHECK_TRUE(i>0, "Less than one nodes returned");

  key = 6;
  avl_for_each_elements_with_key(&head, e, node, p, &key) {
    CHECK_TRUE(false, "Element returned by loop over non-existing key");
  }

  END_TEST();
}

static int
compare_ints (const void *a, const void *b)
{
  const int *da = (const int *) a;
  const int *db = (const int *) b;

  return (*da > *db) - (*da < *db);
}

static void random_insert(uint32_t *array, uint32_t count) {
  uint32_t i,j;
  struct tree_element *e;

  for (i=0; i<count; i++) {
    uint32_t value = (uint32_t)rand();

    array[head.count] = value;
    qsort(array, head.count+1, sizeof(int), compare_ints);

    e = malloc(sizeof(*e));
    e->value = value;
    e->node.key = &e->value;
    avl_insert(&head, &e->node);

    check_tree(__func__, __LINE__);

    j = 0;
    avl_for_each_element(&head, e, node) {
      CHECK_TRUE(array[j++] == e->value, "check random delete order");
    }
  }
}

static void random_delete(uint32_t *array, uint32_t count) {
  uint32_t i, j;
  struct tree_element *e;

  for (i=0; i<count; i++) {
    j = (uint32_t)rand() % head.count;

    e = avl_find_element(&head, &array[j], e, node);
    CHECK_TRUE(e != NULL, "cannot find element during large test");
    if (e) {
      if (j != head.count - 1) {
        memmove(&array[j], &array[j+1], sizeof(int) * (head.count - j - 1));
      }

      avl_remove(&head, &e->node);
      free(e);

      check_tree(__func__, __LINE__);

      j = 0;
      avl_for_each_element(&head, e, node) {
        CHECK_TRUE(array[j++] == e->value, "check random delete order");
      }
    }
  }
}

/* insert/remove 1000's random numbers into tree and check if everything is okay */
static void test_random_insert(void) {
  uint32_t array[1000];
  struct tree_element *e, *ptr;

  srand(0);
  START_TEST();
  avl_init(&head, avl_comp_uint32, true);

  random_insert(array, 1000);
  random_delete(array, 500);
  random_insert(array, 400);
  random_delete(array, 600);

  avl_remove_all_elements(&head, e, node, ptr) {
    free(e);
  }
  END_TEST();
}

static void do_tests(bool do_random) {
  printf("Do %srandom tests.\n", do_random ? "" : "non ");

  test_insert_nondup(do_random);
  test_insert_dup(do_random);
  test_find(do_random);
  test_delete_nondup(do_random);
  test_delete_dup(do_random);
  test_greaterequal(do_random);
  test_lessequal(do_random);
  test_conditions(do_random);
  test_element_functions(do_random);
  test_for_each_macros(do_random);
  test_for_each_reverse_macros(do_random);
  test_for_each_save_macro(do_random);
  test_for_each_reverse_save_macro(do_random);
  test_remove_all_macro(do_random);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-overflow"
int main(int argc __attribute__ ((unused)), char **argv __attribute__ ((unused))) {
  int r;

  BEGIN_TESTING(clear_elements);

  do_tests(false);
  do_tests(true);
  test_random_insert();
  test_for_each_key_macros();

  r = FINISH_TESTING();
  return r;
}
#pragma GCC diagnostic pop
