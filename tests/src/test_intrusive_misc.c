/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include <unity.h>

static void test_crc_streamed(void)
{
    uint32_t crc = crc_add(CRC_INITIAL, 3, "123");
    crc          = crc_add(crc, 6, "456789");
    TEST_ASSERT_EQUAL_UINT32(0x1CF96D7CUL, crc);
    TEST_ASSERT_EQUAL_UINT32(0xE3069283UL, crc ^ CRC_OUTPUT_XOR);
    crc = crc_add(crc, 4, "\x83\x92\x06\xE3"); // Least significant byte first.
    TEST_ASSERT_EQUAL_UINT32(CRC_RESIDUE_BEFORE_OUTPUT_XOR, crc);
    TEST_ASSERT_EQUAL_UINT32(CRC_RESIDUE_AFTER_OUTPUT_XOR, crc ^ CRC_OUTPUT_XOR);
}

static void test_crc_unordered(void)
{
    {
        const uint32_t partials[] = {
            crc_partial(9, 0, 2, "12"),
            crc_partial(9, 2, 3, "345"),
            crc_partial(9, 5, 4, "6789"),
        };
        const uint32_t crc = crc_partial_finalize(9, partials[1] ^ partials[2] ^ partials[0]); // xor is commutative
        TEST_ASSERT_EQUAL_UINT32(0xE3069283UL, crc);
    }
    {
        const uint32_t partials[] = {
            crc_partial(13, 0, 2, "12"),
            crc_partial(13, 2, 3, "345"),
            crc_partial(13, 5, 4, "6789"),
            crc_partial(13, 9, 4, "\x83\x92\x06\xE3"),
        };
        const uint32_t crc = crc_partial_finalize(13, partials[1] ^ partials[3] ^ partials[2] ^ partials[0]);
        TEST_ASSERT_EQUAL_UINT32(CRC_RESIDUE_AFTER_OUTPUT_XOR, crc);
    }
}

static void test_list(void)
{
    typedef struct test_node_t
    {
        int                  value;
        udpard_list_member_t link;
    } test_node_t;

    udpard_list_t list = { .head = NULL, .tail = NULL };

    // Test 1: Empty list state
    TEST_ASSERT_NULL(list.head);
    TEST_ASSERT_NULL(list.tail);

    // Test 2: Enlist single item
    test_node_t node1 = { .value = 1, .link = { .next = NULL, .prev = NULL } };
    enlist_head(&list, &node1.link);
    TEST_ASSERT_EQUAL(&node1.link, list.head);
    TEST_ASSERT_EQUAL(&node1.link, list.tail);
    TEST_ASSERT_NULL(node1.link.next);
    TEST_ASSERT_NULL(node1.link.prev);

    // Test 3: Enlist second item (should become head)
    test_node_t node2 = { .value = 2, .link = { .next = NULL, .prev = NULL } };
    enlist_head(&list, &node2.link);
    TEST_ASSERT_EQUAL(&node2.link, list.head);
    TEST_ASSERT_EQUAL(&node1.link, list.tail);
    TEST_ASSERT_EQUAL(&node1.link, node2.link.next);
    TEST_ASSERT_NULL(node2.link.prev);
    TEST_ASSERT_NULL(node1.link.next);
    TEST_ASSERT_EQUAL(&node2.link, node1.link.prev);

    // Test 4: Enlist third item (should become new head)
    test_node_t node3 = { .value = 3, .link = { .next = NULL, .prev = NULL } };
    enlist_head(&list, &node3.link);
    TEST_ASSERT_EQUAL(&node3.link, list.head);
    TEST_ASSERT_EQUAL(&node1.link, list.tail);
    TEST_ASSERT_EQUAL(&node2.link, node3.link.next);
    TEST_ASSERT_NULL(node3.link.prev);
    TEST_ASSERT_EQUAL(&node1.link, node2.link.next);
    TEST_ASSERT_EQUAL(&node3.link, node2.link.prev);

    // Test 5: Delist middle item
    delist(&list, &node2.link);
    TEST_ASSERT_EQUAL(&node3.link, list.head);
    TEST_ASSERT_EQUAL(&node1.link, list.tail);
    TEST_ASSERT_EQUAL(&node1.link, node3.link.next);
    TEST_ASSERT_NULL(node3.link.prev);
    TEST_ASSERT_NULL(node1.link.next);
    TEST_ASSERT_EQUAL(&node3.link, node1.link.prev);
    TEST_ASSERT_NULL(node2.link.next);
    TEST_ASSERT_NULL(node2.link.prev);

    // Test 6: Re-enlist previously delisted item (should become head)
    enlist_head(&list, &node2.link);
    TEST_ASSERT_EQUAL(&node2.link, list.head);
    TEST_ASSERT_EQUAL(&node1.link, list.tail);
    TEST_ASSERT_EQUAL(&node3.link, node2.link.next);
    TEST_ASSERT_NULL(node2.link.prev);

    // Test 7: Move existing item to head (enlist_head can be used for moving)
    enlist_head(&list, &node1.link);
    TEST_ASSERT_EQUAL(&node1.link, list.head);
    TEST_ASSERT_EQUAL(&node3.link, list.tail);
    TEST_ASSERT_EQUAL(&node2.link, node1.link.next);
    TEST_ASSERT_NULL(node1.link.prev);
    TEST_ASSERT_EQUAL(&node3.link, node2.link.next);
    TEST_ASSERT_EQUAL(&node1.link, node2.link.prev);
    TEST_ASSERT_NULL(node3.link.next);
    TEST_ASSERT_EQUAL(&node2.link, node3.link.prev);

    // Test 8: Delist head
    delist(&list, &node1.link);
    TEST_ASSERT_EQUAL(&node2.link, list.head);
    TEST_ASSERT_EQUAL(&node3.link, list.tail);
    TEST_ASSERT_NULL(node1.link.next);
    TEST_ASSERT_NULL(node1.link.prev);

    // Test 9: Delist tail
    delist(&list, &node3.link);
    TEST_ASSERT_EQUAL(&node2.link, list.head);
    TEST_ASSERT_EQUAL(&node2.link, list.tail);
    TEST_ASSERT_NULL(node2.link.next);
    TEST_ASSERT_NULL(node2.link.prev);
    TEST_ASSERT_NULL(node3.link.next);
    TEST_ASSERT_NULL(node3.link.prev);

    // Test 10: Delist last item
    delist(&list, &node2.link);
    TEST_ASSERT_NULL(list.head);
    TEST_ASSERT_NULL(list.tail);
    TEST_ASSERT_NULL(node2.link.next);
    TEST_ASSERT_NULL(node2.link.prev);

    // Test 11: Delist from empty list (should be safe)
    delist(&list, &node1.link);
    TEST_ASSERT_NULL(list.head);
    TEST_ASSERT_NULL(list.tail);

    // Test 12: LIST_MEMBER macro
    enlist_head(&list, &node1.link);
    enlist_head(&list, &node2.link);
    enlist_head(&list, &node3.link);
    test_node_t* owner = LIST_MEMBER(list.head, test_node_t, link);
    TEST_ASSERT_EQUAL(&node3, owner);
    TEST_ASSERT_EQUAL(3, owner->value);

    // Test 13: LIST_TAIL macro
    test_node_t* tail_owner = LIST_TAIL(list, test_node_t, link);
    TEST_ASSERT_EQUAL(&node1, tail_owner);
    TEST_ASSERT_EQUAL(1, tail_owner->value);

    // Test 14: LIST_MEMBER with NULL
    test_node_t* null_owner = LIST_MEMBER(NULL, test_node_t, link);
    TEST_ASSERT_NULL(null_owner);

    // Test 15: Traverse list from head to tail
    test_node_t* current = LIST_MEMBER(list.head, test_node_t, link);
    TEST_ASSERT_EQUAL(3, current->value);
    current = LIST_MEMBER(current->link.next, test_node_t, link);
    TEST_ASSERT_EQUAL(2, current->value);
    current = LIST_MEMBER(current->link.next, test_node_t, link);
    TEST_ASSERT_EQUAL(1, current->value);
    current = LIST_MEMBER(current->link.next, test_node_t, link);
    TEST_ASSERT_NULL(current);

    // Clean up
    delist(&list, &node1.link);
    delist(&list, &node2.link);
    delist(&list, &node3.link);
    TEST_ASSERT_NULL(list.head);
    TEST_ASSERT_NULL(list.tail);
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_crc_streamed);
    RUN_TEST(test_list);
    RUN_TEST(test_crc_unordered);
    return UNITY_END();
}
