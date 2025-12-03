/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include <unity.h>

static void test_rx_transfer_id_forward_distance(void)
{
    // Test 1: Same value (distance is 0)
    TEST_ASSERT_EQUAL_UINT64(0, rx_transfer_id_forward_distance(0, 0));
    TEST_ASSERT_EQUAL_UINT64(0, rx_transfer_id_forward_distance(100, 100));
    TEST_ASSERT_EQUAL_UINT64(0, rx_transfer_id_forward_distance(UINT64_MAX, UINT64_MAX));

    // Test 2: Simple forward distance (no wraparound)
    TEST_ASSERT_EQUAL_UINT64(1, rx_transfer_id_forward_distance(0, 1));
    TEST_ASSERT_EQUAL_UINT64(10, rx_transfer_id_forward_distance(5, 15));
    TEST_ASSERT_EQUAL_UINT64(100, rx_transfer_id_forward_distance(200, 300));
    TEST_ASSERT_EQUAL_UINT64(1000, rx_transfer_id_forward_distance(1000, 2000));

    // Test 3: Wraparound at UINT64_MAX
    TEST_ASSERT_EQUAL_UINT64(1, rx_transfer_id_forward_distance(UINT64_MAX, 0));
    TEST_ASSERT_EQUAL_UINT64(2, rx_transfer_id_forward_distance(UINT64_MAX, 1));
    TEST_ASSERT_EQUAL_UINT64(10, rx_transfer_id_forward_distance(UINT64_MAX - 5, 4));
    TEST_ASSERT_EQUAL_UINT64(100, rx_transfer_id_forward_distance(UINT64_MAX - 49, 50));

    // Test 4: Large forward distances
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, rx_transfer_id_forward_distance(0, UINT64_MAX));
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, rx_transfer_id_forward_distance(1, 0));
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX - 1, rx_transfer_id_forward_distance(0, UINT64_MAX - 1));
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, rx_transfer_id_forward_distance(2, 1));

    // Test 5: Half-way point (2^63)
    const uint64_t half = 1ULL << 63U;
    TEST_ASSERT_EQUAL_UINT64(half, rx_transfer_id_forward_distance(0, half));
    TEST_ASSERT_EQUAL_UINT64(half, rx_transfer_id_forward_distance(100, 100 + half));
    TEST_ASSERT_EQUAL_UINT64(half, rx_transfer_id_forward_distance(UINT64_MAX, half - 1));

    // Test 6: Backward is interpreted as large forward distance
    // Going from 10 to 5 is actually going forward by UINT64_MAX - 4
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX - 4, rx_transfer_id_forward_distance(10, 5));
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX - 9, rx_transfer_id_forward_distance(100, 90));

    // Test 7: Edge cases around 0
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, rx_transfer_id_forward_distance(1, 0));
    TEST_ASSERT_EQUAL_UINT64(1, rx_transfer_id_forward_distance(0, 1));

    // Test 8: Random large numbers
    TEST_ASSERT_EQUAL_UINT64(0x123456789ABCDEF0ULL - 0x0FEDCBA987654321ULL,
                             rx_transfer_id_forward_distance(0x0FEDCBA987654321ULL, 0x123456789ABCDEF0ULL));
}

static void test_rx_transfer_id_window_slide(void)
{
    rx_transfer_id_window_t obj = { 0 };

    // Test 1: Shift by 0 (no change)
    obj.head      = 100;
    obj.bitset[0] = 0x0000000001000001ULL;
    obj.bitset[1] = 0xF000000010000000ULL;
    obj.bitset[2] = 0x8000000100000002ULL;
    obj.bitset[3] = 0x3000001000000003ULL;
    rx_transfer_id_window_slide(&obj, 100);
    TEST_ASSERT_EQUAL_UINT64(100, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000001000001ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0xF000000010000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x8000000100000002ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x3000001000000003ULL, obj.bitset[3]);

    // Test 2: Shift by 1 bit (within same word)
    obj.head      = 100;
    obj.bitset[0] = 0x0000000001000001ULL;
    obj.bitset[1] = 0xF000000010000000ULL;
    obj.bitset[2] = 0x8000000100000002ULL;
    obj.bitset[3] = 0x3000001000000003ULL;
    rx_transfer_id_window_slide(&obj, 101);
    TEST_ASSERT_EQUAL_UINT64(101, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000002000002ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0xE000000020000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000200000005ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x6000002000000007ULL, obj.bitset[3]);

    // Test 3: Shift by multiple bits within word (shift by 5)
    obj.head      = 200;
    obj.bitset[0] = 0x0000000000000001ULL;
    obj.bitset[1] = 0x0000000000000002ULL;
    obj.bitset[2] = 0x0000000000000004ULL;
    obj.bitset[3] = 0x0000000000000008ULL;
    rx_transfer_id_window_slide(&obj, 205);
    TEST_ASSERT_EQUAL_UINT64(205, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000020ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000040ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000080ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000100ULL, obj.bitset[3]);

    // Test 4: Shift by 63 bits (maximum within word, with carry to next word)
    obj.head      = 300;
    obj.bitset[0] = 0x8000000000000001ULL;
    obj.bitset[1] = 0x8000000000000002ULL;
    obj.bitset[2] = 0x8000000000000004ULL;
    obj.bitset[3] = 0x8000000000000008ULL;
    rx_transfer_id_window_slide(&obj, 363);
    TEST_ASSERT_EQUAL_UINT64(363, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x8000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000001ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000002ULL, obj.bitset[3]);

    // Test 5: Shift by 64 (one full word)
    obj.head      = 100;
    obj.bitset[0] = 0x0000000002000002ULL;
    obj.bitset[1] = 0xE000000020000000ULL;
    obj.bitset[2] = 0x0000000200000005ULL;
    obj.bitset[3] = 0x6000002000000007ULL;
    rx_transfer_id_window_slide(&obj, 164);
    TEST_ASSERT_EQUAL_UINT64(164, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000002000002ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0xE000000020000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000200000005ULL, obj.bitset[3]);

    // Test 6: Shift by 65 bits (one word + 1 bit)
    obj.head      = 500;
    obj.bitset[0] = 0x0000000000000001ULL;
    obj.bitset[1] = 0x0000000000000003ULL;
    obj.bitset[2] = 0x0000000000000007ULL;
    obj.bitset[3] = 0x000000000000000FULL;
    rx_transfer_id_window_slide(&obj, 565);
    TEST_ASSERT_EQUAL_UINT64(565, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000002ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000006ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x000000000000000EULL, obj.bitset[3]);

    // Test 7: Shift by 128 (two full words)
    obj.head      = 1000;
    obj.bitset[0] = 0x1111111111111111ULL;
    obj.bitset[1] = 0x2222222222222222ULL;
    obj.bitset[2] = 0x3333333333333333ULL;
    obj.bitset[3] = 0x4444444444444444ULL;
    rx_transfer_id_window_slide(&obj, 1128);
    TEST_ASSERT_EQUAL_UINT64(1128, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x1111111111111111ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x2222222222222222ULL, obj.bitset[3]);

    // Test 8: Shift by 192 (three full words)
    obj.head      = 2000;
    obj.bitset[0] = 0xAAAAAAAAAAAAAAAAULL;
    obj.bitset[1] = 0xBBBBBBBBBBBBBBBBULL;
    obj.bitset[2] = 0xCCCCCCCCCCCCCCCCULL;
    obj.bitset[3] = 0xDDDDDDDDDDDDDDDDULL;
    rx_transfer_id_window_slide(&obj, 2192);
    TEST_ASSERT_EQUAL_UINT64(2192, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0xAAAAAAAAAAAAAAAAULL, obj.bitset[3]);

    // Test 9: Shift by exactly 256 bits (clears everything)
    obj.head      = 5000;
    obj.bitset[0] = 0x1234567890ABCDEFULL;
    obj.bitset[1] = 0xFEDCBA0987654321ULL;
    obj.bitset[2] = 0xAAAAAAAAAAAAAAAAULL;
    obj.bitset[3] = 0x5555555555555555ULL;
    rx_transfer_id_window_slide(&obj, 5256);
    TEST_ASSERT_EQUAL_UINT64(5256, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);

    // Test 10: Large shift (> 256 bits, erases everything)
    obj.head      = 10000;
    obj.bitset[0] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[1] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[2] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[3] = 0xFFFFFFFFFFFFFFFFULL;
    rx_transfer_id_window_slide(&obj, 10500);
    TEST_ASSERT_EQUAL_UINT64(10500, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);

    // Test 11: Shift from 0 to small value
    obj.head      = 0;
    obj.bitset[0] = 0x0000000000000001ULL;
    obj.bitset[1] = 0x0000000000000000ULL;
    obj.bitset[2] = 0x0000000000000000ULL;
    obj.bitset[3] = 0x0000000000000000ULL;
    rx_transfer_id_window_slide(&obj, 10);
    TEST_ASSERT_EQUAL_UINT64(10, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000400ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);

    // Test 12: Shift with wraparound (UINT64_MAX to 0)
    obj.head      = UINT64_MAX;
    obj.bitset[0] = 0x0000000000000001ULL;
    obj.bitset[1] = 0x0000000000000002ULL;
    obj.bitset[2] = 0x0000000000000004ULL;
    obj.bitset[3] = 0x0000000000000008ULL;
    rx_transfer_id_window_slide(&obj, 0);
    TEST_ASSERT_EQUAL_UINT64(0, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000002ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000004ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000008ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000010ULL, obj.bitset[3]);

    // Test 13: Shift with wraparound (UINT64_MAX - 5 to 5)
    obj.head      = UINT64_MAX - 5;
    obj.bitset[0] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[1] = 0x0000000000000000ULL;
    obj.bitset[2] = 0x0000000000000000ULL;
    obj.bitset[3] = 0x0000000000000000ULL;
    rx_transfer_id_window_slide(&obj, 5);
    TEST_ASSERT_EQUAL_UINT64(5, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFF800ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000000007FFULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);

    // Test 14: Shift by 32 bits (partial word shift with carries)
    obj.head      = 1000;
    obj.bitset[0] = 0xFFFFFFFF00000000ULL;
    obj.bitset[1] = 0xFFFFFFFF00000000ULL;
    obj.bitset[2] = 0xFFFFFFFF00000000ULL;
    obj.bitset[3] = 0xFFFFFFFF00000000ULL;
    rx_transfer_id_window_slide(&obj, 1032);
    TEST_ASSERT_EQUAL_UINT64(1032, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[3]);

    // Test 15: All bits set, shift by 1
    obj.head      = 7777;
    obj.bitset[0] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[1] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[2] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[3] = 0xFFFFFFFFFFFFFFFFULL;
    rx_transfer_id_window_slide(&obj, 7778);
    TEST_ASSERT_EQUAL_UINT64(7778, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFEULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[3]);
}

static void test_rx_transfer_id_window_manip(void)
{
    rx_transfer_id_window_t obj = { 100, { 0 } };
    rx_transfer_id_window_set(&obj, 100);
    TEST_ASSERT_EQUAL_UINT64(100, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000001ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);
    rx_transfer_id_window_set(&obj, 98);
    TEST_ASSERT_EQUAL_UINT64(100, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000005ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);
    rx_transfer_id_window_set(&obj, 0xFFFFFFFFFFFFFFA4ULL);
    TEST_ASSERT_EQUAL_UINT64(100, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000005ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000001ULL, obj.bitset[3]); // 192 bits back

    TEST_ASSERT_TRUE(rx_transfer_id_window_test(&obj, 100));
    TEST_ASSERT_TRUE(rx_transfer_id_window_test(&obj, 98));
    TEST_ASSERT_TRUE(rx_transfer_id_window_test(&obj, 0xFFFFFFFFFFFFFFA4ULL));
    TEST_ASSERT_FALSE(rx_transfer_id_window_test(&obj, 99));
    TEST_ASSERT_FALSE(rx_transfer_id_window_test(&obj, 97));
    TEST_ASSERT_FALSE(rx_transfer_id_window_test(&obj, 0xFFFFFFFFFFFFFFA3ULL));
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rx_transfer_id_forward_distance);
    RUN_TEST(test_rx_transfer_id_window_slide);
    RUN_TEST(test_rx_transfer_id_window_manip);
    return UNITY_END();
}
