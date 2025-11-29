/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include "helpers.h"
#include <unity.h>

static const char ethereal_strength[] =
  "All was silent except for the howl of the wind against the antenna. Ye watched as the remaining birds in the "
  "flock gradually settled back into the forest. She stared at the antenna and thought it looked like an enormous "
  "hand stretched open toward the sky, possessing an ethereal strength.";
static const size_t ethereal_strength_size = sizeof(ethereal_strength) - 1;

static const char detail_of_the_cosmos[] =
  "For us, the dark forest state is all-important, but it's just a detail of the cosmos.";
static const size_t detail_of_the_cosmos_size = sizeof(detail_of_the_cosmos) - 1;

static const char   interstellar_war[]    = "You have not seen what a true interstellar war is like.";
static const size_t interstellar_war_size = sizeof(interstellar_war) - 1;

typedef struct
{
    byte_t data[HEADER_SIZE_BYTES];
} header_buffer_t;

static void test_tx_serialize_header(void)
{
    // Test case 1: Basic header serialization
    {
        header_buffer_t buffer;
        const meta_t    meta = {
               .priority              = udpard_prio_fast,
               .flag_ack              = false,
               .transfer_payload_size = 12345,
               .transfer_id           = 0xBADC0FFEE0DDF00DULL,
               .sender_uid            = 0x0123456789ABCDEFULL,
               .topic_hash            = 0xFEDCBA9876543210ULL,
        };
        (void)header_serialize(buffer.data, meta, 12345, 0, 0);
        TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES, sizeof(buffer.data));
        // Verify version and priority in first byte
        TEST_ASSERT_EQUAL((HEADER_VERSION | ((unsigned)udpard_prio_fast << 5U)), buffer.data[0]);
    }
    // Test case 2: Ack flag
    {
        header_buffer_t buffer;
        const meta_t    meta = {
               .priority              = udpard_prio_nominal,
               .flag_ack              = true,
               .transfer_payload_size = 5000,
               .transfer_id           = 0xAAAAAAAAAAAAAAAAULL,
               .sender_uid            = 0xBBBBBBBBBBBBBBBBULL,
               .topic_hash            = 0xCCCCCCCCCCCCCCCCULL,
        };
        (void)header_serialize(buffer.data, meta, 100, 200, 0);
        TEST_ASSERT_EQUAL((HEADER_VERSION | ((unsigned)udpard_prio_nominal << 5U)), buffer.data[0]);
        TEST_ASSERT_EQUAL(HEADER_FLAG_ACK, buffer.data[1]);
    }
}

static void test_tx_spool_empty(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    char         user_transfer_referent = '\0';
    const meta_t meta                   = {
                          .priority              = udpard_prio_fast,
                          .flag_ack              = false,
                          .transfer_payload_size = 0,
                          .transfer_id           = 0xBADC0FFEE0DDF00DULL,
                          .sender_uid            = 0x0123456789ABCDEFULL,
                          .topic_hash            = 0xFEDCBA9876543210ULL,
    };
    const tx_chain_t chain = tx_spool(mem,
                                      30,
                                      1234567890,
                                      meta,
                                      (udpard_udpip_ep_t){ .ip = 0x0A0B0C0D, .port = 0x1234 },
                                      (udpard_bytes_t){ .size = 0, .data = "" },
                                      &user_transfer_referent);
    TEST_ASSERT_EQUAL(1 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(sizeof(udpard_tx_item_t) + HEADER_SIZE_BYTES, alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(1, chain.count);
    TEST_ASSERT_EQUAL(chain.head, chain.tail);
    TEST_ASSERT_EQUAL(NULL, chain.head->next_in_transfer);
    TEST_ASSERT_EQUAL(1234567890, chain.head->deadline);
    TEST_ASSERT_EQUAL(udpard_prio_fast, chain.head->priority);
    TEST_ASSERT_EQUAL(0x0A0B0C0D, chain.head->destination.ip);
    TEST_ASSERT_EQUAL(0x1234, chain.head->destination.port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES, chain.head->datagram_payload.size);
    TEST_ASSERT_EQUAL(&user_transfer_referent, chain.head->user_transfer_reference);
    udpard_tx_free(mem, chain.head);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void test_tx_spool_single_max_mtu(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    char         user_transfer_referent = '\0';
    const meta_t meta                   = {
                          .priority              = udpard_prio_slow,
                          .flag_ack              = false,
                          .transfer_payload_size = (uint32_t)detail_of_the_cosmos_size,
                          .transfer_id           = 0x0123456789ABCDEFULL,
                          .sender_uid            = 0xFEDCBA9876543210ULL,
                          .topic_hash            = 0x1111111111111111ULL,
    };
    const tx_chain_t chain =
      tx_spool(mem,
               detail_of_the_cosmos_size,
               1234567890,
               meta,
               (udpard_udpip_ep_t){ .ip = 0x0A0B0C00, .port = 7474 },
               (udpard_bytes_t){ .size = detail_of_the_cosmos_size, .data = detail_of_the_cosmos },
               &user_transfer_referent);
    TEST_ASSERT_EQUAL(1 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(sizeof(udpard_tx_item_t) + HEADER_SIZE_BYTES + detail_of_the_cosmos_size, alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(1, chain.count);
    TEST_ASSERT_EQUAL(chain.head, chain.tail);
    TEST_ASSERT_EQUAL(NULL, chain.head->next_in_transfer);
    TEST_ASSERT_EQUAL(1234567890, chain.head->deadline);
    TEST_ASSERT_EQUAL(udpard_prio_slow, chain.head->priority);
    TEST_ASSERT_EQUAL(0x0A0B0C00, chain.head->destination.ip);
    TEST_ASSERT_EQUAL(7474, chain.head->destination.port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + detail_of_the_cosmos_size, chain.head->datagram_payload.size);
    TEST_ASSERT_EQUAL(&user_transfer_referent, chain.head->user_transfer_reference);
    // Verify payload
    const byte_t* payload_ptr = (const byte_t*)chain.head->datagram_payload.data + HEADER_SIZE_BYTES;
    TEST_ASSERT_EQUAL(0, memcmp(detail_of_the_cosmos, payload_ptr, detail_of_the_cosmos_size));
    udpard_tx_free(mem, chain.head);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void test_tx_spool_single_frame_default_mtu(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    const size_t max_single_frame                = UDPARD_MTU_DEFAULT;
    const byte_t payload[UDPARD_MTU_DEFAULT + 1] = { 0 };
    const meta_t meta                            = {
                                   .priority              = udpard_prio_slow,
                                   .flag_ack              = false,
                                   .transfer_payload_size = (uint32_t)max_single_frame,
                                   .transfer_id           = 0x0123456789ABCDEFULL,
                                   .sender_uid            = 0xAAAAAAAAAAAAAAAAULL,
                                   .topic_hash            = 0xBBBBBBBBBBBBBBBBULL,
    };
    // Test: max_single_frame bytes fit in a single frame with the default MTU
    {
        const tx_chain_t chain = tx_spool(mem,
                                          UDPARD_MTU_DEFAULT,
                                          1234567890,
                                          meta,
                                          (udpard_udpip_ep_t){ .ip = 0x0A0B0C00, .port = 7474 },
                                          (udpard_bytes_t){ .size = max_single_frame, .data = payload },
                                          NULL);
        TEST_ASSERT_EQUAL(1 * 2ULL, alloc.allocated_fragments);
        TEST_ASSERT_EQUAL(sizeof(udpard_tx_item_t) + HEADER_SIZE_BYTES + max_single_frame, alloc.allocated_bytes);
        TEST_ASSERT_EQUAL(1, chain.count);
        TEST_ASSERT_EQUAL(chain.head, chain.tail);
        TEST_ASSERT_EQUAL(NULL, chain.head->next_in_transfer);
        udpard_tx_free(mem, chain.head);
        TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    }
    // Test: Increase the payload by 1 byte and ensure it spills over
    {
        meta_t meta2                = meta;
        meta2.transfer_payload_size = (uint32_t)(max_single_frame + 1);
        const tx_chain_t chain      = tx_spool(mem,
                                          UDPARD_MTU_DEFAULT,
                                          1234567890,
                                          meta2,
                                          (udpard_udpip_ep_t){ .ip = 0x0A0B0C00, .port = 7474 },
                                          (udpard_bytes_t){ .size = max_single_frame + 1, .data = payload },
                                          NULL);
        TEST_ASSERT_EQUAL(2 * 2ULL, alloc.allocated_fragments);
        TEST_ASSERT_EQUAL(((sizeof(udpard_tx_item_t) + HEADER_SIZE_BYTES) * 2) + max_single_frame + 1,
                          alloc.allocated_bytes);
        TEST_ASSERT_EQUAL(2, chain.count);
        TEST_ASSERT_NOT_EQUAL(chain.head, chain.tail);
        TEST_ASSERT_EQUAL(chain.tail, chain.head->next_in_transfer);
        TEST_ASSERT_EQUAL(NULL, chain.tail->next_in_transfer);
        udpard_tx_free(mem, chain.head);
        udpard_tx_free(mem, chain.tail);
        TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    }
}

static void test_tx_spool_three_frames(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    char         user_transfer_referent = '\0';
    const meta_t meta                   = {
                          .priority              = udpard_prio_nominal,
                          .flag_ack              = false,
                          .transfer_payload_size = (uint32_t)ethereal_strength_size,
                          .transfer_id           = 0x0123456789ABCDEFULL,
                          .sender_uid            = 0x1111111111111111ULL,
                          .topic_hash            = 0x2222222222222222ULL,
    };
    const size_t     mtu   = (ethereal_strength_size + 2U) / 3U; // Force payload split into three frames
    const tx_chain_t chain = tx_spool(mem,
                                      mtu,
                                      223574680,
                                      meta,
                                      (udpard_udpip_ep_t){ .ip = 0xBABADEDA, .port = 0xD0ED },
                                      (udpard_bytes_t){ .size = ethereal_strength_size, .data = ethereal_strength },
                                      &user_transfer_referent);
    TEST_ASSERT_EQUAL(3 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL((3 * (sizeof(udpard_tx_item_t) + HEADER_SIZE_BYTES)) + ethereal_strength_size,
                      alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(3, chain.count);
    udpard_tx_item_t* const first = chain.head;
    TEST_ASSERT_NOT_EQUAL(NULL, first);
    udpard_tx_item_t* const second = first->next_in_transfer;
    TEST_ASSERT_NOT_EQUAL(NULL, second);
    udpard_tx_item_t* const third = second->next_in_transfer;
    TEST_ASSERT_NOT_EQUAL(NULL, third);
    TEST_ASSERT_EQUAL(NULL, third->next_in_transfer);
    TEST_ASSERT_EQUAL(chain.tail, third);
    // Verify first frame
    TEST_ASSERT_EQUAL(223574680, first->deadline);
    TEST_ASSERT_EQUAL(udpard_prio_nominal, first->priority);
    TEST_ASSERT_EQUAL(0xBABADEDA, first->destination.ip);
    TEST_ASSERT_EQUAL(0xD0ED, first->destination.port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + mtu, first->datagram_payload.size);
    TEST_ASSERT_EQUAL(0,
                      memcmp(ethereal_strength, (const byte_t*)first->datagram_payload.data + HEADER_SIZE_BYTES, mtu));
    TEST_ASSERT_EQUAL(&user_transfer_referent, first->user_transfer_reference);
    // Verify second frame
    TEST_ASSERT_EQUAL(223574680, second->deadline);
    TEST_ASSERT_EQUAL(udpard_prio_nominal, second->priority);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + mtu, second->datagram_payload.size);
    TEST_ASSERT_EQUAL(
      0, memcmp(ethereal_strength + mtu, (const byte_t*)second->datagram_payload.data + HEADER_SIZE_BYTES, mtu));
    TEST_ASSERT_EQUAL(&user_transfer_referent, second->user_transfer_reference);
    // Verify third frame (contains remainder)
    TEST_ASSERT_EQUAL(223574680, third->deadline);
    TEST_ASSERT_EQUAL(udpard_prio_nominal, third->priority);
    const size_t third_payload_size = ethereal_strength_size - (2 * mtu);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + third_payload_size, third->datagram_payload.size);
    TEST_ASSERT_EQUAL(0,
                      memcmp(ethereal_strength + (2 * mtu),
                             (const byte_t*)third->datagram_payload.data + HEADER_SIZE_BYTES,
                             third_payload_size));
    TEST_ASSERT_EQUAL(&user_transfer_referent, third->user_transfer_reference);
    udpard_tx_free(mem, first);
    udpard_tx_free(mem, second);
    udpard_tx_free(mem, third);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void test_tx_push_peek_pop_free(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    udpard_tx_t tx;
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0123456789ABCDEFULL, 10, mem));
    // Use default MTU. Create a payload that will span 3 frames.
    // With MTU=1384 (default), we need payload > 2768 bytes to get 3 frames.
    // Use a simple repeated pattern.
    const size_t test_payload_size = 2800;
    byte_t*      test_payload      = malloc(test_payload_size);
    TEST_ASSERT_NOT_NULL(test_payload);
    for (size_t i = 0; i < test_payload_size; i++) {
        test_payload[i] = (byte_t)(i & 0xFFU);
    }
    char         user_transfer_referent = '\0';
    const meta_t meta                   = {
                          .priority              = udpard_prio_nominal,
                          .flag_ack              = false,
                          .transfer_payload_size = (uint32_t)test_payload_size,
                          .transfer_id           = 0x0123456789ABCDEFULL,
                          .sender_uid            = 0x0123456789ABCDEFULL,
                          .topic_hash            = 0xBBBBBBBBBBBBBBBBULL,
    };
    const uint32_t enqueued = tx_push(&tx,
                                      1234567890U,
                                      meta,
                                      (udpard_udpip_ep_t){ .ip = 0xBABADEDA, .port = 0xD0ED },
                                      (udpard_bytes_t){ .size = test_payload_size, .data = test_payload },
                                      &user_transfer_referent);
    free(test_payload);
    TEST_ASSERT_EQUAL(3, enqueued);
    TEST_ASSERT_EQUAL(3 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(3, tx.queue_size);
    // Peek and pop first frame
    udpard_tx_item_t* frame = udpard_tx_peek(&tx, 0);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_NOT_EQUAL(NULL, frame->next_in_transfer);
    TEST_ASSERT_EQUAL(1234567890U, frame->deadline);
    TEST_ASSERT_EQUAL(udpard_prio_nominal, frame->priority);
    TEST_ASSERT_EQUAL(0xBABADEDA, frame->destination.ip);
    TEST_ASSERT_EQUAL(0xD0ED, frame->destination.port);
    TEST_ASSERT_EQUAL(&user_transfer_referent, frame->user_transfer_reference);
    udpard_tx_pop(&tx, frame);
    udpard_tx_free(tx.memory, frame);
    TEST_ASSERT_EQUAL(2 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(2, tx.queue_size);
    // Peek and pop second frame
    frame = udpard_tx_peek(&tx, 0);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_NOT_EQUAL(NULL, frame->next_in_transfer);
    udpard_tx_pop(&tx, frame);
    udpard_tx_free(tx.memory, frame);
    TEST_ASSERT_EQUAL(1 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(1, tx.queue_size);
    // Peek and pop third frame
    frame = udpard_tx_peek(&tx, 0);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(NULL, frame->next_in_transfer);
    udpard_tx_pop(&tx, frame);
    udpard_tx_free(tx.memory, frame);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(0, tx.queue_size);
    TEST_ASSERT_EQUAL(NULL, udpard_tx_peek(&tx, 0));
}

static void test_tx_push_prioritization(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    udpard_tx_t tx;
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0123456789ABCDEFULL, 10, mem));
    // Use default MTU (respects UDPARD_MTU_MIN). Create payloads that span multiple frames.
    const size_t large_payload_size = 2800; // 3 frames at default MTU
    const size_t small_payload_size = 100;  // 1 frame
    byte_t*      large_payload      = malloc(large_payload_size);
    TEST_ASSERT_NOT_NULL(large_payload);
    for (size_t i = 0; i < large_payload_size; i++) {
        large_payload[i] = (byte_t)(i & 0xFFU);
    }
    // Push transfer A at nominal priority (3 frames)
    meta_t meta_a = {
        .priority              = udpard_prio_nominal,
        .flag_ack              = false,
        .transfer_payload_size = (uint32_t)large_payload_size,
        .transfer_id           = 5000,
        .sender_uid            = 0x0123456789ABCDEFULL,
        .topic_hash            = 0xAAAAAAAAAAAAAAAAULL,
    };
    TEST_ASSERT_EQUAL(3,
                      tx_push(&tx,
                              0,
                              meta_a,
                              (udpard_udpip_ep_t){ .ip = 0xAAAAAAAA, .port = 0xAAAA },
                              (udpard_bytes_t){ .size = large_payload_size, .data = large_payload },
                              NULL));
    TEST_ASSERT_EQUAL(3, tx.queue_size);
    udpard_tx_item_t* frame = udpard_tx_peek(&tx, 0);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xAAAAAAAA, frame->destination.ip);
    // Push transfer B at higher priority (single frame)
    TEST_ASSERT_EQUAL(1,
                      tx_push(&tx,
                              0,
                              (meta_t){
                                .priority              = udpard_prio_high,
                                .flag_ack              = false,
                                .transfer_payload_size = (uint32_t)small_payload_size,
                                .transfer_id           = 100000,
                                .sender_uid            = 0x0123456789ABCDEFULL,
                                .topic_hash            = 0xBBBBBBBBBBBBBBBBULL,
                              },
                              (udpard_udpip_ep_t){ .ip = 0xBBBBBBBB, .port = 0xBBBB },
                              (udpard_bytes_t){ .size = small_payload_size, .data = large_payload },
                              NULL));
    TEST_ASSERT_EQUAL(4, tx.queue_size);
    frame = udpard_tx_peek(&tx, 0);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xBBBBBBBB, frame->destination.ip); // B should be first now
    // Push transfer C at lower priority (single frame)
    TEST_ASSERT_EQUAL(1,
                      tx_push(&tx,
                              1002,
                              (meta_t){
                                .priority              = udpard_prio_low,
                                .flag_ack              = false,
                                .transfer_payload_size = (uint32_t)small_payload_size,
                                .transfer_id           = 10000,
                                .sender_uid            = 0x0123456789ABCDEFULL,
                                .topic_hash            = 0xCCCCCCCCCCCCCCCCULL,
                              },
                              (udpard_udpip_ep_t){ .ip = 0xCCCCCCCC, .port = 0xCCCC },
                              (udpard_bytes_t){ .size = small_payload_size, .data = large_payload },
                              NULL));
    TEST_ASSERT_EQUAL(5, tx.queue_size);
    // Push transfer D at same low priority (should go after C due to FIFO)
    TEST_ASSERT_EQUAL(1,
                      tx_push(&tx,
                              1003,
                              (meta_t){
                                .priority              = udpard_prio_low,
                                .flag_ack              = false,
                                .transfer_payload_size = (uint32_t)small_payload_size,
                                .transfer_id           = 10001,
                                .sender_uid            = 0x0123456789ABCDEFULL,
                                .topic_hash            = 0xDDDDDDDDDDDDDDDDULL,
                              },
                              (udpard_udpip_ep_t){ .ip = 0xDDDDDDDD, .port = 0xDDDD },
                              (udpard_bytes_t){ .size = small_payload_size, .data = large_payload },
                              NULL));
    TEST_ASSERT_EQUAL(6, tx.queue_size);
    // Push transfer E at even higher priority (single frame)
    TEST_ASSERT_EQUAL(1,
                      tx_push(&tx,
                              1003,
                              (meta_t){
                                .priority              = udpard_prio_fast,
                                .flag_ack              = false,
                                .transfer_payload_size = (uint32_t)small_payload_size,
                                .transfer_id           = 1000,
                                .sender_uid            = 0x0123456789ABCDEFULL,
                                .topic_hash            = 0xEEEEEEEEEEEEEEEEULL,
                              },
                              (udpard_udpip_ep_t){ .ip = 0xEEEEEEEE, .port = 0xEEEE },
                              (udpard_bytes_t){ .size = small_payload_size, .data = large_payload },
                              NULL));
    TEST_ASSERT_EQUAL(7, tx.queue_size);
    frame = udpard_tx_peek(&tx, 0);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xEEEEEEEE, frame->destination.ip); // E should be first
    // Now unwind the queue and verify order: E, B, A (3 frames), C, D, E
    udpard_tx_pop(&tx, frame);
    udpard_tx_free(tx.memory, frame);
    TEST_ASSERT_EQUAL(6, tx.queue_size);
    // B
    frame = udpard_tx_peek(&tx, 0);
    TEST_ASSERT_EQUAL(0xBBBBBBBB, frame->destination.ip);
    udpard_tx_pop(&tx, frame);
    udpard_tx_free(tx.memory, frame);
    TEST_ASSERT_EQUAL(5, tx.queue_size);
    // A1
    frame = udpard_tx_peek(&tx, 0);
    TEST_ASSERT_EQUAL(0xAAAAAAAA, frame->destination.ip);
    udpard_tx_pop(&tx, frame);
    udpard_tx_free(tx.memory, frame);
    TEST_ASSERT_EQUAL(4, tx.queue_size);
    // A2
    frame = udpard_tx_peek(&tx, 0);
    TEST_ASSERT_EQUAL(0xAAAAAAAA, frame->destination.ip);
    udpard_tx_pop(&tx, frame);
    udpard_tx_free(tx.memory, frame);
    TEST_ASSERT_EQUAL(3, tx.queue_size);
    // A3
    frame = udpard_tx_peek(&tx, 0);
    TEST_ASSERT_EQUAL(0xAAAAAAAA, frame->destination.ip);
    udpard_tx_pop(&tx, frame);
    udpard_tx_free(tx.memory, frame);
    TEST_ASSERT_EQUAL(2, tx.queue_size);
    // C
    frame = udpard_tx_peek(&tx, 0);
    TEST_ASSERT_EQUAL(0xCCCCCCCC, frame->destination.ip);
    udpard_tx_pop(&tx, frame);
    udpard_tx_free(tx.memory, frame);
    TEST_ASSERT_EQUAL(1, tx.queue_size);
    // D
    frame = udpard_tx_peek(&tx, 0);
    TEST_ASSERT_EQUAL(0xDDDDDDDD, frame->destination.ip);
    udpard_tx_pop(&tx, frame);
    udpard_tx_free(tx.memory, frame);
    TEST_ASSERT_EQUAL(0, tx.queue_size);
    TEST_ASSERT_EQUAL(NULL, udpard_tx_peek(&tx, 0));
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    free(large_payload);
}

static void test_tx_push_capacity_limit(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    udpard_tx_t tx;
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0123456789ABCDEFULL, 2, mem)); // Capacity of only 2 frames
    // Use default MTU. Create payload that will span 3 frames (exceeds capacity of 2).
    const size_t test_payload_size = 2800;
    byte_t*      test_payload      = malloc(test_payload_size);
    TEST_ASSERT_NOT_NULL(test_payload);
    for (size_t i = 0; i < test_payload_size; i++) {
        test_payload[i] = (byte_t)(i & 0xFFU);
    }
    const meta_t meta = {
        .priority              = udpard_prio_nominal,
        .flag_ack              = false,
        .transfer_payload_size = (uint32_t)test_payload_size,
        .transfer_id           = 0x0123456789ABCDEFULL,
        .sender_uid            = 0x0123456789ABCDEFULL,
        .topic_hash            = 0xBBBBBBBBBBBBBBBBULL,
    };
    // Try to push a transfer that would exceed capacity (3 frames > capacity of 2)
    const uint32_t enqueued = tx_push(&tx,
                                      1234567890U,
                                      meta,
                                      (udpard_udpip_ep_t){ .ip = 0xBABADEDA, .port = 0xD0ED },
                                      (udpard_bytes_t){ .size = test_payload_size, .data = test_payload },
                                      NULL);

    TEST_ASSERT_EQUAL(0, enqueued); // Should fail
    TEST_ASSERT_EQUAL(1, tx.errors_capacity);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(0, tx.queue_size);
    free(test_payload);
}

static void test_tx_push_oom(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    udpard_tx_t tx;
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0123456789ABCDEFULL, 10000, mem));
    tx.mtu            = (ethereal_strength_size + 2U) / 3U;
    const meta_t meta = {
        .priority              = udpard_prio_nominal,
        .flag_ack              = false,
        .transfer_payload_size = (uint32_t)ethereal_strength_size,
        .transfer_id           = 0x0123456789ABCDEFULL,
        .sender_uid            = 0x0123456789ABCDEFULL,
        .topic_hash            = 0xBBBBBBBBBBBBBBBBULL,
    };
    alloc.limit_bytes       = ethereal_strength_size; // Not enough for overheads
    const uint32_t enqueued = tx_push(&tx,
                                      1234567890U,
                                      meta,
                                      (udpard_udpip_ep_t){ .ip = 0xBABADEDA, .port = 0xD0ED },
                                      (udpard_bytes_t){ .size = ethereal_strength_size, .data = ethereal_strength },
                                      NULL);
    TEST_ASSERT_EQUAL(0, enqueued);
    TEST_ASSERT_EQUAL(1, tx.errors_oom);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(0, tx.queue_size);
}

static void test_tx_push_payload_oom(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    udpard_tx_t tx;
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0123456789ABCDEFULL, 10000, mem));
    tx.mtu            = ethereal_strength_size;
    const meta_t meta = {
        .priority              = udpard_prio_nominal,
        .flag_ack              = false,
        .transfer_payload_size = (uint32_t)ethereal_strength_size,
        .transfer_id           = 0x0123456789ABCDEFULL,
        .sender_uid            = 0x0123456789ABCDEFULL,
        .topic_hash            = 0xBBBBBBBBBBBBBBBBULL,
    };
    // There is memory for the item, but 1 byte short for payload
    alloc.limit_bytes       = sizeof(udpard_tx_item_t) + (HEADER_SIZE_BYTES + ethereal_strength_size - 1);
    const uint32_t enqueued = tx_push(&tx,
                                      1234567890U,
                                      meta,
                                      (udpard_udpip_ep_t){ .ip = 0xBABADEDA, .port = 0xD0ED },
                                      (udpard_bytes_t){ .size = ethereal_strength_size, .data = ethereal_strength },
                                      NULL);
    TEST_ASSERT_EQUAL(0, enqueued);
    TEST_ASSERT_EQUAL(1, tx.errors_oom);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(0, tx.queue_size);
}

static void test_tx_publish(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    udpard_tx_t tx;
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0123456789ABCDEFULL, 10, mem));
    const uint32_t enqueued =
      udpard_tx_publish(&tx,
                        1000000,               // now
                        2000000,               // deadline
                        udpard_prio_nominal,   // priority
                        0x1122334455667788ULL, // topic_hash
                        123,                   // subject_id
                        0xBADC0FFEE0DDF00DULL, // transfer_id
                        (udpard_bytes_t){ .size = detail_of_the_cosmos_size, .data = detail_of_the_cosmos },
                        false, // ack_required
                        NULL);
    TEST_ASSERT_EQUAL(1, enqueued);
    TEST_ASSERT_EQUAL(1, tx.queue_size);
    udpard_tx_item_t* frame = udpard_tx_peek(&tx, 1000000);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(2000000, frame->deadline);
    TEST_ASSERT_EQUAL(udpard_prio_nominal, frame->priority);
    // Verify the destination is the correct multicast endpoint
    const udpard_udpip_ep_t expected_ep = make_topic_ep(123);
    TEST_ASSERT_EQUAL(expected_ep.ip, frame->destination.ip);
    TEST_ASSERT_EQUAL(expected_ep.port, frame->destination.port);
    udpard_tx_pop(&tx, frame);
    udpard_tx_free(tx.memory, frame);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void test_tx_p2p(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    udpard_tx_t tx;
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0123456789ABCDEFULL, 10, mem));
    const uint32_t enqueued = udpard_tx_p2p(&tx,
                                            1000000,               // now
                                            2000000,               // deadline
                                            0xFEDCBA9876543210ULL, // remote_uid
                                            (udpard_udpip_ep_t){ .ip = 0xC0A80101, .port = 9999 },
                                            udpard_prio_high,      // priority
                                            0x0BADC0DE0BADC0DEULL, // transfer_id
                                            (udpard_bytes_t){ .size = interstellar_war_size, .data = interstellar_war },
                                            true, // ack_required
                                            NULL);
    TEST_ASSERT_EQUAL(1, enqueued);
    TEST_ASSERT_EQUAL(1, tx.queue_size);
    udpard_tx_item_t* frame = udpard_tx_peek(&tx, 1000000);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(2000000, frame->deadline);
    TEST_ASSERT_EQUAL(udpard_prio_high, frame->priority);
    TEST_ASSERT_EQUAL(0xC0A80101, frame->destination.ip);
    TEST_ASSERT_EQUAL(9999, frame->destination.port);
    udpard_tx_pop(&tx, frame);
    udpard_tx_free(tx.memory, frame);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void test_tx_deadline_expiration(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    udpard_tx_t tx;
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0123456789ABCDEFULL, 10, mem));
    // Use default MTU. Create payload for 3 frames.
    const size_t test_payload_size = 2800;
    byte_t*      test_payload      = malloc(test_payload_size);
    TEST_ASSERT_NOT_NULL(test_payload);
    for (size_t i = 0; i < test_payload_size; i++) {
        test_payload[i] = (byte_t)(i & 0xFFU);
    }
    // Push a transfer with a deadline in the past
    const meta_t meta = {
        .priority              = udpard_prio_nominal,
        .flag_ack              = false,
        .transfer_payload_size = (uint32_t)test_payload_size,
        .transfer_id           = 0x0123456789ABCDEFULL,
        .sender_uid            = 0x0123456789ABCDEFULL,
        .topic_hash            = 0xBBBBBBBBBBBBBBBBULL,
    };
    const uint32_t enqueued = tx_push(&tx,
                                      1000000, // deadline in the past
                                      meta,
                                      (udpard_udpip_ep_t){ .ip = 0xBABADEDA, .port = 0xD0ED },
                                      (udpard_bytes_t){ .size = test_payload_size, .data = test_payload },
                                      NULL);
    TEST_ASSERT_EQUAL(3, enqueued);
    TEST_ASSERT_EQUAL(3, tx.queue_size);
    // Try to peek with current time much later
    udpard_tx_item_t* frame = udpard_tx_peek(&tx, 2000000);
    TEST_ASSERT_EQUAL(NULL, frame); // Should be purged
    TEST_ASSERT_EQUAL(0, tx.queue_size);
    TEST_ASSERT_EQUAL(3, tx.errors_expiration); // All 3 frames expired
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    free(test_payload);
}

static void test_tx_deadline_at_current_time(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    udpard_tx_t tx;
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0123456789ABCDEFULL, 10, mem));
    const size_t test_payload_size = 100;
    byte_t       test_payload[100];
    for (size_t i = 0; i < test_payload_size; i++) {
        test_payload[i] = (byte_t)(i & 0xFFU);
    }
    // Test 1: Try to publish with deadline < now (should be rejected)
    uint32_t enqueued = udpard_tx_publish(&tx,
                                          1000000, // now
                                          999999,  // deadline in the past
                                          udpard_prio_nominal,
                                          0x1122334455667788ULL,
                                          123,
                                          0xBADC0FFEE0DDF00DULL,
                                          (udpard_bytes_t){ .size = test_payload_size, .data = test_payload },
                                          false,
                                          NULL);
    TEST_ASSERT_EQUAL(0, enqueued);      // Should return 0 (rejected)
    TEST_ASSERT_EQUAL(0, tx.queue_size); // Nothing enqueued
    // Test 2: Try to publish with deadline == now (should be accepted, as deadline >= now)
    enqueued = udpard_tx_publish(&tx,
                                 1000000, // now
                                 1000000, // deadline equals now
                                 udpard_prio_nominal,
                                 0x1122334455667788ULL,
                                 123,
                                 0xBADC0FFEE0DDF00DULL,
                                 (udpard_bytes_t){ .size = test_payload_size, .data = test_payload },
                                 false,
                                 NULL);
    TEST_ASSERT_EQUAL(1, enqueued);      // Should succeed
    TEST_ASSERT_EQUAL(1, tx.queue_size); // One frame enqueued
    // Test 3: Try p2p with deadline < now (should be rejected)
    enqueued = udpard_tx_p2p(&tx,
                             2000000, // now
                             1999999, // deadline in the past
                             0xFEDCBA9876543210ULL,
                             (udpard_udpip_ep_t){ .ip = 0xC0A80101, .port = 9999 },
                             udpard_prio_high,
                             0x0BADC0DE0BADC0DEULL,
                             (udpard_bytes_t){ .size = test_payload_size, .data = test_payload },
                             false,
                             NULL);
    TEST_ASSERT_EQUAL(0, enqueued);      // Should return 0 (rejected)
    TEST_ASSERT_EQUAL(1, tx.queue_size); // Still only 1 frame from test 2
    // Clean up
    udpard_tx_item_t* frame = udpard_tx_peek(&tx, 0);
    while (frame != NULL) {
        udpard_tx_item_t* const next = frame->next_in_transfer;
        udpard_tx_pop(&tx, frame);
        udpard_tx_free(tx.memory, frame);
        frame = next;
    }
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void test_tx_invalid_params(void)
{
    instrumented_allocator_t alloc;
    instrumented_allocator_new(&alloc);
    const udpard_tx_mem_resources_t mem = {
        .fragment = instrumented_allocator_make_resource(&alloc),
        .payload  = instrumented_allocator_make_resource(&alloc),
    };
    udpard_tx_t tx;
    // Test invalid init params
    TEST_ASSERT_FALSE(udpard_tx_new(NULL, 0x0123456789ABCDEFULL, 10, mem));
    TEST_ASSERT_FALSE(udpard_tx_new(&tx, 0, 10, mem)); // local_uid cannot be 0
    // Test with invalid memory resources
    udpard_tx_mem_resources_t bad_mem = mem;
    bad_mem.fragment.alloc            = NULL;
    TEST_ASSERT_FALSE(udpard_tx_new(&tx, 0x0123456789ABCDEFULL, 10, bad_mem));
    // Valid init
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0123456789ABCDEFULL, 10, mem));
    // Test publish with NULL self
    TEST_ASSERT_EQUAL(0,
                      udpard_tx_publish(NULL,
                                        1000000,
                                        2000000,
                                        udpard_prio_nominal,
                                        0x1122334455667788ULL,
                                        123,
                                        0xBADC0FFEE0DDF00DULL,
                                        (udpard_bytes_t){ .size = 10, .data = "test" },
                                        false,
                                        NULL));
    // Test publish with invalid priority
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange) - intentionally testing invalid value
    const uint_fast8_t invalid_priority = UDPARD_PRIORITY_MAX + 1;
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange) - intentionally testing invalid value
    TEST_ASSERT_EQUAL(0,
                      udpard_tx_publish(&tx,
                                        1000000,
                                        2000000,
                                        (udpard_prio_t)invalid_priority,
                                        0x1122334455667788ULL,
                                        123,
                                        0xBADC0FFEE0DDF00DULL,
                                        (udpard_bytes_t){ .size = 10, .data = "test" },
                                        false,
                                        NULL));
    // Test p2p with invalid params
    TEST_ASSERT_EQUAL(0,
                      udpard_tx_p2p(&tx,
                                    1000000,
                                    2000000,
                                    0, // remote_uid cannot be 0
                                    (udpard_udpip_ep_t){ .ip = 0xC0A80101, .port = 9999 },
                                    udpard_prio_high,
                                    0x0BADC0DE0BADC0DEULL,
                                    (udpard_bytes_t){ .size = 10, .data = "test" },
                                    false,
                                    NULL));
    TEST_ASSERT_EQUAL(0,
                      udpard_tx_p2p(&tx,
                                    1000000,
                                    2000000,
                                    0xFEDCBA9876543210ULL,
                                    (udpard_udpip_ep_t){ .ip = 0, .port = 9999 }, // ip cannot be 0
                                    udpard_prio_high,
                                    0x0BADC0DE0BADC0DEULL,
                                    (udpard_bytes_t){ .size = 10, .data = "test" },
                                    false,
                                    NULL));
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_tx_serialize_header);
    RUN_TEST(test_tx_spool_empty);
    RUN_TEST(test_tx_spool_single_max_mtu);
    RUN_TEST(test_tx_spool_single_frame_default_mtu);
    RUN_TEST(test_tx_spool_three_frames);
    RUN_TEST(test_tx_push_peek_pop_free);
    RUN_TEST(test_tx_push_prioritization);
    RUN_TEST(test_tx_push_capacity_limit);
    RUN_TEST(test_tx_push_oom);
    RUN_TEST(test_tx_push_payload_oom);
    RUN_TEST(test_tx_publish);
    RUN_TEST(test_tx_p2p);
    RUN_TEST(test_tx_deadline_expiration);
    RUN_TEST(test_tx_deadline_at_current_time);
    RUN_TEST(test_tx_invalid_params);
    return UNITY_END();
}
