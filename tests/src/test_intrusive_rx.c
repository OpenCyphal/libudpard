/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c>  // NOLINT(bugprone-suspicious-include)
#include "helpers.h"
#include <unity.h>

// NOLINTBEGIN(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)

/// Moves the payload from the origin into a new buffer and attaches is to the newly allocated fragment.
/// This function performs two allocations. This function is infallible.
static RxFragment* makeRxFragment(struct UdpardMemoryResource* const memory_fragment,
                                  struct UdpardMemoryResource* const memory_payload,
                                  const uint32_t                     frame_index,
                                  const struct UdpardPayload         view,
                                  const struct UdpardMutablePayload  origin,
                                  RxFragmentTreeNode* const          parent)
{
    TEST_PANIC_UNLESS((view.data >= origin.data) && (view.size <= origin.size));
    TEST_PANIC_UNLESS((((const byte_t*) view.data) + view.size) <= (((const byte_t*) origin.data) + origin.size));
    byte_t* const     new_origin = (byte_t*) memAlloc(memory_payload, origin.size);
    RxFragment* const frag       = (RxFragment*) memAlloc(memory_fragment, sizeof(RxFragment));
    if ((new_origin != NULL) && (frag != NULL))
    {
        (void) memmove(new_origin, origin.data, origin.size);
        (void) memset(frag, 0, sizeof(RxFragment));
        frag->tree.base.lr[0]  = NULL;
        frag->tree.base.lr[1]  = NULL;
        frag->tree.base.up     = &parent->base;
        frag->tree.this        = frag;
        frag->frame_index      = frame_index;
        frag->base.view        = view;
        frag->base.origin.data = new_origin;
        frag->base.origin.size = origin.size;
        frag->base.view.data   = new_origin + (((const byte_t*) view.data) - ((byte_t*) origin.data));
        frag->base.view.size   = view.size;
    }
    else
    {
        TEST_PANIC("Failed to allocate RxFragment");
    }
    return frag;
}

/// This is a simple helper wrapper that constructs a new fragment using a null-terminated string as a payload.
static RxFragment* makeRxFragmentString(struct UdpardMemoryResource* const memory_fragment,
                                        struct UdpardMemoryResource* const memory_payload,
                                        const uint32_t                     frame_index,
                                        const char* const                  payload,
                                        RxFragmentTreeNode* const          parent)
{
    const size_t sz = strlen(payload);
    return makeRxFragment(memory_fragment,
                          memory_payload,
                          frame_index,
                          (struct UdpardPayload){.data = payload, .size = sz},
                          (struct UdpardMutablePayload){.data = (void*) payload, .size = sz},
                          parent);
}

static bool compareMemory(const size_t      expected_size,
                          const void* const expected,
                          const size_t      actual_size,
                          const void* const actual)
{
    return (expected_size == actual_size) && (memcmp(expected, actual, expected_size) == 0);
}
static bool compareStringWithPayload(const char* const expected, const struct UdpardPayload payload)
{
    return compareMemory(strlen(expected), expected, payload.size, payload.data);
}

static RxFrameBase makeRxFrameBase(struct UdpardMemoryResource* const memory_payload,
                                   const uint32_t                     frame_index,
                                   const bool                         end_of_transfer,
                                   const struct UdpardPayload         view,
                                   const struct UdpardMutablePayload  origin)
{
    TEST_PANIC_UNLESS((view.data >= origin.data) && (view.size <= origin.size));
    TEST_PANIC_UNLESS((((const byte_t*) view.data) + view.size) <= (((const byte_t*) origin.data) + origin.size));
    RxFrameBase   out        = {0};
    byte_t* const new_origin = (byte_t*) memAlloc(memory_payload, origin.size);
    if (new_origin != NULL)
    {
        (void) memmove(new_origin, origin.data, origin.size);
        out.index           = frame_index;
        out.end_of_transfer = end_of_transfer;
        out.origin.data     = new_origin;
        out.origin.size     = origin.size;
        out.payload.data    = new_origin + (((const byte_t*) view.data) - ((byte_t*) origin.data));
        out.payload.size    = view.size;
    }
    else
    {
        TEST_PANIC("Failed to allocate payload buffer for RxFrameBase");
    }
    return out;
}

static RxFrameBase makeRxFrameBaseString(struct UdpardMemoryResource* const memory_payload,
                                         const uint32_t                     frame_index,
                                         const bool                         end_of_transfer,
                                         const char* const                  payload)
{
    return makeRxFrameBase(memory_payload,
                           frame_index,
                           end_of_transfer,
                           (struct UdpardPayload){.data = payload, .size = strlen(payload)},
                           (struct UdpardMutablePayload){.data = (void*) payload, .size = strlen(payload)});
}

// --------------------------------------------------------------------------------------------------------------------

// Generate reference data using PyCyphal:
//
// >>> from pycyphal.transport.udp import UDPFrame
// >>> from pycyphal.transport import Priority, MessageDataSpecifier, ServiceDataSpecifier
// >>> frame = UDPFrame(priority=Priority.FAST, transfer_id=0xbadc0ffee0ddf00d, index=12345, end_of_transfer=False,
//  payload=memoryview(b''), source_node_id=2345, destination_node_id=5432,
//  data_specifier=MessageDataSpecifier(7654), user_data=0)
// >>> list(frame.compile_header_and_payload()[0])
// [1, 2, 41, 9, 56, 21, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0, 224, 60]
static void testParseFrameValidMessage(void)
{
    byte_t  data[] = {1,   2,   41,  9,   255, 255, 230, 29, 13, 240, 221, 224,
                      254, 15,  220, 186, 57,  48,  0,   0,  0,  0,   30,  179,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
    TEST_ASSERT_EQUAL_UINT64(UdpardPriorityFast, rxf.meta.priority);
    TEST_ASSERT_EQUAL_UINT64(2345, rxf.meta.src_node_id);
    TEST_ASSERT_EQUAL_UINT64(UDPARD_NODE_ID_UNSET, rxf.meta.dst_node_id);
    TEST_ASSERT_EQUAL_UINT64(7654, rxf.meta.data_specifier);
    TEST_ASSERT_EQUAL_UINT64(0xbadc0ffee0ddf00d, rxf.meta.transfer_id);
    TEST_ASSERT_EQUAL_UINT64(12345, rxf.base.index);
    TEST_ASSERT_FALSE(rxf.base.end_of_transfer);
    TEST_ASSERT_EQUAL_UINT64(3, rxf.base.payload.size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY("abc", rxf.base.payload.data, 3);
    TEST_ASSERT_EQUAL_UINT64(sizeof(data), rxf.base.origin.size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(data, rxf.base.origin.data, sizeof(data));
}

static void testParseFrameValidRPCService(void)
{
    // frame = UDPFrame(priority=Priority.FAST, transfer_id=0xbadc0ffee0ddf00d, index=6654, end_of_transfer=False,
    // payload=memoryview(b''), source_node_id=2345, destination_node_id=4567,
    // data_specifier=ServiceDataSpecifier(role=ServiceDataSpecifier.Role.REQUEST, service_id=123), user_data=0)
    byte_t  data[] = {1,   2,   41,  9,   215, 17, 123, 192, 13, 240, 221, 224,
                      254, 15,  220, 186, 254, 25, 0,   0,   0,  0,   173, 122,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
    TEST_ASSERT_EQUAL_UINT64(UdpardPriorityFast, rxf.meta.priority);
    TEST_ASSERT_EQUAL_UINT64(2345, rxf.meta.src_node_id);
    TEST_ASSERT_EQUAL_UINT64(4567, rxf.meta.dst_node_id);
    TEST_ASSERT_EQUAL_UINT64(123U | DATA_SPECIFIER_SERVICE_NOT_MESSAGE_MASK |
                                 DATA_SPECIFIER_SERVICE_REQUEST_NOT_RESPONSE_MASK,
                             rxf.meta.data_specifier);
    TEST_ASSERT_EQUAL_UINT64(0xbadc0ffee0ddf00d, rxf.meta.transfer_id);
    TEST_ASSERT_EQUAL_UINT64(6654, rxf.base.index);
    TEST_ASSERT_FALSE(rxf.base.end_of_transfer);
    TEST_ASSERT_EQUAL_UINT64(3, rxf.base.payload.size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY("abc", rxf.base.payload.data, 3);
    TEST_ASSERT_EQUAL_UINT64(sizeof(data), rxf.base.origin.size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(data, rxf.base.origin.data, sizeof(data));
}

static void testParseFrameValidMessageAnonymous(void)
{
    byte_t  data[] = {1,   2,   255, 255, 255, 255, 230, 29,  13, 240, 221, 224,
                      254, 15,  220, 186, 0,   0,   0,   128, 0,  0,   168, 92,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
    TEST_ASSERT_EQUAL_UINT64(UdpardPriorityFast, rxf.meta.priority);
    TEST_ASSERT_EQUAL_UINT64(UDPARD_NODE_ID_UNSET, rxf.meta.src_node_id);
    TEST_ASSERT_EQUAL_UINT64(UDPARD_NODE_ID_UNSET, rxf.meta.dst_node_id);
    TEST_ASSERT_EQUAL_UINT64(7654, rxf.meta.data_specifier);
    TEST_ASSERT_EQUAL_UINT64(0xbadc0ffee0ddf00d, rxf.meta.transfer_id);
    TEST_ASSERT_EQUAL_UINT64(0, rxf.base.index);
    TEST_ASSERT_TRUE(rxf.base.end_of_transfer);
    TEST_ASSERT_EQUAL_UINT64(3, rxf.base.payload.size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY("abc", rxf.base.payload.data, 3);
    TEST_ASSERT_EQUAL_UINT64(sizeof(data), rxf.base.origin.size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(data, rxf.base.origin.data, sizeof(data));
}

static void testParseFrameRPCServiceAnonymous(void)
{
    byte_t  data[] = {1,   2,   255, 255, 215, 17, 123, 192, 13, 240, 221, 224,
                      254, 15,  220, 186, 254, 25, 0,   0,   0,  0,   75,  79,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
}

static void testParseFrameRPCServiceBroadcast(void)
{
    byte_t  data[] = {1,   2,   41,  9,   255, 255, 123, 192, 13, 240, 221, 224,
                      254, 15,  220, 186, 254, 25,  0,   0,   0,  0,   248, 152,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
}

static void testParseFrameAnonymousNonSingleFrame(void)
{  // Invalid anonymous message frame because EOT not set (multi-frame anonymous transfers are not allowed).
    byte_t  data[] = {1,   2,   255, 255, 255, 255, 230, 29, 13, 240, 221, 224,
                      254, 15,  220, 186, 0,   0,   0,   0,  0,  0,   147, 6,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
}

static void testParseFrameBadHeaderCRC(void)
{  // Bad header CRC.
    byte_t  data[] = {1,   2,   41,  9,   255, 255, 230, 29, 13, 240, 221, 224,
                      254, 15,  220, 186, 57,  48,  0,   0,  0,  0,   30,  180,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
}

static void testParseFrameUnknownHeaderVersion(void)
{
    // >>> from pycyphal.transport.commons.crc import CRC16CCITT
    // >>> list(CRC16CCITT.new(bytes(
    //    [0, 2, 41, 9, 56, 21, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0])).value_as_bytes)
    byte_t  data[] = {0,   2,   41,  9,   56, 21, 230, 29, 13, 240, 221, 224,
                      254, 15,  220, 186, 57, 48, 0,   0,  0,  0,   141, 228,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
}

static void testParseFrameHeaderWithoutPayload(void)
{
    byte_t data[] = {1, 2, 41, 9, 255, 255, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0, 30, 179};
    RxFrame rxf   = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
}

static void testParseFrameEmpty(void)
{
    RxFrame rxf = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = "", .size = 0}, &rxf));
}

static void testSlotRestartEmpty(void)
{
    RxSlot slot = {
        .ts_usec         = 1234567890,
        .transfer_id     = 0x123456789abcdef0,
        .max_index       = 546,
        .eot_index       = 654,
        .accepted_frames = 555,
        .payload_size    = 987,
        .fragments       = NULL,
    };
    InstrumentedAllocator alloc = {0};
    rxSlotRestart(&slot, 0x1122334455667788ULL, &alloc.base, &alloc.base);
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, slot.ts_usec);
    TEST_ASSERT_EQUAL(0x1122334455667788ULL, slot.transfer_id);
    TEST_ASSERT_EQUAL(0, slot.max_index);
    TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, slot.eot_index);
    TEST_ASSERT_EQUAL(0, slot.accepted_frames);
    TEST_ASSERT_EQUAL(0, slot.payload_size);
    TEST_ASSERT_EQUAL(NULL, slot.fragments);
}

static void testSlotRestartNonEmpty(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    byte_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    //
    RxSlot slot = {
        .ts_usec         = 1234567890,
        .transfer_id     = 0x123456789abcdef0,
        .max_index       = 546,
        .eot_index       = 654,
        .accepted_frames = 555,
        .payload_size    = 987,
        //
        .fragments = &makeRxFragment(&mem_fragment.base,
                                     &mem_payload.base,
                                     1,
                                     (struct UdpardPayload){.data = &data[2], .size = 2},
                                     (struct UdpardMutablePayload){.data = data, .size = sizeof(data)},
                                     NULL)
                          ->tree,
    };
    slot.fragments->base.lr[0] = &makeRxFragment(&mem_fragment.base,
                                                 &mem_payload.base,
                                                 0,
                                                 (struct UdpardPayload){.data = &data[1], .size = 1},
                                                 (struct UdpardMutablePayload){.data = data, .size = sizeof(data)},
                                                 slot.fragments)
                                      ->tree.base;
    slot.fragments->base.lr[1] = &makeRxFragment(&mem_fragment.base,
                                                 &mem_payload.base,
                                                 2,
                                                 (struct UdpardPayload){.data = &data[3], .size = 3},
                                                 (struct UdpardMutablePayload){.data = data, .size = sizeof(data)},
                                                 slot.fragments)
                                      ->tree.base;
    // Initialization done, ensure the memory utilization is as we expect.
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(sizeof(data) * 3, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(sizeof(RxFragment) * 3, mem_fragment.allocated_bytes);
    // Now we reset the slot, causing all memory to be freed correctly.
    rxSlotRestart(&slot, 0x1122334455667788ULL, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, slot.ts_usec);
    TEST_ASSERT_EQUAL(0x1122334455667788ULL, slot.transfer_id);
    TEST_ASSERT_EQUAL(0, slot.max_index);
    TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, slot.eot_index);
    TEST_ASSERT_EQUAL(0, slot.accepted_frames);
    TEST_ASSERT_EQUAL(0, slot.payload_size);
    TEST_ASSERT_EQUAL(NULL, slot.fragments);
    // Ensure all memory was freed.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
}

static void testSlotEjectValidLarge(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    //>>> from pycyphal.transport.commons.crc import CRC32C
    //>>> CRC32C.new(data_bytes).value_as_bytes
    static const size_t PayloadSize = 171;
    // Build the fragment tree:
    //      2
    //     / `
    //    1   3
    //   /
    //  0
    RxFragment* const root =                      //
        makeRxFragmentString(&mem_fragment.base,  //
                             &mem_payload.base,
                             2,
                             "Where does Man go? ",
                             NULL);
    root->tree.base.lr[0] =                        //
        &makeRxFragmentString(&mem_fragment.base,  //
                              &mem_payload.base,
                              1,
                              "For example, where does Man come from? ",
                              &root->tree)
             ->tree.base;
    root->tree.base.lr[1] =                        //
        &makeRxFragmentString(&mem_fragment.base,  //
                              &mem_payload.base,
                              3,
                              "Where does the universe come from? xL\xAE\xCB",
                              &root->tree)
             ->tree.base;
    root->tree.base.lr[0]->lr[0] =
        &makeRxFragmentString(&mem_fragment.base,  //
                              &mem_payload.base,
                              0,
                              "Da Shi, have you ever... considered certain ultimate philosophical questions? ",
                              ((RxFragmentTreeNode*) root->tree.base.lr[0]))
             ->tree.base;
    // Initialization done, ensure the memory utilization is as we expect.
    TEST_ASSERT_EQUAL(4, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(PayloadSize + TRANSFER_CRC_SIZE_BYTES, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(4, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(sizeof(RxFragment) * 4, mem_fragment.allocated_bytes);
    // Eject and verify the payload.
    size_t                payload_size = 0;
    struct UdpardFragment payload      = {0};
    TEST_ASSERT(rxSlotEject(&payload_size,
                            &payload,
                            &root->tree,
                            mem_payload.allocated_bytes,
                            1024,
                            &mem_fragment.base,
                            &mem_payload.base));
    TEST_ASSERT_EQUAL(PayloadSize, payload_size);  // CRC removed!
    TEST_ASSERT(                                   //
        compareStringWithPayload("Da Shi, have you ever... considered certain ultimate philosophical questions? ",
                                 payload.view));
    TEST_ASSERT(compareStringWithPayload("For example, where does Man come from? ", payload.next->view));
    TEST_ASSERT(compareStringWithPayload("Where does Man go? ", payload.next->next->view));
    TEST_ASSERT(compareStringWithPayload("Where does the universe come from? ", payload.next->next->next->view));
    TEST_ASSERT_NULL(payload.next->next->next->next);
    // Check the memory utilization. All payload fragments are still kept, but the first fragment is freed because of
    // the Scott's short payload optimization.
    TEST_ASSERT_EQUAL(4, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(PayloadSize + TRANSFER_CRC_SIZE_BYTES, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);                   // One gone!!1
    TEST_ASSERT_EQUAL(sizeof(RxFragment) * 3, mem_fragment.allocated_bytes);  // yes yes!
    // Now, free the payload as the application would.
    udpardFragmentFree(payload, &mem_fragment.base, &mem_payload.base);
    // All memory shall be free now. As in "free beer".
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
}

static void testSlotEjectValidSmall(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    //>>> from pycyphal.transport.commons.crc import CRC32C
    //>>> CRC32C.new(data_bytes).value_as_bytes
    static const size_t PayloadSize = 262;
    // Build the fragment tree:
    //      1
    //     / `
    //    0   3
    //       / `
    //      2   4
    RxFragment* const root =                      //
        makeRxFragmentString(&mem_fragment.base,  //
                             &mem_payload.base,
                             1,
                             "You told me that you came from the sea. Did you build the sea?\n",
                             NULL);
    root->tree.base.lr[0] =                        //
        &makeRxFragmentString(&mem_fragment.base,  //
                              &mem_payload.base,
                              0,
                              "Did you build this four-dimensional fragment?\n",
                              &root->tree)
             ->tree.base;
    root->tree.base.lr[1] =                        //
        &makeRxFragmentString(&mem_fragment.base,  //
                              &mem_payload.base,
                              3,
                              "this four-dimensional space is like the sea for us?\n",
                              &root->tree)
             ->tree.base;
    root->tree.base.lr[1]->lr[0] =                 //
        &makeRxFragmentString(&mem_fragment.base,  //
                              &mem_payload.base,
                              2,
                              "Are you saying that for you, or at least for your creators, ",
                              ((RxFragmentTreeNode*) root->tree.base.lr[1]))
             ->tree.base;
    root->tree.base.lr[1]->lr[1] =                 //
        &makeRxFragmentString(&mem_fragment.base,  //
                              &mem_payload.base,
                              4,
                              "More like a puddle. The sea has gone dry.\xA2\x93-\xB2",
                              ((RxFragmentTreeNode*) root->tree.base.lr[1]))
             ->tree.base;
    // Initialization done, ensure the memory utilization is as we expect.
    TEST_ASSERT_EQUAL(5, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(PayloadSize + TRANSFER_CRC_SIZE_BYTES, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(5, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(sizeof(RxFragment) * 5, mem_fragment.allocated_bytes);
    // Eject and verify the payload. Use a small extent and ensure the excess is dropped.
    size_t                payload_size = 0;
    struct UdpardFragment payload      = {0};
    TEST_ASSERT(rxSlotEject(&payload_size,
                            &payload,
                            &root->tree,
                            mem_payload.allocated_bytes,
                            136,  // <-- small extent, rest truncated
                            &mem_fragment.base,
                            &mem_payload.base));
    TEST_ASSERT_EQUAL(136, payload_size);  // Equals the extent due to the truncation.
    TEST_ASSERT(compareStringWithPayload("Did you build this four-dimensional fragment?\n", payload.view));
    TEST_ASSERT(compareStringWithPayload("You told me that you came from the sea. Did you build the sea?\n",
                                         payload.next->view));
    TEST_ASSERT(compareStringWithPayload("Are you saying that for you", payload.next->next->view));
    TEST_ASSERT_NULL(payload.next->next->next);
    // Check the memory utilization.
    // The first fragment is freed because of the Scott's short payload optimization;
    // the two last fragments are freed because of the truncation.
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(169, mem_payload.allocated_bytes);     // The last block is rounded up.
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);  // One gone!!1
    TEST_ASSERT_EQUAL(sizeof(RxFragment) * 2, mem_fragment.allocated_bytes);
    // Now, free the payload as the application would.
    udpardFragmentFree(payload, &mem_fragment.base, &mem_payload.base);
    // All memory shall be free now. As in "free beer".
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
}

static void testSlotEjectValidEmpty(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    // Build the fragment tree:
    //      1
    //     / `
    //    0   2
    RxFragment* const root = makeRxFragmentString(&mem_fragment.base, &mem_payload.base, 1, "BBB", NULL);
    root->tree.base.lr[0] =
        &makeRxFragmentString(&mem_fragment.base, &mem_payload.base, 0, "AAA", &root->tree)->tree.base;
    root->tree.base.lr[1] =
        &makeRxFragmentString(&mem_fragment.base, &mem_payload.base, 2, "P\xF5\xA5?", &root->tree)->tree.base;
    // Initialization done, ensure the memory utilization is as we expect.
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(6 + TRANSFER_CRC_SIZE_BYTES, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(sizeof(RxFragment) * 3, mem_fragment.allocated_bytes);
    // Eject and verify the payload. The extent is zero, so all payload is removed.
    size_t                payload_size = 0;
    struct UdpardFragment payload      = {0};
    TEST_ASSERT(rxSlotEject(&payload_size,
                            &payload,
                            &root->tree,
                            mem_payload.allocated_bytes,
                            0,
                            &mem_fragment.base,
                            &mem_payload.base));
    TEST_ASSERT_EQUAL(0, payload_size);  // Equals the extent due to the truncation.
    TEST_ASSERT_NULL(payload.next);
    TEST_ASSERT_EQUAL(0, payload.view.size);
    // Check the memory utilization. No memory should be in use by this point.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
    // Now, free the payload as the application would.
    udpardFragmentFree(payload, &mem_fragment.base, &mem_payload.base);
    // No memory is in use anyway, so no change here.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
}

static void testSlotEjectInvalid(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    // Build the fragment tree; no valid CRC here:
    //      1
    //     / `
    //    0   2
    RxFragment* const root = makeRxFragmentString(&mem_fragment.base, &mem_payload.base, 1, "BBB", NULL);
    root->tree.base.lr[0] =
        &makeRxFragmentString(&mem_fragment.base, &mem_payload.base, 0, "AAA", &root->tree)->tree.base;
    root->tree.base.lr[1] =
        &makeRxFragmentString(&mem_fragment.base, &mem_payload.base, 2, "CCC", &root->tree)->tree.base;
    // Initialization done, ensure the memory utilization is as we expect.
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(9, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(sizeof(RxFragment) * 3, mem_fragment.allocated_bytes);
    // Eject and verify the payload.
    size_t                payload_size = 0;
    struct UdpardFragment payload      = {0};
    TEST_ASSERT_FALSE(rxSlotEject(&payload_size,
                                  &payload,
                                  &root->tree,
                                  mem_payload.allocated_bytes,
                                  1000,
                                  &mem_fragment.base,
                                  &mem_payload.base));
    // The call was unsuccessful, so the memory was freed instead of being handed over to the application.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
}

static void testSlotAcceptA(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    // Set up the RX slot instance we're going to be working with.
    RxSlot slot = {
        .ts_usec         = 1234567890,
        .transfer_id     = 0x1122334455667788,
        .max_index       = 0,
        .eot_index       = FRAME_INDEX_UNSET,
        .accepted_frames = 0,
        .payload_size    = 0,
        .fragments       = NULL,
    };
    size_t                payload_size = 0;
    struct UdpardFragment payload      = {0};

    // === TRANSFER ===
    // Accept a single-frame transfer. Ownership transferred to the payload object.
    //>>> from pycyphal.transport.commons.crc import CRC32C
    //>>> CRC32C.new(data_bytes).value_as_bytes
    TEST_ASSERT_EQUAL(1,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,
                                                         0,
                                                         true,
                                                         "The fish responsible for drying the sea are not here."
                                                         "\x04\x1F\x8C\x1F"),
                                   1000,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    // Verify the memory utilization. Note that the small transfer optimization is in effect: head fragment moved.
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(53 + TRANSFER_CRC_SIZE_BYTES, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
    // Verify the payload and free it. Note the CRC is not part of the payload, obviously.
    TEST_ASSERT_EQUAL(53, payload_size);
    TEST_ASSERT(compareStringWithPayload("The fish responsible for drying the sea are not here.", payload.view));
    TEST_ASSERT_NULL(payload.next);
    udpardFragmentFree(payload, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
    // Ensure the slot has been restarted correctly.
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, slot.ts_usec);
    TEST_ASSERT_EQUAL(0x1122334455667789, slot.transfer_id);  // INCREMENTED
    TEST_ASSERT_EQUAL(0, slot.max_index);
    TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, slot.eot_index);
    TEST_ASSERT_EQUAL(0, slot.accepted_frames);
    TEST_ASSERT_EQUAL(0, slot.payload_size);
    TEST_ASSERT_NULL(slot.fragments);

    // === TRANSFER ===
    // Accept a multi-frame transfer. Here, frames arrive in order.
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,
                                                         0,
                                                         false,
                                                         "We're sorry. What you said is really hard to understand.\n"),
                                   1000,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,
                                                         1,
                                                         false,
                                                         "The fish who dried the sea went onto land before they did "
                                                         "this. "),
                                   1000,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(1,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,
                                                         2,
                                                         true,
                                                         "They moved from one dark forest to another dark forest."
                                                         "?\xAC(\xBE"),
                                   1000,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    // Verify the memory utilization. Note that the small transfer optimization is in effect: head fragment moved.
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(176 + TRANSFER_CRC_SIZE_BYTES, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);  // One freed.
    TEST_ASSERT_EQUAL(sizeof(RxFragment) * 2, mem_fragment.allocated_bytes);
    // Verify the payload and free it. Note the CRC is not part of the payload, obviously.
    TEST_ASSERT_EQUAL(176, payload_size);
    TEST_ASSERT(compareStringWithPayload("We're sorry. What you said is really hard to understand.\n", payload.view));
    TEST_ASSERT_NOT_NULL(payload.next);
    TEST_ASSERT(compareStringWithPayload("The fish who dried the sea went onto land before they did this. ",
                                         payload.next->view));
    TEST_ASSERT_NOT_NULL(payload.next->next);
    TEST_ASSERT(compareStringWithPayload("They moved from one dark forest to another dark forest.",  //
                                         payload.next->next->view));
    TEST_ASSERT_NULL(payload.next->next->next);
    udpardFragmentFree(payload, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
    // Ensure the slot has been restarted correctly.
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, slot.ts_usec);
    TEST_ASSERT_EQUAL(0x112233445566778A, slot.transfer_id);  // INCREMENTED
    TEST_ASSERT_EQUAL(0, slot.max_index);
    TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, slot.eot_index);
    TEST_ASSERT_EQUAL(0, slot.accepted_frames);
    TEST_ASSERT_EQUAL(0, slot.payload_size);
    TEST_ASSERT_NULL(slot.fragments);

    // === TRANSFER ===
    // Accept an out-of-order transfer with extent truncation. Frames arrive out-of-order with duplicates.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         2,
                                                         true,
                                                         "Toss it over."
                                                         "K(\xBB\xEE"),
                                   45,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         1,
                                                         false,
                                                         "How do we give it to you?\n"),
                                   45,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         1,
                                                         false,
                                                         "DUPLICATE #1"),
                                   45,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // NO CHANGE, duplicate discarded.
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         2,
                                                         true,
                                                         "DUPLICATE #2"),
                                   45,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // NO CHANGE, duplicate discarded.
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(1,  // transfer completed
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         0,
                                                         false,
                                                         "I like fish. Can I have it?\n"),
                                   45,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    // Verify the memory utilization. Note that the small transfer optimization is in effect: head fragment moved.
    // Due to the implicit truncation (the extent is small), the last fragment is already freed.
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // One freed because of truncation.
    TEST_ASSERT_EQUAL(28 + 26, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);  // One freed because truncation, one optimized away.
    TEST_ASSERT_EQUAL(sizeof(RxFragment) * 1, mem_fragment.allocated_bytes);
    // Verify the payload and free it. Note the CRC is not part of the payload, obviously.
    TEST_ASSERT_EQUAL(45, payload_size);  // Equals the extent.
    TEST_ASSERT(compareStringWithPayload("I like fish. Can I have it?\n", payload.view));
    TEST_ASSERT_NOT_NULL(payload.next);
    TEST_ASSERT(compareStringWithPayload("How do we give it", payload.next->view));  // TRUNCATED
    TEST_ASSERT_NULL(payload.next->next);
    udpardFragmentFree(payload, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
    // Ensure the slot has been restarted correctly.
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, slot.ts_usec);
    TEST_ASSERT_EQUAL(0x112233445566778B, slot.transfer_id);  // INCREMENTED
    TEST_ASSERT_EQUAL(0, slot.max_index);
    TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, slot.eot_index);
    TEST_ASSERT_EQUAL(0, slot.accepted_frames);
    TEST_ASSERT_EQUAL(0, slot.payload_size);
    TEST_ASSERT_NULL(slot.fragments);

    // === TRANSFER ===
    // Shorter than TRANSFER_CRC_SIZE_BYTES, discarded early.
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base, 0, true, ":D"),
                                   1000,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
    // Ensure the slot has been restarted correctly.
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, slot.ts_usec);
    TEST_ASSERT_EQUAL(0x112233445566778C, slot.transfer_id);  // INCREMENTED
    TEST_ASSERT_EQUAL(0, slot.max_index);
    TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, slot.eot_index);
    TEST_ASSERT_EQUAL(0, slot.accepted_frames);
    TEST_ASSERT_EQUAL(0, slot.payload_size);
    TEST_ASSERT_NULL(slot.fragments);

    // === TRANSFER ===
    // OOM on reception. Note that the payload allocator does not require restrictions as the library does not
    // allocate memory for the payload, only for the fragments.
    mem_fragment.limit_fragments = 1;  // Can only store one fragment, but the transfer requires more.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         2,
                                                         true,
                                                         "Toss it over."
                                                         "K(\xBB\xEE"),
                                   1000,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);  // Limit reached here. Cannot accept next fragment.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_MEMORY,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         1,
                                                         false,
                                                         "How do we give it to you?\n"),
                                   1000,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // Payload not accepted, cannot alloc fragment.
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    mem_fragment.limit_fragments = 2;  // Lift the limit and repeat the same frame, this time it is accepted.
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         0,
                                                         false,
                                                         "I like fish. Can I have it?\n"),
                                   1000,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // Accepted!
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_MEMORY,  // Cannot alloc third fragment.
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         1,
                                                         false,
                                                         "How do we give it to you?\n"),
                                   1000,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // Payload not accepted, cannot alloc fragment.
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    mem_fragment.limit_fragments = 3;  // Lift the limit and repeat the same frame, this time it is accepted.
    TEST_ASSERT_EQUAL(1,               // transfer completed
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         1,
                                                         false,
                                                         "How do we give it to you?\n"),
                                   1000,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    // Verify the memory utilization. Note that the small transfer optimization is in effect: head fragment moved.
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(67 + TRANSFER_CRC_SIZE_BYTES, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(sizeof(RxFragment) * 2, mem_fragment.allocated_bytes);
    // Verify the payload and free it. Note the CRC is not part of the payload, obviously.
    TEST_ASSERT_EQUAL(67, payload_size);  // Equals the extent.
    TEST_ASSERT(compareStringWithPayload("I like fish. Can I have it?\n", payload.view));
    TEST_ASSERT_NOT_NULL(payload.next);
    TEST_ASSERT(compareStringWithPayload("How do we give it to you?\n", payload.next->view));
    TEST_ASSERT_NOT_NULL(payload.next->next);
    TEST_ASSERT(compareStringWithPayload("Toss it over.", payload.next->next->view));
    TEST_ASSERT_NULL(payload.next->next->next);
    udpardFragmentFree(payload, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
    // Ensure the slot has been restarted correctly.
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, slot.ts_usec);
    TEST_ASSERT_EQUAL(0x112233445566778D, slot.transfer_id);  // INCREMENTED
    TEST_ASSERT_EQUAL(0, slot.max_index);
    TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, slot.eot_index);
    TEST_ASSERT_EQUAL(0, slot.accepted_frames);
    TEST_ASSERT_EQUAL(0, slot.payload_size);
    TEST_ASSERT_NULL(slot.fragments);

    // === TRANSFER ===
    // Inconsistent EOT flag.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,  // Just an ordinary transfer passing by, what could go wrong?
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         2,
                                                         true,
                                                         "Toss it over."
                                                         "K(\xBB\xEE"),
                                   45,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // Okay, accepted, some data stored...
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         1,                  //
                                                         true,               // SURPRISE! EOT is set in distinct frames!
                                                         "How do we give it to you?\n"),
                                   45,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);  // This is outrageous. Of course we have to drop everything.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // Ensure the slot has been restarted correctly.
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, slot.ts_usec);
    TEST_ASSERT_EQUAL(0x112233445566778E, slot.transfer_id);  // INCREMENTED
    TEST_ASSERT_EQUAL(0, slot.max_index);
    TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, slot.eot_index);
    TEST_ASSERT_EQUAL(0, slot.accepted_frames);
    TEST_ASSERT_EQUAL(0, slot.payload_size);
    TEST_ASSERT_NULL(slot.fragments);

    // === TRANSFER ===
    // More frames past the EOT; or, in other words, the frame index where EOT is set is not the maximum index.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         2,
                                                         true,
                                                         "Toss it over."
                                                         "K(\xBB\xEE"),
                                   45,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // Okay, accepted, some data stored...
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload.base,  //
                                                         3,                  // SURPRISE! Frame #3 while #2 was EOT!
                                                         false,
                                                         "How do we give it to you?\n"),
                                   45,
                                   &mem_fragment.base,
                                   &mem_payload.base));
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);  // This is outrageous. Of course we have to drop everything.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // Ensure the slot has been restarted correctly.
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, slot.ts_usec);
    TEST_ASSERT_EQUAL(0x112233445566778F, slot.transfer_id);  // INCREMENTED
    TEST_ASSERT_EQUAL(0, slot.max_index);
    TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, slot.eot_index);
    TEST_ASSERT_EQUAL(0, slot.accepted_frames);
    TEST_ASSERT_EQUAL(0, slot.payload_size);
    TEST_ASSERT_NULL(slot.fragments);
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(testParseFrameValidMessage);
    RUN_TEST(testParseFrameValidRPCService);
    RUN_TEST(testParseFrameValidMessageAnonymous);
    RUN_TEST(testParseFrameRPCServiceAnonymous);
    RUN_TEST(testParseFrameRPCServiceBroadcast);
    RUN_TEST(testParseFrameAnonymousNonSingleFrame);
    RUN_TEST(testParseFrameBadHeaderCRC);
    RUN_TEST(testParseFrameUnknownHeaderVersion);
    RUN_TEST(testParseFrameHeaderWithoutPayload);
    RUN_TEST(testParseFrameEmpty);
    RUN_TEST(testSlotRestartEmpty);
    RUN_TEST(testSlotRestartNonEmpty);
    RUN_TEST(testSlotEjectValidLarge);
    RUN_TEST(testSlotEjectValidSmall);
    RUN_TEST(testSlotEjectValidEmpty);
    RUN_TEST(testSlotEjectInvalid);
    RUN_TEST(testSlotAcceptA);
    return UNITY_END();
}

// NOLINTEND(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
