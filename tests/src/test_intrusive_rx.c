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

static RxFrame makeRxFrameString(struct UdpardMemoryResource* const memory_payload,
                                 const TransferMetadata             meta,
                                 const uint32_t                     frame_index,
                                 const bool                         end_of_transfer,
                                 const char* const                  payload)
{
    return (RxFrame){.base = makeRxFrameBaseString(memory_payload, frame_index, end_of_transfer, payload),
                     .meta = meta};
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

static void testIfaceIsFutureTransferID(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    RxIface iface;
    rxIfaceInit(&iface, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    for (size_t i = 0; i < RX_SLOT_COUNT; i++)
    {
        TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.slots[i].ts_usec);
        TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[i].transfer_id);
        TEST_ASSERT_EQUAL(0, iface.slots[i].max_index);
        TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, iface.slots[i].eot_index);
        TEST_ASSERT_EQUAL(0, iface.slots[i].accepted_frames);
        TEST_ASSERT_EQUAL(0, iface.slots[i].payload_size);
        TEST_ASSERT_NULL(iface.slots[i].fragments);
    }
    TEST_ASSERT_TRUE(rxIfaceIsFutureTransferID(&iface, 0));
    TEST_ASSERT_TRUE(rxIfaceIsFutureTransferID(&iface, 0xFFFFFFFFFFFFFFFFULL));
    iface.slots[0].transfer_id = 100;
    TEST_ASSERT_FALSE(rxIfaceIsFutureTransferID(&iface, 99));
    TEST_ASSERT_FALSE(rxIfaceIsFutureTransferID(&iface, 100));
    TEST_ASSERT_TRUE(rxIfaceIsFutureTransferID(&iface, 101));
    iface.slots[0].transfer_id = TRANSFER_ID_UNSET;
    iface.slots[1].transfer_id = 100;
    TEST_ASSERT_FALSE(rxIfaceIsFutureTransferID(&iface, 99));
    TEST_ASSERT_FALSE(rxIfaceIsFutureTransferID(&iface, 100));
    TEST_ASSERT_TRUE(rxIfaceIsFutureTransferID(&iface, 101));
}

static void testIfaceCheckTransferIDTimeout(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    RxIface iface;
    rxIfaceInit(&iface, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    for (size_t i = 0; i < RX_SLOT_COUNT; i++)
    {
        TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.slots[i].ts_usec);
        TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[i].transfer_id);
        TEST_ASSERT_EQUAL(0, iface.slots[i].max_index);
        TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, iface.slots[i].eot_index);
        TEST_ASSERT_EQUAL(0, iface.slots[i].accepted_frames);
        TEST_ASSERT_EQUAL(0, iface.slots[i].payload_size);
        TEST_ASSERT_NULL(iface.slots[i].fragments);
    }
    // No successful transfers so far, and no slots in progress at the moment.
    TEST_ASSERT_TRUE(rxIfaceCheckTransferIDTimeout(&iface, 0, 100));
    TEST_ASSERT_TRUE(rxIfaceCheckTransferIDTimeout(&iface, 1000, 100));
    // Suppose we have on successful transfer now.
    iface.ts_usec = 1000;
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 500, 100));  // TS is in the past! Check overflows.
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 1000, 100));
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 1050, 100));
    TEST_ASSERT_TRUE(rxIfaceCheckTransferIDTimeout(&iface, 1150, 100));  // Yup, this is a timeout.
    TEST_ASSERT_TRUE(rxIfaceCheckTransferIDTimeout(&iface, 2150, 100));  // Yup, this is a timeout.
    // Suppose there are some slots in progress.
    iface.ts_usec          = 1000;
    iface.slots[0].ts_usec = 2000;
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 500, 100));  // TS is in the past! Check overflows.
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 1000, 100));
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 1050, 100));
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 1150, 100));  // No timeout because of the slot in progress.
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 2050, 100));  // Nope.
    TEST_ASSERT_TRUE(rxIfaceCheckTransferIDTimeout(&iface, 2150, 100));   // Yeah.
    TEST_ASSERT_TRUE(rxIfaceCheckTransferIDTimeout(&iface, 3050, 100));   // Ooh.
    // More slots in progress.
    iface.ts_usec          = 1000;
    iface.slots[0].ts_usec = 2000;
    iface.slots[1].ts_usec = 3000;
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 500, 100));  // TS is in the past! Check overflows.
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 1000, 100));
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 1050, 100));
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 1150, 100));  // No timeout because of the slot in progress.
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 2050, 100));  // Nope.
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 2150, 100));  // The other slot is newer.
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 3050, 100));  // Yes, but not yet.
    TEST_ASSERT_TRUE(rxIfaceCheckTransferIDTimeout(&iface, 3150, 100));   // Yes.
    // Now suppose there is no successful transfer, but there are some slots in progress. It's all the same.
    iface.ts_usec          = TIMESTAMP_UNSET;
    iface.slots[0].ts_usec = 2000;
    iface.slots[1].ts_usec = 3000;
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 500, 100));  // TS is in the past! Check overflows.
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 1000, 100));
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 1050, 100));
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 1150, 100));  // No timeout because of the slot in progress.
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 2050, 100));  // Nope.
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 2150, 100));  // The other slot is newer.
    TEST_ASSERT_FALSE(rxIfaceCheckTransferIDTimeout(&iface, 3050, 100));  // Yes, but not yet.
    TEST_ASSERT_TRUE(rxIfaceCheckTransferIDTimeout(&iface, 3150, 100));   // Ooh yes.
}

static void testIfaceFindMatchingSlot(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    RxSlot slots[RX_SLOT_COUNT] = {0};
    rxSlotRestart(&slots[0], 1000, &mem_fragment.base, &mem_payload.base);
    rxSlotRestart(&slots[1], 1001, &mem_fragment.base, &mem_payload.base);
    // No matching slot.
    TEST_ASSERT_NULL(rxIfaceFindMatchingSlot(slots, 123));
    // Matching slots.
    TEST_ASSERT_EQUAL_PTR(&slots[0], rxIfaceFindMatchingSlot(slots, 1000));
    TEST_ASSERT_EQUAL_PTR(&slots[1], rxIfaceFindMatchingSlot(slots, 1001));
    // Identical slots, neither in progress.
    slots[0].ts_usec     = TIMESTAMP_UNSET;
    slots[1].ts_usec     = TIMESTAMP_UNSET;
    slots[0].transfer_id = 1000;
    slots[1].transfer_id = 1000;
    TEST_ASSERT_EQUAL_PTR(&slots[0], rxIfaceFindMatchingSlot(slots, 1000));  // First match.
    TEST_ASSERT_EQUAL_PTR(NULL, rxIfaceFindMatchingSlot(slots, 1001));
    // Identical slots, one of them in progress.
    slots[0].ts_usec = TIMESTAMP_UNSET;
    slots[1].ts_usec = 1234567890;
    TEST_ASSERT_EQUAL_PTR(&slots[1], rxIfaceFindMatchingSlot(slots, 1000));
    TEST_ASSERT_EQUAL_PTR(NULL, rxIfaceFindMatchingSlot(slots, 1001));
    // The other is in progress now.
    slots[0].ts_usec = 1234567890;
    slots[1].ts_usec = TIMESTAMP_UNSET;
    TEST_ASSERT_EQUAL_PTR(&slots[0], rxIfaceFindMatchingSlot(slots, 1000));
    TEST_ASSERT_EQUAL_PTR(NULL, rxIfaceFindMatchingSlot(slots, 1001));
    // Both in progress, pick first.
    slots[0].ts_usec = 1234567890;
    slots[1].ts_usec = 2345678901;
    TEST_ASSERT_EQUAL_PTR(&slots[0], rxIfaceFindMatchingSlot(slots, 1000));
    TEST_ASSERT_EQUAL_PTR(NULL, rxIfaceFindMatchingSlot(slots, 1001));
}

static void testIfaceAcceptA(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    RxIface iface;
    rxIfaceInit(&iface, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    for (size_t i = 0; i < RX_SLOT_COUNT; i++)
    {
        TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.slots[i].ts_usec);
        TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[i].transfer_id);
        TEST_ASSERT_EQUAL(0, iface.slots[i].max_index);
        TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, iface.slots[i].eot_index);
        TEST_ASSERT_EQUAL(0, iface.slots[i].accepted_frames);
        TEST_ASSERT_EQUAL(0, iface.slots[i].payload_size);
        TEST_ASSERT_NULL(iface.slots[i].fragments);
    }
    struct UdpardRxTransfer transfer = {0};

    // === TRANSFER ===
    // A simple single-frame transfer successfully accepted.
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    1234567890,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1234,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1234,
                                                                         .transfer_id    = 0x1122334455667788U},
                                                      0,
                                                      true,
                                                      "I am a tomb."
                                                      "\x1F\\\xCDs"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);  // Head fragment is not heap-allocated.
    // Check the transfer we just accepted.
    TEST_ASSERT_EQUAL(1234567890, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityHigh, transfer.priority);
    TEST_ASSERT_EQUAL(1234, transfer.source_node_id);
    TEST_ASSERT_EQUAL(0x1122334455667788U, transfer.transfer_id);
    TEST_ASSERT_EQUAL(12, transfer.payload_size);
    TEST_ASSERT(compareStringWithPayload("I am a tomb.", transfer.payload.view));
    udpardFragmentFree(transfer.payload, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // Check the internal states of the iface.
    TEST_ASSERT_EQUAL(1234567890, iface.ts_usec);
    TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[0].transfer_id);    // Still unused.
    TEST_ASSERT_EQUAL(0x1122334455667789U, iface.slots[1].transfer_id);  // Incremented.

    // === TRANSFER ===
    // Send a duplicate and ensure it is rejected.
    TEST_ASSERT_EQUAL(0,  // No transfer accepted.
                      rxIfaceAccept(&iface,
                                    1234567891,                           // different timestamp but ignored anyway
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1234,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1234,
                                                                         .transfer_id    = 0x1122334455667788U},
                                                      0,
                                                      true,
                                                      "I am a tomb."
                                                      "\x1F\\\xCDs"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // Check the internal states of the iface.
    TEST_ASSERT_EQUAL(1234567890, iface.ts_usec);                        // same old timestamp
    TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[0].transfer_id);    // Still unused.
    TEST_ASSERT_EQUAL(0x1122334455667789U, iface.slots[1].transfer_id);  // good ol' transfer id

    // === TRANSFER ===
    // Send a non-duplicate transfer with an invalid CRC using an in-sequence (matching) transfer-ID.
    TEST_ASSERT_EQUAL(0,  // No transfer accepted.
                      rxIfaceAccept(&iface,
                                    1234567892,                           // different timestamp but ignored anyway
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1234,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1234,
                                                                         .transfer_id    = 0x1122334455667789U},
                                                      0,
                                                      true,
                                                      "I am a tomb."
                                                      "No CRC here."),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // Check the internal states of the iface.
    TEST_ASSERT_EQUAL(1234567890, iface.ts_usec);                        // same old timestamp
    TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[0].transfer_id);    // Still unused.
    TEST_ASSERT_EQUAL(0x112233445566778AU, iface.slots[1].transfer_id);  // Incremented.

    // === TRANSFER ===
    // Send a non-duplicate transfer with an invalid CRC using an out-of-sequence (non-matching) transfer-ID.
    // Transfer-ID jumps forward, no existing slot; will use the second one.
    TEST_ASSERT_EQUAL(0,  // No transfer accepted.
                      rxIfaceAccept(&iface,
                                    1234567893,                           // different timestamp but ignored anyway
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1234,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1234,
                                                                         .transfer_id    = 0x1122334455667790U},
                                                      0,
                                                      true,
                                                      "I am a tomb."
                                                      "No CRC here, #2."),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // Check the internal states of the iface.
    TEST_ASSERT_EQUAL(1234567890, iface.ts_usec);                        // same old timestamp
    TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[0].transfer_id);    // Still unused.
    TEST_ASSERT_EQUAL(0x1122334455667791U, iface.slots[1].transfer_id);  // Replaced the old one, it was unneeded.

    // === TRANSFER === (x2)
    // Send two interleaving multi-frame out-of-order transfers:
    //  A2 B1 A0 B0 A1
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // A2
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000020,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1111,
                                                                         .transfer_id    = 1000U},
                                                      2,
                                                      true,
                                                      "A2"
                                                      "v\x1E\xBD]"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(1234567890, iface.ts_usec);                      // same old timestamp
    TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[0].transfer_id);  // Still unused.
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);               // Replaced the old one, it was unneeded.
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // B1
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000010,                           // Transfer-ID timeout.
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPrioritySlow,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x2222,
                                                                         .transfer_id    = 1001U},
                                                      1,
                                                      true,
                                                      "B1"
                                                      "g\x8D\x9A\xD7"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(1234567890, iface.ts_usec);         // same old timestamp
    TEST_ASSERT_EQUAL(1001, iface.slots[0].transfer_id);  // Used for B because the other one is taken.
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);  // Keeps A because it is in-progress, can't discard.
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    // A0
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000030,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1111,
                                                                         .transfer_id    = 1000U},
                                                      0,
                                                      false,
                                                      "A0"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(1234567890, iface.ts_usec);  // same old timestamp
    TEST_ASSERT_EQUAL(1001, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);
    // B0
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000040,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPrioritySlow,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x2222,
                                                                         .transfer_id    = 1001U},
                                                      0,
                                                      false,
                                                      "B0"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    // TRANSFER B RECEIVED, check it.
    TEST_ASSERT_EQUAL(2000000010, iface.ts_usec);
    TEST_ASSERT_EQUAL(1002, iface.slots[0].transfer_id);  // Incremented to meet the next transfer.
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(4, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);  // One fragment freed because of the head optimization.
    // Check the payload.
    TEST_ASSERT_EQUAL(2000000010, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPrioritySlow, transfer.priority);
    TEST_ASSERT_EQUAL(2222, transfer.source_node_id);
    TEST_ASSERT_EQUAL(1001, transfer.transfer_id);
    TEST_ASSERT_EQUAL(4, transfer.payload_size);
    TEST_ASSERT(compareStringWithPayload("B0", transfer.payload.view));
    TEST_ASSERT_NOT_NULL(transfer.payload.next);
    TEST_ASSERT(compareStringWithPayload("B1", transfer.payload.next->view));
    TEST_ASSERT_NULL(transfer.payload.next->next);
    udpardFragmentFree(transfer.payload, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // Only the remaining A0 A2 are left.
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    // A1
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000050,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1111,
                                                                         .transfer_id    = 1000U},
                                                      1,
                                                      false,
                                                      "A1"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    // TRANSFER A RECEIVED, check it.
    TEST_ASSERT_EQUAL(2000000020, iface.ts_usec);  // same old timestamp
    TEST_ASSERT_EQUAL(1002, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1001, iface.slots[1].transfer_id);  // Incremented to meet the next transfer.
    // Check the payload.
    TEST_ASSERT_EQUAL(2000000020, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityHigh, transfer.priority);
    TEST_ASSERT_EQUAL(1111, transfer.source_node_id);
    TEST_ASSERT_EQUAL(1000, transfer.transfer_id);
    TEST_ASSERT_EQUAL(6, transfer.payload_size);
    TEST_ASSERT(compareStringWithPayload("A0", transfer.payload.view));
    TEST_ASSERT_NOT_NULL(transfer.payload.next);
    TEST_ASSERT(compareStringWithPayload("A1", transfer.payload.next->view));
    TEST_ASSERT_NOT_NULL(transfer.payload.next->next);
    TEST_ASSERT(compareStringWithPayload("A2", transfer.payload.next->next->view));
    TEST_ASSERT_NULL(transfer.payload.next->next->next);
    udpardFragmentFree(transfer.payload, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
}

static void testIfaceAcceptB(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    RxIface iface;
    rxIfaceInit(&iface, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    for (size_t i = 0; i < RX_SLOT_COUNT; i++)
    {
        TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.slots[i].ts_usec);
        TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[i].transfer_id);
        TEST_ASSERT_EQUAL(0, iface.slots[i].max_index);
        TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, iface.slots[i].eot_index);
        TEST_ASSERT_EQUAL(0, iface.slots[i].accepted_frames);
        TEST_ASSERT_EQUAL(0, iface.slots[i].payload_size);
        TEST_ASSERT_NULL(iface.slots[i].fragments);
    }
    struct UdpardRxTransfer transfer = {0};
    // === TRANSFER === (x3)
    // Send three interleaving multi-frame out-of-order transfers (primes for duplicates):
    //  A2 B1 A0 C0 B0 A1 C0' C1
    // Transfer B will be evicted by C because by the time C0 arrives, transfer B is the oldest one,
    // since its timestamp is inherited from B0.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // A2
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000020,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1111,
                                                                         .transfer_id    = 1000U},
                                                      2,
                                                      true,
                                                      "A2"
                                                      "v\x1E\xBD]"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // B1
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000010,                           // Transfer-ID timeout.
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPrioritySlow,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x2222,
                                                                         .transfer_id    = 1001U},
                                                      1,
                                                      true,
                                                      "B1"
                                                      "g\x8D\x9A\xD7"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(1001, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    // A0
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000030,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1111,
                                                                         .transfer_id    = 1000U},
                                                      0,
                                                      false,
                                                      "A0"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(1001, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);
    // C0
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000040,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 3333,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x3333,
                                                                         .transfer_id    = 1002U},
                                                      0,
                                                      false,
                                                      "C0"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(1002, iface.slots[0].transfer_id);  // B evicted by C.
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);  // Payload of B is freed, so the usage is unchanged.
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);
    // B0
    TEST_ASSERT_EQUAL(0,  // Cannot be accepted because its slot is taken over by C.
                      rxIfaceAccept(&iface,
                                    2000000050,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPrioritySlow,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x2222,
                                                                         .transfer_id    = 1001U},
                                                      0,
                                                      false,
                                                      "B0"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(1002, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);  // No increase, frame not accepted.
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);
    // A1
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000050,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1111,
                                                                         .transfer_id    = 1000U},
                                                      1,
                                                      false,
                                                      "A1"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    // TRANSFER A RECEIVED, check it.
    TEST_ASSERT_EQUAL(2000000020, iface.ts_usec);  // same old timestamp
    TEST_ASSERT_EQUAL(1002, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1001, iface.slots[1].transfer_id);  // Incremented to meet the next transfer.
    // Check the payload.
    TEST_ASSERT_EQUAL(2000000020, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityHigh, transfer.priority);
    TEST_ASSERT_EQUAL(1111, transfer.source_node_id);
    TEST_ASSERT_EQUAL(1000, transfer.transfer_id);
    TEST_ASSERT_EQUAL(6, transfer.payload_size);
    TEST_ASSERT(compareStringWithPayload("A0", transfer.payload.view));
    TEST_ASSERT_NOT_NULL(transfer.payload.next);
    TEST_ASSERT(compareStringWithPayload("A1", transfer.payload.next->view));
    TEST_ASSERT_NOT_NULL(transfer.payload.next->next);
    TEST_ASSERT(compareStringWithPayload("A2", transfer.payload.next->next->view));
    TEST_ASSERT_NULL(transfer.payload.next->next->next);
    udpardFragmentFree(transfer.payload, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // Some memory is retained for the C0 payload.
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // C0 DUPLICATE
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000060,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 3333,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x3333,
                                                                         .transfer_id    = 1002U},
                                                      0,
                                                      false,
                                                      "C0 DUPLICATE"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(2000000020, iface.ts_usec);  // Last transfer timestamp.
    TEST_ASSERT_EQUAL(1002, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1001, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // Not accepted, so no change.
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // C1
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000070,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 3333,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x3333,
                                                                         .transfer_id    = 1002U},
                                                      1,
                                                      true,
                                                      "C1"
                                                      "\xA8\xBF}\x19"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    // TRANSFER C RECEIVED, check it.
    TEST_ASSERT_EQUAL(2000000040, iface.ts_usec);
    TEST_ASSERT_EQUAL(1003, iface.slots[0].transfer_id);  // Incremented to meet the next transfer.
    TEST_ASSERT_EQUAL(1001, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);   // Keeping two fragments of C.
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);  // Head optimization in effect.
    // Check the payload.
    TEST_ASSERT_EQUAL(2000000040, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityHigh, transfer.priority);
    TEST_ASSERT_EQUAL(3333, transfer.source_node_id);
    TEST_ASSERT_EQUAL(1002, transfer.transfer_id);
    TEST_ASSERT_EQUAL(4, transfer.payload_size);
    TEST_ASSERT(compareStringWithPayload("C0", transfer.payload.view));
    TEST_ASSERT_NOT_NULL(transfer.payload.next);
    TEST_ASSERT(compareStringWithPayload("C1", transfer.payload.next->view));
    TEST_ASSERT_NULL(transfer.payload.next->next);
    udpardFragmentFree(transfer.payload, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);  // Some memory is retained for the C0 payload.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
}

static void testIfaceAcceptC(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    RxIface iface;
    rxIfaceInit(&iface, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    for (size_t i = 0; i < RX_SLOT_COUNT; i++)
    {
        TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.slots[i].ts_usec);
        TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[i].transfer_id);
        TEST_ASSERT_EQUAL(0, iface.slots[i].max_index);
        TEST_ASSERT_EQUAL(FRAME_INDEX_UNSET, iface.slots[i].eot_index);
        TEST_ASSERT_EQUAL(0, iface.slots[i].accepted_frames);
        TEST_ASSERT_EQUAL(0, iface.slots[i].payload_size);
        TEST_ASSERT_NULL(iface.slots[i].fragments);
    }
    struct UdpardRxTransfer transfer = {0};
    // === TRANSFER ===
    // Send interleaving multi-frame transfers such that in the end slots have the same transfer-ID value
    // (primes for duplicates):
    //  A0 B0 A1 C0 B1 C1 B1'
    // The purpose of this test is to ensure that the case of multiple RX slots having the same transfer-ID is
    // handled correctly (including correct duplicate detection).
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // A0
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000010,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityOptional,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xA},
                                                      0,
                                                      false,
                                                      "A0"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(0xA, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // B0
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000020,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xB},
                                                      0,
                                                      false,
                                                      "B0"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(0xB, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(0xA, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    // A1
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000030,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityOptional,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xA},
                                                      1,
                                                      true,
                                                      "A1"
                                                      "\xc7\xac_\x81"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    // Check the received transfer.
    TEST_ASSERT_EQUAL(2000000010, iface.ts_usec);
    TEST_ASSERT_EQUAL(0xB, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(0xB, iface.slots[1].transfer_id);  // SAME VALUE!!1
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);  // Head optimization in effect.
    TEST_ASSERT_EQUAL(UdpardPriorityOptional, transfer.priority);
    TEST_ASSERT_EQUAL(4, transfer.payload_size);
    TEST_ASSERT(compareStringWithPayload("A0", transfer.payload.view));
    TEST_ASSERT_NOT_NULL(transfer.payload.next);
    TEST_ASSERT(compareStringWithPayload("A1", transfer.payload.next->view));
    TEST_ASSERT_NULL(transfer.payload.next->next);
    udpardFragmentFree(transfer.payload, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // B0 still allocated.
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // C0
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000040,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                         .src_node_id    = 3333,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xC},
                                                      0,
                                                      false,
                                                      "C0"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(2000000010, iface.ts_usec);  // <- unchanged.
    TEST_ASSERT_EQUAL(0xB, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(0xC, iface.slots[1].transfer_id);     // <- reused for C.
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // Two transfers in transit again: B and C.
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    // B1
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000050,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xB},
                                                      1,
                                                      true,
                                                      "B1"
                                                      "g\x8D\x9A\xD7"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    // Check the received transfer.
    TEST_ASSERT_EQUAL(2000000020, iface.ts_usec);
    TEST_ASSERT_EQUAL(0xC, iface.slots[0].transfer_id);  // <-- INCREMENTED, SO
    TEST_ASSERT_EQUAL(0xC, iface.slots[1].transfer_id);  // WE HAVE TWO IDENTICAL VALUES AGAIN!
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(UdpardPriorityExceptional, transfer.priority);
    TEST_ASSERT_EQUAL(4, transfer.payload_size);
    TEST_ASSERT(compareStringWithPayload("B0", transfer.payload.view));
    TEST_ASSERT_NOT_NULL(transfer.payload.next);
    TEST_ASSERT(compareStringWithPayload("B1", transfer.payload.next->view));
    TEST_ASSERT_NULL(transfer.payload.next->next);
    udpardFragmentFree(transfer.payload, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // C0 is still allocated.
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // C1
    // This is the DIFFICULT CASE because we have two RX slots with the same transfer-ID, but THE FIRST ONE IS NOT
    // THE ONE THAT WE NEED! Watch what happens next.
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000060,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                         .src_node_id    = 3333,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xC},
                                                      1,
                                                      true,
                                                      "C1"
                                                      "\xA8\xBF}\x19"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    // Check the received transfer.
    TEST_ASSERT_EQUAL(2000000040, iface.ts_usec);
    TEST_ASSERT_EQUAL(0xC, iface.slots[0].transfer_id);  // Old, unused.
    TEST_ASSERT_EQUAL(0xD, iface.slots[1].transfer_id);  // INCREMENTED!
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(UdpardPriorityExceptional, transfer.priority);
    TEST_ASSERT_EQUAL(3333, transfer.source_node_id);
    TEST_ASSERT_EQUAL(4, transfer.payload_size);
    TEST_ASSERT(compareStringWithPayload("C0", transfer.payload.view));
    TEST_ASSERT_NOT_NULL(transfer.payload.next);
    TEST_ASSERT(compareStringWithPayload("C1", transfer.payload.next->view));
    TEST_ASSERT_NULL(transfer.payload.next->next);
    udpardFragmentFree(transfer.payload, &mem_fragment.base, &mem_payload.base);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // B0 duplicate multi-frame; shall be rejected.
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000070,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xB},
                                                      0,
                                                      false,
                                                      "B0"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // B0 duplicate single-frame; shall be rejected.
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000080,
                                    makeRxFrameString(&mem_payload.base,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xB},
                                                      0,
                                                      true,
                                                      "B0"
                                                      "g\x8D\x9A\xD7"),
                                    &transfer,
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    &mem_fragment.base,
                                    &mem_payload.base));
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    // frame parser
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
    // slot
    RUN_TEST(testSlotRestartEmpty);
    RUN_TEST(testSlotRestartNonEmpty);
    RUN_TEST(testSlotEjectValidLarge);
    RUN_TEST(testSlotEjectValidSmall);
    RUN_TEST(testSlotEjectValidEmpty);
    RUN_TEST(testSlotEjectInvalid);
    RUN_TEST(testSlotAcceptA);
    // iface
    RUN_TEST(testIfaceIsFutureTransferID);
    RUN_TEST(testIfaceCheckTransferIDTimeout);
    RUN_TEST(testIfaceFindMatchingSlot);
    RUN_TEST(testIfaceAcceptA);
    RUN_TEST(testIfaceAcceptB);
    RUN_TEST(testIfaceAcceptC);
    return UNITY_END();
}

// NOLINTEND(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
