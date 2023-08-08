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
static RxFragment* makeRxFragment(const RxMemory                    memory,
                                  const uint32_t                    frame_index,
                                  const struct UdpardPayload        view,
                                  const struct UdpardMutablePayload origin,
                                  RxFragmentTreeNode* const         parent)
{
    TEST_PANIC_UNLESS((view.data >= origin.data) && (view.size <= origin.size));
    TEST_PANIC_UNLESS((((const byte_t*) view.data) + view.size) <= (((const byte_t*) origin.data) + origin.size));
    byte_t* const     new_origin = (byte_t*) instrumentedAllocatorAllocate(memory.payload.user_reference, origin.size);
    RxFragment* const frag       = (RxFragment*) memAlloc(memory.fragment, sizeof(RxFragment));
    if ((new_origin != NULL) && (frag != NULL))
    {
        (void) memmove(new_origin, origin.data, origin.size);
        (void) memset(frag, 0, sizeof(RxFragment));
        frag->tree.base.lr[0]  = NULL;
        frag->tree.base.lr[1]  = NULL;
        frag->tree.base.up     = &parent->base;
        frag->tree.this        = frag;
        frag->frame_index      = frame_index;
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
static RxFragment* makeRxFragmentString(const RxMemory            memory,
                                        const uint32_t            frame_index,
                                        const char* const         payload,
                                        RxFragmentTreeNode* const parent)
{
    const size_t sz = strlen(payload);
    return makeRxFragment(memory,
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

static RxFrameBase makeRxFrameBase(InstrumentedAllocator* const      memory_payload,
                                   const uint32_t                    frame_index,
                                   const bool                        end_of_transfer,
                                   const struct UdpardPayload        view,
                                   const struct UdpardMutablePayload origin)
{
    TEST_PANIC_UNLESS((view.data >= origin.data) && (view.size <= origin.size));
    TEST_PANIC_UNLESS((((const byte_t*) view.data) + view.size) <= (((const byte_t*) origin.data) + origin.size));
    RxFrameBase   out        = {0};
    byte_t* const new_origin = (byte_t*) instrumentedAllocatorAllocate(memory_payload, origin.size);
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

static RxFrameBase makeRxFrameBaseString(InstrumentedAllocator* const memory,
                                         const uint32_t               frame_index,
                                         const bool                   end_of_transfer,
                                         const char* const            payload)
{
    return makeRxFrameBase(memory,
                           frame_index,
                           end_of_transfer,
                           (struct UdpardPayload){.data = payload, .size = strlen(payload)},
                           (struct UdpardMutablePayload){.data = (void*) payload, .size = strlen(payload)});
}

static RxFrame makeRxFrameString(InstrumentedAllocator* const memory,
                                 const TransferMetadata       meta,
                                 const uint32_t               frame_index,
                                 const bool                   end_of_transfer,
                                 const char* const            payload)
{
    return (RxFrame){.base = makeRxFrameBaseString(memory, frame_index, end_of_transfer, payload), .meta = meta};
}

static RxMemory makeRxMemory(InstrumentedAllocator* const fragment, InstrumentedAllocator* const payload)
{
    return (RxMemory){.fragment = instrumentedAllocatorMakeMemoryResource(fragment),
                      .payload  = instrumentedAllocatorMakeMemoryDeleter(payload)};
}

static struct UdpardMutablePayload makeDatagramPayload(InstrumentedAllocator* const memory,
                                                       const TransferMetadata       meta,
                                                       const uint32_t               frame_index,
                                                       const bool                   end_of_transfer,
                                                       const struct UdpardPayload   payload)
{
    struct UdpardMutablePayload pld = {.size = payload.size + HEADER_SIZE_BYTES};
    pld.data                        = instrumentedAllocatorAllocate(memory, pld.size);
    if (pld.data != NULL)
    {
        (void) memcpy(txSerializeHeader(pld.data, meta, frame_index, end_of_transfer), payload.data, payload.size);
    }
    else
    {
        TEST_PANIC("Failed to allocate datagram payload");
    }
    return pld;
}

static struct UdpardMutablePayload makeDatagramPayloadString(InstrumentedAllocator* const memory,
                                                             const TransferMetadata       meta,
                                                             const uint32_t               frame_index,
                                                             const bool                   end_of_transfer,
                                                             const char* const            string)
{
    return makeDatagramPayload(memory,
                               meta,
                               frame_index,
                               end_of_transfer,
                               (struct UdpardPayload){.data = string, .size = strlen(string)});
}

static struct UdpardMutablePayload makeDatagramPayloadSingleFrame(InstrumentedAllocator* const memory,
                                                                  const TransferMetadata       meta,
                                                                  const struct UdpardPayload   payload)
{
    struct UdpardMutablePayload pld =
        makeDatagramPayload(memory,
                            meta,
                            0,
                            true,
                            (struct UdpardPayload){.data = payload.data,
                                                   .size = payload.size + TRANSFER_CRC_SIZE_BYTES});
    TEST_PANIC_UNLESS(pld.size == (payload.size + HEADER_SIZE_BYTES + TRANSFER_CRC_SIZE_BYTES));
    txSerializeU32(((byte_t*) pld.data) + HEADER_SIZE_BYTES + payload.size,
                   transferCRCCompute(payload.size, payload.data));
    return pld;
}

static struct UdpardMutablePayload makeDatagramPayloadSingleFrameString(InstrumentedAllocator* const memory,
                                                                        const TransferMetadata       meta,
                                                                        const char* const            payload)
{
    return makeDatagramPayloadSingleFrame(memory,
                                          meta,
                                          (struct UdpardPayload){.data = payload, .size = strlen(payload)});
}

// --------------------------------------------------  MISC  --------------------------------------------------

static void testCompare32(void)
{
    TEST_ASSERT_EQUAL(0, compare32(0, 0));
    TEST_ASSERT_EQUAL(0, compare32(1, 1));
    TEST_ASSERT_EQUAL(0, compare32(0xdeadbeef, 0xdeadbeef));
    TEST_ASSERT_EQUAL(0, compare32(0x0badc0de, 0x0badc0de));
    TEST_ASSERT_EQUAL(0, compare32(0xffffffff, 0xffffffff));
    TEST_ASSERT_EQUAL(+1, compare32(1, 0));
    TEST_ASSERT_EQUAL(+1, compare32(0xffffffff, 0xfffffffe));
    TEST_ASSERT_EQUAL(-1, compare32(0, 1));
    TEST_ASSERT_EQUAL(-1, compare32(0xfffffffe, 0xffffffff));
}

// --------------------------------------------------  FRAME PARSING  --------------------------------------------------

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

// --------------------------------------------------  SLOT  --------------------------------------------------

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
    rxSlotRestart(&slot, 0x1122334455667788ULL, makeRxMemory(&alloc, &alloc));
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
    const RxMemory mem    = makeRxMemory(&mem_fragment, &mem_payload);
    byte_t         data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    //
    RxSlot slot = {
        .ts_usec         = 1234567890,
        .transfer_id     = 0x123456789abcdef0,
        .max_index       = 546,
        .eot_index       = 654,
        .accepted_frames = 555,
        .payload_size    = 987,
        //
        .fragments = &makeRxFragment(mem,
                                     1,
                                     (struct UdpardPayload){.data = &data[2], .size = 2},
                                     (struct UdpardMutablePayload){.data = data, .size = sizeof(data)},
                                     NULL)
                          ->tree,
    };
    slot.fragments->base.lr[0] = &makeRxFragment(mem,
                                                 0,
                                                 (struct UdpardPayload){.data = &data[1], .size = 1},
                                                 (struct UdpardMutablePayload){.data = data, .size = sizeof(data)},
                                                 slot.fragments)
                                      ->tree.base;
    slot.fragments->base.lr[1] = &makeRxFragment(mem,
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
    rxSlotRestart(&slot, 0x1122334455667788ULL, makeRxMemory(&mem_fragment, &mem_payload));
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
    const RxMemory mem = makeRxMemory(&mem_fragment, &mem_payload);
    //>>> from pycyphal.transport.commons.crc import CRC32C
    //>>> CRC32C.new(data_bytes).value_as_bytes
    static const size_t PayloadSize = 171;
    // Build the fragment tree:
    //      2
    //     / `
    //    1   3
    //   /
    //  0
    RxFragment* const root =  //
        makeRxFragmentString(mem, 2, "Where does Man go? ", NULL);
    root->tree.base.lr[0] =  //
        &makeRxFragmentString(mem, 1, "For example, where does Man come from? ", &root->tree)->tree.base;
    root->tree.base.lr[1] =  //
        &makeRxFragmentString(mem, 3, "Where does the universe come from? xL\xAE\xCB", &root->tree)->tree.base;
    root->tree.base.lr[0]->lr[0] =
        &makeRxFragmentString(mem,  //
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
                            makeRxMemory(&mem_fragment, &mem_payload)));
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
    udpardRxFragmentFree(payload, mem.fragment, mem.payload);
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
    const RxMemory mem = makeRxMemory(&mem_fragment, &mem_payload);
    //>>> from pycyphal.transport.commons.crc import CRC32C
    //>>> CRC32C.new(data_bytes).value_as_bytes
    static const size_t PayloadSize = 262;
    // Build the fragment tree:
    //      1
    //     / `
    //    0   3
    //       / `
    //      2   4
    RxFragment* const root =  //
        makeRxFragmentString(mem, 1, "You told me that you came from the sea. Did you build the sea?\n", NULL);
    root->tree.base.lr[0] =  //
        &makeRxFragmentString(mem, 0, "Did you build this four-dimensional fragment?\n", &root->tree)->tree.base;
    root->tree.base.lr[1] =  //
        &makeRxFragmentString(mem, 3, "this four-dimensional space is like the sea for us?\n", &root->tree)->tree.base;
    root->tree.base.lr[1]->lr[0] =  //
        &makeRxFragmentString(mem,
                              2,
                              "Are you saying that for you, or at least for your creators, ",
                              ((RxFragmentTreeNode*) root->tree.base.lr[1]))
             ->tree.base;
    root->tree.base.lr[1]->lr[1] =  //
        &makeRxFragmentString(mem,
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
                            makeRxMemory(&mem_fragment, &mem_payload)));
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
    udpardRxFragmentFree(payload, mem.fragment, mem.payload);
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
    const RxMemory mem = makeRxMemory(&mem_fragment, &mem_payload);
    // Build the fragment tree:
    //      1
    //     / `
    //    0   2
    RxFragment* const root = makeRxFragmentString(mem, 1, "BBB", NULL);
    root->tree.base.lr[0]  = &makeRxFragmentString(mem, 0, "AAA", &root->tree)->tree.base;
    root->tree.base.lr[1]  = &makeRxFragmentString(mem, 2, "P\xF5\xA5?", &root->tree)->tree.base;
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
                            makeRxMemory(&mem_fragment, &mem_payload)));
    TEST_ASSERT_EQUAL(0, payload_size);  // Equals the extent due to the truncation.
    TEST_ASSERT_NULL(payload.next);
    TEST_ASSERT_EQUAL(0, payload.view.size);
    // Check the memory utilization. No memory should be in use by this point.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
    // Now, free the payload as the application would.
    udpardRxFragmentFree(payload, mem.fragment, mem.payload);
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
    const RxMemory mem = makeRxMemory(&mem_fragment, &mem_payload);
    // Build the fragment tree; no valid CRC here:
    //      1
    //     / `
    //    0   2
    RxFragment* const root = makeRxFragmentString(mem, 1, "BBB", NULL);
    root->tree.base.lr[0]  = &makeRxFragmentString(mem, 0, "AAA", &root->tree)->tree.base;
    root->tree.base.lr[1]  = &makeRxFragmentString(mem, 2, "CCC", &root->tree)->tree.base;
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
                                  makeRxMemory(&mem_fragment, &mem_payload)));
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
    const RxMemory mem = makeRxMemory(&mem_fragment, &mem_payload);
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
                                   makeRxFrameBaseString(&mem_payload,
                                                         0,
                                                         true,
                                                         "The fish responsible for drying the sea are not here."
                                                         "\x04\x1F\x8C\x1F"),
                                   1000,
                                   mem));
    // Verify the memory utilization. Note that the small transfer optimization is in effect: head fragment moved.
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(53 + TRANSFER_CRC_SIZE_BYTES, mem_payload.allocated_bytes);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_bytes);
    // Verify the payload and free it. Note the CRC is not part of the payload, obviously.
    TEST_ASSERT_EQUAL(53, payload_size);
    TEST_ASSERT(compareStringWithPayload("The fish responsible for drying the sea are not here.", payload.view));
    TEST_ASSERT_NULL(payload.next);
    udpardRxFragmentFree(payload, mem.fragment, mem.payload);
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
                                   makeRxFrameBaseString(&mem_payload,
                                                         0,
                                                         false,
                                                         "We're sorry. What you said is really hard to understand.\n"),
                                   1000,
                                   mem));
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload,
                                                         1,
                                                         false,
                                                         "The fish who dried the sea went onto land before they did "
                                                         "this. "),
                                   1000,
                                   mem));
    TEST_ASSERT_EQUAL(1,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload,
                                                         2,
                                                         true,
                                                         "They moved from one dark forest to another dark forest."
                                                         "?\xAC(\xBE"),
                                   1000,
                                   mem));
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
    udpardRxFragmentFree(payload, mem.fragment, mem.payload);
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
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         2,
                                                         true,
                                                         "Toss it over."
                                                         "K(\xBB\xEE"),
                                   45,
                                   mem));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         1,
                                                         false,
                                                         "How do we give it to you?\n"),
                                   45,
                                   mem));
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         1,
                                                         false,
                                                         "DUPLICATE #1"),
                                   45,
                                   mem));
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // NO CHANGE, duplicate discarded.
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         2,
                                                         true,
                                                         "DUPLICATE #2"),
                                   45,
                                   mem));
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // NO CHANGE, duplicate discarded.
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(1,  // transfer completed
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         0,
                                                         false,
                                                         "I like fish. Can I have it?\n"),
                                   45,
                                   mem));
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
    udpardRxFragmentFree(payload, mem.fragment, mem.payload);
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
                                   makeRxFrameBaseString(&mem_payload, 0, true, ":D"),
                                   1000,
                                   mem));
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
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         2,
                                                         true,
                                                         "Toss it over."
                                                         "K(\xBB\xEE"),
                                   1000,
                                   mem));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);  // Limit reached here. Cannot accept next fragment.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_MEMORY,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         1,
                                                         false,
                                                         "How do we give it to you?\n"),
                                   1000,
                                   mem));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // Payload not accepted, cannot alloc fragment.
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    mem_fragment.limit_fragments = 2;  // Lift the limit and repeat the same frame, this time it is accepted.
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         0,
                                                         false,
                                                         "I like fish. Can I have it?\n"),
                                   1000,
                                   mem));
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // Accepted!
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_MEMORY,  // Cannot alloc third fragment.
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         1,
                                                         false,
                                                         "How do we give it to you?\n"),
                                   1000,
                                   mem));
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // Payload not accepted, cannot alloc fragment.
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    mem_fragment.limit_fragments = 3;  // Lift the limit and repeat the same frame, this time it is accepted.
    TEST_ASSERT_EQUAL(1,               // transfer completed
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         1,
                                                         false,
                                                         "How do we give it to you?\n"),
                                   1000,
                                   mem));
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
    udpardRxFragmentFree(payload, mem.fragment, mem.payload);
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
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         2,
                                                         true,
                                                         "Toss it over."
                                                         "K(\xBB\xEE"),
                                   45,
                                   mem));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // Okay, accepted, some data stored...
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         1,             //
                                                         true,          // SURPRISE! EOT is set in distinct frames!
                                                         "How do we give it to you?\n"),
                                   45,
                                   mem));
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
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         2,
                                                         true,
                                                         "Toss it over."
                                                         "K(\xBB\xEE"),
                                   45,
                                   mem));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // Okay, accepted, some data stored...
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxSlotAccept(&slot,
                                   &payload_size,
                                   &payload,
                                   makeRxFrameBaseString(&mem_payload,  //
                                                         3,             // SURPRISE! Frame #3 while #2 was EOT!
                                                         false,
                                                         "How do we give it to you?\n"),
                                   45,
                                   mem));
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

// --------------------------------------------------  IFACE  --------------------------------------------------

static void testIfaceIsFutureTransferID(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    RxIface iface;
    rxIfaceInit(&iface, makeRxMemory(&mem_fragment, &mem_payload));
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
    rxIfaceInit(&iface, makeRxMemory(&mem_fragment, &mem_payload));
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
    rxSlotRestart(&slots[0], 1000, makeRxMemory(&mem_fragment, &mem_payload));
    rxSlotRestart(&slots[1], 1001, makeRxMemory(&mem_fragment, &mem_payload));
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
    const RxMemory mem = makeRxMemory(&mem_fragment, &mem_payload);
    RxIface        iface;
    rxIfaceInit(&iface, mem);
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
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1234,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1234,
                                                                         .transfer_id    = 0x1122334455667788U},
                                                      0,
                                                      true,
                                                      "I am a tomb."
                                                      "\x1F\\\xCDs"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);  // Head fragment is not heap-allocated.
    // Check the transfer we just accepted.
    TEST_ASSERT_EQUAL(1234567890, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityHigh, transfer.priority);
    TEST_ASSERT_EQUAL(1234, transfer.source_node_id);
    TEST_ASSERT_EQUAL(0x1122334455667788U, transfer.transfer_id);
    TEST_ASSERT_EQUAL(12, transfer.payload_size);
    TEST_ASSERT(compareStringWithPayload("I am a tomb.", transfer.payload.view));
    udpardRxFragmentFree(transfer.payload, mem.fragment, mem.payload);
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
                                    1234567891,                      // different timestamp but ignored anyway
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1234,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1234,
                                                                         .transfer_id    = 0x1122334455667788U},
                                                      0,
                                                      true,
                                                      "I am a tomb."
                                                      "\x1F\\\xCDs"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
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
                                    1234567892,                      // different timestamp but ignored anyway
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1234,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1234,
                                                                         .transfer_id    = 0x1122334455667789U},
                                                      0,
                                                      true,
                                                      "I am a tomb."
                                                      "No CRC here."),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
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
                                    1234567893,                      // different timestamp but ignored anyway
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1234,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1234,
                                                                         .transfer_id    = 0x1122334455667790U},
                                                      0,
                                                      true,
                                                      "I am a tomb."
                                                      "No CRC here, #2."),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
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
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1111,
                                                                         .transfer_id    = 1000U},
                                                      2,
                                                      true,
                                                      "A2"
                                                      "v\x1E\xBD]"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(1234567890, iface.ts_usec);                      // same old timestamp
    TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[0].transfer_id);  // Still unused.
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);               // Replaced the old one, it was unneeded.
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // B1
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000010,                      // Transfer-ID timeout.
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPrioritySlow,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x2222,
                                                                         .transfer_id    = 1001U},
                                                      1,
                                                      true,
                                                      "B1"
                                                      "g\x8D\x9A\xD7"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(1234567890, iface.ts_usec);         // same old timestamp
    TEST_ASSERT_EQUAL(1001, iface.slots[0].transfer_id);  // Used for B because the other one is taken.
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);  // Keeps A because it is in-progress, can't discard.
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    // A0
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000030,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1111,
                                                                         .transfer_id    = 1000U},
                                                      0,
                                                      false,
                                                      "A0"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(1234567890, iface.ts_usec);  // same old timestamp
    TEST_ASSERT_EQUAL(1001, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);
    // B0
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000040,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPrioritySlow,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x2222,
                                                                         .transfer_id    = 1001U},
                                                      0,
                                                      false,
                                                      "B0"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
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
    udpardRxFragmentFree(transfer.payload, mem.fragment, mem.payload);
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // Only the remaining A0 A2 are left.
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    // A1
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000050,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1111,
                                                                         .transfer_id    = 1000U},
                                                      1,
                                                      false,
                                                      "A1"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
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
    udpardRxFragmentFree(transfer.payload, mem.fragment, mem.payload);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
}

static void testIfaceAcceptB(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    const RxMemory mem = makeRxMemory(&mem_fragment, &mem_payload);
    RxIface        iface;
    rxIfaceInit(&iface, mem);
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
    // A2 arrives before B1 but its timestamp is higher.
    // Transfer B will be evicted by C because by the time C0 arrives, transfer B is the oldest one,
    // since its timestamp is inherited from B0.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // A2
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000020,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1111,
                                                                         .transfer_id    = 1000U},
                                                      2,
                                                      true,
                                                      "A2"
                                                      "v\x1E\xBD]"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // B1
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000010,                      // TIME REORDERING -- lower than previous.
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPrioritySlow,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x2222,
                                                                         .transfer_id    = 1001U},
                                                      1,
                                                      true,
                                                      "B1"
                                                      "g\x8D\x9A\xD7"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(1001, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    // A0
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000030,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1111,
                                                                         .transfer_id    = 1000U},
                                                      0,
                                                      false,
                                                      "A0"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(1001, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);
    // C0
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000040,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 3333,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x3333,
                                                                         .transfer_id    = 1002U},
                                                      0,
                                                      false,
                                                      "C0"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(1002, iface.slots[0].transfer_id);  // B evicted by C.
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);  // Payload of B is freed, so the usage is unchanged.
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);
    // B0
    TEST_ASSERT_EQUAL(0,  // Cannot be accepted because its slot is taken over by C.
                      rxIfaceAccept(&iface,
                                    2000000050,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPrioritySlow,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x2222,
                                                                         .transfer_id    = 1001U},
                                                      0,
                                                      false,
                                                      "B0"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(1002, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1000, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);  // No increase, frame not accepted.
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);
    // A1
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000050,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x1111,
                                                                         .transfer_id    = 1000U},
                                                      1,
                                                      false,
                                                      "A1"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
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
    udpardRxFragmentFree(transfer.payload, mem.fragment, mem.payload);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // Some memory is retained for the C0 payload.
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // C0 DUPLICATE
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000060,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 3333,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x3333,
                                                                         .transfer_id    = 1002U},
                                                      0,
                                                      false,
                                                      "C0 DUPLICATE"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(2000000020, iface.ts_usec);  // Last transfer timestamp.
    TEST_ASSERT_EQUAL(1002, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(1001, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // Not accepted, so no change.
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // C1
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000070,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityHigh,
                                                                         .src_node_id    = 3333,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0x3333,
                                                                         .transfer_id    = 1002U},
                                                      1,
                                                      true,
                                                      "C1"
                                                      "\xA8\xBF}\x19"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
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
    udpardRxFragmentFree(transfer.payload, mem.fragment, mem.payload);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);  // Some memory is retained for the C0 payload.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
}

static void testIfaceAcceptC(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    const RxMemory mem = makeRxMemory(&mem_fragment, &mem_payload);
    RxIface        iface;
    rxIfaceInit(&iface, mem);
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
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityOptional,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xA},
                                                      0,
                                                      false,
                                                      "A0"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(0xA, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // B0
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000020,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xB},
                                                      0,
                                                      false,
                                                      "B0"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, iface.ts_usec);
    TEST_ASSERT_EQUAL(0xB, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(0xA, iface.slots[1].transfer_id);
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    // A1
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000030,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityOptional,
                                                                         .src_node_id    = 1111,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xA},
                                                      1,
                                                      true,
                                                      "A1"
                                                      "\xc7\xac_\x81"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
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
    udpardRxFragmentFree(transfer.payload, mem.fragment, mem.payload);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // B0 still allocated.
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // C0
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000040,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                         .src_node_id    = 3333,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xC},
                                                      0,
                                                      false,
                                                      "C0"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(2000000010, iface.ts_usec);  // <- unchanged.
    TEST_ASSERT_EQUAL(0xB, iface.slots[0].transfer_id);
    TEST_ASSERT_EQUAL(0xC, iface.slots[1].transfer_id);     // <- reused for C.
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // Two transfers in transit again: B and C.
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    // B1
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000050,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xB},
                                                      1,
                                                      true,
                                                      "B1"
                                                      "g\x8D\x9A\xD7"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
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
    udpardRxFragmentFree(transfer.payload, mem.fragment, mem.payload);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // C0 is still allocated.
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    // C1
    // This is the DIFFICULT CASE because we have two RX slots with the same transfer-ID, but THE FIRST ONE IS NOT
    // THE ONE THAT WE NEED! Watch what happens next.
    TEST_ASSERT_EQUAL(1,
                      rxIfaceAccept(&iface,
                                    2000000060,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                         .src_node_id    = 3333,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xC},
                                                      1,
                                                      true,
                                                      "C1"
                                                      "\xA8\xBF}\x19"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
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
    udpardRxFragmentFree(transfer.payload, mem.fragment, mem.payload);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // B0 duplicate multi-frame; shall be rejected.
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000070,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xB},
                                                      0,
                                                      false,
                                                      "B0"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // B0 duplicate single-frame; shall be rejected.
    TEST_ASSERT_EQUAL(0,
                      rxIfaceAccept(&iface,
                                    2000000080,
                                    makeRxFrameString(&mem_payload,  //
                                                      (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                         .src_node_id    = 2222,
                                                                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                         .data_specifier = 0,
                                                                         .transfer_id    = 0xB},
                                                      0,
                                                      true,
                                                      "B0"
                                                      "g\x8D\x9A\xD7"),
                                    1000,
                                    UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                    mem,
                                    &transfer));
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
}

// --------------------------------------------------  SESSION  --------------------------------------------------

static void testSessionDeduplicate(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    const RxMemory                 mem     = makeRxMemory(&mem_fragment, &mem_payload);
    struct UdpardInternalRxSession session = {0};
    rxSessionInit(&session, mem);
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, session.last_ts_usec);
    TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, session.last_transfer_id);
    {
        struct UdpardFragment* const head = &makeRxFragmentString(mem, 0, "ABC", NULL)->base;
        head->next                        = &makeRxFragmentString(mem, 1, "DEF", NULL)->base;
        struct UdpardRxTransfer transfer  = {.timestamp_usec = 10000000,
                                             .transfer_id    = 0x0DDC0FFEEBADF00D,
                                             .payload_size   = 6,
                                             .payload        = *head};
        memFree(mem.fragment, sizeof(RxFragment), head);  // Cloned, no longer needed.
        TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
        TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
        // The first transfer after initialization is always accepted.
        TEST_ASSERT(rxSessionDeduplicate(&session, UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC, &transfer, mem));
        // Check the final states.
        TEST_ASSERT_EQUAL(6, transfer.payload_size);
        TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // The application shall free the payload.
        TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
        TEST_ASSERT_EQUAL(10000000, session.last_ts_usec);
        TEST_ASSERT_EQUAL(0x0DDC0FFEEBADF00D, session.last_transfer_id);
        // Feed the same transfer again; now it is a duplicate and so it is rejected and freed.
        transfer.timestamp_usec = 10000001;
        TEST_ASSERT_FALSE(rxSessionDeduplicate(&session, UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC, &transfer, mem));
        TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
        TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
        TEST_ASSERT_EQUAL(10000000, session.last_ts_usec);  // Timestamp is not updated.
        TEST_ASSERT_EQUAL(0x0DDC0FFEEBADF00D, session.last_transfer_id);
    }
    {
        // Emit a duplicate but after the transfer-ID timeout has occurred. Ensure it is accepted.
        struct UdpardFragment* const head = &makeRxFragmentString(mem, 0, "ABC", NULL)->base;
        head->next                        = &makeRxFragmentString(mem, 1, "DEF", NULL)->base;
        struct UdpardRxTransfer transfer  = {.timestamp_usec = 12000000,            // TID timeout.
                                             .transfer_id    = 0x0DDC0FFEEBADF000,  // transfer-ID reduced.
                                             .payload_size   = 6,
                                             .payload        = *head};
        memFree(mem.fragment, sizeof(RxFragment), head);  // Cloned, no longer needed.
        TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
        TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
        // Accepted due to the TID timeout.
        TEST_ASSERT(rxSessionDeduplicate(&session, UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC, &transfer, mem));
        // Check the final states.
        TEST_ASSERT_EQUAL(6, transfer.payload_size);
        TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // The application shall free the payload.
        TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
        TEST_ASSERT_EQUAL(12000000, session.last_ts_usec);
        TEST_ASSERT_EQUAL(0x0DDC0FFEEBADF000, session.last_transfer_id);
        // Feed the same transfer again; now it is a duplicate and so it is rejected and freed.
        transfer.timestamp_usec = 12000001;
        TEST_ASSERT_FALSE(rxSessionDeduplicate(&session, UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC, &transfer, mem));
        TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
        TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
        TEST_ASSERT_EQUAL(12000000, session.last_ts_usec);  // Timestamp is not updated.
        TEST_ASSERT_EQUAL(0x0DDC0FFEEBADF000, session.last_transfer_id);
    }
    {
        // Ensure another transfer with a greater transfer-ID is accepted immediately.
        struct UdpardFragment* const head = &makeRxFragmentString(mem, 0, "ABC", NULL)->base;
        head->next                        = &makeRxFragmentString(mem, 1, "DEF", NULL)->base;
        struct UdpardRxTransfer transfer  = {.timestamp_usec = 11000000,            // Simulate clock jitter.
                                             .transfer_id    = 0x0DDC0FFEEBADF001,  // Incremented.
                                             .payload_size   = 6,
                                             .payload        = *head};
        memFree(mem.fragment, sizeof(RxFragment), head);  // Cloned, no longer needed.
        TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
        TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
        // Accepted because TID greater.
        TEST_ASSERT(rxSessionDeduplicate(&session, UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC, &transfer, mem));
        // Check the final states.
        TEST_ASSERT_EQUAL(6, transfer.payload_size);
        TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);  // The application shall free the payload.
        TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
        TEST_ASSERT_EQUAL(11000000, session.last_ts_usec);                // Updated.
        TEST_ASSERT_EQUAL(0x0DDC0FFEEBADF001, session.last_transfer_id);  // Updated.
        // Feed the same transfer again; now it is a duplicate and so it is rejected and freed.
        transfer.timestamp_usec = 11000000;
        TEST_ASSERT_FALSE(rxSessionDeduplicate(&session, UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC, &transfer, mem));
        TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
        TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
        TEST_ASSERT_EQUAL(11000000, session.last_ts_usec);  // Timestamp is not updated.
        TEST_ASSERT_EQUAL(0x0DDC0FFEEBADF001, session.last_transfer_id);
    }
}

static void testSessionAcceptA(void)
{
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    const RxMemory                 mem     = makeRxMemory(&mem_fragment, &mem_payload);
    struct UdpardInternalRxSession session = {0};
    rxSessionInit(&session, mem);
    TEST_ASSERT_EQUAL(TIMESTAMP_UNSET, session.last_ts_usec);
    TEST_ASSERT_EQUAL(TRANSFER_ID_UNSET, session.last_transfer_id);
    struct UdpardRxTransfer transfer = {0};
    // Accept a simple transfer through iface #1.
    TEST_ASSERT_EQUAL(1,
                      rxSessionAccept(&session,
                                      1,
                                      10000000,
                                      makeRxFrameString(&mem_payload,  //
                                                        (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                           .src_node_id    = 2222,
                                                                           .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                           .data_specifier = 0,
                                                                           .transfer_id    = 0xB},
                                                        0,
                                                        true,
                                                        "Z\xBA\xA1\xBAh"),
                                      1000,
                                      UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                      mem,
                                      &transfer));
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // Free the payload.
    udpardRxFragmentFree(transfer.payload, mem.fragment, mem.payload);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // Send the same transfer again through a different iface; it is a duplicate and so it is rejected and freed.
    TEST_ASSERT_EQUAL(0,
                      rxSessionAccept(&session,
                                      0,
                                      10000010,
                                      makeRxFrameString(&mem_payload,  //
                                                        (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                           .src_node_id    = 2222,
                                                                           .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                           .data_specifier = 0,
                                                                           .transfer_id    = 0xB},
                                                        0,
                                                        true,
                                                        "Z\xBA\xA1\xBAh"),
                                      1000,
                                      UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                      mem,
                                      &transfer));
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    // Send a valid transfer that should be accepted but we inject an OOM error.
    mem_fragment.limit_fragments = 0;
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_MEMORY,
                      rxSessionAccept(&session,
                                      2,
                                      12000020,
                                      makeRxFrameString(&mem_payload,  //
                                                        (TransferMetadata){.priority       = UdpardPriorityExceptional,
                                                                           .src_node_id    = 2222,
                                                                           .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                           .data_specifier = 0,
                                                                           .transfer_id    = 0xC},
                                                        0,
                                                        true,
                                                        "Z\xBA\xA1\xBAh"),
                                      1000,
                                      UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC,
                                      mem,
                                      &transfer));
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
}

// --------------------------------------------------  PORT  --------------------------------------------------

static inline void testPortAcceptFrameA(void)
{
    InstrumentedAllocator mem_session  = {0};
    InstrumentedAllocator mem_fragment = {0};
    InstrumentedAllocator mem_payload  = {0};
    instrumentedAllocatorNew(&mem_session);
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    const struct UdpardRxMemoryResources mem = {.session  = instrumentedAllocatorMakeMemoryResource(&mem_session),  //
                                                .fragment = instrumentedAllocatorMakeMemoryResource(&mem_fragment),
                                                .payload  = instrumentedAllocatorMakeMemoryDeleter(&mem_payload)};
    struct UdpardRxTransfer              transfer = {0};
    // Initialize the port.
    struct UdpardRxPort port;
    rxPortInit(&port);
    TEST_ASSERT_EQUAL(SIZE_MAX, port.extent);
    TEST_ASSERT_EQUAL(UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC, port.transfer_id_timeout_usec);
    TEST_ASSERT_NULL(port.sessions);

    // Accept valid non-anonymous transfer.
    TEST_ASSERT_EQUAL(
        1,
        rxPortAcceptFrame(&port,
                          1,
                          10000000,
                          makeDatagramPayloadSingleFrameString(&mem_payload,  //
                                                               (TransferMetadata){.priority = UdpardPriorityImmediate,
                                                                                  .src_node_id = 2222,
                                                                                  .dst_node_id = UDPARD_NODE_ID_UNSET,
                                                                                  .data_specifier = 0,
                                                                                  .transfer_id    = 0xB},
                                                               "When will the collapse of space in the vicinity of the "
                                                               "Solar System into two dimensions cease?"),
                          mem,
                          &transfer));
    TEST_ASSERT_EQUAL(1, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);  // Head optimization in effect.
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    // Check the received transfer.
    TEST_ASSERT_EQUAL(10000000, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityImmediate, transfer.priority);
    TEST_ASSERT_EQUAL(2222, transfer.source_node_id);
    TEST_ASSERT_EQUAL(0xB, transfer.transfer_id);
    TEST_ASSERT_EQUAL(94, transfer.payload_size);
    TEST_ASSERT(compareStringWithPayload("When will the collapse of space in the vicinity of the "
                                         "Solar System into two dimensions cease?",
                                         transfer.payload.view));
    // Free the memory.
    udpardRxFragmentFree(transfer.payload, mem.fragment, mem.payload);
    TEST_ASSERT_EQUAL(1, mem_session.allocated_fragments);  // The session remains.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);

    // Send another transfer from another node and see the session count increase.
    TEST_ASSERT_EQUAL(
        1,
        rxPortAcceptFrame(&port,
                          0,
                          10000010,
                          makeDatagramPayloadSingleFrameString(&mem_payload,  //
                                                               (TransferMetadata){.priority = UdpardPriorityImmediate,
                                                                                  .src_node_id = 3333,
                                                                                  .dst_node_id = UDPARD_NODE_ID_UNSET,
                                                                                  .data_specifier = 0,
                                                                                  .transfer_id    = 0xC},
                                                               "It will never cease."),
                          mem,
                          &transfer));
    TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);   // New session created.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);  // Head optimization in effect.
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    // Check the received transfer.
    TEST_ASSERT_EQUAL(10000010, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityImmediate, transfer.priority);
    TEST_ASSERT_EQUAL(3333, transfer.source_node_id);
    TEST_ASSERT_EQUAL(0xC, transfer.transfer_id);
    TEST_ASSERT_EQUAL(20, transfer.payload_size);
    TEST_ASSERT(compareStringWithPayload("It will never cease.", transfer.payload.view));
    // Free the memory.
    udpardRxFragmentFree(transfer.payload, mem.fragment, mem.payload);
    TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);  // The sessions remain.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);

    // Try sending another frame with no memory left and see it fail during session allocation.
    mem_session.limit_fragments = 0;
    TEST_ASSERT_EQUAL(
        -UDPARD_ERROR_MEMORY,
        rxPortAcceptFrame(&port,
                          2,
                          10000020,
                          makeDatagramPayloadSingleFrameString(&mem_payload,  //
                                                               (TransferMetadata){.priority = UdpardPriorityImmediate,
                                                                                  .src_node_id = 4444,
                                                                                  .dst_node_id = UDPARD_NODE_ID_UNSET,
                                                                                  .data_specifier = 0,
                                                                                  .transfer_id    = 0xD},
                                                               "Cheng Xin shuddered."),
                          mem,
                          &transfer));
    TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);   // Not increased.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);  // Not accepted.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);   // Buffer freed.

    // Anonymous transfers are stateless and do not require session allocation.
    mem_session.limit_fragments = 0;
    TEST_ASSERT_EQUAL(
        1,
        rxPortAcceptFrame(&port,
                          2,
                          10000030,
                          makeDatagramPayloadSingleFrameString(&mem_payload,  //
                                                               (TransferMetadata){.priority = UdpardPriorityImmediate,
                                                                                  .src_node_id = UDPARD_NODE_ID_UNSET,
                                                                                  .dst_node_id = UDPARD_NODE_ID_UNSET,
                                                                                  .data_specifier = 0,
                                                                                  .transfer_id    = 0xD},
                                                               "Cheng Xin shuddered."),
                          mem,
                          &transfer));
    TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);   // Not increased.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);  // Head optimization in effect.
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);   // Frame passed to the application.
    // Check the received transfer.
    TEST_ASSERT_EQUAL(10000030, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityImmediate, transfer.priority);
    TEST_ASSERT_EQUAL(UDPARD_NODE_ID_UNSET, transfer.source_node_id);
    TEST_ASSERT_EQUAL(0xD, transfer.transfer_id);
    TEST_ASSERT_EQUAL(20, transfer.payload_size);
    TEST_ASSERT(compareStringWithPayload("Cheng Xin shuddered.", transfer.payload.view));
    // Free the memory.
    udpardRxFragmentFree(transfer.payload, mem.fragment, mem.payload);
    TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);  // The sessions remain.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);

    // Send invalid anonymous transfers and see them fail.
    {  // Bad CRC.
        struct UdpardMutablePayload datagram =
            makeDatagramPayloadSingleFrameString(&mem_payload,  //
                                                 (TransferMetadata){.priority       = UdpardPriorityImmediate,
                                                                    .src_node_id    = UDPARD_NODE_ID_UNSET,
                                                                    .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                    .data_specifier = 0,
                                                                    .transfer_id    = 0xE},
                                                 "You are scared? Do you think that in this galaxy, in this universe, "
                                                 "only the Solar System is collapsing into two dimensions? Haha...");
        *(((byte_t*) datagram.data) + HEADER_SIZE_BYTES) = 0x00;  // Corrupt the payload, CRC invalid.
        TEST_ASSERT_EQUAL(0, rxPortAcceptFrame(&port, 0, 10000040, datagram, mem, &transfer));
        TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);
        TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
        TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    }
    {  // No payload (transfer CRC is always required).
        byte_t* const payload = instrumentedAllocatorAllocate(&mem_payload, HEADER_SIZE_BYTES);
        (void) txSerializeHeader(payload,
                                 (TransferMetadata){.priority       = UdpardPriorityImmediate,
                                                    .src_node_id    = UDPARD_NODE_ID_UNSET,
                                                    .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                    .data_specifier = 0,
                                                    .transfer_id    = 0xE},
                                 0,
                                 true);
        TEST_ASSERT_EQUAL(0,
                          rxPortAcceptFrame(&port,
                                            0,
                                            10000050,
                                            (struct UdpardMutablePayload){.size = HEADER_SIZE_BYTES, .data = payload},
                                            mem,
                                            &transfer));
        TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);
        TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
        TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    }

    // Send an invalid frame and make sure the memory is freed.
    TEST_ASSERT_EQUAL(0,
                      rxPortAcceptFrame(&port,
                                        0,
                                        10000060,
                                        (struct
                                         UdpardMutablePayload){.size = HEADER_SIZE_BYTES,
                                                               .data =
                                                                   instrumentedAllocatorAllocate(&mem_payload,
                                                                                                 HEADER_SIZE_BYTES)},
                                        mem,
                                        &transfer));
    TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);   // Not increased.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);  // Not accepted.
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);   // Buffer freed.

    // Send incomplete transfers to see them cleaned up upon destruction.
    mem_session.limit_fragments = SIZE_MAX;
    TEST_ASSERT_EQUAL(0,
                      rxPortAcceptFrame(&port,
                                        0,
                                        10000070,
                                        makeDatagramPayloadString(&mem_payload,  //
                                                                  (TransferMetadata){
                                                                      .priority       = UdpardPriorityImmediate,
                                                                      .src_node_id    = 10000,
                                                                      .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                      .data_specifier = 0,
                                                                      .transfer_id    = 0xD,
                                                                  },
                                                                  100,
                                                                  false,
                                                                  "What you're saying makes no sense. "
                                                                  "At least, it doesn't make sense to lower spatial "
                                                                  "dimensions as a weapon. "),
                                        mem,
                                        &transfer));
    TEST_ASSERT_EQUAL(3, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxPortAcceptFrame(&port,
                                        0,
                                        10000080,
                                        makeDatagramPayloadString(&mem_payload,  //
                                                                  (TransferMetadata){
                                                                      .priority       = UdpardPriorityImmediate,
                                                                      .src_node_id    = 10000,
                                                                      .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                      .data_specifier = 0,
                                                                      .transfer_id    = 0xD,
                                                                  },
                                                                  101,
                                                                  false,
                                                                  "In the long run, that's the sort of attack that "
                                                                  "would kill the attacker as well as the target. "
                                                                  "Eventually, the side that initiated attack would "
                                                                  "also see their own space fall into the "
                                                                  "two-dimensional abyss they created."),
                                        mem,
                                        &transfer));
    TEST_ASSERT_EQUAL(3, mem_session.allocated_fragments);  // Same session because it comes from the same source.
    TEST_ASSERT_EQUAL(2, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(2, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0,
                      rxPortAcceptFrame(&port,
                                        2,
                                        10000090,
                                        makeDatagramPayloadString(&mem_payload,  //
                                                                  (TransferMetadata){
                                                                      .priority       = UdpardPriorityImmediate,
                                                                      .src_node_id    = 10001,
                                                                      .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                                                      .data_specifier = 0,
                                                                      .transfer_id    = 0xD,
                                                                  },
                                                                  10,
                                                                  true,
                                                                  "You're too... kind-hearted."),
                                        mem,
                                        &transfer));
    TEST_ASSERT_EQUAL(4, mem_session.allocated_fragments);  // New source.
    TEST_ASSERT_EQUAL(3, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(3, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(4 * sizeof(struct UdpardInternalRxSession), mem_session.allocated_bytes);
    TEST_ASSERT_EQUAL(3 * sizeof(RxFragment), mem_fragment.allocated_bytes);

    // Free the port instance and ensure all ifaces and sessions are cleaned up.
    rxPortFree(&port, mem);
    TEST_ASSERT_EQUAL(0, mem_session.allocated_fragments);  // All gone.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
}

// ---------------------------------------------------------------------------------------------------------------------

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    // misc
    RUN_TEST(testCompare32);
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
    // session
    RUN_TEST(testSessionDeduplicate);
    RUN_TEST(testSessionAcceptA);
    // port
    RUN_TEST(testPortAcceptFrameA);
    return UNITY_END();
}

// NOLINTEND(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
