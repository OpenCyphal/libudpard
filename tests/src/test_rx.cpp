/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.h>
#include "helpers.h"
#include "hexdump.hpp"
#include <unity.h>
#include <cstring>
#include <array>

namespace
{
void testRxSubscriptionInit()
{
    InstrumentedAllocator mem_session{};
    InstrumentedAllocator mem_fragment{};
    InstrumentedAllocator mem_payload{};
    instrumentedAllocatorNew(&mem_session);
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    UdpardRxSubscription sub{};
    TEST_ASSERT_EQUAL(0,
                      udpardRxSubscriptionInit(&sub,
                                               0x1234,
                                               1000,
                                               {
                                                   .session  = instrumentedAllocatorMakeMemoryResource(&mem_session),
                                                   .fragment = instrumentedAllocatorMakeMemoryResource(&mem_fragment),
                                                   .payload  = instrumentedAllocatorMakeMemoryDeleter(&mem_payload),
                                               }));
    TEST_ASSERT_EQUAL(&instrumentedAllocatorAllocate, sub.memory.session.allocate);
    TEST_ASSERT_EQUAL(&instrumentedAllocatorDeallocate, sub.memory.session.deallocate);
    TEST_ASSERT_EQUAL(1000, sub.port.extent);
    TEST_ASSERT_EQUAL(UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC, sub.port.transfer_id_timeout_usec);
    TEST_ASSERT_EQUAL(nullptr, sub.port.sessions);
    TEST_ASSERT_EQUAL(0xEF001234UL, sub.udp_ip_endpoint.ip_address);
    TEST_ASSERT_EQUAL(9382, sub.udp_ip_endpoint.udp_port);
    TEST_ASSERT_EQUAL(0, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    udpardRxSubscriptionFree(&sub);
    TEST_ASSERT_EQUAL(0, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    udpardRxSubscriptionFree(nullptr);  // No-op.
    // Invalid arguments.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardRxSubscriptionInit(nullptr,
                                               0xFFFF,
                                               1000,
                                               {
                                                   .session  = instrumentedAllocatorMakeMemoryResource(&mem_session),
                                                   .fragment = instrumentedAllocatorMakeMemoryResource(&mem_fragment),
                                                   .payload  = instrumentedAllocatorMakeMemoryDeleter(&mem_payload),
                                               }));
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardRxSubscriptionInit(&sub,
                                               0xFFFF,
                                               1000,
                                               {
                                                   .session  = instrumentedAllocatorMakeMemoryResource(&mem_session),
                                                   .fragment = instrumentedAllocatorMakeMemoryResource(&mem_fragment),
                                                   .payload  = instrumentedAllocatorMakeMemoryDeleter(&mem_payload),
                                               }));
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT, udpardRxSubscriptionInit(&sub, 1234, 1000, {}));
}

void testRxSubscriptionReceive()
{
    InstrumentedAllocator mem_session{};
    InstrumentedAllocator mem_fragment{};
    InstrumentedAllocator mem_payload{};
    instrumentedAllocatorNew(&mem_session);
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    UdpardRxSubscription sub{};
    TEST_ASSERT_EQUAL(0,
                      udpardRxSubscriptionInit(&sub,
                                               0x1234,
                                               1000,
                                               {
                                                   .session  = instrumentedAllocatorMakeMemoryResource(&mem_session),
                                                   .fragment = instrumentedAllocatorMakeMemoryResource(&mem_fragment),
                                                   .payload  = instrumentedAllocatorMakeMemoryDeleter(&mem_payload),
                                               }));
    TEST_ASSERT_EQUAL(1000, sub.port.extent);
    TEST_ASSERT_EQUAL(UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC, sub.port.transfer_id_timeout_usec);
    TEST_ASSERT_EQUAL(nullptr, sub.port.sessions);
    TEST_ASSERT_EQUAL(0xEF001234UL, sub.udp_ip_endpoint.ip_address);
    TEST_ASSERT_EQUAL(9382, sub.udp_ip_endpoint.udp_port);
    TEST_ASSERT_EQUAL(0, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    UdpardRxTransfer transfer{};
    // Feed a single-frame transfer. Remember that in Cyphal/UDP, the payload CRC is part of the payload itself.
    //
    //>>> from pycyphal.transport.commons.crc import CRC32C
    //>>> CRC32C.new(b"Hello!").value_as_bytes
    //
    // >>> from pycyphal.transport.udp import UDPFrame
    // >>> from pycyphal.transport import Priority, MessageDataSpecifier, ServiceDataSpecifier
    // >>> frame = UDPFrame(priority=Priority.FAST, transfer_id=0xbadc0ffee0ddf00d, index=0, end_of_transfer=True,
    //  payload=memoryview(b'Hello!\xd6\xeb\xfd\t'), source_node_id=2345, destination_node_id=0xFFFF,
    //  data_specifier=MessageDataSpecifier(0x1234), user_data=0)
    // >>> list(frame.compile_header_and_payload()[0])
    // >>> list(frame.compile_header_and_payload()[1])
    {
        const std::array<std::uint_fast8_t, 34> data{{1,   2,   41,  9,   255, 255, 52,  18,  13,  240, 221, 224,
                                                      254, 15,  220, 186, 0,   0,   0,   128, 0,   0,   246, 129,  //
                                                      72,  101, 108, 108, 111, 33,  214, 235, 253, 9}};
        const UdpardMutablePayload              datagram{
                         .size = sizeof(data),
                         .data = instrumentedAllocatorAllocate(&mem_payload, sizeof(data)),
        };
        TEST_ASSERT_NOT_NULL(datagram.data);
        std::memcpy(datagram.data, data.data(), data.size());
        TEST_ASSERT_EQUAL(1, udpardRxSubscriptionReceive(&sub, 10'000'000, datagram, 0, &transfer));
    }
    TEST_ASSERT_EQUAL(1, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);  // Head optimization in effect.
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(10'000'000, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityFast, transfer.priority);
    TEST_ASSERT_EQUAL(2345, transfer.source_node_id);
    TEST_ASSERT_EQUAL(0xBADC0FFEE0DDF00DUL, transfer.transfer_id);
    TEST_ASSERT_EQUAL(6, transfer.payload_size);
    TEST_ASSERT_EQUAL(6, transfer.payload.view.size);
    TEST_ASSERT_EQUAL_MEMORY("Hello!", transfer.payload.view.data, 6);
    TEST_ASSERT_NULL(transfer.payload.next);
    // Free the subscription, ensure the payload is not affected because its ownership has been transferred to us.
    udpardRxSubscriptionFree(&sub);
    udpardRxSubscriptionFree(&sub);  // The API does not guarantee anything but this is for extra safety.
    TEST_ASSERT_EQUAL(0, mem_session.allocated_fragments);  // Session gone. Bye bye.
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);  // Stayin' alive.
    // Free the payload as well.
    udpardRxFragmentFree(transfer.payload,
                         instrumentedAllocatorMakeMemoryResource(&mem_fragment),
                         instrumentedAllocatorMakeMemoryDeleter(&mem_payload));
    TEST_ASSERT_EQUAL(0, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);  // Yeah.
}

void testRxSubscriptionReceiveInvalidArgument()
{
    InstrumentedAllocator mem_session{};
    InstrumentedAllocator mem_fragment{};
    InstrumentedAllocator mem_payload{};
    instrumentedAllocatorNew(&mem_session);
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);
    UdpardRxSubscription sub{};
    TEST_ASSERT_EQUAL(0,
                      udpardRxSubscriptionInit(&sub,
                                               0x1234,
                                               1000,
                                               {
                                                   .session  = instrumentedAllocatorMakeMemoryResource(&mem_session),
                                                   .fragment = instrumentedAllocatorMakeMemoryResource(&mem_fragment),
                                                   .payload  = instrumentedAllocatorMakeMemoryDeleter(&mem_payload),
                                               }));
    TEST_ASSERT_EQUAL(1000, sub.port.extent);
    TEST_ASSERT_EQUAL(UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC, sub.port.transfer_id_timeout_usec);
    TEST_ASSERT_EQUAL(nullptr, sub.port.sessions);
    TEST_ASSERT_EQUAL(0xEF001234UL, sub.udp_ip_endpoint.ip_address);
    TEST_ASSERT_EQUAL(9382, sub.udp_ip_endpoint.udp_port);
    TEST_ASSERT_EQUAL(0, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
    // Pass invalid arguments with a valid instance; the memory will be freed anyway to avoid leaks.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardRxSubscriptionReceive(&sub,
                                                  0xFFFF'FFFF'FFFF'FFFFUL,
                                                  UdpardMutablePayload{.size = 100,
                                                                       .data =
                                                                           instrumentedAllocatorAllocate(&mem_payload,
                                                                                                         100)},
                                                  0xFF,
                                                  nullptr));
    TEST_ASSERT_EQUAL(0, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);  // Memory freed on exit despite the error.
    // Calls with an invalid self pointer also result in the invalid argument error but the memory won't be freed.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardRxSubscriptionReceive(nullptr,
                                                  0xFFFF'FFFF'FFFF'FFFFUL,
                                                  UdpardMutablePayload{},
                                                  0xFF,
                                                  nullptr));
    // Free the subscription.
    udpardRxSubscriptionFree(&sub);
    udpardRxSubscriptionFree(&sub);  // The API does not guarantee anything but this is for extra safety.
    TEST_ASSERT_EQUAL(0, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);
}

}  // namespace

void setUp() {}

void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(testRxSubscriptionInit);
    RUN_TEST(testRxSubscriptionReceive);
    RUN_TEST(testRxSubscriptionReceiveInvalidArgument);
    return UNITY_END();
}
