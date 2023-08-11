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

void testRxRPCDispatcher()
{
    InstrumentedAllocator mem_session{};
    InstrumentedAllocator mem_fragment{};
    InstrumentedAllocator mem_payload{};
    instrumentedAllocatorNew(&mem_session);
    instrumentedAllocatorNew(&mem_fragment);
    instrumentedAllocatorNew(&mem_payload);

    // Initialize the RPC dispatcher.
    UdpardRxRPCDispatcher self{};
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardRxRPCDispatcherInit(nullptr,
                                                0xFFFFU,
                                                {
                                                    .session  = instrumentedAllocatorMakeMemoryResource(&mem_session),
                                                    .fragment = instrumentedAllocatorMakeMemoryResource(&mem_fragment),
                                                    .payload  = instrumentedAllocatorMakeMemoryDeleter(&mem_payload),
                                                }));
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardRxRPCDispatcherInit(&self,
                                                0x1042,
                                                {
                                                    .session  = {nullptr, nullptr, nullptr},
                                                    .fragment = instrumentedAllocatorMakeMemoryResource(&mem_fragment),
                                                    .payload  = instrumentedAllocatorMakeMemoryDeleter(&mem_payload),
                                                }));
    TEST_ASSERT_EQUAL(0,
                      udpardRxRPCDispatcherInit(&self,
                                                0x1042,
                                                {
                                                    .session  = instrumentedAllocatorMakeMemoryResource(&mem_session),
                                                    .fragment = instrumentedAllocatorMakeMemoryResource(&mem_fragment),
                                                    .payload  = instrumentedAllocatorMakeMemoryDeleter(&mem_payload),
                                                }));
    TEST_ASSERT_EQUAL(&instrumentedAllocatorAllocate, self.memory.session.allocate);
    TEST_ASSERT_EQUAL(&instrumentedAllocatorDeallocate, self.memory.session.deallocate);
    TEST_ASSERT_NULL(self.request_ports);
    TEST_ASSERT_NULL(self.response_ports);
    TEST_ASSERT_EQUAL(0x1042, self.local_node_id);
    TEST_ASSERT_EQUAL(0xEF011042UL, self.udp_ip_endpoint.ip_address);
    TEST_ASSERT_EQUAL(9382, self.udp_ip_endpoint.udp_port);
    TEST_ASSERT_EQUAL(0, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);

    // Add a request port.
    UdpardRxRPCPort port_request_foo{};
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT, udpardRxRPCDispatcherListen(&self, nullptr, 511, true, 100));
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT, udpardRxRPCDispatcherListen(&self, &port_request_foo, 0xFFFF, true, 100));
    TEST_ASSERT_EQUAL(1, udpardRxRPCDispatcherListen(&self, &port_request_foo, 511, true, 0));  // Added successfully.
    TEST_ASSERT_EQUAL(0, udpardRxRPCDispatcherListen(&self, &port_request_foo, 511, true, 0));  // Re-added.
    TEST_ASSERT_EQUAL(511, port_request_foo.service_id);
    TEST_ASSERT_EQUAL(UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC, port_request_foo.port.transfer_id_timeout_usec);
    TEST_ASSERT_EQUAL(0, port_request_foo.port.extent);
    TEST_ASSERT_NULL(port_request_foo.port.sessions);
    TEST_ASSERT_NULL(port_request_foo.user_reference);
    TEST_ASSERT_NOT_NULL(self.request_ports);
    TEST_ASSERT_NULL(self.response_ports);

    // Add a response port.
    UdpardRxRPCPort port_response_bar{};
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT, udpardRxRPCDispatcherListen(&self, nullptr, 0, false, 0));
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT, udpardRxRPCDispatcherListen(&self, &port_response_bar, 0xFFFF, false, 0));
    TEST_ASSERT_EQUAL(1, udpardRxRPCDispatcherListen(&self, &port_response_bar, 0, false, 100));  // Added successfully.
    TEST_ASSERT_EQUAL(0, udpardRxRPCDispatcherListen(&self, &port_response_bar, 0, false, 100));  // Re-added.
    TEST_ASSERT_EQUAL(0, port_response_bar.service_id);
    TEST_ASSERT_EQUAL(UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC, port_response_bar.port.transfer_id_timeout_usec);
    TEST_ASSERT_EQUAL(100, port_response_bar.port.extent);
    TEST_ASSERT_NULL(port_response_bar.port.sessions);
    TEST_ASSERT_NULL(port_response_bar.user_reference);
    TEST_ASSERT_NOT_NULL(self.request_ports);
    TEST_ASSERT_NOT_NULL(self.response_ports);

    // Check the global states.
    TEST_ASSERT_EQUAL(0, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);

    // Feed a valid request for the existing port we created above.
    //
    //>>> from pycyphal.transport.commons.crc import CRC32C
    //>>> CRC32C.new(b"Hello!").value_as_bytes
    //
    // >>> from pycyphal.transport.udp import UDPFrame
    // >>> from pycyphal.transport import Priority, MessageDataSpecifier, ServiceDataSpecifier
    // >>> frame = UDPFrame(priority=Priority.SLOW, transfer_id=0xbadc0ffee0ddf00d, index=0, end_of_transfer=True,
    //  payload=memoryview(b'Hello!\xd6\xeb\xfd\t'), source_node_id=2345, destination_node_id=0x1042,
    //  data_specifier=ServiceDataSpecifier(511, ServiceDataSpecifier.Role.REQUEST), user_data=0)
    // >>> list(frame.compile_header_and_payload()[0])
    // >>> list(frame.compile_header_and_payload()[1])
    UdpardRxRPCPort*    out_port = nullptr;
    UdpardRxRPCTransfer transfer{};
    {
        const std::array<std::uint_fast8_t, 34> data{{1,   6,   41,  9,   66,  16, 255, 193, 13,  240, 221, 224,
                                                      254, 15,  220, 186, 0,   0,  0,   128, 0,   0,   111, 105,  //
                                                      72,  101, 108, 108, 111, 33, 214, 235, 253, 9}};
        const UdpardMutablePayload              datagram{
                         .size = sizeof(data),
                         .data = instrumentedAllocatorAllocate(&mem_payload, sizeof(data)),
        };
        TEST_ASSERT_NOT_NULL(datagram.data);
        std::memcpy(datagram.data, data.data(), data.size());
        TEST_ASSERT_EQUAL(1, udpardRxRPCDispatcherReceive(&self, 10'000'000, datagram, 2, &out_port, &transfer));
    }
    TEST_ASSERT_EQUAL(&port_request_foo, out_port);  // Points to the correct port.
    TEST_ASSERT_EQUAL(511, transfer.service_id);
    TEST_ASSERT_EQUAL(true, transfer.is_request);
    TEST_ASSERT_EQUAL(10'000'000, transfer.base.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPrioritySlow, transfer.base.priority);
    TEST_ASSERT_EQUAL(2345, transfer.base.source_node_id);
    TEST_ASSERT_EQUAL(0xBADC0FFEE0DDF00D, transfer.base.transfer_id);
    TEST_ASSERT_EQUAL(0, transfer.base.payload_size);  // Truncated away because extent zero.
    TEST_ASSERT_EQUAL(0, transfer.base.payload.view.size);
    TEST_ASSERT_NULL(transfer.base.payload.next);
    // Check the global states.
    TEST_ASSERT_EQUAL(1, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);  // Because the payload was truncated away.
    udpardRxFragmentFree(transfer.base.payload, self.memory.fragment, self.memory.payload);  // No-op.
    TEST_ASSERT_EQUAL(1, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);

    // Feed the same transfer as before through another interface. It will be rejected as it is a duplicate.
    {
        const std::array<std::uint_fast8_t, 34> data{{1,   6,   41,  9,   66,  16, 255, 193, 13,  240, 221, 224,
                                                      254, 15,  220, 186, 0,   0,  0,   128, 0,   0,   111, 105,  //
                                                      72,  101, 108, 108, 111, 33, 214, 235, 253, 9}};
        const UdpardMutablePayload              datagram{
                         .size = sizeof(data),
                         .data = instrumentedAllocatorAllocate(&mem_payload, sizeof(data)),
        };
        TEST_ASSERT_NOT_NULL(datagram.data);
        std::memcpy(datagram.data, data.data(), data.size());
        TEST_ASSERT_EQUAL(0, udpardRxRPCDispatcherReceive(&self, 10'001'000, datagram, 0, nullptr, &transfer));
    }
    // Check the global states.
    TEST_ASSERT_EQUAL(1, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);

    // Feed a valid response for the existing port we created above.
    //
    // >>> frame = UDPFrame(priority=Priority.OPTIONAL, transfer_id=0x123456789ABCDEF, index=0, end_of_transfer=True,
    // payload=memoryview(b'Hello!\xd6\xeb\xfd\t'), source_node_id=5432, destination_node_id=0x1042,
    // data_specifier=ServiceDataSpecifier(0, ServiceDataSpecifier.Role.RESPONSE), user_data=0)
    {
        const std::array<std::uint_fast8_t, 34> data{{1,   7,   56,  21,  66,  16, 0,   128, 239, 205, 171, 137,
                                                      103, 69,  35,  1,   0,   0,  0,   128, 0,   0,   164, 48,  //
                                                      72,  101, 108, 108, 111, 33, 214, 235, 253, 9}};
        const UdpardMutablePayload              datagram{
                         .size = sizeof(data),
                         .data = instrumentedAllocatorAllocate(&mem_payload, sizeof(data)),
        };
        TEST_ASSERT_NOT_NULL(datagram.data);
        std::memcpy(datagram.data, data.data(), data.size());
        TEST_ASSERT_EQUAL(1, udpardRxRPCDispatcherReceive(&self, 10'002'000, datagram, 1, &out_port, &transfer));
    }
    TEST_ASSERT_EQUAL(&port_response_bar, out_port);  // Points to the correct port.
    TEST_ASSERT_EQUAL(0, transfer.service_id);
    TEST_ASSERT_EQUAL(false, transfer.is_request);
    TEST_ASSERT_EQUAL(10'002'000, transfer.base.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityOptional, transfer.base.priority);
    TEST_ASSERT_EQUAL(5432, transfer.base.source_node_id);
    TEST_ASSERT_EQUAL(0x123456789ABCDEF, transfer.base.transfer_id);
    TEST_ASSERT_EQUAL(6, transfer.base.payload_size);
    TEST_ASSERT_EQUAL(6, transfer.base.payload.view.size);
    TEST_ASSERT_EQUAL_MEMORY("Hello!", transfer.base.payload.view.data, 6);
    TEST_ASSERT_NULL(transfer.base.payload.next);
    // Check the global states.
    TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(1, mem_payload.allocated_fragments);
    udpardRxFragmentFree(transfer.base.payload, self.memory.fragment, self.memory.payload);
    TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);

    // Feed another valid transfer for which there is no port. It will be ignored.
    // >>> frame = UDPFrame(priority=Priority.OPTIONAL, transfer_id=0x123456789ABCDEF, index=0, end_of_transfer=True,
    // payload=memoryview(b'Hello!\xd6\xeb\xfd\t'), source_node_id=5432, destination_node_id=0x1042,
    // data_specifier=ServiceDataSpecifier(123, ServiceDataSpecifier.Role.RESPONSE), user_data=0)
    {
        const std::array<std::uint_fast8_t, 34> data{{1,   7,   56,  21,  66,  16, 123, 128, 239, 205, 171, 137,
                                                      103, 69,  35,  1,   0,   0,  0,   128, 0,   0,   180, 206,  //
                                                      72,  101, 108, 108, 111, 33, 214, 235, 253, 9}};
        const UdpardMutablePayload              datagram{
                         .size = sizeof(data),
                         .data = instrumentedAllocatorAllocate(&mem_payload, sizeof(data)),
        };
        TEST_ASSERT_NOT_NULL(datagram.data);
        std::memcpy(datagram.data, data.data(), data.size());
        TEST_ASSERT_EQUAL(0, udpardRxRPCDispatcherReceive(&self, 10'003'000, datagram, 1, &out_port, &transfer));
    }
    TEST_ASSERT_NULL(out_port);  // No port.
    TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);

    // Feed another valid transfer on the correct port but addressed to the wrong node.
    // >>> frame = UDPFrame(priority=Priority.OPTIONAL, transfer_id=0x123456789ABCDEF, index=0, end_of_transfer=True,
    // payload=memoryview(b'Hello!\xd6\xeb\xfd\t'), source_node_id=5432, destination_node_id=1234,
    // data_specifier=ServiceDataSpecifier(0, ServiceDataSpecifier.Role.RESPONSE), user_data=0)
    {
        const std::array<std::uint_fast8_t, 34> data{{1,   7,   56,  21,  210, 4,  0,   128, 239, 205, 171, 137,
                                                      103, 69,  35,  1,   0,   0,  0,   128, 0,   0,   236, 89,  //
                                                      72,  101, 108, 108, 111, 33, 214, 235, 253, 9}};
        const UdpardMutablePayload              datagram{
                         .size = sizeof(data),
                         .data = instrumentedAllocatorAllocate(&mem_payload, sizeof(data)),
        };
        TEST_ASSERT_NOT_NULL(datagram.data);
        std::memcpy(datagram.data, data.data(), data.size());
        TEST_ASSERT_EQUAL(0, udpardRxRPCDispatcherReceive(&self, 10'004'000, datagram, 1, nullptr, &transfer));
    }
    TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);

    // Feed an invalid frame. Ensure it is freed regardless.
    TEST_ASSERT_EQUAL(0,
                      udpardRxRPCDispatcherReceive(&self,
                                                   10'005'000,
                                                   UdpardMutablePayload{
                                                       .size = 100,
                                                       .data = instrumentedAllocatorAllocate(&mem_payload, 100),
                                                   },
                                                   1,
                                                   nullptr,
                                                   &transfer));
    TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);  // Freed.

    // Invalid arguments. The memory is freed as long as self is valid.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardRxRPCDispatcherReceive(&self,
                                                   0,
                                                   UdpardMutablePayload{
                                                       .size = 100,
                                                       .data = instrumentedAllocatorAllocate(&mem_payload, 100),
                                                   },
                                                   1,
                                                   nullptr,
                                                   nullptr));
    TEST_ASSERT_EQUAL(2, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);  // Freed.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardRxRPCDispatcherReceive(nullptr, 0, UdpardMutablePayload{}, 1, nullptr, nullptr));

    // Remove the ports.
    TEST_ASSERT_EQUAL(0, udpardRxRPCDispatcherCancel(&self, 511, false));  // No such port.
    TEST_ASSERT_EQUAL(0, udpardRxRPCDispatcherCancel(&self, 0, true));     // No such port.

    TEST_ASSERT_EQUAL(1, udpardRxRPCDispatcherCancel(&self, 511, true));  // Removed.
    TEST_ASSERT_NULL(self.request_ports);
    TEST_ASSERT_NOT_NULL(self.response_ports);
    TEST_ASSERT_EQUAL(1, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);

    TEST_ASSERT_EQUAL(1, udpardRxRPCDispatcherCancel(&self, 0, false));  // Removed.
    TEST_ASSERT_NULL(self.request_ports);
    TEST_ASSERT_NULL(self.response_ports);
    TEST_ASSERT_EQUAL(0, mem_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, mem_payload.allocated_fragments);

    TEST_ASSERT_EQUAL(0, udpardRxRPCDispatcherCancel(&self, 511, true));  // Idempotency.
    TEST_ASSERT_EQUAL(0, udpardRxRPCDispatcherCancel(&self, 0, false));   // Idempotency.

    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT, udpardRxRPCDispatcherCancel(&self, 0xFFFF, true));
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT, udpardRxRPCDispatcherCancel(nullptr, 123, false));
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
    RUN_TEST(testRxRPCDispatcher);
    return UNITY_END();
}
