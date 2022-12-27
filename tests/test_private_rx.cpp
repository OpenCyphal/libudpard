// This software is distributed under the terms of the MIT License.
// Copyright (c) 2016-2020 OpenCyphal Development Team.
/// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

#include "exposed.hpp"
#include "helpers.hpp"
#include "catch/catch.hpp"
#include <cstring>

TEST_CASE("rxTryParseFrame")
{
    using exposed::RxFrameModel;
    using exposed::rxTryParseFrame;

    RxFrameModel           model{};
    UdpardSessionSpecifier specifier{};
    UdpardFrameHeader      header{};

    const auto parse = [&](const UdpardMicrosecond          timestamp_usec,
                           UdpardSessionSpecifier           session_specifier,
                           const std::vector<std::uint8_t>& payload) {
        static std::vector<std::uint8_t> payload_storage;
        payload_storage = payload;
        UdpardFrame frame{};
        frame.payload_size = std::size(payload);
        frame.payload      = payload_storage.data();
        model              = RxFrameModel{};
        return rxTryParseFrame(timestamp_usec, &session_specifier, &frame, &model);
    };

    // Some initial header setup and payload test
    header.version                           = 0x01;
    header.priority                          = 0x07;
    header.source_node_id                    = 0x0000;
    header.destination_node_id               = 0xFFFF;
    header.data_specifier                    = 0x0000;
    header.transfer_id                       = 0x0000000000000001;
    header.frame_index_eot                   = (1U << 31U) + 1U;
    header._opaque                           = 0x0000;
    header.cyphal_header_checksum            = 0x0000;


    const std::vector<uint8_t>& test_payload = {
        0x01,                                            // Version
        0x07,                                            // Priority
        0x00, 0x00,                                      // Source Node ID
        0xFF, 0xFF,                                      // Destination Node ID
        0x00, 0x00,                                      // Data Specifier
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Transfer ID
        0x01, 0x00, 0x00, 0x80,                          // Frame EOT
        0x00, 0x00,                                      // Opaque Data
        0x00, 0x00,                                      // Transfer CRC
    };

    REQUIRE(sizeof(header) == 24U);
    REQUIRE(std::size(test_payload) == 24U);

    auto test_header_ptr      = reinterpret_cast<std::uint8_t*>(&header);
    auto test_payload_storage = std::vector<std::uint8_t>(test_header_ptr, test_header_ptr + sizeof(header));
    REQUIRE(test_payload_storage == test_payload);

    // MESSAGE
    REQUIRE(0 == exposed::txMakeMessageSessionSpecifier(0b0, 0b0, 0xc0a80000, &specifier));
    REQUIRE(parse(543210U,
                  specifier,
                  {
                      0x01,                                            // Version
                      0x00,                                            // Priority
                      0x00, 0x00,                                      // Source Node ID
                      0xFF, 0xFF,                                      // Destination Node ID
                      0x00, 0x00,                                      // Data Specifier
                      0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Transfer ID
                      0x01, 0x00, 0x00, 0x80,                          // Frame EOT
                      0x00, 0x00,                                      // Opaque Data
                      0x00, 0x00,                                      // Transfer CRC
                      0,    1,    2,    3,    4,    5,    6,    7      // Payload
                  }));
    REQUIRE(model.timestamp_usec == 543210U);
    REQUIRE(model.priority == UdpardPriorityExceptional);
    REQUIRE(model.transfer_kind == UdpardTransferKindMessage);
    REQUIRE(model.port_id == 0U);
    REQUIRE(model.source_node_id == 0U);
    REQUIRE(model.destination_node_id == UDPARD_NODE_ID_UNSET);
    REQUIRE(model.transfer_id == 1U);
    // REQUIRE(model.frame_index == 1U);
    REQUIRE(model.start_of_transfer);
    REQUIRE(model.end_of_transfer);
    REQUIRE(model.payload_size == 8);
    REQUIRE(model.payload[0] == 0);
    REQUIRE(model.payload[1] == 1);
    REQUIRE(model.payload[2] == 2);
    REQUIRE(model.payload[3] == 3);
    REQUIRE(model.payload[4] == 4);
    REQUIRE(model.payload[5] == 5);
    REQUIRE(model.payload[6] == 6);
    REQUIRE(model.payload[7] == 7);

    // SIMILAR BUT INVALID
    REQUIRE(0 == exposed::txMakeMessageSessionSpecifier(0b0, 0b0, 0xc0a80000, &specifier));
    REQUIRE(!parse(543210U,
                   specifier,
                   {
                       0x01,                                            // Version
                       0x00,                                            // Priority
                       0x00, 0x00,                                      // Source Node ID
                       0xFF, 0xFF,                                      // Destination Node ID
                       0x00, 0x00,                                      // Data Specifier
                       0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Transfer ID
                       0x00, 0x00, 0x00, 0x80,                          // Frame EOT
                       0x00, 0x00,                                      // Opaque Data
                       0x00, 0x00,                                      // Transfer CRC
                   }));                                                 // MFT FRAMES REQUIRE PAYLOAD

    // MESSAGE
    REQUIRE(0 == exposed::txMakeMessageSessionSpecifier(0b0110011001100, 0b0100111, 0xc0a80000, &specifier));
    REQUIRE(parse(123456U,
                  specifier,
                  {
                      0x01,                                            // Version
                      0x01,                                            // Priority
                      0x27, 0x00,                                      // Source Node ID
                      0xFF, 0xFF,                                      // Destination Node ID
                      0xCC, 0x0C,                                      // Data Specifier
                      0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Transfer ID
                      0x01, 0x00, 0x00, 0x00,                          // Frame EOT
                      0x00, 0x00,                                      // Opaque Data
                      0x00, 0x00,                                      // Transfer CRC
                      0,    1,    2,    3,    4,    5,    6            // Payload
                  }));
    REQUIRE(model.timestamp_usec == 123456U);
    REQUIRE(model.priority == UdpardPriorityImmediate);
    REQUIRE(model.transfer_kind == UdpardTransferKindMessage);
    REQUIRE(model.port_id == 0b0110011001100U);
    REQUIRE(model.source_node_id == 0b0100111U);
    REQUIRE(model.destination_node_id == UDPARD_NODE_ID_UNSET);
    REQUIRE(model.transfer_id == 23U);
    REQUIRE(model.start_of_transfer);
    REQUIRE(!model.end_of_transfer);
    REQUIRE(model.payload_size == 7);
    REQUIRE(model.payload[0] == 0);
    REQUIRE(model.payload[1] == 1);
    REQUIRE(model.payload[2] == 2);
    REQUIRE(model.payload[3] == 3);
    REQUIRE(model.payload[4] == 4);
    REQUIRE(model.payload[5] == 5);
    REQUIRE(model.payload[6] == 6);
    // SIMILAR BUT INVALID
    REQUIRE(0 == exposed::txMakeMessageSessionSpecifier(0b0110011001100, 0b0100111, 0xc0a80000, &specifier));
    // NO HEADER
    REQUIRE(!parse(123456U, specifier, {}));
    // ANON NOT SINGLE FRAME
    REQUIRE(0 == exposed::txMakeMessageSessionSpecifier(0b0110011001100, 0b1111111111111111, 0xc0a80000, &specifier));
    REQUIRE(!parse(123456U,
                   specifier,
                   {
                       0x01,                                            // Version
                       0x01,                                            // Priority
                       0xFF, 0xFF,                                      // Source Node ID
                       0xFF, 0xFF,                                      // Destination Node ID
                       0xCC, 0x0C,                                      // Data Specifier
                       0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Transfer ID
                       0x17, 0x00, 0x00, 0x80,                          // Frame EOT
                       0x00, 0x00,                                      // Opaque Data
                       0x00, 0x00,                                      // Transfer CRC
                       0,    1,    2,    3,    4,    5,    6            // Payload
                   }));

    // ANONYMOUS MESSAGE
    REQUIRE(0 == exposed::txMakeMessageSessionSpecifier(0b0110011001101, 0b1111111111111111, 0xc0a80000, &specifier));
    REQUIRE(parse(12345U,
                  specifier,
                  {
                      0x01,                                            // Version
                      0x02,                                            // Priority
                      0xFF, 0xFF,                                      // Source Node ID
                      0xFF, 0xFF,                                      // Destination Node ID
                      0xCD, 0x0C,                                      // Data Specifier
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Transfer ID
                      0x01, 0x00, 0x00, 0x80,                          // Frame EOT
                      0x00, 0x00,                                      // Opaque Data
                      0x00, 0x00,                                      // Transfer CRC
                  }));
    REQUIRE(model.timestamp_usec == 12345U);
    REQUIRE(model.priority == UdpardPriorityFast);
    REQUIRE(model.transfer_kind == UdpardTransferKindMessage);
    REQUIRE(model.port_id == 0b0110011001101U);
    REQUIRE(model.source_node_id == UDPARD_NODE_ID_UNSET);
    REQUIRE(model.destination_node_id == UDPARD_NODE_ID_UNSET);
    REQUIRE(model.transfer_id == 0U);
    REQUIRE(model.start_of_transfer);
    REQUIRE(model.end_of_transfer);
    REQUIRE(model.payload_size == 0);
    // SIMILAR BUT INVALID
    REQUIRE(!parse(12345U, specifier, {}));  // NO HEADER

    // REQUEST
    REQUIRE(0 ==
            exposed::txMakeServiceSessionSpecifier(0b0000110011, true, 0b0100111, 0b0011010, 0xc0a80000, &specifier));
    REQUIRE(parse(999'999U,
                  specifier,
                  {
                      0x01,                                            // Version
                      0x03,                                            // Priority
                      0x27, 0x00,                                      // Source Node ID
                      0x1A, 0x00,                                      // Destination Node ID
                      0x33, 0xC0,                                      // Data Specifier
                      0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Transfer ID
                      0xFF, 0x00, 0x00, 0x80,                          // Frame EOT
                      0x00, 0x00,                                      // Opaque Data
                      0x00, 0x00,                                      // Transfer CRC
                      0,    1,    2,    3                              // Payload
                  }));

    REQUIRE(model.timestamp_usec == 999'999U);
    REQUIRE(model.priority == UdpardPriorityHigh);
    REQUIRE(model.transfer_kind == UdpardTransferKindRequest);
    REQUIRE(model.port_id == 0b0000110011U);
    REQUIRE(model.source_node_id == 0b0100111U);
    REQUIRE(model.destination_node_id == 0b0011010U);
    REQUIRE(model.transfer_id == 31U);
    REQUIRE(!model.start_of_transfer);
    REQUIRE(model.end_of_transfer);
    REQUIRE(model.payload_size == 4);
    REQUIRE(model.payload[0] == 0);
    REQUIRE(model.payload[1] == 1);
    REQUIRE(model.payload[2] == 2);
    REQUIRE(model.payload[3] == 3);
    // SIMILAR BUT INVALID (Source Node ID cant be equal to Destination Node ID)
    REQUIRE(!parse(999'999U, specifier, {}));  // NO HEADER
    REQUIRE(0 ==
            exposed::txMakeServiceSessionSpecifier(0b0000110011, true, 0b0100111, 0b0100111, 0xc0a80000, &specifier));
    REQUIRE(!parse(999'999U,
                   specifier,
                   {
                       0x01,                                            // Version
                       0x03,                                            // Priority
                       0x27, 0x00,                                      // Source Node ID
                       0x27, 0x00,                                      // Destination Node ID
                       0x33, 0xC0,                                      // Data Specifier
                       0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Transfer ID
                       0xFF, 0x00, 0x00, 0x80,                          // Frame EOT
                       0x00, 0x00,                                      // Opaque Data
                       0x00, 0x00,                                      // Transfer CRC
                       0,    1,    2,    3                              // Payload
                   }));

    // RESPONSE
    REQUIRE(0 ==
            exposed::txMakeServiceSessionSpecifier(0b0000110011, false, 0b00011010, 0b0100111, 0xc0a80000, &specifier));
    REQUIRE(parse(888'888,
                  specifier,
                  {
                      0x01,                                            // Version
                      0x04,                                            // Priority
                      0x1A, 0x00,                                      // Source Node ID
                      0x27, 0x00,                                      // Destination Node ID
                      0x33, 0x80,                                      // Data Specifier
                      0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Transfer ID
                      0xFF, 0x00, 0x00, 0x80,                          // Frame EOT
                      0x00, 0x00,                                      // Opaque Data
                      0x00, 0x00,                                      // Transfer CRC
                      255                                              // Payload
                  }));
    REQUIRE(model.timestamp_usec == 888'888U);
    REQUIRE(model.priority == UdpardPriorityNominal);
    REQUIRE(model.transfer_kind == UdpardTransferKindResponse);
    REQUIRE(model.port_id == 0b0000110011U);
    REQUIRE(model.source_node_id == 0b0011010U);
    REQUIRE(model.destination_node_id == 0b0100111U);
    REQUIRE(model.transfer_id == 1U);
    REQUIRE(!model.start_of_transfer);
    REQUIRE(model.end_of_transfer);
    REQUIRE(model.payload_size == 1);
    REQUIRE(model.payload[0] == 255);
    // SIMILAR BUT INVALID (Source Node ID cant be equal to Destination Node ID)
    REQUIRE(!parse(888'888U, specifier, {}));  // NO TAIL BYTE
    REQUIRE(
        0 ==
        exposed::txMakeServiceSessionSpecifier(0b0000110011, false, 0b00011010, 0b00011010, 0xc0a80000, &specifier));
    REQUIRE(!parse(888'888,
                   specifier,
                   {
                       0x01,                                            // Version
                       0x04,                                            // Priority
                       0x1A, 0x00,                                      // Source Node ID
                       0x1A, 0x00,                                      // Destination Node ID
                       0x33, 0x80,                                      // Data Specifier
                       0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Transfer ID
                       0xFF, 0x00, 0x00, 0x80,                          // Frame EOT
                       0x00, 0x00,                                      // Opaque Data
                       0x00, 0x00,                                      // Transfer CRC
                       255                                              // Payload
                   }));
}
TEST_CASE("rxSessionWritePayload")
{
    using helpers::Instance;
    using exposed::RxSession;
    using exposed::rxSessionWritePayload;
    using exposed::rxSessionRestart;

    Instance  ins;
    RxSession rxs;
    rxs.transfer_id = 0U;

    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 0);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 0);

    // Regular write, the RX state is uninitialized so a new allocation will take place.
    REQUIRE(0 == rxSessionWritePayload(&ins.getInstance(), &rxs, 10, 5, "\x00\x01\x02\x03\x04"));
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 1);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 10);
    REQUIRE(rxs.payload_size == 5);
    REQUIRE(rxs.payload != nullptr);
    REQUIRE(rxs.payload[0] == 0);
    REQUIRE(rxs.payload[1] == 1);
    REQUIRE(rxs.payload[2] == 2);
    REQUIRE(rxs.payload[3] == 3);
    REQUIRE(rxs.payload[4] == 4);

    // Appending the pre-allocated storage.
    REQUIRE(0 == rxSessionWritePayload(&ins.getInstance(), &rxs, 10, 4, "\x05\x06\x07\x08"));
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 1);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 10);
    REQUIRE(rxs.payload_size == 9);
    REQUIRE(rxs.payload != nullptr);
    REQUIRE(rxs.payload[0] == 0);
    REQUIRE(rxs.payload[1] == 1);
    REQUIRE(rxs.payload[2] == 2);
    REQUIRE(rxs.payload[3] == 3);
    REQUIRE(rxs.payload[4] == 4);
    REQUIRE(rxs.payload[5] == 5);
    REQUIRE(rxs.payload[6] == 6);
    REQUIRE(rxs.payload[7] == 7);
    REQUIRE(rxs.payload[8] == 8);

    // Implicit truncation -- too much payload, excess ignored.
    REQUIRE(0 == rxSessionWritePayload(&ins.getInstance(), &rxs, 10, 3, "\x09\x0A\x0B"));
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 1);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 10);
    REQUIRE(rxs.payload_size == 10);
    REQUIRE(rxs.payload != nullptr);
    REQUIRE(rxs.payload[0] == 0);
    REQUIRE(rxs.payload[1] == 1);
    REQUIRE(rxs.payload[2] == 2);
    REQUIRE(rxs.payload[3] == 3);
    REQUIRE(rxs.payload[4] == 4);
    REQUIRE(rxs.payload[5] == 5);
    REQUIRE(rxs.payload[6] == 6);
    REQUIRE(rxs.payload[7] == 7);
    REQUIRE(rxs.payload[8] == 8);
    REQUIRE(rxs.payload[9] == 9);

    // Storage is already full, write ignored.
    REQUIRE(0 == rxSessionWritePayload(&ins.getInstance(), &rxs, 10, 3, "\x0C\x0D\x0E"));
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 1);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 10);
    REQUIRE(rxs.payload_size == 10);
    REQUIRE(rxs.payload != nullptr);
    REQUIRE(rxs.payload[0] == 0);
    REQUIRE(rxs.payload[1] == 1);
    REQUIRE(rxs.payload[2] == 2);
    REQUIRE(rxs.payload[3] == 3);
    REQUIRE(rxs.payload[4] == 4);
    REQUIRE(rxs.payload[5] == 5);
    REQUIRE(rxs.payload[6] == 6);
    REQUIRE(rxs.payload[7] == 7);
    REQUIRE(rxs.payload[8] == 8);
    REQUIRE(rxs.payload[9] == 9);

    // Restart frees the buffer. The transfer-ID will be incremented, too.
    rxSessionRestart(&ins.getInstance(), &rxs);
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 0);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 0);
    REQUIRE(rxs.payload_size == 0);
    REQUIRE(rxs.payload == nullptr);
    REQUIRE(rxs.calculated_crc == 0xFFFFFFFFU);
    REQUIRE(rxs.transfer_id == 1);

    // Double restart has no effect on memory.
    rxs.calculated_crc = 0x1234U;
    rxs.transfer_id    = 23;
    rxSessionRestart(&ins.getInstance(), &rxs);
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 0);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 0);
    REQUIRE(rxs.payload_size == 0);
    REQUIRE(rxs.payload == nullptr);
    REQUIRE(rxs.calculated_crc == 0xFFFFFFFFU);
    REQUIRE(rxs.transfer_id == 24U);

    // Restart with a transfer-ID overflow.
    rxs.calculated_crc = 0x1234U;
    rxs.transfer_id    = 0xFFFFFFFFFFFFFFFF;
    rxSessionRestart(&ins.getInstance(), &rxs);
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 0);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 0);
    REQUIRE(rxs.payload_size == 0);
    REQUIRE(rxs.payload == nullptr);
    REQUIRE(rxs.calculated_crc == 0xFFFFFFFFU);
    REQUIRE(rxs.transfer_id == 0U);

    // Write into a zero-capacity storage. NULL at the output.
    REQUIRE(0 == rxSessionWritePayload(&ins.getInstance(), &rxs, 0, 3, "\x00\x01\x02"));
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 0);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 0);
    REQUIRE(rxs.payload_size == 0);
    REQUIRE(rxs.payload == nullptr);

    // Write with OOM.
    ins.getAllocator().setAllocationCeiling(5);
    REQUIRE(-UDPARD_ERROR_OUT_OF_MEMORY == rxSessionWritePayload(&ins.getInstance(), &rxs, 10, 3, "\x00\x01\x02"));
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 0);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 0);
    REQUIRE(rxs.payload_size == 0);
    REQUIRE(rxs.payload == nullptr);
}

TEST_CASE("rxSessionUpdate")
{
    using helpers::Instance;
    using exposed::RxSession;
    using exposed::RxFrameModel;
    using exposed::rxSessionUpdate;
    using exposed::crcAdd;

    Instance ins;
    ins.getAllocator().setAllocationCeiling(16);

    RxFrameModel frame;
    frame.timestamp_usec      = 10'000'000;
    frame.priority            = UdpardPrioritySlow;
    frame.transfer_kind       = UdpardTransferKindMessage;
    frame.port_id             = 2'222;
    frame.source_node_id      = 55;
    frame.destination_node_id = UDPARD_NODE_ID_UNSET;
    frame.transfer_id         = 11;
    frame.start_of_transfer   = true;
    frame.end_of_transfer     = true;
    frame.payload_size        = 3;
    frame.payload             = reinterpret_cast<const uint8_t*>("\x01\x01\x01");

    RxSession rxs;
    rxs.transfer_id               = 31;
    rxs.redundant_transport_index = 1;

    UdpardRxTransfer transfer{};

    const auto update = [&](const std::uint8_t  redundant_transport_index,
                            const std::uint64_t tid_timeout_usec,
                            const std::size_t   extent) {
        return rxSessionUpdate(&ins.getInstance(),
                               &rxs,
                               &frame,
                               redundant_transport_index,
                               tid_timeout_usec,
                               extent,
                               &transfer);
    };

    // const auto crc = [](const char* const string) { return crcAdd(0xFFFF, std::strlen(string), string); };

    // Accept one transfer.
    REQUIRE(1 == update(1, 1'000'000, 16));
    REQUIRE(rxs.transfer_timestamp_usec == 10'000'000);
    REQUIRE(rxs.payload_size == 0);   // Handed over to the output transfer.
    REQUIRE(rxs.payload == nullptr);  // Handed over to the output transfer.
    REQUIRE(rxs.calculated_crc == 0xFFFFFFFFU);
    REQUIRE(rxs.transfer_id == 12U);  // Incremented.
    REQUIRE(rxs.redundant_transport_index == 1);
    REQUIRE(transfer.timestamp_usec == 10'000'000);
    REQUIRE(transfer.metadata.priority == UdpardPrioritySlow);
    REQUIRE(transfer.metadata.transfer_kind == UdpardTransferKindMessage);
    REQUIRE(transfer.metadata.port_id == 2'222);
    REQUIRE(transfer.metadata.remote_node_id == 55);
    REQUIRE(transfer.metadata.transfer_id == 11);
    REQUIRE(transfer.payload_size == 3);
    REQUIRE(0 == std::memcmp(transfer.payload, "\x01\x01\x01", 3));
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 1);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 16);
    ins.getAllocator().deallocate(transfer.payload);

    // Valid next transfer, wrong transport.
    frame.timestamp_usec = 10'000'100;
    frame.transfer_id    = 12;
    frame.payload        = reinterpret_cast<const uint8_t*>("\x02\x02\x02");
    REQUIRE(0 == update(2, 1'000'000, 16));
    REQUIRE(rxs.transfer_timestamp_usec == 10'000'000);
    REQUIRE(rxs.payload_size == 0);   // Handed over to the output transfer.
    REQUIRE(rxs.payload == nullptr);  // Handed over to the output transfer.
    REQUIRE(rxs.calculated_crc == 0xFFFFFFFFU);
    REQUIRE(rxs.transfer_id == 12U);  // Incremented.
    REQUIRE(rxs.redundant_transport_index == 1);

    // Correct transport.
    frame.timestamp_usec = 10'000'050;
    frame.payload        = reinterpret_cast<const uint8_t*>("\x03\x03\x03");
    REQUIRE(1 == update(1, 1'000'000, 16));
    REQUIRE(rxs.transfer_timestamp_usec == 10'000'050);
    REQUIRE(rxs.payload_size == 0);
    REQUIRE(rxs.payload == nullptr);
    REQUIRE(rxs.calculated_crc == 0xFFFFFFFFU);
    REQUIRE(rxs.transfer_id == 13U);
    REQUIRE(rxs.redundant_transport_index == 1);
    REQUIRE(transfer.timestamp_usec == 10'000'050);
    REQUIRE(transfer.metadata.priority == UdpardPrioritySlow);
    REQUIRE(transfer.metadata.transfer_kind == UdpardTransferKindMessage);
    REQUIRE(transfer.metadata.port_id == 2'222);
    REQUIRE(transfer.metadata.remote_node_id == 55);
    REQUIRE(transfer.metadata.transfer_id == 12);
    REQUIRE(transfer.payload_size == 3);
    REQUIRE(0 == std::memcmp(transfer.payload, "\x03\x03\x03", 3));
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 1);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 16);
    ins.getAllocator().deallocate(transfer.payload);

    // Same TID.
    frame.timestamp_usec = 10'000'200;
    frame.transfer_id    = 12;
    frame.payload        = reinterpret_cast<const uint8_t*>("\x04\x04\x04");
    REQUIRE(0 == update(1, 1'000'200, 16));
    REQUIRE(rxs.transfer_timestamp_usec == 10'000'050);
    REQUIRE(rxs.payload_size == 0);
    REQUIRE(rxs.payload == nullptr);
    REQUIRE(rxs.calculated_crc == 0xFFFFFFFFU);
    REQUIRE(rxs.transfer_id == 13U);
    REQUIRE(rxs.redundant_transport_index == 1);

    // Restart due to TID timeout, switch iface.
    frame.timestamp_usec = 20'000'000;
    frame.transfer_id    = 12;
    frame.payload        = reinterpret_cast<const uint8_t*>("\x05\x05\x05");
    REQUIRE(1 == update(0, 1'000'000, 16));
    REQUIRE(rxs.transfer_timestamp_usec == 20'000'000);
    REQUIRE(rxs.payload_size == 0);
    REQUIRE(rxs.payload == nullptr);
    REQUIRE(rxs.calculated_crc == 0xFFFFFFFFU);
    REQUIRE(rxs.transfer_id == 13U);
    REQUIRE(rxs.redundant_transport_index == 0);
    REQUIRE(transfer.timestamp_usec == 20'000'000);
    REQUIRE(transfer.metadata.priority == UdpardPrioritySlow);
    REQUIRE(transfer.metadata.transfer_kind == UdpardTransferKindMessage);
    REQUIRE(transfer.metadata.port_id == 2'222);
    REQUIRE(transfer.metadata.remote_node_id == 55);
    REQUIRE(transfer.metadata.transfer_id == 12);
    REQUIRE(transfer.payload_size == 3);
    REQUIRE(0 == std::memcmp(transfer.payload, "\x05\x05\x05", 3));
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 1);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 16);
    ins.getAllocator().deallocate(transfer.payload);

    // Restart by TID timeout, not the first frame.
    frame.timestamp_usec    = 30'000'000;
    frame.transfer_id       = 12;  // Goes back.
    frame.start_of_transfer = false;
    frame.end_of_transfer   = false;
    frame.payload_size      = 7;
    frame.payload           = reinterpret_cast<const uint8_t*>("\x0A\x0A\x0A\x0A\x0A\x0A\x0A");
    REQUIRE(0 == update(2, 1'000'000, 16));
    REQUIRE(rxs.transfer_timestamp_usec == 20'000'000);  // No change.
    REQUIRE(rxs.payload_size == 0);
    REQUIRE(rxs.payload == nullptr);
    REQUIRE(rxs.calculated_crc == 0xFFFFFFFFU);
    REQUIRE(rxs.transfer_id == 13U);
    REQUIRE(rxs.redundant_transport_index == 2);
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 0);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 0);

    // OOM -- reset on error.
    frame.timestamp_usec    = 20'000'200;
    frame.transfer_id       = 30;
    frame.start_of_transfer = true;
    frame.end_of_transfer   = true;
    frame.payload_size      = 8;
    frame.payload           = reinterpret_cast<const uint8_t*>("\x0E\x0E\x0E\x0E\x0E\x0E\x0E\xF7");
    REQUIRE((-UDPARD_ERROR_OUT_OF_MEMORY) == update(2, 1'000'000, 17));  // Exceeds the heap quota.
    REQUIRE(rxs.transfer_timestamp_usec == 20'000'200);
    REQUIRE(rxs.payload_size == 0);
    REQUIRE(rxs.payload == nullptr);
    REQUIRE(rxs.calculated_crc == 0xFFFFFFFFU);
    REQUIRE(rxs.transfer_id == 31U);  // Reset.
    REQUIRE(rxs.redundant_transport_index == 2);
    REQUIRE(ins.getAllocator().getNumAllocatedFragments() == 0);
    REQUIRE(ins.getAllocator().getTotalAllocatedAmount() == 0);
}
