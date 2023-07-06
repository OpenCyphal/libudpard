/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c>  // NOLINT(bugprone-suspicious-include)
#include "helpers.hpp"
#include "hexdump.hpp"
#include <gtest/gtest.h>
#include <span>

namespace
{
// >>> from pycyphal.transport.commons.crc import CRC32C
// >>> list(CRC32C.new(data).value_as_bytes)
constexpr std::string_view EtherealStrength =
    "All was silent except for the howl of the wind against the antenna. Ye watched as the remaining birds in the "
    "flock gradually settled back into the forest. She stared at the antenna and thought it looked like an enormous "
    "hand stretched open toward the sky, possessing an ethereal strength.";
constexpr std::array<std::uint8_t, 4> EtherealStrengthCRC{{209, 88, 130, 43}};

constexpr std::string_view DetailOfTheCosmos =
    "For us, the dark forest state is all-important, but it's just a detail of the cosmos.";
constexpr std::array<std::uint8_t, 4> DetailOfTheCosmosCRC{{125, 113, 207, 171}};

constexpr std::string_view            InterstellarWar = "You have not seen what a true interstellar war is like.";
constexpr std::array<std::uint8_t, 4> InterstellarWarCRC{{102, 217, 109, 188}};

auto makeHeader(const TransferMetadata meta, const std::uint32_t frame_index, const bool end_of_transfer)
{
    std::array<byte_t, HEADER_SIZE_BYTES> buffer{};
    (void) txSerializeHeader(buffer.data(), meta, frame_index, end_of_transfer);
    return buffer;
}
}  // namespace

// Generate reference data using PyCyphal:
//
// >>> from pycyphal.transport.udp import UDPFrame
// >>> from pycyphal.transport import Priority, MessageDataSpecifier
// >>> frame = UDPFrame(priority=Priority.FAST, transfer_id=0xbadc0ffee0ddf00d, index=12345, end_of_transfer=False,
//  payload=memoryview(b''), source_node_id=2345, destination_node_id=5432,
//  data_specifier=MessageDataSpecifier(7654), user_data=0)
// >>> list(frame.compile_header_and_payload()[0])
// [1, 2, 41, 9, 56, 21, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0, 224, 60]
TEST(TxPrivate, SerializeHeader)
{
    using HeaderBuffer = std::array<byte_t, HEADER_SIZE_BYTES>;
    {
        HeaderBuffer buffer{};
        ASSERT_EQ(buffer.end(),
                  txSerializeHeader(buffer.data(),
                                    {
                                        .priority       = UdpardPriorityFast,
                                        .src_node_id    = 2345,
                                        .dst_node_id    = 5432,
                                        .data_specifier = 7654,
                                        .transfer_id    = 0xBADC'0FFE'E0DD'F00dULL,
                                    },
                                    12345,
                                    false));
        const HeaderBuffer ref{
            {1, 2, 41, 9, 56, 21, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0, 224, 60}};
        ASSERT_EQ(ref, buffer);
    }
    {
        HeaderBuffer buffer{};
        ASSERT_EQ(buffer.end(),
                  txSerializeHeader(buffer.data(),
                                    {
                                        .priority       = UdpardPriorityLow,
                                        .src_node_id    = 0xFEDC,
                                        .dst_node_id    = 0xBA98,
                                        .data_specifier = 1234,
                                        .transfer_id    = 0x0BAD'C0DE'0BAD'C0DEULL,
                                    },
                                    0x7FFF,
                                    true));
        const HeaderBuffer ref{
            {1, 5, 220, 254, 152, 186, 210, 4, 222, 192, 173, 11, 222, 192, 173, 11, 255, 127, 0, 128, 0, 0, 229, 4}};
        ASSERT_EQ(ref, buffer);
    }
}

TEST(TxPrivate, MakeChainEmpty)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const TransferMetadata meta{
        .priority       = UdpardPriorityFast,
        .src_node_id    = 1234,
        .dst_node_id    = 2345,
        .data_specifier = 5432,
        .transfer_id    = 0xBADC'0FFE'E0DD'F00DULL,
    };
    const auto chain = txMakeChain(&alloc,
                                   std::array<std::uint_least8_t, 8>{{11, 22, 33, 44, 55, 66, 77, 88}}.data(),
                                   30,
                                   1234567890,
                                   meta,
                                   UdpardUDPIPEndpoint{.ip_address = 0x0A0B'0C0DU, .udp_port = 0x1234},
                                   UdpardConstPayload{.size = 0, .data = ""},
                                   &user_transfer_referent);
    ASSERT_EQ(1, alloc.getNumAllocatedFragments());
    ASSERT_EQ(sizeof(TxItem) + HEADER_SIZE_BYTES + 4, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(1, chain.count);
    std::cout << hexdump::hexdump(chain.head->base.datagram_payload.data, chain.head->base.datagram_payload.size)
              << "\n\n";
    ASSERT_EQ(chain.head, chain.tail);
    ASSERT_EQ(nullptr, chain.head->base.next_in_transfer);
    ASSERT_EQ(1234567890, chain.head->base.deadline_usec);
    ASSERT_EQ(33, chain.head->base.dscp);
    ASSERT_EQ(0x0A0B'0C0DU, chain.head->base.destination.ip_address);
    ASSERT_EQ(0x1234, chain.head->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + 4, chain.head->base.datagram_payload.size);
    ASSERT_EQ(0,
              std::memcmp(makeHeader(meta, 0, true).data(), chain.head->base.datagram_payload.data, HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp("\x00\x00\x00\x00",  // CRC of the empty transfer.
                          static_cast<byte_t*>(chain.head->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          4));
    ASSERT_EQ(&user_transfer_referent, chain.head->base.user_transfer_reference);
}

TEST(TxPrivate, MakeChainSingleMaxMTU)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const TransferMetadata meta{
        .priority       = UdpardPrioritySlow,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    const auto chain =
        txMakeChain(&alloc,
                    std::array<std::uint_least8_t, 8>{{11, 22, 33, 44, 55, 66, 77, 88}}.data(),
                    DetailOfTheCosmos.size() + DetailOfTheCosmosCRC.size(),
                    1234567890,
                    meta,
                    UdpardUDPIPEndpoint{.ip_address = 0x0A0B'0C00U, .udp_port = 7474},
                    UdpardConstPayload{.size = DetailOfTheCosmos.size(), .data = DetailOfTheCosmos.data()},
                    &user_transfer_referent);
    ASSERT_EQ(1, alloc.getNumAllocatedFragments());
    ASSERT_EQ(sizeof(TxItem) + HEADER_SIZE_BYTES + DetailOfTheCosmos.size() + DetailOfTheCosmosCRC.size(),
              alloc.getTotalAllocatedAmount());
    ASSERT_EQ(1, chain.count);
    std::cout << hexdump::hexdump(chain.head->base.datagram_payload.data, chain.head->base.datagram_payload.size)
              << "\n\n";
    ASSERT_EQ(chain.head, chain.tail);
    ASSERT_EQ(nullptr, chain.head->base.next_in_transfer);
    ASSERT_EQ(1234567890, chain.head->base.deadline_usec);
    ASSERT_EQ(77, chain.head->base.dscp);
    ASSERT_EQ(0x0A0B'0C00U, chain.head->base.destination.ip_address);
    ASSERT_EQ(7474, chain.head->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + DetailOfTheCosmos.size() + DetailOfTheCosmosCRC.size(),
              chain.head->base.datagram_payload.size);
    ASSERT_EQ(0,
              std::memcmp(makeHeader(meta, 0, true).data(), chain.head->base.datagram_payload.data, HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp(DetailOfTheCosmos.data(),
                          static_cast<byte_t*>(chain.head->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          DetailOfTheCosmos.size()));
    ASSERT_EQ(0,
              std::memcmp(DetailOfTheCosmosCRC.data(),
                          static_cast<byte_t*>(chain.head->base.datagram_payload.data) + HEADER_SIZE_BYTES +
                              DetailOfTheCosmos.size(),
                          DetailOfTheCosmosCRC.size()));
    ASSERT_EQ(&user_transfer_referent, chain.head->base.user_transfer_reference);
}

TEST(TxPrivate, MakeChainThreeFrames)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const TransferMetadata meta{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    const auto mtu   = (EtherealStrength.size() + 4U + 3U) / 3U;  // Force payload split into three frames.
    const auto chain = txMakeChain(&alloc,
                                   std::array<std::uint_least8_t, 8>{{11, 22, 33, 44, 55, 66, 77, 88}}.data(),
                                   mtu,
                                   223574680,
                                   meta,
                                   UdpardUDPIPEndpoint{.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                                   UdpardConstPayload{.size = EtherealStrength.size(), .data = EtherealStrength.data()},
                                   &user_transfer_referent);
    ASSERT_EQ(3, alloc.getNumAllocatedFragments());
    ASSERT_EQ(3 * (sizeof(TxItem) + HEADER_SIZE_BYTES) + EtherealStrength.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(3, chain.count);
    const auto* const first = chain.head;
    ASSERT_NE(nullptr, first);
    const auto* const second = reinterpret_cast<TxItem*>(first->base.next_in_transfer);
    ASSERT_NE(nullptr, second);
    const auto* const third = reinterpret_cast<TxItem*>(second->base.next_in_transfer);
    ASSERT_NE(nullptr, third);
    ASSERT_EQ(nullptr, third->base.next_in_transfer);
    ASSERT_EQ(chain.tail, third);

    // FIRST FRAME -- contains the first part of the payload.
    std::cout << hexdump::hexdump(first->base.datagram_payload.data, first->base.datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, first->base.deadline_usec);
    ASSERT_EQ(55, first->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, first->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, first->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + mtu, first->base.datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, false).data(), first->base.datagram_payload.data, HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp(EtherealStrength.data(),
                          static_cast<byte_t*>(first->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          mtu));
    ASSERT_EQ(&user_transfer_referent, first->base.user_transfer_reference);

    // SECOND FRAME -- contains the second part of the payload.
    std::cout << hexdump::hexdump(second->base.datagram_payload.data, second->base.datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, second->base.deadline_usec);
    ASSERT_EQ(55, second->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, second->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, second->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + mtu, second->base.datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 1, false).data(), second->base.datagram_payload.data, HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp(EtherealStrength.data() + mtu,
                          static_cast<byte_t*>(second->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          mtu));
    ASSERT_EQ(&user_transfer_referent, second->base.user_transfer_reference);

    // THIRD FRAME -- contains the third part of the payload and the CRC at the end.
    std::cout << hexdump::hexdump(third->base.datagram_payload.data, third->base.datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, third->base.deadline_usec);
    ASSERT_EQ(55, third->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, third->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, third->base.destination.udp_port);
    const auto third_payload_size = EtherealStrength.size() - 2 * mtu;
    ASSERT_EQ(HEADER_SIZE_BYTES + third_payload_size + 4U, third->base.datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 2, true).data(), third->base.datagram_payload.data, HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp(EtherealStrength.data() + 2 * mtu,
                          static_cast<byte_t*>(third->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          third_payload_size));
    ASSERT_EQ(0,
              std::memcmp(EtherealStrengthCRC.data(),
                          static_cast<byte_t*>(third->base.datagram_payload.data) + HEADER_SIZE_BYTES +
                              third_payload_size,
                          EtherealStrengthCRC.size()));
    ASSERT_EQ(&user_transfer_referent, third->base.user_transfer_reference);
}

TEST(TxPrivate, MakeChainCRCSpill1)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const TransferMetadata meta{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    const auto mtu   = InterstellarWar.size() + 3U;
    const auto chain = txMakeChain(&alloc,
                                   std::array<std::uint_least8_t, 8>{{11, 22, 33, 44, 55, 66, 77, 88}}.data(),
                                   mtu,
                                   223574680,
                                   meta,
                                   UdpardUDPIPEndpoint{.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                                   UdpardConstPayload{.size = InterstellarWar.size(), .data = InterstellarWar.data()},
                                   &user_transfer_referent);
    ASSERT_EQ(2, alloc.getNumAllocatedFragments());
    ASSERT_EQ(2 * (sizeof(TxItem) + HEADER_SIZE_BYTES) + InterstellarWar.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(2, chain.count);
    ASSERT_NE(chain.head, chain.tail);
    ASSERT_EQ(chain.tail, reinterpret_cast<TxItem*>(chain.head->base.next_in_transfer));
    ASSERT_EQ(nullptr, chain.tail->base.next_in_transfer);

    // FIRST FRAME -- contains the payload and the first three bytes of the CRC.
    std::cout << hexdump::hexdump(chain.head->base.datagram_payload.data, chain.head->base.datagram_payload.size)
              << "\n\n";
    ASSERT_EQ(223574680, chain.head->base.deadline_usec);
    ASSERT_EQ(55, chain.head->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.head->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.head->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + mtu, chain.head->base.datagram_payload.size);
    ASSERT_EQ(0,
              std::memcmp(makeHeader(meta, 0, false).data(),
                          chain.head->base.datagram_payload.data,
                          HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWar.data(),
                          static_cast<byte_t*>(chain.head->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          InterstellarWar.size()));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data(),
                          static_cast<byte_t*>(chain.head->base.datagram_payload.data) + HEADER_SIZE_BYTES +
                              InterstellarWar.size(),
                          3U));
    ASSERT_EQ(&user_transfer_referent, chain.head->base.user_transfer_reference);

    // SECOND FRAME -- contains the last byte of the CRC.
    std::cout << hexdump::hexdump(chain.tail->base.datagram_payload.data, chain.tail->base.datagram_payload.size)
              << "\n\n";
    ASSERT_EQ(223574680, chain.tail->base.deadline_usec);
    ASSERT_EQ(55, chain.tail->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.tail->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.tail->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + 1U, chain.tail->base.datagram_payload.size);
    ASSERT_EQ(0,
              std::memcmp(makeHeader(meta, 1, true).data(), chain.tail->base.datagram_payload.data, HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data() + 3U,
                          static_cast<byte_t*>(chain.tail->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          1U));
    ASSERT_EQ(&user_transfer_referent, chain.tail->base.user_transfer_reference);
}

TEST(TxPrivate, MakeChainCRCSpill2)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const TransferMetadata meta{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    const auto mtu   = InterstellarWar.size() + 2U;
    const auto chain = txMakeChain(&alloc,
                                   std::array<std::uint_least8_t, 8>{{11, 22, 33, 44, 55, 66, 77, 88}}.data(),
                                   mtu,
                                   223574680,
                                   meta,
                                   UdpardUDPIPEndpoint{.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                                   UdpardConstPayload{.size = InterstellarWar.size(), .data = InterstellarWar.data()},
                                   &user_transfer_referent);
    ASSERT_EQ(2, alloc.getNumAllocatedFragments());
    ASSERT_EQ(2 * (sizeof(TxItem) + HEADER_SIZE_BYTES) + InterstellarWar.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(2, chain.count);
    ASSERT_NE(chain.head, chain.tail);
    ASSERT_EQ(chain.tail, reinterpret_cast<TxItem*>(chain.head->base.next_in_transfer));
    ASSERT_EQ(nullptr, chain.tail->base.next_in_transfer);

    // FIRST FRAME -- contains the payload and the first two bytes of the CRC.
    std::cout << hexdump::hexdump(chain.head->base.datagram_payload.data, chain.head->base.datagram_payload.size)
              << "\n\n";
    ASSERT_EQ(223574680, chain.head->base.deadline_usec);
    ASSERT_EQ(55, chain.head->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.head->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.head->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + mtu, chain.head->base.datagram_payload.size);
    ASSERT_EQ(0,
              std::memcmp(makeHeader(meta, 0, false).data(),
                          chain.head->base.datagram_payload.data,
                          HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWar.data(),
                          static_cast<byte_t*>(chain.head->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          InterstellarWar.size()));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data(),
                          static_cast<byte_t*>(chain.head->base.datagram_payload.data) + HEADER_SIZE_BYTES +
                              InterstellarWar.size(),
                          2U));
    ASSERT_EQ(&user_transfer_referent, chain.head->base.user_transfer_reference);

    // SECOND FRAME -- contains the last two bytes of the CRC.
    std::cout << hexdump::hexdump(chain.tail->base.datagram_payload.data, chain.tail->base.datagram_payload.size)
              << "\n\n";
    ASSERT_EQ(223574680, chain.tail->base.deadline_usec);
    ASSERT_EQ(55, chain.tail->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.tail->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.tail->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + 2U, chain.tail->base.datagram_payload.size);
    ASSERT_EQ(0,
              std::memcmp(makeHeader(meta, 1, true).data(), chain.tail->base.datagram_payload.data, HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data() + 2U,
                          static_cast<byte_t*>(chain.tail->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          2U));
    ASSERT_EQ(&user_transfer_referent, chain.tail->base.user_transfer_reference);
}

TEST(TxPrivate, MakeChainCRCSpill3)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const TransferMetadata meta{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    const auto mtu   = InterstellarWar.size() + 1U;
    const auto chain = txMakeChain(&alloc,
                                   std::array<std::uint_least8_t, 8>{{11, 22, 33, 44, 55, 66, 77, 88}}.data(),
                                   mtu,
                                   223574680,
                                   meta,
                                   UdpardUDPIPEndpoint{.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                                   UdpardConstPayload{.size = InterstellarWar.size(), .data = InterstellarWar.data()},
                                   &user_transfer_referent);
    ASSERT_EQ(2, alloc.getNumAllocatedFragments());
    ASSERT_EQ(2 * (sizeof(TxItem) + HEADER_SIZE_BYTES) + InterstellarWar.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(2, chain.count);
    ASSERT_NE(chain.head, chain.tail);
    ASSERT_EQ(chain.tail, reinterpret_cast<TxItem*>(chain.head->base.next_in_transfer));
    ASSERT_EQ(nullptr, chain.tail->base.next_in_transfer);

    // FIRST FRAME -- contains the payload and the first byte of the CRC.
    std::cout << hexdump::hexdump(chain.head->base.datagram_payload.data, chain.head->base.datagram_payload.size)
              << "\n\n";
    ASSERT_EQ(223574680, chain.head->base.deadline_usec);
    ASSERT_EQ(55, chain.head->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.head->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.head->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + mtu, chain.head->base.datagram_payload.size);
    ASSERT_EQ(0,
              std::memcmp(makeHeader(meta, 0, false).data(),
                          chain.head->base.datagram_payload.data,
                          HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWar.data(),
                          static_cast<byte_t*>(chain.head->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          InterstellarWar.size()));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data(),
                          static_cast<byte_t*>(chain.head->base.datagram_payload.data) + HEADER_SIZE_BYTES +
                              InterstellarWar.size(),
                          1U));
    ASSERT_EQ(&user_transfer_referent, chain.head->base.user_transfer_reference);

    // SECOND FRAME -- contains the last three bytes of the CRC.
    std::cout << hexdump::hexdump(chain.tail->base.datagram_payload.data, chain.tail->base.datagram_payload.size)
              << "\n\n";
    ASSERT_EQ(223574680, chain.tail->base.deadline_usec);
    ASSERT_EQ(55, chain.tail->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.tail->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.tail->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + 3U, chain.tail->base.datagram_payload.size);
    ASSERT_EQ(0,
              std::memcmp(makeHeader(meta, 1, true).data(), chain.tail->base.datagram_payload.data, HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data() + 1U,
                          static_cast<byte_t*>(chain.tail->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          3U));
    ASSERT_EQ(&user_transfer_referent, chain.tail->base.user_transfer_reference);
}

TEST(TxPrivate, MakeChainCRCSpillFull)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const TransferMetadata meta{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    const auto mtu   = InterstellarWar.size();
    const auto chain = txMakeChain(&alloc,
                                   std::array<std::uint_least8_t, 8>{{11, 22, 33, 44, 55, 66, 77, 88}}.data(),
                                   mtu,
                                   223574680,
                                   meta,
                                   UdpardUDPIPEndpoint{.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                                   UdpardConstPayload{.size = InterstellarWar.size(), .data = InterstellarWar.data()},
                                   &user_transfer_referent);
    ASSERT_EQ(2, alloc.getNumAllocatedFragments());
    ASSERT_EQ(2 * (sizeof(TxItem) + HEADER_SIZE_BYTES) + InterstellarWar.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(2, chain.count);
    ASSERT_NE(chain.head, chain.tail);
    ASSERT_EQ(chain.tail, reinterpret_cast<TxItem*>(chain.head->base.next_in_transfer));
    ASSERT_EQ(nullptr, chain.tail->base.next_in_transfer);

    // FIRST FRAME -- contains the payload only.
    std::cout << hexdump::hexdump(chain.head->base.datagram_payload.data, chain.head->base.datagram_payload.size)
              << "\n\n";
    ASSERT_EQ(223574680, chain.head->base.deadline_usec);
    ASSERT_EQ(55, chain.head->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.head->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.head->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + mtu, chain.head->base.datagram_payload.size);
    ASSERT_EQ(HEADER_SIZE_BYTES + InterstellarWar.size(), chain.head->base.datagram_payload.size);
    ASSERT_EQ(0,
              std::memcmp(makeHeader(meta, 0, false).data(),
                          chain.head->base.datagram_payload.data,
                          HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWar.data(),
                          static_cast<byte_t*>(chain.head->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          InterstellarWar.size()));
    ASSERT_EQ(&user_transfer_referent, chain.head->base.user_transfer_reference);

    // SECOND FRAME -- contains the last byte of the CRC.
    std::cout << hexdump::hexdump(chain.tail->base.datagram_payload.data, chain.tail->base.datagram_payload.size)
              << "\n\n";
    ASSERT_EQ(223574680, chain.tail->base.deadline_usec);
    ASSERT_EQ(55, chain.tail->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.tail->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.tail->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + 4U, chain.tail->base.datagram_payload.size);
    ASSERT_EQ(0,
              std::memcmp(makeHeader(meta, 1, true).data(), chain.tail->base.datagram_payload.data, HEADER_SIZE_BYTES));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data(),
                          static_cast<byte_t*>(chain.tail->base.datagram_payload.data) + HEADER_SIZE_BYTES,
                          4U));
    ASSERT_EQ(&user_transfer_referent, chain.tail->base.user_transfer_reference);
}

TEST(TxPrivate, PushPeekPopFree)
{
    helpers::TestAllocator allocator;
    const UdpardNodeID     node_id = 1234;
    //
    UdpardTx tx{
        .local_node_id           = &node_id,
        .queue_capacity          = 3,
        .mtu                     = (EtherealStrength.size() + 4U + 3U) / 3U,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = &allocator,
        .queue_size              = 0,
        .root                    = nullptr,
    };
    const TransferMetadata meta{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    std::monostate user_transfer_referent;
    ASSERT_EQ(3,
              txPush(&tx,
                     1234567890U,
                     meta,
                     {.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                     {.size = EtherealStrength.size(), .data = EtherealStrength.data()},
                     &user_transfer_referent));
    ASSERT_EQ(3, allocator.getNumAllocatedFragments());
    ASSERT_EQ(3 * (sizeof(TxItem) + HEADER_SIZE_BYTES) + EtherealStrength.size() + 4U,
              allocator.getTotalAllocatedAmount());
    ASSERT_EQ(3, tx.queue_size);

    const auto* frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    std::cout << hexdump::hexdump(frame->base.datagram_payload.data, frame->base.datagram_payload.size) << "\n\n";
    ASSERT_NE(nullptr, frame);
    ASSERT_NE(nullptr, frame->base.next_in_transfer);
    ASSERT_EQ(1234567890U, frame->base.deadline_usec);
    ASSERT_EQ(4, frame->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, frame->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, frame->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + tx.mtu, frame->base.datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, false).data(), frame->base.datagram_payload.data, HEADER_SIZE_BYTES));
    udpardTxFree(tx.memory, udpardTxPop(&tx, &frame->base));

    ASSERT_EQ(2, allocator.getNumAllocatedFragments());
    ASSERT_EQ(2, tx.queue_size);

    frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    std::cout << hexdump::hexdump(frame->base.datagram_payload.data, frame->base.datagram_payload.size) << "\n\n";
    ASSERT_NE(nullptr, frame);
    ASSERT_NE(nullptr, frame->base.next_in_transfer);
    ASSERT_EQ(1234567890U, frame->base.deadline_usec);
    ASSERT_EQ(4, frame->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, frame->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, frame->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + tx.mtu, frame->base.datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 1, false).data(), frame->base.datagram_payload.data, HEADER_SIZE_BYTES));
    udpardTxFree(tx.memory, udpardTxPop(&tx, &frame->base));

    ASSERT_EQ(1, allocator.getNumAllocatedFragments());
    ASSERT_EQ(1, tx.queue_size);

    frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    std::cout << hexdump::hexdump(frame->base.datagram_payload.data, frame->base.datagram_payload.size) << "\n\n";
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(nullptr, frame->base.next_in_transfer);
    ASSERT_EQ(1234567890U, frame->base.deadline_usec);
    ASSERT_EQ(4, frame->base.dscp);
    ASSERT_EQ(0xBABA'DEDAU, frame->base.destination.ip_address);
    ASSERT_EQ(0xD0ED, frame->base.destination.udp_port);
    ASSERT_EQ(HEADER_SIZE_BYTES + EtherealStrength.size() - 2 * tx.mtu + 4U, frame->base.datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 2, true).data(), frame->base.datagram_payload.data, HEADER_SIZE_BYTES));
    udpardTxFree(tx.memory, udpardTxPop(&tx, &frame->base));

    ASSERT_EQ(0, allocator.getNumAllocatedFragments());
    ASSERT_EQ(0, tx.queue_size);
    ASSERT_EQ(nullptr, udpardTxPeek(&tx));
}

TEST(TxPrivate, PushPrioritization)
{
    helpers::TestAllocator allocator;
    const UdpardNodeID     node_id = 1234;
    //
    UdpardTx tx{
        .local_node_id           = &node_id,
        .queue_capacity          = 7,
        .mtu                     = 140,  // This is chosen to match the test data.
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = &allocator,
        .queue_size              = 0,
        .root                    = nullptr,
    };
    // A -- Push the first multi-frame transfer at nominal priority level.
    const TransferMetadata meta_a{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 100,
        .dst_node_id    = UDPARD_NODE_ID_UNSET,
        .data_specifier = 200,
        .transfer_id    = 5'000,
    };
    ASSERT_EQ(3,
              txPush(&tx,
                     0,
                     meta_a,
                     {.ip_address = 0xAAAA'AAAA, .udp_port = 0xAAAA},
                     {.size = EtherealStrength.size(), .data = EtherealStrength.data()},
                     nullptr));
    ASSERT_EQ(3, allocator.getNumAllocatedFragments());
    ASSERT_EQ(3, tx.queue_size);
    const auto* frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(0xAAAA'AAAA, frame->base.destination.ip_address);

    // B -- Next, push a higher-priority transfer and ensure it takes precedence.
    ASSERT_EQ(1,
              txPush(&tx,
                     0,
                     {
                         .priority       = UdpardPriorityHigh,
                         .src_node_id    = 100,
                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                         .data_specifier = 200,
                         .transfer_id    = 100'000,
                     },
                     {.ip_address = 0xBBBB'BBBB, .udp_port = 0xBBBB},
                     {.size = DetailOfTheCosmos.size(), .data = DetailOfTheCosmos.data()},
                     nullptr));
    ASSERT_EQ(4, allocator.getNumAllocatedFragments());
    ASSERT_EQ(4, tx.queue_size);
    frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(0xBBBB'BBBB, frame->base.destination.ip_address);

    // C -- Next, push a lower-priority transfer and ensure it goes towards the back.
    ASSERT_EQ(1,
              txPush(&tx,
                     1002,
                     {
                         .priority       = UdpardPriorityLow,
                         .src_node_id    = 100,
                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                         .data_specifier = 200,
                         .transfer_id    = 10'000,
                     },
                     {.ip_address = 0xCCCC'CCCC, .udp_port = 0xCCCC},
                     {.size = InterstellarWar.size(), .data = InterstellarWar.data()},
                     nullptr));
    ASSERT_EQ(5, allocator.getNumAllocatedFragments());
    ASSERT_EQ(5, tx.queue_size);
    frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(0xBBBB'BBBB, frame->base.destination.ip_address);

    // D -- Add another transfer like the previous one and ensure it goes in the back.
    ASSERT_EQ(1,
              txPush(&tx,
                     1003,
                     {
                         .priority       = UdpardPriorityLow,
                         .src_node_id    = 100,
                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                         .data_specifier = 200,
                         .transfer_id    = 10'001,
                     },
                     {.ip_address = 0xDDDD'DDDD, .udp_port = 0xDDDD},
                     {.size = InterstellarWar.size(), .data = InterstellarWar.data()},
                     nullptr));
    ASSERT_EQ(6, allocator.getNumAllocatedFragments());
    ASSERT_EQ(6, tx.queue_size);
    frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(0xBBBB'BBBB, frame->base.destination.ip_address);

    // E -- Add an even higher priority transfer.
    ASSERT_EQ(1,
              txPush(&tx,
                     1003,
                     {
                         .priority       = UdpardPriorityFast,
                         .src_node_id    = 100,
                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                         .data_specifier = 200,
                         .transfer_id    = 1'000,
                     },
                     {.ip_address = 0xEEEE'EEEE, .udp_port = 0xEEEE},
                     {.size = InterstellarWar.size(), .data = InterstellarWar.data()},
                     nullptr));
    ASSERT_EQ(7, allocator.getNumAllocatedFragments());
    ASSERT_EQ(7, tx.queue_size);
    frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(0xEEEE'EEEE, frame->base.destination.ip_address);

    // Now, unwind the queue and ensure the frames are popped in the right order.
    // E
    udpardTxFree(tx.memory, udpardTxPop(&tx, &frame->base));
    ASSERT_EQ(6, allocator.getNumAllocatedFragments());
    ASSERT_EQ(6, tx.queue_size);
    // B
    frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(0xBBBB'BBBB, frame->base.destination.ip_address);
    udpardTxFree(tx.memory, udpardTxPop(&tx, &frame->base));
    ASSERT_EQ(5, allocator.getNumAllocatedFragments());
    ASSERT_EQ(5, tx.queue_size);
    // A1, three frames.
    frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(0xAAAA'AAAA, frame->base.destination.ip_address);
    ASSERT_EQ(0,
              std::memcmp(makeHeader(meta_a, 0, false).data(), frame->base.datagram_payload.data, HEADER_SIZE_BYTES));
    udpardTxFree(tx.memory, udpardTxPop(&tx, &frame->base));
    ASSERT_EQ(4, allocator.getNumAllocatedFragments());
    ASSERT_EQ(4, tx.queue_size);
    // A2
    frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(0xAAAA'AAAA, frame->base.destination.ip_address);
    ASSERT_EQ(0,
              std::memcmp(makeHeader(meta_a, 1, false).data(), frame->base.datagram_payload.data, HEADER_SIZE_BYTES));
    udpardTxFree(tx.memory, udpardTxPop(&tx, &frame->base));
    ASSERT_EQ(3, allocator.getNumAllocatedFragments());
    ASSERT_EQ(3, tx.queue_size);
    // A3
    frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(0xAAAA'AAAA, frame->base.destination.ip_address);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta_a, 2, true).data(), frame->base.datagram_payload.data, HEADER_SIZE_BYTES));
    udpardTxFree(tx.memory, udpardTxPop(&tx, &frame->base));
    ASSERT_EQ(2, allocator.getNumAllocatedFragments());
    ASSERT_EQ(2, tx.queue_size);
    // C
    frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(0xCCCC'CCCC, frame->base.destination.ip_address);
    udpardTxFree(tx.memory, udpardTxPop(&tx, &frame->base));
    ASSERT_EQ(1, allocator.getNumAllocatedFragments());
    ASSERT_EQ(1, tx.queue_size);
    // D
    frame = reinterpret_cast<const TxItem*>(udpardTxPeek(&tx));
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(0xDDDD'DDDD, frame->base.destination.ip_address);
    udpardTxFree(tx.memory, udpardTxPop(&tx, &frame->base));
    ASSERT_EQ(0, allocator.getNumAllocatedFragments());
    ASSERT_EQ(0, tx.queue_size);

    ASSERT_EQ(nullptr, udpardTxPeek(&tx));
}

TEST(TxPrivate, PushCapacityLimit)
{
    helpers::TestAllocator allocator;
    const UdpardNodeID     node_id = 1234;
    //
    UdpardTx tx{
        .local_node_id           = &node_id,
        .queue_capacity          = 2,
        .mtu                     = 10U,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = &allocator,
        .queue_size              = 0,
        .root                    = nullptr,
    };
    const TransferMetadata meta{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    ASSERT_EQ(-UDPARD_ERROR_CAPACITY,
              txPush(&tx,
                     1234567890U,
                     meta,
                     {.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                     {.size = EtherealStrength.size(), .data = EtherealStrength.data()},
                     nullptr));
    ASSERT_EQ(0, allocator.getNumAllocatedFragments());
    ASSERT_EQ(0, allocator.getTotalAllocatedAmount());
    ASSERT_EQ(0, tx.queue_size);
}

TEST(TxPrivate, PushOOM)
{
    helpers::TestAllocator allocator;
    const UdpardNodeID     node_id = 1234;
    //
    UdpardTx tx{
        .local_node_id           = &node_id,
        .queue_capacity          = 10'000U,
        .mtu                     = (EtherealStrength.size() + 4U + 3U) / 3U,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = &allocator,
        .queue_size              = 0,
        .root                    = nullptr,
    };
    const TransferMetadata meta{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    allocator.setAllocationCeiling(EtherealStrength.size());  // No memory for the overheads.
    ASSERT_EQ(-UDPARD_ERROR_MEMORY,
              txPush(&tx,
                     1234567890U,
                     meta,
                     {.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                     {.size = EtherealStrength.size(), .data = EtherealStrength.data()},
                     nullptr));
    ASSERT_EQ(0, allocator.getNumAllocatedFragments());
    ASSERT_EQ(0, allocator.getTotalAllocatedAmount());
    ASSERT_EQ(0, tx.queue_size);
}

TEST(TxPrivate, PushAnonymousMultiFrame)
{
    helpers::TestAllocator allocator;
    const UdpardNodeID     node_id = 0xFFFFU;
    //
    UdpardTx tx{
        .local_node_id           = &node_id,
        .queue_capacity          = 10'000U,
        .mtu                     = (EtherealStrength.size() + 4U + 3U) / 3U,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = &allocator,
        .queue_size              = 0,
        .root                    = nullptr,
    };
    const TransferMetadata meta{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    ASSERT_EQ(-UDPARD_ERROR_ANONYMOUS,
              txPush(&tx,
                     1234567890U,
                     meta,
                     {.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                     {.size = EtherealStrength.size(), .data = EtherealStrength.data()},
                     nullptr));
    ASSERT_EQ(0, allocator.getNumAllocatedFragments());
    ASSERT_EQ(0, allocator.getTotalAllocatedAmount());
    ASSERT_EQ(0, tx.queue_size);
}

TEST(TxPrivate, PushAnonymousService)
{
    helpers::TestAllocator allocator;
    const UdpardNodeID     node_id = 0xFFFFU;
    //
    UdpardTx tx{
        .local_node_id           = &node_id,
        .queue_capacity          = 10'000,
        .mtu                     = 1500,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = &allocator,
        .queue_size              = 0,
        .root                    = nullptr,
    };
    const TransferMetadata meta{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 0x8099U,  // Service response.
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    ASSERT_EQ(-UDPARD_ERROR_ANONYMOUS,
              txPush(&tx,
                     1234567890U,
                     meta,
                     {.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                     {.size = EtherealStrength.size(), .data = EtherealStrength.data()},
                     nullptr));
    ASSERT_EQ(0, allocator.getNumAllocatedFragments());
    ASSERT_EQ(0, allocator.getTotalAllocatedAmount());
    ASSERT_EQ(0, tx.queue_size);
}
