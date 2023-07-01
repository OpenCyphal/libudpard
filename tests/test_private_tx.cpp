/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include "exposed.hpp"
#include "helpers.hpp"
#include "hexdump.hpp"
#include <gtest/gtest.h>
#include <span>

namespace
{
using exposed::HeaderSize;
using exposed::Metadata;
using exposed::TxItem;
using exposed::txSerializeHeader;
using exposed::txMakeChain;
using exposed::txPush;

// >>> from pycyphal.transport.commons.crc import CRC32C
// >>> data = b"For us, the dark forest state is all-important, but it's just a detail of the cosmos."
// >>> list(CRC32C.new(data).value_as_bytes)
constexpr std::string_view DetailOfTheCosmos =
    "For us, the dark forest state is all-important, but it's just a detail of the cosmos.";
constexpr std::array<std::uint8_t, 4> DetailOfTheCosmosCRC{{125, 113, 207, 171}};

constexpr std::string_view GrandScheme =
    "If you think of the cosmos as a great battlefield, dark forest strikes are nothing more than snipers shooting at "
    "the careless---messengers, mess men, etc. In the grand scheme of the battle, they are nothing.";
constexpr std::array<std::uint8_t, 4> GrandSchemeCRC{{119, 220, 185, 219}};

constexpr std::string_view            InterstellarWar = "You have not seen what a true interstellar war is like.";
constexpr std::array<std::uint8_t, 4> InterstellarWarCRC{{102, 217, 109, 188}};

constexpr std::string_view EtherealStrength =
    "All was silent except for the howl of the wind against the antenna. Ye watched as the remaining birds in the "
    "flock gradually settled back into the forest. She stared at the antenna and thought it looked like an enormous "
    "hand stretched open toward the sky, possessing an ethereal strength.";

auto makeHeader(const Metadata meta, const std::uint32_t frame_index, const bool end_of_transfer)
{
    std::array<exposed::byte_t, HeaderSize> buffer{};
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
    using HeaderBuffer = std::array<exposed::byte_t, HeaderSize>;
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
    const Metadata         meta{
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
    ASSERT_EQ(sizeof(TxItem) + HeaderSize + 4, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(1, chain.count);
    std::cout << hexdump::hexdump(chain.head->datagram_payload.data, chain.head->datagram_payload.size) << "\n\n";
    ASSERT_EQ(chain.head, chain.tail);
    ASSERT_EQ(nullptr, chain.head->next_in_transfer);
    ASSERT_EQ(1234567890, chain.head->deadline_usec);
    ASSERT_EQ(33, chain.head->dscp);
    ASSERT_EQ(0x0A0B'0C0DU, chain.head->destination.ip_address);
    ASSERT_EQ(0x1234, chain.head->destination.udp_port);
    ASSERT_EQ(HeaderSize + 4, chain.head->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, true).data(), chain.head->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp("\x00\x00\x00\x00",  // CRC of the empty transfer.
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize,
                          4));
    ASSERT_EQ(&user_transfer_referent, chain.head->user_transfer_reference);
}

TEST(TxPrivate, MakeChainSingleMaxMTU)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const Metadata         meta{
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
    ASSERT_EQ(sizeof(TxItem) + HeaderSize + DetailOfTheCosmos.size() + DetailOfTheCosmosCRC.size(),
              alloc.getTotalAllocatedAmount());
    ASSERT_EQ(1, chain.count);
    std::cout << hexdump::hexdump(chain.head->datagram_payload.data, chain.head->datagram_payload.size) << "\n\n";
    ASSERT_EQ(chain.head, chain.tail);
    ASSERT_EQ(nullptr, chain.head->next_in_transfer);
    ASSERT_EQ(1234567890, chain.head->deadline_usec);
    ASSERT_EQ(77, chain.head->dscp);
    ASSERT_EQ(0x0A0B'0C00U, chain.head->destination.ip_address);
    ASSERT_EQ(7474, chain.head->destination.udp_port);
    ASSERT_EQ(HeaderSize + DetailOfTheCosmos.size() + DetailOfTheCosmosCRC.size(), chain.head->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, true).data(), chain.head->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(DetailOfTheCosmos.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize,
                          DetailOfTheCosmos.size()));
    ASSERT_EQ(0,
              std::memcmp(DetailOfTheCosmosCRC.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize +
                              DetailOfTheCosmos.size(),
                          DetailOfTheCosmosCRC.size()));
    ASSERT_EQ(&user_transfer_referent, chain.head->user_transfer_reference);
}

TEST(TxPrivate, MakeChainThreeFrames)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const Metadata         meta{
                .priority       = UdpardPriorityNominal,
                .src_node_id    = 4321,
                .dst_node_id    = 5432,
                .data_specifier = 7766,
                .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    const auto mtu   = (GrandScheme.size() + 4U + 3U) / 3U;  // Force payload split into three frames.
    const auto chain = txMakeChain(&alloc,
                                   std::array<std::uint_least8_t, 8>{{11, 22, 33, 44, 55, 66, 77, 88}}.data(),
                                   mtu,
                                   223574680,
                                   meta,
                                   UdpardUDPIPEndpoint{.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                                   UdpardConstPayload{.size = GrandScheme.size(), .data = GrandScheme.data()},
                                   &user_transfer_referent);
    ASSERT_EQ(3, alloc.getNumAllocatedFragments());
    ASSERT_EQ(3 * (sizeof(TxItem) + HeaderSize) + GrandScheme.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(3, chain.count);
    const auto* const first = chain.head;
    ASSERT_NE(nullptr, first);
    const auto* const second = first->next_in_transfer;
    ASSERT_NE(nullptr, second);
    const auto* const third = second->next_in_transfer;
    ASSERT_NE(nullptr, third);
    ASSERT_EQ(nullptr, third->next_in_transfer);
    ASSERT_EQ(chain.tail, third);

    // FIRST FRAME -- contains the first part of the payload.
    std::cout << hexdump::hexdump(first->datagram_payload.data, first->datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, first->deadline_usec);
    ASSERT_EQ(55, first->dscp);
    ASSERT_EQ(0xBABA'DEDAU, first->destination.ip_address);
    ASSERT_EQ(0xD0ED, first->destination.udp_port);
    ASSERT_EQ(HeaderSize + mtu, first->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, false).data(), first->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(GrandScheme.data(),
                          static_cast<exposed::byte_t*>(first->datagram_payload.data) + HeaderSize,
                          mtu));
    ASSERT_EQ(&user_transfer_referent, first->user_transfer_reference);

    // SECOND FRAME -- contains the second part of the payload.
    std::cout << hexdump::hexdump(second->datagram_payload.data, second->datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, second->deadline_usec);
    ASSERT_EQ(55, second->dscp);
    ASSERT_EQ(0xBABA'DEDAU, second->destination.ip_address);
    ASSERT_EQ(0xD0ED, second->destination.udp_port);
    ASSERT_EQ(HeaderSize + mtu, second->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 1, false).data(), second->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(GrandScheme.data() + mtu,
                          static_cast<exposed::byte_t*>(second->datagram_payload.data) + HeaderSize,
                          mtu));
    ASSERT_EQ(&user_transfer_referent, second->user_transfer_reference);

    // THIRD FRAME -- contains the third part of the payload and the CRC at the end.
    std::cout << hexdump::hexdump(third->datagram_payload.data, third->datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, third->deadline_usec);
    ASSERT_EQ(55, third->dscp);
    ASSERT_EQ(0xBABA'DEDAU, third->destination.ip_address);
    ASSERT_EQ(0xD0ED, third->destination.udp_port);
    const auto third_payload_size = GrandScheme.size() - 2 * mtu;
    ASSERT_EQ(HeaderSize + third_payload_size + 4U, third->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 2, true).data(), third->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(GrandScheme.data() + 2 * mtu,
                          static_cast<exposed::byte_t*>(third->datagram_payload.data) + HeaderSize,
                          third_payload_size));
    ASSERT_EQ(0,
              std::memcmp(GrandSchemeCRC.data(),
                          static_cast<exposed::byte_t*>(third->datagram_payload.data) + HeaderSize + third_payload_size,
                          GrandSchemeCRC.size()));
    ASSERT_EQ(&user_transfer_referent, third->user_transfer_reference);
}

TEST(TxPrivate, MakeChainCRCSpill1)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const Metadata         meta{
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
    ASSERT_EQ(2 * (sizeof(TxItem) + HeaderSize) + InterstellarWar.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(2, chain.count);
    ASSERT_NE(chain.head, chain.tail);
    ASSERT_EQ(chain.tail, chain.head->next_in_transfer);
    ASSERT_EQ(nullptr, chain.tail->next_in_transfer);

    // FIRST FRAME -- contains the payload and the first three bytes of the CRC.
    std::cout << hexdump::hexdump(chain.head->datagram_payload.data, chain.head->datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, chain.head->deadline_usec);
    ASSERT_EQ(55, chain.head->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.head->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.head->destination.udp_port);
    ASSERT_EQ(HeaderSize + mtu, chain.head->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, false).data(), chain.head->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWar.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize,
                          InterstellarWar.size()));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize +
                              InterstellarWar.size(),
                          3U));
    ASSERT_EQ(&user_transfer_referent, chain.head->user_transfer_reference);

    // SECOND FRAME -- contains the last byte of the CRC.
    std::cout << hexdump::hexdump(chain.tail->datagram_payload.data, chain.tail->datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, chain.tail->deadline_usec);
    ASSERT_EQ(55, chain.tail->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.tail->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.tail->destination.udp_port);
    ASSERT_EQ(HeaderSize + 1U, chain.tail->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 1, true).data(), chain.tail->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data() + 3U,
                          static_cast<exposed::byte_t*>(chain.tail->datagram_payload.data) + HeaderSize,
                          1U));
    ASSERT_EQ(&user_transfer_referent, chain.tail->user_transfer_reference);
}

TEST(TxPrivate, MakeChainCRCSpill2)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const Metadata         meta{
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
    ASSERT_EQ(2 * (sizeof(TxItem) + HeaderSize) + InterstellarWar.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(2, chain.count);
    ASSERT_NE(chain.head, chain.tail);
    ASSERT_EQ(chain.tail, chain.head->next_in_transfer);
    ASSERT_EQ(nullptr, chain.tail->next_in_transfer);

    // FIRST FRAME -- contains the payload and the first two bytes of the CRC.
    std::cout << hexdump::hexdump(chain.head->datagram_payload.data, chain.head->datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, chain.head->deadline_usec);
    ASSERT_EQ(55, chain.head->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.head->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.head->destination.udp_port);
    ASSERT_EQ(HeaderSize + mtu, chain.head->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, false).data(), chain.head->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWar.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize,
                          InterstellarWar.size()));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize +
                              InterstellarWar.size(),
                          2U));
    ASSERT_EQ(&user_transfer_referent, chain.head->user_transfer_reference);

    // SECOND FRAME -- contains the last two bytes of the CRC.
    std::cout << hexdump::hexdump(chain.tail->datagram_payload.data, chain.tail->datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, chain.tail->deadline_usec);
    ASSERT_EQ(55, chain.tail->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.tail->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.tail->destination.udp_port);
    ASSERT_EQ(HeaderSize + 2U, chain.tail->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 1, true).data(), chain.tail->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data() + 2U,
                          static_cast<exposed::byte_t*>(chain.tail->datagram_payload.data) + HeaderSize,
                          2U));
    ASSERT_EQ(&user_transfer_referent, chain.tail->user_transfer_reference);
}

TEST(TxPrivate, MakeChainCRCSpill3)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const Metadata         meta{
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
    ASSERT_EQ(2 * (sizeof(TxItem) + HeaderSize) + InterstellarWar.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(2, chain.count);
    ASSERT_NE(chain.head, chain.tail);
    ASSERT_EQ(chain.tail, chain.head->next_in_transfer);
    ASSERT_EQ(nullptr, chain.tail->next_in_transfer);

    // FIRST FRAME -- contains the payload and the first byte of the CRC.
    std::cout << hexdump::hexdump(chain.head->datagram_payload.data, chain.head->datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, chain.head->deadline_usec);
    ASSERT_EQ(55, chain.head->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.head->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.head->destination.udp_port);
    ASSERT_EQ(HeaderSize + mtu, chain.head->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, false).data(), chain.head->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWar.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize,
                          InterstellarWar.size()));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize +
                              InterstellarWar.size(),
                          1U));
    ASSERT_EQ(&user_transfer_referent, chain.head->user_transfer_reference);

    // SECOND FRAME -- contains the last three bytes of the CRC.
    std::cout << hexdump::hexdump(chain.tail->datagram_payload.data, chain.tail->datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, chain.tail->deadline_usec);
    ASSERT_EQ(55, chain.tail->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.tail->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.tail->destination.udp_port);
    ASSERT_EQ(HeaderSize + 3U, chain.tail->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 1, true).data(), chain.tail->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data() + 1U,
                          static_cast<exposed::byte_t*>(chain.tail->datagram_payload.data) + HeaderSize,
                          3U));
    ASSERT_EQ(&user_transfer_referent, chain.tail->user_transfer_reference);
}

TEST(TxPrivate, MakeChainCRCSpillFull)
{
    helpers::TestAllocator alloc;
    std::monostate         user_transfer_referent;
    const Metadata         meta{
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
    ASSERT_EQ(2 * (sizeof(TxItem) + HeaderSize) + InterstellarWar.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(2, chain.count);
    ASSERT_NE(chain.head, chain.tail);
    ASSERT_EQ(chain.tail, chain.head->next_in_transfer);
    ASSERT_EQ(nullptr, chain.tail->next_in_transfer);

    // FIRST FRAME -- contains the payload only.
    std::cout << hexdump::hexdump(chain.head->datagram_payload.data, chain.head->datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, chain.head->deadline_usec);
    ASSERT_EQ(55, chain.head->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.head->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.head->destination.udp_port);
    ASSERT_EQ(HeaderSize + mtu, chain.head->datagram_payload.size);
    ASSERT_EQ(HeaderSize + InterstellarWar.size(), chain.head->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, false).data(), chain.head->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWar.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize,
                          InterstellarWar.size()));
    ASSERT_EQ(&user_transfer_referent, chain.head->user_transfer_reference);

    // SECOND FRAME -- contains the last byte of the CRC.
    std::cout << hexdump::hexdump(chain.tail->datagram_payload.data, chain.tail->datagram_payload.size) << "\n\n";
    ASSERT_EQ(223574680, chain.tail->deadline_usec);
    ASSERT_EQ(55, chain.tail->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.tail->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.tail->destination.udp_port);
    ASSERT_EQ(HeaderSize + 4U, chain.tail->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 1, true).data(), chain.tail->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(InterstellarWarCRC.data(),
                          static_cast<exposed::byte_t*>(chain.tail->datagram_payload.data) + HeaderSize,
                          4U));
    ASSERT_EQ(&user_transfer_referent, chain.tail->user_transfer_reference);
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
    const Metadata meta{
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
    ASSERT_EQ(3 * (sizeof(TxItem) + HeaderSize) + EtherealStrength.size() + 4U, allocator.getTotalAllocatedAmount());
    ASSERT_EQ(3, tx.queue_size);

    const auto* frame = udpardTxPeek(&tx);
    std::cout << hexdump::hexdump(frame->datagram_payload.data, frame->datagram_payload.size) << "\n\n";
    ASSERT_NE(nullptr, frame);
    ASSERT_NE(nullptr, frame->next_in_transfer);
    ASSERT_EQ(1234567890U, frame->deadline_usec);
    ASSERT_EQ(4, frame->dscp);
    ASSERT_EQ(0xBABA'DEDAU, frame->destination.ip_address);
    ASSERT_EQ(0xD0ED, frame->destination.udp_port);
    ASSERT_EQ(HeaderSize + tx.mtu, frame->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, false).data(), frame->datagram_payload.data, HeaderSize));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));

    ASSERT_EQ(2, allocator.getNumAllocatedFragments());
    ASSERT_EQ(2, tx.queue_size);

    frame = udpardTxPeek(&tx);
    std::cout << hexdump::hexdump(frame->datagram_payload.data, frame->datagram_payload.size) << "\n\n";
    ASSERT_NE(nullptr, frame);
    ASSERT_NE(nullptr, frame->next_in_transfer);
    ASSERT_EQ(1234567890U, frame->deadline_usec);
    ASSERT_EQ(4, frame->dscp);
    ASSERT_EQ(0xBABA'DEDAU, frame->destination.ip_address);
    ASSERT_EQ(0xD0ED, frame->destination.udp_port);
    ASSERT_EQ(HeaderSize + tx.mtu, frame->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 1, false).data(), frame->datagram_payload.data, HeaderSize));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));

    ASSERT_EQ(1, allocator.getNumAllocatedFragments());
    ASSERT_EQ(1, tx.queue_size);

    frame = udpardTxPeek(&tx);
    std::cout << hexdump::hexdump(frame->datagram_payload.data, frame->datagram_payload.size) << "\n\n";
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(nullptr, frame->next_in_transfer);
    ASSERT_EQ(1234567890U, frame->deadline_usec);
    ASSERT_EQ(4, frame->dscp);
    ASSERT_EQ(0xBABA'DEDAU, frame->destination.ip_address);
    ASSERT_EQ(0xD0ED, frame->destination.udp_port);
    ASSERT_EQ(HeaderSize + EtherealStrength.size() - 2 * tx.mtu + 4U, frame->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 2, true).data(), frame->datagram_payload.data, HeaderSize));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));

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
    const Metadata meta{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    ASSERT_EQ(-UDPARD_ERROR_CAPACITY_LIMIT,
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
    const Metadata meta{
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123'4567'89AB'CDEFULL,
    };
    allocator.setAllocationCeiling(EtherealStrength.size());  // No memory for the overheads.
    ASSERT_EQ(-UDPARD_ERROR_OUT_OF_MEMORY,
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
