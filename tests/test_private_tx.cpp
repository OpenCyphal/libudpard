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
using exposed::Metadata;
using exposed::TxItem;
using exposed::txMakeChain;
using exposed::HeaderSize;
using exposed::txSerializeHeader;

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
    std::cout << hexdump::hexdump(chain.head->datagram_payload.data, chain.head->datagram_payload.size) << std::endl;
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
    std::cout << hexdump::hexdump(chain.head->datagram_payload.data, chain.head->datagram_payload.size) << std::endl;
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
    const auto mtu   = GrandScheme.size() + 3U;
    const auto chain = txMakeChain(&alloc,
                                   std::array<std::uint_least8_t, 8>{{11, 22, 33, 44, 55, 66, 77, 88}}.data(),
                                   mtu,
                                   223574680,
                                   meta,
                                   UdpardUDPIPEndpoint{.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                                   UdpardConstPayload{.size = GrandScheme.size(), .data = GrandScheme.data()},
                                   &user_transfer_referent);
    ASSERT_EQ(2, alloc.getNumAllocatedFragments());
    ASSERT_EQ(2 * (sizeof(TxItem) + HeaderSize) + GrandScheme.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(2, chain.count);
    ASSERT_NE(chain.head, chain.tail);
    ASSERT_EQ(chain.tail, chain.head->next_in_transfer);
    ASSERT_EQ(nullptr, chain.tail->next_in_transfer);

    // FIRST FRAME -- contains the payload and the first three bytes of the CRC.
    std::cout << hexdump::hexdump(chain.head->datagram_payload.data, chain.head->datagram_payload.size) << std::endl;
    ASSERT_EQ(223574680, chain.head->deadline_usec);
    ASSERT_EQ(55, chain.head->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.head->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.head->destination.udp_port);
    ASSERT_EQ(HeaderSize + mtu, chain.head->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, false).data(), chain.head->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(GrandScheme.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize,
                          GrandScheme.size()));
    ASSERT_EQ(0,
              std::memcmp(GrandSchemeCRC.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize +
                              GrandScheme.size(),
                          3U));
    ASSERT_EQ(&user_transfer_referent, chain.head->user_transfer_reference);

    // SECOND FRAME -- contains the last byte of the CRC.
    std::cout << hexdump::hexdump(chain.tail->datagram_payload.data, chain.tail->datagram_payload.size) << std::endl;
    ASSERT_EQ(223574680, chain.tail->deadline_usec);
    ASSERT_EQ(55, chain.tail->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.tail->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.tail->destination.udp_port);
    ASSERT_EQ(HeaderSize + 1U, chain.tail->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 1, true).data(), chain.tail->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(GrandSchemeCRC.data() + 3U,
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
    const auto mtu   = GrandScheme.size() + 2U;
    const auto chain = txMakeChain(&alloc,
                                   std::array<std::uint_least8_t, 8>{{11, 22, 33, 44, 55, 66, 77, 88}}.data(),
                                   mtu,
                                   223574680,
                                   meta,
                                   UdpardUDPIPEndpoint{.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                                   UdpardConstPayload{.size = GrandScheme.size(), .data = GrandScheme.data()},
                                   &user_transfer_referent);
    ASSERT_EQ(2, alloc.getNumAllocatedFragments());
    ASSERT_EQ(2 * (sizeof(TxItem) + HeaderSize) + GrandScheme.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(2, chain.count);
    ASSERT_NE(chain.head, chain.tail);
    ASSERT_EQ(chain.tail, chain.head->next_in_transfer);
    ASSERT_EQ(nullptr, chain.tail->next_in_transfer);

    // FIRST FRAME -- contains the payload and the first two bytes of the CRC.
    std::cout << hexdump::hexdump(chain.head->datagram_payload.data, chain.head->datagram_payload.size) << std::endl;
    ASSERT_EQ(223574680, chain.head->deadline_usec);
    ASSERT_EQ(55, chain.head->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.head->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.head->destination.udp_port);
    ASSERT_EQ(HeaderSize + mtu, chain.head->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, false).data(), chain.head->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(GrandScheme.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize,
                          GrandScheme.size()));
    ASSERT_EQ(0,
              std::memcmp(GrandSchemeCRC.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize +
                              GrandScheme.size(),
                          2U));
    ASSERT_EQ(&user_transfer_referent, chain.head->user_transfer_reference);

    // SECOND FRAME -- contains the last two bytes of the CRC.
    std::cout << hexdump::hexdump(chain.tail->datagram_payload.data, chain.tail->datagram_payload.size) << std::endl;
    ASSERT_EQ(223574680, chain.tail->deadline_usec);
    ASSERT_EQ(55, chain.tail->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.tail->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.tail->destination.udp_port);
    ASSERT_EQ(HeaderSize + 2U, chain.tail->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 1, true).data(), chain.tail->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(GrandSchemeCRC.data() + 2U,
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
    const auto mtu   = GrandScheme.size() + 1U;
    const auto chain = txMakeChain(&alloc,
                                   std::array<std::uint_least8_t, 8>{{11, 22, 33, 44, 55, 66, 77, 88}}.data(),
                                   mtu,
                                   223574680,
                                   meta,
                                   UdpardUDPIPEndpoint{.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                                   UdpardConstPayload{.size = GrandScheme.size(), .data = GrandScheme.data()},
                                   &user_transfer_referent);
    ASSERT_EQ(2, alloc.getNumAllocatedFragments());
    ASSERT_EQ(2 * (sizeof(TxItem) + HeaderSize) + GrandScheme.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(2, chain.count);
    ASSERT_NE(chain.head, chain.tail);
    ASSERT_EQ(chain.tail, chain.head->next_in_transfer);
    ASSERT_EQ(nullptr, chain.tail->next_in_transfer);

    // FIRST FRAME -- contains the payload and the first byte of the CRC.
    std::cout << hexdump::hexdump(chain.head->datagram_payload.data, chain.head->datagram_payload.size) << std::endl;
    ASSERT_EQ(223574680, chain.head->deadline_usec);
    ASSERT_EQ(55, chain.head->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.head->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.head->destination.udp_port);
    ASSERT_EQ(HeaderSize + mtu, chain.head->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, false).data(), chain.head->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(GrandScheme.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize,
                          GrandScheme.size()));
    ASSERT_EQ(0,
              std::memcmp(GrandSchemeCRC.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize +
                              GrandScheme.size(),
                          1U));
    ASSERT_EQ(&user_transfer_referent, chain.head->user_transfer_reference);

    // SECOND FRAME -- contains the last three bytes of the CRC.
    std::cout << hexdump::hexdump(chain.tail->datagram_payload.data, chain.tail->datagram_payload.size) << std::endl;
    ASSERT_EQ(223574680, chain.tail->deadline_usec);
    ASSERT_EQ(55, chain.tail->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.tail->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.tail->destination.udp_port);
    ASSERT_EQ(HeaderSize + 3U, chain.tail->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 1, true).data(), chain.tail->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(GrandSchemeCRC.data() + 1U,
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
    const auto mtu   = GrandScheme.size();
    const auto chain = txMakeChain(&alloc,
                                   std::array<std::uint_least8_t, 8>{{11, 22, 33, 44, 55, 66, 77, 88}}.data(),
                                   mtu,
                                   223574680,
                                   meta,
                                   UdpardUDPIPEndpoint{.ip_address = 0xBABA'DEDAU, .udp_port = 0xD0ED},
                                   UdpardConstPayload{.size = GrandScheme.size(), .data = GrandScheme.data()},
                                   &user_transfer_referent);
    ASSERT_EQ(2, alloc.getNumAllocatedFragments());
    ASSERT_EQ(2 * (sizeof(TxItem) + HeaderSize) + GrandScheme.size() + 4U, alloc.getTotalAllocatedAmount());
    ASSERT_EQ(2, chain.count);
    ASSERT_NE(chain.head, chain.tail);
    ASSERT_EQ(chain.tail, chain.head->next_in_transfer);
    ASSERT_EQ(nullptr, chain.tail->next_in_transfer);

    // FIRST FRAME -- contains the payload only.
    std::cout << hexdump::hexdump(chain.head->datagram_payload.data, chain.head->datagram_payload.size) << std::endl;
    ASSERT_EQ(223574680, chain.head->deadline_usec);
    ASSERT_EQ(55, chain.head->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.head->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.head->destination.udp_port);
    ASSERT_EQ(HeaderSize + mtu, chain.head->datagram_payload.size);
    ASSERT_EQ(HeaderSize + GrandScheme.size(), chain.head->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 0, false).data(), chain.head->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(GrandScheme.data(),
                          static_cast<exposed::byte_t*>(chain.head->datagram_payload.data) + HeaderSize,
                          GrandScheme.size()));
    ASSERT_EQ(&user_transfer_referent, chain.head->user_transfer_reference);

    // SECOND FRAME -- contains the last byte of the CRC.
    std::cout << hexdump::hexdump(chain.tail->datagram_payload.data, chain.tail->datagram_payload.size) << std::endl;
    ASSERT_EQ(223574680, chain.tail->deadline_usec);
    ASSERT_EQ(55, chain.tail->dscp);
    ASSERT_EQ(0xBABA'DEDAU, chain.tail->destination.ip_address);
    ASSERT_EQ(0xD0ED, chain.tail->destination.udp_port);
    ASSERT_EQ(HeaderSize + 4U, chain.tail->datagram_payload.size);
    ASSERT_EQ(0, std::memcmp(makeHeader(meta, 1, true).data(), chain.tail->datagram_payload.data, HeaderSize));
    ASSERT_EQ(0,
              std::memcmp(GrandSchemeCRC.data(),
                          static_cast<exposed::byte_t*>(chain.tail->datagram_payload.data) + HeaderSize,
                          4U));
    ASSERT_EQ(&user_transfer_referent, chain.tail->user_transfer_reference);
}
