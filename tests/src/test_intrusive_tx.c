/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c>  // NOLINT(bugprone-suspicious-include)
#include "helpers.h"
#include <unity.h>

// >>> from pycyphal.transport.commons.crc import CRC32C
// >>> list(CRC32C.new(data).value_as_bytes)
static const char EtherealStrength[] =
    "All was silent except for the howl of the wind against the antenna. Ye watched as the remaining birds in the "
    "flock gradually settled back into the forest. She stared at the antenna and thought it looked like an enormous "
    "hand stretched open toward the sky, possessing an ethereal strength.";
static const size_t EtherealStrengthSize   = sizeof(EtherealStrength) - 1;
static const byte_t EtherealStrengthCRC[4] = {209, 88, 130, 43};

static const char DetailOfTheCosmos[] =
    "For us, the dark forest state is all-important, but it's just a detail of the cosmos.";
static const size_t DetailOfTheCosmosSize   = sizeof(DetailOfTheCosmos) - 1;
static const byte_t DetailOfTheCosmosCRC[4] = {125, 113, 207, 171};

static const char   InterstellarWar[]     = "You have not seen what a true interstellar war is like.";
static const size_t InterstellarWarSize   = sizeof(InterstellarWar) - 1;
static const byte_t InterstellarWarCRC[4] = {102, 217, 109, 188};

// These aliases cannot be defined in the public API section: https://github.com/OpenCyphal-Garage/libudpard/issues/36
typedef struct UdpardPayload       UdpardPayload;
typedef struct UdpardUDPIPEndpoint UdpardUDPIPEndpoint;
typedef struct UdpardTx            UdpardTx;
typedef struct UdpardTxItem        UdpardTxItem;

typedef struct
{
    byte_t data[HEADER_SIZE_BYTES];
} HeaderBuffer;

static HeaderBuffer makeHeader(const TransferMetadata meta, const uint32_t frame_index, const bool end_of_transfer)
{
    HeaderBuffer buffer;
    (void) txSerializeHeader(&buffer.data[0], meta, frame_index, end_of_transfer);
    return buffer;
}

// Generate reference data using PyCyphal:
//
// >>> from pycyphal.transport.udp import UDPFrame
// >>> from pycyphal.transport import Priority, MessageDataSpecifier
// >>> frame = UDPFrame(priority=Priority.FAST, transfer_id=0xbadc0ffee0ddf00d, index=12345, end_of_transfer=False,
//  payload=memoryview(b''), source_node_id=2345, destination_node_id=5432,
//  data_specifier=MessageDataSpecifier(7654), user_data=0)
// >>> list(frame.compile_header_and_payload()[0])
// [1, 2, 41, 9, 56, 21, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0, 224, 60]
static void testTxSerializeHeader(void)
{
    {
        HeaderBuffer buffer;
        TEST_ASSERT_EQUAL_PTR(&buffer.data[0] + HEADER_SIZE_BYTES,
                              txSerializeHeader(buffer.data,
                                                (TransferMetadata){
                                                    .priority       = UdpardPriorityFast,
                                                    .src_node_id    = 2345,
                                                    .dst_node_id    = 5432,
                                                    .data_specifier = 7654,
                                                    .transfer_id    = 0xBADC0FFEE0DDF00dULL,
                                                },
                                                12345,
                                                false));
        const HeaderBuffer ref = {
            .data = {1, 2, 41, 9, 56, 21, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0, 224, 60}};
        TEST_ASSERT_EQUAL_MEMORY(ref.data, buffer.data, HEADER_SIZE_BYTES);
    }
    {
        HeaderBuffer buffer;
        TEST_ASSERT_EQUAL(&buffer.data[0] + HEADER_SIZE_BYTES,
                          txSerializeHeader(buffer.data,
                                            (TransferMetadata){
                                                .priority       = UdpardPriorityLow,
                                                .src_node_id    = 0xFEDC,
                                                .dst_node_id    = 0xBA98,
                                                .data_specifier = 1234,
                                                .transfer_id    = 0x0BADC0DE0BADC0DEULL,
                                            },
                                            0x7FFF,
                                            true));
        const HeaderBuffer ref = {.data = {1,   5,   220, 254, 152, 186, 210, 4,   222, 192, 173, 11,
                                           222, 192, 173, 11,  255, 127, 0,   128, 0,   0,   229, 4}};
        TEST_ASSERT_EQUAL_MEMORY(ref.data, buffer.data, HEADER_SIZE_BYTES);
    }
}

static void testMakeChainEmpty(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    char                   user_transfer_referent = '\0';
    const TransferMetadata meta                   = {
                          .priority       = UdpardPriorityFast,
                          .src_node_id    = 1234,
                          .dst_node_id    = 2345,
                          .data_specifier = 5432,
                          .transfer_id    = 0xBADC0FFEE0DDF00DULL,
    };
    const TxChain chain = txMakeChain(mem,
                                      (byte_t[]){11, 22, 33, 44, 55, 66, 77, 88},
                                      30,
                                      1234567890,
                                      meta,
                                      (UdpardUDPIPEndpoint){.ip_address = 0x0A0B0C0DU, .udp_port = 0x1234},
                                      (UdpardPayload){.size = 0, .data = ""},
                                      &user_transfer_referent);
    TEST_ASSERT_EQUAL(1 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(sizeof(struct UdpardTxItem) + HEADER_SIZE_BYTES + 4, alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(1, chain.count);
    TEST_ASSERT_EQUAL(chain.head, chain.tail);
    TEST_ASSERT_EQUAL(NULL, chain.head->next_in_transfer);
    TEST_ASSERT_EQUAL(1234567890, chain.head->deadline_usec);
    TEST_ASSERT_EQUAL(33, chain.head->dscp);
    TEST_ASSERT_EQUAL(0x0A0B0C0DU, chain.head->destination.ip_address);
    TEST_ASSERT_EQUAL(0x1234, chain.head->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + 4, chain.head->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 0, true).data, chain.head->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0,
                      memcmp("\x00\x00\x00\x00",  // CRC of the empty transfer.
                             (byte_t*) (chain.head->datagram_payload.data) + HEADER_SIZE_BYTES,
                             4));
    TEST_ASSERT_EQUAL(&user_transfer_referent, chain.head->user_transfer_reference);
    udpardTxFree(mem, chain.head);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void testMakeChainSingleMaxMTU(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    char                   user_transfer_referent = '\0';
    const TransferMetadata meta                   = {
                          .priority       = UdpardPrioritySlow,
                          .src_node_id    = 4321,
                          .dst_node_id    = 5432,
                          .data_specifier = 7766,
                          .transfer_id    = 0x0123456789ABCDEFULL,
    };
    const TxChain chain = txMakeChain(mem,
                                      (byte_t[]){11, 22, 33, 44, 55, 66, 77, 88},
                                      DetailOfTheCosmosSize + TRANSFER_CRC_SIZE_BYTES,
                                      1234567890,
                                      meta,
                                      (UdpardUDPIPEndpoint){.ip_address = 0x0A0B0C00U, .udp_port = 7474},
                                      (UdpardPayload){.size = DetailOfTheCosmosSize, .data = DetailOfTheCosmos},
                                      &user_transfer_referent);
    TEST_ASSERT_EQUAL(1 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(sizeof(struct UdpardTxItem) + HEADER_SIZE_BYTES + DetailOfTheCosmosSize + TRANSFER_CRC_SIZE_BYTES,
                      alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(1, chain.count);
    TEST_ASSERT_EQUAL(chain.head, chain.tail);
    TEST_ASSERT_EQUAL(NULL, chain.head->next_in_transfer);
    TEST_ASSERT_EQUAL(1234567890, chain.head->deadline_usec);
    TEST_ASSERT_EQUAL(77, chain.head->dscp);
    TEST_ASSERT_EQUAL(0x0A0B0C00U, chain.head->destination.ip_address);
    TEST_ASSERT_EQUAL(7474, chain.head->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + DetailOfTheCosmosSize + TRANSFER_CRC_SIZE_BYTES,
                      chain.head->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 0, true).data, chain.head->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0,
                      memcmp(DetailOfTheCosmos,
                             (byte_t*) (chain.head->datagram_payload.data) + HEADER_SIZE_BYTES,
                             DetailOfTheCosmosSize));
    TEST_ASSERT_EQUAL(0,
                      memcmp(DetailOfTheCosmosCRC,
                             (byte_t*) (chain.head->datagram_payload.data) + HEADER_SIZE_BYTES + DetailOfTheCosmosSize,
                             TRANSFER_CRC_SIZE_BYTES));
    TEST_ASSERT_EQUAL(&user_transfer_referent, chain.head->user_transfer_reference);
    udpardTxFree(mem, chain.head);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void testMakeChainSingleFrameDefaultMTU(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    const byte_t payload[UDPARD_MTU_DEFAULT_MAX_SINGLE_FRAME + 1] = {0};
    {  // Ensure UDPARD_MTU_DEFAULT_MAX_SINGLE_FRAME bytes fit in a single frame with the default MTU.
        const TxChain chain = txMakeChain(mem,
                                          (byte_t[]){11, 22, 33, 44, 55, 66, 77, 88},
                                          UDPARD_MTU_DEFAULT,
                                          1234567890,
                                          (TransferMetadata){.priority       = UdpardPrioritySlow,
                                                             .src_node_id    = 4321,
                                                             .dst_node_id    = 5432,
                                                             .data_specifier = 7766,
                                                             .transfer_id    = 0x0123456789ABCDEFULL},
                                          (UdpardUDPIPEndpoint){.ip_address = 0x0A0B0C00U, .udp_port = 7474},
                                          (UdpardPayload){.size = UDPARD_MTU_DEFAULT_MAX_SINGLE_FRAME, .data = payload},
                                          NULL);
        TEST_ASSERT_EQUAL(1 * 2ULL, alloc.allocated_fragments);
        TEST_ASSERT_EQUAL(sizeof(struct UdpardTxItem) + HEADER_SIZE_BYTES + UDPARD_MTU_DEFAULT_MAX_SINGLE_FRAME +
                              TRANSFER_CRC_SIZE_BYTES,
                          alloc.allocated_bytes);
        TEST_ASSERT_EQUAL(1, chain.count);
        TEST_ASSERT_EQUAL(chain.head, chain.tail);
        TEST_ASSERT_EQUAL(NULL, chain.head->next_in_transfer);
        udpardTxFree(mem, chain.head);
        TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    }
    {  // Increase the payload by 1 byte and ensure it spills over.
        const TxChain chain =
            txMakeChain(mem,
                        (byte_t[]){11, 22, 33, 44, 55, 66, 77, 88},
                        UDPARD_MTU_DEFAULT,
                        1234567890,
                        (TransferMetadata){.priority       = UdpardPrioritySlow,
                                           .src_node_id    = 4321,
                                           .dst_node_id    = 5432,
                                           .data_specifier = 7766,
                                           .transfer_id    = 0x0123456789ABCDEFULL},
                        (UdpardUDPIPEndpoint){.ip_address = 0x0A0B0C00U, .udp_port = 7474},
                        (UdpardPayload){.size = UDPARD_MTU_DEFAULT_MAX_SINGLE_FRAME + 1, .data = payload},
                        NULL);
        TEST_ASSERT_EQUAL(2 * 2ULL, alloc.allocated_fragments);
        TEST_ASSERT_EQUAL((sizeof(struct UdpardTxItem) + HEADER_SIZE_BYTES) * 2 + UDPARD_MTU_DEFAULT_MAX_SINGLE_FRAME +
                              1 + TRANSFER_CRC_SIZE_BYTES,
                          alloc.allocated_bytes);
        TEST_ASSERT_EQUAL(2, chain.count);
        TEST_ASSERT_NOT_EQUAL(chain.head, chain.tail);
        TEST_ASSERT_EQUAL((UdpardTxItem*) chain.tail, chain.head->next_in_transfer);
        TEST_ASSERT_EQUAL(NULL, chain.tail->next_in_transfer);
        udpardTxFree(mem, chain.head);
        udpardTxFree(mem, chain.tail);
        TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    }
}

static void testMakeChainThreeFrames(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    char                   user_transfer_referent = '\0';
    const TransferMetadata meta                   = {
                          .priority       = UdpardPriorityNominal,
                          .src_node_id    = 4321,
                          .dst_node_id    = 5432,
                          .data_specifier = 7766,
                          .transfer_id    = 0x0123456789ABCDEFULL,
    };
    const size_t  mtu   = (EtherealStrengthSize + 4U + 3U) / 3U;  // Force payload split into three frames.
    const TxChain chain = txMakeChain(mem,
                                      (byte_t[]){11, 22, 33, 44, 55, 66, 77, 88},
                                      mtu,
                                      223574680,
                                      meta,
                                      (UdpardUDPIPEndpoint){.ip_address = 0xBABADEDAU, .udp_port = 0xD0ED},
                                      (UdpardPayload){.size = EtherealStrengthSize, .data = EtherealStrength},
                                      &user_transfer_referent);
    TEST_ASSERT_EQUAL(3 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(3 * (sizeof(struct UdpardTxItem) + HEADER_SIZE_BYTES) + EtherealStrengthSize + 4U,
                      alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(3, chain.count);
    UdpardTxItem* const first = chain.head;
    TEST_ASSERT_NOT_EQUAL(NULL, first);
    UdpardTxItem* const second = first->next_in_transfer;
    TEST_ASSERT_NOT_EQUAL(NULL, second);
    UdpardTxItem* const third = second->next_in_transfer;
    TEST_ASSERT_NOT_EQUAL(NULL, third);
    TEST_ASSERT_EQUAL(NULL, third->next_in_transfer);
    TEST_ASSERT_EQUAL((UdpardTxItem*) chain.tail, third);

    // FIRST FRAME -- contains the first part of the payload.
    TEST_ASSERT_EQUAL(223574680, first->deadline_usec);
    TEST_ASSERT_EQUAL(55, first->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, first->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, first->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + mtu, first->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 0, false).data, first->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0, memcmp(EtherealStrength, (byte_t*) (first->datagram_payload.data) + HEADER_SIZE_BYTES, mtu));
    TEST_ASSERT_EQUAL(&user_transfer_referent, first->user_transfer_reference);

    // SECOND FRAME -- contains the second part of the payload.
    TEST_ASSERT_EQUAL(223574680, second->deadline_usec);
    TEST_ASSERT_EQUAL(55, second->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, second->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, second->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + mtu, second->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 1, false).data, second->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0,
                      memcmp(EtherealStrength + mtu,
                             (byte_t*) (second->datagram_payload.data) + HEADER_SIZE_BYTES,
                             mtu));
    TEST_ASSERT_EQUAL(&user_transfer_referent, second->user_transfer_reference);

    // THIRD FRAME -- contains the third part of the payload and the CRC at the end.
    TEST_ASSERT_EQUAL(223574680, third->deadline_usec);
    TEST_ASSERT_EQUAL(55, third->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, third->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, third->destination.udp_port);
    const size_t third_payload_size = EtherealStrengthSize - 2 * mtu;
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + third_payload_size + 4U, third->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 2, true).data, third->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0,
                      memcmp(EtherealStrength + 2 * mtu,
                             (byte_t*) (third->datagram_payload.data) + HEADER_SIZE_BYTES,
                             third_payload_size));
    TEST_ASSERT_EQUAL(0,
                      memcmp(EtherealStrengthCRC,
                             (byte_t*) (third->datagram_payload.data) + HEADER_SIZE_BYTES + third_payload_size,
                             TRANSFER_CRC_SIZE_BYTES));
    TEST_ASSERT_EQUAL(&user_transfer_referent, third->user_transfer_reference);

    // Clean up.
    udpardTxFree(mem, first);
    udpardTxFree(mem, second);
    udpardTxFree(mem, third);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void testMakeChainCRCSpill1(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    char                   user_transfer_referent = '\0';
    const TransferMetadata meta                   = {
                          .priority       = UdpardPriorityNominal,
                          .src_node_id    = 4321,
                          .dst_node_id    = 5432,
                          .data_specifier = 7766,
                          .transfer_id    = 0x0123456789ABCDEFULL,
    };
    const size_t  mtu   = InterstellarWarSize + 3U;
    const TxChain chain = txMakeChain(mem,
                                      (byte_t[]){11, 22, 33, 44, 55, 66, 77, 88},
                                      mtu,
                                      223574680,
                                      meta,
                                      (UdpardUDPIPEndpoint){.ip_address = 0xBABADEDAU, .udp_port = 0xD0ED},
                                      (UdpardPayload){.size = InterstellarWarSize, .data = InterstellarWar},
                                      &user_transfer_referent);
    TEST_ASSERT_EQUAL(2 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(2 * (sizeof(struct UdpardTxItem) + HEADER_SIZE_BYTES) + InterstellarWarSize + 4U,
                      alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(2, chain.count);
    TEST_ASSERT_NOT_EQUAL(chain.head, chain.tail);
    TEST_ASSERT_EQUAL((UdpardTxItem*) chain.tail, chain.head->next_in_transfer);
    TEST_ASSERT_EQUAL(NULL, chain.tail->next_in_transfer);

    // FIRST FRAME -- contains the payload and the first three bytes of the CRC.
    TEST_ASSERT_EQUAL(223574680, chain.head->deadline_usec);
    TEST_ASSERT_EQUAL(55, chain.head->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, chain.head->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, chain.head->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + mtu, chain.head->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 0, false).data, chain.head->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0,
                      memcmp(InterstellarWar,
                             (byte_t*) (chain.head->datagram_payload.data) + HEADER_SIZE_BYTES,
                             InterstellarWarSize));
    TEST_ASSERT_EQUAL(0,
                      memcmp(InterstellarWarCRC,
                             (byte_t*) (chain.head->datagram_payload.data) + HEADER_SIZE_BYTES + InterstellarWarSize,
                             3U));
    TEST_ASSERT_EQUAL(&user_transfer_referent, chain.head->user_transfer_reference);

    // SECOND FRAME -- contains the last byte of the CRC.
    TEST_ASSERT_EQUAL(223574680, chain.tail->deadline_usec);
    TEST_ASSERT_EQUAL(55, chain.tail->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, chain.tail->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, chain.tail->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + 1U, chain.tail->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 1, true).data, chain.tail->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0,
                      memcmp(InterstellarWarCRC + 3U,
                             (byte_t*) (chain.tail->datagram_payload.data) + HEADER_SIZE_BYTES,
                             1U));
    TEST_ASSERT_EQUAL(&user_transfer_referent, chain.tail->user_transfer_reference);

    // Clean up.
    udpardTxFree(mem, chain.head);
    udpardTxFree(mem, chain.tail);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void testMakeChainCRCSpill2(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    char                   user_transfer_referent = '\0';
    const TransferMetadata meta                   = {
                          .priority       = UdpardPriorityNominal,
                          .src_node_id    = 4321,
                          .dst_node_id    = 5432,
                          .data_specifier = 7766,
                          .transfer_id    = 0x0123456789ABCDEFULL,
    };
    const size_t  mtu   = InterstellarWarSize + 2U;
    const TxChain chain = txMakeChain(mem,
                                      (byte_t[]){11, 22, 33, 44, 55, 66, 77, 88},
                                      mtu,
                                      223574680,
                                      meta,
                                      (UdpardUDPIPEndpoint){.ip_address = 0xBABADEDAU, .udp_port = 0xD0ED},
                                      (UdpardPayload){.size = InterstellarWarSize, .data = InterstellarWar},
                                      &user_transfer_referent);
    TEST_ASSERT_EQUAL(2 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(2 * (sizeof(struct UdpardTxItem) + HEADER_SIZE_BYTES) + InterstellarWarSize + 4U,
                      alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(2, chain.count);
    TEST_ASSERT_NOT_EQUAL(chain.head, chain.tail);
    TEST_ASSERT_EQUAL((UdpardTxItem*) chain.tail, chain.head->next_in_transfer);
    TEST_ASSERT_EQUAL(NULL, chain.tail->next_in_transfer);

    // FIRST FRAME -- contains the payload and the first two bytes of the CRC.
    TEST_ASSERT_EQUAL(223574680, chain.head->deadline_usec);
    TEST_ASSERT_EQUAL(55, chain.head->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, chain.head->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, chain.head->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + mtu, chain.head->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 0, false).data, chain.head->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0,
                      memcmp(InterstellarWar,
                             (byte_t*) (chain.head->datagram_payload.data) + HEADER_SIZE_BYTES,
                             InterstellarWarSize));
    TEST_ASSERT_EQUAL(0,
                      memcmp(InterstellarWarCRC,
                             (byte_t*) (chain.head->datagram_payload.data) + HEADER_SIZE_BYTES + InterstellarWarSize,
                             2U));
    TEST_ASSERT_EQUAL(&user_transfer_referent, chain.head->user_transfer_reference);

    // SECOND FRAME -- contains the last two bytes of the CRC.
    TEST_ASSERT_EQUAL(223574680, chain.tail->deadline_usec);
    TEST_ASSERT_EQUAL(55, chain.tail->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, chain.tail->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, chain.tail->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + 2U, chain.tail->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 1, true).data, chain.tail->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0,
                      memcmp(InterstellarWarCRC + 2U,
                             (byte_t*) (chain.tail->datagram_payload.data) + HEADER_SIZE_BYTES,
                             2U));
    TEST_ASSERT_EQUAL(&user_transfer_referent, chain.tail->user_transfer_reference);

    // Clean up.
    udpardTxFree(mem, chain.head);
    udpardTxFree(mem, chain.tail);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void testMakeChainCRCSpill3(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    char                   user_transfer_referent = '\0';
    const TransferMetadata meta                   = {
                          .priority       = UdpardPriorityNominal,
                          .src_node_id    = 4321,
                          .dst_node_id    = 5432,
                          .data_specifier = 7766,
                          .transfer_id    = 0x0123456789ABCDEFULL,
    };
    const size_t  mtu   = InterstellarWarSize + 1U;
    const TxChain chain = txMakeChain(mem,
                                      (byte_t[]){11, 22, 33, 44, 55, 66, 77, 88},
                                      mtu,
                                      223574680,
                                      meta,
                                      (UdpardUDPIPEndpoint){.ip_address = 0xBABADEDAU, .udp_port = 0xD0ED},
                                      (UdpardPayload){.size = InterstellarWarSize, .data = InterstellarWar},
                                      &user_transfer_referent);
    TEST_ASSERT_EQUAL(2 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(2 * (sizeof(struct UdpardTxItem) + HEADER_SIZE_BYTES) + InterstellarWarSize + 4U,
                      alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(2, chain.count);
    TEST_ASSERT_NOT_EQUAL(chain.head, chain.tail);
    TEST_ASSERT_EQUAL((UdpardTxItem*) chain.tail, chain.head->next_in_transfer);
    TEST_ASSERT_EQUAL(NULL, chain.tail->next_in_transfer);

    // FIRST FRAME -- contains the payload and the first byte of the CRC.
    TEST_ASSERT_EQUAL(223574680, chain.head->deadline_usec);
    TEST_ASSERT_EQUAL(55, chain.head->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, chain.head->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, chain.head->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + mtu, chain.head->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 0, false).data, chain.head->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0,
                      memcmp(InterstellarWar,
                             (byte_t*) (chain.head->datagram_payload.data) + HEADER_SIZE_BYTES,
                             InterstellarWarSize));
    TEST_ASSERT_EQUAL(0,
                      memcmp(InterstellarWarCRC,
                             (byte_t*) (chain.head->datagram_payload.data) + HEADER_SIZE_BYTES + InterstellarWarSize,
                             1U));
    TEST_ASSERT_EQUAL(&user_transfer_referent, chain.head->user_transfer_reference);

    // SECOND FRAME -- contains the last three bytes of the CRC.
    TEST_ASSERT_EQUAL(223574680, chain.tail->deadline_usec);
    TEST_ASSERT_EQUAL(55, chain.tail->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, chain.tail->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, chain.tail->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + 3U, chain.tail->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 1, true).data, chain.tail->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0,
                      memcmp(InterstellarWarCRC + 1U,
                             (byte_t*) (chain.tail->datagram_payload.data) + HEADER_SIZE_BYTES,
                             3U));
    TEST_ASSERT_EQUAL(&user_transfer_referent, chain.tail->user_transfer_reference);

    // Clean up.
    udpardTxFree(mem, chain.head);
    udpardTxFree(mem, chain.tail);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void testMakeChainCRCSpillFull(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    char                   user_transfer_referent = '\0';
    const TransferMetadata meta                   = {
                          .priority       = UdpardPriorityNominal,
                          .src_node_id    = 4321,
                          .dst_node_id    = 5432,
                          .data_specifier = 7766,
                          .transfer_id    = 0x0123456789ABCDEFULL,
    };
    const size_t  mtu   = InterstellarWarSize;
    const TxChain chain = txMakeChain(mem,
                                      (byte_t[]){11, 22, 33, 44, 55, 66, 77, 88},
                                      mtu,
                                      223574680,
                                      meta,
                                      (UdpardUDPIPEndpoint){.ip_address = 0xBABADEDAU, .udp_port = 0xD0ED},
                                      (UdpardPayload){.size = InterstellarWarSize, .data = InterstellarWar},
                                      &user_transfer_referent);
    TEST_ASSERT_EQUAL(2 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(2 * (sizeof(struct UdpardTxItem) + HEADER_SIZE_BYTES) + InterstellarWarSize + 4U,
                      alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(2, chain.count);
    TEST_ASSERT_NOT_EQUAL(chain.head, chain.tail);
    TEST_ASSERT_EQUAL((UdpardTxItem*) chain.tail, chain.head->next_in_transfer);
    TEST_ASSERT_EQUAL(NULL, chain.tail->next_in_transfer);

    // FIRST FRAME -- contains the payload only.
    TEST_ASSERT_EQUAL(223574680, chain.head->deadline_usec);
    TEST_ASSERT_EQUAL(55, chain.head->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, chain.head->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, chain.head->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + mtu, chain.head->datagram_payload.size);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + InterstellarWarSize, chain.head->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 0, false).data, chain.head->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0,
                      memcmp(InterstellarWar,
                             (byte_t*) (chain.head->datagram_payload.data) + HEADER_SIZE_BYTES,
                             InterstellarWarSize));
    TEST_ASSERT_EQUAL(&user_transfer_referent, chain.head->user_transfer_reference);

    // SECOND FRAME -- contains the last byte of the CRC.
    TEST_ASSERT_EQUAL(223574680, chain.tail->deadline_usec);
    TEST_ASSERT_EQUAL(55, chain.tail->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, chain.tail->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, chain.tail->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + 4U, chain.tail->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 1, true).data, chain.tail->datagram_payload.data, HEADER_SIZE_BYTES));
    TEST_ASSERT_EQUAL(0,
                      memcmp(InterstellarWarCRC,
                             (byte_t*) (chain.tail->datagram_payload.data) + HEADER_SIZE_BYTES,
                             4U));
    TEST_ASSERT_EQUAL(&user_transfer_referent, chain.tail->user_transfer_reference);

    // Clean up.
    udpardTxFree(mem, chain.head);
    udpardTxFree(mem, chain.tail);
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
}

static void testPushPeekPopFree(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    const UdpardNodeID node_id = 1234;
    //
    UdpardTx tx = {
        .local_node_id           = &node_id,
        .queue_capacity          = 3,
        .mtu                     = (EtherealStrengthSize + 4U + 3U) / 3U,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = mem,
        .queue_size              = 0,
        .root                    = NULL,
    };
    const TransferMetadata meta = {
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123456789ABCDEFULL,
    };
    char user_transfer_referent = '\0';
    TEST_ASSERT_EQUAL(3,
                      txPush(&tx,
                             1234567890U,
                             meta,
                             (UdpardUDPIPEndpoint){.ip_address = 0xBABADEDAU, .udp_port = 0xD0ED},
                             (UdpardPayload){.size = EtherealStrengthSize, .data = EtherealStrength},
                             &user_transfer_referent));
    TEST_ASSERT_EQUAL(3 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(3 * (sizeof(struct UdpardTxItem) + HEADER_SIZE_BYTES) + EtherealStrengthSize + 4U,
                      alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(3, tx.queue_size);

    const UdpardTxItem* frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_NOT_EQUAL(NULL, frame->next_in_transfer);
    TEST_ASSERT_EQUAL(1234567890U, frame->deadline_usec);
    TEST_ASSERT_EQUAL(4, frame->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, frame->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, frame->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + tx.mtu, frame->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 0, false).data, frame->datagram_payload.data, HEADER_SIZE_BYTES));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));

    TEST_ASSERT_EQUAL(2 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(2, tx.queue_size);

    frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_NOT_EQUAL(NULL, frame->next_in_transfer);
    TEST_ASSERT_EQUAL(1234567890U, frame->deadline_usec);
    TEST_ASSERT_EQUAL(4, frame->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, frame->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, frame->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + tx.mtu, frame->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 1, false).data, frame->datagram_payload.data, HEADER_SIZE_BYTES));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));

    TEST_ASSERT_EQUAL(1 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(1, tx.queue_size);

    frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(NULL, frame->next_in_transfer);
    TEST_ASSERT_EQUAL(1234567890U, frame->deadline_usec);
    TEST_ASSERT_EQUAL(4, frame->dscp);
    TEST_ASSERT_EQUAL(0xBABADEDAU, frame->destination.ip_address);
    TEST_ASSERT_EQUAL(0xD0ED, frame->destination.udp_port);
    TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES + EtherealStrengthSize - 2 * tx.mtu + 4U, frame->datagram_payload.size);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta, 2, true).data, frame->datagram_payload.data, HEADER_SIZE_BYTES));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));

    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(0, tx.queue_size);
    TEST_ASSERT_EQUAL(NULL, udpardTxPeek(&tx));
}

static void testPushPrioritization(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    const UdpardNodeID node_id = 1234;
    //
    UdpardTx tx = {
        .local_node_id           = &node_id,
        .queue_capacity          = 7,
        .mtu                     = 140,  // This is chosen to match the test data.
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = mem,
        .queue_size              = 0,
        .root                    = NULL,
    };
    // A -- Push the first multi-frame transfer at nominal priority level.
    const TransferMetadata meta_a = {
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 100,
        .dst_node_id    = UDPARD_NODE_ID_UNSET,
        .data_specifier = 200,
        .transfer_id    = 5000,
    };
    TEST_ASSERT_EQUAL(3,
                      txPush(&tx,
                             0,
                             meta_a,
                             (UdpardUDPIPEndpoint){.ip_address = 0xAAAAAAAA, .udp_port = 0xAAAA},
                             (UdpardPayload){.size = EtherealStrengthSize, .data = EtherealStrength},
                             NULL));
    TEST_ASSERT_EQUAL(3 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(3, tx.queue_size);
    const UdpardTxItem* frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xAAAAAAAA, frame->destination.ip_address);

    // B -- Next, push a higher-priority transfer and ensure it takes precedence.
    TEST_ASSERT_EQUAL(1,
                      txPush(&tx,
                             0,
                             (TransferMetadata){
                                 .priority       = UdpardPriorityHigh,
                                 .src_node_id    = 100,
                                 .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                 .data_specifier = 200,
                                 .transfer_id    = 100000,
                             },
                             (UdpardUDPIPEndpoint){.ip_address = 0xBBBBBBBB, .udp_port = 0xBBBB},
                             (UdpardPayload){.size = DetailOfTheCosmosSize, .data = DetailOfTheCosmos},
                             NULL));
    TEST_ASSERT_EQUAL(4 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(4, tx.queue_size);
    frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xBBBBBBBB, frame->destination.ip_address);

    // C -- Next, push a lower-priority transfer and ensure it goes towards the back.
    TEST_ASSERT_EQUAL(1,
                      txPush(&tx,
                             1002,
                             (TransferMetadata){
                                 .priority       = UdpardPriorityLow,
                                 .src_node_id    = 100,
                                 .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                 .data_specifier = 200,
                                 .transfer_id    = 10000,
                             },
                             (UdpardUDPIPEndpoint){.ip_address = 0xCCCCCCCC, .udp_port = 0xCCCC},
                             (UdpardPayload){.size = InterstellarWarSize, .data = InterstellarWar},
                             NULL));
    TEST_ASSERT_EQUAL(5 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(5, tx.queue_size);
    frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xBBBBBBBB, frame->destination.ip_address);

    // D -- Add another transfer like the previous one and ensure it goes in the back.
    TEST_ASSERT_EQUAL(1,
                      txPush(&tx,
                             1003,
                             (TransferMetadata){
                                 .priority       = UdpardPriorityLow,
                                 .src_node_id    = 100,
                                 .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                 .data_specifier = 200,
                                 .transfer_id    = 10001,
                             },
                             (UdpardUDPIPEndpoint){.ip_address = 0xDDDDDDDD, .udp_port = 0xDDDD},
                             (UdpardPayload){.size = InterstellarWarSize, .data = InterstellarWar},
                             NULL));
    TEST_ASSERT_EQUAL(6 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(6, tx.queue_size);
    frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xBBBBBBBB, frame->destination.ip_address);

    // E -- Add an even higher priority transfer.
    TEST_ASSERT_EQUAL(1,
                      txPush(&tx,
                             1003,
                             (TransferMetadata){
                                 .priority       = UdpardPriorityFast,
                                 .src_node_id    = 100,
                                 .dst_node_id    = UDPARD_NODE_ID_UNSET,
                                 .data_specifier = 200,
                                 .transfer_id    = 1000,
                             },
                             (UdpardUDPIPEndpoint){.ip_address = 0xEEEEEEEE, .udp_port = 0xEEEE},
                             (UdpardPayload){.size = InterstellarWarSize, .data = InterstellarWar},
                             NULL));
    TEST_ASSERT_EQUAL(7 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(7, tx.queue_size);
    frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xEEEEEEEE, frame->destination.ip_address);

    // Now, unwind the queue and ensure the frames are popped in the right order.
    // E
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));
    TEST_ASSERT_EQUAL(6 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(6, tx.queue_size);
    // B
    frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xBBBBBBBB, frame->destination.ip_address);
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));
    TEST_ASSERT_EQUAL(5 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(5, tx.queue_size);
    // A1, three frames.
    frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xAAAAAAAA, frame->destination.ip_address);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta_a, 0, false).data, frame->datagram_payload.data, HEADER_SIZE_BYTES));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));
    TEST_ASSERT_EQUAL(4 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(4, tx.queue_size);
    // A2
    frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xAAAAAAAA, frame->destination.ip_address);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta_a, 1, false).data, frame->datagram_payload.data, HEADER_SIZE_BYTES));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));
    TEST_ASSERT_EQUAL(3 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(3, tx.queue_size);
    // A3
    frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xAAAAAAAA, frame->destination.ip_address);
    TEST_ASSERT_EQUAL(0, memcmp(makeHeader(meta_a, 2, true).data, frame->datagram_payload.data, HEADER_SIZE_BYTES));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));
    TEST_ASSERT_EQUAL(2 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(2, tx.queue_size);
    // C
    frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xCCCCCCCC, frame->destination.ip_address);
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));
    TEST_ASSERT_EQUAL(1 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(1, tx.queue_size);
    // D
    frame = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_EQUAL(NULL, frame);
    TEST_ASSERT_EQUAL(0xDDDDDDDD, frame->destination.ip_address);
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(0, tx.queue_size);

    TEST_ASSERT_EQUAL(NULL, udpardTxPeek(&tx));
}

static void testPushCapacityLimit(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    const UdpardNodeID node_id = 1234;
    //
    UdpardTx tx = {
        .local_node_id           = &node_id,
        .queue_capacity          = 2,
        .mtu                     = 10U,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = mem,
        .queue_size              = 0,
        .root                    = NULL,
    };
    const TransferMetadata meta = {
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123456789ABCDEFULL,
    };
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_CAPACITY,
                      txPush(&tx,
                             1234567890U,
                             meta,
                             (UdpardUDPIPEndpoint){.ip_address = 0xBABADEDAU, .udp_port = 0xD0ED},
                             (UdpardPayload){.size = EtherealStrengthSize, .data = EtherealStrength},
                             NULL));
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(0, tx.queue_size);
}

static void testPushOOM(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    const UdpardNodeID node_id = 1234;
    //
    UdpardTx tx = {
        .local_node_id           = &node_id,
        .queue_capacity          = 10000U,
        .mtu                     = (EtherealStrengthSize + 4U + 3U) / 3U,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = mem,
        .queue_size              = 0,
        .root                    = NULL,
    };
    const TransferMetadata meta = {
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123456789ABCDEFULL,
    };
    alloc.limit_bytes = EtherealStrengthSize;  // No memory for the overheads.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_MEMORY,
                      txPush(&tx,
                             1234567890U,
                             meta,
                             (UdpardUDPIPEndpoint){.ip_address = 0xBABADEDAU, .udp_port = 0xD0ED},
                             (UdpardPayload){.size = EtherealStrengthSize, .data = EtherealStrength},
                             NULL));
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(0, tx.queue_size);
}

static void testPushPayloadOOM(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    const UdpardNodeID node_id = 1234;
    //
    UdpardTx tx = {
        .local_node_id           = &node_id,
        .queue_capacity          = 10000U,
        .mtu                     = EtherealStrengthSize + HEADER_CRC_SIZE_BYTES,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = mem,
        .queue_size              = 0,
        .root                    = NULL,
    };
    const TransferMetadata meta = {
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123456789ABCDEFULL,
    };
    // There is memory of the item, but 1 byte short for payload.
    alloc.limit_bytes = sizeof(UdpardTxItem) + (HEADER_SIZE_BYTES + EtherealStrengthSize + HEADER_CRC_SIZE_BYTES - 1);
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_MEMORY,
                      txPush(&tx,
                             1234567890U,
                             meta,
                             (UdpardUDPIPEndpoint){.ip_address = 0xBABADEDAU, .udp_port = 0xD0ED},
                             (UdpardPayload){.size = EtherealStrengthSize, .data = EtherealStrength},
                             NULL));
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(0, tx.queue_size);
}

static void testPushAnonymousMultiFrame(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    const UdpardNodeID node_id = 0xFFFFU;
    //
    UdpardTx tx = {
        .local_node_id           = &node_id,
        .queue_capacity          = 10000U,
        .mtu                     = (EtherealStrengthSize + 4U + 3U) / 3U,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = mem,
        .queue_size              = 0,
        .root                    = NULL,
    };
    const TransferMetadata meta = {
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 7766,
        .transfer_id    = 0x0123456789ABCDEFULL,
    };
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ANONYMOUS,
                      txPush(&tx,
                             1234567890U,
                             meta,
                             (UdpardUDPIPEndpoint){.ip_address = 0xBABADEDAU, .udp_port = 0xD0ED},
                             (UdpardPayload){.size = EtherealStrengthSize, .data = EtherealStrength},
                             NULL));
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(0, tx.queue_size);
}

static void testPushAnonymousService(void)
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const struct UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    const UdpardNodeID node_id = 0xFFFFU;
    //
    UdpardTx tx = {
        .local_node_id           = &node_id,
        .queue_capacity          = 10000,
        .mtu                     = 1500,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = mem,
        .queue_size              = 0,
        .root                    = NULL,
    };
    const TransferMetadata meta = {
        .priority       = UdpardPriorityNominal,
        .src_node_id    = 4321,
        .dst_node_id    = 5432,
        .data_specifier = 0x8099U,  // Service response.
        .transfer_id    = 0x0123456789ABCDEFULL,
    };
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ANONYMOUS,
                      txPush(&tx,
                             1234567890U,
                             meta,
                             (UdpardUDPIPEndpoint){.ip_address = 0xBABADEDAU, .udp_port = 0xD0ED},
                             (UdpardPayload){.size = EtherealStrengthSize, .data = EtherealStrength},
                             NULL));
    TEST_ASSERT_EQUAL(0, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc.allocated_bytes);
    TEST_ASSERT_EQUAL(0, tx.queue_size);
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(testTxSerializeHeader);
    RUN_TEST(testMakeChainEmpty);
    RUN_TEST(testMakeChainSingleMaxMTU);
    RUN_TEST(testMakeChainSingleFrameDefaultMTU);
    RUN_TEST(testMakeChainThreeFrames);
    RUN_TEST(testMakeChainCRCSpill1);
    RUN_TEST(testMakeChainCRCSpill2);
    RUN_TEST(testMakeChainCRCSpill3);
    RUN_TEST(testMakeChainCRCSpillFull);
    RUN_TEST(testPushPeekPopFree);
    RUN_TEST(testPushPrioritization);
    RUN_TEST(testPushCapacityLimit);
    RUN_TEST(testPushOOM);
    RUN_TEST(testPushPayloadOOM);
    RUN_TEST(testPushAnonymousMultiFrame);
    RUN_TEST(testPushAnonymousService);
    return UNITY_END();
}
