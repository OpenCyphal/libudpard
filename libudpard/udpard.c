/// This software is distributed under the terms of the MIT License.
/// Copyright (c) 2016 OpenCyphal.
/// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
/// Author: Pavel Kirienko <pavel@opencyphal.org>

#include "udpard.h"
#include "_udpard_cavl.h"
#include <string.h>

// --------------------------------------------- BUILD CONFIGURATION ---------------------------------------------

/// Define this macro to include build configuration header.
/// Usage example with CMake: "-DUDPARD_CONFIG_HEADER=\"${CMAKE_CURRENT_SOURCE_DIR}/my_udpard_config.h\""
#ifdef UDPARD_CONFIG_HEADER
#    include UDPARD_CONFIG_HEADER
#endif

/// By default, this macro resolves to the standard assert(). The user can redefine this if necessary.
/// To disable assertion checks completely, make it expand into `(void)(0)`.
#ifndef UDPARD_ASSERT
// Intentional violation of MISRA: inclusion not at the top of the file to eliminate unnecessary dependency on assert.h.
#    include <assert.h>  // NOSONAR
// Intentional violation of MISRA: assertion macro cannot be replaced with a function definition.
#    define UDPARD_ASSERT(x) assert(x)  // NOSONAR
#endif

/// This macro is needed for testing and for library development.
#ifndef UDPARD_PRIVATE
#    define UDPARD_PRIVATE static inline
#endif

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
#    error "Unsupported language: ISO C99 or a newer version is required."
#endif

// --------------------------------------------- COMMON DEFINITIONS ---------------------------------------------

typedef uint_least8_t byte_t;  ///< For compatibility with platforms where byte size is not 8 bits.

static const uint_fast8_t ByteWidth = 8U;
static const byte_t       ByteMask  = 0xFFU;

typedef struct
{
    UdpardPriority   priority;
    UdpardNodeID     src_node_id;
    UdpardNodeID     dst_node_id;
    uint16_t         data_specifier;
    UdpardTransferID transfer_id;
} TransferMetadata;

#define DATA_SPECIFIER_SERVICE_NOT_MESSAGE_MASK 0x8000U
#define DATA_SPECIFIER_SERVICE_REQUEST_NOT_RESPONSE_MASK 0x4000U

#define HEADER_SIZE_BYTES 24U
#define HEADER_VERSION 1U
/// The frame index is a 31-bit unsigned integer. The most significant bit is used to indicate the end of transfer.
#define HEADER_FRAME_INDEX_EOT_MASK 0x80000000UL
#define HEADER_FRAME_INDEX_MAX 0x7FFFFFFFUL

/// The port number is defined in the Cyphal/UDP Specification.
#define UDP_PORT 9382U

// See Cyphal/UDP Specification, section 4.3.2.1 Endpoints.
#define SUBJECT_MULTICAST_GROUP_ADDRESS_MASK 0xEF000000UL
#define SERVICE_MULTICAST_GROUP_ADDRESS_MASK 0xEF010000UL

UDPARD_PRIVATE uint32_t makeSubjectIPGroupAddress(const UdpardPortID subject_id)
{
    return SUBJECT_MULTICAST_GROUP_ADDRESS_MASK | ((uint32_t) subject_id);
}

UDPARD_PRIVATE uint32_t makeServiceIPGroupAddress(const UdpardNodeID destination_node_id)
{
    return SERVICE_MULTICAST_GROUP_ADDRESS_MASK | ((uint32_t) destination_node_id);
}

UDPARD_PRIVATE UdpardUDPIPEndpoint makeSubjectUDPIPEndpoint(const UdpardPortID subject_id)
{
    return (UdpardUDPIPEndpoint){.ip_address = makeSubjectIPGroupAddress(subject_id), .udp_port = UDP_PORT};
}

UDPARD_PRIVATE UdpardUDPIPEndpoint makeServiceUDPIPEndpoint(const UdpardNodeID destination_node_id)
{
    return (UdpardUDPIPEndpoint){.ip_address = makeServiceIPGroupAddress(destination_node_id), .udp_port = UDP_PORT};
}

/// Used for inserting new items into AVL trees. Refer to the documentation for cavlSearch() for details.
UDPARD_PRIVATE UdpardTreeNode* avlTrivialFactory(void* const user_reference)
{
    return (UdpardTreeNode*) user_reference;
}

UDPARD_PRIVATE size_t smaller(const size_t a, const size_t b)
{
    return (a < b) ? a : b;
}

UDPARD_PRIVATE size_t larger(const size_t a, const size_t b)
{
    return (a > b) ? a : b;
}

// --------------------------------------------- HEADER CRC ---------------------------------------------

#define HEADER_CRC_INITIAL 0xFFFFU
#define HEADER_CRC_RESIDUE 0x0000U
#define HEADER_CRC_SIZE_BYTES 2U

UDPARD_PRIVATE uint16_t headerCRCAddByte(const uint16_t crc, const byte_t byte)
{
    static const uint16_t Table[256] = {
        0x0000U, 0x1021U, 0x2042U, 0x3063U, 0x4084U, 0x50A5U, 0x60C6U, 0x70E7U, 0x8108U, 0x9129U, 0xA14AU, 0xB16BU,
        0xC18CU, 0xD1ADU, 0xE1CEU, 0xF1EFU, 0x1231U, 0x0210U, 0x3273U, 0x2252U, 0x52B5U, 0x4294U, 0x72F7U, 0x62D6U,
        0x9339U, 0x8318U, 0xB37BU, 0xA35AU, 0xD3BDU, 0xC39CU, 0xF3FFU, 0xE3DEU, 0x2462U, 0x3443U, 0x0420U, 0x1401U,
        0x64E6U, 0x74C7U, 0x44A4U, 0x5485U, 0xA56AU, 0xB54BU, 0x8528U, 0x9509U, 0xE5EEU, 0xF5CFU, 0xC5ACU, 0xD58DU,
        0x3653U, 0x2672U, 0x1611U, 0x0630U, 0x76D7U, 0x66F6U, 0x5695U, 0x46B4U, 0xB75BU, 0xA77AU, 0x9719U, 0x8738U,
        0xF7DFU, 0xE7FEU, 0xD79DU, 0xC7BCU, 0x48C4U, 0x58E5U, 0x6886U, 0x78A7U, 0x0840U, 0x1861U, 0x2802U, 0x3823U,
        0xC9CCU, 0xD9EDU, 0xE98EU, 0xF9AFU, 0x8948U, 0x9969U, 0xA90AU, 0xB92BU, 0x5AF5U, 0x4AD4U, 0x7AB7U, 0x6A96U,
        0x1A71U, 0x0A50U, 0x3A33U, 0x2A12U, 0xDBFDU, 0xCBDCU, 0xFBBFU, 0xEB9EU, 0x9B79U, 0x8B58U, 0xBB3BU, 0xAB1AU,
        0x6CA6U, 0x7C87U, 0x4CE4U, 0x5CC5U, 0x2C22U, 0x3C03U, 0x0C60U, 0x1C41U, 0xEDAEU, 0xFD8FU, 0xCDECU, 0xDDCDU,
        0xAD2AU, 0xBD0BU, 0x8D68U, 0x9D49U, 0x7E97U, 0x6EB6U, 0x5ED5U, 0x4EF4U, 0x3E13U, 0x2E32U, 0x1E51U, 0x0E70U,
        0xFF9FU, 0xEFBEU, 0xDFDDU, 0xCFFCU, 0xBF1BU, 0xAF3AU, 0x9F59U, 0x8F78U, 0x9188U, 0x81A9U, 0xB1CAU, 0xA1EBU,
        0xD10CU, 0xC12DU, 0xF14EU, 0xE16FU, 0x1080U, 0x00A1U, 0x30C2U, 0x20E3U, 0x5004U, 0x4025U, 0x7046U, 0x6067U,
        0x83B9U, 0x9398U, 0xA3FBU, 0xB3DAU, 0xC33DU, 0xD31CU, 0xE37FU, 0xF35EU, 0x02B1U, 0x1290U, 0x22F3U, 0x32D2U,
        0x4235U, 0x5214U, 0x6277U, 0x7256U, 0xB5EAU, 0xA5CBU, 0x95A8U, 0x8589U, 0xF56EU, 0xE54FU, 0xD52CU, 0xC50DU,
        0x34E2U, 0x24C3U, 0x14A0U, 0x0481U, 0x7466U, 0x6447U, 0x5424U, 0x4405U, 0xA7DBU, 0xB7FAU, 0x8799U, 0x97B8U,
        0xE75FU, 0xF77EU, 0xC71DU, 0xD73CU, 0x26D3U, 0x36F2U, 0x0691U, 0x16B0U, 0x6657U, 0x7676U, 0x4615U, 0x5634U,
        0xD94CU, 0xC96DU, 0xF90EU, 0xE92FU, 0x99C8U, 0x89E9U, 0xB98AU, 0xA9ABU, 0x5844U, 0x4865U, 0x7806U, 0x6827U,
        0x18C0U, 0x08E1U, 0x3882U, 0x28A3U, 0xCB7DU, 0xDB5CU, 0xEB3FU, 0xFB1EU, 0x8BF9U, 0x9BD8U, 0xABBBU, 0xBB9AU,
        0x4A75U, 0x5A54U, 0x6A37U, 0x7A16U, 0x0AF1U, 0x1AD0U, 0x2AB3U, 0x3A92U, 0xFD2EU, 0xED0FU, 0xDD6CU, 0xCD4DU,
        0xBDAAU, 0xAD8BU, 0x9DE8U, 0x8DC9U, 0x7C26U, 0x6C07U, 0x5C64U, 0x4C45U, 0x3CA2U, 0x2C83U, 0x1CE0U, 0x0CC1U,
        0xEF1FU, 0xFF3EU, 0xCF5DU, 0xDF7CU, 0xAF9BU, 0xBFBAU, 0x8FD9U, 0x9FF8U, 0x6E17U, 0x7E36U, 0x4E55U, 0x5E74U,
        0x2E93U, 0x3EB2U, 0x0ED1U, 0x1EF0U,
    };
    return (uint16_t) ((uint16_t) (crc << ByteWidth) ^
                       Table[(uint16_t) ((uint16_t) (crc >> ByteWidth) ^ byte) & ByteMask]);
}

UDPARD_PRIVATE uint16_t headerCRCCompute(const size_t size, const void* const data)
{
    UDPARD_ASSERT((data != NULL) || (size == 0U));
    uint16_t      out = HEADER_CRC_INITIAL;
    const byte_t* p   = (const byte_t*) data;
    for (size_t i = 0; i < size; i++)
    {
        out = headerCRCAddByte(out, *p);
        ++p;
    }
    return out;
}

// --------------------------------------------- TRANSFER CRC ---------------------------------------------

#define TRANSFER_CRC_INITIAL 0xFFFFFFFFUL
#define TRANSFER_CRC_OUTPUT_XOR 0xFFFFFFFFUL
#define TRANSFER_CRC_RESIDUE_BEFORE_OUTPUT_XOR 0xB798B438UL
#define TRANSFER_CRC_SIZE_BYTES 4U

UDPARD_PRIVATE uint32_t transferCRCAddByte(const uint32_t crc, const byte_t byte)
{
    static const uint32_t Table[256] = {
        0x00000000UL, 0xF26B8303UL, 0xE13B70F7UL, 0x1350F3F4UL, 0xC79A971FUL, 0x35F1141CUL, 0x26A1E7E8UL, 0xD4CA64EBUL,
        0x8AD958CFUL, 0x78B2DBCCUL, 0x6BE22838UL, 0x9989AB3BUL, 0x4D43CFD0UL, 0xBF284CD3UL, 0xAC78BF27UL, 0x5E133C24UL,
        0x105EC76FUL, 0xE235446CUL, 0xF165B798UL, 0x030E349BUL, 0xD7C45070UL, 0x25AFD373UL, 0x36FF2087UL, 0xC494A384UL,
        0x9A879FA0UL, 0x68EC1CA3UL, 0x7BBCEF57UL, 0x89D76C54UL, 0x5D1D08BFUL, 0xAF768BBCUL, 0xBC267848UL, 0x4E4DFB4BUL,
        0x20BD8EDEUL, 0xD2D60DDDUL, 0xC186FE29UL, 0x33ED7D2AUL, 0xE72719C1UL, 0x154C9AC2UL, 0x061C6936UL, 0xF477EA35UL,
        0xAA64D611UL, 0x580F5512UL, 0x4B5FA6E6UL, 0xB93425E5UL, 0x6DFE410EUL, 0x9F95C20DUL, 0x8CC531F9UL, 0x7EAEB2FAUL,
        0x30E349B1UL, 0xC288CAB2UL, 0xD1D83946UL, 0x23B3BA45UL, 0xF779DEAEUL, 0x05125DADUL, 0x1642AE59UL, 0xE4292D5AUL,
        0xBA3A117EUL, 0x4851927DUL, 0x5B016189UL, 0xA96AE28AUL, 0x7DA08661UL, 0x8FCB0562UL, 0x9C9BF696UL, 0x6EF07595UL,
        0x417B1DBCUL, 0xB3109EBFUL, 0xA0406D4BUL, 0x522BEE48UL, 0x86E18AA3UL, 0x748A09A0UL, 0x67DAFA54UL, 0x95B17957UL,
        0xCBA24573UL, 0x39C9C670UL, 0x2A993584UL, 0xD8F2B687UL, 0x0C38D26CUL, 0xFE53516FUL, 0xED03A29BUL, 0x1F682198UL,
        0x5125DAD3UL, 0xA34E59D0UL, 0xB01EAA24UL, 0x42752927UL, 0x96BF4DCCUL, 0x64D4CECFUL, 0x77843D3BUL, 0x85EFBE38UL,
        0xDBFC821CUL, 0x2997011FUL, 0x3AC7F2EBUL, 0xC8AC71E8UL, 0x1C661503UL, 0xEE0D9600UL, 0xFD5D65F4UL, 0x0F36E6F7UL,
        0x61C69362UL, 0x93AD1061UL, 0x80FDE395UL, 0x72966096UL, 0xA65C047DUL, 0x5437877EUL, 0x4767748AUL, 0xB50CF789UL,
        0xEB1FCBADUL, 0x197448AEUL, 0x0A24BB5AUL, 0xF84F3859UL, 0x2C855CB2UL, 0xDEEEDFB1UL, 0xCDBE2C45UL, 0x3FD5AF46UL,
        0x7198540DUL, 0x83F3D70EUL, 0x90A324FAUL, 0x62C8A7F9UL, 0xB602C312UL, 0x44694011UL, 0x5739B3E5UL, 0xA55230E6UL,
        0xFB410CC2UL, 0x092A8FC1UL, 0x1A7A7C35UL, 0xE811FF36UL, 0x3CDB9BDDUL, 0xCEB018DEUL, 0xDDE0EB2AUL, 0x2F8B6829UL,
        0x82F63B78UL, 0x709DB87BUL, 0x63CD4B8FUL, 0x91A6C88CUL, 0x456CAC67UL, 0xB7072F64UL, 0xA457DC90UL, 0x563C5F93UL,
        0x082F63B7UL, 0xFA44E0B4UL, 0xE9141340UL, 0x1B7F9043UL, 0xCFB5F4A8UL, 0x3DDE77ABUL, 0x2E8E845FUL, 0xDCE5075CUL,
        0x92A8FC17UL, 0x60C37F14UL, 0x73938CE0UL, 0x81F80FE3UL, 0x55326B08UL, 0xA759E80BUL, 0xB4091BFFUL, 0x466298FCUL,
        0x1871A4D8UL, 0xEA1A27DBUL, 0xF94AD42FUL, 0x0B21572CUL, 0xDFEB33C7UL, 0x2D80B0C4UL, 0x3ED04330UL, 0xCCBBC033UL,
        0xA24BB5A6UL, 0x502036A5UL, 0x4370C551UL, 0xB11B4652UL, 0x65D122B9UL, 0x97BAA1BAUL, 0x84EA524EUL, 0x7681D14DUL,
        0x2892ED69UL, 0xDAF96E6AUL, 0xC9A99D9EUL, 0x3BC21E9DUL, 0xEF087A76UL, 0x1D63F975UL, 0x0E330A81UL, 0xFC588982UL,
        0xB21572C9UL, 0x407EF1CAUL, 0x532E023EUL, 0xA145813DUL, 0x758FE5D6UL, 0x87E466D5UL, 0x94B49521UL, 0x66DF1622UL,
        0x38CC2A06UL, 0xCAA7A905UL, 0xD9F75AF1UL, 0x2B9CD9F2UL, 0xFF56BD19UL, 0x0D3D3E1AUL, 0x1E6DCDEEUL, 0xEC064EEDUL,
        0xC38D26C4UL, 0x31E6A5C7UL, 0x22B65633UL, 0xD0DDD530UL, 0x0417B1DBUL, 0xF67C32D8UL, 0xE52CC12CUL, 0x1747422FUL,
        0x49547E0BUL, 0xBB3FFD08UL, 0xA86F0EFCUL, 0x5A048DFFUL, 0x8ECEE914UL, 0x7CA56A17UL, 0x6FF599E3UL, 0x9D9E1AE0UL,
        0xD3D3E1ABUL, 0x21B862A8UL, 0x32E8915CUL, 0xC083125FUL, 0x144976B4UL, 0xE622F5B7UL, 0xF5720643UL, 0x07198540UL,
        0x590AB964UL, 0xAB613A67UL, 0xB831C993UL, 0x4A5A4A90UL, 0x9E902E7BUL, 0x6CFBAD78UL, 0x7FAB5E8CUL, 0x8DC0DD8FUL,
        0xE330A81AUL, 0x115B2B19UL, 0x020BD8EDUL, 0xF0605BEEUL, 0x24AA3F05UL, 0xD6C1BC06UL, 0xC5914FF2UL, 0x37FACCF1UL,
        0x69E9F0D5UL, 0x9B8273D6UL, 0x88D28022UL, 0x7AB90321UL, 0xAE7367CAUL, 0x5C18E4C9UL, 0x4F48173DUL, 0xBD23943EUL,
        0xF36E6F75UL, 0x0105EC76UL, 0x12551F82UL, 0xE03E9C81UL, 0x34F4F86AUL, 0xC69F7B69UL, 0xD5CF889DUL, 0x27A40B9EUL,
        0x79B737BAUL, 0x8BDCB4B9UL, 0x988C474DUL, 0x6AE7C44EUL, 0xBE2DA0A5UL, 0x4C4623A6UL, 0x5F16D052UL, 0xAD7D5351UL,
    };
    return (crc >> ByteWidth) ^ Table[byte ^ (crc & ByteMask)];
}

/// Do not forget to apply the output XOR when done, or use transferCRCCompute().
UDPARD_PRIVATE uint32_t transferCRCAdd(const uint32_t crc, const size_t size, const void* const data)
{
    UDPARD_ASSERT((data != NULL) || (size == 0U));
    uint32_t      out = crc;
    const byte_t* p   = (const byte_t*) data;
    for (size_t i = 0; i < size; i++)
    {
        out = transferCRCAddByte(out, *p);
        ++p;
    }
    return out;
}

UDPARD_PRIVATE uint32_t transferCRCCompute(const size_t size, const void* const data)
{
    return transferCRCAdd(TRANSFER_CRC_INITIAL, size, data) ^ TRANSFER_CRC_OUTPUT_XOR;
}

// =====================================================================================================================
// =================================================  MEMORY RESOURCE  =================================================
// =====================================================================================================================

UDPARD_PRIVATE bool isValidMemoryResource(const UdpardMemoryResource* const memory)
{
    return (memory != NULL) && (memory->allocate != NULL) && (memory->free != NULL);
}

// =====================================================================================================================
// =================================================    TX PIPELINE    =================================================
// =====================================================================================================================

/// This is a subclass of UdpardTxItem. A pointer to this type can be cast to UdpardTxItem safely.
/// This is standard-compliant. The paragraph 6.7.2.1.15 says:
///     A pointer to a structure object, suitably converted, points to its initial member (or if that member is a
///     bit-field, then to the unit in which it resides), and vice versa. There may be unnamed padding within a
///     structure object, but not at its beginning.
typedef struct
{
    UdpardTxItem   base;
    UdpardPriority priority;  ///< Do we need this exposed in the public structure? We already have DSCP there.
    // The MISRA violation here is hard to get rid of without having to allocate a separate memory block for the
    // payload, which is much more costly risk-wise.
    byte_t payload_buffer[];  // NOSONAR MISRA C 18.7 Flexible array member.
} TxItem;

/// Chain of TX frames prepared for insertion into a TX queue.
typedef struct
{
    TxItem* head;
    TxItem* tail;
    size_t  count;
} TxChain;

UDPARD_PRIVATE TxItem* txNewItem(UdpardMemoryResource* const memory,
                                 const uint_least8_t         dscp_value_per_priority[UDPARD_PRIORITY_MAX + 1U],
                                 const UdpardMicrosecond     deadline_usec,
                                 const UdpardPriority        priority,
                                 const UdpardUDPIPEndpoint   endpoint,
                                 const size_t                datagram_payload_size,
                                 void* const                 user_transfer_reference)
{
    UDPARD_ASSERT(memory != NULL);
    TxItem* const out = (TxItem*) memory->allocate(memory, sizeof(TxItem) + datagram_payload_size);
    if (out != NULL)
    {
        // No tree linkage by default.
        out->base.base.up    = NULL;
        out->base.base.lr[0] = NULL;
        out->base.base.lr[1] = NULL;
        out->base.base.bf    = 0;
        // Init metadata.
        out->priority              = priority;
        out->base.next_in_transfer = NULL;  // Last by default.
        out->base.deadline_usec    = deadline_usec;
        UDPARD_ASSERT(priority <= UDPARD_PRIORITY_MAX);
        out->base.dscp                    = dscp_value_per_priority[priority];
        out->base.destination             = endpoint;
        out->base.user_transfer_reference = user_transfer_reference;
        // The payload points to the buffer already allocated.
        out->base.datagram_payload.size = datagram_payload_size;
        out->base.datagram_payload.data = &out->payload_buffer[0];
    }
    return out;
}

/// Frames with identical weight are processed in the FIFO order.
/// Frames with higher weight compare smaller (i.e., put on the left side of the tree).
UDPARD_PRIVATE int8_t txAVLPredicate(void* const user_reference,  // NOSONAR Cavl API requires pointer to non-const.
                                     const UdpardTreeNode* const node)
{
    const TxItem* const target = (const TxItem*) user_reference;
    const TxItem* const other  = (const TxItem*) (const void*) node;
    UDPARD_ASSERT((target != NULL) && (other != NULL));
    return (target->priority >= other->priority) ? +1 : -1;
}

/// The primitive serialization functions are endian-agnostic.
UDPARD_PRIVATE byte_t* txSerializeU16(byte_t* const destination_buffer, const uint16_t value)
{
    byte_t* p = destination_buffer;
    *p++      = (byte_t) (value & ByteMask);
    *p++      = (byte_t) ((byte_t) (value >> ByteWidth) & ByteMask);
    return p;
}

UDPARD_PRIVATE byte_t* txSerializeU32(byte_t* const destination_buffer, const uint32_t value)
{
    byte_t* p = destination_buffer;
    for (size_t i = 0; i < sizeof(value); i++)  // We sincerely hope that the compiler will use memcpy.
    {
        *p++ = (byte_t) ((byte_t) (value >> (i * ByteWidth)) & ByteMask);
    }
    return p;
}

UDPARD_PRIVATE byte_t* txSerializeU64(byte_t* const destination_buffer, const uint64_t value)
{
    byte_t* p = destination_buffer;
    for (size_t i = 0; i < sizeof(value); i++)  // We sincerely hope that the compiler will use memcpy.
    {
        *p++ = (byte_t) ((byte_t) (value >> (i * ByteWidth)) & ByteMask);
    }
    return p;
}

UDPARD_PRIVATE byte_t* txSerializeHeader(byte_t* const          destination_buffer,
                                         const TransferMetadata meta,
                                         const uint32_t         frame_index,
                                         const bool             end_of_transfer)
{
    byte_t* p = destination_buffer;
    *p++      = HEADER_VERSION;
    *p++      = (byte_t) meta.priority;
    p         = txSerializeU16(p, meta.src_node_id);
    p         = txSerializeU16(p, meta.dst_node_id);
    p         = txSerializeU16(p, meta.data_specifier);
    p         = txSerializeU64(p, meta.transfer_id);
    UDPARD_ASSERT((frame_index + 0UL) <= HEADER_FRAME_INDEX_MAX);  // +0UL is to avoid a compiler warning.
    p = txSerializeU32(p, frame_index | (end_of_transfer ? HEADER_FRAME_INDEX_EOT_MASK : 0U));
    p = txSerializeU16(p, 0);  // opaque user data
    // Header CRC in the big endian format. Optimization prospect: the header up to frame_index is constant in
    // multi-frame transfers, so we don't really need to recompute the CRC from scratch per frame.
    const uint16_t crc = headerCRCCompute(HEADER_SIZE_BYTES - HEADER_CRC_SIZE_BYTES, destination_buffer);
    *p++               = (byte_t) ((byte_t) (crc >> ByteWidth) & ByteMask);
    *p++               = (byte_t) (crc & ByteMask);
    UDPARD_ASSERT(p == (destination_buffer + HEADER_SIZE_BYTES));
    return p;
}

/// Produces a chain of Tx queue items for later insertion into the Tx queue. The tail is NULL if OOM.
/// The caller is responsible for freeing the memory allocated for the chain.
UDPARD_PRIVATE TxChain txMakeChain(UdpardMemoryResource* const memory,
                                   const uint_least8_t         dscp_value_per_priority[UDPARD_PRIORITY_MAX + 1U],
                                   const size_t                mtu,
                                   const UdpardMicrosecond     deadline_usec,
                                   const TransferMetadata      meta,
                                   const UdpardUDPIPEndpoint   endpoint,
                                   const UdpardConstPayload    payload,
                                   void* const                 user_transfer_reference)
{
    UDPARD_ASSERT(memory != NULL);
    UDPARD_ASSERT(mtu > 0);
    UDPARD_ASSERT((payload.data != NULL) || (payload.size == 0U));
    const size_t payload_size_with_crc = payload.size + TRANSFER_CRC_SIZE_BYTES;
    byte_t       crc_bytes[TRANSFER_CRC_SIZE_BYTES];
    txSerializeU32(crc_bytes, transferCRCCompute(payload.size, payload.data));
    TxChain out    = {NULL, NULL, 0};
    size_t  offset = 0U;
    while (offset < payload_size_with_crc)
    {
        TxItem* const tqi = txNewItem(memory,
                                      dscp_value_per_priority,
                                      deadline_usec,
                                      meta.priority,
                                      endpoint,
                                      smaller(payload_size_with_crc - offset, mtu) + HEADER_SIZE_BYTES,
                                      user_transfer_reference);
        if (NULL == out.head)
        {
            out.head = tqi;
        }
        else
        {
            // C std, 6.7.2.1.15: A pointer to a structure object <...> points to its initial member, and vice versa.
            // Can't just read tqi->base because tqi may be NULL; https://github.com/OpenCyphal/libcanard/issues/203.
            out.tail->base.next_in_transfer = (UdpardTxItem*) tqi;
        }
        out.tail = tqi;
        if (NULL == out.tail)
        {
            break;
        }
        const bool last      = (payload_size_with_crc - offset) <= mtu;
        byte_t*    write_ptr = txSerializeHeader(&tqi->payload_buffer[0], meta, (uint32_t) out.count, last);
        if (offset < payload.size)
        {
            const size_t progress = smaller(payload.size - offset, mtu);
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            (void) memcpy(write_ptr, ((const byte_t*) payload.data) + offset, progress);
            offset += progress;
            write_ptr += progress;
            UDPARD_ASSERT(offset <= payload.size);
            UDPARD_ASSERT((!last) || (offset == payload.size));
        }
        if (offset >= payload.size)
        {
            const size_t crc_offset = offset - payload.size;
            UDPARD_ASSERT(crc_offset < TRANSFER_CRC_SIZE_BYTES);
            const size_t available = tqi->base.datagram_payload.size - (size_t) (write_ptr - &tqi->payload_buffer[0]);
            UDPARD_ASSERT(available <= TRANSFER_CRC_SIZE_BYTES);
            const size_t write_size = smaller(TRANSFER_CRC_SIZE_BYTES - crc_offset, available);
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            (void) memcpy(write_ptr, &crc_bytes[crc_offset], write_size);
            offset += write_size;
        }
        UDPARD_ASSERT((out.count + 0ULL) < HEADER_FRAME_INDEX_MAX);  // +0 is to suppress warning.
        out.count++;
    }
    UDPARD_ASSERT((offset == payload_size_with_crc) || (out.tail == NULL));
    return out;
}

UDPARD_PRIVATE int32_t txPush(UdpardTx* const           tx,
                              const UdpardMicrosecond   deadline_usec,
                              const TransferMetadata    meta,
                              const UdpardUDPIPEndpoint endpoint,
                              const UdpardConstPayload  payload,
                              void* const               user_transfer_reference)
{
    UDPARD_ASSERT(tx != NULL);
    int32_t      out         = 0;  // The number of frames enqueued or negated error.
    const size_t mtu         = larger(tx->mtu, 1U);
    const size_t frame_count = ((payload.size + TRANSFER_CRC_SIZE_BYTES + mtu) - 1U) / mtu;
    UDPARD_ASSERT((frame_count > 0U) && ((frame_count + 0ULL) <= INT32_MAX));  // +0 is to suppress warning.
    const bool anonymous = (*tx->local_node_id) > UDPARD_NODE_ID_MAX;
    const bool service   = (meta.data_specifier & DATA_SPECIFIER_SERVICE_NOT_MESSAGE_MASK) != 0;
    if (anonymous && ((frame_count > 1) || service))
    {
        out = -UDPARD_ERROR_ANONYMOUS;  // Only single-frame message transfers can be anonymous.
    }
    else if ((tx->queue_size + frame_count) > tx->queue_capacity)
    {
        out = -UDPARD_ERROR_CAPACITY;  // Not enough space in the queue.
    }
    else
    {
        const TxChain chain = txMakeChain(tx->memory,
                                          tx->dscp_value_per_priority,
                                          mtu,
                                          deadline_usec,
                                          meta,
                                          endpoint,
                                          payload,
                                          user_transfer_reference);
        if (chain.tail != NULL)
        {
            UDPARD_ASSERT(frame_count == chain.count);
            UdpardTxItem* next = &chain.head->base;
            do
            {
                const UdpardTreeNode* const res =
                    cavlSearch(&tx->root, &next->base, &txAVLPredicate, &avlTrivialFactory);
                (void) res;
                UDPARD_ASSERT(res == &next->base);
                UDPARD_ASSERT(tx->root != NULL);
                next = next->next_in_transfer;
            } while (next != NULL);
            tx->queue_size += chain.count;
            UDPARD_ASSERT(tx->queue_size <= tx->queue_capacity);
            UDPARD_ASSERT((chain.count + 0ULL) <= INT32_MAX);  // +0 is to suppress warning.
            out = (int32_t) chain.count;
        }
        else  // The queue is large enough but we ran out of heap memory, so we have to unwind the chain.
        {
            out                = -UDPARD_ERROR_MEMORY;
            UdpardTxItem* head = &chain.head->base;
            while (head != NULL)
            {
                UdpardTxItem* const next = head->next_in_transfer;
                tx->memory->free(tx->memory, sizeof(TxItem) + head->datagram_payload.size, head);
                head = next;
            }
        }
    }
    UDPARD_ASSERT((out < 0) || (out >= 1));
    return out;
}

int8_t udpardTxInit(UdpardTx* const             self,
                    const UdpardNodeID* const   local_node_id,
                    const size_t                queue_capacity,
                    UdpardMemoryResource* const memory)
{
    int8_t ret = -UDPARD_ERROR_ARGUMENT;
    if ((NULL != self) && (NULL != local_node_id) && isValidMemoryResource(memory))
    {
        ret = 0;
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        (void) memset(self, 0, sizeof(*self));
        self->local_node_id  = local_node_id;
        self->queue_capacity = queue_capacity;
        self->mtu            = UDPARD_MTU_DEFAULT;
        // The DSCP mapping recommended by the Specification is all zeroes, so we don't need to set it.
        self->memory     = memory;
        self->queue_size = 0;
        self->root       = NULL;
    }
    return ret;
}

int32_t udpardTxPublish(UdpardTx* const          self,
                        const UdpardMicrosecond  deadline_usec,
                        const UdpardPriority     priority,
                        const UdpardPortID       subject_id,
                        UdpardTransferID* const  transfer_id,
                        const UdpardConstPayload payload,
                        void* const              user_transfer_reference)
{
    int32_t    out     = -UDPARD_ERROR_ARGUMENT;
    const bool args_ok = (self != NULL) && (self->local_node_id != NULL) && (priority <= UDPARD_PRIORITY_MAX) &&
                         (subject_id <= UDPARD_SUBJECT_ID_MAX) && (transfer_id != NULL) &&
                         ((payload.data != NULL) || (payload.size == 0U));
    if (args_ok)
    {
        out = txPush(self,
                     deadline_usec,
                     (TransferMetadata){
                         .priority       = priority,
                         .src_node_id    = *self->local_node_id,
                         .dst_node_id    = UDPARD_NODE_ID_UNSET,
                         .transfer_id    = *transfer_id,
                         .data_specifier = subject_id,
                     },
                     makeSubjectUDPIPEndpoint(subject_id),
                     payload,
                     user_transfer_reference);
        if (out > 0)
        {
            ++*transfer_id;
        }
    }
    return out;
}

int32_t udpardTxRequest(UdpardTx* const          self,
                        const UdpardMicrosecond  deadline_usec,
                        const UdpardPriority     priority,
                        const UdpardPortID       service_id,
                        const UdpardNodeID       server_node_id,
                        UdpardTransferID* const  transfer_id,
                        const UdpardConstPayload payload,
                        void* const              user_transfer_reference)
{
    int32_t    out     = -UDPARD_ERROR_ARGUMENT;
    const bool args_ok = (self != NULL) && (self->local_node_id != NULL) && (priority <= UDPARD_PRIORITY_MAX) &&
                         (service_id <= UDPARD_SERVICE_ID_MAX) && (server_node_id <= UDPARD_NODE_ID_MAX) &&
                         (transfer_id != NULL) && ((payload.data != NULL) || (payload.size == 0U));
    if (args_ok)
    {
        out = txPush(self,
                     deadline_usec,
                     (TransferMetadata){
                         .priority       = priority,
                         .src_node_id    = *self->local_node_id,
                         .dst_node_id    = server_node_id,
                         .transfer_id    = *transfer_id,
                         .data_specifier = DATA_SPECIFIER_SERVICE_NOT_MESSAGE_MASK |
                                           DATA_SPECIFIER_SERVICE_REQUEST_NOT_RESPONSE_MASK | service_id,
                     },
                     makeServiceUDPIPEndpoint(server_node_id),
                     payload,
                     user_transfer_reference);
        if (out > 0)
        {
            ++*transfer_id;
        }
    }
    return out;
}

int32_t udpardTxRespond(UdpardTx* const          self,
                        const UdpardMicrosecond  deadline_usec,
                        const UdpardPriority     priority,
                        const UdpardPortID       service_id,
                        const UdpardNodeID       client_node_id,
                        const UdpardTransferID   transfer_id,
                        const UdpardConstPayload payload,
                        void* const              user_transfer_reference)
{
    int32_t    out     = -UDPARD_ERROR_ARGUMENT;
    const bool args_ok = (self != NULL) && (self->local_node_id != NULL) && (priority <= UDPARD_PRIORITY_MAX) &&
                         (service_id <= UDPARD_SERVICE_ID_MAX) && (client_node_id <= UDPARD_NODE_ID_MAX) &&
                         ((payload.data != NULL) || (payload.size == 0U));
    if (args_ok)
    {
        out = txPush(self,
                     deadline_usec,
                     (TransferMetadata){
                         .priority       = priority,
                         .src_node_id    = *self->local_node_id,
                         .dst_node_id    = client_node_id,
                         .transfer_id    = transfer_id,
                         .data_specifier = DATA_SPECIFIER_SERVICE_NOT_MESSAGE_MASK | service_id,
                     },
                     makeServiceUDPIPEndpoint(client_node_id),
                     payload,
                     user_transfer_reference);
    }
    return out;
}

const UdpardTxItem* udpardTxPeek(const UdpardTx* const self)
{
    const UdpardTxItem* out = NULL;
    if (self != NULL)
    {
        // Paragraph 6.7.2.1.15 of the C standard says:
        //     A pointer to a structure object, suitably converted, points to its initial member, and vice versa.
        out = (const UdpardTxItem*) (void*) cavlFindExtremum(self->root, false);
    }
    return out;
}

UdpardTxItem* udpardTxPop(UdpardTx* const self, const UdpardTxItem* const item)
{
    UdpardTxItem* out = NULL;
    if ((self != NULL) && (item != NULL))
    {
        // Intentional violation of MISRA: casting away const qualifier. This is considered safe because the API
        // contract dictates that the pointer shall point to a mutable entity in RAM previously allocated by the
        // memory manager. It is difficult to avoid this cast in this context.
        out = (UdpardTxItem*) item;  // NOSONAR casting away const qualifier.
        // Paragraph 6.7.2.1.15 of the C standard says:
        //     A pointer to a structure object, suitably converted, points to its initial member, and vice versa.
        // Note that the highest-priority frame is always a leaf node in the AVL tree, which means that it is very
        // cheap to remove.
        cavlRemove(&self->root, &item->base);
        self->queue_size--;
    }
    return out;
}

void udpardTxFree(UdpardMemoryResource* const memory, UdpardTxItem* const item)
{
    if ((memory != NULL) && (item != NULL))
    {
        memory->free(memory, sizeof(TxItem) + item->datagram_payload.size, item);
    }
}
