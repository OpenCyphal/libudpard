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

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
#    error "Unsupported language: ISO C99 or a newer version is required."
#endif

// --------------------------------------------- COMMON DEFINITIONS ---------------------------------------------

typedef uint_least8_t byte_t;  ///< For compatibility with platforms where byte size is not 8 bits.

static const uint_fast8_t ByteWidth = 8U;
static const byte_t       ByteMask  = 0xFFU;

#define RX_SLOT_COUNT 2
#define TIMESTAMP_UNSET UINT64_MAX
#define FRAME_INDEX_UNSET UINT32_MAX
#define TRANSFER_ID_UNSET UINT64_MAX

typedef struct
{
    enum UdpardPriority priority;
    UdpardNodeID        src_node_id;
    UdpardNodeID        dst_node_id;
    uint16_t            data_specifier;
    UdpardTransferID    transfer_id;
} TransferMetadata;

#define DATA_SPECIFIER_SERVICE_NOT_MESSAGE_MASK 0x8000U
#define DATA_SPECIFIER_SERVICE_REQUEST_NOT_RESPONSE_MASK 0x4000U

#define HEADER_SIZE_BYTES 24U
#define HEADER_VERSION 1U
/// The frame index is a 31-bit unsigned integer. The most significant bit is used to indicate the end of transfer.
#define HEADER_FRAME_INDEX_EOT_MASK 0x80000000UL
#define HEADER_FRAME_INDEX_MAX 0x7FFFFFFFUL
#define HEADER_FRAME_INDEX_MASK HEADER_FRAME_INDEX_MAX

/// The port number is defined in the Cyphal/UDP Specification.
#define UDP_PORT 9382U

// See Cyphal/UDP Specification, section 4.3.2.1 Endpoints.
#define SUBJECT_MULTICAST_GROUP_ADDRESS_MASK 0xEF000000UL
#define SERVICE_MULTICAST_GROUP_ADDRESS_MASK 0xEF010000UL

static inline uint32_t makeSubjectIPGroupAddress(const UdpardPortID subject_id)
{
    return SUBJECT_MULTICAST_GROUP_ADDRESS_MASK | ((uint32_t) subject_id);
}

static inline uint32_t makeServiceIPGroupAddress(const UdpardNodeID destination_node_id)
{
    return SERVICE_MULTICAST_GROUP_ADDRESS_MASK | ((uint32_t) destination_node_id);
}

static inline struct UdpardUDPIPEndpoint makeSubjectUDPIPEndpoint(const UdpardPortID subject_id)
{
    return (struct UdpardUDPIPEndpoint){.ip_address = makeSubjectIPGroupAddress(subject_id),  //
                                        .udp_port   = UDP_PORT};
}

static inline struct UdpardUDPIPEndpoint makeServiceUDPIPEndpoint(const UdpardNodeID destination_node_id)
{
    return (struct UdpardUDPIPEndpoint){.ip_address = makeServiceIPGroupAddress(destination_node_id),
                                        .udp_port   = UDP_PORT};
}

/// Used for inserting new items into AVL trees. Refer to the documentation for cavlSearch() for details.
static inline struct UdpardTreeNode* avlTrivialFactory(void* const user_reference)
{
    return (struct UdpardTreeNode*) user_reference;
}

static inline size_t smaller(const size_t a, const size_t b)
{
    return (a < b) ? a : b;
}

static inline size_t larger(const size_t a, const size_t b)
{
    return (a > b) ? a : b;
}

static inline uint32_t max32(const uint32_t a, const uint32_t b)
{
    return (a > b) ? a : b;
}

/// Returns the sign of the subtraction of the operands; zero if equal. This is useful for AVL search.
static inline int_fast8_t compare32(const uint32_t a, const uint32_t b)
{
    int_fast8_t result = 0;
    if (a > b)
    {
        result = +1;
    }
    if (a < b)
    {
        result = -1;
    }
    return result;
}

static inline void* memAlloc(const struct UdpardMemoryResource memory, const size_t size)
{
    UDPARD_ASSERT(memory.allocate != NULL);
    return memory.allocate(memory.user_reference, size);
}

static inline void memFree(const struct UdpardMemoryResource memory, const size_t size, void* const data)
{
    UDPARD_ASSERT(memory.deallocate != NULL);
    memory.deallocate(memory.user_reference, size, data);
}

static inline void memFreePayload(const struct UdpardMemoryDeleter memory, const struct UdpardMutablePayload payload)
{
    UDPARD_ASSERT(memory.deallocate != NULL);
    memory.deallocate(memory.user_reference, payload.size, payload.data);
}

static inline void memZero(const size_t size, void* const data)
{
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    (void) memset(data, 0, size);
}

// --------------------------------------------- HEADER CRC ---------------------------------------------

#define HEADER_CRC_INITIAL 0xFFFFU
#define HEADER_CRC_RESIDUE 0x0000U
#define HEADER_CRC_SIZE_BYTES 2U

static inline uint16_t headerCRCAddByte(const uint16_t crc, const byte_t byte)
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

static inline uint16_t headerCRCCompute(const size_t size, const void* const data)
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
#define TRANSFER_CRC_RESIDUE_AFTER_OUTPUT_XOR (TRANSFER_CRC_RESIDUE_BEFORE_OUTPUT_XOR ^ TRANSFER_CRC_OUTPUT_XOR)
#define TRANSFER_CRC_SIZE_BYTES 4U

static inline uint32_t transferCRCAddByte(const uint32_t crc, const byte_t byte)
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
static inline uint32_t transferCRCAdd(const uint32_t crc, const size_t size, const void* const data)
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

static inline uint32_t transferCRCCompute(const size_t size, const void* const data)
{
    return transferCRCAdd(TRANSFER_CRC_INITIAL, size, data) ^ TRANSFER_CRC_OUTPUT_XOR;
}

// =====================================================================================================================
// =================================================    TX PIPELINE    =================================================
// =====================================================================================================================

/// This is a subclass of UdpardTxItem. A pointer to this type can be cast to UdpardTxItem safely.
/// This is compliant with the C99 standard; paragraph 6.7.2.1.15 says:
///     A pointer to a structure object, suitably converted, points to its initial member (or if that member is a
///     bit-field, then to the unit in which it resides), and vice versa. There may be unnamed padding within a
///     structure object, but not at its beginning.
typedef struct
{
    struct UdpardTxItem base;
    enum UdpardPriority priority;  ///< Do we need this exposed in the public structure? We already have DSCP there.
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

static inline TxItem* txNewItem(const struct UdpardMemoryResource memory,
                                const uint_least8_t               dscp_value_per_priority[UDPARD_PRIORITY_MAX + 1U],
                                const UdpardMicrosecond           deadline_usec,
                                const enum UdpardPriority         priority,
                                const struct UdpardUDPIPEndpoint  endpoint,
                                const size_t                      datagram_payload_size,
                                void* const                       user_transfer_reference)
{
    TxItem* const out = (TxItem*) memAlloc(memory, sizeof(TxItem) + datagram_payload_size);
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
static inline int_fast8_t txAVLPredicate(void* const user_reference,  // NOSONAR Cavl API requires pointer to non-const.
                                         const struct UdpardTreeNode* const node)
{
    const TxItem* const target = (const TxItem*) user_reference;
    const TxItem* const other  = (const TxItem*) (const void*) node;
    UDPARD_ASSERT((target != NULL) && (other != NULL));
    return (target->priority >= other->priority) ? +1 : -1;
}

/// The primitive serialization functions are endian-agnostic.
static inline byte_t* txSerializeU16(byte_t* const destination_buffer, const uint16_t value)
{
    byte_t* ptr = destination_buffer;
    *ptr++      = (byte_t) (value & ByteMask);
    *ptr++      = (byte_t) ((byte_t) (value >> ByteWidth) & ByteMask);
    return ptr;
}

static inline byte_t* txSerializeU32(byte_t* const destination_buffer, const uint32_t value)
{
    byte_t* ptr = destination_buffer;
    for (size_t i = 0; i < sizeof(value); i++)  // We sincerely hope that the compiler will use memcpy.
    {
        *ptr++ = (byte_t) ((byte_t) (value >> (i * ByteWidth)) & ByteMask);
    }
    return ptr;
}

static inline byte_t* txSerializeU64(byte_t* const destination_buffer, const uint64_t value)
{
    byte_t* ptr = destination_buffer;
    for (size_t i = 0; i < sizeof(value); i++)  // We sincerely hope that the compiler will use memcpy.
    {
        *ptr++ = (byte_t) ((byte_t) (value >> (i * ByteWidth)) & ByteMask);
    }
    return ptr;
}

static inline byte_t* txSerializeHeader(byte_t* const          destination_buffer,
                                        const TransferMetadata meta,
                                        const uint32_t         frame_index,
                                        const bool             end_of_transfer)
{
    byte_t* ptr = destination_buffer;
    *ptr++      = HEADER_VERSION;
    *ptr++      = (byte_t) meta.priority;
    ptr         = txSerializeU16(ptr, meta.src_node_id);
    ptr         = txSerializeU16(ptr, meta.dst_node_id);
    ptr         = txSerializeU16(ptr, meta.data_specifier);
    ptr         = txSerializeU64(ptr, meta.transfer_id);
    UDPARD_ASSERT((frame_index + 0UL) <= HEADER_FRAME_INDEX_MAX);  // +0UL is to avoid a compiler warning.
    ptr = txSerializeU32(ptr, frame_index | (end_of_transfer ? HEADER_FRAME_INDEX_EOT_MASK : 0U));
    ptr = txSerializeU16(ptr, 0);  // opaque user data
    // Header CRC in the big endian format. Optimization prospect: the header up to frame_index is constant in
    // multi-frame transfers, so we don't really need to recompute the CRC from scratch per frame.
    const uint16_t crc = headerCRCCompute(HEADER_SIZE_BYTES - HEADER_CRC_SIZE_BYTES, destination_buffer);
    *ptr++             = (byte_t) ((byte_t) (crc >> ByteWidth) & ByteMask);
    *ptr++             = (byte_t) (crc & ByteMask);
    UDPARD_ASSERT(ptr == (destination_buffer + HEADER_SIZE_BYTES));
    return ptr;
}

/// Produces a chain of Tx queue items for later insertion into the Tx queue. The tail is NULL if OOM.
/// The caller is responsible for freeing the memory allocated for the chain.
static inline TxChain txMakeChain(const struct UdpardMemoryResource memory,
                                  const uint_least8_t               dscp_value_per_priority[UDPARD_PRIORITY_MAX + 1U],
                                  const size_t                      mtu,
                                  const UdpardMicrosecond           deadline_usec,
                                  const TransferMetadata            meta,
                                  const struct UdpardUDPIPEndpoint  endpoint,
                                  const struct UdpardPayload        payload,
                                  void* const                       user_transfer_reference)
{
    UDPARD_ASSERT(mtu > 0);
    UDPARD_ASSERT((payload.data != NULL) || (payload.size == 0U));
    const size_t payload_size_with_crc = payload.size + TRANSFER_CRC_SIZE_BYTES;
    byte_t       crc_bytes[TRANSFER_CRC_SIZE_BYTES];
    txSerializeU32(crc_bytes, transferCRCCompute(payload.size, payload.data));
    TxChain out    = {NULL, NULL, 0};
    size_t  offset = 0U;
    while (offset < payload_size_with_crc)
    {
        TxItem* const item = txNewItem(memory,
                                       dscp_value_per_priority,
                                       deadline_usec,
                                       meta.priority,
                                       endpoint,
                                       smaller(payload_size_with_crc - offset, mtu) + HEADER_SIZE_BYTES,
                                       user_transfer_reference);
        if (NULL == out.head)
        {
            out.head = item;
        }
        else
        {
            // C std, 6.7.2.1.15: A pointer to a structure object <...> points to its initial member, and vice versa.
            // Can't just read tqi->base because tqi may be NULL; https://github.com/OpenCyphal/libcanard/issues/203.
            out.tail->base.next_in_transfer = (struct UdpardTxItem*) item;
        }
        out.tail = item;
        if (NULL == out.tail)
        {
            break;
        }
        const bool last      = (payload_size_with_crc - offset) <= mtu;
        byte_t*    write_ptr = txSerializeHeader(&item->payload_buffer[0], meta, (uint32_t) out.count, last);
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
            const size_t available = item->base.datagram_payload.size - (size_t) (write_ptr - &item->payload_buffer[0]);
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

static inline int32_t txPush(struct UdpardTx* const           tx,
                             const UdpardMicrosecond          deadline_usec,
                             const TransferMetadata           meta,
                             const struct UdpardUDPIPEndpoint endpoint,
                             const struct UdpardPayload       payload,
                             void* const                      user_transfer_reference)
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
            struct UdpardTxItem* next = &chain.head->base;
            do
            {
                const struct UdpardTreeNode* const res =
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
            out                       = -UDPARD_ERROR_MEMORY;
            struct UdpardTxItem* head = &chain.head->base;
            while (head != NULL)
            {
                struct UdpardTxItem* const next = head->next_in_transfer;
                memFree(tx->memory, sizeof(TxItem) + head->datagram_payload.size, head);
                head = next;
            }
        }
    }
    UDPARD_ASSERT((out < 0) || (out >= 1));
    return out;
}

int_fast8_t udpardTxInit(struct UdpardTx* const            self,
                         const UdpardNodeID* const         local_node_id,
                         const size_t                      queue_capacity,
                         const struct UdpardMemoryResource memory)
{
    int_fast8_t ret = -UDPARD_ERROR_ARGUMENT;
    if ((NULL != self) && (NULL != local_node_id) && (memory.allocate != NULL) && (memory.deallocate != NULL))
    {
        ret = 0;
        memZero(sizeof(*self), self);
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

int32_t udpardTxPublish(struct UdpardTx* const     self,
                        const UdpardMicrosecond    deadline_usec,
                        const enum UdpardPriority  priority,
                        const UdpardPortID         subject_id,
                        UdpardTransferID* const    transfer_id,
                        const struct UdpardPayload payload,
                        void* const                user_transfer_reference)
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
            ++(*transfer_id);
        }
    }
    return out;
}

int32_t udpardTxRequest(struct UdpardTx* const     self,
                        const UdpardMicrosecond    deadline_usec,
                        const enum UdpardPriority  priority,
                        const UdpardPortID         service_id,
                        const UdpardNodeID         server_node_id,
                        UdpardTransferID* const    transfer_id,
                        const struct UdpardPayload payload,
                        void* const                user_transfer_reference)
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
            ++(*transfer_id);
        }
    }
    return out;
}

int32_t udpardTxRespond(struct UdpardTx* const     self,
                        const UdpardMicrosecond    deadline_usec,
                        const enum UdpardPriority  priority,
                        const UdpardPortID         service_id,
                        const UdpardNodeID         client_node_id,
                        const UdpardTransferID     transfer_id,
                        const struct UdpardPayload payload,
                        void* const                user_transfer_reference)
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

const struct UdpardTxItem* udpardTxPeek(const struct UdpardTx* const self)
{
    const struct UdpardTxItem* out = NULL;
    if (self != NULL)
    {
        // Paragraph 6.7.2.1.15 of the C standard says:
        //     A pointer to a structure object, suitably converted, points to its initial member, and vice versa.
        out = (const struct UdpardTxItem*) (void*) cavlFindExtremum(self->root, false);
    }
    return out;
}

struct UdpardTxItem* udpardTxPop(struct UdpardTx* const self, const struct UdpardTxItem* const item)
{
    struct UdpardTxItem* out = NULL;
    if ((self != NULL) && (item != NULL))
    {
        // Intentional violation of MISRA: casting away const qualifier. This is considered safe because the API
        // contract dictates that the pointer shall point to a mutable entity in RAM previously allocated by the
        // memory manager. It is difficult to avoid this cast in this context.
        out = (struct UdpardTxItem*) item;  // NOSONAR casting away const qualifier.
        // Paragraph 6.7.2.1.15 of the C standard says:
        //     A pointer to a structure object, suitably converted, points to its initial member, and vice versa.
        // Note that the highest-priority frame is always a leaf node in the AVL tree, which means that it is very
        // cheap to remove.
        cavlRemove(&self->root, &item->base);
        UDPARD_ASSERT(self->queue_size > 0U);
        self->queue_size--;
    }
    return out;
}

void udpardTxFree(const struct UdpardMemoryResource memory, struct UdpardTxItem* const item)
{
    if (item != NULL)
    {
        memFree(memory, sizeof(TxItem) + item->datagram_payload.size, item);
    }
}

// =====================================================================================================================
// =================================================    RX PIPELINE    =================================================
// =====================================================================================================================

/// All but the transfer metadata.
typedef struct
{
    uint32_t                    index;
    bool                        end_of_transfer;
    struct UdpardPayload        payload;  ///< Also contains the transfer CRC (but not the header CRC).
    struct UdpardMutablePayload origin;   ///< The entirety of the free-able buffer passed from the application.
} RxFrameBase;

/// Full frame state.
typedef struct
{
    RxFrameBase      base;
    TransferMetadata meta;
} RxFrame;

/// The primitive deserialization functions are endian-agnostic.
static inline const byte_t* txDeserializeU16(const byte_t* const source_buffer, uint16_t* const out_value)
{
    UDPARD_ASSERT((source_buffer != NULL) && (out_value != NULL));
    const byte_t* ptr = source_buffer;
    *out_value        = *ptr;
    ptr++;
    *out_value |= (uint16_t) (((uint16_t) *ptr) << ByteWidth);
    ptr++;
    return ptr;
}

static inline const byte_t* txDeserializeU32(const byte_t* const source_buffer, uint32_t* const out_value)
{
    UDPARD_ASSERT((source_buffer != NULL) && (out_value != NULL));
    const byte_t* ptr = source_buffer;
    *out_value        = 0;
    for (size_t i = 0; i < sizeof(*out_value); i++)  // We sincerely hope that the compiler will use memcpy.
    {
        *out_value |= (uint32_t) ((uint32_t) *ptr << (i * ByteWidth));  // NOLINT(google-readability-casting) NOSONAR
        ptr++;
    }
    return ptr;
}

static inline const byte_t* txDeserializeU64(const byte_t* const source_buffer, uint64_t* const out_value)
{
    UDPARD_ASSERT((source_buffer != NULL) && (out_value != NULL));
    const byte_t* ptr = source_buffer;
    *out_value        = 0;
    for (size_t i = 0; i < sizeof(*out_value); i++)  // We sincerely hope that the compiler will use memcpy.
    {
        *out_value |= ((uint64_t) *ptr << (i * ByteWidth));
        ptr++;
    }
    return ptr;
}

/// This is roughly the inverse of the txSerializeHeader function, but it also handles the frame payload.
static inline bool rxParseFrame(const struct UdpardMutablePayload datagram_payload, RxFrame* const out)
{
    UDPARD_ASSERT((out != NULL) && (datagram_payload.data != NULL));
    out->base.origin = datagram_payload;
    bool ok          = false;
    if (datagram_payload.size > 0)  // HEADER_SIZE_BYTES may change in the future depending on the header version.
    {
        const byte_t*      ptr     = (const byte_t*) datagram_payload.data;
        const uint_fast8_t version = *ptr++;
        // The frame payload cannot be empty because every transfer has at least four bytes of CRC.
        if ((datagram_payload.size > HEADER_SIZE_BYTES) && (version == HEADER_VERSION) &&
            (headerCRCCompute(HEADER_SIZE_BYTES, datagram_payload.data) == HEADER_CRC_RESIDUE))
        {
            const uint_fast8_t priority = *ptr++;
            if (priority <= UDPARD_PRIORITY_MAX)
            {
                out->meta.priority        = (enum UdpardPriority) priority;
                ptr                       = txDeserializeU16(ptr, &out->meta.src_node_id);
                ptr                       = txDeserializeU16(ptr, &out->meta.dst_node_id);
                ptr                       = txDeserializeU16(ptr, &out->meta.data_specifier);
                ptr                       = txDeserializeU64(ptr, &out->meta.transfer_id);
                uint32_t index_eot        = 0;
                ptr                       = txDeserializeU32(ptr, &index_eot);
                out->base.index           = (uint32_t) (index_eot & HEADER_FRAME_INDEX_MASK);
                out->base.end_of_transfer = (index_eot & HEADER_FRAME_INDEX_EOT_MASK) != 0U;
                ptr += 2;  // Opaque user data.
                ptr += HEADER_CRC_SIZE_BYTES;
                out->base.payload.data = ptr;
                out->base.payload.size = datagram_payload.size - HEADER_SIZE_BYTES;
                ok                     = true;
                UDPARD_ASSERT((ptr == (((const byte_t*) datagram_payload.data) + HEADER_SIZE_BYTES)) &&
                              (out->base.payload.size > 0U));
            }
        }
        // Parsers for other header versions may be added here later.
    }
    if (ok)  // Version-agnostic semantics check.
    {
        UDPARD_ASSERT(out->base.payload.size > 0);  // Follows from the prior checks.
        const bool anonymous    = out->meta.src_node_id == UDPARD_NODE_ID_UNSET;
        const bool broadcast    = out->meta.dst_node_id == UDPARD_NODE_ID_UNSET;
        const bool service      = (out->meta.data_specifier & DATA_SPECIFIER_SERVICE_NOT_MESSAGE_MASK) != 0;
        const bool single_frame = (out->base.index == 0) && out->base.end_of_transfer;
        ok = service ? ((!broadcast) && (!anonymous)) : (broadcast && ((!anonymous) || single_frame));
    }
    return ok;
}

/// This helper is needed to minimize the risk of argument swapping when passing these two resources around,
/// as they almost always go side by side.
typedef struct
{
    struct UdpardMemoryResource fragment;
    struct UdpardMemoryDeleter  payload;
} RxMemory;

typedef struct
{
    struct UdpardTreeNode base;
    struct RxFragment* this;  // This is needed to avoid pointer arithmetic with multiple inheritance.
} RxFragmentTreeNode;

/// This is designed to be convertible to/from UdpardFragment, so that the application could be
/// given a linked list of these objects represented as a list of UdpardFragment.
typedef struct RxFragment
{
    struct UdpardFragment base;
    RxFragmentTreeNode    tree;
    uint32_t              frame_index;
} RxFragment;

/// Internally, the RX pipeline is arranged as follows:
///
/// - There is one port per subscription or an RPC-service listener. Within the port, there are N sessions,
///   one session per remote node emitting transfers on this port (i.e., on this subject, or sending
///   request/response of this service). Sessions are constructed dynamically in memory provided by
///   UdpardMemoryResource.
///
/// - Per session, there are UDPARD_NETWORK_INTERFACE_COUNT_MAX interface states to support interface redundancy.
///
/// - Per interface, there are RX_SLOT_COUNT slots; a slot keeps the state of a transfer in the process of being
///   reassembled which includes its payload fragments.
///
/// Port -> Session -> Interface -> Slot -> Fragments.
///
/// Consider the following examples, where A,B,C denote distinct multi-frame transfers:
///
///     A0 A1 A2 B0 B1 B2    -- two transfers without OOO frames; both accepted
///     A2 A0 A1 B0 B2 B1    -- two transfers with OOO frames; both accepted
///     A0 A1 B0 A2 B1 B2    -- two transfers with interleaved frames; both accepted (this is why we need 2 slots)
///     B1 A2 A0 C0 B0 A1 C1 -- B evicted by C; A and C accepted, B dropped (to accept B we would need 3 slots)
///     B0 A0 A1 C0 B1 A2 C1 -- ditto
///     A0 A1 C0 B0 A2 C1 B1 -- A evicted by B; B and C accepted, A dropped
///
/// In this implementation we postpone the implicit truncation until all fragments of a transfer are received.
/// Early truncation such that excess payload is not stored in memory at all is difficult to implement if
/// out-of-order reassembly is a requirement.
/// To implement early truncation with out-of-order reassembly, we need to deduce the MTU of the sender per transfer
/// (which is easy as we only need to take note of the payload size of any non-last frame of the transfer),
/// then, based on the MTU, determine the maximum frame index we should accept (higher indexes will be dropped);
/// then, for each fragment (i.e., frame) we need to compute the CRC (including those that are discarded).
/// At the end, when all frames have been observed, combine all CRCs to obtain the final transfer CRC
/// (this is possible because all common CRC functions are linear).
typedef struct
{
    UdpardMicrosecond   ts_usec;      ///< Timestamp of the earliest frame; TIMESTAMP_UNSET upon restart.
    UdpardTransferID    transfer_id;  ///< When first constructed, this shall be set to UINT64_MAX (unreachable value).
    uint32_t            max_index;    ///< Maximum observed frame index in this transfer (so far); zero upon restart.
    uint32_t            eot_index;    ///< Frame index where the EOT flag was observed; FRAME_INDEX_UNSET upon restart.
    uint32_t            accepted_frames;  ///< Number of frames accepted so far.
    size_t              payload_size;
    RxFragmentTreeNode* fragments;
} RxSlot;

typedef struct
{
    UdpardMicrosecond ts_usec;  ///< The timestamp of the last valid transfer to arrive on this interface.
    RxSlot            slots[RX_SLOT_COUNT];
} RxIface;

/// This type is forward-declared externally, hence why it has such a long name with the "udpard" prefix.
/// Keep in mind that we have a dedicated session object per remote node per port; this means that the states
/// kept here -- the timestamp and the transfer-ID -- are specific per remote node, as it should be.
struct UdpardInternalRxSession
{
    struct UdpardTreeNode base;
    /// The remote node-ID is needed here as this is the ordering/search key.
    UdpardNodeID remote_node_id;
    /// This shared state is used for redundant transfer deduplication.
    /// Redundancies occur as a result of the use of multiple network interfaces, spurious frame duplication along
    /// the network path, and trivial forward error correction through duplication (if used by the sender).
    UdpardMicrosecond last_ts_usec;
    UdpardTransferID  last_transfer_id;
    /// Each redundant interface maintains its own session state independently.
    /// The first interface to receive a transfer takes precedence, thus the redundant group always operates
    /// at the speed of the fastest interface. Duplicate transfers delivered by the slower interfaces are discarded.
    RxIface ifaces[UDPARD_NETWORK_INTERFACE_COUNT_MAX];
};

// --------------------------------------------------  RX FRAGMENT  --------------------------------------------------

/// Frees all fragments in the tree and their payload buffers. Destroys the passed fragment.
/// This is meant to be invoked on the root of the tree.
/// The maximum recursion depth is ceil(1.44*log2(FRAME_INDEX_MAX+1)-0.328) = 45 levels.
// NOLINTNEXTLINE(misc-no-recursion) MISRA C:2012 rule 17.2
static inline void rxFragmentDestroyTree(RxFragment* const self, const RxMemory memory)
{
    UDPARD_ASSERT(self != NULL);
    memFreePayload(memory.payload, self->base.origin);
    for (uint_fast8_t i = 0; i < 2; i++)
    {
        RxFragmentTreeNode* const child = (RxFragmentTreeNode*) self->tree.base.lr[i];
        if (child != NULL)
        {
            UDPARD_ASSERT(child->base.up == &self->tree.base);
            rxFragmentDestroyTree(child->this, memory);  // NOSONAR recursion
        }
    }
    memFree(memory.fragment, sizeof(RxFragment), self);  // self-destruct
}

/// Frees all fragments in the list and their payload buffers. Destroys the passed fragment.
/// This is meant to be invoked on the head of the list.
/// This function is needed because when a fragment tree is transformed into a list, the tree structure itself
/// is invalidated and cannot be used to free the fragments anymore.
static inline void rxFragmentDestroyList(struct UdpardFragment* const head, const RxMemory memory)
{
    struct UdpardFragment* handle = head;
    while (handle != NULL)
    {
        struct UdpardFragment* const next = handle->next;
        memFreePayload(memory.payload, handle->origin);  // May be NULL, is okay.
        memFree(memory.fragment, sizeof(RxFragment), handle);
        handle = next;
    }
}

// --------------------------------------------------  RX SLOT  --------------------------------------------------

static inline void rxSlotFree(RxSlot* const self, const RxMemory memory)
{
    UDPARD_ASSERT(self != NULL);
    if (self->fragments != NULL)
    {
        rxFragmentDestroyTree(self->fragments->this, memory);
        self->fragments = NULL;
    }
}

static inline void rxSlotRestart(RxSlot* const self, const UdpardTransferID transfer_id, const RxMemory memory)
{
    UDPARD_ASSERT(self != NULL);
    rxSlotFree(self, memory);
    self->ts_usec         = TIMESTAMP_UNSET;  // Will be assigned when the first frame of the transfer has arrived.
    self->transfer_id     = transfer_id;
    self->max_index       = 0;
    self->eot_index       = FRAME_INDEX_UNSET;
    self->accepted_frames = 0;
    self->payload_size    = 0;
}

/// This is a helper for rxSlotRestart that restarts the transfer for the next transfer-ID value.
/// The transfer-ID increment is necessary to weed out duplicate transfers.
static inline void rxSlotRestartAdvance(RxSlot* const self, const RxMemory memory)
{
    rxSlotRestart(self, self->transfer_id + 1U, memory);
}

typedef struct
{
    uint32_t                    frame_index;
    bool                        accepted;
    struct UdpardMemoryResource memory_fragment;
} RxSlotUpdateContext;

static inline int_fast8_t rxSlotFragmentSearch(void* const user_reference,  // NOSONAR Cavl API requires non-const.
                                               const struct UdpardTreeNode* node)
{
    UDPARD_ASSERT((user_reference != NULL) && (node != NULL));
    return compare32(((const RxSlotUpdateContext*) user_reference)->frame_index,
                     ((const RxFragmentTreeNode*) node)->this->frame_index);
}

static inline struct UdpardTreeNode* rxSlotFragmentFactory(void* const user_reference)
{
    RxSlotUpdateContext* const ctx = (RxSlotUpdateContext*) user_reference;
    UDPARD_ASSERT((ctx != NULL) && (ctx->memory_fragment.allocate != NULL) &&
                  (ctx->memory_fragment.deallocate != NULL));
    struct UdpardTreeNode* out  = NULL;
    RxFragment* const      frag = memAlloc(ctx->memory_fragment, sizeof(RxFragment));
    if (frag != NULL)
    {
        memZero(sizeof(RxFragment), frag);
        out               = &frag->tree.base;  // this is not an escape bug, we retain the pointer via "this"
        frag->frame_index = ctx->frame_index;
        frag->tree.this   = frag;  // <-- right here, see?
        ctx->accepted     = true;
    }
    return out;  // OOM handled by the caller
}

/// States outliving each level of recursion while ejecting the transfer from the fragment tree.
typedef struct
{
    struct UdpardFragment* head;  // Points to the first fragment in the list.
    struct UdpardFragment* predecessor;
    uint32_t               crc;
    size_t                 retain_size;
    size_t                 offset;
    RxMemory               memory;
} RxSlotEjectContext;

/// See rxSlotEject() for details.
/// The maximum recursion depth is ceil(1.44*log2(FRAME_INDEX_MAX+1)-0.328) = 45 levels.
/// NOLINTNEXTLINE(misc-no-recursion) MISRA C:2012 rule 17.2
static inline void rxSlotEjectFragment(RxFragment* const frag, RxSlotEjectContext* const ctx)
{
    UDPARD_ASSERT((frag != NULL) && (ctx != NULL));
    if (frag->tree.base.lr[0] != NULL)
    {
        RxFragment* const child = ((RxFragmentTreeNode*) frag->tree.base.lr[0])->this;
        UDPARD_ASSERT(child->frame_index < frag->frame_index);
        UDPARD_ASSERT(child->tree.base.up == &frag->tree.base);
        rxSlotEjectFragment(child, ctx);  // NOSONAR recursion
    }
    const size_t fragment_size = frag->base.view.size;
    frag->base.next            = NULL;  // Default state; may be overwritten.
    ctx->crc                   = transferCRCAdd(ctx->crc, fragment_size, frag->base.view.data);
    // Truncate unnecessary payload past the specified limit. This enforces the extent and removes the transfer CRC.
    const bool retain = ctx->offset < ctx->retain_size;
    if (retain)
    {
        UDPARD_ASSERT(ctx->retain_size >= ctx->offset);
        ctx->head            = (ctx->head == NULL) ? &frag->base : ctx->head;
        frag->base.view.size = smaller(frag->base.view.size, ctx->retain_size - ctx->offset);
        if (ctx->predecessor != NULL)
        {
            ctx->predecessor->next = &frag->base;
        }
        ctx->predecessor = &frag->base;
    }
    // Adjust the offset of the next fragment and descend into it. Keep the sub-tree alive for now even if not needed.
    ctx->offset += fragment_size;
    if (frag->tree.base.lr[1] != NULL)
    {
        RxFragment* const child = ((RxFragmentTreeNode*) frag->tree.base.lr[1])->this;
        UDPARD_ASSERT(child->frame_index > frag->frame_index);
        UDPARD_ASSERT(child->tree.base.up == &frag->tree.base);
        rxSlotEjectFragment(child, ctx);  // NOSONAR recursion
    }
    // Drop the unneeded fragments and their handles after the sub-tree is fully traversed.
    if (!retain)
    {
        memFreePayload(ctx->memory.payload, frag->base.origin);
        memFree(ctx->memory.fragment, sizeof(RxFragment), frag);
    }
}

/// This function finalizes the fragmented transfer payload by doing multiple things in one pass through the tree:
///
/// - Compute the transfer-CRC. The caller should verify the result.
/// - Build a linked list of fragments ordered by frame index, as the application would expect it.
/// - Truncate the payload according to the specified size limit.
/// - Free the tree nodes and their payload buffers past the size limit.
///
/// It is guaranteed that the output list is sorted by frame index. It may be empty.
/// After this function is invoked, the tree will be destroyed and cannot be used anymore;
/// hence, in the event of invalid transfer being received (bad CRC), the fragments will have to be freed
/// by traversing the linked list instead of the tree.
///
/// The payload shall contain at least the transfer CRC, so the minimum size is TRANSFER_CRC_SIZE_BYTES.
/// There shall be at least one fragment (because a Cyphal transfer contains at least one frame).
///
/// The return value indicates whether the transfer is valid (CRC is correct).
static inline bool rxSlotEject(size_t* const                out_payload_size,
                               struct UdpardFragment* const out_payload_head,
                               RxFragmentTreeNode* const    fragment_tree,
                               const size_t                 received_total_size,  // With CRC.
                               const size_t                 extent,
                               const RxMemory               memory)
{
    UDPARD_ASSERT((received_total_size >= TRANSFER_CRC_SIZE_BYTES) && (fragment_tree != NULL) &&
                  (out_payload_size != NULL) && (out_payload_head != NULL));
    bool               result    = false;
    RxSlotEjectContext eject_ctx = {
        .head        = NULL,
        .predecessor = NULL,
        .crc         = TRANSFER_CRC_INITIAL,
        .retain_size = smaller(received_total_size - TRANSFER_CRC_SIZE_BYTES, extent),
        .offset      = 0,
        .memory      = memory,
    };
    rxSlotEjectFragment(fragment_tree->this, &eject_ctx);
    UDPARD_ASSERT(eject_ctx.offset == received_total_size);  // Ensure we have traversed the entire tree.
    if (TRANSFER_CRC_RESIDUE_BEFORE_OUTPUT_XOR == eject_ctx.crc)
    {
        result            = true;
        *out_payload_size = eject_ctx.retain_size;
        *out_payload_head = (eject_ctx.head != NULL)
                                ? (*eject_ctx.head)  // Slice off the derived type fields as they are not needed.
                                : (struct UdpardFragment){.next = NULL, .view = {0, NULL}, .origin = {0, NULL}};
        // This is the single-frame transfer optimization suggested by Scott: we free the first fragment handle
        // early by moving the contents into the rx_transfer structure by value.
        // No need to free the payload buffer because it has been transferred to the transfer.
        memFree(memory.fragment, sizeof(RxFragment), eject_ctx.head);  // May be empty.
    }
    else  // The transfer turned out to be invalid. We have to free the fragments. Can't use the tree anymore.
    {
        rxFragmentDestroyList(eject_ctx.head, memory);
    }
    return result;
}

/// Update the frame count discovery state in this transfer.
/// Returns true on success, false if inconsistencies are detected and the slot should be restarted.
static inline bool rxSlotAccept_UpdateFrameCount(RxSlot* const self, const RxFrameBase frame)
{
    UDPARD_ASSERT((self != NULL) && (frame.payload.size > 0));
    bool ok         = true;
    self->max_index = max32(self->max_index, frame.index);
    if (frame.end_of_transfer)
    {
        if ((self->eot_index != FRAME_INDEX_UNSET) && (self->eot_index != frame.index))
        {
            ok = false;  // Inconsistent EOT flag, could be a node-ID conflict.
        }
        self->eot_index = frame.index;
    }
    UDPARD_ASSERT(frame.index <= self->max_index);
    if (self->max_index > self->eot_index)
    {
        ok = false;  // Frames past EOT found, discard the entire transfer because we don't trust it anymore.
    }
    return ok;
}

/// Insert the fragment into the fragment tree. If it already exists, drop and free the duplicate.
/// Returns 0 if the fragment is not needed, 1 if it is needed, negative on error.
/// The fragment shall be deallocated unless the return value is 1.
static inline int_fast8_t rxSlotAccept_InsertFragment(RxSlot* const     self,
                                                      const RxFrameBase frame,
                                                      const RxMemory    memory)
{
    UDPARD_ASSERT((self != NULL) && (frame.payload.size > 0) && (self->max_index <= self->eot_index) &&
                  (self->accepted_frames <= self->eot_index));
    RxSlotUpdateContext       update_ctx = {.frame_index     = frame.index,
                                            .accepted        = false,
                                            .memory_fragment = memory.fragment};
    RxFragmentTreeNode* const frag   = (RxFragmentTreeNode*) cavlSearch((struct UdpardTreeNode**) &self->fragments,  //
                                                                      &update_ctx,
                                                                      &rxSlotFragmentSearch,
                                                                      &rxSlotFragmentFactory);
    int_fast8_t               result = update_ctx.accepted ? 1 : 0;
    if (frag == NULL)
    {
        UDPARD_ASSERT(!update_ctx.accepted);
        result = -UDPARD_ERROR_MEMORY;
        // No restart because there is hope that there will be enough memory when we receive a duplicate.
    }
    UDPARD_ASSERT(self->max_index <= self->eot_index);
    if (update_ctx.accepted)
    {
        UDPARD_ASSERT((result > 0) && (frag->this->frame_index == frame.index));
        frag->this->base.view   = frame.payload;
        frag->this->base.origin = frame.origin;
        self->payload_size += frame.payload.size;
        self->accepted_frames++;
    }
    return result;
}

/// Detect transfer completion. If complete, eject the payload from the fragment tree and check its CRC.
/// The return value is passed over from rxSlotEject.
static inline int_fast8_t rxSlotAccept_FinalizeMaybe(RxSlot* const                self,
                                                     size_t* const                out_transfer_payload_size,
                                                     struct UdpardFragment* const out_transfer_payload_head,
                                                     const size_t                 extent,
                                                     const RxMemory               memory)
{
    UDPARD_ASSERT((self != NULL) && (out_transfer_payload_size != NULL) && (out_transfer_payload_head != NULL) &&
                  (self->fragments != NULL));
    int_fast8_t result = 0;
    if (self->accepted_frames > self->eot_index)  // Mind the off-by-one: cardinal vs. ordinal.
    {
        if (self->payload_size >= TRANSFER_CRC_SIZE_BYTES)
        {
            result = rxSlotEject(out_transfer_payload_size,
                                 out_transfer_payload_head,
                                 self->fragments,
                                 self->payload_size,
                                 extent,
                                 memory)
                         ? 1
                         : 0;
            // The tree is now unusable and the data is moved into rx_transfer.
            self->fragments = NULL;
        }
        rxSlotRestartAdvance(self, memory);  // Restart needed even if invalid.
    }
    return result;
}

/// This function will either move the frame payload into the session, or free it if it can't be used.
/// Upon return, certain state fields may be overwritten, so the caller should not rely on them.
/// Returns: 1 -- transfer available, payload written; 0 -- transfer not yet available; <0 -- error.
static inline int_fast8_t rxSlotAccept(RxSlot* const                self,
                                       size_t* const                out_transfer_payload_size,
                                       struct UdpardFragment* const out_transfer_payload_head,
                                       const RxFrameBase            frame,
                                       const size_t                 extent,
                                       const RxMemory               memory)
{
    UDPARD_ASSERT((self != NULL) && (frame.payload.size > 0) && (out_transfer_payload_size != NULL) &&
                  (out_transfer_payload_head != NULL));
    int_fast8_t result  = 0;
    bool        release = true;
    if (rxSlotAccept_UpdateFrameCount(self, frame))
    {
        result = rxSlotAccept_InsertFragment(self, frame, memory);
        UDPARD_ASSERT(result <= 1);
        if (result > 0)
        {
            release = false;
            result  = rxSlotAccept_FinalizeMaybe(self,  //
                                                out_transfer_payload_size,
                                                out_transfer_payload_head,
                                                extent,
                                                memory);
        }
    }
    else
    {
        rxSlotRestartAdvance(self, memory);
    }
    if (release)
    {
        memFreePayload(memory.payload, frame.origin);
    }
    UDPARD_ASSERT(result <= 1);
    return result;
}

// --------------------------------------------------  RX IFACE  --------------------------------------------------

/// Whether the supplied transfer-ID is greater than all transfer-IDs in the RX slots.
/// This indicates that the new transfer is not a duplicate and should be accepted.
static inline bool rxIfaceIsFutureTransferID(const RxIface* const self, const UdpardTransferID transfer_id)
{
    bool is_future_tid = true;
    for (uint_fast8_t i = 0; i < RX_SLOT_COUNT; i++)  // Expected to be unrolled by the compiler.
    {
        is_future_tid = is_future_tid && ((self->slots[i].transfer_id < transfer_id) ||
                                          (self->slots[i].transfer_id == TRANSFER_ID_UNSET));
    }
    return is_future_tid;
}

/// Whether the time that has passed since the last accepted first frame of a transfer exceeds the TID timeout.
/// This indicates that the transfer should be accepted even if its transfer-ID is not greater than all transfer-IDs
/// in the RX slots.
static inline bool rxIfaceCheckTransferIDTimeout(const RxIface* const    self,
                                                 const UdpardMicrosecond ts_usec,
                                                 const UdpardMicrosecond transfer_id_timeout_usec)
{
    // We use the RxIface state here because the RxSlot state is reset between transfers.
    // If there is reassembly in progress, we want to use the timestamps from these in-progress transfers,
    // as that eliminates the risk of a false-positive TID-timeout detection.
    UdpardMicrosecond most_recent_ts_usec = self->ts_usec;
    for (uint_fast8_t i = 0; i < RX_SLOT_COUNT; i++)  // Expected to be unrolled by the compiler.
    {
        if ((most_recent_ts_usec == TIMESTAMP_UNSET) ||
            ((self->slots[i].ts_usec != TIMESTAMP_UNSET) && (self->slots[i].ts_usec > most_recent_ts_usec)))
        {
            most_recent_ts_usec = self->slots[i].ts_usec;
        }
    }
    return (most_recent_ts_usec == TIMESTAMP_UNSET) ||
           ((ts_usec >= most_recent_ts_usec) && ((ts_usec - most_recent_ts_usec) >= transfer_id_timeout_usec));
}

/// Traverses the list of slots trying to find a slot with a matching transfer-ID that is already IN PROGRESS.
/// If there is no such slot, tries again without the IN PROGRESS requirement.
/// The purpose of this complicated dual check is to support the case where multiple slots have the same
/// transfer-ID, which may occur with interleaved transfers.
static inline RxSlot* rxIfaceFindMatchingSlot(RxSlot slots[RX_SLOT_COUNT], const UdpardTransferID transfer_id)
{
    RxSlot* slot = NULL;
    for (uint_fast8_t i = 0; i < RX_SLOT_COUNT; i++)
    {
        if ((slots[i].transfer_id == transfer_id) && (slots[i].ts_usec != TIMESTAMP_UNSET))
        {
            slot = &slots[i];
            break;
        }
    }
    if (slot == NULL)
    {
        for (uint_fast8_t i = 0; i < RX_SLOT_COUNT; i++)
        {
            if (slots[i].transfer_id == transfer_id)
            {
                slot = &slots[i];
                break;
            }
        }
    }
    return slot;
}

/// This function is invoked when a new datagram pertaining to a certain session is received on an interface.
/// This function will either move the frame payload into the session, or free it if it cannot be made use of.
/// Returns: 1 -- transfer available; 0 -- transfer not yet available; <0 -- error.
static inline int_fast8_t rxIfaceAccept(RxIface* const                 self,
                                        const UdpardMicrosecond        ts_usec,
                                        const RxFrame                  frame,
                                        const size_t                   extent,
                                        const UdpardMicrosecond        transfer_id_timeout_usec,
                                        const RxMemory                 memory,
                                        struct UdpardRxTransfer* const out_transfer)
{
    UDPARD_ASSERT((self != NULL) && (frame.base.payload.size > 0) && (out_transfer != NULL));
    RxSlot* slot = rxIfaceFindMatchingSlot(self->slots, frame.meta.transfer_id);
    // If there is no suitable slot, we should check if the transfer is a future one (high transfer-ID),
    // or a transfer-ID timeout has occurred. In this case we sacrifice the oldest slot.
    if (slot == NULL)
    {
        // The timestamp is UNSET when the slot is waiting for the next transfer.
        // Such slots are the best candidates for replacement because reusing them does not cause loss of
        // transfers that are in the process of being reassembled. If there are no such slots, we must
        // sacrifice the one whose first frame has arrived the longest time ago.
        RxSlot* victim = &self->slots[0];
        for (uint_fast8_t i = 0; i < RX_SLOT_COUNT; i++)  // Expected to be unrolled by the compiler.
        {
            if ((self->slots[i].ts_usec == TIMESTAMP_UNSET) ||
                ((victim->ts_usec != TIMESTAMP_UNSET) && (self->slots[i].ts_usec < victim->ts_usec)))
            {
                victim = &self->slots[i];
            }
        }
        if (rxIfaceIsFutureTransferID(self, frame.meta.transfer_id) ||
            rxIfaceCheckTransferIDTimeout(self, ts_usec, transfer_id_timeout_usec))
        {
            rxSlotRestart(victim, frame.meta.transfer_id, memory);
            slot = victim;
            UDPARD_ASSERT(slot != NULL);
        }
    }
    // If there is a suitable slot (perhaps a newly created one for this frame), update it.
    // If there is neither a suitable slot nor a new one was created, the frame cannot be used.
    int_fast8_t result = 0;
    if (slot != NULL)
    {
        if (slot->ts_usec == TIMESTAMP_UNSET)
        {
            slot->ts_usec = ts_usec;  // Transfer timestamp is the timestamp of the earliest frame.
        }
        const UdpardMicrosecond ts = slot->ts_usec;
        UDPARD_ASSERT(slot->transfer_id == frame.meta.transfer_id);
        result = rxSlotAccept(slot,  // May invalidate state variables such as timestamp or transfer-ID.
                              &out_transfer->payload_size,
                              &out_transfer->payload,
                              frame.base,
                              extent,
                              memory);
        if (result > 0)  // Transfer successfully received, populate the transfer descriptor for the client.
        {
            self->ts_usec                = ts;  // Update the last valid transfer timestamp on this iface.
            out_transfer->timestamp_usec = ts;
            out_transfer->priority       = frame.meta.priority;
            out_transfer->source_node_id = frame.meta.src_node_id;
            out_transfer->transfer_id    = frame.meta.transfer_id;
        }
    }
    else
    {
        memFreePayload(memory.payload, frame.base.origin);
    }
    return result;
}

static inline void rxIfaceInit(RxIface* const self, const RxMemory memory)
{
    UDPARD_ASSERT(self != NULL);
    memZero(sizeof(*self), self);
    self->ts_usec = TIMESTAMP_UNSET;
    for (uint_fast8_t i = 0; i < RX_SLOT_COUNT; i++)
    {
        self->slots[i].fragments = NULL;
        rxSlotRestart(&self->slots[i], TRANSFER_ID_UNSET, memory);
    }
}

/// Frees the iface and all slots in it. The iface instance itself is not freed.
static inline void rxIfaceFree(RxIface* const self, const RxMemory memory)
{
    UDPARD_ASSERT(self != NULL);
    for (uint_fast8_t i = 0; i < RX_SLOT_COUNT; i++)
    {
        rxSlotFree(&self->slots[i], memory);
    }
}

// --------------------------------------------------  RX SESSION  --------------------------------------------------

/// Checks if the given transfer should be accepted. If not, the transfer is freed.
/// Internal states are updated.
static inline bool rxSessionDeduplicate(struct UdpardInternalRxSession* const self,
                                        const UdpardMicrosecond               transfer_id_timeout_usec,
                                        struct UdpardRxTransfer* const        transfer,
                                        const RxMemory                        memory)
{
    UDPARD_ASSERT((self != NULL) && (transfer != NULL));
    const bool future_tid = (self->last_transfer_id == TRANSFER_ID_UNSET) ||  //
                            (transfer->transfer_id > self->last_transfer_id);
    const bool tid_timeout = (self->last_ts_usec == TIMESTAMP_UNSET) ||
                             ((transfer->timestamp_usec >= self->last_ts_usec) &&
                              ((transfer->timestamp_usec - self->last_ts_usec) >= transfer_id_timeout_usec));
    const bool accept = future_tid || tid_timeout;
    if (accept)
    {
        self->last_ts_usec     = transfer->timestamp_usec;
        self->last_transfer_id = transfer->transfer_id;
    }
    else  // This is a duplicate: received from another interface, a FEC retransmission, or a network glitch.
    {
        memFreePayload(memory.payload, transfer->payload.origin);
        rxFragmentDestroyList(transfer->payload.next, memory);
        transfer->payload_size = 0;
        transfer->payload      = (struct UdpardFragment){.next   = NULL,
                                                         .view   = {.size = 0, .data = NULL},
                                                         .origin = {.size = 0, .data = NULL}};
    }
    return accept;
}

/// Takes ownership of the frame payload buffer.
static inline int_fast8_t rxSessionAccept(struct UdpardInternalRxSession* const self,
                                          const uint_fast8_t                    redundant_iface_index,
                                          const UdpardMicrosecond               ts_usec,
                                          const RxFrame                         frame,
                                          const size_t                          extent,
                                          const UdpardMicrosecond               transfer_id_timeout_usec,
                                          const RxMemory                        memory,
                                          struct UdpardRxTransfer* const        out_transfer)
{
    UDPARD_ASSERT((self != NULL) && (redundant_iface_index < UDPARD_NETWORK_INTERFACE_COUNT_MAX) &&
                  (out_transfer != NULL));
    int_fast8_t result = rxIfaceAccept(&self->ifaces[redundant_iface_index],
                                       ts_usec,
                                       frame,
                                       extent,
                                       transfer_id_timeout_usec,
                                       memory,
                                       out_transfer);
    UDPARD_ASSERT(result <= 1);
    if (result > 0)
    {
        result = rxSessionDeduplicate(self, transfer_id_timeout_usec, out_transfer, memory) ? 1 : 0;
    }
    return result;
}

static inline void rxSessionInit(struct UdpardInternalRxSession* const self, const RxMemory memory)
{
    UDPARD_ASSERT(self != NULL);
    memZero(sizeof(*self), self);
    self->remote_node_id   = UDPARD_NODE_ID_UNSET;
    self->last_ts_usec     = TIMESTAMP_UNSET;
    self->last_transfer_id = TRANSFER_ID_UNSET;
    for (uint_fast8_t i = 0; i < UDPARD_NETWORK_INTERFACE_COUNT_MAX; i++)
    {
        rxIfaceInit(&self->ifaces[i], memory);
    }
}

/// Frees all ifaces in the session, all children in the session tree recursively, and destroys the session itself.
/// The maximum recursion depth is ceil(1.44*log2(UDPARD_NODE_ID_MAX+1)-0.328) = 23 levels.
// NOLINTNEXTLINE(*-no-recursion) MISRA C:2012 rule 17.2
static inline void rxSessionDestroyTree(struct UdpardInternalRxSession* const self,
                                        const struct UdpardRxMemoryResources  memory)
{
    for (uint_fast8_t i = 0; i < UDPARD_NETWORK_INTERFACE_COUNT_MAX; i++)
    {
        rxIfaceFree(&self->ifaces[i], (RxMemory){.fragment = memory.fragment, .payload = memory.payload});
    }
    for (uint_fast8_t i = 0; i < 2; i++)
    {
        struct UdpardInternalRxSession* const child = (struct UdpardInternalRxSession*) (void*) self->base.lr[i];
        if (child != NULL)
        {
            UDPARD_ASSERT(child->base.up == &self->base);
            rxSessionDestroyTree(child, memory);  // NOSONAR recursion
        }
    }
    memFree(memory.session, sizeof(struct UdpardInternalRxSession), self);
}

// --------------------------------------------------  RX PORT  --------------------------------------------------

typedef struct
{
    UdpardNodeID                   remote_node_id;
    struct UdpardRxMemoryResources memory;
} RxPortSessionSearchContext;

static inline int_fast8_t rxPortSessionSearch(void* const                  user_reference,  // NOSONAR non-const API
                                              const struct UdpardTreeNode* node)
{
    UDPARD_ASSERT((user_reference != NULL) && (node != NULL));
    return compare32(((const RxPortSessionSearchContext*) user_reference)->remote_node_id,
                     ((const struct UdpardInternalRxSession*) (const void*) node)->remote_node_id);
}

static inline struct UdpardTreeNode* rxPortSessionFactory(void* const user_reference)  // NOSONAR non-const API
{
    const RxPortSessionSearchContext* const ctx = (const RxPortSessionSearchContext*) user_reference;
    UDPARD_ASSERT((ctx != NULL) && (ctx->remote_node_id <= UDPARD_NODE_ID_MAX));
    struct UdpardTreeNode*                out = NULL;
    struct UdpardInternalRxSession* const session =
        memAlloc(ctx->memory.session, sizeof(struct UdpardInternalRxSession));
    if (session != NULL)
    {
        rxSessionInit(session, (RxMemory){.payload = ctx->memory.payload, .fragment = ctx->memory.fragment});
        session->remote_node_id = ctx->remote_node_id;
        out                     = &session->base;
    }
    return out;  // OOM handled by the caller
}

/// Accepts a frame into a port, possibly creating a new session along the way.
/// The frame shall not be anonymous. Takes ownership of the frame payload buffer.
static inline int_fast8_t rxPortAccept(struct UdpardRxPort* const           self,
                                       const uint_fast8_t                   redundant_iface_index,
                                       const UdpardMicrosecond              ts_usec,
                                       const RxFrame                        frame,
                                       const struct UdpardRxMemoryResources memory,
                                       struct UdpardRxTransfer* const       out_transfer)
{
    UDPARD_ASSERT((self != NULL) && (redundant_iface_index < UDPARD_NETWORK_INTERFACE_COUNT_MAX) &&
                  (out_transfer != NULL) && (frame.meta.src_node_id != UDPARD_NODE_ID_UNSET));
    int_fast8_t                           result  = 0;
    struct UdpardInternalRxSession* const session = (struct UdpardInternalRxSession*) (void*)
        cavlSearch((struct UdpardTreeNode**) &self->sessions,
                   &(RxPortSessionSearchContext){.remote_node_id = frame.meta.src_node_id, .memory = memory},
                   &rxPortSessionSearch,
                   &rxPortSessionFactory);
    if (session != NULL)
    {
        UDPARD_ASSERT(session->remote_node_id == frame.meta.src_node_id);
        result = rxSessionAccept(session,  // The callee takes ownership of the memory.
                                 redundant_iface_index,
                                 ts_usec,
                                 frame,
                                 self->extent,
                                 self->transfer_id_timeout_usec,
                                 (RxMemory){.payload = memory.payload, .fragment = memory.fragment},
                                 out_transfer);
    }
    else  // Failed to allocate a new session.
    {
        result = -UDPARD_ERROR_MEMORY;
        memFreePayload(memory.payload, frame.base.origin);
    }
    return result;
}

/// A special case of rxPortAccept() for anonymous transfers. Accepts all transfers unconditionally.
/// Does not allocate new memory. Takes ownership of the frame payload buffer.
static inline int_fast8_t rxPortAcceptAnonymous(const UdpardMicrosecond          ts_usec,
                                                const RxFrame                    frame,
                                                const struct UdpardMemoryDeleter memory,
                                                struct UdpardRxTransfer* const   out_transfer)
{
    UDPARD_ASSERT((out_transfer != NULL) && (frame.meta.src_node_id == UDPARD_NODE_ID_UNSET));
    int_fast8_t result  = 0;
    const bool  size_ok = frame.base.payload.size >= TRANSFER_CRC_SIZE_BYTES;
    const bool  crc_ok =
        transferCRCCompute(frame.base.payload.size, frame.base.payload.data) == TRANSFER_CRC_RESIDUE_AFTER_OUTPUT_XOR;
    if (size_ok && crc_ok)
    {
        result = 1;
        memZero(sizeof(*out_transfer), out_transfer);
        // Copy relevant metadata from the frame. Remember that anonymous transfers are always single-frame.
        out_transfer->timestamp_usec = ts_usec;
        out_transfer->priority       = frame.meta.priority;
        out_transfer->source_node_id = frame.meta.src_node_id;
        out_transfer->transfer_id    = frame.meta.transfer_id;
        // Manually set up the transfer payload to point to the relevant slice inside the frame payload.
        out_transfer->payload.next      = NULL;
        out_transfer->payload.view.size = frame.base.payload.size - TRANSFER_CRC_SIZE_BYTES;
        out_transfer->payload.view.data = frame.base.payload.data;
        out_transfer->payload.origin    = frame.base.origin;
        out_transfer->payload_size      = out_transfer->payload.view.size;
    }
    else
    {
        memFreePayload(memory, frame.base.origin);
    }
    return result;
}

/// Accepts a raw frame and, if valid, passes it on to rxPortAccept() for further processing.
/// Takes ownership of the frame payload buffer.
static inline int_fast8_t rxPortAcceptFrame(struct UdpardRxPort* const           self,
                                            const uint_fast8_t                   redundant_iface_index,
                                            const UdpardMicrosecond              ts_usec,
                                            const struct UdpardMutablePayload    datagram_payload,
                                            const struct UdpardRxMemoryResources memory,
                                            struct UdpardRxTransfer* const       out_transfer)
{
    int_fast8_t result = 0;
    RxFrame     frame  = {0};
    if (rxParseFrame(datagram_payload, &frame))
    {
        if (frame.meta.src_node_id != UDPARD_NODE_ID_UNSET)
        {
            result = rxPortAccept(self, redundant_iface_index, ts_usec, frame, memory, out_transfer);
        }
        else
        {
            result = rxPortAcceptAnonymous(ts_usec, frame, memory.payload, out_transfer);
        }
    }
    else  // Malformed datagram or unsupported header version, drop.
    {
        memFreePayload(memory.payload, datagram_payload);
    }
    return result;
}

static inline void rxPortInit(struct UdpardRxPort* const self)
{
    memZero(sizeof(*self), self);
    self->extent                   = SIZE_MAX;  // Unlimited extent by default.
    self->transfer_id_timeout_usec = UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC;
    self->sessions                 = NULL;
}

static inline void rxPortFree(struct UdpardRxPort* const self, const struct UdpardRxMemoryResources memory)
{
    rxSessionDestroyTree(self->sessions, memory);
}

// --------------------------------------------------  RX API  --------------------------------------------------

void udpardRxFragmentFree(const struct UdpardFragment       head,
                          const struct UdpardMemoryResource memory_fragment,
                          const struct UdpardMemoryDeleter  memory_payload)
{
    // The head is not heap-allocated so not freed.
    memFreePayload(memory_payload, head.origin);  // May be NULL, is okay.
    rxFragmentDestroyList(head.next, (RxMemory){.fragment = memory_fragment, .payload = memory_payload});
}

int_fast8_t udpardRxSubscriptionInit(struct UdpardRxSubscription* const   self,
                                     const UdpardPortID                   subject_id,
                                     const size_t                         extent,
                                     const struct UdpardRxMemoryResources memory)
{
    (void) self;
    (void) subject_id;
    (void) extent;
    (void) memory;
    (void) &rxPortAcceptFrame;
    (void) &rxPortInit;
    (void) &rxPortFree;
    return 0;
}

// =====================================================================================================================
// ====================================================    MISC    =====================================================
// =====================================================================================================================

size_t udpardGather(const struct UdpardFragment head, const size_t destination_size, void* const destination)
{
    size_t offset = 0;
    if (NULL != destination)
    {
        const struct UdpardFragment* frag = &head;
        while ((frag != NULL) && (offset < destination_size))
        {
            UDPARD_ASSERT(frag->view.data != NULL);
            const size_t frag_size = smaller(frag->view.size, destination_size - offset);
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            (void) memmove(((byte_t*) destination) + offset, frag->view.data, frag_size);
            offset += frag_size;
            UDPARD_ASSERT(offset <= destination_size);
            frag = frag->next;
        }
    }
    return offset;
}
