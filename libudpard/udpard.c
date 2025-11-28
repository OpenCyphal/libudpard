/// This software is distributed under the terms of the MIT License.
/// Copyright (c) 2016 OpenCyphal.
/// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
/// Author: Pavel Kirienko <pavel@opencyphal.org>

#include "udpard.h"
#include <string.h>

// ---------------------------------------------  BUILD CONFIGURATION  ---------------------------------------------

/// Define this macro to include build configuration header.
/// Usage example with CMake: "-DUDPARD_CONFIG_HEADER=\"${CMAKE_CURRENT_SOURCE_DIR}/my_udpard_config.h\""
#ifdef UDPARD_CONFIG_HEADER
#include UDPARD_CONFIG_HEADER
#endif

/// By default, this macro resolves to the standard assert(). The user can redefine this if necessary.
/// To disable assertion checks completely, make it expand into `(void)(0)`.
#ifndef UDPARD_ASSERT
// Intentional violation of MISRA: inclusion not at the top of the file to eliminate unnecessary dependency on assert.h.
#include <assert.h> // NOSONAR
// Intentional violation of MISRA: assertion macro cannot be replaced with a function definition.
#define UDPARD_ASSERT(x) assert(x) // NOSONAR
#endif

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
#error "Unsupported language: ISO C99 or a newer version is required."
#endif

// ---------------------------------------------  COMMONS  ---------------------------------------------

#define CAVL2_T         udpard_tree_t
#define CAVL2_RELATION  int32_t
#define CAVL2_ASSERT(x) UDPARD_ASSERT(x) // NOSONAR
#include "cavl2.h"

typedef unsigned char byte_t; ///< For compatibility with platforms where byte size is not 8 bits.

#define RX_SLOT_COUNT (UDPARD_PRIORITY_MAX + 1U)
#define BIG_BANG      INT64_MIN

#define KILO 1000L
#define MEGA 1000000LL

/// Sessions will be garbage-collected after being idle for this long, along with unfinished transfers, if any.
#define SESSION_LIFETIME (60 * MEGA)

#define UDP_PORT               9382U
#define IPv4_MCAST_PREFIX      0xEF000000UL
#define IPv4_MCAST_SUFFIX_MASK 0x007FFFFFUL

static udpard_udpip_ep_t make_topic_ep(const uint32_t subject_id)
{
    return (udpard_udpip_ep_t){ .ip = IPv4_MCAST_PREFIX | (subject_id & IPv4_MCAST_SUFFIX_MASK), .port = UDP_PORT };
}

static size_t   smaller(const size_t a, const size_t b) { return (a < b) ? a : b; }
static size_t   larger(const size_t a, const size_t b) { return (a > b) ? a : b; }
static uint32_t max_u32(const uint32_t a, const uint32_t b) { return (a > b) ? a : b; }

static void* mem_alloc(const udpard_mem_resource_t memory, const size_t size)
{
    UDPARD_ASSERT(memory.alloc != NULL);
    return memory.alloc(memory.user, size);
}

static void mem_free(const udpard_mem_resource_t memory, const size_t size, void* const data)
{
    UDPARD_ASSERT(memory.free != NULL);
    memory.free(memory.user, size, data);
}

static void mem_free_payload(const udpard_mem_deleter_t memory, const udpard_bytes_mut_t payload)
{
    UDPARD_ASSERT(memory.free != NULL);
    if (payload.data != NULL) {
        memory.free(memory.user, payload.size, payload.data);
    }
}

// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
static void mem_zero(const size_t size, void* const data) { (void)memset(data, 0, size); }

// ---------------------------------------------  CRC  ---------------------------------------------

#define CRC_INITIAL                   0xFFFFFFFFUL
#define CRC_OUTPUT_XOR                0xFFFFFFFFUL
#define CRC_RESIDUE_BEFORE_OUTPUT_XOR 0xB798B438UL
#define CRC_RESIDUE_AFTER_OUTPUT_XOR  (CRC_RESIDUE_BEFORE_OUTPUT_XOR ^ CRC_OUTPUT_XOR)
#define CRC_SIZE_BYTES                4U

static uint32_t crc_add_byte(const uint32_t crc, const byte_t byte)
{
    static const uint32_t table[256] = {
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
    return (crc >> 8U) ^ table[byte ^ (crc & 0xFFU)];
}

/// Do not forget to apply the output XOR when done, or use crc_compute().
static uint32_t crc_add(uint32_t crc, const size_t size, const void* const data)
{
    UDPARD_ASSERT((data != NULL) || (size == 0U));
    const byte_t* p = (const byte_t*)data;
    for (size_t i = 0; i < size; i++) {
        crc = crc_add_byte(crc, *p);
        ++p;
    }
    return crc;
}

static uint32_t crc_compute(const size_t size, const void* const data)
{
    return crc_add(CRC_INITIAL, size, data) ^ CRC_OUTPUT_XOR;
}

// ---------------------------------------------  HEADER  ---------------------------------------------

#define HEADER_SIZE_BYTES 48U
#define HEADER_VERSION    2U

#define HEADER_FLAG_EOT 0x01U
#define HEADER_FLAG_ACK 0x02U

typedef struct
{
    udpard_prio_t priority;
    bool          flag_ack;
    uint32_t      transfer_payload_size;
    uint64_t      transfer_id;
    uint64_t      sender_uid;
    uint64_t      topic_hash;
} meta_t;

static byte_t* serialize_u32(byte_t* ptr, const uint32_t value)
{
    for (size_t i = 0; i < sizeof(value); i++) {
        *ptr++ = (byte_t)((byte_t)(value >> (i * 8U)) & 0xFFU);
    }
    return ptr;
}

static byte_t* serialize_u64(byte_t* ptr, const uint64_t value)
{
    for (size_t i = 0; i < sizeof(value); i++) {
        *ptr++ = (byte_t)((byte_t)(value >> (i * 8U)) & 0xFFU);
    }
    return ptr;
}

static const byte_t* deserialize_u32(const byte_t* ptr, uint32_t* const out_value)
{
    UDPARD_ASSERT((ptr != NULL) && (out_value != NULL));
    *out_value = 0;
    for (size_t i = 0; i < sizeof(*out_value); i++) {
        *out_value |= (uint32_t)((uint32_t)*ptr << (i * 8U)); // NOLINT(google-readability-casting) NOSONAR
        ptr++;
    }
    return ptr;
}

static const byte_t* deserialize_u64(const byte_t* ptr, uint64_t* const out_value)
{
    UDPARD_ASSERT((ptr != NULL) && (out_value != NULL));
    *out_value = 0;
    for (size_t i = 0; i < sizeof(*out_value); i++) {
        *out_value |= ((uint64_t)*ptr << (i * 8U));
        ptr++;
    }
    return ptr;
}

static byte_t* header_serialize(byte_t* const  buffer,
                                const meta_t   meta,
                                const bool     flag_eot,
                                const uint32_t frame_index,
                                const uint32_t frame_payload_offset)
{
    byte_t* ptr   = buffer;
    byte_t  flags = 0;
    if (flag_eot) {
        flags |= HEADER_FLAG_EOT;
    }
    if (meta.flag_ack) {
        flags |= HEADER_FLAG_ACK;
    }
    *ptr++ = (byte_t)(HEADER_VERSION | (meta.priority << 5U));
    *ptr++ = flags;
    *ptr++ = 0;
    *ptr++ = 0;
    ptr    = serialize_u32(ptr, frame_index);
    ptr    = serialize_u32(ptr, frame_payload_offset);
    ptr    = serialize_u32(ptr, meta.transfer_payload_size);
    ptr    = serialize_u64(ptr, meta.transfer_id);
    ptr    = serialize_u64(ptr, meta.sender_uid);
    ptr    = serialize_u64(ptr, meta.topic_hash);
    ptr    = serialize_u32(ptr, 0);
    ptr    = serialize_u32(ptr, crc_compute(HEADER_SIZE_BYTES - CRC_SIZE_BYTES, buffer));
    UDPARD_ASSERT((size_t)(ptr - buffer) == HEADER_SIZE_BYTES);
    return ptr;
}

static bool header_deserialize(const udpard_bytes_mut_t  dgram_payload,
                               meta_t* const             out_meta,
                               bool* const               flag_eot,
                               uint32_t* const           frame_index,
                               uint32_t* const           frame_payload_offset,
                               udpard_bytes_mut_t* const out_payload)
{
    UDPARD_ASSERT(out_payload != NULL);
    bool ok = (dgram_payload.size >= HEADER_SIZE_BYTES) && (dgram_payload.data != NULL) && //
              (crc_compute(HEADER_SIZE_BYTES, dgram_payload.data) == CRC_RESIDUE_AFTER_OUTPUT_XOR);
    if (ok) {
        const byte_t* ptr     = dgram_payload.data;
        const byte_t  head    = *ptr++;
        const byte_t  version = head & 0x1FU;
        if (version == HEADER_VERSION) {
            out_meta->priority = (udpard_prio_t)((byte_t)(head >> 5U) & 0x07U);
            const byte_t flags = *ptr++;
            *flag_eot          = (flags & HEADER_FLAG_EOT) != 0U;
            out_meta->flag_ack = (flags & HEADER_FLAG_ACK) != 0U;
            ptr += 2U;
            ptr = deserialize_u32(ptr, frame_index);
            ptr = deserialize_u32(ptr, frame_payload_offset);
            ptr = deserialize_u32(ptr, &out_meta->transfer_payload_size);
            ptr = deserialize_u64(ptr, &out_meta->transfer_id);
            ptr = deserialize_u64(ptr, &out_meta->sender_uid);
            ptr = deserialize_u64(ptr, &out_meta->topic_hash);
            (void)ptr;
            // Set up the output payload view.
            out_payload->size = dgram_payload.size - HEADER_SIZE_BYTES;
            out_payload->data = (byte_t*)dgram_payload.data + HEADER_SIZE_BYTES;
        } else {
            ok = false;
        }
    }
    return ok;
}

// ---------------------------------------------  TX PIPELINE  ---------------------------------------------

typedef struct
{
    udpard_tx_item_t* head;
    udpard_tx_item_t* tail;
    size_t            count;
} tx_chain_t;

static bool tx_validate_mem_resources(const udpard_tx_mem_resources_t memory)
{
    return (memory.fragment.alloc != NULL) && (memory.fragment.free != NULL) && //
           (memory.payload.alloc != NULL) && (memory.payload.free != NULL);
}

/// Frames with identical weight are processed in the FIFO order.
static int32_t tx_cavl_compare_prio(const void* const user, const udpard_tree_t* const node)
{
    return (((int)*(const udpard_prio_t*)user) >= (int)CAVL2_TO_OWNER(node, udpard_tx_item_t, index_prio)->priority)
             ? +1
             : -1;
}

static int32_t tx_cavl_compare_deadline(const void* const user, const udpard_tree_t* const node)
{
    return ((*(const udpard_microsecond_t*)user) >= CAVL2_TO_OWNER(node, udpard_tx_item_t, index_deadline)->deadline)
             ? +1
             : -1;
}

static udpard_tx_item_t* tx_item_new(const udpard_tx_mem_resources_t memory,
                                     const udpard_microsecond_t      deadline,
                                     const udpard_prio_t             priority,
                                     const udpard_udpip_ep_t         endpoint,
                                     const size_t                    datagram_payload_size,
                                     void* const                     user_transfer_reference)
{
    udpard_tx_item_t* out = mem_alloc(memory.fragment, sizeof(udpard_tx_item_t));
    if (out != NULL) {
        out->index_prio     = (udpard_tree_t){ 0 };
        out->index_deadline = (udpard_tree_t){ 0 };
        UDPARD_ASSERT(priority <= UDPARD_PRIORITY_MAX);
        out->priority                = priority;
        out->next_in_transfer        = NULL; // Last by default.
        out->deadline                = deadline;
        out->destination             = endpoint;
        out->user_transfer_reference = user_transfer_reference;
        void* const payload_data     = mem_alloc(memory.payload, datagram_payload_size);
        if (NULL != payload_data) {
            out->datagram_payload.data = payload_data;
            out->datagram_payload.size = datagram_payload_size;
        } else {
            mem_free(memory.fragment, sizeof(udpard_tx_item_t), out);
            out = NULL;
        }
    }
    return out;
}

/// Produces a chain of tx queue items for later insertion into the tx queue. The tail is NULL if OOM.
/// The caller is responsible for freeing the memory allocated for the chain.
static tx_chain_t tx_spool(const udpard_tx_mem_resources_t memory,
                           const size_t                    mtu,
                           const udpard_microsecond_t      deadline,
                           const meta_t                    meta,
                           const udpard_udpip_ep_t         endpoint,
                           const udpard_bytes_t            payload,
                           void* const                     user_transfer_reference)
{
    UDPARD_ASSERT(mtu > 0);
    UDPARD_ASSERT((payload.data != NULL) || (payload.size == 0U));
    const size_t payload_size_with_crc = payload.size + CRC_SIZE_BYTES;
    byte_t       crc_bytes[CRC_SIZE_BYTES];
    serialize_u32(crc_bytes, crc_compute(payload.size, payload.data));
    tx_chain_t out    = { NULL, NULL, 0 };
    size_t     offset = 0U;
    while (offset < payload_size_with_crc) {
        udpard_tx_item_t* const item = tx_item_new(memory,
                                                   deadline,
                                                   meta.priority,
                                                   endpoint,
                                                   smaller(payload_size_with_crc - offset, mtu) + HEADER_SIZE_BYTES,
                                                   user_transfer_reference);
        if (NULL == out.head) {
            out.head = item;
        } else {
            out.tail->next_in_transfer = item;
        }
        out.tail = item;
        if (NULL == out.tail) {
            break;
        }
        const bool    last       = (payload_size_with_crc - offset) <= mtu;
        byte_t* const dst_buffer = item->datagram_payload.data;
        byte_t*       write_ptr  = header_serialize(dst_buffer, meta, last, (uint32_t)out.count, (uint32_t)offset);
        if (offset < payload.size) {
            const size_t progress = smaller(payload.size - offset, mtu);
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            (void)memcpy(write_ptr, ((const byte_t*)payload.data) + offset, progress);
            offset += progress;
            write_ptr += progress;
            UDPARD_ASSERT(offset <= payload.size);
            UDPARD_ASSERT((!last) || (offset == payload.size));
        }
        if (offset >= payload.size) {
            const size_t crc_offset = offset - payload.size;
            UDPARD_ASSERT(crc_offset < CRC_SIZE_BYTES);
            const size_t available = item->datagram_payload.size - (size_t)(write_ptr - dst_buffer);
            UDPARD_ASSERT(available <= CRC_SIZE_BYTES);
            const size_t write_size = smaller(CRC_SIZE_BYTES - crc_offset, available);
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            (void)memcpy(write_ptr, &crc_bytes[crc_offset], write_size);
            offset += write_size;
        }
        out.count++;
    }
    UDPARD_ASSERT((offset == payload_size_with_crc) || (out.tail == NULL));
    return out;
}

static uint32_t tx_push(udpard_tx_t* const         tx,
                        const udpard_microsecond_t deadline,
                        const meta_t               meta,
                        const udpard_udpip_ep_t    endpoint,
                        const udpard_bytes_t       payload,
                        void* const                user_transfer_reference)
{
    UDPARD_ASSERT(tx != NULL);
    uint32_t     out         = 0; // The number of frames enqueued; zero on error (error counters incremented).
    const size_t mtu         = larger(tx->mtu, UDPARD_MTU_MIN);
    const size_t frame_count = ((payload.size + CRC_SIZE_BYTES + mtu) - 1U) / mtu;
    if ((tx->queue_size + frame_count) > tx->queue_capacity) {
        tx->errors_capacity++;
    } else {
        const tx_chain_t chain = tx_spool(tx->memory, mtu, deadline, meta, endpoint, payload, user_transfer_reference);
        if (chain.tail != NULL) { // Insert the head into the tx index. Only the head, the rest is linked-listed.
            udpard_tx_item_t* const head = chain.head;
            UDPARD_ASSERT(frame_count == chain.count);
            const udpard_tree_t* res = cavl2_find_or_insert(
              &tx->index_prio, &head->priority, &tx_cavl_compare_prio, &head->index_prio, &cavl2_trivial_factory);
            UDPARD_ASSERT(res == &head->index_prio);
            (void)res;
            res = cavl2_find_or_insert(&tx->index_deadline,
                                       &head->deadline,
                                       &tx_cavl_compare_deadline,
                                       &head->index_deadline,
                                       &cavl2_trivial_factory);
            UDPARD_ASSERT(res == &head->index_deadline);
            (void)res;
            tx->queue_size += chain.count;
            UDPARD_ASSERT(tx->queue_size <= tx->queue_capacity);
            out = (uint32_t)chain.count;
        } else { // The queue is large enough but we ran out of heap memory, so we have to unwind the chain.
            tx->errors_oom++;
            udpard_tx_item_t* head = chain.head;
            while (head != NULL) {
                udpard_tx_item_t* const next = head->next_in_transfer;
                udpard_tx_free(tx->memory, head);
                head = next;
            }
        }
    }
    return out;
}

static uint64_t tx_purge_expired(udpard_tx_t* const self, const udpard_microsecond_t now)
{
    uint64_t count = 0;
    for (udpard_tree_t* p = cavl2_min(self->index_deadline); p != NULL; p = cavl2_next_greater(p)) {
        udpard_tx_item_t* const item = CAVL2_TO_OWNER(p, udpard_tx_item_t, index_deadline);
        if (item->deadline >= now) {
            break;
        }
        // Remove from both indices.
        cavl2_remove(&self->index_deadline, &item->index_deadline);
        cavl2_remove(&self->index_prio, &item->index_prio);
        // Free the entire transfer chain.
        udpard_tx_item_t* current = item;
        while (current != NULL) {
            udpard_tx_item_t* const next = current->next_in_transfer;
            udpard_tx_free(self->memory, current);
            current = next;
            count++;
            self->queue_size--;
        }
    }
    return count;
}

bool udpard_tx_new(udpard_tx_t* const              self,
                   const uint64_t                  local_uid,
                   const size_t                    queue_capacity,
                   const udpard_tx_mem_resources_t memory)
{
    const bool ok = (NULL != self) && (local_uid != 0) && tx_validate_mem_resources(memory);
    if (ok) {
        mem_zero(sizeof(*self), self);
        self->local_uid      = local_uid;
        self->queue_capacity = queue_capacity;
        self->mtu            = UDPARD_MTU_DEFAULT;
        self->memory         = memory;
        self->queue_size     = 0;
        self->index_prio     = NULL;
        self->index_deadline = NULL;
    }
    return ok;
}

uint32_t udpard_tx_publish(udpard_tx_t* const         self,
                           const udpard_microsecond_t now,
                           const udpard_microsecond_t deadline,
                           const udpard_prio_t        priority,
                           const uint64_t             topic_hash,
                           const uint32_t             subject_id,
                           const uint64_t             transfer_id,
                           const udpard_bytes_t       payload,
                           const bool                 ack_required,
                           void* const                user_transfer_reference)
{
    uint32_t out = 0;
    if ((self != NULL) && (self->local_uid != 0) && (priority <= UDPARD_PRIORITY_MAX) &&
        ((payload.data != NULL) || (payload.size == 0U))) {
        self->errors_expiration += tx_purge_expired(self, now);
        const meta_t meta = {
            .priority              = priority,
            .flag_ack              = ack_required,
            .transfer_payload_size = (uint32_t)payload.size,
            .transfer_id           = transfer_id,
            .sender_uid            = self->local_uid,
            .topic_hash            = topic_hash,
        };
        out = tx_push(self, deadline, meta, make_topic_ep(subject_id), payload, user_transfer_reference);
    }
    return out;
}

uint32_t udpard_tx_p2p(udpard_tx_t* const         self,
                       const udpard_microsecond_t now,
                       const udpard_microsecond_t deadline,
                       const uint64_t             remote_uid,
                       const udpard_udpip_ep_t    remote_ep,
                       const udpard_prio_t        priority,
                       const uint64_t             transfer_id,
                       const udpard_bytes_t       payload,
                       const bool                 ack_required,
                       void* const                user_transfer_reference)
{
    uint32_t out = 0;
    if ((self != NULL) && (self->local_uid != 0) && (remote_uid != 0) && (remote_ep.ip != 0) && (remote_ep.port != 0) &&
        (priority <= UDPARD_PRIORITY_MAX) && ((payload.data != NULL) || (payload.size == 0U))) {
        self->errors_expiration += tx_purge_expired(self, now);
        const meta_t meta = {
            .priority              = priority,
            .flag_ack              = ack_required,
            .transfer_payload_size = (uint32_t)payload.size,
            .transfer_id           = transfer_id,
            .sender_uid            = self->local_uid,
            .topic_hash            = remote_uid,
        };
        out = tx_push(self, deadline, meta, remote_ep, payload, user_transfer_reference);
    }
    return out;
}

udpard_tx_item_t* udpard_tx_peek(udpard_tx_t* const self, const udpard_microsecond_t now)
{
    udpard_tx_item_t* out = NULL;
    if (self != NULL) {
        self->errors_expiration += tx_purge_expired(self, now);
        out = CAVL2_TO_OWNER(cavl2_min(self->index_prio), udpard_tx_item_t, index_prio);
    }
    return out;
}

void udpard_tx_pop(udpard_tx_t* const self, udpard_tx_item_t* const item)
{
    if ((self != NULL) && (item != NULL)) {
        if (item->next_in_transfer == NULL) {
            cavl2_remove(&self->index_prio, &item->index_prio);
            cavl2_remove(&self->index_deadline, &item->index_deadline);
        } else { // constant-time update, super quick, just relink a few pointers!
            cavl2_replace(&self->index_prio, &item->index_prio, &item->next_in_transfer->index_prio);
            cavl2_replace(&self->index_deadline, &item->index_deadline, &item->next_in_transfer->index_deadline);
        }
        self->queue_size--;
    }
}

void udpard_tx_free(const udpard_tx_mem_resources_t memory, udpard_tx_item_t* const item)
{
    if (item != NULL) {
        UDPARD_ASSERT((item->index_prio.lr[0] == NULL) && (item->index_prio.up == NULL) &&
                      (item->index_prio.lr[1] == NULL));
        UDPARD_ASSERT((item->index_deadline.lr[0] == NULL) && (item->index_deadline.up == NULL) &&
                      (item->index_deadline.lr[1] == NULL));
        if (item->datagram_payload.data != NULL) {
            mem_free(memory.payload, item->datagram_payload.size, item->datagram_payload.data);
        }
        mem_free(memory.fragment, sizeof(udpard_tx_item_t), item);
    }
}

// ---------------------------------------------  RX PIPELINE  ---------------------------------------------
