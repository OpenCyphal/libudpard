/// This software is distributed under the terms of the MIT License.
/// Copyright (c) 2016 OpenCyphal.
/// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
/// Author: Pavel Kirienko <pavel@opencyphal.org>

// ReSharper disable CppDFATimeOver

#include "udpard.h"
#include <assert.h>
#include <string.h>

/// Define this macro to include build configuration header.
/// Usage example with CMake: "-DUDPARD_CONFIG_HEADER=\"${CMAKE_CURRENT_SOURCE_DIR}/my_udpard_config.h\""
#ifdef UDPARD_CONFIG_HEADER
#include UDPARD_CONFIG_HEADER
#endif

/// By default, this macro resolves to the standard assert(). The user can redefine this if necessary.
/// To disable assertion checks completely, make it expand into `(void)(0)`.
#ifndef UDPARD_ASSERT
// Intentional violation of MISRA: assertion macro cannot be replaced with a function definition.
#define UDPARD_ASSERT(x) assert(x) // NOSONAR
#endif

#if __STDC_VERSION__ < 201112L
// Intentional violation of MISRA: static assertion macro cannot be replaced with a function definition.
#define static_assert(x, ...)   typedef char _static_assert_gl(_static_assertion_, __LINE__)[(x) ? 1 : -1] // NOSONAR
#define _static_assert_gl(a, b) _static_assert_gl_impl(a, b)                                               // NOSONAR
// Intentional violation of MISRA: the paste operator ## cannot be avoided in this context.
#define _static_assert_gl_impl(a, b) a##b // NOSONAR
#endif

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
#error "Unsupported language: ISO C99 or a newer version is required."
#endif

#define CAVL2_T         udpard_tree_t
#define CAVL2_RELATION  int32_t
#define CAVL2_ASSERT(x) UDPARD_ASSERT(x) // NOSONAR
#include "cavl2.h"                       // NOSONAR

typedef unsigned char byte_t; ///< For compatibility with platforms where byte size is not 8 bits.

/// Sessions will be garbage-collected after being idle for this long, along with unfinished transfers, if any.
/// Pending slots within a live session will also be reset after this timeout to avoid storing stale data indefinitely.
#define SESSION_LIFETIME (60 * MEGA)

/// The maximum number of incoming transfers that can be in the state of incomplete reassembly simultaneously.
/// Additional transfers will replace the oldest ones.
/// This number should normally be at least as large as there are priority levels. More is fine but rarely useful.
#define RX_SLOT_COUNT UDPARD_PRIORITY_COUNT

/// The number of most recent transfers to keep in the history for ACK retransmission and duplicate detection.
/// Should be a power of two to allow replacement of modulo operation with a bitwise AND.
///
/// Implementation node: we used to store bitmask windows instead of a full list of recent transfer-IDs, but they
/// were found to offer no advantage except in the perfect scenario of non-restarting senders, and an increased
/// implementation complexity (more branches, more lines of code), so they were replaced with a simple list.
/// The list works equally well given a non-contiguous transfer-ID stream, unlike the bitmask, thus more robust.
#define RX_TRANSFER_HISTORY_COUNT 32U

/// In the ORDERED reassembly mode, with the most recently received transfer-ID N, the library will reject
/// transfers with transfer-ID less than or equal to N-ORDERING_WINDOW (modulo 2^64) as late.
#define RX_TRANSFER_ORDERING_WINDOW 1024U

#define UDP_PORT          9382U
#define IPv4_MCAST_PREFIX 0xEF000000UL
static_assert((UDPARD_IPv4_SUBJECT_ID_MAX & (UDPARD_IPv4_SUBJECT_ID_MAX + 1)) == 0,
              "UDPARD_IPv4_SUBJECT_ID_MAX must be one less than a power of 2");

#define P2P_KIND_RESPONSE 0U
#define P2P_KIND_ACK      1U

#define BIG_BANG   INT64_MIN
#define HEAT_DEATH INT64_MAX

#define KILO 1000LL
#define MEGA 1000000LL

/// Pending ack transfers expire after this long if not transmitted.
#define ACK_TX_DEADLINE MEGA

static size_t      smaller(const size_t a, const size_t b) { return (a < b) ? a : b; }
static size_t      larger(const size_t a, const size_t b) { return (a > b) ? a : b; }
static int64_t     min_i64(const int64_t a, const int64_t b) { return (a < b) ? a : b; }
static int64_t     max_i64(const int64_t a, const int64_t b) { return (a > b) ? a : b; }
static udpard_us_t earlier(const udpard_us_t a, const udpard_us_t b) { return min_i64(a, b); }
static udpard_us_t later(const udpard_us_t a, const udpard_us_t b) { return max_i64(a, b); }

/// Two memory resources are considered identical if they share the same user pointer and the same allocation function.
/// The deallocation function is intentionally excluded from the comparison.
static bool mem_same(const udpard_mem_resource_t a, const udpard_mem_resource_t b)
{
    return (a.user == b.user) && (a.alloc == b.alloc);
}

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

// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
static void mem_zero(const size_t size, void* const data) { (void)memset(data, 0, size); }

/// We require that the fragment tree does not contain fully-contained or equal-range fragments. This implies that no
/// two fragments have the same offset, and that fragments ordered by offset also order by their ends.
static int32_t cavl_compare_fragment_offset(const void* const user, const udpard_tree_t* const node)
{
    const size_t u = *(const size_t*)user;
    const size_t v = ((const udpard_fragment_t*)node)->offset; // clang-format off
    if (u < v) { return -1; }
    if (u > v) { return +1; }
    return 0; // clang-format on
}
static int32_t cavl_compare_fragment_end(const void* const user, const udpard_tree_t* const node)
{
    const size_t                   u = *(const size_t*)user;
    const udpard_fragment_t* const f = (const udpard_fragment_t*)node;
    const size_t                   v = f->offset + f->view.size; // clang-format off
    if (u < v) { return -1; }
    if (u > v) { return +1; }
    return 0; // clang-format on
}

bool udpard_is_valid_endpoint(const udpard_udpip_ep_t ep)
{
    return (ep.port != 0) && (ep.ip != 0) && (ep.ip != UINT32_MAX);
}

static uint32_t valid_ep_mask(const udpard_udpip_ep_t remote_ep[UDPARD_IFACE_COUNT_MAX])
{
    uint32_t mask = 0U;
    for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        if (udpard_is_valid_endpoint(remote_ep[i])) {
            mask |= (1U << i);
        }
    }
    return mask;
}

udpard_udpip_ep_t udpard_make_subject_endpoint(const uint32_t subject_id)
{
    return (udpard_udpip_ep_t){ .ip = IPv4_MCAST_PREFIX | (subject_id & UDPARD_IPv4_SUBJECT_ID_MAX), .port = UDP_PORT };
}

// NOLINTNEXTLINE(misc-no-recursion)
void udpard_fragment_free_all(udpard_fragment_t* const frag, const udpard_mem_resource_t fragment_mem_resource)
{
    if (frag != NULL) {
        // Descend the tree
        for (uint_fast8_t i = 0; i < 2; i++) {
            if (frag->index_offset.lr[i] != NULL) {
                frag->index_offset.lr[i]->up = NULL; // Prevent backtrack ascension from this branch
                udpard_fragment_free_all((udpard_fragment_t*)frag->index_offset.lr[i], fragment_mem_resource);
                frag->index_offset.lr[i] = NULL; // Avoid dangly pointers even if we're headed for imminent destruction
            }
        }
        // Delete this fragment
        udpard_fragment_t* const parent = (udpard_fragment_t*)frag->index_offset.up;
        mem_free_payload(frag->payload_deleter, frag->origin);
        mem_free(fragment_mem_resource, sizeof(udpard_fragment_t), frag);
        // Ascend the tree.
        if (parent != NULL) {
            parent->index_offset.lr[parent->index_offset.lr[1] == (udpard_tree_t*)frag] = NULL;
            udpard_fragment_free_all(parent, fragment_mem_resource); // tail call hopefully
        }
    }
}

udpard_fragment_t* udpard_fragment_seek(const udpard_fragment_t* frag, const size_t offset)
{
    if (frag != NULL) {
        while (frag->index_offset.up != NULL) { // Only if the given node is not already the root.
            frag = (const udpard_fragment_t*)frag->index_offset.up;
        }
        if (offset == 0) { // Common fast path.
            return (udpard_fragment_t*)cavl2_min((udpard_tree_t*)frag);
        }
        udpard_fragment_t* const f =
          (udpard_fragment_t*)cavl2_predecessor((udpard_tree_t*)frag, &offset, &cavl_compare_fragment_offset);
        if ((f != NULL) && ((f->offset + f->view.size) > offset)) {
            UDPARD_ASSERT(f->offset <= offset);
            return f;
        }
    }
    return NULL;
}

udpard_fragment_t* udpard_fragment_next(const udpard_fragment_t* frag)
{
    return (frag != NULL) ? ((udpard_fragment_t*)cavl2_next_greater((udpard_tree_t*)frag)) : NULL;
}

size_t udpard_fragment_gather(const udpard_fragment_t** cursor,
                              const size_t              offset,
                              const size_t              size,
                              void* const               destination)
{
    size_t copied = 0;
    if ((cursor != NULL) && (*cursor != NULL) && (destination != NULL)) {
        const size_t             end_offset = (*cursor)->offset + (*cursor)->view.size;
        const udpard_fragment_t* f          = NULL;
        if ((offset < (*cursor)->offset) || (offset > end_offset)) {
            f = udpard_fragment_seek(*cursor, offset);
        } else if (offset == end_offset) { // Common case during sequential access.
            f = udpard_fragment_next(*cursor);
        } else {
            f = *cursor;
        }
        if ((f != NULL) && (size > 0U)) {
            const udpard_fragment_t* last = f;
            size_t                   pos  = offset;
            byte_t* const            out  = (byte_t*)destination;
            while ((f != NULL) && (copied < size)) { // Copy contiguous fragments starting at the requested offset.
                UDPARD_ASSERT(f->offset <= pos);
                UDPARD_ASSERT(pos < (f->offset + f->view.size));
                UDPARD_ASSERT(f->view.data != NULL);
                const size_t bias    = pos - f->offset;
                const size_t to_copy = smaller(f->view.size - bias, size - copied);
                // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
                (void)memcpy(out + copied, ((const byte_t*)f->view.data) + bias, to_copy);
                copied += to_copy;
                pos += to_copy;
                last = f;
                if (copied < size) {
                    f = udpard_fragment_next(f);
                    UDPARD_ASSERT((f == NULL) || (f->offset == pos));
                }
            }
            *cursor = last; // Keep iterator non-NULL.
        }
        UDPARD_ASSERT(NULL != *cursor);
    }
    return copied;
}

// ---------------------------------------------  CRC  ---------------------------------------------

#define CRC_INITIAL                   0xFFFFFFFFUL
#define CRC_OUTPUT_XOR                0xFFFFFFFFUL
#define CRC_RESIDUE_BEFORE_OUTPUT_XOR 0xB798B438UL
#define CRC_RESIDUE_AFTER_OUTPUT_XOR  (CRC_RESIDUE_BEFORE_OUTPUT_XOR ^ CRC_OUTPUT_XOR)
#define CRC_SIZE_BYTES                4U

static const uint32_t crc_table[256] = {
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

/// Do not forget to apply the output XOR when done, or use crc_full().
static uint32_t crc_add(uint32_t crc, const size_t n_bytes, const void* const data)
{
    UDPARD_ASSERT((data != NULL) || (n_bytes == 0U));
    const byte_t* p = (const byte_t*)data;
    for (size_t i = 0; i < n_bytes; i++) {
        crc = (crc >> 8U) ^ crc_table[(*p++) ^ (crc & 0xFFU)];
    }
    return crc;
}

static uint32_t crc_full(const size_t n_bytes, const void* const data)
{
    return crc_add(CRC_INITIAL, n_bytes, data) ^ CRC_OUTPUT_XOR;
}

// ---------------------------------------------  LIST CONTAINER  ---------------------------------------------

/// True iff the member is in the list.
static bool is_listed(const udpard_list_t* const list, const udpard_list_member_t* const member)
{
    return (member->next != NULL) || (member->prev != NULL) || (list->head == member);
}

/// No effect if not in the list.
static void delist(udpard_list_t* const list, udpard_list_member_t* const member)
{
    if (member->next != NULL) {
        member->next->prev = member->prev;
    }
    if (member->prev != NULL) {
        member->prev->next = member->next;
    }
    if (list->head == member) {
        list->head = member->next;
    }
    if (list->tail == member) {
        list->tail = member->prev;
    }
    member->next = NULL;
    member->prev = NULL;
    assert((list->head != NULL) == (list->tail != NULL));
}

/// If the item is already in the list, it will be delisted first. Can be used for moving to the front.
static void enlist_head(udpard_list_t* const list, udpard_list_member_t* const member)
{
    delist(list, member);
    assert((member->next == NULL) && (member->prev == NULL));
    assert((list->head != NULL) == (list->tail != NULL));
    member->next = list->head;
    if (list->head != NULL) {
        list->head->prev = member;
    }
    list->head = member;
    if (list->tail == NULL) {
        list->tail = member;
    }
    assert((list->head != NULL) && (list->tail != NULL));
}

#define LIST_MEMBER(ptr, owner_type, owner_field) ((owner_type*)unbias_ptr((ptr), offsetof(owner_type, owner_field)))
static void* unbias_ptr(const void* const ptr, const size_t offset)
{
    return (ptr == NULL) ? NULL : (void*)((char*)ptr - offset);
}
#define LIST_TAIL(list, owner_type, owner_field) LIST_MEMBER((list).tail, owner_type, owner_field)

// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------          HEADER           ---------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------

#define HEADER_SIZE_BYTES      48U
#define HEADER_VERSION         2U
#define HEADER_FLAG_ACK        0x01U
#define HEADER_FRAME_INDEX_MAX 0xFFFFFFU /// 4 GiB with 256-byte MTU

typedef struct
{
    udpard_prio_t priority;
    bool          flag_ack;
    uint32_t      transfer_payload_size;
    uint64_t      transfer_id;
    uint64_t      sender_uid;
    uint64_t      topic_hash;
} meta_t;

static byte_t* header_serialize(byte_t* const  buffer,
                                const meta_t   meta,
                                const uint32_t frame_index,
                                const uint32_t frame_payload_offset,
                                const uint32_t prefix_crc)
{
    byte_t* ptr   = buffer;
    byte_t  flags = 0;
    if (meta.flag_ack) {
        flags |= HEADER_FLAG_ACK;
    }
    *ptr++ = (byte_t)(HEADER_VERSION | (meta.priority << 5U));
    *ptr++ = flags;
    *ptr++ = 0;
    *ptr++ = 0;
    ptr    = serialize_u32(ptr, frame_index & HEADER_FRAME_INDEX_MAX);
    ptr    = serialize_u32(ptr, frame_payload_offset);
    ptr    = serialize_u32(ptr, meta.transfer_payload_size);
    ptr    = serialize_u64(ptr, meta.transfer_id);
    ptr    = serialize_u64(ptr, meta.sender_uid);
    ptr    = serialize_u64(ptr, meta.topic_hash);
    ptr    = serialize_u32(ptr, prefix_crc);
    ptr    = serialize_u32(ptr, crc_full(HEADER_SIZE_BYTES - CRC_SIZE_BYTES, buffer));
    UDPARD_ASSERT((size_t)(ptr - buffer) == HEADER_SIZE_BYTES);
    return ptr;
}

static bool header_deserialize(const udpard_bytes_mut_t dgram_payload,
                               meta_t* const            out_meta,
                               uint32_t* const          frame_index,
                               uint32_t* const          frame_payload_offset,
                               uint32_t* const          prefix_crc,
                               udpard_bytes_t* const    out_payload)
{
    UDPARD_ASSERT(out_payload != NULL);
    bool ok = (dgram_payload.size >= HEADER_SIZE_BYTES) && (dgram_payload.data != NULL) && //
              (crc_full(HEADER_SIZE_BYTES, dgram_payload.data) == CRC_RESIDUE_AFTER_OUTPUT_XOR);
    if (ok) {
        const byte_t* ptr     = dgram_payload.data;
        const byte_t  head    = *ptr++;
        const byte_t  version = head & 0x1FU;
        if (version == HEADER_VERSION) {
            out_meta->priority = (udpard_prio_t)((byte_t)(head >> 5U) & 0x07U);
            const byte_t flags = *ptr++;
            out_meta->flag_ack = (flags & HEADER_FLAG_ACK) != 0U;
            ptr += 2U;
            ptr = deserialize_u32(ptr, frame_index);
            ptr = deserialize_u32(ptr, frame_payload_offset);
            ptr = deserialize_u32(ptr, &out_meta->transfer_payload_size);
            ptr = deserialize_u64(ptr, &out_meta->transfer_id);
            ptr = deserialize_u64(ptr, &out_meta->sender_uid);
            ptr = deserialize_u64(ptr, &out_meta->topic_hash);
            ptr = deserialize_u32(ptr, prefix_crc);
            (void)ptr;
            // Set up the output payload view.
            out_payload->size = dgram_payload.size - HEADER_SIZE_BYTES;
            out_payload->data = (byte_t*)dgram_payload.data + HEADER_SIZE_BYTES;
            // Finalize the fields.
            *frame_index = HEADER_FRAME_INDEX_MAX & *frame_index;
            // Validate the fields.
            ok = ((uint64_t)*frame_payload_offset + (uint64_t)out_payload->size) <=
                 (uint64_t)out_meta->transfer_payload_size;
            ok = ok && ((0 == *frame_index) == (0 == *frame_payload_offset));
            // The prefix-CRC of the first frame of a transfer equals the CRC of its payload.
            ok = ok && ((0 < *frame_payload_offset) || (crc_full(out_payload->size, out_payload->data) == *prefix_crc));
        } else {
            ok = false;
        }
    }
    return ok;
}

// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------        TX PIPELINE        ---------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------

typedef struct tx_frame_t
{
    size_t               refcount;
    udpard_mem_deleter_t deleter;
    size_t*              objcount;
    struct tx_frame_t*   next;
    size_t               size;
    byte_t               data[];
} tx_frame_t;

static udpard_bytes_t tx_frame_view(const tx_frame_t* const frame)
{
    return (udpard_bytes_t){ .size = frame->size, .data = frame->data };
}

static tx_frame_t* tx_frame_from_view(const udpard_bytes_t view)
{
    return (tx_frame_t*)unbias_ptr(view.data, offsetof(tx_frame_t, data));
}

static tx_frame_t* tx_frame_new(udpard_tx_t* const tx, const udpard_mem_resource_t mem, const size_t data_size)
{
    tx_frame_t* const frame = (tx_frame_t*)mem_alloc(mem, sizeof(tx_frame_t) + data_size);
    if (frame != NULL) {
        frame->refcount = 1U;
        frame->deleter  = (udpard_mem_deleter_t){ .user = mem.user, .free = mem.free };
        frame->objcount = &tx->enqueued_frames_count;
        frame->next     = NULL;
        frame->size     = data_size;
        // Update the count; this is decremented when the frame is freed upon refcount reaching zero.
        tx->enqueued_frames_count++;
        UDPARD_ASSERT(tx->enqueued_frames_count <= tx->enqueued_frames_limit);
    }
    return frame;
}

typedef struct
{
    uint64_t topic_hash;
    uint64_t transfer_id;
} tx_transfer_key_t;

/// The transmission scheduler maintains several indexes for the transfers in the pipeline.
///
/// The segregated priority queue only contains transfers that are ready for transmission.
/// The staged index contains transfers ordered by readiness time;
/// transfers that will no longer be transmitted but are retained waiting for the ack are in neither of these.
/// The deadline index contains ALL transfers, ordered by their deadlines, used for purging expired transfers.
/// The transfer index contains ALL transfers, used for lookup by (topic_hash, transfer_id).
typedef struct tx_transfer_t
{
    udpard_tree_t        index_staged;   ///< Soonest to be ready on the left. Key: staged_until
    udpard_tree_t        index_deadline; ///< Soonest to expire on the left. Key: deadline
    udpard_tree_t        index_transfer; ///< Specific transfer lookup for ack management. Key: tx_transfer_key_t
    udpard_list_member_t queue[UDPARD_IFACE_COUNT_MAX]; ///< Listed when ready for transmission.
    udpard_list_member_t agewise;                       ///< Listed when created; oldest at the tail.

    /// We always keep a pointer to the head, plus a cursor that scans the frames during transmission.
    /// Both are NULL if the payload is destroyed.
    /// The head points to the first frame unless it is known that no (further) retransmissions are needed,
    /// in which case the old head is deleted and the head points to the next frame to transmit.
    tx_frame_t* head[UDPARD_IFACE_COUNT_MAX];

    /// Mutable transmission state. All other fields, except for the index handles, are immutable.
    tx_frame_t*  cursor[UDPARD_IFACE_COUNT_MAX];
    uint_fast8_t epoch;        ///< Does not overflow due to exponential backoff.
    udpard_us_t  staged_until; ///< If staged_until>=deadline, this is the last attempt; frames can be freed as leave.

    /// Constant transfer properties supplied by the client.
    uint64_t          topic_hash;
    uint64_t          transfer_id;
    udpard_us_t       deadline;
    bool              reliable;
    udpard_prio_t     priority;
    udpard_udpip_ep_t destination[UDPARD_IFACE_COUNT_MAX];
    void*             user_transfer_reference;

    void (*feedback)(udpard_tx_t*, udpard_tx_feedback_t);

    /// These entities are specific to outgoing acks only. I considered extracting them into a polymorphic
    /// tx_transfer_ack_t subtype with a virtual destructor, but it adds a bit more complexity than I would like
    /// to tolerate for a gain of only a dozen bytes per transfer object.
    /// These are undefined for non-ack transfers.
    udpard_tree_t index_transfer_remote; ///< Key: tx_transfer_key_t but referencing the remotes.
    uint64_t      remote_topic_hash;
    uint64_t      remote_transfer_id;
} tx_transfer_t;

static bool tx_validate_mem_resources(const udpard_tx_mem_resources_t memory)
{
    for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        if ((memory.payload[i].alloc == NULL) || (memory.payload[i].free == NULL)) {
            return false;
        }
    }
    return (memory.transfer.alloc != NULL) && (memory.transfer.free != NULL);
}

static void tx_transfer_free_payload(tx_transfer_t* const tr)
{
    UDPARD_ASSERT(tr != NULL);
    for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        const tx_frame_t* frame = tr->head[i];
        while (frame != NULL) {
            const tx_frame_t* const next = frame->next;
            udpard_tx_refcount_dec(tx_frame_view(frame));
            frame = next;
        }
        tr->head[i]   = NULL;
        tr->cursor[i] = NULL;
    }
}

static void tx_transfer_free(udpard_tx_t* const tx, tx_transfer_t* const tr)
{
    UDPARD_ASSERT(tr != NULL);
    tx_transfer_free_payload(tr);
    for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        delist(&tx->queue[i][tr->priority], &tr->queue[i]);
    }
    delist(&tx->agewise, &tr->agewise);
    if (cavl2_is_inserted(tx->index_staged, &tr->index_staged)) {
        cavl2_remove(&tx->index_staged, &tr->index_staged);
    }
    cavl2_remove(&tx->index_deadline, &tr->index_deadline);
    cavl2_remove(&tx->index_transfer, &tr->index_transfer);
    if (cavl2_is_inserted(tx->index_transfer_remote, &tr->index_transfer_remote)) {
        cavl2_remove(&tx->index_transfer_remote, &tr->index_transfer_remote);
    }
    mem_free(tx->memory.transfer, sizeof(tx_transfer_t), tr);
}

/// When the queue is exhausted, finds a transfer to sacrifice using simple heuristics and returns it.
/// Will return NULL if there are no transfers worth sacrificing (no queue space can be reclaimed).
/// We cannot simply stop accepting new transfers when the queue is full, because it may be caused by a single
/// stalled interface holding back progress for all transfers.
/// The heuristics are subject to review and improvement.
static tx_transfer_t* tx_sacrifice(udpard_tx_t* const tx) { return LIST_TAIL(tx->agewise, tx_transfer_t, agewise); }

/// True on success, false if not possible to reclaim enough space.
static bool tx_ensure_queue_space(udpard_tx_t* const tx, const size_t total_frames_needed)
{
    if (total_frames_needed > tx->enqueued_frames_limit) {
        return false; // not gonna happen
    }
    while (total_frames_needed > (tx->enqueued_frames_limit - tx->enqueued_frames_count)) {
        tx_transfer_t* const victim = tx_sacrifice(tx);
        if (victim == NULL) {
            break; // We may have no transfers anymore but the NIC TX driver could still be holding some frames.
        }
        tx_transfer_free(tx, victim);
        tx->errors_sacrifice++;
    }
    return total_frames_needed <= (tx->enqueued_frames_limit - tx->enqueued_frames_count);
}

static int32_t tx_cavl_compare_staged(const void* const user, const udpard_tree_t* const node)
{
    return ((*(const udpard_us_t*)user) >= CAVL2_TO_OWNER(node, tx_transfer_t, index_staged)->staged_until) ? +1 : -1;
}
static int32_t tx_cavl_compare_deadline(const void* const user, const udpard_tree_t* const node)
{
    return ((*(const udpard_us_t*)user) >= CAVL2_TO_OWNER(node, tx_transfer_t, index_deadline)->deadline) ? +1 : -1;
}
static int32_t tx_cavl_compare_transfer(const void* const user, const udpard_tree_t* const node)
{
    const tx_transfer_key_t* const key = (const tx_transfer_key_t*)user;
    const tx_transfer_t* const tr = CAVL2_TO_OWNER(node, tx_transfer_t, index_transfer); // clang-format off
    if (key->topic_hash  < tr->topic_hash)  { return -1; }
    if (key->topic_hash  > tr->topic_hash)  { return +1; }
    if (key->transfer_id < tr->transfer_id) { return -1; }
    if (key->transfer_id > tr->transfer_id) { return +1; }
    return 0; // clang-format on
}
static int32_t tx_cavl_compare_transfer_remote(const void* const user, const udpard_tree_t* const node)
{
    const tx_transfer_key_t* const key = (const tx_transfer_key_t*)user;
    const tx_transfer_t* const tr = CAVL2_TO_OWNER(node, tx_transfer_t, index_transfer_remote); // clang-format off
    if (key->topic_hash  < tr->remote_topic_hash)  { return -1; }
    if (key->topic_hash  > tr->remote_topic_hash)  { return +1; }
    if (key->transfer_id < tr->remote_transfer_id) { return -1; }
    if (key->transfer_id > tr->remote_transfer_id) { return +1; }
    return 0; // clang-format on
}

static tx_transfer_t* tx_transfer_find(udpard_tx_t* const tx, const uint64_t topic_hash, const uint64_t transfer_id)
{
    const tx_transfer_key_t key = { .topic_hash = topic_hash, .transfer_id = transfer_id };
    return CAVL2_TO_OWNER(
      cavl2_find(tx->index_transfer, &key, &tx_cavl_compare_transfer), tx_transfer_t, index_transfer);
}

/// True iff listed in at least one interface queue.
static bool tx_is_pending(const udpard_tx_t* const tx, const tx_transfer_t* const tr)
{
    for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        if (is_listed(&tx->queue[i][tr->priority], &tr->queue[i])) {
            return true;
        }
    }
    return false;
}

static udpard_tx_feedback_t tx_make_feedback(const tx_transfer_t* const tr, const bool success)
{
    const udpard_tx_feedback_t fb = { .topic_hash              = tr->topic_hash,
                                      .transfer_id             = tr->transfer_id,
                                      .user_transfer_reference = tr->user_transfer_reference,
                                      .success                 = success };
    return fb;
}

/// Returns the head of the transfer chain; NULL on OOM.
static tx_frame_t* tx_spool(udpard_tx_t* const          tx,
                            const udpard_mem_resource_t memory,
                            const size_t                mtu,
                            const meta_t                meta,
                            const udpard_bytes_t        payload)
{
    UDPARD_ASSERT(mtu > 0);
    UDPARD_ASSERT((payload.data != NULL) || (payload.size == 0U));
    uint32_t    prefix_crc  = CRC_INITIAL;
    tx_frame_t* head        = NULL;
    tx_frame_t* tail        = NULL;
    size_t      frame_index = 0U;
    size_t      offset      = 0U;
    do {
        // Compute the size of the next frame, allocate it and link it up in the chain.
        const size_t      progress = smaller(payload.size - offset, mtu);
        tx_frame_t* const item     = tx_frame_new(tx, memory, progress + HEADER_SIZE_BYTES);
        if (NULL == head) {
            head = item;
        } else {
            tail->next = item;
        }
        tail = item;
        // On OOM, deallocate the entire chain and quit.
        if (NULL == tail) {
            while (head != NULL) {
                tx_frame_t* const next = head->next;
                udpard_tx_refcount_dec(tx_frame_view(head));
                head = next;
            }
            break;
        }
        // Populate the frame contents.
        const byte_t* const read_ptr = ((const byte_t*)payload.data) + offset;
        prefix_crc                   = crc_add(prefix_crc, progress, read_ptr);
        byte_t* const write_ptr =
          header_serialize(tail->data, meta, (uint32_t)frame_index, (uint32_t)offset, prefix_crc ^ CRC_OUTPUT_XOR);
        (void)memcpy(write_ptr, read_ptr, progress); // NOLINT(*DeprecatedOrUnsafeBufferHandling)
        // Advance the state.
        ++frame_index;
        offset += progress;
        UDPARD_ASSERT(offset <= payload.size);
    } while (offset < payload.size);
    UDPARD_ASSERT((offset == payload.size) || ((head == NULL) && (tail == NULL)));
    return head;
}

/// Derives the ack timeout for an outgoing transfer.
static udpard_us_t tx_ack_timeout(const udpard_us_t baseline, const udpard_prio_t prio, const uint_fast8_t attempts)
{
    return baseline * (1L << smaller((size_t)prio + attempts, 62)); // NOLINT(*-signed-bitwise)
}

/// A transfer can use the same fragments between two interfaces if both have the same MTU and use the same allocator.
/// The allocator requirement is important because it is possible that distinct NICs may not be able to reach the
/// same memory region via DMA.
static bool tx_spool_shareable(const size_t                mtu_a,
                               const udpard_mem_resource_t mem_a,
                               const size_t                mtu_b,
                               const udpard_mem_resource_t mem_b)
{
    return (mtu_a == mtu_b) && mem_same(mem_a, mem_b);
}

/// The prediction takes into account that some interfaces may share the same frame spool.
static size_t tx_predict_frame_count(const size_t                mtu[UDPARD_IFACE_COUNT_MAX],
                                     const udpard_mem_resource_t memory[UDPARD_IFACE_COUNT_MAX],
                                     const udpard_udpip_ep_t     endpoint[UDPARD_IFACE_COUNT_MAX],
                                     const size_t                payload_size)
{
    size_t n_frames_total = 0;
    for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        if (udpard_is_valid_endpoint(endpoint[i])) {
            bool shared = false;
            for (uint_fast8_t j = 0; j < i; j++) {
                shared = shared || (udpard_is_valid_endpoint(endpoint[j]) &&
                                    tx_spool_shareable(mtu[i], memory[i], mtu[j], memory[j]));
            }
            if (!shared) {
                n_frames_total += larger(1, (payload_size + mtu[i] - 1U) / mtu[i]);
            }
        }
    }
    return n_frames_total;
}

static uint32_t tx_push(udpard_tx_t* const      tx,
                        const udpard_us_t       now,
                        const udpard_us_t       deadline,
                        const meta_t            meta,
                        const udpard_udpip_ep_t endpoint[UDPARD_IFACE_COUNT_MAX],
                        const udpard_bytes_t    payload,
                        void (*const feedback)(udpard_tx_t*, udpard_tx_feedback_t),
                        void* const           user_transfer_reference,
                        tx_transfer_t** const out_transfer)
{
    UDPARD_ASSERT(now <= deadline);
    UDPARD_ASSERT(tx != NULL);

    // Ensure the queue has enough space.
    for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        tx->mtu[i] = larger(tx->mtu[i], UDPARD_MTU_MIN); // enforce minimum MTU
    }
    const size_t n_frames = tx_predict_frame_count(tx->mtu, tx->memory.payload, endpoint, meta.transfer_payload_size);
    if (!tx_ensure_queue_space(tx, n_frames)) {
        tx->errors_capacity++;
        return 0;
    }

    // Construct the transfer object, without the frames for now. The frame spools will be constructed next.
    tx_transfer_t* const tr = mem_alloc(tx->memory.transfer, sizeof(tx_transfer_t));
    if (tr == NULL) {
        tx->errors_oom++;
        return 0;
    }
    mem_zero(sizeof(*tr), tr);
    tr->epoch                   = 0;
    tr->topic_hash              = meta.topic_hash;
    tr->transfer_id             = meta.transfer_id;
    tr->deadline                = deadline;
    tr->reliable                = meta.flag_ack;
    tr->priority                = meta.priority;
    tr->user_transfer_reference = user_transfer_reference;
    tr->feedback                = feedback;
    tr->staged_until =
      meta.flag_ack ? (now + tx_ack_timeout(tx->ack_baseline_timeout, tr->priority, tr->epoch)) : HEAT_DEATH;
    for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        tr->destination[i] = endpoint[i];
        tr->head[i] = tr->cursor[i] = NULL;
    }

    // Spool the frames for each interface, with deduplication where possible to conserve space.
    const size_t enqueued_frames_before = tx->enqueued_frames_count;
    bool         oom                    = false;
    for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        if (udpard_is_valid_endpoint(tr->destination[i])) {
            if (tr->head[i] == NULL) {
                tr->head[i]   = tx_spool(tx, tx->memory.payload[i], tx->mtu[i], meta, payload);
                tr->cursor[i] = tr->head[i];
                if (tr->head[i] == NULL) {
                    oom = true;
                    break;
                }
                // Detect which interfaces can use the same spool to conserve memory.
                for (uint_fast8_t j = i + 1; j < UDPARD_IFACE_COUNT_MAX; j++) {
                    if (udpard_is_valid_endpoint(tr->destination[j]) &&
                        tx_spool_shareable(tx->mtu[i], tx->memory.payload[i], tx->mtu[j], tx->memory.payload[j])) {
                        tr->head[j]       = tr->head[i];
                        tr->cursor[j]     = tr->cursor[i];
                        tx_frame_t* frame = tr->head[j];
                        while (frame != NULL) {
                            frame->refcount++;
                            frame = frame->next;
                        }
                    }
                }
            }
        }
    }
    if (oom) {
        tx_transfer_free_payload(tr);
        mem_free(tx->memory.transfer, sizeof(tx_transfer_t), tr);
        tx->errors_oom++;
        return 0;
    }
    UDPARD_ASSERT((tx->enqueued_frames_count - enqueued_frames_before) == n_frames);
    UDPARD_ASSERT(tx->enqueued_frames_count <= tx->enqueued_frames_limit);
    (void)enqueued_frames_before;

    // Enqueue for transmission immediately.
    for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        if (udpard_is_valid_endpoint(tr->destination[i])) {
            enlist_head(&tx->queue[i][tr->priority], &tr->queue[i]);
        }
    }
    // If retransmissions are possible, add to the staged index so that it is re-enqueued later unless acknowledged.
    if (tr->deadline > tr->staged_until) {
        (void)cavl2_find_or_insert(
          &tx->index_staged, &tr->staged_until, tx_cavl_compare_staged, &tr->index_staged, cavl2_trivial_factory);
    }
    // Add to the deadline index for expiration management.
    (void)cavl2_find_or_insert(
      &tx->index_deadline, &tr->deadline, tx_cavl_compare_deadline, &tr->index_deadline, cavl2_trivial_factory);
    // Add to the transfer index for incoming ack management.
    const tx_transfer_key_t key = { .topic_hash = tr->topic_hash, .transfer_id = tr->transfer_id };
    (void)cavl2_find_or_insert(
      &tx->index_transfer, &key, tx_cavl_compare_transfer, &tr->index_transfer, cavl2_trivial_factory);
    // Add to the agewise list to allow instant sacrifice when needed; oldest at the tail.
    enlist_head(&tx->agewise, &tr->agewise);

    // Finalize.
    if (out_transfer != NULL) {
        *out_transfer = tr;
    }
    UDPARD_ASSERT(n_frames <= UINT32_MAX);
    return (uint32_t)n_frames;
}

/// Handle an ACK received from a remote node.
static void tx_receive_ack(udpard_rx_t* const rx, const uint64_t topic_hash, const uint64_t transfer_id)
{
    if (rx->tx != NULL) {
        tx_transfer_t* const tr = tx_transfer_find(rx->tx, topic_hash, transfer_id);
        if ((tr != NULL) && tr->reliable) {
            if (tr->feedback != NULL) {
                const udpard_tx_feedback_t fb = tx_make_feedback(tr, true);
                tx_transfer_free_payload(tr); // do this early to release memory before callback
                tr->feedback(rx->tx, fb);
            }
            tx_transfer_free(rx->tx, tr);
        }
    }
}

/// Generate an ack transfer for the specified remote transfer.
/// Do nothing if an ack for the same transfer is already enqueued with equal or better endpoint coverage.
static void tx_send_ack(udpard_rx_t* const    rx,
                        const udpard_us_t     now,
                        const udpard_prio_t   priority,
                        const uint64_t        topic_hash,
                        const uint64_t        transfer_id,
                        const udpard_remote_t remote)
{
    udpard_tx_t* const tx = rx->tx;
    if (tx != NULL) {
        // Check if an ack for this transfer is already enqueued.
        const tx_transfer_key_t key = { .topic_hash = topic_hash, .transfer_id = transfer_id };
        tx_transfer_t* const    prior =
          CAVL2_TO_OWNER(cavl2_find(tx->index_transfer_remote, &key, &tx_cavl_compare_transfer_remote),
                         tx_transfer_t,
                         index_transfer_remote);
        const uint32_t prior_ep_mask = (prior != NULL) ? valid_ep_mask(prior->destination) : 0U;
        const uint32_t new_ep_mask   = valid_ep_mask(remote.endpoints);
        const bool     new_better    = (new_ep_mask & (~prior_ep_mask)) != 0U;
        if (!new_better) {
            return; // Can we get an ack? We have ack at home!
        }
        if (prior != NULL) {
            tx_transfer_free(tx, prior); // avoid redundant acks for the same transfer -- replace with better one
        }

        // Serialize the ACK payload.
        byte_t  header[UDPARD_P2P_HEADER_BYTES];
        byte_t* ptr = header;
        *ptr++      = P2P_KIND_ACK;
        ptr += 7U; // Reserved bytes.
        ptr = serialize_u64(ptr, topic_hash);
        ptr = serialize_u64(ptr, transfer_id);
        UDPARD_ASSERT((ptr - header) == UDPARD_P2P_HEADER_BYTES);
        (void)ptr;

        // Enqueue the transfer.
        const udpard_bytes_t payload = { .size = UDPARD_P2P_HEADER_BYTES, .data = header };
        const meta_t         meta    = { .priority              = priority,
                                         .flag_ack              = false,
                                         .transfer_payload_size = (uint32_t)payload.size,
                                         .transfer_id           = tx->p2p_transfer_id++,
                                         .sender_uid            = tx->local_uid,
                                         .topic_hash            = remote.uid };
        tx_transfer_t*       tr      = NULL;
        const uint32_t       count =
          tx_push(tx, now, now + ACK_TX_DEADLINE, meta, remote.endpoints, payload, NULL, NULL, &tr);
        UDPARD_ASSERT(count <= 1);
        if (count == 1) { // ack is always a single-frame transfer, so we get either 0 or 1
            UDPARD_ASSERT(tr != NULL);
            tr->remote_topic_hash  = topic_hash;
            tr->remote_transfer_id = transfer_id;
            (void)cavl2_find_or_insert(&tx->index_transfer_remote,
                                       &key,
                                       tx_cavl_compare_transfer_remote,
                                       &tr->index_transfer_remote,
                                       cavl2_trivial_factory);
        } else {
            rx->errors_ack_tx++;
        }
    } else {
        rx->errors_ack_tx++;
    }
}

bool udpard_tx_new(udpard_tx_t* const              self,
                   const uint64_t                  local_uid,
                   const uint64_t                  p2p_transfer_id_initial,
                   const size_t                    enqueued_frames_limit,
                   const udpard_tx_mem_resources_t memory,
                   const udpard_tx_vtable_t* const vtable)
{
    const bool ok = (NULL != self) && (local_uid != 0) && tx_validate_mem_resources(memory) && (vtable != NULL) &&
                    (vtable->eject != NULL);
    if (ok) {
        mem_zero(sizeof(*self), self);
        self->vtable                = vtable;
        self->local_uid             = local_uid;
        self->p2p_transfer_id       = p2p_transfer_id_initial;
        self->ack_baseline_timeout  = UDPARD_TX_ACK_BASELINE_TIMEOUT_DEFAULT_us;
        self->enqueued_frames_limit = enqueued_frames_limit;
        self->enqueued_frames_count = 0;
        self->memory                = memory;
        self->index_staged          = NULL;
        self->index_deadline        = NULL;
        self->index_transfer        = NULL;
        self->user                  = NULL;
        for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
            self->mtu[i] = UDPARD_MTU_DEFAULT;
            for (uint_fast8_t p = 0; p < UDPARD_PRIORITY_COUNT; p++) {
                self->queue[i][p].head = NULL;
                self->queue[i][p].tail = NULL;
            }
        }
    }
    return ok;
}

uint32_t udpard_tx_push(udpard_tx_t* const      self,
                        const udpard_us_t       now,
                        const udpard_us_t       deadline,
                        const udpard_prio_t     priority,
                        const uint64_t          topic_hash,
                        const udpard_udpip_ep_t remote_ep[UDPARD_IFACE_COUNT_MAX],
                        const uint64_t          transfer_id,
                        const udpard_bytes_t    payload,
                        void (*const feedback)(udpard_tx_t*, udpard_tx_feedback_t),
                        void* const user_transfer_reference)
{
    uint32_t   out = 0;
    const bool ok  = (self != NULL) && (deadline >= now) && (now >= 0) && (self->local_uid != 0) &&
                    (valid_ep_mask(remote_ep) != 0) && (priority <= UDPARD_PRIORITY_MAX) &&
                    ((payload.data != NULL) || (payload.size == 0U)) &&
                    (tx_transfer_find(self, topic_hash, transfer_id) == NULL);
    if (ok) {
        // Before attempting to enqueue a new transfer, we need to update the transmission scheduler.
        // It may release some items from the tx queue, and it may also promote some staged transfers to the queue.
        udpard_tx_poll(self, now, UDPARD_IFACE_MASK_ALL);
        const meta_t meta = {
            .priority              = priority,
            .flag_ack              = feedback != NULL,
            .transfer_payload_size = (uint32_t)payload.size,
            .transfer_id           = transfer_id,
            .sender_uid            = self->local_uid,
            .topic_hash            = topic_hash,
        };
        out = tx_push(self, //
                      now,
                      deadline,
                      meta,
                      remote_ep,
                      payload,
                      feedback,
                      user_transfer_reference,
                      NULL);
    }
    return out;
}

static void tx_purge_expired(udpard_tx_t* const self, const udpard_us_t now)
{
    while (true) { // we can use next_greater instead of doing min search every time
        tx_transfer_t* const tr = CAVL2_TO_OWNER(cavl2_min(self->index_deadline), tx_transfer_t, index_deadline);
        if ((tr != NULL) && (now > tr->deadline)) {
            if (tr->feedback != NULL) {
                const udpard_tx_feedback_t fb = tx_make_feedback(tr, false);
                tx_transfer_free_payload(tr); // do this early to release memory before callback
                tr->feedback(self, fb);
            }
            tx_transfer_free(self, tr);
            self->errors_expiration++;
        } else {
            break;
        }
    }
}

static void tx_promote_staged(udpard_tx_t* const self, const udpard_us_t now)
{
    while (true) { // we can use next_greater instead of doing min search every time
        tx_transfer_t* const tr = CAVL2_TO_OWNER(cavl2_min(self->index_staged), tx_transfer_t, index_staged);
        if ((tr != NULL) && (now >= tr->staged_until)) {
            UDPARD_ASSERT(tr->cursor != NULL); // cannot stage without payload, doesn't make sense
            // Reinsert into the staged index at the new position, when the next attempt is due.
            // Do not insert if this is the last attempt -- no point doing that since it will not be transmitted again.
            cavl2_remove(&self->index_staged, &tr->index_staged);
            tr->staged_until += tx_ack_timeout(self->ack_baseline_timeout, tr->priority, ++(tr->epoch));
            if (tr->deadline > tr->staged_until) {
                (void)cavl2_find_or_insert(&self->index_staged,
                                           &tr->staged_until,
                                           tx_cavl_compare_staged,
                                           &tr->index_staged,
                                           cavl2_trivial_factory);
            }
            // Enqueue for transmission unless it's been there since the last attempt (stalled interface?)
            for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
                UDPARD_ASSERT(tr->cursor[i] == tr->head[i]);
                if (udpard_is_valid_endpoint(tr->destination[i]) &&
                    !is_listed(&self->queue[i][tr->priority], &tr->queue[i])) {
                    enlist_head(&self->queue[i][tr->priority], &tr->queue[i]);
                }
            }
        } else {
            break;
        }
    }
}

static void tx_eject_pending(udpard_tx_t* const self, const udpard_us_t now, const uint_fast8_t ifindex)
{
    while (true) {
        // Find the highest-priority pending transfer.
        tx_transfer_t* tr = NULL;
        for (size_t prio = 0; prio < UDPARD_PRIORITY_COUNT; prio++) {
            tx_transfer_t* const candidate = // This pointer arithmetic is ugly and perhaps should be improved
              unbias_ptr(self->queue[ifindex][prio].tail,
                         offsetof(tx_transfer_t, queue) + (sizeof(udpard_list_member_t) * ifindex));
            if (candidate != NULL) {
                tr = candidate;
                break;
            }
        }
        if (tr == NULL) {
            break; // No pending transfers at the moment. Find something else to do.
        }
        UDPARD_ASSERT(tr->cursor[ifindex] != NULL); // cannot be pending without payload, doesn't make sense
        UDPARD_ASSERT(tr->priority < UDPARD_PRIORITY_COUNT);

        // Eject the frame.
        const tx_frame_t* const frame        = tr->cursor[ifindex];
        tx_frame_t* const       frame_next   = frame->next;
        const bool              last_attempt = tr->deadline <= tr->staged_until;
        const bool              last_frame  = frame_next == NULL; // if not last attempt we will have to rewind to head.
        const udpard_tx_ejection_t ejection = {
            .now                     = now,
            .deadline                = tr->deadline,
            .iface_index             = ifindex,
            .dscp                    = self->dscp_value_per_priority[tr->priority],
            .destination             = tr->destination[ifindex],
            .datagram                = tx_frame_view(frame),
            .user_transfer_reference = tr->user_transfer_reference,
        };
        if (!self->vtable->eject(self, ejection)) { // The easy case -- no progress was made at this time;
            break;                                  // don't change anything, just try again later as-is
        }

        // Frame ejected successfully. Update the transfer state to get ready for the next frame.
        if (last_attempt) { // no need to keep frames that we will no longer use; free early to reduce pressure
            UDPARD_ASSERT(tr->head[ifindex] == tr->cursor[ifindex]);
            tr->head[ifindex] = frame_next;
            udpard_tx_refcount_dec(ejection.datagram);
        }
        tr->cursor[ifindex] = frame_next;

        // Finalize the transmission if this was the last frame of the transfer.
        if (last_frame) {
            tr->cursor[ifindex] = tr->head[ifindex];
            delist(&self->queue[ifindex][tr->priority], &tr->queue[ifindex]); // no longer pending for transmission
            UDPARD_ASSERT(!last_attempt || (tr->head[ifindex] == NULL));      // this iface is done with the payload
            if (last_attempt && !tr->reliable && !tx_is_pending(self, tr)) {  // remove early once all ifaces are done
                tx_transfer_free(self, tr);
            }
        }
    }
}

void udpard_tx_poll(udpard_tx_t* const self, const udpard_us_t now, const uint_fast8_t iface_mask)
{
    if ((self != NULL) && (now >= 0)) { // This is the main scheduler state machine update tick.
        tx_purge_expired(self, now);    // This may free up some memory and some queue slots.
        tx_promote_staged(self, now);   // This may add some new transfers to the queue.
        for (uint_fast8_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
            if ((iface_mask & (1U << i)) != 0U) {
                tx_eject_pending(self, now, i);
            }
        }
    }
}

void udpard_tx_refcount_inc(const udpard_bytes_t tx_payload_view)
{
    if (tx_payload_view.data != NULL) {
        tx_frame_t* const frame = tx_frame_from_view(tx_payload_view);
        UDPARD_ASSERT(frame->refcount > 0); // NOLINT(*ArrayBound)
        frame->refcount++;
    }
}

void udpard_tx_refcount_dec(const udpard_bytes_t tx_payload_view)
{
    if (tx_payload_view.data != NULL) {
        tx_frame_t* const frame = tx_frame_from_view(tx_payload_view);
        UDPARD_ASSERT(frame->refcount > 0); // NOLINT(*ArrayBound)
        frame->refcount--;
        if (frame->refcount == 0U) {
            --*frame->objcount;
            frame->deleter.free(frame->deleter.user, sizeof(tx_frame_t) + tx_payload_view.size, frame);
        }
    }
}

void udpard_tx_free(udpard_tx_t* const self)
{
    if (self != NULL) {
        while (self->index_transfer != NULL) {
            tx_transfer_free(self, CAVL2_TO_OWNER(self->index_transfer, tx_transfer_t, index_transfer));
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------        RX PIPELINE        ---------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
//
// The RX pipeline is a layered solution: PORT -> SESSION -> SLOT -> FRAGMENT TREE.
//
// Ports are created by the application per subject to subscribe to. There are various parameters defined per port,
// such as the extent (max payload size to accept) and the reassembly mode (ORDERED, UNORDERED, STATELESS).
//
// Each port automatically creates a dedicated session per remote node that publishes on that subject
// (unless the STATELESS mode is used, which is simple and limited). Sessions are automatically cleaned up and
// removed when the remote node ceases to publish for a certain (large) timeout period.
//
// Each session holds RX_SLOT_COUNT slots for concurrent transfers from the same remote node on the same subject;
// concurrent transfers may occur due to spontaneous datagram reordering or when the sender needs to emit a higher-
// priority transfer while a lower-priority transfer is still ongoing (this is why there needs to be at least as many
// slots as there are priority levels). Each slot accepts frames from all redundant network interfaces at once and
// runs an efficient fragment tree reassembler to reconstruct the original transfer payload with automatic deduplication
// and defragmentation; since all interfaces are pooled together, the reassembler is completely insensitive to
// permanent or transient failure of any of the redundant interfaces; as long as at least one of them is able to
// deliver frames, the link will function; further, transient packet loss in one of the interfaces does not affect
// the overall reliability.
//
// Each session holds an efficient bitmap of recently received/seen transfers, which is used for ack retransmission
// if the remote end attempts to retransmit a transfer that was already fully received, and is also used for duplicate
// rejection. In the ORDERED mode, late transfers (those arriving out of order past the reordering window closure)
// are never acked, but they may still be received and acked by some other nodes in the network.
//
// Acks are transmitted immediately upon successful reception of a transfer. If the remote end retransmits the transfer
// (e.g., if the first ack was lost or due to a spurious duplication), repeat acks are only retransmitted
// for the first frame of the transfer because:
//
// - We don't want to flood the network with duplicate ACKs for every fragment of a multi-frame transfer.
//   They are already duplicated for each redundant interface.
//
// - The application may need to look at the head of the transfer to handle acks, which is in the first frame.
//
// The redundant interfaces may have distinct MTUs, so the fragment offsets and sizes may vary significantly.
// The reassembler decides if a newly arrived fragment is needed based on gap detection in the fragment tree.
// An accepted fragment may overlap with neighboring fragments; however, the reassembler guarantees that no fragment is
// fully contained within another fragment; this also implies that there are no fragments sharing the same offset,
// and that fragments ordered by offset are also ordered by their ends.
// The reassembler prefers to keep fewer large fragments over many small fragments, to reduce the overhead of
// managing the fragment tree and the amount of auxiliary memory required for it.

/// All but the transfer metadata: fields that change from frame to frame within the same transfer.
typedef struct
{
    size_t             offset;  ///< Offset of this fragment's payload within the full transfer payload.
    udpard_bytes_t     payload; ///< Does not include the header, just pure payload.
    udpard_bytes_mut_t origin;  ///< The entirety of the free-able buffer passed from the application.
    uint32_t           crc;     ///< CRC of all preceding payload bytes in the transfer plus this fragment's payload.
} rx_frame_base_t;

/// Full frame state.
typedef struct rx_frame_t
{
    rx_frame_base_t base;
    meta_t          meta;
} rx_frame_t;

// ---------------------------------------------  FRAGMENT TREE  ---------------------------------------------

/// Finds the number of contiguous payload bytes received from offset zero after accepting a new fragment.
/// The transfer is considered fully received when covered_prefix >= min(extent, transfer_payload_size).
/// This should be invoked after the fragment tree accepted a new fragment at frag_offset with frag_size.
/// The complexity is amortized-logarithmic, worst case is linear in the number of frames in the transfer.
static size_t rx_fragment_tree_update_covered_prefix(udpard_tree_t* const root,
                                                     const size_t         old_prefix,
                                                     const size_t         frag_offset,
                                                     const size_t         frag_size)
{
    const size_t end = frag_offset + frag_size;
    if ((frag_offset > old_prefix) || (end <= old_prefix)) {
        return old_prefix; // The new fragment does not cross the frontier, so it cannot affect the prefix.
    }
    udpard_fragment_t* fr = (udpard_fragment_t*)cavl2_predecessor(root, &old_prefix, &cavl_compare_fragment_offset);
    UDPARD_ASSERT(fr != NULL);
    size_t out = old_prefix;
    while ((fr != NULL) && (fr->offset <= out)) {
        out = larger(out, fr->offset + fr->view.size);
        fr  = (udpard_fragment_t*)cavl2_next_greater(&fr->index_offset);
    }
    return out;
}

/// If NULL, the payload ownership could not be transferred due to OOM. The caller still owns the payload.
static udpard_fragment_t* rx_fragment_new(const udpard_mem_resource_t memory,
                                          const udpard_mem_deleter_t  payload_deleter,
                                          const rx_frame_base_t       frame)
{
    udpard_fragment_t* const mew = mem_alloc(memory, sizeof(udpard_fragment_t));
    if (mew != NULL) {
        mem_zero(sizeof(*mew), mew);
        mew->index_offset    = (udpard_tree_t){ NULL, { NULL, NULL }, 0 };
        mew->offset          = frame.offset;
        mew->view.data       = frame.payload.data;
        mew->view.size       = frame.payload.size;
        mew->origin.data     = frame.origin.data;
        mew->origin.size     = frame.origin.size;
        mew->payload_deleter = payload_deleter;
    }
    return mew;
}

typedef enum
{
    rx_fragment_tree_rejected, ///< The newly received fragment was not needed for the tree and was freed.
    rx_fragment_tree_accepted, ///< The newly received fragment was accepted into the tree, possibly replacing another.
    rx_fragment_tree_done,     ///< The newly received fragment completed the transfer; the caller must extract payload.
    rx_fragment_tree_oom,      ///< The fragment could not be accepted, but a possible future duplicate may work.
} rx_fragment_tree_update_result_t;

/// Takes ownership of the frame payload; either a new fragment is inserted or the payload is freed.
static rx_fragment_tree_update_result_t rx_fragment_tree_update(udpard_tree_t** const       root,
                                                                const udpard_mem_resource_t fragment_memory,
                                                                const udpard_mem_deleter_t  payload_deleter,
                                                                const rx_frame_base_t       frame,
                                                                const size_t                transfer_payload_size,
                                                                const size_t                extent,
                                                                size_t* const               covered_prefix_io)
{
    const size_t left  = frame.offset;
    const size_t right = frame.offset + frame.payload.size;

    // Ignore frames beyond the extent. Zero extent requires special handling because from the reassembler's
    // view such transfers are useless, but we still want them.
    if (((extent > 0) && (left >= extent)) || ((extent == 0) && (left > extent))) {
        mem_free_payload(payload_deleter, frame.origin);
        return rx_fragment_tree_rejected; // New fragment is beyond the extent, discard.
    }

    // Check if the new fragment is fully contained within an existing fragment, or is an exact replica of one.
    // We discard those early to maintain an essential invariant of the fragment tree: no fully-contained fragments.
    {
        const udpard_fragment_t* const frag =
          (udpard_fragment_t*)cavl2_predecessor(*root, &left, &cavl_compare_fragment_offset);
        if ((frag != NULL) && ((frag->offset + frag->view.size) >= right)) {
            mem_free_payload(payload_deleter, frame.origin);
            return rx_fragment_tree_rejected; // New fragment is fully contained within an existing one, discard.
        }
    }

    // Find the left and right neighbors, if any, with possible (likely) overlap. Consider new fragment X with A, B, C:
    //         |----X----|
    //      |--A--|
    //           |--B--|
    //                |--C--|
    // Here, only A is the left neighbor, and only C is the right neighbor. B is a victim.
    // If A.right >= C.left, then there is neither a gap nor a victim to remove.
    //
    // To find the left neighbor, we need to find the fragment crossing the left boundary whose offset is the smallest.
    // To do that, we simply need to find the fragment with the smallest right boundary that is on the right of our
    // left boundary. This works because by construction we guarantee that our tree has no fully-contained fragments,
    // implying that ordering by left is also ordering by right.
    //
    // The right neighbor is found by analogy: find the fragment with the largest left boundary that is on the left
    // of our right boundary. This guarantees that the new virtual right boundary will max out to the right.
    const udpard_fragment_t* n_left = (udpard_fragment_t*)cavl2_lower_bound(*root, &left, &cavl_compare_fragment_end);
    if ((n_left != NULL) && (n_left->offset >= left)) {
        n_left = NULL; // There is no left neighbor.
    }
    const udpard_fragment_t* n_right =
      (udpard_fragment_t*)cavl2_predecessor(*root, &right, &cavl_compare_fragment_offset);
    if ((n_right != NULL) && ((n_right->offset + n_right->view.size) <= right)) {
        n_right = NULL; // There is no right neighbor.
    }
    const size_t n_left_size  = (n_left != NULL) ? n_left->view.size : 0U;
    const size_t n_right_size = (n_right != NULL) ? n_right->view.size : 0U;

    // Simple acceptance heuristic -- if the new fragment adds new payload, allows to eliminate a smaller fragment,
    // or is larger than either neighbor, we accept it. The 'larger' condition is intended to allow
    // eventual replacement of many small fragments with fewer large fragments.
    // Consider the following scenario:
    //      |--A--|--B--|--C--|--D--|   <-- small MTU set
    //      |---X---|---Y---|---Z---|   <-- large MTU set
    // Suppose we already have A..D received. Arrival of either X or Z allows eviction of A/D immediately.
    // Arrival of Y does not allow an immediate eviction of any fragment, but if we had rejected it because it added
    // no new coverage, we would miss the opportunity to evict B/C when X or Z arrive later. By this logic alone,
    // we would also have to accept B and C if they were to arrive after X/Y/Z, which is however unnecessary because
    // these fragments add no new information AND are smaller than the existing fragments, meaning that they offer
    // no prospect of eventual defragmentation, so we reject them immediately.
    const bool accept = (n_left == NULL) || (n_right == NULL) ||
                        ((n_left->offset + n_left->view.size) < n_right->offset) ||
                        (frame.payload.size > smaller(n_left_size, n_right_size));
    if (!accept) {
        mem_free_payload(payload_deleter, frame.origin);
        return rx_fragment_tree_rejected; // New fragment is not expected to be useful.
    }

    // Ensure we can allocate the fragment header for the new frame before pruning the tree to avoid data loss.
    udpard_fragment_t* const mew = rx_fragment_new(fragment_memory, payload_deleter, frame);
    if (mew == NULL) {
        mem_free_payload(payload_deleter, frame.origin);
        return rx_fragment_tree_oom; // Cannot allocate fragment header. Maybe we will succeed later.
    }

    // The addition of a new fragment that joins adjacent fragments together into a larger contiguous block may
    // render smaller fragments crossing its boundaries redundant.
    // To check for that, we create a new virtual fragment that represents the new fragment together with those
    // that join it on either end, if any, and then look for fragments contained within the virtual one.
    // The virtual boundaries are adjusted by 1 to ensure that the neighbors themselves are not marked for eviction.
    // Example:
    //          |--A--|--B--|
    //             |--X--|
    // The addition of fragment A or B will render X redundant, even though it is not contained within either.
    // This algorithm will detect that and mark X for removal.
    const size_t v_left = smaller(left, (n_left == NULL) ? SIZE_MAX : (n_left->offset + 1U));
    const size_t v_right =
      larger(right, (n_right == NULL) ? 0 : (larger(n_right->offset + n_right->view.size, 1U) - 1U));
    UDPARD_ASSERT((v_left <= left) && (right <= v_right));

    // Remove all redundant fragments before inserting the new one.
    // No need to repeat tree lookup at every iteration, we just step through the nodes using the next_greater lookup.
    udpard_fragment_t* victim = (udpard_fragment_t*)cavl2_lower_bound(*root, &v_left, &cavl_compare_fragment_offset);
    while ((victim != NULL) && (victim->offset >= v_left) && ((victim->offset + victim->view.size) <= v_right)) {
        udpard_fragment_t* const next = (udpard_fragment_t*)cavl2_next_greater(&victim->index_offset);
        cavl2_remove(root, &victim->index_offset);
        mem_free_payload(victim->payload_deleter, victim->origin);
        mem_free(fragment_memory, sizeof(udpard_fragment_t), victim);
        victim = next;
    }
    // Insert the new fragment.
    const udpard_tree_t* const res = cavl2_find_or_insert(root, //
                                                          &mew->offset,
                                                          &cavl_compare_fragment_offset,
                                                          &mew->index_offset,
                                                          &cavl2_trivial_factory);
    UDPARD_ASSERT(res == &mew->index_offset);
    (void)res;
    // Update the covered prefix. This requires only a single full scan across all iterations!
    *covered_prefix_io = rx_fragment_tree_update_covered_prefix(*root, //
                                                                *covered_prefix_io,
                                                                frame.offset,
                                                                frame.payload.size);
    return (*covered_prefix_io >= smaller(extent, transfer_payload_size)) ? rx_fragment_tree_done
                                                                          : rx_fragment_tree_accepted;
}

/// 1. Eliminates payload overlaps. They may appear if redundant interfaces with different MTU settings are used.
/// 2. Verifies the CRC of the reassembled payload.
/// 3. Links all fragments into a linked list for convenient application consumption.
/// Returns true iff the transfer is valid and safe to deliver to the application.
/// Observe that this function alters the tree ordering keys, but it does not alter the tree topology,
/// because each fragment's offset is changed within the bounds that preserve the ordering.
static bool rx_fragment_tree_finalize(udpard_tree_t* const root, const uint32_t crc_expected)
{
    uint32_t crc_computed = CRC_INITIAL;
    size_t   offset       = 0;
    for (udpard_tree_t* p = cavl2_min(root); p != NULL; p = cavl2_next_greater(p)) {
        udpard_fragment_t* const frag = (udpard_fragment_t*)p;
        UDPARD_ASSERT(frag->offset <= offset); // The tree reassembler cannot leave gaps.
        const size_t trim = offset - frag->offset;
        // The tree reassembler evicts redundant fragments, so there must be some payload, unless the transfer is empty.
        UDPARD_ASSERT((trim < frag->view.size) || ((frag->view.size == 0) && (trim == 0) && (offset == 0)));
        frag->offset += trim;
        frag->view.data = (const byte_t*)frag->view.data + trim;
        frag->view.size -= trim;
        offset += frag->view.size;
        crc_computed = crc_add(crc_computed, frag->view.size, frag->view.data);
    }
    return (crc_computed ^ CRC_OUTPUT_XOR) == crc_expected;
}

// ---------------------------------------------  SLOT  ---------------------------------------------

typedef enum
{
    rx_slot_idle = 0,
    rx_slot_busy = 1,
    rx_slot_done = 2,
} rx_slot_state_t;

/// Frames from all redundant interfaces are pooled into the same reassembly slot per transfer-ID.
/// The redundant interfaces may use distinct MTU, which requires special fragment tree handling.
typedef struct
{
    rx_slot_state_t state;

    uint64_t transfer_id; ///< Which transfer we're reassembling here.

    udpard_us_t ts_min; ///< Earliest frame timestamp, aka transfer reception timestamp.
    udpard_us_t ts_max; ///< Latest frame timestamp, aka transfer completion timestamp.

    size_t covered_prefix; ///< Number of bytes received contiguously from offset zero.
    size_t total_size;     ///< The total size of the transfer payload being transmitted (we may only use part of it).

    size_t   crc_end; ///< The end offset of the frame whose CRC is stored in `crc`.
    uint32_t crc;     ///< Once the reassembly is done, holds the CRC of the entire transfer.

    udpard_prio_t priority;

    udpard_tree_t* fragments;
} rx_slot_t;

static void rx_slot_reset(rx_slot_t* const slot, const udpard_mem_resource_t fragment_memory)
{
    udpard_fragment_free_all((udpard_fragment_t*)slot->fragments, fragment_memory);
    slot->fragments      = NULL;
    slot->state          = rx_slot_idle;
    slot->covered_prefix = 0U;
    slot->crc_end        = 0U;
    slot->crc            = CRC_INITIAL;
}

/// The caller will accept the ownership of the fragments iff the resulting state is done.
static void rx_slot_update(rx_slot_t* const            slot,
                           const udpard_us_t           ts,
                           const udpard_mem_resource_t fragment_memory,
                           const udpard_mem_deleter_t  payload_deleter,
                           rx_frame_t* const           frame,
                           const size_t                extent,
                           uint64_t* const             errors_oom,
                           uint64_t* const             errors_transfer_malformed)
{
    if (slot->state != rx_slot_busy) {
        rx_slot_reset(slot, fragment_memory);
        slot->state       = rx_slot_busy;
        slot->transfer_id = frame->meta.transfer_id;
        slot->ts_min      = ts;
        slot->ts_max      = ts;
        // Some metadata is only needed to pass it over to the application once the transfer is done.
        slot->total_size = frame->meta.transfer_payload_size;
        slot->priority   = frame->meta.priority;
    }
    // Enforce consistent per-frame values throughout the transfer.
    if ((slot->total_size != frame->meta.transfer_payload_size) || (slot->priority != frame->meta.priority)) {
        ++*errors_transfer_malformed;
        mem_free_payload(payload_deleter, frame->base.origin);
        rx_slot_reset(slot, fragment_memory);
        return;
    }
    const rx_fragment_tree_update_result_t tree_res = rx_fragment_tree_update(&slot->fragments,
                                                                              fragment_memory,
                                                                              payload_deleter,
                                                                              frame->base,
                                                                              frame->meta.transfer_payload_size,
                                                                              extent,
                                                                              &slot->covered_prefix);
    if ((tree_res == rx_fragment_tree_accepted) || (tree_res == rx_fragment_tree_done)) {
        slot->ts_max         = later(slot->ts_max, ts);
        slot->ts_min         = earlier(slot->ts_min, ts);
        const size_t crc_end = frame->base.offset + frame->base.payload.size;
        if (crc_end >= slot->crc_end) {
            slot->crc_end = crc_end;
            slot->crc     = frame->base.crc;
        }
    }
    if (tree_res == rx_fragment_tree_oom) {
        ++*errors_oom;
    }
    if (tree_res == rx_fragment_tree_done) {
        if (rx_fragment_tree_finalize(slot->fragments, slot->crc)) {
            slot->state = rx_slot_done; // The caller will handle the completed transfer.
        } else {
            ++*errors_transfer_malformed;
            rx_slot_reset(slot, fragment_memory);
        }
    }
}

// ---------------------------------------------  SESSION & PORT  ---------------------------------------------

/// The number of times `from` must be incremented (modulo 2^64) to reach `to`.
static uint64_t rx_transfer_id_forward_distance(const uint64_t from, const uint64_t to) { return to - from; }

/// Keep in mind that we have a dedicated session object per remote node per port; this means that the states
/// kept here are specific per remote node, as it should be.
typedef struct rx_session_t
{
    udpard_tree_t   index_remote_uid; ///< Must be the first member.
    udpard_remote_t remote;           ///< Most recent discovered reverse path for P2P to the sender.

    udpard_rx_port_t* port;

    /// Sessions interned for the reordering window closure.
    udpard_tree_t index_reordering_window;
    udpard_us_t   reordering_window_deadline;

    /// LRU last animated list for automatic retirement of stale sessions.
    udpard_list_member_t list_by_animation;
    udpard_us_t          last_animated_ts;

    /// Most recently received transfer-IDs, used for duplicate detection and ACK retransmission.
    /// The index is always in [0,RX_TRANSFER_HISTORY_COUNT), pointing to the last added (newest) entry.
    uint64_t     history[RX_TRANSFER_HISTORY_COUNT];
    uint_fast8_t history_current;

    bool initialized; ///< Set after the first frame is seen.

    rx_slot_t slots[RX_SLOT_COUNT];
} rx_session_t;

/// The reassembly strategy is composed once at initialization time by choosing a vtable with the desired behavior.
typedef struct udpard_rx_port_vtable_private_t
{
    /// Takes ownership of the frame payload.
    void (*accept)(udpard_rx_t*,
                   udpard_rx_port_t*,
                   udpard_us_t,
                   udpard_udpip_ep_t,
                   rx_frame_t*,
                   udpard_mem_deleter_t,
                   uint_fast8_t);
    /// Takes ownership of the frame payload.
    void (*update_session)(rx_session_t*, udpard_rx_t*, udpard_us_t, rx_frame_t*, udpard_mem_deleter_t);
} udpard_rx_port_vtable_private_t;

/// True iff the given transfer-ID was recently ejected.
static bool rx_session_is_transfer_ejected(const rx_session_t* const self, const uint64_t transfer_id)
{
    for (size_t i = 0; i < RX_TRANSFER_HISTORY_COUNT; i++) { // dear compiler, please unroll this loop
        if (transfer_id == self->history[i]) {
            return true;
        }
    }
    return false;
}

/// True iff the given transfer-ID is shortly before one of the recently ejected ones or equals one.
/// In the ORDERED mode, this indicates that the transfer is late and can no longer be ejected.
static bool rx_session_is_transfer_late_or_ejected(const rx_session_t* const self, const uint64_t transfer_id)
{
    for (size_t i = 0; i < RX_TRANSFER_HISTORY_COUNT; i++) {
        if (rx_transfer_id_forward_distance(transfer_id, self->history[i]) < RX_TRANSFER_ORDERING_WINDOW) {
            return true;
        }
    }
    return false;
}

/// True iff the transfer is already received but is not yet ejected to maintain ordering. Only useful for ORDERED mode.
static bool rx_session_is_transfer_interned(const rx_session_t* const self, const uint64_t transfer_id)
{
    for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
        if ((self->slots[i].state == rx_slot_done) && (self->slots[i].transfer_id == transfer_id)) {
            return true;
        }
    }
    return false;
}

static int32_t cavl_compare_rx_session_by_remote_uid(const void* const user, const udpard_tree_t* const node)
{
    const uint64_t uid_a = *(const uint64_t*)user;
    const uint64_t uid_b = ((const rx_session_t*)(const void*)node)->remote.uid; // clang-format off
    if (uid_a < uid_b) { return -1; }
    if (uid_a > uid_b) { return +1; }
    return 0; // clang-format on
}

static int32_t cavl_compare_rx_session_by_reordering_deadline(const void* const user, const udpard_tree_t* const node)
{
    const udpard_us_t dl_a = *(const udpard_us_t*)user;
    const udpard_us_t dl_b = CAVL2_TO_OWNER(node, rx_session_t, index_reordering_window)->reordering_window_deadline;
    return (dl_a >= dl_b) ? +1 : -1;
}

typedef struct
{
    udpard_rx_port_t* owner;
    udpard_list_t*    sessions_by_animation;
    uint64_t          remote_uid;
    udpard_us_t       now;
} rx_session_factory_args_t;

static udpard_tree_t* cavl_factory_rx_session_by_remote_uid(void* const user)
{
    const rx_session_factory_args_t* const args = (const rx_session_factory_args_t*)user;
    rx_session_t* const                    out  = mem_alloc(args->owner->memory.session, sizeof(rx_session_t));
    if (out != NULL) {
        mem_zero(sizeof(*out), out);
        out->index_remote_uid           = (udpard_tree_t){ NULL, { NULL, NULL }, 0 };
        out->index_reordering_window    = (udpard_tree_t){ NULL, { NULL, NULL }, 0 };
        out->reordering_window_deadline = BIG_BANG;
        out->list_by_animation          = (udpard_list_member_t){ NULL, NULL };
        for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
            out->slots[i].fragments = NULL;
            rx_slot_reset(&out->slots[i], args->owner->memory.fragment);
        }
        out->remote.uid       = args->remote_uid;
        out->port             = args->owner;
        out->last_animated_ts = args->now;
        out->history_current  = 0;
        out->initialized      = false;
        enlist_head(args->sessions_by_animation, &out->list_by_animation);
    }
    return (udpard_tree_t*)out;
}

/// Removes the instance from all indexes and frees all associated memory.
static void rx_session_free(rx_session_t* const   self,
                            udpard_list_t* const  sessions_by_animation,
                            udpard_tree_t** const sessions_by_reordering)
{
    for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
        rx_slot_reset(&self->slots[i], self->port->memory.fragment);
    }
    cavl2_remove(&self->port->index_session_by_remote_uid, &self->index_remote_uid);
    if (cavl2_is_inserted(*sessions_by_reordering, &self->index_reordering_window)) {
        cavl2_remove(sessions_by_reordering, &self->index_reordering_window);
    }
    delist(sessions_by_animation, &self->list_by_animation);
    mem_free(self->port->memory.session, sizeof(rx_session_t), self);
}

/// The payload ownership is transferred to the application. The history log and the window will be updated.
static void rx_session_eject(rx_session_t* const self, udpard_rx_t* const rx, rx_slot_t* const slot)
{
    UDPARD_ASSERT(slot->state == rx_slot_done);

    // Update the history -- overwrite the oldest entry.
    self->history_current                = (self->history_current + 1U) % RX_TRANSFER_HISTORY_COUNT;
    self->history[self->history_current] = slot->transfer_id;

    // Construct the arguments and invoke the callback.
    const udpard_rx_transfer_t transfer = {
        .timestamp           = slot->ts_min,
        .priority            = slot->priority,
        .transfer_id         = slot->transfer_id,
        .remote              = self->remote,
        .payload_size_stored = slot->covered_prefix,
        .payload_size_wire   = slot->total_size,
        .payload             = (udpard_fragment_t*)slot->fragments,
    };
    self->port->vtable->on_message(rx, self->port, transfer);

    // Finally, reset the slot.
    slot->fragments = NULL; // Transfer ownership to the application.
    rx_slot_reset(slot, self->port->memory.fragment);
}

/// In the ORDERED mode, checks which slots can be ejected or interned in the reordering window.
/// This is only useful for the ORDERED mode.
/// Should be invoked whenever a slot MAY or MUST be ejected (i.e., on completion or when an empty slot is required).
/// If the force flag is set, at least one DONE slot will be ejected even if its reordering window is still open;
/// this is used to forcibly free up at least one slot when all slots are busy and a new transfer arrives.
static void rx_session_ordered_scan_slots(rx_session_t* const self,
                                          udpard_rx_t* const  rx,
                                          const udpard_us_t   ts,
                                          const bool          force_one)
{
    // Reset the reordering window timer because we will either eject everything or arm it again later.
    if (cavl2_is_inserted(rx->index_session_by_reordering, &self->index_reordering_window)) {
        cavl2_remove(&rx->index_session_by_reordering, &self->index_reordering_window);
        self->reordering_window_deadline = BIG_BANG;
    }
    // We need to repeat the scan because each ejection may open up the window for the next in-sequence transfer.
    for (size_t iter = 0; iter < RX_SLOT_COUNT; iter++) {
        // Find the slot closest to the next in-sequence transfer-ID.
        const uint64_t tid_expected = self->history[self->history_current] + 1U;
        uint64_t       min_tid_dist = UINT64_MAX;
        rx_slot_t*     slot         = NULL;
        for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
            const uint64_t dist = rx_transfer_id_forward_distance(tid_expected, self->slots[i].transfer_id);
            if ((self->slots[i].state == rx_slot_done) && (dist < min_tid_dist)) {
                min_tid_dist = dist;
                slot         = &self->slots[i];
                if (dist == 0) {
                    break; // Fast path for a common case.
                }
            }
        }
        // The slot needs to be ejected if it's in-sequence, if it's reordering window is closed, or if we're
        // asked to force an ejection and we haven't done so yet.
        // The reordering window timeout implies that earlier transfers will be dropped if ORDERED mode is used.
        const bool eject =
          (slot != NULL) && ((slot->transfer_id == tid_expected) ||
                             (ts >= (slot->ts_min + self->port->reordering_window)) || (force_one && (iter == 0)));
        if (!eject) {
            // The slot is done but cannot be ejected yet; arm the reordering window timer.
            // There may be transfers with future (more distant) transfer-IDs with an earlier reordering window
            // closure deadline, but we ignore them because the nearest transfer overrides the more distant ones.
            if (slot != NULL) {
                self->reordering_window_deadline = slot->ts_min + self->port->reordering_window;
                const udpard_tree_t* res = cavl2_find_or_insert(&rx->index_session_by_reordering, //-------------
                                                                &self->reordering_window_deadline,
                                                                &cavl_compare_rx_session_by_reordering_deadline,
                                                                &self->index_reordering_window,
                                                                &cavl2_trivial_factory);
                UDPARD_ASSERT(res == &self->index_reordering_window);
                (void)res;
            }
            break; // No more slots can be ejected at this time.
        }
        // We always pick the next transfer to eject with the nearest transfer-ID, which guarantees that the other
        // DONE transfers will not end up being late.
        // Some of the in-progress slots may be obsoleted by this move, which will be taken care of later.
        UDPARD_ASSERT((slot != NULL) && (slot->state == rx_slot_done));
        rx_session_eject(self, rx, slot);
    }
    // Ensure that in-progress slots, if any, have not ended up within the accepted window after the update.
    // We can release them early to avoid holding the payload buffers that won't be used anyway.
    for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
        rx_slot_t* const slot = &self->slots[i];
        if ((slot->state == rx_slot_busy) && rx_session_is_transfer_late_or_ejected(self, slot->transfer_id)) {
            rx_slot_reset(slot, self->port->memory.fragment);
        }
    }
}

/// Finds an existing in-progress slot with the specified transfer-ID, or allocates a new one.
/// Allocation always succeeds so the result is never NULL, but it may cause early ejection of an interned DONE slot.
/// THIS IS POTENTIALLY DESTRUCTIVE IN THE ORDERED MODE because it may force an early reordering window closure.
static rx_slot_t* rx_session_get_slot(rx_session_t* const self,
                                      udpard_rx_t* const  rx,
                                      const udpard_us_t   ts,
                                      const uint64_t      transfer_id)
{
    // First, check if one is in progress already; resume it if so.
    for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
        if ((self->slots[i].state == rx_slot_busy) && (self->slots[i].transfer_id == transfer_id)) {
            return &self->slots[i];
        }
    }
    // Use this opportunity to check for timed-out in-progress slots. This may free up a slot for the search below.
    for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
        if ((self->slots[i].state == rx_slot_busy) && (ts >= (self->slots[i].ts_max + SESSION_LIFETIME))) {
            rx_slot_reset(&self->slots[i], self->port->memory.fragment);
        }
    }
    // This appears to be a new transfer, so we will need to allocate a new slot for it.
    for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
        if (self->slots[i].state == rx_slot_idle) {
            return &self->slots[i];
        }
    }
    // All slots are currently occupied; find the oldest slot to sacrifice, which may be busy or done.
    rx_slot_t*  slot      = NULL;
    udpard_us_t oldest_ts = HEAT_DEATH;
    for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
        UDPARD_ASSERT(self->slots[i].state != rx_slot_idle); // Checked this already.
        if (self->slots[i].ts_max < oldest_ts) {
            oldest_ts = self->slots[i].ts_max;
            slot      = &self->slots[i];
        }
    }
    UDPARD_ASSERT((slot != NULL) && ((slot->state == rx_slot_busy) || (slot->state == rx_slot_done)));
    // If it's busy, it is probably just a stale transfer, so it's a no-brainer to evict it.
    // If it's done, we have to force the reordering window to close early to free up a slot without transfer loss.
    if (slot->state == rx_slot_busy) {
        rx_slot_reset(slot, self->port->memory.fragment); // Just a stale transfer, it's probably dead anyway.
    } else {
        UDPARD_ASSERT(slot->state == rx_slot_done);
        // The oldest slot is DONE; we cannot just reset it, we must force an early ejection.
        // The slot to eject will be chosen based on the transfer-ID, which may not be the oldest slot.
        // Then we repeat the search looking for any IDLE slot, which must succeed now.
        rx_session_ordered_scan_slots(self, rx, ts, true); // A slot will be ejected (we don't know which one).
        slot = NULL;
        for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
            if (self->slots[i].state == rx_slot_idle) {
                slot = &self->slots[i];
                break;
            }
        }
    }
    UDPARD_ASSERT((slot != NULL) && (slot->state == rx_slot_idle));
    return slot;
}

static void rx_session_update(rx_session_t* const        self,
                              udpard_rx_t* const         rx,
                              const udpard_us_t          ts,
                              const udpard_udpip_ep_t    src_ep,
                              rx_frame_t* const          frame,
                              const udpard_mem_deleter_t payload_deleter,
                              const uint_fast8_t         ifindex)
{
    UDPARD_ASSERT(self->remote.uid == frame->meta.sender_uid);
    UDPARD_ASSERT(frame->meta.topic_hash == self->port->topic_hash); // must be checked by the caller beforehand

    // Animate the session to prevent it from being retired.
    enlist_head(&rx->list_session_by_animation, &self->list_by_animation);
    self->last_animated_ts = ts;

    // Update the return path discovery state.
    // We identify nodes by their UID, allowing them to migrate across interfaces and IP addresses.
    UDPARD_ASSERT(ifindex < UDPARD_IFACE_COUNT_MAX);
    self->remote.endpoints[ifindex] = src_ep;

    // Do-once initialization to ensure we don't lose any transfers by choosing the initial transfer-ID poorly.
    // Any transfers with prior transfer-ID values arriving later will be rejected, which is acceptable.
    if (!self->initialized) {
        self->initialized     = true;
        self->history_current = 0;
        for (size_t i = 0; i < RX_TRANSFER_HISTORY_COUNT; i++) {
            self->history[i] = frame->meta.transfer_id - 1U;
        }
    }
    self->port->vtable_private->update_session(self, rx, ts, frame, payload_deleter);
}

/// The ORDERED mode implementation. May delay incoming transfers to maintain strict transfer-ID ordering.
static void rx_session_update_ordered(rx_session_t* const        self,
                                      udpard_rx_t* const         rx,
                                      const udpard_us_t          ts,
                                      rx_frame_t* const          frame,
                                      const udpard_mem_deleter_t payload_deleter)
{
    // The queries here may be a bit time-consuming. If this becomes a problem, there are many ways to optimize this.
    const bool is_ejected         = rx_session_is_transfer_ejected(self, frame->meta.transfer_id);
    const bool is_late_or_ejected = rx_session_is_transfer_late_or_ejected(self, frame->meta.transfer_id);
    const bool is_interned        = rx_session_is_transfer_interned(self, frame->meta.transfer_id);
    const bool is_new             = !is_late_or_ejected && !is_interned;
    if (is_new) {
        rx_slot_t* const slot = rx_session_get_slot(self, rx, ts, frame->meta.transfer_id);
        UDPARD_ASSERT((slot != NULL) && (slot->state != rx_slot_done));
        UDPARD_ASSERT((slot->state == rx_slot_idle) ||
                      ((slot->state == rx_slot_busy) && (slot->transfer_id == frame->meta.transfer_id)));
        rx_slot_update(slot,
                       ts,
                       self->port->memory.fragment,
                       payload_deleter,
                       frame,
                       self->port->extent,
                       &rx->errors_oom,
                       &rx->errors_transfer_malformed);
        if (slot->state == rx_slot_done) {
            UDPARD_ASSERT(rx_session_is_transfer_interned(self, slot->transfer_id));
            if (frame->meta.flag_ack) {
                // Payload view: ((udpard_fragment_t*)cavl2_min(slot->fragments))->view
                tx_send_ack(rx, ts, slot->priority, self->port->topic_hash, slot->transfer_id, self->remote);
            }
            rx_session_ordered_scan_slots(self, rx, ts, false);
        }
    } else { // retransmit ACK if needed
        // Note: transfers that are no longer retained in the history will not solicit an ACK response,
        // meaning that the sender will not get a confirmation if the retransmitted transfer is too old.
        // We assume that RX_TRANSFER_HISTORY_COUNT is enough to cover all sensible use cases.
        if ((is_interned || is_ejected) && frame->meta.flag_ack && (frame->base.offset == 0U)) {
            // Payload view: frame->base.payload
            tx_send_ack(rx, ts, frame->meta.priority, self->port->topic_hash, frame->meta.transfer_id, self->remote);
        }
        mem_free_payload(payload_deleter, frame->base.origin);
    }
}

/// The UNORDERED mode implementation. Ejects every transfer immediately upon completion without delay.
static void rx_session_update_unordered(rx_session_t* const        self,
                                        udpard_rx_t* const         rx,
                                        const udpard_us_t          ts,
                                        rx_frame_t* const          frame,
                                        const udpard_mem_deleter_t payload_deleter)
{
    UDPARD_ASSERT(self->port->reordering_window < 0);
    // We do not check interned transfers because in the UNORDERED mode they are never interned, always ejected ASAP.
    // We don't care about the ordering, either; we just accept anything that looks new.
    if (!rx_session_is_transfer_ejected(self, frame->meta.transfer_id)) {
        rx_slot_t* const slot = rx_session_get_slot(self, rx, ts, frame->meta.transfer_id); // new or continuation
        UDPARD_ASSERT((slot != NULL) && (slot->state != rx_slot_done));
        UDPARD_ASSERT((slot->state == rx_slot_idle) ||
                      ((slot->state == rx_slot_busy) && (slot->transfer_id == frame->meta.transfer_id)));
        rx_slot_update(slot,
                       ts,
                       self->port->memory.fragment,
                       payload_deleter,
                       frame,
                       self->port->extent,
                       &rx->errors_oom,
                       &rx->errors_transfer_malformed);
        if (slot->state == rx_slot_done) {
            if (frame->meta.flag_ack) { // Payload view: ((udpard_fragment_t*)cavl2_min(slot->fragments))->view
                tx_send_ack(rx, ts, slot->priority, self->port->topic_hash, slot->transfer_id, self->remote);
            }
            rx_session_eject(self, rx, slot);
        }
    } else {                                                      // retransmit ACK if needed
        if (frame->meta.flag_ack && (frame->base.offset == 0U)) { // Payload view: frame->base.payload
            UDPARD_ASSERT(rx_session_is_transfer_ejected(self, frame->meta.transfer_id));
            tx_send_ack(rx, ts, frame->meta.priority, self->port->topic_hash, frame->meta.transfer_id, self->remote);
        }
        mem_free_payload(payload_deleter, frame->base.origin);
    }
}

/// The stateful strategy maintains a dedicated session per remote node, indexed in a fast AVL tree.
static void rx_port_accept_stateful(udpard_rx_t* const         rx,
                                    udpard_rx_port_t* const    port,
                                    const udpard_us_t          timestamp,
                                    const udpard_udpip_ep_t    source_ep,
                                    rx_frame_t* const          frame,
                                    const udpard_mem_deleter_t payload_deleter,
                                    const uint_fast8_t         redundant_iface_index)
{
    rx_session_factory_args_t fac_args = { .owner                 = port,
                                           .sessions_by_animation = &rx->list_session_by_animation,
                                           .remote_uid            = frame->meta.sender_uid,
                                           .now                   = timestamp };
    rx_session_t* const       ses      = // Will find an existing one or create a new one.
      (rx_session_t*)(void*)cavl2_find_or_insert(&port->index_session_by_remote_uid,
                                                 &frame->meta.sender_uid,
                                                 &cavl_compare_rx_session_by_remote_uid,
                                                 &fac_args,
                                                 &cavl_factory_rx_session_by_remote_uid);
    if (ses != NULL) {
        rx_session_update(ses, rx, timestamp, source_ep, frame, payload_deleter, redundant_iface_index);
    } else {
        mem_free_payload(payload_deleter, frame->base.origin);
        ++rx->errors_oom;
    }
}

/// The stateless strategy accepts only single-frame transfers and does not maintain any session state.
static void rx_port_accept_stateless(udpard_rx_t* const         rx,
                                     udpard_rx_port_t* const    port,
                                     const udpard_us_t          timestamp,
                                     const udpard_udpip_ep_t    source_ep,
                                     rx_frame_t* const          frame,
                                     const udpard_mem_deleter_t payload_deleter,
                                     const uint_fast8_t         redundant_iface_index)
{
    const size_t required_size = smaller(port->extent, frame->meta.transfer_payload_size);
    const bool   full_transfer = (frame->base.offset == 0) && (frame->base.payload.size >= required_size);
    if (full_transfer) {
        // The fragment allocation is only needed to uphold the callback protocol.
        // Maybe we could do something about it in the future to avoid this allocation.
        udpard_fragment_t* const frag = rx_fragment_new(port->memory.fragment, payload_deleter, frame->base);
        if (frag != NULL) {
            udpard_remote_t remote                  = { .uid = frame->meta.sender_uid };
            remote.endpoints[redundant_iface_index] = source_ep;
            // The CRC is validated by the frame parser for the first frame of any transfer. It is certainly correct.
            UDPARD_ASSERT(frame->base.crc == crc_full(frame->base.payload.size, frame->base.payload.data));
            const udpard_rx_transfer_t transfer = {
                .timestamp           = timestamp,
                .priority            = frame->meta.priority,
                .transfer_id         = frame->meta.transfer_id,
                .remote              = remote,
                .payload_size_stored = required_size,
                .payload_size_wire   = frame->meta.transfer_payload_size,
                .payload             = frag,
            };
            port->vtable->on_message(rx, port, transfer);
        } else {
            mem_free_payload(payload_deleter, frame->base.origin);
            ++rx->errors_oom;
        }
    } else {
        mem_free_payload(payload_deleter, frame->base.origin);
        ++rx->errors_transfer_malformed; // The stateless mode expects only single-frame transfers.
    }
}

static const udpard_rx_port_vtable_private_t rx_port_vtb_ordered   = { .accept         = rx_port_accept_stateful,
                                                                       .update_session = rx_session_update_ordered };
static const udpard_rx_port_vtable_private_t rx_port_vtb_unordered = { .accept         = rx_port_accept_stateful,
                                                                       .update_session = rx_session_update_unordered };
static const udpard_rx_port_vtable_private_t rx_port_vtb_stateless = { .accept         = rx_port_accept_stateless,
                                                                       .update_session = NULL };

// ---------------------------------------------  RX PUBLIC API  ---------------------------------------------

static bool rx_validate_mem_resources(const udpard_rx_mem_resources_t memory)
{
    return (memory.session.alloc != NULL) && (memory.session.free != NULL) && //
           (memory.fragment.alloc != NULL) && (memory.fragment.free != NULL);
}

void udpard_rx_new(udpard_rx_t* const self, udpard_tx_t* const tx)
{
    UDPARD_ASSERT(self != NULL);
    mem_zero(sizeof(*self), self);
    self->list_session_by_animation   = (udpard_list_t){ NULL, NULL };
    self->index_session_by_reordering = NULL;
    self->errors_oom                  = 0;
    self->errors_frame_malformed      = 0;
    self->errors_transfer_malformed   = 0;
    self->tx                          = tx;
    self->user                        = NULL;
}

void udpard_rx_poll(udpard_rx_t* const self, const udpard_us_t now)
{
    // Retire timed out sessions. We retire at most one per poll to avoid burstiness because session retirement
    // may potentially free up a lot of memory at once.
    {
        rx_session_t* const ses = LIST_TAIL(self->list_session_by_animation, rx_session_t, list_by_animation);
        if ((ses != NULL) && (now >= (ses->last_animated_ts + SESSION_LIFETIME))) {
            rx_session_free(ses, &self->list_session_by_animation, &self->index_session_by_reordering);
        }
    }
    // Process reordering window timeouts.
    // We may process more than one to minimize transfer delays; this is also expected to be quick.
    while (true) {
        rx_session_t* const ses =
          CAVL2_TO_OWNER(cavl2_min(self->index_session_by_reordering), rx_session_t, index_reordering_window);
        if ((ses == NULL) || (now < ses->reordering_window_deadline)) {
            break;
        }
        rx_session_ordered_scan_slots(ses, self, now, false);
    }
}

bool udpard_rx_port_new(udpard_rx_port_t* const              self,
                        const uint64_t                       topic_hash,
                        const size_t                         extent,
                        const udpard_us_t                    reordering_window,
                        const udpard_rx_mem_resources_t      memory,
                        const udpard_rx_port_vtable_t* const vtable)
{
    const bool win_ok = (reordering_window >= 0) || //
                        (reordering_window == UDPARD_RX_REORDERING_WINDOW_UNORDERED) ||
                        (reordering_window == UDPARD_RX_REORDERING_WINDOW_STATELESS);
    const bool ok = (self != NULL) && rx_validate_mem_resources(memory) && win_ok && (vtable != NULL) &&
                    (vtable->on_message != NULL) && (vtable->on_collision != NULL);
    if (ok) {
        mem_zero(sizeof(*self), self);
        self->topic_hash                  = topic_hash;
        self->extent                      = extent;
        self->reordering_window           = reordering_window;
        self->memory                      = memory;
        self->index_session_by_remote_uid = NULL;
        self->vtable                      = vtable;
        self->user                        = NULL;
        if (reordering_window == UDPARD_RX_REORDERING_WINDOW_STATELESS) {
            self->vtable_private = &rx_port_vtb_stateless;
        } else if (reordering_window == UDPARD_RX_REORDERING_WINDOW_UNORDERED) {
            self->vtable_private = &rx_port_vtb_unordered;
        } else {
            self->vtable_private = &rx_port_vtb_ordered;
        }
    }
    return ok;
}

/// A thin proxy that reads the P2P header and dispatches the message to the appropriate handler.
static void rx_p2p_on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    udpard_rx_port_p2p_t* const self = (udpard_rx_port_p2p_t*)port;

    // Read the header.
    udpard_fragment_t* const frag0 = udpard_fragment_seek(transfer.payload, 0);
    if (frag0->view.size < UDPARD_P2P_HEADER_BYTES) {
        ++rx->errors_transfer_malformed;
        udpard_fragment_free_all(transfer.payload, port->memory.fragment);
        return; // Bad transfer -- fragmented header. We can still handle it but it's a protocol violation.
    }

    // Parse the P2P header.
    const byte_t* ptr  = (const byte_t*)frag0->view.data;
    const byte_t  kind = *ptr++;
    ptr += 7U; // reserved
    uint64_t topic_hash  = 0;
    uint64_t transfer_id = 0;
    ptr                  = deserialize_u64(ptr, &topic_hash);
    ptr                  = deserialize_u64(ptr, &transfer_id);
    UDPARD_ASSERT((ptr == (UDPARD_P2P_HEADER_BYTES + (byte_t*)frag0->view.data)));
    (void)ptr;

    // Remove the header from the view.
    frag0->view.size -= UDPARD_P2P_HEADER_BYTES;
    frag0->view.data = UDPARD_P2P_HEADER_BYTES + (byte_t*)(frag0->view.data);

    // Process the data depending on the kind.
    if (kind == P2P_KIND_ACK) {
        tx_receive_ack(rx, topic_hash, transfer_id);
    } else if (kind == P2P_KIND_RESPONSE) {
        const udpard_rx_transfer_p2p_t tr = { .base = transfer, .topic_hash = topic_hash };
        self->vtable->on_message(rx, self, tr);
    } else {
        (void)0; // Malformed, ignored.
    }
}

static void rx_p2p_on_collision(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_remote_t remote)
{
    (void)rx;
    (void)port;
    (void)remote;
    // A hash collision on a P2P port simply means that someone sent a transfer to the wrong unicast endpoint.
    // This could happen if nodes swapped UDP/IP endpoints live, or if there are multiple nodes sharing the
    // same UDP endpoint (same socket). Simply ignore it as there is nothing to do.
}

bool udpard_rx_port_new_p2p(udpard_rx_port_p2p_t* const              self,
                            const uint64_t                           local_uid,
                            const size_t                             extent,
                            const udpard_rx_mem_resources_t          memory,
                            const udpard_rx_port_p2p_vtable_t* const vtable)
{
    static const udpard_rx_port_vtable_t proxy = { .on_message   = rx_p2p_on_message,
                                                   .on_collision = rx_p2p_on_collision };
    if ((self != NULL) && (vtable != NULL) && (vtable->on_message != NULL)) {
        self->vtable = vtable;
        return udpard_rx_port_new((udpard_rx_port_t*)self, //
                                  local_uid,
                                  extent + UDPARD_P2P_HEADER_BYTES,
                                  UDPARD_RX_REORDERING_WINDOW_UNORDERED,
                                  memory,
                                  &proxy);
    }
    return false;
}

void udpard_rx_port_free(udpard_rx_t* const rx, udpard_rx_port_t* const port)
{
    if ((rx != NULL) && (port != NULL)) {
        while (port->index_session_by_remote_uid != NULL) {
            rx_session_free((rx_session_t*)(void*)port->index_session_by_remote_uid,
                            &rx->list_session_by_animation,
                            &rx->index_session_by_reordering);
        }
    }
}

bool udpard_rx_port_push(udpard_rx_t* const         rx,
                         udpard_rx_port_t* const    port,
                         const udpard_us_t          timestamp,
                         const udpard_udpip_ep_t    source_ep,
                         const udpard_bytes_mut_t   datagram_payload,
                         const udpard_mem_deleter_t payload_deleter,
                         const uint_fast8_t         redundant_iface_index)
{
    const bool ok = (rx != NULL) && (port != NULL) && (timestamp >= 0) && udpard_is_valid_endpoint(source_ep) &&
                    (datagram_payload.data != NULL) && (payload_deleter.free != NULL) &&
                    (redundant_iface_index < UDPARD_IFACE_COUNT_MAX);
    if (ok) {
        rx_frame_t frame       = { 0 };
        uint32_t   frame_index = 0;
        uint32_t   offset_32   = 0;
        const bool frame_valid = header_deserialize(
          datagram_payload, &frame.meta, &frame_index, &offset_32, &frame.base.crc, &frame.base.payload);
        frame.base.offset = (size_t)offset_32;
        (void)frame_index;                    // currently not used by this reassembler implementation.
        frame.base.origin = datagram_payload; // Take ownership of the payload.
        if (frame_valid) {
            if (frame.meta.topic_hash == port->topic_hash) {
                port->vtable_private->accept(
                  rx, port, timestamp, source_ep, &frame, payload_deleter, redundant_iface_index);
            } else { // Collisions are discovered early so that we don't attempt to allocate sessions for them.
                mem_free_payload(payload_deleter, frame.base.origin);
                udpard_remote_t remote                  = { .uid = frame.meta.sender_uid };
                remote.endpoints[redundant_iface_index] = source_ep;
                port->vtable->on_collision(rx, port, remote);
            }
        } else {
            mem_free_payload(payload_deleter, frame.base.origin);
            ++rx->errors_frame_malformed;
        }
    }
    return ok;
}
