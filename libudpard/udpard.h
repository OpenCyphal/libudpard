///                            ____                   ______            __          __
///                           / __ `____  ___  ____  / ____/_  ______  / /_  ____  / /
///                          / / / / __ `/ _ `/ __ `/ /   / / / / __ `/ __ `/ __ `/ /
///                         / /_/ / /_/ /  __/ / / / /___/ /_/ / /_/ / / / / /_/ / /
///                         `____/ .___/`___/_/ /_/`____/`__, / .___/_/ /_/`__,_/_/
///                             /_/                     /____/_/
///
/// LibUDPard is a compact implementation of the Cyphal/UDP protocol for high-integrity real-time embedded systems.
/// It is designed for use in robust deterministic embedded systems equipped with at least 64K ROM and RAM.
/// The codebase is compliant with a large subset of MISRA C and is fully covered by unit and end-to-end tests.
/// The library is designed to be compatible with any conventional target platform, from 8 to 64 bit, little- and
/// big-endian, RTOS-based or baremetal, as long as there is a standards-compliant ISO C99+ compiler available.
///
/// The library is intended to be integrated into the end application by simply copying its source files into the
/// source tree of the project; it does not require any special compilation options and should work out of the box.
/// There are build-time configuration parameters defined near the top of udpard.c, but they are optional to use.
///
/// To use the library, the application needs to provide a UDP/IPv4 stack supporting IGMP and ARP.
/// POSIX-based systems may use the standard Berkeley sockets API, while more constrained embedded systems may choose
/// to rely either on a third-party solution like LwIP or a custom UDP/IP stack.
///
/// The library can be used either with a regular heap (preferably constant-time) or with a collection of fixed-size
/// block pool allocators (may be preferable in safety-certified systems).
/// If block pool allocators are used, the following block sizes should be served:
/// - MTU-sized blocks for the TX and RX pipelines (typically at most 1.5 KB unless jumbo frames are used).
/// - sizeof(tx_transfer_t) blocks for the TX pipeline.
/// - sizeof(tx_frame_t) blocks for the TX pipeline.
/// - sizeof(rx_session_t) blocks for the RX pipeline.
/// - sizeof(udpard_fragment_t) blocks for the RX pipeline.
///
/// Suitable allocators may be found here:
/// - Constant-time ultrafast deterministic heap: https://github.com/pavel-kirienko/o1heap
/// - Single-header fixed-size block pool: https://gist.github.com/pavel-kirienko/daf89e0481e6eac0f1fa8a7614667f59
///
/// --------------------------------------------------------------------------------------------------------------------
///
/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT
/// Author: Pavel Kirienko <pavel@opencyphal.org>

// ReSharper disable CppUnusedIncludeDirective

#ifndef UDPARD_H_INCLUDED
#define UDPARD_H_INCLUDED

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/// Semantic version of this library (not the Cyphal specification).
/// API will be backward compatible within the same major version.
#define UDPARD_VERSION_MAJOR 3
#define UDPARD_VERSION_MINOR 0

/// The version number of the Cyphal specification implemented by this library.
#define UDPARD_CYPHAL_SPECIFICATION_VERSION_MAJOR 1
#define UDPARD_CYPHAL_SPECIFICATION_VERSION_MINOR 1

/// RFC 791 states that hosts must be prepared to accept datagrams of up to 576 octets and it is expected that this
/// library will receive non IP-fragmented datagrams thus the minimum MTU should be larger than 576.
/// This is also the maximum size of a single-frame transfer.
/// That being said, the MTU here is set to a larger value that is derived as:
///     1500B Ethernet MTU (RFC 894) - 60B IPv4 max header - 8B UDP Header - 48B Cyphal header
#define UDPARD_MTU_DEFAULT 1384U

/// MTU less than this should not be used. This value may be increased in a future version of the library.
#define UDPARD_MTU_MIN 460U

/// The library supports at most this many local redundant network interfaces.
#define UDPARD_IFACE_COUNT_MAX 3U

#define UDPARD_IFACE_MASK_ALL ((1U << UDPARD_IFACE_COUNT_MAX) - 1U)

/// All P2P transfers have a fixed prefix, handled by the library transparently for the application,
/// defined as follows in DSDL notation:
///
///     uint8 KIND_RESPONSE = 0  # The topic hash and transfer-ID specify which message this is a response to.
///     uint8 KIND_ACK = 1       # The topic hash and transfer-ID specify which transfer is being acknowledged.
///     uint8 kind
///     void56
///     uint64 topic_hash
///     uint64 transfer_id
///     # Payload follows only for KIND_RESPONSE.
///
/// The extent of P2P ports must be at least this large to accommodate the header.
#define UDPARD_P2P_HEADER_BYTES 24U

/// Timestamps supplied by the application must be non-negative monotonically increasing counts of microseconds.
typedef int64_t udpard_us_t;

/// See udpard_tx_t::ack_baseline_timeout.
#define UDPARD_TX_ACK_BASELINE_TIMEOUT_DEFAULT_us 16000LL

/// The subject-ID only affects the formation of the multicast UDP/IP endpoint address.
/// In IPv4 networks, it is limited to 23 bits only due to the limited MAC multicast address space.
/// In IPv6 networks, 32 bits are supported.
#define UDPARD_IPv4_SUBJECT_ID_MAX 0x7FFFFFUL

#define UDPARD_PRIORITY_MAX   7U
#define UDPARD_PRIORITY_COUNT (UDPARD_PRIORITY_MAX + 1U)

typedef enum udpard_prio_t
{
    udpard_prio_exceptional = 0,
    udpard_prio_immediate   = 1,
    udpard_prio_fast        = 2,
    udpard_prio_high        = 3,
    udpard_prio_nominal     = 4, ///< Nominal priority level should be the default.
    udpard_prio_low         = 5,
    udpard_prio_slow        = 6,
    udpard_prio_optional    = 7,
} udpard_prio_t;

typedef struct udpard_tree_t
{
    struct udpard_tree_t* up;
    struct udpard_tree_t* lr[2];
    int_fast8_t           bf;
} udpard_tree_t;

typedef struct udpard_list_member_t
{
    struct udpard_list_member_t* next;
    struct udpard_list_member_t* prev;
} udpard_list_member_t;
typedef struct udpard_list_t
{
    udpard_list_member_t* head; ///< NULL if list empty
    udpard_list_member_t* tail; ///< NULL if list empty
} udpard_list_t;

typedef struct udpard_bytes_mut_t
{
    size_t size;
    void*  data;
} udpard_bytes_mut_t;

typedef struct udpard_bytes_t
{
    size_t      size;
    const void* data;
} udpard_bytes_t;

/// Zeros if invalid/unset/unavailable.
typedef struct udpard_udpip_ep_t
{
    uint32_t ip;
    uint16_t port;
} udpard_udpip_ep_t;

/// The remote information can be used for sending P2P responses back to the sender, if needed.
/// The RX pipeline will attempt to discover the sender's UDP/IP endpoint per redundant interface
/// based on the source address of the received UDP datagrams. If the sender's endpoint could not be discovered
/// for a certain interface (e.g., if the sender is not connected to that interface), the corresponding entry in
/// the endpoints array will be zeroed.
/// Cyphal/UDP thus allows nodes to change their network interface addresses dynamically.
/// The library does not make any assumptions about the specific values and their uniqueness;
/// as such, multiple remote nodes can even share the same endpoint.
typedef struct udpard_remote_t
{
    uint64_t          uid;
    udpard_udpip_ep_t endpoints[UDPARD_IFACE_COUNT_MAX]; ///< Zeros in unavailable ifaces.
} udpard_remote_t;

/// Returns true if the given UDP/IP endpoint appears to be valid. Zero port or IP are considered invalid.
bool udpard_is_valid_endpoint(const udpard_udpip_ep_t ep);

/// Returns the destination multicast UDP/IP endpoint for the given subject ID.
/// The application should use this function when setting up subscription sockets or sending transfers.
/// If the subject-ID exceeds the allowed range, the excessive bits are masked out.
/// For P2P ports use the unicast node address instead.
udpard_udpip_ep_t udpard_make_subject_endpoint(const uint32_t subject_id);

/// The semantics are similar to malloc/free.
/// Consider using O1Heap: https://github.com/pavel-kirienko/o1heap. Alternatively, some applications may prefer to
/// use a set of fixed-size block pool allocators (see the high-level overview for details); for example:
/// https://github.com/OpenCyphal-Garage/demos/blob/87741d8242bcb27b39e22115559a4b91e92ffe06/libudpard_demo/src/memory_block.h
/// The API documentation is written on the assumption that the memory management functions are O(1).
/// The value of the user reference is taken from the corresponding field of the memory resource structure.
typedef void* (*udpard_mem_alloc_t)(void* const user, const size_t size);
typedef void (*udpard_mem_free_t)(void* const user, const size_t size, void* const pointer);

/// A kind of memory resource that can only be used to free memory previously allocated by the user.
typedef struct udpard_mem_deleter_t
{
    void*             user;
    udpard_mem_free_t free;
} udpard_mem_deleter_t;

/// A memory resource encapsulates the dynamic memory allocation and deallocation facilities.
/// Note that the library allocates a large amount of small fixed-size objects for bookkeeping purposes;
/// allocators for them can be implemented using fixed-size block pools to eliminate extrinsic memory fragmentation.
typedef struct udpard_mem_resource_t
{
    void*              user;
    udpard_mem_free_t  free;
    udpard_mem_alloc_t alloc;
} udpard_mem_resource_t;

/// This type represents payload as a binary tree of its fragments ordered by offset to eliminate data copying.
/// The fragments are guaranteed to be non-redundant and non-overlapping; therefore, they are also ordered by their
/// end offsets. See the helper functions below for managing the fragment tree.
typedef struct udpard_fragment_t
{
    /// The index_offset BST orders fragments by their offset (and also end=offset+size) within the transfer payload.
    /// It must be the first member.
    udpard_tree_t index_offset;

    /// Offset of this fragment's payload within the full payload buffer. The ordering key for the index_offset tree.
    size_t offset;

    /// Contains the actual data to be used by the application.
    /// The memory pointed to by this fragment shall not be freed nor mutated by the application.
    udpard_bytes_t view;

    /// Points to the base buffer that contains this fragment.
    /// The application can use this pointer to free the outer buffer after the payload has been consumed.
    /// This memory must not be accessed by the application for any purpose other than freeing it.
    udpard_bytes_mut_t origin;

    /// When the fragment is no longer needed, this deleter shall be used to free the origin buffer.
    /// We provide a dedicated deleter per fragment to allow NIC drivers to manage the memory directly,
    /// which allows DMA access to the fragment data without copying.
    /// See https://github.com/OpenCyphal-Garage/libcyphal/issues/352#issuecomment-2163056622
    udpard_mem_deleter_t payload_deleter;
} udpard_fragment_t;

/// Frees the memory allocated for the payload and its fragment headers using the correct memory resources: the memory
/// resource for the fragments is given explicitly, and the payload is freed using the payload_deleter per fragment.
/// All fragments in the tree will be freed and invalidated.
/// The passed fragment can be any fragment inside the tree (not necessarily the root).
/// If the fragment argument is NULL, the function has no effect. The complexity is linear in the number of fragments.
void udpard_fragment_free_all(udpard_fragment_t* const frag, const udpard_mem_resource_t fragment_mem_resource);

/// Given any fragment in a transfer, returns the fragment that contains the given payload offset.
/// Returns NULL if the offset points beyond the stored payload, or if frag is NULL.
/// This is also the idiomatic way to find the head of the fragment list when invoked with offset zero.
/// This function accepts any node in the fragment tree, not necessarily the head or the root, and
/// has a logarithmic complexity in the number of fragments, which makes it very efficient.
udpard_fragment_t* udpard_fragment_seek(const udpard_fragment_t* frag, const size_t offset);

/// Given any fragment in a transfer, returns the next fragment in strictly ascending order of offsets.
/// The offset of the next fragment always equals the sum of the offset and size of the current fragment.
/// Returns NULL if there is no next fragment or if the given fragment is NULL.
/// The complexity is amortized-constant.
udpard_fragment_t* udpard_fragment_next(const udpard_fragment_t* frag);

/// Copies `size` bytes of payload stored in a fragment tree starting from `offset` into `destination`.
/// The cursor pointer is an iterator updated to the last fragment touched, enabling very efficient sequential
/// access without repeated searches; it is never set to NULL.
/// Returns the number of bytes copied into the contiguous destination buffer, which equals `size` unless
/// `offset+size` exceeds the amount of data stored in the fragments.
/// The function has no effect and returns zero if the destination buffer or iterator pointer are NULL.
size_t udpard_fragment_gather(const udpard_fragment_t** cursor,
                              const size_t              offset,
                              const size_t              size,
                              void* const               destination);

// =====================================================================================================================
// =================================================    TX PIPELINE    =================================================
// =====================================================================================================================

typedef struct udpard_tx_t udpard_tx_t;

/// A TX queue uses these memory resources for allocating the enqueued items (UDP datagrams).
/// There are exactly two allocations per enqueued item:
/// - the first for bookkeeping purposes (udpard_tx_item_t)
/// - second for payload storage (the frame data)
/// In a simple application, there would be just one memory resource shared by all parts of the library.
/// If the application knows its MTU, it can use block allocation to avoid extrinsic fragmentation.
typedef struct udpard_tx_mem_resources_t
{
    /// The queue bookkeeping structures are allocated per outgoing transfer.
    /// Each instance is sizeof(tx_transfer_t), so a trivial zero-fragmentation block allocator is enough.
    udpard_mem_resource_t transfer;

    /// The UDP datagram payload buffers are allocated per frame; each buffer is of size at most
    /// HEADER_SIZE + MTU + small overhead, so a trivial block pool is enough if MTU is known in advance.
    udpard_mem_resource_t payload[UDPARD_IFACE_COUNT_MAX];
} udpard_tx_mem_resources_t;

/// Outcome notification for a reliable transfer previously scheduled for transmission.
typedef struct udpard_tx_feedback_t
{
    uint64_t topic_hash;
    uint64_t transfer_id;
    void*    user_transfer_reference; ///< This is the same pointer that was passed to udpard_tx_push().

    bool success; ///< False if no ack was received from the remote end before deadline expiration or forced eviction.
} udpard_tx_feedback_t;

typedef struct udpard_tx_ejection_t
{
    udpard_us_t now;

    /// Specifies when the frame should be considered expired and dropped if not yet transmitted by then;
    /// it is optional to use depending on the implementation of the NIC driver (most traditional drivers ignore it).
    udpard_us_t deadline;

    uint_fast8_t iface_index; ///< The interface index on which the datagram is to be transmitted.

    uint_fast8_t      dscp;        ///< Set the DSCP field of the outgoing packet to this.
    udpard_udpip_ep_t destination; ///< Unicast or multicast UDP/IP endpoint.

    /// If the datagram pointer is retained by the application, udpard_tx_refcount_inc() must be invoked on it.
    /// When no longer needed (e.g, upon transmission), udpard_tx_refcount_dec() must be invoked.
    udpard_bytes_t datagram;

    /// This is the same pointer that was passed to udpard_tx_push().
    void* user_transfer_reference;
} udpard_tx_ejection_t;

typedef struct udpard_tx_vtable_t
{
    /// Invoked from udpard_tx_poll() to push outgoing UDP datagrams into the socket/NIC driver.
    bool (*eject)(udpard_tx_t*, udpard_tx_ejection_t);
} udpard_tx_vtable_t;

struct udpard_tx_t
{
    const udpard_tx_vtable_t* vtable;

    /// The globally unique identifier of the local node. Must not change after initialization.
    uint64_t local_uid;

    /// A random-initialized transfer-ID counter for all outgoing P2P transfers.
    uint64_t p2p_transfer_id;

    /// The maximum number of Cyphal transfer payload bytes per UDP datagram.
    /// The Cyphal/UDP header is added to this value to obtain the total UDP datagram payload size. See UDPARD_MTU_*.
    /// The value can be changed arbitrarily between enqueue operations as long as it is at least UDPARD_MTU_MIN.
    size_t mtu[UDPARD_IFACE_COUNT_MAX];

    /// This duration is used to derive the acknowledgment timeout for reliable transfers in tx_ack_timeout().
    /// It must be a positive number of microseconds. A sensible default is provided at initialization.
    udpard_us_t ack_baseline_timeout;

    /// Optional user-managed mapping from the Cyphal priority level in [0,7] (highest priority at index 0)
    /// to the IP DSCP field value for use by the application when transmitting. By default, all entries are zero.
    uint_least8_t dscp_value_per_priority[UDPARD_PRIORITY_COUNT];

    /// The maximum number of UDP datagrams irrespective of the transfer count, for all ifaces pooled.
    /// The purpose of this limitation is to ensure that a blocked interface queue does not exhaust the memory.
    /// When the limit is reached, the library will apply simple heuristics to choose which transfers to sacrifice.
    size_t enqueued_frames_limit;

    /// The number of frames that are currently registered in the queue, initially zero.
    /// This includes frames that are handed over to the NIC driver for transmission that are not yet released
    /// via udpard_tx_refcount_dec().
    /// READ-ONLY!
    size_t enqueued_frames_count;

    udpard_tx_mem_resources_t memory;

    /// Error counters incremented automatically when the corresponding error condition occurs.
    /// These counters are never decremented by the library but they can be reset by the application if needed.
    uint64_t errors_oom;        ///< A transfer could not be enqueued due to OOM.
    uint64_t errors_capacity;   ///< A transfer could not be enqueued due to queue capacity limit.
    uint64_t errors_expiration; ///< A frame had to be dropped due to premature deadline expiration.

    /// Internal use only, do not modify! See tx_transfer_t for details.
    udpard_list_t  queue[UDPARD_IFACE_COUNT_MAX][UDPARD_PRIORITY_COUNT]; ///< Next to transmit at the tail.
    udpard_list_t  agewise;                                              ///< Oldest at the tail.
    udpard_tree_t* index_staged;
    udpard_tree_t* index_deadline;
    udpard_tree_t* index_transfer;
    udpard_tree_t* index_transfer_remote;

    /// Opaque pointer for the application use only. Not accessed by the library.
    void* user;
};

/// The parameters are initialized deterministically (MTU defaults to UDPARD_MTU_DEFAULT and counters are reset)
/// and can be changed later by modifying the struct fields directly. No memory allocation is going to take place
/// until the first transfer is successfully pushed via udpard_tx_push().
/// True on success, false if any of the arguments are invalid.
bool udpard_tx_new(udpard_tx_t* const              self,
                   const uint64_t                  local_uid,
                   const uint64_t                  p2p_transfer_id_initial,
                   const size_t                    enqueued_frames_limit,
                   const udpard_tx_mem_resources_t memory,
                   const udpard_tx_vtable_t* const vtable);

/// This function serializes a transfer into a sequence of UDP datagrams and inserts them into the prioritized
/// transmission queue at the appropriate position. The transfer payload will be copied into the transmission queue
/// so that the lifetime of the datagrams is not related to the lifetime of the input payload buffer.
///
/// The topic hash is not defined for P2P transfers since there are no topics involved; in P2P, this parameter
/// is used to pass the destination node's UID instead. Setting it incorrectly will cause the destination node
/// to reject the transfer as misaddressed.
///
/// The transfer_id parameter is used to populate the transfer_id field of the generated Cyphal/UDP frames.
/// The caller shall increment the transfer-ID counter after each successful invocation of this function
/// per redundant interface; the same transfer published over redundant interfaces shall have the same transfer-ID.
/// There shall be a separate transfer-ID counter per topic. The initial value shall be chosen randomly
/// such that it is likely to be distinct per application startup (embedded systems can use noinit memory sections,
/// hash uninitialized SRAM, use timers or ADC noise, etc).
///
/// The user_transfer_reference is an opaque pointer that will be stored for each enqueued item of this transfer.
/// The library itself does not use or check this value in any way, so it can be NULL if not needed.
///
/// The function returns the number of UDP datagrams enqueued, which is always a positive number, in case of success.
/// In case of failure, the function returns zero. Runtime failures increment the corresponding error counters,
/// while invocations with invalid arguments just return zero without modifying the queue state. In all cases,
/// either all frames of the transfer are enqueued successfully or none are.
///
/// An attempt to push a transfer with a (topic hash, transfer-ID) pair that is already enqueued will fail.
///
/// The callback is invoked from udpard_tx_poll() to report the result of reliable transfer transmission attempts.
/// This is ALWAYS invoked EXACTLY ONCE per reliable transfer pushed via udpard_tx_push() successfully.
/// Set the callback to NULL for best-effort (non-acknowledged) transfers.
///
/// Reliable transfers will keep retransmitting until either an acknowledgment is received from the remote,
/// or the deadline expires. The number of retransmissions cannot be limited directly. Each subsequent
/// retransmission timeout is doubled compared to the previous one (exponential backoff).
///
/// The memory allocation requirement is two allocations per datagram:
/// a single-frame transfer takes two allocations; a multi-frame transfer of N frames takes N*2 allocations.
/// In each pair of allocations:
/// - the first allocation is for `udpard_tx_item_t`; the size is `sizeof(udpard_tx_item_t)`;
///   the TX queue `memory.fragment` memory resource is used for this allocation (and later for deallocation);
/// - the second allocation is for the payload (the datagram data) - the size is normally MTU but could be less for
///   the last frame of the transfer; the TX queue `memory.payload` resource is used for this allocation.
///
/// The time complexity is O(p + log e), where p is the transfer payload size, and e is the number of
/// transfers (not frames) already enqueued in the transmission queue.
uint32_t udpard_tx_push(udpard_tx_t* const      self,
                        const udpard_us_t       now,
                        const udpard_us_t       deadline,
                        const udpard_prio_t     priority,
                        const uint64_t          topic_hash, // For P2P transfers, this is the destination's UID.
                        const udpard_udpip_ep_t remote_ep[UDPARD_IFACE_COUNT_MAX], // May be invalid for some ifaces.
                        const uint64_t          transfer_id,
                        const udpard_bytes_t    payload,
                        void (*const feedback)(udpard_tx_t*, udpard_tx_feedback_t), // NULL if best-effort.
                        void* const user_transfer_reference);

/// This should be invoked whenever the socket/NIC of this queue becomes ready to accept new datagrams for transmission.
/// It is fine to also invoke it periodically unconditionally to drive the transmission process.
/// Internally, the function will query the scheduler for the next frame to be transmitted and will attempt
/// to submit it via the eject() callback provided in the vtable.
/// The iface mask indicates which interfaces are currently available for transmission;
/// eject() will only be invoked on these interfaces.
/// The function may deallocate memory. The time complexity is logarithmic in the number of enqueued transfers.
void udpard_tx_poll(udpard_tx_t* const self, const udpard_us_t now, const uint_fast8_t iface_mask);

/// When a datagram is ejected and the application opts to keep it, these functions must be used to manage the
/// datagram buffer lifetime. The datagram will be freed once the reference count reaches zero.
void udpard_tx_refcount_inc(const udpard_bytes_t tx_payload_view);
void udpard_tx_refcount_dec(const udpard_bytes_t tx_payload_view);

/// Drops all enqueued items; afterward, the instance is safe to discard. Callbacks will not be invoked.
void udpard_tx_free(udpard_tx_t* const self);

// =====================================================================================================================
// =================================================    RX PIPELINE    =================================================
// =====================================================================================================================

/// The reception (RX) pipeline is used to subscribe to subjects and to receive P2P transfers.
/// The reception pipeline is highly robust and is able to accept datagrams with arbitrary MTU distinct per interface,
/// delivered out-of-order (OOO) with duplication and arbitrary interleaving between transfers.
/// Robust OOO reassembly is particularly interesting when simple repetition coding FEC is used.
/// All redundant interfaces are pooled together into a single fragment stream per RX port,
/// thus providing seamless failover and great resilience against packet loss on any of the interfaces.
/// The RX pipeline operates at the speed/latency of the best-performing interface at any given time.
///
/// The application should instantiate one RX port instance per subject it needs to receive messages from,
/// irrespective of the number of redundant interfaces. There needs to be one socket (or a similar abstraction
/// provided by the underlying UDP/IP stack) per RX port instance per redundant interface,
/// each socket bound to the same UDP/IP endpoint (IP address and UDP port) obtained using udpard_make_subject_endpoint.
/// The application needs to listen to all these sockets simultaneously and pass the received UDP datagrams to the
/// corresponding RX port instance as they arrive.
///
/// P2P transfers are handled in a similar way, except that the topic hash is replaced with the destination node's UID,
/// and the UDP/IP endpoints are unicast addresses instead of multicast addresses.
///
/// Graphically, the subscription pipeline is arranged per port as shown below.
/// Remember that the application with N RX ports would have N such pipelines, one per port.
///
///     REDUNDANT INTERFACE A ---> UDP SOCKET ---+
///                                              |
///     REDUNDANT INTERFACE B ---> UDP SOCKET ---+---> udpard_rx_port_t ---> TRANSFERS
///                                              |
///                                       ... ---+
///
/// The transfer reassembly state machine can operate in several modes described below. First, a brief summary:
///
/// Mode       Guarantees                       Limitations                        Reordering window setting
/// -----------------------------------------−--------------------------------------------------------------------------
/// ORDERED    Strictly increasing transfer-ID  May delay transfers, CPU heavier   Non-negative number of microseconds
/// UNORDERED  Unique transfer-ID               Ordering not guaranteed            UDPARD_RX_REORDERING_WINDOW_UNORDERED
/// STATELESS  Constant time, constant memory   1-frame only, dups, no responses   UDPARD_RX_REORDERING_WINDOW_STATELESS
///
/// If not sure, choose UNORDERED. The ORDERED mode is a good fit for ordering-sensitive use cases like state estimators
/// and control loops, but it is not suitable for P2P. The STATELESS mode is chiefly intended for the heartbeat topic.
///
///     ORDERED
///
/// Each transfer is received at most once. The sequence of transfers delivered (ejected)
/// to the application is STRICTLY INCREASING (with possible gaps in case of loss).
///
/// The reassembler may hold completed transfers for a brief time if they arrive out-of-order,
/// hoping for the earlier missing transfers to show up, such that they are not permanently lost.
/// For example, a sequence 1 2 4 3 5 will be delivered as 1 2 3 4 5 if 3 arrives shortly after 4;
/// however, if 3 does not arrive within the configured reordering window,
/// the application will receive 1 2 4 5, and transfer 3 will be permanently lost even if it arrives later
/// because accepting it without violating the strictly increasing transfer-ID constraint is not possible.
///
/// This mode requires much more bookkeeping which results in a greater processing load per received fragment/transfer.
///
/// The ORDERED mode is used if the reordering window is non-negative. Zero is not really a special case, it
/// simply means that out-of-order transfers are not waited for at all (declared permanently lost immediately).
/// This should be the default option for most subscriptions; in particular, it is intended for state estimators
/// and control systems where ordering is critical.
///
///     UNORDERED
///
/// Each transfer is ejected immediately upon successful reassembly. Ordering is not enforced,
/// but duplicates are still removed. For example, a sequence 1 2 4 3 5 will be delivered as-is without delay.
///
/// This mode does not reject nor delay transfers arriving late, making it the desired choice for applications
/// where all transfers need to be received no matter the order. This is in particular useful for request-response
/// topics, where late arrivals occur not only due to network conditions but also due to the inherent
/// asynchrony between requests and responses. For example, node A could publish messages X and Y on subject S,
/// while node B could respond to X only after receiving Y, thus causing the response to X to arrive late with
/// respect to Y. This would cause the ORDERED mode to delay or drop the response to X, which is undesirable;
/// therefore, the UNORDERED mode is preferred for request-response topics.
///
/// The UNORDERED mode is used if the reordering window duration is set to UDPARD_RX_REORDERING_WINDOW_UNORDERED.
///
///     STATELESS
///
/// Only single-frame transfers are accepted (where the entire payload fits into a single datagram,
/// or the extent does not exceed the MTU). No attempt to enforce ordering or remove duplicates is made.
/// The return path is only discovered for the one interface that delivered the transfer.
/// Transfers arriving from N interfaces are duplicated N times.
///
/// The stateless mode allocates only a fragment header per accepted frame and does not contain any
/// variable-complexity processing logic, enabling great scalability for topics with a very large number of
/// publishers where unordered and duplicated messages are acceptable, such as the heartbeat topic.
///
/// The STATELESS mode is used if the reordering window duration is set to UDPARD_RX_REORDERING_WINDOW_STATELESS.

#define UDPARD_RX_REORDERING_WINDOW_UNORDERED ((udpard_us_t)(-1))
#define UDPARD_RX_REORDERING_WINDOW_STATELESS ((udpard_us_t)(-2))

typedef struct udpard_rx_t
{
    udpard_list_t  list_session_by_animation;   ///< Oldest at the tail.
    udpard_tree_t* index_session_by_reordering; ///< Earliest reordering window closure on the left.

    uint64_t errors_oom;                ///< A frame could not be processed (transfer possibly dropped) due to OOM.
    uint64_t errors_frame_malformed;    ///< A received frame was malformed and thus dropped.
    uint64_t errors_transfer_malformed; ///< A transfer could not be reassembled correctly.

    /// Whenever an ack fails to transmit, the counter is incremented.
    /// The specific error can be determined by checking the specific counters in the corresponding tx instance.
    uint64_t errors_ack_tx;

    /// The transmission pipeline is needed to manage ack transmission and removal of acknowledged transfers.
    /// If the application wants to only listen, the pointer may be NULL (no acks will be sent).
    udpard_tx_t* tx;

    void* user; ///< Opaque pointer for the application use only. Not accessed by the library.
} udpard_rx_t;

/// These are used to serve the memory needs of the library to keep state while reassembling incoming transfers.
/// Several memory resources are provided to enable fine control over the allocated memory if necessary; however,
/// simple applications may choose to use the same memory resource implemented via malloc()/free() for all of them.
typedef struct udpard_rx_mem_resources_t
{
    /// Provides memory for rx_session_t described below.
    /// Each instance is fixed-size, so a trivial zero-fragmentation block allocator is sufficient.
    udpard_mem_resource_t session;

    /// The udpard_fragment_t handles are allocated per payload fragment; each contains a pointer to its fragment.
    /// Each instance is of a very small fixed size, so a trivial zero-fragmentation block allocator is sufficient.
    udpard_mem_resource_t fragment;
} udpard_rx_mem_resources_t;

typedef struct udpard_rx_port_t         udpard_rx_port_t;
typedef struct udpard_rx_port_p2p_t     udpard_rx_port_p2p_t;
typedef struct udpard_rx_transfer_t     udpard_rx_transfer_t;
typedef struct udpard_rx_transfer_p2p_t udpard_rx_transfer_p2p_t;

/// Provided by the application per port instance to specify the callbacks to be invoked on certain events.
/// This design allows distinct callbacks per port, which is especially useful for the P2P port.
typedef struct udpard_rx_port_vtable_t
{
    /// A new message is received on a port. The handler takes ownership of the payload; it must free it after use.
    void (*on_message)(udpard_rx_t*, udpard_rx_port_t*, udpard_rx_transfer_t);
    /// A topic hash collision is detected on a port.
    void (*on_collision)(udpard_rx_t*, udpard_rx_port_t*, udpard_remote_t);
} udpard_rx_port_vtable_t;

/// This type represents an open input port, such as a subscription to a topic.
struct udpard_rx_port_t
{
    /// Mismatch will be filtered out and the collision notification callback invoked.
    /// For P2P ports, this is the destination node's UID (i.e., the local node's UID).
    uint64_t topic_hash;

    /// Transfer payloads exceeding this extent may be truncated.
    /// The total size of the received payload may still exceed this extent setting by some small margin.
    /// For P2P ports, UDPARD_P2P_HEADER_BYTES must be included in this value.
    size_t extent;

    /// See UDPARD_RX_REORDERING_WINDOW_... above.
    /// Behavior undefined if the reassembly mode is switched on a live port with ongoing transfers.
    udpard_us_t reordering_window;

    udpard_rx_mem_resources_t memory;

    /// Libudpard creates a new session instance per remote UID that emits transfers matching this port.
    /// For example, if the local node is subscribed to a certain subject and there are X nodes publishing
    /// transfers on that subject, then there will be X sessions created for that subject.
    ///
    /// Each session instance takes sizeof(rx_session_t) bytes of dynamic memory for itself.
    /// On top of that, each session instance holds memory for the transfer payload fragments and small fixed-size
    /// metadata objects of type udpard_fragment_t, one handle per fragment.
    ///
    /// The transfer payload memory is not allocated by the library but rather moved from the application
    /// when the corresponding UDP datagram is received. If the library chooses to keep the frame payload,
    /// a new fragment handle is allocated and it takes ownership of the entire datagram payload.
    /// If the library does not need the datagram to reassemble the transfer, its payload buffer is freed immediately.
    /// There is a 1-to-1 correspondence between the fragment handles and the payload fragments.
    /// Remote nodes that emit highly fragmented transfers cause a higher memory utilization in the local node
    /// because of the increased number of fragment handles and per-datagram overheads.
    ///
    /// Ultimately, the worst-case memory consumption is dependent on the configured extent and the transmitting
    /// side's MTU, as these parameters affect the number of payload buffers retained in memory.
    ///
    /// The maximum memory consumption is when there is a large number of nodes emitting data such that each node
    /// begins a multi-frame transfer while never completing it. The library mitigates this by pruning stale
    /// transfers and removing sessions that have been inactive for a long time.
    ///
    /// If the dynamic memory pool(s) is(are) sized correctly, and all transmitting nodes are known to avoid excessive
    /// fragmentation of egress transfers (which can be ensured by avoiding small MTU values),
    /// the application is guaranteed to never encounter an out-of-memory (OOM) error at runtime.
    /// High-integrity applications can optionally police ingress traffic for MTU violations and filter it before
    /// passing it to the library; alternatively, applications could limit memory consumption per port,
    /// which is easy to implement since each port gets a dedicated set of memory resources.
    udpard_tree_t* index_session_by_remote_uid;

    const udpard_rx_port_vtable_t*                vtable;
    const struct udpard_rx_port_vtable_private_t* vtable_private;

    /// Opaque pointer for the application use only. Not accessed by the library.
    void* user;
};

/// Represents a received Cyphal transfer.
/// The payload is owned by this instance, so the application must free it after use using udpard_fragment_free_all()
/// together with the port's fragment memory resource.
struct udpard_rx_transfer_t
{
    udpard_us_t     timestamp;
    udpard_prio_t   priority;
    uint64_t        transfer_id;
    udpard_remote_t remote;

    /// The total size of the payload available to the application, in bytes, is provided for convenience;
    /// it is the sum of the sizes of all its fragments. For example, if the sender emitted a transfer of 2000
    /// bytes split into two frames, 1408 bytes in the first frame and 592 bytes in the second frame,
    /// then the payload_size_stored will be 2000 and the payload buffer will contain two fragments of 1408 and
    /// 592 bytes. If the received payload exceeds the configured extent, (some of) the excess payload may be
    /// discarded and the payload_size_stored will be set accordingly, but it may still exceed the extent somewhat.
    ///
    /// The application is given ownership of the payload buffer, so it is required to free it after use;
    /// this requires freeing both the handles and the payload buffers they point to.
    /// Beware that different memory resources may have been used to allocate the handles and the payload buffers;
    /// the application is responsible for freeing them using the correct memory resource.
    ///
    /// If the payload is empty, the corresponding buffer pointers may be NULL.
    size_t payload_size_stored;

    /// The original size of the transfer payload before extent-based truncation, in bytes.
    /// This value is provided for informational purposes only; the application should not attempt to access
    /// the excess payload as it has already been discarded. Cannot be less than payload_size_stored.
    size_t payload_size_wire;

    /// The payload is stored in a tree of fragments ordered by their offset within the payload.
    /// See udpard_fragment_t and its helper functions for managing the fragment tree.
    udpard_fragment_t* payload;
};

/// A P2P transfer carries a response to a message published earlier.
/// The transfer-ID in the base structure identifies the original message being responded to.
/// The topic_hash field identifies the topic of the original message.
struct udpard_rx_transfer_p2p_t
{
    udpard_rx_transfer_t base;
    uint64_t             topic_hash;
};

/// A specialization of udpard_rx_port_vtable_t for P2P ports.
typedef struct udpard_rx_port_p2p_vtable_t
{
    /// A new message is received on a port. The handler takes ownership of the payload; it must free it after use.
    void (*on_message)(udpard_rx_t*, udpard_rx_port_p2p_t*, udpard_rx_transfer_p2p_t);
} udpard_rx_port_p2p_vtable_t;

/// A specialization of udpard_rx_port_t for the local node's P2P port.
struct udpard_rx_port_p2p_t
{
    udpard_rx_port_t                   base;
    const udpard_rx_port_p2p_vtable_t* vtable;
};

/// The RX instance holds no resources and can be destroyed at any time by simply freeing all its ports first
/// using udpard_rx_port_free(), then discarding the instance itself. The self pointer must not be NULL.
void udpard_rx_new(udpard_rx_t* const self, udpard_tx_t* const tx);

/// Must be invoked at least every few milliseconds (more often is fine) to purge timed-out sessions and eject
/// received transfers when the reordering window expires. If this is invoked simultaneously with rx subscription
/// reception, then this function should ideally be invoked after the reception handling.
/// The time complexity is logarithmic in the number of living sessions.
void udpard_rx_poll(udpard_rx_t* const self, const udpard_us_t now);

/// To subscribe to a subject, the application should do this:
///     1. Create a new udpard_rx_port_t instance using udpard_rx_port_new().
///     2. Per redundant network interface:
///        - Create a new RX socket bound to the IP multicast group address and UDP port number returned by
///          udpard_make_subject_endpoint() for the desired subject-ID.
///          For P2P transfer ports use ordinary sockets.
///     3. Read data from the sockets continuously and forward each datagram to udpard_rx_port_push(),
///        along with the index of the redundant interface the datagram was received on.
///
/// For P2P ports, the procedure is similar except that the appropriate function is udpard_rx_port_new_p2p().
/// There must be exactly one P2P port per node.
///
/// The extent defines the maximum possible size of received objects, considering also possible future data type
/// versions with new fields. It is safe to pick larger values. Note well that the extent is not the same thing as
/// the maximum size of the object, it is usually larger! Transfers that carry payloads that exceed the specified
/// extent will be accepted anyway but the excess payload will be truncated away, as mandated by the Specification.
///
/// The topic hash is needed to detect and ignore transfers that use different topics on the same subject-ID.
/// The collision callback is invoked if a topic hash collision is detected.
///
/// If not sure which reassembly mode to choose, consider UDPARD_RX_REORDERING_WINDOW_UNORDERED as the default choice.
/// For ordering-sensitive use cases, such as state estimators and control loops, use ORDERED with a short window.
///
/// The pointed-to vtable instance must outlive the port instance.
///
/// The return value is true on success, false if any of the arguments are invalid.
/// The time complexity is constant. This function does not invoke the dynamic memory manager.
bool udpard_rx_port_new(udpard_rx_port_t* const              self,
                        const uint64_t                       topic_hash, // For P2P ports, this is the local node's UID.
                        const size_t                         extent,
                        const udpard_us_t                    reordering_window,
                        const udpard_rx_mem_resources_t      memory,
                        const udpard_rx_port_vtable_t* const vtable);

/// Same as udpard_rx_port_new() but explicitly indicates that this is the local node's P2P port.
/// UDPARD_P2P_HEADER_BYTES will be added to the specified extent value.
bool udpard_rx_port_new_p2p(udpard_rx_port_p2p_t* const              self,
                            const uint64_t                           local_uid,
                            const size_t                             extent,
                            const udpard_rx_mem_resources_t          memory,
                            const udpard_rx_port_p2p_vtable_t* const vtable);

/// Returns all memory allocated for the sessions, slots, fragments, etc of the given port.
/// Does not free the port itself and does not alter the RX instance aside from unlinking the port from it.
/// It is safe to invoke this at any time, but the port instance shall not be used again unless re-initialized.
/// The function has no effect if any of the arguments are NULL.
void udpard_rx_port_free(udpard_rx_t* const rx, udpard_rx_port_t* const port);

/// The timestamp value indicates the arrival time of the datagram and shall be non-negative.
/// Often, naive software timestamping is adequate for these purposes, but some applications may require
/// a greater accuracy (e.g., for time synchronization).
///
/// The function takes ownership of the passed datagram payload buffer. The library will either store it as a
/// fragment of the reassembled transfer payload or free it using the corresponding memory resource
/// (see udpard_rx_mem_resources_t) if the datagram is not needed for reassembly. Because of the ownership transfer,
/// the datagram payload buffer has to be mutable (non-const). The ownership transfer does not take place if
/// any of the arguments are invalid; the function returns false in that case and the caller must clean up.
///
/// The function invokes the dynamic memory manager in the following cases only (refer to udpard_rx_port_t):
/// 1. A new session state instance is allocated when a new session is initiated.
/// 2. A new transfer fragment handle is allocated when a new transfer fragment is accepted.
/// 3. Allocated objects may occasionally be deallocated to clean up stale transfers and sessions.
///
/// The time complexity is O(log n + log k) where n is the number of remote nodes publishing on this subject,
/// and k is the number of fragments retained in memory for the corresponding in-progress transfer.
/// No data copying takes place.
///
/// Returns true on successful processing, false if any of the arguments are invalid.
bool udpard_rx_port_push(udpard_rx_t* const         rx,
                         udpard_rx_port_t* const    port,
                         const udpard_us_t          timestamp,
                         const udpard_udpip_ep_t    source_ep,
                         const udpard_bytes_mut_t   datagram_payload,
                         const udpard_mem_deleter_t payload_deleter,
                         const uint_fast8_t         redundant_iface_index);

#ifdef __cplusplus
}
#endif
#endif
