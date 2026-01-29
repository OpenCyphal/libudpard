///                            ____                   ______            __          __
///                           / __ `____  ___  ____  / ____/_  ______  / /_  ____  / /
///                          / / / / __ `/ _ `/ __ `/ /   / / / / __ `/ __ `/ __ `/ /
///                         / /_/ / /_/ /  __/ / / / /___/ /_/ / /_/ / / / / /_/ / /
///                         `____/ .___/`___/_/ /_/`____/`__, / .___/_/ /_/`__,_/_/
///                             /_/                     /____/_/
///
/// LibUDPard is a compact implementation of the Cyphal/UDP transport for high-integrity real-time embedded systems.
/// It is designed for use in robust deterministic embedded systems equipped with at least ~100K ROM and RAM,
/// as well as in general-purpose software.
///
/// The codebase is compliant with a large subset of MISRA C and is fully covered by unit and end-to-end tests.
/// The library is designed to be compatible with any conventional target platform, from 8 to 64 bit, little- and
/// big-endian, RTOS-based or baremetal, as long as there is a standards-compliant ISO C99 or C11 compiler available.
///
/// The library is intended to be integrated into the end application by simply copying udpard.c/.h into the
/// source tree of the project; it does not require any special compilation options and should work out of the box.
/// There are build-time configuration parameters defined near the top of udpard.c, but they are optional to use.
///
/// To use the library, the application needs to provide a minimal UDP/IPv4 stack supporting IGMP v2 and passive ARP.
/// POSIX-based systems may use the standard Berkeley sockets API, while more constrained embedded systems may choose
/// to rely either on a third-party solution like LwIP or a custom minimal UDP/IP stack.
///
/// The library can be used either with a regular heap (preferably constant-time) or with a collection of fixed-size
/// block pool allocators (may be preferable in safety-certified systems).
/// If block pool allocators are used, the following block sizes should be served:
/// - MTU-sized blocks for the TX and RX pipelines (typically at most 1.5 KB unless jumbo frames are used).
///   The TX pipeline adds a small overhead of sizeof(tx_frame_t).
/// - sizeof(tx_transfer_t) blocks for the TX pipeline to store outgoing transfer metadata.
/// - sizeof(rx_session_t) blocks for the RX pipeline to store incoming transfer session metadata.
/// - sizeof(udpard_fragment_t) blocks for the RX pipeline to store received data fragments.
///
/// Suitable memory allocators may be found here:
/// - Constant-time ultrafast deterministic heap: https://github.com/pavel-kirienko/o1heap
/// - Single-header fixed-size block pool: https://gist.github.com/pavel-kirienko/daf89e0481e6eac0f1fa8a7614667f59
///
/// --------------------------------------------------------------------------------------------------------------------
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
#define UDPARD_CYPHAL_VERSION_MAJOR 1
#define UDPARD_CYPHAL_VERSION_MINOR 1

/// RFC 791 states that hosts must be prepared to accept datagrams of up to 576 octets and it is expected that this
/// library will receive non IP-fragmented datagrams thus the minimum MTU should be larger than 576.
/// That being said, the MTU here is set to a larger value that is derived as:
///     1500B Ethernet MTU (RFC 894) - 60B IPv4 max header - 8B UDP Header - 48B Cyphal header
/// This is also the default maximum size of a single-frame transfer.
/// The application can change this value at runtime as needed.
#define UDPARD_MTU_DEFAULT 1384U

/// MTU less than this should not be used. This value may be increased in a future version of the library.
#define UDPARD_MTU_MIN 460U

/// The library supports at most this many local redundant network interfaces.
#define UDPARD_IFACE_COUNT_MAX 3U

#define UDPARD_IFACE_BITMAP_ALL ((1U << UDPARD_IFACE_COUNT_MAX) - 1U)

/// All P2P transfers have a fixed prefix in the payload, handled by the library transparently for the application,
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
/// The extent of P2P ports includes this header; udpard_rx_port_new_p2p adds it automatically.
#define UDPARD_P2P_HEADER_BYTES 24U

/// Timestamps supplied by the application must be non-negative monotonically increasing counts of microseconds.
typedef int64_t udpard_us_t;

/// See udpard_tx_t::ack_baseline_timeout.
/// This default value might be a good starting point for many applications running over a local network.
/// The baseline timeout should be greater than the expected round-trip time (RTT) between the most distant
/// nodes in the network for a message at the highest priority level.
#define UDPARD_TX_ACK_BASELINE_TIMEOUT_DEFAULT_us 16000LL

/// The subject-ID only affects the formation of the multicast UDP/IP endpoint address.
/// In IPv4 networks, it is limited to 23 bits only due to the limited MAC multicast address space.
/// In IPv6 networks, 32 bits are supported.
#define UDPARD_IPv4_SUBJECT_ID_MAX 0x7FFFFFUL

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
#define UDPARD_PRIORITY_COUNT 8U

/// RX port mode for transfer reassembly behavior.
typedef enum udpard_rx_mode_t
{
    udpard_rx_ordered   = 0, ///< Ordered mode with configurable reordering window.
    udpard_rx_unordered = 1, ///< Unordered mode, ejects immediately.
    udpard_rx_stateless = 2, ///< Stateless mode, single-frame only.
} udpard_rx_mode_t;

typedef struct udpard_tree_t
{
    struct udpard_tree_t* up;
    struct udpard_tree_t* lr[2];
    int_fast8_t           bf;
} udpard_tree_t;

typedef struct udpard_listed_t
{
    struct udpard_listed_t* next;
    struct udpard_listed_t* prev;
} udpard_listed_t;

typedef struct udpard_list_t
{
    udpard_listed_t* head; ///< NULL if list empty
    udpard_listed_t* tail; ///< NULL if list empty
} udpard_list_t;

typedef struct udpard_bytes_t
{
    size_t      size;
    const void* data;
} udpard_bytes_t;

typedef struct udpard_bytes_scattered_t
{
    udpard_bytes_t                         bytes;
    const struct udpard_bytes_scattered_t* next; ///< NULL in the last fragment.
} udpard_bytes_scattered_t;

typedef struct udpard_bytes_mut_t
{
    size_t size;
    void*  data;
} udpard_bytes_mut_t;

/// The size can be changed arbitrarily. This value is a compromise between copy size and footprint and utility.
#define UDPARD_USER_CONTEXT_PTR_COUNT 4

/// The library carries the user-provided context from inputs to outputs without interpreting it,
/// allowing the application to associate its own data with various entities inside the library.
typedef union udpard_user_context_t
{
    void*         ptr[UDPARD_USER_CONTEXT_PTR_COUNT];
    unsigned char bytes[sizeof(void*) * UDPARD_USER_CONTEXT_PTR_COUNT];
} udpard_user_context_t;
#ifdef __cplusplus
#define UDPARD_USER_CONTEXT_NULL \
    udpard_user_context_t {}
#else
#define UDPARD_USER_CONTEXT_NULL ((udpard_user_context_t){ .ptr = { NULL } })
#endif

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
/// the endpoints array will be zeroed and udpard_is_valid_endpoint() will return false for that entry.
///
/// Cyphal/UDP thus allows nodes to change their network interface addresses dynamically.
/// The library does not make any assumptions about the specific values and their uniqueness;
/// as such, multiple remote nodes can even share the same endpoint.
typedef struct udpard_remote_t
{
    uint64_t          uid;
    udpard_udpip_ep_t endpoints[UDPARD_IFACE_COUNT_MAX]; ///< Zeros in unavailable ifaces.
} udpard_remote_t;

/// Returns true if the given UDP/IP endpoint appears to be valid. Zero IP/port are considered invalid.
bool udpard_is_valid_endpoint(const udpard_udpip_ep_t ep);

/// Returns the destination multicast UDP/IP endpoint for the given subject-ID.
/// The application should use this function when setting up subscription sockets or sending datagrams in
/// udpard_tx_vtable_t::eject_subject().
/// If the subject-ID exceeds UDPARD_IPv4_SUBJECT_ID_MAX, the excessive bits are masked out.
/// For P2P use the unicast node address directly instead, as provided by the RX pipeline per received transfer.
udpard_udpip_ep_t udpard_make_subject_endpoint(const uint32_t subject_id);

/// The memory resource semantics are similar to malloc/free.
/// Consider using O1Heap: https://github.com/pavel-kirienko/o1heap.
/// The API documentation is written on the assumption that the memory management functions are O(1).
typedef struct udpard_deleter_t udpard_deleter_t;
typedef struct udpard_mem_t     udpard_mem_t;

typedef struct udpard_deleter_vtable_t
{
    void (*free)(void* context, size_t size, void* pointer);
} udpard_deleter_vtable_t;

struct udpard_deleter_t
{
    const udpard_deleter_vtable_t* vtable;
    void*                          context;
};

typedef struct udpard_mem_vtable_t
{
    udpard_deleter_vtable_t base;
    void* (*alloc)(void* context, size_t size);
} udpard_mem_vtable_t;

struct udpard_mem_t
{
    const udpard_mem_vtable_t* vtable;
    void*                      context;
};

/// A helper that upcasts a memory resource into a deleter.
udpard_deleter_t udpard_make_deleter(const udpard_mem_t memory);

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
    udpard_deleter_t payload_deleter;
} udpard_fragment_t;

/// Frees the memory allocated for the payload and its fragment headers using the correct deleters: the fragment
/// deleter is given explicitly (use udpard_make_deleter() to obtain it from a memory resource), and the payload is
/// freed using the payload_deleter per fragment.
/// All fragments in the tree will be freed and invalidated.
/// The passed fragment can be any fragment inside the tree (not necessarily the root).
/// If the fragment argument is NULL, the function has no effect. The complexity is linear in the number of fragments.
void udpard_fragment_free_all(udpard_fragment_t* const frag, const udpard_deleter_t fragment_deleter);

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

/// A convenience function built on top of udpard_fragment_seek() and udpard_fragment_next().
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

/// Graphically, the transmission pipeline is arranged as shown below.
/// There is a single pipeline instance that serves all topics, P2P, and all network interfaces.
///
///                                   +---> REDUNDANT INTERFACE A
///                                   |
///     TRANSFERS ---> udpard_tx_t ---+---> REDUNDANT INTERFACE B
///                                   |
///                                   +---> ...
///
/// The RX pipeline is linked with the TX pipeline for reliable message management: the RX pipeline notifies
/// the TX when acknowledgments are received, and also enqueues outgoing acknowledgments to confirm received messages.
/// Thus the transmission pipeline is inherently remote-controlled by other nodes and one needs to keep in mind
/// that new frames may appear in the TX pipeline even while the application is idle.
///
/// The reliable delivery mechanism informs the application about the number of remote subscribers that confirmed the
/// reception of each reliable message. The library uses heuristics to determine the number of attempts needed to
/// deliver the message, but it is guaranteed to cease attempts by the specified deadline.
/// Rudimentary congestion control is implemented by exponential backoff of retransmission intervals.
/// The reliability is chosen by the publisher on a per-message basis; as such, the same topic may carry both
/// reliable and unreliable messages depending on who is publishing at any given time.
///
/// Reliable messages published over high-fanout topics will generate a large amount of feedback acknowledgments,
/// which must be kept in mind when designing the network.
///
/// Subscribers operating in the ORDERED mode do not acknowledge messages that have been designated as lost
/// (arriving too late, after the reordering window has passed). No negative acknowledgments are sent either
/// because there may be other subscribers on the same topic who might still be able to receive the message.
typedef struct udpard_tx_t udpard_tx_t;

typedef struct udpard_tx_mem_resources_t
{
    /// The queue bookkeeping structures are allocated per outgoing transfer, i.e., one per udpard_tx_push().
    /// Each allocation is sizeof(tx_transfer_t).
    udpard_mem_t transfer;

    /// The UDP datagram payload buffers are allocated per frame, each at most HEADER_SIZE+MTU+sizeof(tx_frame_t).
    /// These may be distinct per interface to allow each interface to draw buffers from a specific memory region
    /// or a specific DMA-compatible memory pool.
    ///
    /// IMPORTANT: distinct memory resources increase tx memory usage and data copying.
    /// If possible, it is recommended to use the same memory resource for all interfaces, because the library will be
    /// able to avoid frame duplication and instead reuse each frame across all interfaces when the MTUs are identical.
    udpard_mem_t payload[UDPARD_IFACE_COUNT_MAX];
} udpard_tx_mem_resources_t;

/// Outcome notification for a reliable transfer previously scheduled for transmission.
/// For P2P transfers, the topic hash and the transfer-ID are taken from the request header this response targets,
/// not from the locally assigned response metadata.
typedef struct udpard_tx_feedback_t
{
    uint64_t topic_hash;
    uint64_t transfer_id;

    udpard_user_context_t user; ///< Same value that was passed to udpard_tx_push().

    /// The number of remote nodes that acknowledged the reception of the transfer.
    /// For P2P transfers, this value is either 0 (failure) or 1 (success).
    uint16_t acknowledgements;
} udpard_tx_feedback_t;

/// Request to transmit a UDP datagram over the specified interface.
/// Which interface indexes are available is determined by the user when pushing the transfer.
/// If Berkeley sockets or similar API is used, the application should use a dedicated socket per redundant interface.
typedef struct udpard_tx_ejection_t
{
    /// The current time carried over from the API function that initiated the ejection.
    udpard_us_t now;

    /// Specifies when the frame should be considered expired and dropped if not yet transmitted by then;
    /// it is optional to use depending on the implementation of the NIC driver (most traditional drivers ignore it).
    /// The library guarantees that now >= deadline at the time of ejection -- expired frames are purged beforehand.
    udpard_us_t deadline;

    uint_fast8_t iface_index; ///< The interface index on which the datagram is to be transmitted.
    uint_fast8_t dscp;        ///< Set the DSCP field of the outgoing UDP packet to this.

    /// If the datagram pointer is retained by the application, udpard_tx_refcount_inc() must be invoked on it
    /// to prevent it from being garbage collected. When no longer needed (e.g, upon transmission),
    /// udpard_tx_refcount_dec() must be invoked to release the reference.
    udpard_bytes_t datagram;

    /// This is the same value that was passed to udpard_tx_push().
    udpard_user_context_t user;
} udpard_tx_ejection_t;

/// Virtual function table for the TX pipeline, to be provided by the application.
typedef struct udpard_tx_vtable_t
{
    /// Invoked from udpard_tx_poll() to push outgoing UDP datagrams into the socket/NIC driver.
    /// It is GUARANTEED that ONLY udpard_tx_poll() can invoke this function; in particular, pushing new transfers
    /// will not trigger ejection callbacks.
    /// The callback must not mutate the TX pipeline (no udpard_tx_push/cancel/free).
    ///
    /// The destination endpoint is provided only for P2P transfers; for multicast transfers, the application
    /// must compute the endpoint using udpard_make_subject_endpoint() based on the subject-ID. This is because
    /// the subject-ID may be changed by the consensus algorithm at any time if a collision/divergence is detected.
    /// The application is expected to rely on the user context to access the topic context for subject-ID derivation.
    bool (*eject_subject)(udpard_tx_t*, udpard_tx_ejection_t*);
    bool (*eject_p2p)(udpard_tx_t*, udpard_tx_ejection_t*, udpard_udpip_ep_t destination);
} udpard_tx_vtable_t;

/// The application must create a single instance of this struct to manage the TX pipeline.
/// A single instance manages all redundant interfaces.
struct udpard_tx_t
{
    const udpard_tx_vtable_t* vtable;

    /// The globally unique identifier of the local node. Must not change after initialization.
    uint64_t local_uid;

    /// A random-initialized transfer-ID counter for all outgoing P2P transfers. Must not be changed by the application.
    uint64_t p2p_transfer_id;

    /// The maximum number of Cyphal transfer payload bytes per UDP datagram. See UDPARD_MTU_*.
    /// The Cyphal/UDP header is added to this value to obtain the total UDP datagram payload size.
    /// The value can be changed arbitrarily between enqueue operations as long as it is at least UDPARD_MTU_MIN.
    ///
    /// IMPORTANT: distinct MTU values increase tx memory usage and data copying.
    /// If possible, it is recommended to use the same MTU for all interfaces, because the library will be
    /// able to avoid frame duplication and instead reuse each frame across all interfaces.
    size_t mtu[UDPARD_IFACE_COUNT_MAX];

    /// This duration is used to derive the acknowledgment timeout for reliable transfers in tx_ack_timeout().
    /// It must be a positive number of microseconds.
    ///
    /// The baseline timeout should be greater than the expected round-trip time (RTT) between the most distant
    /// nodes in the network for a message at the highest priority level.
    ///
    /// A sensible default is provided at initialization, which can be overridden by the application.
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
    uint64_t errors_oom;        ///< A transfer could not be enqueued due to OOM, while there was queue space available.
    uint64_t errors_capacity;   ///< A transfer could not be enqueued due to queue capacity limit.
    uint64_t errors_sacrifice;  ///< A transfer had to be sacrificed to make room for a new transfer.
    uint64_t errors_expiration; ///< A transfer had to be dequeued due to deadline expiration.

    /// Internal use only, do not modify! See tx_transfer_t for details.
    udpard_list_t  queue[UDPARD_IFACE_COUNT_MAX][UDPARD_PRIORITY_COUNT]; ///< Next to transmit at the tail.
    udpard_list_t  agewise;                                              ///< Oldest at the tail.
    udpard_tree_t* index_staged;
    udpard_tree_t* index_deadline;
    udpard_tree_t* index_transfer;
    udpard_tree_t* index_transfer_ack;

    /// Opaque pointer for the application use only. Not accessed by the library.
    void* user;
};

/// The parameters are default-initialized (MTU defaults to UDPARD_MTU_DEFAULT and counters are reset)
/// and can be changed later by modifying the struct fields directly. No memory allocation is going to take place
/// until the first transfer is successfully pushed via udpard_tx_push().
///
/// The local UID should be a globally unique EUI-64 identifier assigned to the local node. It may be a random
/// EUI-64, which is especially useful for short-lived software nodes.
///
/// The p2p_transfer_id_initial value must be chosen randomly such that it is likely to be distinct per application
/// startup. See the transfer-ID counter requirements in udpard_tx_push() for details.
///
/// The enqueued_frames_limit should be large enough to accommodate the expected burstiness of the application traffic.
/// If the limit is reached, the library will apply heuristics to sacrifice some older transfers to make room
/// for the new one. This behavior allows the library to make progress even when some interfaces are stalled.
///
/// True on success, false if any of the arguments are invalid.
bool udpard_tx_new(udpard_tx_t* const              self,
                   const uint64_t                  local_uid,
                   const uint64_t                  p2p_transfer_id_initial,
                   const size_t                    enqueued_frames_limit,
                   const udpard_tx_mem_resources_t memory,
                   const udpard_tx_vtable_t* const vtable);

/// Submit a transfer for transmission. The payload data will be copied into the transmission queue, so it can be
/// invalidated immediately after this function returns. When redundant interfaces are used, the library will attempt to
/// minimize the number of copies by reusing frames across interfaces with identical MTU values and memory resources.
///
/// The caller shall increment the transfer-ID counter after each successful invocation of this function per topic.
/// There shall be a separate transfer-ID counter per topic. The initial value shall be chosen randomly
/// such that it is likely to be distinct per application startup (embedded systems can use noinit memory sections,
/// hash uninitialized SRAM, use timers or ADC noise, etc).
/// Related thread on random transfer-ID init: https://forum.opencyphal.org/t/improve-the-transfer-id-timeout/2375
///
/// The user context value is carried through to the callbacks. It must contain enough context to allow subject-ID
/// derivation inside udpard_tx_vtable_t::eject_subject(). For example, it may contain a pointer to the topic struct.
///
/// Returns true on success. Runtime failures increment the corresponding error counters,
/// while invocations with invalid arguments just return zero without modifying the queue state.
///
/// The enqueued transfer will be emitted over all interfaces specified in the iface_bitmap.
/// The subject-ID is computed inside the udpard_tx_vtable::eject_subject() callback at the time of transmission.
/// The subject-ID cannot be computed beforehand at the time of enqueuing because the topic->subject consensus protocol
/// may find a different subject-ID allocation between the time of enqueuing and the time of (re)transmission.
///
/// An attempt to push a transfer with a (topic hash, transfer-ID) pair that is already enqueued will fail,
/// as that violates the transfer-ID uniqueness requirement stated above.
///
/// The feedback callback is set to NULL for best-effort (non-acknowledged) transfers. Otherwise, the transfer is
/// treated as reliable, requesting a delivery acknowledgement from remote subscribers with repeated retransmissions if
/// necessary; it is guaranteed that delivery attempts will cease no later than by the specified deadline.
/// The feedback callback is ALWAYS invoked EXACTLY ONCE per reliable transfer pushed via udpard_tx_push() successfully,
/// indicating the number of remote nodes that acknowledged the reception of the transfer.
/// The retransmission delay is increased exponentially with each retransmission attempt as a means of congestion
/// control and latency adaptation; please refer to udpard_tx_t::ack_baseline_timeout for details.
///
/// Beware that reliable delivery may cause message reordering. For example, when sending messages A and B,
/// and A is lost on the first attempt, the next attempt may be scheduled after B is published,
/// so that the remote sees B followed by A. Most applications tolerate it without issues; if this is not the case,
/// the subscriber should use the ORDERED subscription mode (refer to the RX pipeline for details),
/// which will reconstruct the original message ordering.
///
/// On success, the function allocates a single transfer state instance and a number of payload fragments.
/// The time complexity is O(p + log e), where p is the transfer payload size, and e is the number of
/// transfers already enqueued in the transmission queue.
bool udpard_tx_push(udpard_tx_t* const             self,
                    const udpard_us_t              now,
                    const udpard_us_t              deadline,
                    const uint16_t                 iface_bitmap,
                    const udpard_prio_t            priority,
                    const uint64_t                 topic_hash,
                    const uint64_t                 transfer_id,
                    const udpard_bytes_scattered_t payload,
                    void (*const feedback)(udpard_tx_t*, udpard_tx_feedback_t), // NULL if best-effort.
                    const udpard_user_context_t user);

/// This is a specialization of the general push function for P2P transfers.
/// It is used to send P2P responses to messages received from topics; the request_* values shall be taken from
/// the message transfer that is being responded to. The topic_hash and the transfer_id fields of the feedback struct
/// will be set to the request_topic_hash and request_transfer_id values, respectively.
/// If out_transfer_id is not NULL, the assigned internal transfer-ID is stored there for use with udpard_tx_cancel_p2p.
/// P2P transfers are a bit more complex because they carry some additional metadata that is automatically
/// composed/parsed by the library transparently for the application.
/// The size of the serialized payload will include UDPARD_P2P_HEADER_BYTES additional bytes for the P2P header.
bool udpard_tx_push_p2p(udpard_tx_t* const             self,
                        const udpard_us_t              now,
                        const udpard_us_t              deadline,
                        const udpard_prio_t            priority,
                        const uint64_t                 request_topic_hash,
                        const uint64_t                 request_transfer_id,
                        const udpard_remote_t          remote, // Endpoints may be invalid for some ifaces.
                        const udpard_bytes_scattered_t payload,
                        void (*const feedback)(udpard_tx_t*, udpard_tx_feedback_t), // NULL if best-effort.
                        const udpard_user_context_t user,
                        uint64_t* const             out_transfer_id);

/// This should be invoked whenever the socket/NIC of this queue becomes ready to accept new datagrams for transmission.
/// It is fine to also invoke it periodically unconditionally to drive the transmission process.
/// Internally, the function will query the scheduler for the next frame to be transmitted and will attempt
/// to submit it via the eject() callback provided in the vtable.
/// The iface bitmap indicates which interfaces are currently ready to accept new datagrams.
/// The function may deallocate memory. The time complexity is logarithmic in the number of enqueued transfers.
void udpard_tx_poll(udpard_tx_t* const self, const udpard_us_t now, const uint16_t iface_bitmap);

/// Cancel a previously enqueued transfer.
/// If provided, the feedback callback will be invoked with success==false.
/// Not safe to call from the eject() callback.
/// Returns true if a transfer was found and cancelled, false if no such transfer was found.
/// The complexity is O(log t + f), where t is the number of enqueued transfers,
/// and f is the number of frames in the transfer.
/// The function will free the memory associated with the transfer.
bool udpard_tx_cancel(udpard_tx_t* const self, const uint64_t topic_hash, const uint64_t transfer_id);
bool udpard_tx_cancel_p2p(udpard_tx_t* const self, const uint64_t destination_uid, const uint64_t transfer_id);

/// Like udpard_tx_cancel(), but cancels all transfers matching the given topic hash.
/// Returns the number of matched transfers.
/// This is important to invoke when destroying a topic to ensure no dangling callbacks remain.
size_t udpard_tx_cancel_all(udpard_tx_t* const self, const uint64_t topic_hash);

/// Returns a bitmap of interfaces that have pending transmissions. This is useful for IO multiplexing loops.
/// Zero indicates that there are no pending transmissions.
/// Which interfaces are usable is defined by the remote endpoints provided when pushing transfers.
uint16_t udpard_tx_pending_ifaces(const udpard_tx_t* const self);

/// When a datagram is ejected and the application opts to keep it, these functions must be used to manage the
/// datagram buffer lifetime. The datagram will be freed once the reference count reaches zero.
void udpard_tx_refcount_inc(const udpard_bytes_t tx_payload_view);
void udpard_tx_refcount_dec(const udpard_bytes_t tx_payload_view);

/// Drops all enqueued items; afterward, the instance is safe to discard. Reliable transfer callbacks are still invoked.
void udpard_tx_free(udpard_tx_t* const self);

// =====================================================================================================================
// =================================================    RX PIPELINE    =================================================
// =====================================================================================================================

/// The reception (RX) pipeline is used to subscribe to subjects and to receive P2P transfers.
/// The reception pipeline is highly robust and is able to accept datagrams with arbitrary MTU distinct per interface,
/// delivered out-of-order (OOO) with duplication and arbitrary interleaving between transfers.
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
/// Mode       Guarantees                       Limitations                        Reordering window
/// -----------------------------------------−------------------------------------------------------------------
/// ORDERED    Strictly increasing transfer-ID  May delay transfers, CPU heavier   Non-negative microseconds
/// UNORDERED  Unique transfer-ID               Ordering not guaranteed            Ignored
/// STATELESS  Constant time, constant memory   1-frame only, dups, no responses   Ignored
///
/// If not sure, choose `udpard_rx_unordered`. The `udpard_rx_ordered` mode is a good fit for ordering-sensitive
/// use cases like state estimators and control loops, but it is not suitable for P2P.
/// The `udpard_rx_stateless` mode is chiefly intended for the heartbeat topic.
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
/// The `udpard_rx_ordered` mode is used by passing `udpard_rx_ordered` as the mode parameter.
/// Zero is not really a special case for the reordering window; it simply means that out-of-order transfers
/// are not waited for at all (declared permanently lost immediately), and no received transfer is delayed
/// before ejection to the application.
///
/// The ORDERED mode is mostly intended for applications like state estimators, control systems, and data streaming
/// where ordering is critical.
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
/// The UNORDERED mode is used by passing `udpard_rx_unordered` as the mode parameter.
/// This should be the default mode for most use cases.
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
/// The STATELESS mode is used by passing `udpard_rx_stateless` as the mode parameter.

/// The application will have a single RX instance to manage all subscriptions and P2P ports.
typedef struct udpard_rx_t
{
    udpard_list_t  list_session_by_animation;   ///< Oldest at the tail.
    udpard_tree_t* index_session_by_reordering; ///< Earliest reordering window closure on the left.

    uint64_t errors_oom;                ///< A frame could not be processed (transfer possibly dropped) due to OOM.
    uint64_t errors_frame_malformed;    ///< A received frame was malformed and thus dropped.
    uint64_t errors_transfer_malformed; ///< A transfer could not be reassembled correctly.

    /// Incremented when an ack cannot be enqueued (including when tx is NULL).
    /// If tx is available, inspect its error counters for details.
    uint64_t errors_ack_tx;

    /// The transmission pipeline is needed to manage ack transmission and removal of acknowledged transfers.
    /// If the application wants to only listen, the pointer may be NULL (no acks will be sent).
    /// When initializing the library, the TX instance needs to be created first.
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
    udpard_mem_t session;

    /// The udpard_fragment_t handles are allocated per payload fragment; each contains a pointer to its fragment.
    /// Each instance is of a very small fixed size, so a trivial zero-fragmentation block allocator is sufficient.
    udpard_mem_t fragment;
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
    /// For P2P ports, UDPARD_P2P_HEADER_BYTES must be included in this value (the library takes care of this).
    size_t extent;

    /// See UDPARD_RX_REORDERING_WINDOW_... above.
    /// Behavior undefined if the reassembly mode is switched on a live port with ongoing transfers.
    udpard_rx_mode_t mode;
    udpard_us_t      reordering_window;

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
    /// 592 bytes. If the received payload exceeds the configured extent, fragments starting past the extent are
    /// dropped but fragments crossing it are kept, so payload_size_stored may exceed the extent.
    ///
    /// The application is given ownership of the payload buffer, so it is required to free it after use;
    /// this requires freeing both the handles and the payload buffers they point to.
    /// Beware that different memory resources may have been used to allocate the handles and the payload buffers;
    /// the application is responsible for freeing them using the correct memory resource.
    ///
    /// If the payload is empty, the corresponding buffer pointers may be NULL.
    size_t payload_size_stored;

    /// The original size of the transfer payload before extent-based dropping, in bytes.
    /// This may exceed the stored payload if fragments beyond the extent were skipped. Cannot be less than
    /// payload_size_stored.
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
/// Each node must have exactly one P2P port, which is used for P2P transfers and acknowledgments.
struct udpard_rx_port_p2p_t
{
    udpard_rx_port_t                   base;
    const udpard_rx_port_p2p_vtable_t* vtable;
};

/// The RX instance holds no resources and can be destroyed at any time by simply freeing all its ports first
/// using udpard_rx_port_free(), then discarding the instance itself. The self pointer must not be NULL.
/// The TX instance must be initialized beforehand, unless the application wants to only listen,
/// in which case it may be NULL.
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
///          For P2P transfer ports use ordinary unicast sockets.
///     3. Read data from the sockets continuously and forward each datagram to udpard_rx_port_push(),
///        along with the index of the redundant interface the datagram was received on.
///
/// For P2P ports, the procedure is similar except that the appropriate function is udpard_rx_port_new_p2p().
/// There must be exactly one P2P port per node.
///
/// The extent defines the maximum possible size of received objects, considering also possible future data type
/// versions with new fields. It is safe to pick larger values. Note well that the extent is not the same thing as
/// the maximum size of the object, it is usually larger! Transfers that carry payloads beyond the specified extent
/// still keep fragments that start before the extent, so the delivered payload may exceed it; fragments starting past
/// the limit are dropped.
///
/// The topic hash is needed to detect and ignore transfers that use different topics on the same subject-ID.
/// The collision callback is invoked if a topic hash collision is detected.
///
/// If not sure which reassembly mode to choose, consider `udpard_rx_unordered` as the default choice.
/// For ordering-sensitive use cases, such as state estimators and control loops, use `udpard_rx_ordered` with a short
/// window.
///
/// The pointed-to vtable instance must outlive the port instance.
///
/// The return value is true on success, false if any of the arguments are invalid.
/// The time complexity is constant. This function does not invoke the dynamic memory manager.
bool udpard_rx_port_new(udpard_rx_port_t* const              self,
                        const uint64_t                       topic_hash, // For P2P ports, this is the local node's UID.
                        const size_t                         extent,
                        const udpard_rx_mode_t               mode,
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
/// This is usable with udpard_rx_port_p2p_t as well via the base member.
/// Does not free the port itself since it is allocated by the application rather than the library,
/// and does not alter the RX instance aside from unlinking the port from it.
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
/// Returns false if any of the arguments are invalid.
bool udpard_rx_port_push(udpard_rx_t* const       rx,
                         udpard_rx_port_t* const  port,
                         const udpard_us_t        timestamp,
                         const udpard_udpip_ep_t  source_ep,
                         const udpard_bytes_mut_t datagram_payload,
                         const udpard_deleter_t   payload_deleter,
                         const uint_fast8_t       iface_index);

#ifdef __cplusplus
}
#endif
#endif
