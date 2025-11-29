///                            ____                   ______            __          __
///                           / __ `____  ___  ____  / ____/_  ______  / /_  ____  / /
///                          / / / / __ `/ _ `/ __ `/ /   / / / / __ `/ __ `/ __ `/ /
///                         / /_/ / /_/ /  __/ / / / /___/ /_/ / /_/ / / / / /_/ / /
///                         `____/ .___/`___/_/ /_/`____/`__, / .___/_/ /_/`__,_/_/
///                             /_/                     /____/_/
///
/// LibUDPard is a compact implementation of the Cyphal/UDP protocol for high-integrity real-time embedded systems.
/// It is designed for use in robust deterministic embedded systems equipped with at least 64K ROM and RAM.
/// The codebase is compliant with a large subset of MISRA C, has full test coverage, and is validated by at least
/// two static analyzers. The library is designed to be compatible with any conventional target platform and
/// instruction set architecture, from 8 to 64 bit, little- and big-endian, RTOS-based or baremetal,
/// as long as there is a standards-compliant ISO C99 compiler available.
///
/// The library offers a very low-level API that may be cumbersome to use in many applications.
/// It is intended to be paired with a higher-layer protocol engine that implements the named topic abstractions etc.
///
/// The library is intended to be integrated into the end application by simply copying its source files into the
/// source tree of the project; it does not require any special compilation options and should work out of the box.
/// There are build-time configuration parameters defined near the top of udpard.c, but they are optional to use.
///
/// To use the library, the application needs to provide an implementation of the UDP/IP stack with IGMP support.
/// POSIX-based systems may use the standard Berkeley sockets API, while more constrained embedded systems may choose
/// to rely either on a third-party solution like LwIP or a custom UDP/IP stack implementation.
///
///
/// The transmission pipeline is used to publish messages and send P2P transfers to the network through a
/// particular redundant interface. A Cyphal node with R redundant network interfaces needs to instantiate
/// R transmission pipelines, one per interface, unless the application is not interested in sending data at all.
/// The transmission pipeline contains a prioritized queue of UDP datagrams scheduled for transmission via its
/// network interface.
///
/// Each transmission pipeline instance requires one socket (or a similar abstraction provided by the underlying
/// UDP/IP stack) that is not connected to any specific remote endpoint (i.e., usable with sendto(),
/// speaking in terms of Berkeley sockets). In the case of redundant interfaces, each socket may need to be configured
/// to emit data through its specific interface.
///
/// Graphically, the transmission pipeline is arranged as follows:
///
///                             +---> TX PIPELINE ---> UDP SOCKET ---> REDUNDANT INTERFACE A
///                             |
///     SERIALIZED TRANSFERS ---+---> TX PIPELINE ---> UDP SOCKET ---> REDUNDANT INTERFACE B
///                             |
///                             +---> ...
///
/// The library supports configurable DSCP marking of the outgoing UDP datagrams as a function of Cyphal transfer
/// priority level. This is configured separately per TX pipeline instance (i.e., per network interface).
/// The maximum transmission unit (MTU) can also be configured separately per TX pipeline instance.
/// Applications that are interested in maximizing their wire compatibility should not change the default MTU setting.
///
///
/// The reception pipelines are used to subscribe to subjects (aka topics) and to receive P2P transfers.
/// The reception pipeline is able to accept datagrams with arbitrary MTU, frames delivered out-of-order (OOO) with
/// arbitrary duplication, including duplication of non-adjacent frames, and/or frames interleaved between adjacent
/// transfers. The support for OOO reassembly is particularly interesting when simple repetition coding FEC is used.
///
/// The application should instantiate one subscription instance per subject it needs to receive messages from,
/// irrespective of the number of redundant interfaces. There needs to be one socket (or a similar abstraction
/// provided by the underlying UDP/IP stack) per subscription instance per redundant interface,
/// each socket bound to the same UDP/IP endpoint (IP address and UDP port) which is selected by the library when
/// the subscription is created.
/// The application needs to listen to all these sockets simultaneously and pass the received UDP datagrams to the
/// corresponding subscription instance as they arrive, thus unifying the datagrams received from all redundant
/// interface sockets into a single stream.
/// At the output, subscription instances provide reassembled and deduplicated stream of Cyphal transfers ready for
/// deserialization.
///
/// Graphically, the subscription pipeline is arranged as shown below.
/// Remember that the application with S topic subscriptions would have S such pipelines, one per subscription.
///
///     REDUNDANT INTERFACE A ---> UDP SOCKET ---+
///                                              |
///     REDUNDANT INTERFACE B ---> UDP SOCKET ---+---> SUBSCRIPTION ---> SERIALIZED TRANSFERS
///                                              |
///                                       ... ---+
///
///
///     Memory management
///
/// The library can be used either with a regular heap (preferably constant-time) or with a collection of fixed-size
/// block pool allocators (in safety-certified systems). It is up to the application to choose the desired memory
/// management strategy; the library is interfaced with the memory managers via a special memory resource abstraction.
///
/// Typically, if block pool allocators are used, the following block sizes should be served:
///
///     - MTU sized blocks for the TX and RX pipelines (usually less than 2048 bytes);
///     - TX fragment item sized blocks for the TX pipeline (less than 128 bytes).
///     - RX session object sized blocks for the RX pipeline (less than 512 bytes);
///     - RX fragment handle sized blocks for the RX pipeline (less than 128 bytes).
///     - udpard_remote_t sized blocks for the return path discovery.
///
/// --------------------------------------------------------------------------------------------------------------------
///
/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT
/// Author: Pavel Kirienko <pavel@opencyphal.org>

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
/// That being said, the MTU here is set to a larger value that is derived as:
///     1500B Ethernet MTU (RFC 894) - 60B IPv4 max header - 8B UDP Header - 48B Cyphal header
#define UDPARD_MTU_DEFAULT 1384U
/// To guarantee a single frame transfer, the maximum payload size shall be 4 bytes less to accommodate the CRC.
#define UDPARD_MTU_DEFAULT_MAX_SINGLE_FRAME (UDPARD_MTU_DEFAULT - 4U)

/// MTU less than this should not be used.
#define UDPARD_MTU_MIN 460U

#define UDPARD_PRIORITY_MAX 7U

/// The library supports at most this many local redundant network interfaces.
#define UDPARD_NETWORK_INTERFACE_COUNT_MAX 3U

typedef int64_t udpard_microsecond_t;

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
/// The reassembly stack will attempt to discover the sender's UDP/IP endpoint per redundant interface
/// based on the source address of the received UDP datagrams. If the sender's endpoint could not be discovered
/// for a certain interface, the corresponding entry in the origin array will be zeroed.
/// Note that this allows the sender to change its network interface address dynamically.
typedef struct udpard_remote_t
{
    uint64_t          source_uid;
    udpard_udpip_ep_t origin[UDPARD_NETWORK_INTERFACE_COUNT_MAX]; ///< Zeros in unavailable ifaces.
} udpard_remote_t;

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

/// This type represents payload as an ordered sequence of its fragments to eliminate data copying.
/// To free a fragmented payload buffer, the application needs to traverse the list and free each fragment's payload
/// as well as the payload structure itself, assuming that it is also heap-allocated.
/// The model is as follows:
///
///     (payload header) ---> udpard_fragment_t:
///                               next   ---> udpard_fragment_t...
///                               origin ---> (the free()able payload data buffer)
///                               view   ---> (somewhere inside the payload data buffer)
///
/// Payloads of received transfers are represented using this type, where each fragment corresponds to a frame.
/// The application can either consume them directly or to copy the data into a contiguous buffer beforehand
/// at the expense of extra time and memory utilization.
typedef struct udpard_fragment_t
{
    struct udpard_fragment_t* next; ///< Next in the fragmented payload buffer chain; NULL in the last entry.

    /// Contains the actual data to be used by the application.
    /// The memory pointed to by this fragment shall not be freed by the application.
    udpard_bytes_t view;

    /// Points to the base buffer that contains this fragment.
    /// The application can use this pointer to free the outer buffer after the payload has been consumed.
    udpard_bytes_mut_t origin;

    /// Zero-based index and byte offset of this fragment view from the beginning of the transfer payload.
    size_t   offset;
    uint32_t index;

    /// When the fragment is no longer needed, this deleter shall be used to free the origin buffer.
    /// We provide a dedicated deleter per fragment to allow NIC drivers to manage the memory directly,
    /// which allows DMA access to the fragment data without copying.
    /// See https://github.com/OpenCyphal-Garage/libcyphal/issues/352#issuecomment-2163056622
    udpard_mem_deleter_t payload_deleter;
} udpard_fragment_t;

/// Frees the memory allocated for the payload and its fragment headers using the correct memory resources.
/// The application can do the same thing manually if it has access to the required context to compute the size,
/// or if the memory resource implementation does not require deallocation size.
/// The head of the fragment list is passed by value so it is not freed. This is in line with the udpard_rx_transfer_t
/// design, where the head is stored by value to reduce indirection in small transfers. We call it Scott's Head.
/// If any of the arguments are NULL, the function has no effect.
void udpard_fragment_free(const udpard_fragment_t head, const udpard_mem_resource_t memory_fragment);

// =====================================================================================================================
// =================================================    TX PIPELINE    =================================================
// =====================================================================================================================

/// A TX queue uses these memory resources for allocating the enqueued items (UDP datagrams).
/// There are exactly two allocations per enqueued item:
/// - the first for bookkeeping purposes (UdpardTxItem)
/// - second for payload storage (the frame data)
/// In a simple application, there would be just one memory resource shared by all parts of the library.
/// If the application knows its MTU, it can use block allocation to avoid extrinsic fragmentation.
typedef struct udpard_tx_mem_resources_t
{
    /// The fragment handles are allocated per payload fragment; each handle contains a pointer to its fragment.
    /// Each instance is of a very small fixed size, so a trivial zero-fragmentation block allocator is enough.
    udpard_mem_resource_t fragment;

    /// The payload fragments are allocated per payload frame; each payload fragment is at most MTU-sized buffer,
    /// so a trivial zero-fragmentation MTU-sized block allocator is enough if MTU is known in advance.
    udpard_mem_resource_t payload;
} udpard_tx_mem_resources_t;

/// The transmission pipeline is a prioritized transmission queue that keeps UDP datagrams (aka transport frames)
/// destined for transmission via one network interface.
/// Applications with redundant network interfaces are expected to have one instance of this type per interface.
/// Applications that are not interested in transmission may have zero such instances.
///
/// All operations are logarithmic in complexity on the number of enqueued items.
/// Once initialized, instances cannot be copied.
///
/// FUTURE: Eventually we might consider adding another way of arranging the transmission pipeline where the UDP
/// datagrams ready for transmission are not enqueued into the local prioritized queue but instead are sent directly
/// to the network interface driver using a dedicated callback. The callback would accept not just a single
/// chunk of data but a list of three chunks to avoid copying the source transfer payload: the datagram header,
/// the payload, and (only for the last frame) the CRC. The driver would then use some form of vectorized IO or
/// MSG_MORE/UDP_CORK to transmit the data; the advantage of this approach is that up to two data copy operations are
/// eliminated from the stack and the memory allocator is not used at all. The disadvantage is that if the driver
/// callback is blocking, the application thread will be blocked as well; plus the driver will be responsible
/// for the correct prioritization of the outgoing datagrams according to the DSCP value.
typedef struct udpard_tx_t
{
    /// A globally unique identifier of the local node, composed of (VID<<48)|(PID<<32)|INSTANCE_ID.
    uint64_t local_uid;

    /// The maximum number of UDP datagrams this instance is allowed to enqueue.
    /// The purpose of this limitation is to ensure that a blocked queue does not exhaust the memory.
    size_t queue_capacity;

    /// The maximum number of Cyphal transfer payload bytes per UDP datagram.
    /// The Cyphal/UDP header and the final CRC are added to this value to obtain the total UDP datagram payload size.
    /// See UDPARD_MTU_*.
    /// The value can be changed arbitrarily at any time between enqueue operations.
    size_t mtu;

    /// The mapping from the Cyphal priority level in [0,7], where the highest priority is at index 0
    /// and the lowest priority is at the last element of the array, to the IP DSCP field value.
    /// By default, the mapping is initialized per the recommendations given in the Cyphal/UDP specification.
    /// The value can be changed arbitrarily at any time between enqueue operations.
    uint_least8_t dscp_value_per_priority[UDPARD_PRIORITY_MAX + 1U];

    udpard_tx_mem_resources_t memory;

    /// The number of frames that are currently contained in the queue, initially zero. READ-ONLY!
    size_t queue_size;

    /// Error counters incremented automatically when the corresponding error condition occurs.
    /// These counters are never decremented by the library but they can be reset by the application if needed.
    uint64_t errors_oom;        ///< A transfer could not be enqueued due to OOM.
    uint64_t errors_capacity;   ///< A transfer could not be enqueued due to queue capacity limit.
    uint64_t errors_expiration; ///< A frame had to be dropped due to premature deadline expiration.

    /// Internal use only, do not modify!
    udpard_tree_t* index_prio;     ///< Most urgent on the left, then according to the insertion order.
    udpard_tree_t* index_deadline; ///< Soonest on the left, then according to the insertion order.
} udpard_tx_t;

/// One UDP datagram stored in the udpard_tx_t transmission queue along with its metadata.
/// The datagram should be sent to the indicated UDP/IP endpoint with the specified DSCP value.
/// The datagram should be discarded (transmission aborted) if the deadline has expired.
/// All fields are READ-ONLY except the mutable `datagram_payload` field, which could be nullified to indicate
/// a transfer of the payload memory ownership to somewhere else.
typedef struct udpard_tx_item_t
{
    udpard_tree_t index_prio;
    udpard_tree_t index_deadline;

    /// Points to the next frame in this transfer or NULL. This field is mostly intended for own needs of the library.
    /// Normally, the application would not use it because transfer frame ordering is orthogonal to global TX ordering.
    /// It can be useful though for pulling pending frames from the TX queue if at least one frame of their transfer
    /// failed to transmit; the idea is that if at least one frame is missing, the transfer will not be received by
    /// remote nodes anyway, so all its remaining frames can be dropped from the queue at once using udpard_tx_pop().
    struct udpard_tx_item_t* next_in_transfer;

    /// This is the same value that is passed to udpard_tx_publish()/p2p().
    /// Frames whose transmission deadline is in the past are dropped (transmission aborted).
    udpard_microsecond_t deadline;

    /// The original transfer priority level. The application should obtain the corresponding DSCP value
    /// by mapping it via the dscp_value_per_priority array of the udpard_tx_t instance.
    udpard_prio_t priority;

    /// This UDP/IP datagram compiled by libudpard should be sent to this remote endpoint (usually multicast).
    udpard_udpip_ep_t destination;

    /// The completed UDP/IP datagram payload. This includes the Cyphal header as well as all required CRCs.
    udpard_bytes_mut_t datagram_payload;

    /// This opaque pointer is assigned the value that is passed to udpardTxPublish/Request/Respond.
    /// The library itself does not make use of it but the application can use it to provide continuity between
    /// its high-level transfer objects and datagrams that originate from it. Assign NULL if not needed.
    void* user_transfer_reference;
} udpard_tx_item_t;

/// The parameters will be initialized to the recommended defaults automatically,
/// which can be changed later by modifying the struct fields directly.
/// No memory allocation is going to take place until the pipeline is actually written to.
///
/// The instance does not hold any resources itself except for the allocated memory.
/// To safely discard it, simply pop all enqueued frames from it.
///
/// True on success, false if any of the arguments are invalid.
bool udpard_tx_new(udpard_tx_t* const              self,
                   const uint64_t                  local_uid,
                   const size_t                    queue_capacity,
                   const udpard_tx_mem_resources_t memory);

/// This function serializes a message transfer into a sequence of UDP datagrams and inserts them into the prioritized
/// transmission queue at the appropriate position. Afterwards, the application is supposed to take the enqueued frames
/// from the transmission queue using the udpard_tx_peek/pop() and transmit them one by one. The enqueued items
/// are prioritized according to their Cyphal transfer priority to avoid the inner priority inversion. The transfer
/// payload will be copied into the transmission queue so that the lifetime of the datagrams is not related to the
/// lifetime of the input payload buffer.
///
/// The MTU of the generated datagrams is dependent on the value of the MTU setting at the time when this function
/// is invoked. The MTU setting can be changed arbitrarily between invocations.
///
/// The transfer_id parameter will be used to populate the transfer_id field of the generated datagrams.
/// The caller shall increment the transfer-ID counter after each successful invocation of this function
/// per redundant interface; the same transfer published over redundant interfaces shall have the same transfer-ID.
/// There shall be a separate transfer-ID counter per topic. The initial value shall be chosen randomly
/// such that it is likely to be distinct per application startup (embedded systems can use noinit memory sections,
/// hash uninitialized SRAM, use timers or ADC noise, etc).
///
/// The user_transfer_reference is an opaque pointer that will be assigned to the user_transfer_reference field of
/// each enqueued item. The library itself does not use or check this value in any way, so it can be NULL if not needed.
///
/// The deadline value will be used to populate the eponymous field of the generated datagrams (all will share the
/// same deadline value). This feature is intended to allow aborting frames that could not be transmitted before
/// the specified deadline; therefore, the timestamp value should be in the future.
///
/// The function returns the number of UDP datagrams enqueued, which is always a positive number, in case of success.
/// In case of failure, the function returns zero, with the corresponding error counters incremented.
/// In case of an error, no frames are added to the queue; in other words, either all frames of the transfer are
/// enqueued successfully, or none are.
///
/// The memory allocation requirement is two allocations per datagram:
/// a single-frame transfer takes two allocations; a multi-frame transfer of N frames takes N*2 allocations.
/// In each pair of allocations:
/// - the first allocation is for `udpard_tx_t`; the size is `sizeof(udpard_tx_t)`;
///   the TX queue `memory.fragment` memory resource is used for this allocation (and later for deallocation);
/// - the second allocation is for payload storage (the datagram data) - size is normally MTU but could be less for
///   the last frame of the transfer; the TX queue `memory.payload` resource is used for this allocation.
///
/// The time complexity is O(p + log e), where p is the amount of payload in the transfer, and e is the number of
/// transfers (not frames) already enqueued in the transmission queue.
uint32_t udpard_tx_publish(udpard_tx_t* const         self,
                           const udpard_microsecond_t now,
                           const udpard_microsecond_t deadline,
                           const udpard_prio_t        priority,
                           const uint64_t             topic_hash,
                           const uint32_t             subject_id,
                           const uint64_t             transfer_id,
                           const udpard_bytes_t       payload,
                           const bool                 ack_required,
                           void* const                user_transfer_reference);

/// Similar to udpard_tx_publish, but for P2P transfers between specific nodes.
/// This can only be sent in a response to a published message; the RX pipeline will provide the discovered return
/// endpoint for this particular remote node.
uint32_t udpard_tx_p2p(udpard_tx_t* const         self,
                       const udpard_microsecond_t now,
                       const udpard_microsecond_t deadline,
                       const uint64_t             remote_uid,
                       const udpard_udpip_ep_t    remote_ep,
                       const udpard_prio_t        priority,
                       const uint64_t             transfer_id,
                       const udpard_bytes_t       payload,
                       const bool                 ack_required,
                       void* const                user_transfer_reference);

/// Purges all timed out items from the transmission queue automatically; returns the next item to be transmitted,
/// if there is any, otherwise NULL. The returned item is not removed from the queue; use udpard_tx_pop() to do that.
/// The returned item (if any) is guaranteed to be non-expired (deadline>=now).
udpard_tx_item_t* udpard_tx_peek(udpard_tx_t* const self, const udpard_microsecond_t now);

/// Transfers the ownership of the specified item to the application. The item does not necessarily need to be the
/// top one -- it is safe to dequeue any item. The item is dequeued but not invalidated; it is the responsibility of
/// the application to deallocate its memory later.
/// The memory SHALL NOT be deallocated UNTIL this function is invoked (use udpard_tx_free()).
/// If any of the arguments are NULL, the function has no effect.
/// This function does not invoke the dynamic memory manager.
void udpard_tx_pop(udpard_tx_t* const self, udpard_tx_item_t* const item);

/// This is a simple helper that frees the memory allocated for the item and its payload.
/// If the item argument is NULL, the function has no effect. The time complexity is constant.
/// If the item frame payload is NULL then it is assumed that the payload buffer was already freed,
/// or moved to a different owner (f.e. to the media layer).
void udpard_tx_free(const udpard_tx_mem_resources_t memory, udpard_tx_item_t* const item);

// =====================================================================================================================
// =================================================    RX PIPELINE    =================================================
// =====================================================================================================================

/// These are used to serve the memory needs of the library to keep state while reassembling incoming transfers.
/// Several memory resources are provided to enable fine control over the allocated memory if necessary; however,
/// simple applications may choose to use the same memory resource implemented via malloc()/free() for all of them.
typedef struct udpard_rx_memory_resources_t
{
    /// Provides memory for the session instances described below.
    /// Each instance is fixed-size, so a trivial zero-fragmentation block allocator is sufficient.
    udpard_mem_resource_t session;

    /// The fragment handles are allocated per payload fragment; each handle contains a pointer to its fragment.
    /// Each instance is of a very small fixed size, so a trivial zero-fragmentation block allocator is sufficient.
    udpard_mem_resource_t fragment;
} udpard_rx_memory_resources_t;

/// This type represents an open input port, such as a subscription to a topic.
typedef struct udpard_rx_port_t
{
    uint64_t topic_hash; ///< Mismatch will be filtered out.
    size_t   extent;

    /// The transfer reassembly state machine can operate in two modes:
    ///
    /// ORDERED --- Each transfer is received at most once. The sequence of transfers delivered (ejected)
    /// to the application is STRICTLY INCREASING (with possible gaps in case of loss). The reassembler may hold
    /// completed transfers for a brief time if they arrive out-of-order, hoping for the earlier missing transfers
    /// to show up, such that they are not permanently lost. For example, a sequence 1 2 4 3 5 will be delivered as
    /// 1 2 3 4 5 if 3 arrives shortly after 4; however, if 3 does not arrive within the configured reordering window,
    /// the application will receive 1 2 4 5, and transfer 3 will be permanently lost even if it arrives later.
    ///
    /// IMMEDIATE --- Each transfer is ejected immediately upon successful reassembly. Transfers may be duplicated
    /// and arrive out-of-order.
    ///
    /// The ORDERED mode is used if the reordering window is non-negative. Zero is not really a special case, it
    /// simply means that out-of-order transfers are not waited for at all (declared permanently lost immediately).
    /// The IMMEDIATE mode is used if the reordering window is negative.
    udpard_microsecond_t reordering_window;

    udpard_rx_memory_resources_t memory;

    /// Libudpard creates a new session instance per remote UID that emits transfers matching this port.
    /// For example, if the local node is subscribed to a certain subject and there are X nodes publishing
    /// transfers on that subject, then there will be X sessions created for that subject.
    ///
    /// Each session instance takes sizeof(UdpardInternalRxSession) bytes of dynamic memory for itself,
    /// which is at most 512 bytes on wide-word platforms (on small word size platforms it is usually much smaller).
    /// On top of that, each session instance holds memory for the transfer payload fragments and small fixed-size
    /// metadata objects called "fragment handles" (at most 128 bytes large, usually much smaller,
    /// depending on the pointer width and the word size), one handle per fragment.
    ///
    /// The transfer payload memory is not allocated by the library but rather moved from the application
    /// when the corresponding UDP datagram is received. If the library chooses to keep the frame payload
    /// (which is the case if the frame is not a duplicate, the frame sequence is valid, and the received payload
    /// does not exceed the extent configured for the port), a new fragment handle is allocated and it takes ownership
    /// of the entire datagram payload (including all overheads such as the Cyphal/UDP frame header and possible
    /// data that spills over the configured extent value for this port).
    /// If the library does not need the datagram to reassemble the transfer, its payload buffer is freed immediately.
    /// There is a 1-to-1 correspondence between the fragment handles and the payload fragments.
    /// Remote nodes that emit highly fragmented transfers cause a higher memory utilization in the local node
    /// because of the increased number of fragment handles and per-datagram overheads.
    ///
    /// Ultimately, the worst-case memory consumption is dependent on the configured extent and the transmitting
    /// side's MTU, as these parameters affect the number of payload buffers retained in memory.
    ///
    /// The maximum memory consumption is when there is a large number of nodes emitting data such that each node
    /// begins a multi-frame transfer while never completing it.
    ///
    /// If the dynamic memory pool(s) is(are) sized correctly, and all transmitting nodes are known to avoid excessive
    /// fragmentation of egress transfers (which can be ensured by not using MTU values smaller than the default),
    /// the application is guaranteed to never encounter an out-of-memory (OOM) error at runtime.
    /// High-integrity applications can optionally police ingress traffic for MTU violations and filter it before
    /// passing it to the library; alternatively, applications could limit memory consumption per port,
    /// which is easy to implement since each port gets a dedicated set of memory resources.
    udpard_tree_t* index_session_by_remote_uid;
} udpard_rx_port_t;

typedef struct udpard_rx_subscription_t
{
    udpard_rx_port_t port;

    uint32_t subject_id;

    /// The IP multicast group address and the UDP port number where UDP/IP datagrams matching this Cyphal
    /// subject will be sent by the publishers (remote nodes). READ-ONLY
    udpard_udpip_ep_t mcast_ep;
} udpard_rx_subscription_t;

/// Represents a received Cyphal transfer.
/// The payload is owned by this instance, so the application must free it after use; see udpardRxTransferFree.
typedef struct udpard_rx_transfer_t
{
    udpard_microsecond_t timestamp;
    udpard_remote_t      origin;
    udpard_prio_t        priority;
    uint64_t             transfer_id;

    /// The total size of the payload available to the application, in bytes, is provided for convenience;
    /// it is the sum of the sizes of all its fragments. For example, if the sender emitted a transfer of 2000
    /// bytes split into two frames, 1408 bytes in the first frame and 592 bytes in the second frame,
    /// then the payload_size_stored will be 2000 and the payload buffer will contain two fragments of 1408 and
    /// 592 bytes. The transfer CRC is not included here. If the received payload exceeds the configured extent,
    /// the excess payload will be discarded and the payload_size_stored will be set to the extent.
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

    udpard_fragment_t payload;
} udpard_rx_transfer_t;

/// Emitted when the stack detects the need to send a reception acknowledgment back to the remote node.
typedef struct udpard_rx_ack_mandate_t
{
    udpard_remote_t remote;
    udpard_prio_t   priority;
    uint64_t        transfer_id;
    udpard_bytes_t  payload_head; ///< View of the first <=MTU bytes of the transfer payload that is being confirmed.
} udpard_rx_ack_mandate_t;

struct udpard_rx_t;

/// A new message is received from a topic, or a P2P message is received.
/// The subscription is NULL for P2P transfers.
/// The handler takes ownership of the payload; it must free it after use.
typedef void* (*udpard_rx_on_message_t)(struct udpard_rx_t*, udpard_rx_subscription_t*, udpard_rx_transfer_t);

/// A topic hash collision is detected on a topic.
typedef void* (*udpard_rx_on_collision_t)(struct udpard_rx_t*, udpard_rx_subscription_t*);

/// The application is required to send an acknowledgment back to the sender.
/// The subscription is NULL for P2P transfers.
typedef void* (*udpard_rx_on_ack_mandate_t)(struct udpard_rx_t*, udpard_rx_subscription_t*, udpard_rx_ack_mandate_t);

typedef struct udpard_rx_t
{
    udpard_rx_port_t p2p_port; ///< A single port used for accepting all P2P transfers.

    udpard_list_t  list_session_by_animation;   ///< Oldest at the tail.
    udpard_tree_t* index_session_by_reordering; ///< Earliest reordering window closure on the left.

    udpard_rx_on_message_t     on_message;
    udpard_rx_on_collision_t   on_collision;
    udpard_rx_on_ack_mandate_t on_ack_mandate;

    uint64_t errors_oom;                ///< A frame could not be processed (transfer possibly dropped) due to OOM.
    uint64_t errors_frame_malformed;    ///< A received frame was malformed and thus dropped.
    uint64_t errors_transfer_malformed; ///< A received transfer was malformed (e.g., CRC error) and thus dropped.
} udpard_rx_t;

/// True on success, false if any of the arguments are invalid.
bool udpard_rx_new(udpard_rx_t* const                 self,
                   const uint64_t                     local_uid,
                   const udpard_rx_memory_resources_t memory,
                   const udpard_rx_on_message_t       on_message,
                   const udpard_rx_on_collision_t     on_collision,
                   const udpard_rx_on_ack_mandate_t   on_ack_mandate);

/// Must be invoked at least every few milliseconds (more often is fine) to purge timed-out sessions and eject
/// received transfers when the reordering window expires. If this is invoked simultaneously with rx subscription
/// reception, then this function should be invoked after the reception handling.
/// The time complexity is logarithmic in the number of living sessions.
void udpard_rx_poll(udpard_rx_t* const self, const udpard_microsecond_t now);

/// To subscribe to a subject, the application should do this:
///     1. Create a new udpard_rx_subscription_t instance using udpard_rx_subscription_new().
///     2. Per redundant network interface:
///        - Create a new RX socket bound to the IP multicast group address and UDP port number specified in the
///          endpoint field of the initialized subscription instance.
///     3. Read data from the sockets continuously and forward each datagram to udpard_rx_subscription_receive,
///        along with the index of the redundant interface the datagram was received on.
///
/// The extent defines the maximum possible size of received objects, considering also possible future data type
/// versions with new fields. It is safe to pick larger values. Note well that the extent is not the same thing as
/// the maximum size of the object, it is usually larger! Transfers that carry payloads that exceed the specified
/// extent will be accepted anyway but the excess payload will be truncated away, as mandated by the Specification.
/// The transfer CRC is always validated regardless of whether its payload is truncated.
///
/// The topic hash is needed to detect and ignore transfers that use different topics on the same subject-ID.
/// The collision callback is invoked if a topic hash collision is detected.
///
/// If not sure, set the reordering window to 1 millisecond.
///
/// The return value is true on success, false if any of the arguments are invalid.
/// The time complexity is constant. This function does not invoke the dynamic memory manager.
bool udpard_rx_subscription_new(udpard_rx_subscription_t* const    self,
                                const uint32_t                     subject_id,
                                const uint64_t                     topic_hash,
                                const size_t                       extent,
                                udpard_microsecond_t               reordering_window,
                                const udpard_rx_memory_resources_t memory);

void udpard_rx_subscription_free(udpard_rx_subscription_t* const self);

/// The timestamp value indicates the arrival time of the datagram. Often, naive software timestamping is adequate
/// for these purposes, but some applications may require a greater accuracy (e.g., for time synchronization).
///
/// The function takes ownership of the passed datagram payload buffer. The library will either store it as a
/// fragment of the reassembled transfer payload or free it using the corresponding memory resource
/// (see UdpardRxMemoryResources) if the datagram is not needed for reassembly. Because of the ownership transfer,
/// the datagram payload buffer has to be mutable (non-const).
/// One exception is that if the "self" pointer is invalid, the library will be unable to process or free the datagram,
/// which may lead to a memory leak in the application; hence, the caller should always check that the "self" pointer
/// is always valid.
///
/// The function invokes the dynamic memory manager in the following cases only (refer to UdpardRxPort for details):
///
///     1. A new session state instance is allocated when a new session is initiated.
///
///     2. A new transfer fragment handle is allocated when a new transfer fragment is accepted.
///
///     3. A new return path discovery instance is allocated when a new remote UID is observed.
///
///     4. Allocated objects may occasionally be deallocated at the discretion of the library.
///        This behavior does not increase the worst case execution time and does not improve the worst case memory
///        consumption, so a deterministic application need not consider this behavior in its resource analysis.
///        This behavior is implemented for the benefit of applications where rigorous characterization is unnecessary.
///
/// The time complexity is O(log n) where n is the number of remote notes publishing on this subject (topic).
/// No data copy takes place. Malformed frames are discarded in constant time.
/// Linear time is spent on the CRC verification of the transfer payload when the transfer is complete.
///
/// Returns true on successful processing, false if any of the arguments are invalid.
bool udpard_rx_subscription_receive(udpard_rx_t* const              rx,
                                    udpard_rx_subscription_t* const sub,
                                    const udpard_microsecond_t      timestamp_usec,
                                    const udpard_udpip_ep_t         source_endpoint,
                                    const udpard_bytes_mut_t        datagram_payload,
                                    const udpard_mem_deleter_t      payload_deleter,
                                    const uint_fast8_t              redundant_iface_index);

/// Like the above but for P2P unicast transfers exchanged between specific nodes.
bool udpard_rx_p2p_receive(udpard_rx_subscription_t* const rx,
                           const udpard_microsecond_t      timestamp_usec,
                           const udpard_udpip_ep_t         source_endpoint,
                           const udpard_bytes_mut_t        datagram_payload,
                           const udpard_mem_deleter_t      payload_deleter,
                           const uint_fast8_t              redundant_iface_index);

#ifdef __cplusplus
}
#endif
#endif
