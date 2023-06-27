///                            ____                   ______            __          __
///                           / __ `____  ___  ____  / ____/_  ______  / /_  ____  / /
///                          / / / / __ `/ _ `/ __ `/ /   / / / / __ `/ __ `/ __ `/ /
///                         / /_/ / /_/ /  __/ / / / /___/ /_/ / /_/ / / / / /_/ / /
///                         `____/ .___/`___/_/ /_/`____/`__, / .___/_/ /_/`__,_/_/
///                             /_/                     /____/_/
///
/// description tbd
///
/// Two decoupled parts of the library: TX pipeline and RX pipeline.
/// The following sockets (or similar abstractions) are needed to use the library:
///
/// - One unconnected and unbound transmission socket used for all outgoing transfers:
///   publications, RPC-requests, and RPC-responses.
///
/// - One bound socket per subscription.
///
/// - One bound socket shared for all incoming RPC transfers
///   (responses for the local RPC-clients and requests for the local RPC-servers).
///
/// Therefore, an application with X subscriptions requires X+2 sockets, unless it is not interested in publishing
/// and/or using RPC-services.
///
/// --------------------------------------------------------------------------------------------------------------------
///
/// This software is distributed under the terms of the MIT License.
/// Copyright (c) 2016 OpenCyphal.
/// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
/// Author: Pavel Kirienko <pavel@opencyphal.org>

#ifndef UDPARD_H_INCLUDED
#define UDPARD_H_INCLUDED

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Semantic version of this library (not the Cyphal specification).
/// API will be backward compatible within the same major version.
#define UDPARD_VERSION_MAJOR 0
#define UDPARD_VERSION_MINOR 1

/// The version number of the Cyphal specification implemented by this library.
#define UDPARD_CYPHAL_SPECIFICATION_VERSION_MAJOR 1
#define UDPARD_CYPHAL_SPECIFICATION_VERSION_MINOR 0

/// These error codes may be returned from the library API calls whose return type is a signed integer in the negated
/// form (e.g., error code 2 returned as -2). A non-negative return value represents success.
/// API calls whose return type is not a signed integer cannot fail by contract.
/// No other error states may occur in the library.
/// By contract, a well-characterized application with a properly sized memory pool will never encounter errors.
/// The error code 1 is not used because -1 is often used as a generic error code in 3rd-party code.
#define UDPARD_ERROR_INVALID_ARGUMENT 2
#define UDPARD_ERROR_OUT_OF_MEMORY 3

/// MTU values for the supported protocols.
/// RFC 791 states that hosts must be prepared to accept datagrams of up to 576 octets and it is expected that this
/// library will receive non IP-fragmented datagrams thus the minimum MTU should be larger than 576.
/// That being said, the MTU here is set to 1408 which is derived as:
///     1500B Ethernet MTU (RFC 894) - 60B IPv4 max header - 8B UDP Header - 24B Cyphal header
#define UDPARD_MTU_MAX 1408U
/// To guarantee a single frame transfer, the maximum payload size shall be 4 bytes less to accommodate for the CRC.
#define UDPARD_MTU_MAX_SINGLE_FRAME (UDPARD_MTU_MAX - 4U)

/// The port number is defined in the Cyphal/UDP Specification. The same port number is used for all transfer kinds.
#define UDPARD_UDP_PORT 9382U

/// Parameter ranges are inclusive; the lower bound is zero for all. See Cyphal/UDP Specification for background.
#define UDPARD_SUBJECT_ID_MAX 8191U
#define UDPARD_SERVICE_ID_MAX 511U
#define UDPARD_NODE_ID_MAX 0xFFFEU  /// 2**16-1 is reserved for the anonymous/broadcast ID.
#define UDPARD_PRIORITY_MAX 7U

/// This value represents an undefined node-ID: broadcast destination or anonymous source.
#define UDPARD_NODE_ID_UNSET 0xFFFFU

/// This is the recommended transfer-ID timeout value given in the Cyphal Specification. The application may choose
/// different values per subscription (i.e., per data specifier) depending on its timing requirements.
#define UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC 2000000UL

/// The library supports at most this many redundant network interfaces per Cyphal node.
#define UDPARD_NETWORK_INTERFACE_COUNT_MAX 3U

// Forward declarations.
typedef struct UdpardInstance       UdpardInstance;
typedef struct UdpardTreeNode       UdpardTreeNode;
typedef struct UdpardTxItem         UdpardTxItem;
typedef struct UdpardMemoryResource UdpardMemoryResource;
typedef uint64_t                    UdpardMicrosecond;
typedef uint16_t                    UdpardPortID;
typedef uint16_t                    UdpardNodeID;
typedef uint64_t                    UdpardTransferID;

/// Transfer priority level mnemonics per the recommendations given in the Cyphal Specification.
typedef enum
{
    UdpardPriorityExceptional = 0,
    UdpardPriorityImmediate   = 1,
    UdpardPriorityFast        = 2,
    UdpardPriorityHigh        = 3,
    UdpardPriorityNominal     = 4,  ///< Nominal priority level should be the default.
    UdpardPriorityLow         = 5,
    UdpardPrioritySlow        = 6,
    UdpardPriorityOptional    = 7,
} UdpardPriority;

/// The AVL tree node structure is exposed here to avoid pointer casting/arithmetics inside the library.
/// The user code is not expected to interact with this type except if advanced introspection is required.
struct UdpardTreeNode
{
    UdpardTreeNode* up;     ///< Do not access this field.
    UdpardTreeNode* lr[2];  ///< Left and right children of this node may be accessed for tree traversal.
    int8_t          bf;     ///< Do not access this field.
};

typedef struct
{
    size_t size;
    void*  data;
} UdpardMutablePayload;

typedef struct
{
    size_t      size;
    const void* data;
} UdpardConstPayload;

typedef struct
{
    uint32_t ip_address;
    uint16_t udp_port;
} UdpardUDPIPEndpoint;

// =============================================================================================================
// =============================================  MEMORY RESOURCE  =============================================
// =============================================================================================================

/// A pointer to the memory allocation function. The semantics are similar to malloc():
///     - The returned pointer shall point to an uninitialized block of memory that is at least "amount" bytes large.
///     - If there is not enough memory, the returned pointer shall be NULL.
///     - The memory shall be aligned at least at max_align_t.
///     - The execution time should be constant (O(1)).
///     - The worst-case memory fragmentation should be bounded and easily predictable.
/// If the standard dynamic memory manager of the target platform does not satisfy the above requirements,
/// consider using O1Heap: https://github.com/pavel-kirienko/o1heap.
typedef void* (*UdpardMemoryAllocate)(UdpardMemoryResource* const self, const size_t size);

/// The counterpart of the above -- this function is invoked to return previously allocated memory to the allocator.
/// The size argument contains the amount of memory that was originally requested via UdpardMemoryAllocate.
/// The semantics are similar to free():
///     - The pointer was previously returned by the allocation function.
///     - The pointer may be NULL, in which case the function shall have no effect.
///     - The execution time should be constant (O(1)).
typedef void (*UdpardMemoryFree)(UdpardMemoryResource* const self, const size_t size, void* const pointer);

/// A memory resource encapsulates the dynamic memory allocation and deallocation facilities.
/// The time complexity models given in the API documentation are made on the assumption that the memory management
/// functions have constant complexity O(1).
/// Consider using https://github.com/pavel-kirienko/o1heap as the memory resource implementation.
struct UdpardMemoryResource
{
    /// The function pointers shall be valid at all times.
    UdpardMemoryAllocate allocate;
    UdpardMemoryFree     free;
    /// This is an opaque pointer that can be freely utilized by the user for arbitrary needs.
    void* user_reference;
};

// =============================================================================================================
// =============================================    TX PIPELINE    =============================================
// =============================================================================================================

/// The transmission pipeline is a prioritized transmission queue that keeps UDP datagrams (aka frames)
/// destined for transmission via one network interface.
/// Applications with redundant network interfaces are expected to have one instance of this type per interface.
/// Applications that are not interested in transmission may have zero such instances.
///
/// All operations (push, peek, pop) are O(log n) in the worst case; there is exactly one memory allocation per element.
/// The size of each allocation is sizeof(UdpardTxItem) + payload_size.
/// Once initialized, instances cannot be copied.
///
/// API functions that work with this type are named "udpardTx*()", find them below.
typedef struct
{
    /// The node-ID of the local node. This is used to populate the source node-ID field of the Cyphal header.
    /// Set to UDPARD_NODE_ID_UNSET if the local node is anonymous.
    /// This is a reference to simplify plug-and-play node-ID allocation where the value has to be changed
    /// after the PnP process is complete; use of a pointer allows the application to update the node-ID in one place.
    const UdpardNodeID* local_node_id;

    /// The maximum number of frames this queue is allowed to contain. An attempt to push more will fail with an
    /// out-of-memory error even if the memory is not exhausted. This value can be changed by the user at any moment.
    /// The purpose of this limitation is to ensure that a blocked queue does not exhaust the heap memory.
    size_t queue_capacity;

    /// The transport-layer maximum transmission unit (MTU). The value can be changed arbitrarily at any time between
    /// pushes. It defines the maximum number of data bytes per UDP data frame in outgoing transfers via this queue.
    /// See UDPARD_MTU_*.
    size_t mtu_bytes;

    /// Mapping from the Cyphal priority level in [0,7], where the highest priority is at index 0
    /// and the lowest priority is at the last element of the array, to the IP DSCP field value.
    /// By default, the mapping is initialized per the recommendations given in the Cyphal/UDP specification.
    /// The user can change it at any moment individually per queue (i.e., per interface).
    uint8_t dscp_value_per_priority[UDPARD_PRIORITY_MAX + 1U];

    /// This field can be arbitrarily mutated by the user. It is never accessed by the library.
    /// Its purpose is to simplify integration with OOP interfaces.
    void* user_reference;

    /// The memory resource used by this queue for allocating the enqueued items (UDP datagrams).
    /// There is exactly one allocation per enqueued datagram.
    /// In a simple application there would be just one memory resource shared by all queues.
    UdpardMemoryResource memory;

    /// The number of frames that are currently contained in the queue, initially zero.
    /// READ-ONLY FIELD
    size_t size;

    /// The root of the priority queue is NULL if the queue is empty.
    /// READ-ONLY FIELD
    UdpardTreeNode* root;
} UdpardTx;

/// One frame (UDP datagram) stored in the transmission queue along with its metadata.
struct UdpardTxItem
{
    /// Internal use only; do not access this field.
    UdpardTreeNode base;

    /// Points to the next frame in this transfer or NULL. This field is mostly intended for own needs of the library.
    /// Normally, the application would not use it because transfer frame ordering is orthogonal to global TX ordering.
    /// It can be useful though for pulling pending frames from the TX queue if at least one frame of their transfer
    /// failed to transmit; the idea is that if at least one frame is missing, the transfer will not be received by
    /// remote nodes anyway, so all its remaining frames can be dropped from the queue at once using udpardTxPop().
    UdpardTxItem* next_in_transfer;

    /// This is the same value that is passed to udpardTxPublish/Request/Respond.
    /// Frames whose transmission deadline is in the past shall be dropped.
    UdpardMicrosecond deadline_usec;

    /// The differentiated services code point (DSCP) is used to prioritize UDP frames on the network.
    /// LibUDPard selects the DSCP value based on the transfer priority level and the configured DSCP mapping.
    /// Refer to the IP specification for details.
    uint8_t dscp;

    /// The UDP/IP datagram compiled by libudpard should be sent to this endpoint, which is always a multicast address.
    UdpardUDPIPEndpoint destination;

    /// The UDP/IP datagram payload. This includes the Cyphal header as well and all required CRC-s.
    /// It should be sent to the socket (or equivalent abstraction) verbatim.
    UdpardMutablePayload datagram_payload;

    /// This opaque pointer is assigned the value that is passed to udpardTxPush().
    /// The library itself does not make use of it but the application can use it to provide continuity between
    /// its high-level transfer objects and the low-level frame objects.
    /// If not needed, the application can set it to NULL.
    void* user_transfer_reference;
};

/// Construct a new transmission pipeline with the specified queue capacity and memory resource.
/// The other parameters will be initialized to the recommended defaults automatically, which can be changed later.
/// No memory allocation is going to take place until the queue is actually pushed to.
/// Applications are expected to have one instance of this type per redundant interface.
///
/// The instance does not hold any resources itself except for the allocated memory.
/// To safely discard it, simply pop all items from the queue.
///
/// The time complexity is constant. This function does not invoke the dynamic memory manager.
int8_t udpardTxInit(UdpardTx* const            self,
                    const UdpardNodeID* const  local_node_id,
                    const size_t               queue_capacity,
                    const UdpardMemoryResource memory_resource);

/// This function serializes a transfer into a sequence of transport frames and inserts them into the prioritized
/// transmission queue at the appropriate position. Afterwards, the application is supposed to take the enqueued frames
/// from the transmission queue using the function udpardTxPeek() and transmit them. Each transmitted (or otherwise
/// discarded, e.g., due to timeout) frame should be removed from the queue using udpardTxPop(). The queue is
/// prioritized following the normal UDP frame arbitration rules to avoid the inner priority inversion. The transfer
/// payload will be copied into the transmission queue so that the lifetime of the frames is not related to the
/// lifetime of the input payload buffer.
///
/// The MTU of the generated frames is dependent on the value of the MTU setting at the time when this function
/// is invoked. The MTU setting can be changed arbitrarily between invocations.
///
/// The user_transfer_reference is an opaque pointer that will be assigned to the user_transfer_reference field of
/// each frame in the resulting transfer. The library itself does not use or check this value in any way, so it can
/// be NULL if not needed.
///
/// The tx_deadline_usec will be used to populate the timestamp values of the resulting transport
/// frames (so all frames will have the same timestamp value). This feature is intended to facilitate transmission
/// deadline tracking, i.e., aborting frames that could not be transmitted before the specified deadline.
/// Therefore, normally, the timestamp value should be in the future.
/// The library itself, however, does not use or check this value in any way, so it can be zero if not needed.
///
/// The function returns the number of frames enqueued into the prioritized TX queue (which is always a positive
/// number) in case of success (so that the application can track the number of items in the TX queue if necessary).
/// In case of failure, the function returns a negated error code: either invalid argument or out-of-memory.
///
/// An invalid argument error may be returned in the following cases:
///     - Any of the input arguments are NULL.
///     - The remote node-ID is not UDPARD_NODE_ID_UNSET and the transfer is a message transfer.
///     - The remote node-ID is above UDPARD_NODE_ID_MAX and the transfer is a service transfer.
///     - The priority, subject-ID, or service-ID exceed their respective maximums.
///     - The transfer kind is invalid.
///     - The payload pointer is NULL while the payload size is nonzero.
///     - The local node is anonymous and a message transfer is requested that requires a multi-frame transfer.
///     - The local node is anonymous and a service transfer is requested.
/// The following cases are handled without raising an invalid argument error:
///     - If the transfer-ID is above the maximum, the excessive bits are silently masked away
///       (i.e., the modulo is computed automatically, so the caller doesn't have to bother).
///
/// An out-of-memory error is returned if a TX frame could not be allocated due to the memory being exhausted,
/// or if the capacity of the queue would be exhausted by this operation. In such cases, all frames allocated for
/// this transfer (if any) will be deallocated automatically. In other words, either all frames of the transfer are
/// enqueued successfully, or none are.
///
/// The time complexity is O(p + log e), where p is the amount of payload in the transfer, and e is the number of
/// frames already enqueued in the transmission queue.
///
/// The memory allocation requirement is one allocation per transport frame. A single-frame transfer takes one
/// allocation; a multi-frame transfer of N frames takes N allocations. The size of each allocation is
/// (sizeof(UdpardTxItem) + MTU).
int32_t udpardTxPublish(UdpardTx* const          self,
                        void* const              user_transfer_reference,
                        const UdpardMicrosecond  deadline_usec,
                        const UdpardPriority     priority,
                        const UdpardPortID       subject_id,
                        UdpardTransferID* const  transfer_id,
                        const UdpardConstPayload payload);

int32_t udpardTxRequest(UdpardTx* const          self,
                        void* const              user_transfer_reference,
                        const UdpardMicrosecond  deadline_usec,
                        const UdpardPriority     priority,
                        const UdpardPortID       service_id,
                        const UdpardNodeID       server_node_id,
                        UdpardTransferID* const  transfer_id,
                        const UdpardConstPayload payload);

int32_t udpardTxRespond(UdpardTx* const          self,
                        void* const              user_transfer_reference,
                        const UdpardMicrosecond  deadline_usec,
                        const UdpardPriority     priority,
                        const UdpardPortID       service_id,
                        const UdpardNodeID       client_node_id,
                        const UdpardTransferID   transfer_id,
                        const UdpardConstPayload payload);

/// This function accesses the top element of the prioritized transmission queue. The queue itself is not modified
/// (i.e., the accessed element is not removed). The application should invoke this function to collect the transport
/// frames of serialized transfers pushed into the prioritized transmission queue by udpardTxPush().
///
/// The timestamp values of returned frames are initialized with tx_deadline_usec from udpardTxPush().
/// Timestamps are used to specify the transmission deadline. It is up to the application and/or the media layer
/// to implement the discardment of timed-out transport frames. The library does not check it, so a frame that is
/// already timed out may be returned here.
///
/// If the queue is empty or if the argument is NULL, the returned value is NULL.
///
/// If the queue is non-empty, the returned value is a pointer to its top element (i.e., the next frame to transmit).
/// The returned pointer points to an object allocated in the dynamic storage; it should be eventually freed by the
/// application by calling udpardInstance::memory_free(). The memory shall not be freed before the entry is removed
/// from the queue by calling udpardTxPop(); this is because until udpardTxPop() is executed, the library retains
/// ownership of the object. The pointer retains validity until explicitly freed by the application; in other words,
/// calling udpardTxPop() does not invalidate the object.
///
/// The payload buffer is located shortly after the object itself, in the same memory fragment. The application shall
/// not attempt to free it.
///
/// The time complexity is logarithmic of the queue size. This function does not invoke the dynamic memory manager.
const UdpardTxItem* udpardTxPeek(const UdpardTx* const self);

/// This function transfers the ownership of the specified element of the prioritized transmission queue from the queue
/// to the application. The element does not necessarily need to be the top one -- it is safe to dequeue any element.
/// The element is dequeued but not invalidated; it is the responsibility of the application to deallocate the
/// memory used by the object later. The memory SHALL NOT be deallocated UNTIL this function is invoked.
/// The function returns the same pointer that it is given except that it becomes mutable.
///
/// If any of the arguments are NULL, the function has no effect and returns NULL.
///
/// The time complexity is logarithmic of the queue size. This function does not invoke the dynamic memory manager.
UdpardTxItem* udpardTxPop(UdpardTx* const self, const UdpardTxItem* const item);

// =============================================================================================================
// =============================================    RX PIPELINE    =============================================
// =============================================================================================================

/// This type represents an open input port, such as a subscription to a subject (topic), a service server port
/// that accepts RPC-service requests, or a service client port that accepts RPC-service responses.
/// It is not meant to be accessed by the application directly except if advanced introspection is required.
typedef struct
{
    /// For subject ports this is the subject-ID. For RPC-service ports this is the service-ID.
    /// READ-ONLY FIELD
    UdpardPortID port_id;

    /// The maximum payload size that can be accepted at this port.
    /// The rest will be truncated away following the implicit truncation rule defined in the Cyphal specification.
    /// READ-ONLY FIELD
    size_t extent;

    /// Refer to the Cyphal specification for the description of the transfer-ID timeout.
    /// See UDPARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC.
    /// This field can be adjusted at runtime arbitrarily; e.g., this is useful to implement adaptive timeouts.
    UdpardMicrosecond transfer_id_timeout_usec;

    /// A new session state instance is created per remote node-ID that emits transfers matching this port
    /// per redundant interface.
    /// For example, if the local node is subscribed to a certain subject and there are X nodes publishing
    /// transfers on that subject, then there will be X sessions created for that subject.
    /// Same applies to RPC-services as well.
    ///
    /// Once a session is created, it is never freed again until the port that owns it (this structure) is destroyed.
    /// This is in line with the assumption that the network configuration is usually static, and that
    /// once a node has started emitting data on a certain port, it is likely to continue doing so.
    /// Applications where this is not the case may consider cycling their ports periodically
    /// by destroying and re-creating them immediately.
    ///
    /// Each session instance takes sizeof(UdpardInternalRxSession) bytes of heap memory,
    /// which is at most 128 bytes on most platforms (on small word size platforms it may be much smaller).
    /// On top of that, each session instance may have one payload buffer allocated for the reassembled transfer;
    /// the size of that buffer is determined by the application at the time of subscription.
    /// The payload buffer is only allocated while reassembly is in progress; when the subscription is idle,
    /// no additional memory is held by the session instance.
    ///
    /// From the above one can deduce that the worst situation from the memory management standpoint is when
    /// there is a large number of nodes emitting data under a certain session specifier (e.g., publishing on a subject)
    /// such that each node begins a multi-frame transfer while never completing it.
    ///
    /// READ-ONLY FIELD
    UdpardTreeNode* sessions;
} UdpardRxPort;

/// Represents a received Cyphal transfer.
/// The payload is owned by this instance, so the application is required to free it after use.
typedef struct
{
    UdpardMicrosecond    timestamp_usec;
    UdpardPriority       priority;
    UdpardNodeID         remote_node_id;
    UdpardTransferID     transfer_id;
    UdpardMutablePayload payload;
} UdpardRxTransfer;

// ---------------------------------------------  SUBJECTS  ---------------------------------------------

/// This is a specialization of a port for subject (topic) subscriptions.
/// In Cyphal/UDP, each subject (topic) has a specific IP multicast group address associated with it.
/// This address is available here in a dedicated field.
/// The application is expected to open a socket bound to that endpoint and then feed the UDP datagrams received
/// from that socket into the library by calling udpardRxSubscriptionReceive.
typedef struct
{
    /// The IP address and UDP port number where UDP/IP datagrams matching this Cyphal subject will be sent.
    /// The application should initialize a multicast socket bound to this endpoint.
    /// READ-ONLY FIELD
    UdpardUDPIPEndpoint udpip_endpoint;

    UdpardMemoryResource memory_for_sessions;
    UdpardMemoryResource memory_for_payloads;

    UdpardRxPort port;
} UdpardRxSubscription;

int8_t udpardRxSubscriptionInit(UdpardRxSubscription* const self,
                                const UdpardPortID          subject_id,
                                const size_t                extent,
                                const UdpardMemoryResource  memory_for_sessions,
                                const UdpardMemoryResource  memory_for_payloads);

void udpardRxSubscriptionDestroy(UdpardRxSubscription* const self);

/// redundant_iface_index shall not exceed UDPARD_NETWORK_INTERFACE_COUNT_MAX.
int8_t udpardRxSubscriptionReceive(UdpardRxSubscription* const self,
                                   const UdpardMicrosecond     timestamp_usec,
                                   const UdpardConstPayload    datagram_payload,
                                   const uint8_t               redundant_iface_index,
                                   UdpardRxTransfer* const     out_transfer);

// ---------------------------------------------  RPC-SERVICES  ---------------------------------------------

typedef struct
{
    /// READ-ONLY FIELD
    UdpardTreeNode base;

    UdpardRxPort port;

    /// This field can be arbitrarily mutated by the user. It is never accessed by the library.
    /// Its purpose is to simplify integration with OOP interfaces.
    void* user_reference;
} UdpardRxService;

typedef struct
{
    /// The IP address and UDP port number where UDP/IP datagrams carrying RPC-service transfers destined to this node
    /// will be sent.
    /// The application should initialize a socket bound to the IP multicast group and UDP socket specified here.
    /// READ-ONLY FIELD
    UdpardUDPIPEndpoint udpip_endpoint;

    UdpardMemoryResource memory_for_sessions;
    UdpardMemoryResource memory_for_payloads;

    /// READ-ONLY FIELDS
    UdpardRxService* request_ports;
    UdpardRxService* response_ports;
} UdpardRxServiceDispatcher;

/// Represents a received Cyphal RPC-service transfer -- either request or response.
typedef struct
{
    UdpardRxTransfer base;
    UdpardPortID     service_id;
    bool             is_request;
} UdpardRxServiceTransfer;

int8_t udpardRxServiceDispatcherInit(UdpardRxServiceDispatcher* const self,
                                     const UdpardNodeID               local_node_id,
                                     const UdpardMemoryResource       memory_for_sessions,
                                     const UdpardMemoryResource       memory_for_payloads);

void udpardRxServiceDispatcherDestroy(UdpardRxServiceDispatcher* const self);

int8_t udpardRxServiceDispatcherListen(UdpardRxServiceDispatcher* const self,
                                       UdpardRxService* const           out_service,
                                       const UdpardPortID               service_id,
                                       const bool                       is_request,
                                       const size_t                     extent);

void udpardRxServiceDispatcherUnlisten(UdpardRxServiceDispatcher* const self,
                                       const UdpardPortID               service_id,
                                       const bool                       is_request);

/// redundant_iface_index shall not exceed UDPARD_NETWORK_INTERFACE_COUNT_MAX.
int8_t udpardRxServiceDispatcherReceive(UdpardRxServiceDispatcher* const self,
                                        UdpardRxService** const          out_service,
                                        const UdpardMicrosecond          timestamp_usec,
                                        const UdpardConstPayload         datagram_payload,
                                        const uint8_t                    redundant_iface_index,
                                        UdpardRxServiceTransfer* const   out_transfer);

#ifdef __cplusplus
}
#endif
#endif
