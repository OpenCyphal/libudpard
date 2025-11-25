# Migration Guide: Upgrading from LibUDPard v1.x to v2.0

This migration guide provides step-by-step instructions to help you update your application code from LibUDPard version 1.x to version 2.0. The guide highlights the key changes in the API and offers recommendations on how to adapt your code accordingly.

## Introduction

LibUDPard version 2.0 introduces several significant changes to improve memory management and payload handling. This guide will help you understand these changes and update your application code to be compatible with the new version.

These changes do not affect wire compatibility.

## Version Changes

- **LibUDPard Version**:
  - **Old**: `UDPARD_VERSION_MAJOR 1`, `UDPARD_VERSION_MINOR 2`
  - **New**: `UDPARD_VERSION_MAJOR 2`, `UDPARD_VERSION_MINOR 0`
- **Cyphal Specification Version**: Remains the same (`1.0`).

## Key API Changes

### UdpardTx Structure Changes

- **Memory Resource Field**: The `UdpardTx` structure's `memory` field type has changed from `UdpardMemoryResource` to `UdpardTxMemoryResources`.

  ```c
  // In v1.x
  struct UdpardTx {
      // ...
      struct UdpardMemoryResource memory;
      // ...
  };

  // In v2.0
  struct UdpardTx {
      // ...
      struct UdpardTxMemoryResources memory;
      // ...
  };
  ```

### Memory Management Adjustments

- **Separate Memory Resources**: `UdpardTxMemoryResources` now allows separate memory resources for fragment handles and payload storage.
  
  ```c
  struct UdpardTxMemoryResources {
      struct UdpardMemoryResource fragment; // For UdpardTxItem allocations
      struct UdpardMemoryResource payload;  // For datagram payload allocations
  };
  ```

- **Memory Allocation Changes**: The number of memory allocations per datagram has increased from one to two:
  - **v1.x**: One allocation per datagram (including `UdpardTxItem` and payload).
  - **v2.0**: Two allocations per datagram—one for `UdpardTxItem` and one for the payload.

### UdpardTxItem Structure Updates

- **Mutable datagram_payload Field**: The `datagram_payload` field in `UdpardTxItem` is now mutable, allowing ownership transfer of the payload.
  
- **New priority Field**: A new `priority` field has been added to `UdpardTxItem` to retain the original transfer priority level.
  
  ```c
  struct UdpardTxItem {
      // ...
      enum UdpardPriority priority;          // New field in v2.0
      struct UdpardMutablePayload datagram_payload; // Now mutable
      // ...
  };
  ```

### Function Signature Modifications

- **udpardTxInit**: The `memory` parameter type has changed to `UdpardTxMemoryResources`.
  
  ```c
  // In v1.x
  int_fast8_t udpardTxInit(
      struct UdpardTx* self,
      const UdpardNodeID* local_node_id,
      size_t queue_capacity,
      struct UdpardMemoryResource memory
  );

  // In v2.0
  int_fast8_t udpardTxInit(
      struct UdpardTx* self,
      const UdpardNodeID* local_node_id,
      size_t queue_capacity,
      struct UdpardTxMemoryResources memory
  );
  ```

- **udpardTxFree**: The `memory` parameter type has changed to `UdpardTxMemoryResources`.
  
  ```c
  // In v1.x
  void udpardTxFree(
      const struct UdpardMemoryResource memory,
      struct UdpardTxItem* item
  );

  // In v2.0
  void udpardTxFree(
      const struct UdpardTxMemoryResources memory,
      struct UdpardTxItem* item
  );
  ```

- **udpardTxPeek**: The return type has changed from `const struct UdpardTxItem*` to `struct UdpardTxItem*` to allow modification of the `datagram_payload` field.
  
  ```c
  // In v1.x
  const struct UdpardTxItem* udpardTxPeek(const struct UdpardTx* self);

  // In v2.0
  struct UdpardTxItem* udpardTxPeek(const struct UdpardTx* self);
  ```

## Migration Steps

Follow these steps to update your application code to be compatible with LibUDPard v2.0.

### 1. Update UdpardTx Initialization

- **Adjust the `udpardTxInit` Call**: Update the `memory` parameter to use `UdpardTxMemoryResources`.

  ```c
  // Before (v1.x)
  struct UdpardMemoryResource tx_memory = { /*...*/ };
  udpardTxInit(&tx_instance, &local_node_id, queue_capacity, tx_memory);

  // After (v2.0)
  struct UdpardTxMemoryResources tx_memory = {
      .fragment = { /*...*/ },
      .payload = { /*...*/ }
  };
  udpardTxInit(&tx_instance, &local_node_id, queue_capacity, tx_memory);
  ```

- **Define Separate Memory Resources**: Initialize separate memory resources for fragments and payloads.

### 2. Adjust Memory Resources

- **Update Memory Allocation Logic**: Ensure that your memory allocator handles two separate allocations per datagram—one for `UdpardTxItem` and one for the payload.

  ```c
  // Example allocator adjustments
  void* allocate_fragment(void* user_reference, size_t size) { /*...*/ }
  void* allocate_payload(void* user_reference, size_t size) { /*...*/ }
  ```

### 3. Modify UdpardTxItem Usage

- **Handle Mutable Payloads**: Since `datagram_payload` is now mutable, you can transfer ownership of the payload to another component (e.g., transmission media) by nullifying the `size` and `data` fields after copying.

  ```c
  struct UdpardTxItem* tx_item = udpardTxPeek(&tx_instance);
  if (tx_item) {
      // Transfer ownership of the payload
      transmit_payload(tx_item->datagram_payload.data, tx_item->datagram_payload.size);
      tx_item->datagram_payload.data = NULL;
      tx_item->datagram_payload.size = 0;

      // Pop and free the item after transmission
      udpardTxPop(&tx_instance, tx_item);
      udpardTxFree(tx_instance.memory, tx_item);
  }
  ```

- **Utilize the New priority Field**: Access the `priority` field in `UdpardTxItem` if needed for your application logic.

  ```c
  enum UdpardPriority tx_priority = tx_item->priority;
  ```

### 4. Revise Function Calls

- **Update `udpardTxFree` Calls**: Pass the updated `memory` parameter type.

  ```c
  // Before (v1.x)
  udpardTxFree(tx_memory, tx_item);

  // After (v2.0)
  udpardTxFree(tx_instance.memory, tx_item);
  ```

- **Modify `udpardTxPeek` Usage**: Since `udpardTxPeek` now returns a mutable pointer, update your code to handle the mutable `UdpardTxItem`.

  ```c
  // Before (v1.x)
  const struct UdpardTxItem* tx_item = udpardTxPeek(&tx_instance);

  // After (v2.0)
  struct UdpardTxItem* tx_item = udpardTxPeek(&tx_instance);
  ```

- **Ensure Correct Deallocation**: When freeing payloads, use the appropriate memory resource from `UdpardTxMemoryResources`.
