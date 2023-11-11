/**
 * @file   tm.c
 * @author [...]
 *
 * @section LICENSE
 *
 * [...]
 *
 * @section DESCRIPTION
 *
 * Implementation of your own transaction manager.
 * You can completely rewrite this file (and create more files) as you wish.
 * Only the interface (i.e. exported symbols and semantic) must be preserved.
**/

// External headers
#include <array>
#include <functional>
#include <vector>
#include <utility>
#include <atomic>
#include <bitset>
#include <list>
#include <cstdlib>
#include <cstring>
#include <map>

// Internal headers
#include <tm.hpp>

#include "macros.h"

constexpr size_t NUM_LOCKS = 4096;

struct write_map_key_t {
    void *location;
    uint64_t version_clock;
};

struct write_map_value_t {
    void *value;
    size_t size;
};

struct write_map_comp_t {
    bool operator()(write_map_key_t lhs, write_map_key_t rhs) {
        return lhs.version_clock < rhs.version_clock;
    }
};

struct transaction_t {
    using key_type = write_map_key_t;
    using value_type = write_map_value_t;
    using comp_type = write_map_comp_t;
    std::map<key_type, value_type, comp_type> write_set; // Location -> Value map.
    std::vector<void *> read_set;   // Locations read.
    std::vector<uint64_t> locks;    // Locks acquired.
};

struct segment_node {
    struct segment_node* prev;
    struct segment_node* next;
};
typedef struct segment_node* segment_list;

struct region_t {
    std::atomic<uint64_t> version_clock;
    std::atomic<uint64_t> lock_table[NUM_LOCKS];
    void *start;
    size_t size;
    size_t align;
    segment_list allocs;

    uint64_t get_version_clock() {
        // TODO(kostas): FIXME.
        return version_clock.load();
    }
};

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) {
    region_t *region = new (std::nothrow) region_t;
    void *start;
    
    if (unlikely(region != nullptr)) {
        return invalid_shared;
    }
    
    // We allocate the shared memory buffer such that its words are correctly
    // aligned.
    if (posix_memalign(&start, align, size) != 0) {
        delete region;
        return invalid_shared;
    }

    region->version_clock = 0;
    std::memset(start, 0, size);
    region->size        = size;
    region->align       = align;    
    region->allocs      = NULL;
    
    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t unused(shared)) {
    // TODO: tm_destroy(shared_t)
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared) {
    return ((region_t *) shared)->start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) {
    return ((region_t *) shared)->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) {
    return ((region_t *) shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t unused(shared), bool unused(is_ro)) {
    return invalid_tx;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t unused(shared), tx_t unused(tx)) {
    return false;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t unused(shared), tx_t unused(tx), void const* unused(source), size_t unused(size), void* unused(target)) {
    return false;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared, tx_t tx, void const* unused(source), size_t unused(size), void* unused(target)) {
    uint64_t version_clock = ((region_t *) shared)->get_version_clock();
    
    return true;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
alloc_t tm_alloc(shared_t unused(shared), tx_t unused(tx), size_t unused(size), void** unused(target)) {
    // TODO: tm_alloc(shared_t, tx_t, size_t, void**)
    return abort_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t unused(shared), tx_t unused(tx), void* unused(target)) {
    // TODO: tm_free(shared_t, tx_t, void*)
    return false;
}
