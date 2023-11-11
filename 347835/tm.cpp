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
#include <functional>
#include <vector>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <list>
#include <cassert>

// Internal headers
#include "tm.hpp"
#include "macros.h"

constexpr size_t NUM_LOCKS = 4096;
constexpr size_t SPINLOCK_TRIES = 1024;
constexpr size_t GRAIN = 4;

struct write_map_value_t {
    void *value;
    size_t size;
};

struct lock_t {
    std::atomic<uint64_t> version_number;
    std::atomic<bool> lock;
};

struct transaction_t {
    using key_type = void *;
    using value_type = write_map_value_t;
    std::list<void *> write_set;
    std::unordered_map<key_type, value_type> write_map; // Location -> Value map.
    std::vector<const void *> read_set;  // Locations read.
    bool is_ro;  // Is read-only.
    uint64_t rv;  // Read version number.

    void insert_write_chronological_order(void *addr) {
        // We want to avoid expensive list lookup for every tm_write.
        // Quickly search the map to see if it is indeed already there.
        auto it = write_map.find(addr);
        if (likely(it == write_map.end())) {
            // Common case, not duplicate.
            write_set.push_back(addr);
            return;
        }

        // Uncommon case.
        write_set.remove(addr);
        write_set.push_back(addr);
    }
};

struct segment_node_t {
    struct segment_node_t* prev;
    struct segment_node_t* next;
};
typedef struct segment_node_t* segment_list;

struct region_t {
    std::atomic<uint64_t> version_clock;
    lock_t lock_table[NUM_LOCKS];
    void *start;
    size_t size;
    size_t align;
    segment_list allocs;

    uint64_t get_version_clock() const {
        return version_clock.load();
    }

    size_t get_lock_table_idx(const void *location) const {
        return (((uintptr_t) location) >> GRAIN) % NUM_LOCKS;
    }

    uint64_t get_version_number(const void *location) const {
        size_t idx = get_lock_table_idx(location);
        return lock_table[idx].version_number.load();
    }

    void set_version_number(const void *location, uint64_t version_number) {
        size_t idx = get_lock_table_idx(location);
        return lock_table[idx].version_number.store(version_number);
    }

    bool is_locked(const void *location) const {
        size_t idx = get_lock_table_idx(location);
        return lock_table[idx].lock.load();
    }

    bool acquire_lock(const void *location) {
        size_t idx = get_lock_table_idx(location);
        std::atomic<bool> *l = &lock_table[idx].lock;
        // Bounded spinlock.
        size_t tries = 0;
        while (tries < SPINLOCK_TRIES) {
            if (!l->exchange(true, std::memory_order_acquire)) {
                // Lock acquired.
                return true;
            }
        }

        // Lock not acquired.
        return false;
    }

    void release_lock(const void *location) {
        size_t idx = get_lock_table_idx(location);
        std::atomic<bool> *l = &lock_table[idx].lock;
        l->exchange(false, std::memory_order_release);
    }
};

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) noexcept {
    auto *region = new (std::nothrow) region_t;
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
    region->size = size;
    region->align = align;
    region->allocs = nullptr;

    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t unused(shared)) noexcept {
    // TODO: tm_destroy(shared_t)
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared) noexcept {
    return ((region_t *) shared)->start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) noexcept {
    return ((region_t *) shared)->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) noexcept {
    return ((region_t *) shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared, bool is_ro) noexcept {
    auto *transaction = new (std::nothrow) transaction_t;

    if (unlikely(transaction == nullptr)) {
        return invalid_tx;
    }

    transaction->is_ro = is_ro;
    transaction->rv = ((region_t *) shared)->get_version_clock();

    return (tx_t) transaction;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) noexcept {
    transaction_t *transaction = (transaction_t *) tx;

    if (transaction->write_map.empty()) {
        transaction->read_set.clear();
        return true;
    }

    if (transaction->is_ro) {
        return true;
    }

    region_t *region = ((region_t *) shared);
    // Acquire locks for write_set.
    for (auto addr : transaction->write_set) {
        if (!region->acquire_lock(addr)) {
            return false;
        }
    }

    // All locks acquired, increment_and_fetch on global version clock.
    auto wv = region->version_clock.fetch_add(1);

    // Validate read set.
    if (wv != transaction->rv + 1) {
        for (const auto& addr: transaction->read_set) {
            auto wl = region->get_version_number(addr);
            if (wl > transaction->rv) {
                return false;
            }
        }
    }

    // Commit writes and release locks.
    for (const auto& kv: transaction->write_map) {
        std::memcpy(kv.first, kv.second.value, kv.second.size);
        region->release_lock(kv.first);
        region->set_version_number(kv.first, wv);
    }

    return true;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target) noexcept {
    auto *transaction = (transaction_t *) tx;

    if (transaction->is_ro) {
        std::memcpy(target, source, size);
        return true;
    }

    // const_cast is undefined behavior only if we attempt to modify.
    // This is not the case here.
    auto it = transaction->write_map.find(const_cast<void *>(source));
    if (it != transaction->write_map.end()) {
        std::memcpy(target, it->second.value, it->second.size);
        return true;
    }

    region_t *region = (region_t *) shared;
    bool locked = region->is_locked(source);
    uint64_t version_number = region->get_version_number(source);
    std::memcpy(target, source, size);

    bool cont = !locked && transaction->rv <= version_number;
    if (cont) {
        transaction->read_set.push_back(source);
    }

    return cont;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t unused(shared), tx_t tx, void const *source, size_t size, void *target) noexcept {
    auto *transaction = (transaction_t *) tx;

    assert(!transaction->is_ro);

    void *temp = (void *) malloc(size);
    std::memcpy(temp, source, size);
    transaction->insert_write_chronological_order(target);
    transaction->write_map[target] = {temp, size};

    return true;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
Alloc tm_alloc(shared_t shared, tx_t unused(tx), size_t size, void **target) noexcept {
    // We allocate the dynamic segment such that its words are correctly
    // aligned. Moreover, the alignment of the 'next' and 'prev' pointers must
    // be satisfied. Thus, we use align on max(align, struct segment_node_t*).
    size_t align = ((struct region_t*) shared)->align;
    align = align < sizeof(struct segment_node_t*) ? sizeof(void*) : align;

    struct segment_node_t* sn;
    if (unlikely(posix_memalign((void**)&sn, align, sizeof(struct segment_node_t) + size) != 0)) // Allocation failed
        return Alloc::nomem;

    // Insert in the linked list
    sn->prev = nullptr;
    sn->next = ((struct region_t*) shared)->allocs;
    if (sn->next) sn->next->prev = sn;
    ((struct region_t*) shared)->allocs = sn;

    void *segment = (void*) ((uintptr_t) sn + sizeof(struct segment_node_t));
    std::memset(segment, 0, size);
    *target = segment;

    return Alloc::success;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t unused(shared), tx_t unused(tx), void* unused(target)) noexcept {
    // TODO: tm_free(shared_t, tx_t, void*)
    return false;
}
