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
#include <algorithm>
#include <functional>
#include <vector>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <map>
#include <list>
#include <cassert>
#include <iostream>

// Internal headers
#include "tm.hpp"
#include "macros.h"

constexpr size_t pow2(size_t pow)
{
    return (pow >= sizeof(unsigned int)*8) ? 0 :
        pow == 0 ? 1 : 2 * pow2(pow - 1);
}

constexpr size_t NUM_LOCKS = pow2(20);
constexpr size_t SPINLOCK_TRIES = pow2(6);
constexpr uint32_t VERSION_LOCK_MASK = 0xFFFFFFFE;
constexpr uint64_t HASH_MASK = 0x3FFFFC; 

struct lock_t {
    // std::atomic<uint32_t> versioned_lock;
    std::atomic<uint32_t> version_number;
    std::atomic<bool> lock;

    lock_t() : version_number(0), lock(0) {}
    // lock_t() : versioned_lock(0) {}

    bool acquire_lock() {
        // uint32_t new_versioned_lock = versioned_lock.load() | 0x1;
        // // Bounded spinlock.
        // size_t tries = 0;
        // while (tries < SPINLOCK_TRIES) {
        //     uint32_t old_versioned_lock = versioned_lock.exchange(new_versioned_lock, std::memory_order_acquire);
        //     if (!(old_versioned_lock & 0x1)) {
        //         // Lock acquired.
        //         return true;
        //     }
        //     tries++;
        // }

        // // Lock not acquired.
        // return false;

        // Bounded spinlock.
        size_t tries = 0;
        while (tries < SPINLOCK_TRIES) {
            if (!lock.exchange(true, std::memory_order_acquire)) {
                // Lock acquired.
                return true;
            }
            tries++;
        }

        // Lock not acquired.
        return false;    
    }

    void release_lock() {
        // uint32_t new_versioned_lock = (versioned_lock & VERSION_LOCK_MASK);
        // versioned_lock.store(new_versioned_lock, std::memory_order_release);
        lock.exchange(false, std::memory_order_release);
    }

    bool locked() const {
        // return versioned_lock.load() & 0x1;
        return lock.load();
    }

    uint32_t get_version_number() const {
        // return (versioned_lock.load() & VERSION_LOCK_MASK) >> 1;
        // return versioned_lock.load() >> 1;
        return version_number.load();
    }

    void set_version_number(uint32_t new_version_number) {
        // Shifting the number left causes the lock-bit to be 0 which is what we want in this case.
        // return versioned_lock.store(new_version_number << 1);
        return version_number.store(new_version_number);
    }
};

// struct write_map_value_t {
//     void *value;
//     size_t size;
// };

struct write_set_value_t {
    void *location; // Shared memory location.
    void *value;    // Value to be written.
    lock_t *lock;   // Lock associated with the shared location.

    bool operator==(const write_set_value_t& rhs) {
        return this->location == rhs.location;
    }
    bool operator==(void *rhs) {
        return this->location == rhs;
    }
};

struct write_map_value_t {
    void *value;
    lock_t *lock;
};

struct read_set_value_t {
    const void *location;
    lock_t *lock;
};

struct transaction_t {
    std::map<void *, write_map_value_t> write_set;
    // std::vector<write_set_value_t> write_set;
    std::vector<read_set_value_t> read_set;
    // std::unordered_map<write_map_key_type, write_map_value_type> write_map; // Location -> Value map.
    // std::vector<const void *> read_set;  // Locations read.
    // std::vector<lock_t *> locks;  // Locks acquired.
    bool is_ro;  // Is read-only.
    uint64_t rv;  // Read version number.

    // void insert_write_chronological_order(void *addr) {
    //     // We want to avoid expensive list lookup for every tm_write.
    //     // Quickly search the map to see if it is indeed already there.
    //     // auto it = write_map.find(addr);
    //     // if (likely(it == write_map.end())) {
    //     //     // Common case, not duplicate.
    //     //     write_set.push_back(addr);
    //     //     return;
    //     // }

    //     // Uncommon case.
    //     // write_set.remove(addr);
    //     write_set.push_back(addr);
    // }
    
    // void release_acquired_locks(size_t stop) {
    //     // for (size_t i = 0; i < stop; i++) {
    //     //     write_set[i].lock->release_lock();
    //     // }
    //     // for (auto& v : write_set) {
    //     //     v.lock->release_lock();
    //     // }
    // }

    void release_acquired_locks() {
        for (auto it = write_set.begin(); it != write_set.end(); it++) {
            if (it->second.lock != nullptr) {
                it->second.lock->release_lock();
            }
        }
    }
};

struct segment_node_t {
    struct segment_node_t* prev;
    struct segment_node_t* next;
};
typedef struct segment_node_t* segment_list;

struct region_t {
    std::atomic<uint32_t> version_clock;
    lock_t lock_table[NUM_LOCKS];
    void *start;
    size_t size;
    size_t align;
    segment_list allocs;

    uint32_t get_version_clock() const {
        return version_clock.load();
    }

    uint32_t increment_version_clock() {
        // return version_clock.fetch_add(2);
        return version_clock.fetch_add(1) + 1;
        // return version_clock.fetch_add(2);
    }

    lock_t *get_lock_table_entry(const void *location) {
        // std::hash<const void*> hash;
        // return &(lock_table[(uintptr_t) hash(location) % NUM_LOCKS]);
        return lock_table + ((uintptr_t) location & HASH_MASK);
    }
};

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) noexcept {
    // std::cerr << "CHECKPOINT" << __LINE__ << std::endl;

    auto *region = new (std::nothrow) region_t;
    void *start;

    if (unlikely(region == nullptr)) {
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
    region->start = start;
    region->size = size;
    region->align = align;
    region->allocs = nullptr;

    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared) noexcept {
    region_t *region = (region_t *) shared;
    while (region->allocs) { // Free allocated segments
        segment_list tail = region->allocs->next;
        free(region->allocs);
        region->allocs = tail;
    }
    free(region->start);
    delete region;
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

    // std::cerr << "CHECKPOINT" << __LINE__ << std::endl;
    return (tx_t) transaction;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) noexcept {
    transaction_t *transaction = (transaction_t *) tx;

    if (transaction->is_ro || transaction->write_set.empty()) {
        return true;
    }

    region_t *region = ((region_t *) shared);
    // Acquire locks for write_set.
    // for (size_t i = 0; i < transaction->write_set.size(); i++) {
    //     if (!transaction->write_set[i].lock->acquire_lock()) {
    //         std::cerr << "Aborting" << __LINE__ << std::endl;
    //         transaction->release_acquired_locks(i);
    //         return false;
    //     }
    // }
    for (auto it = transaction->write_set.begin(); it != transaction->write_set.end(); it++) {
        lock_t *lock = region->get_lock_table_entry(it->first);
        if (!lock->acquire_lock()) {
            // std::cerr << "Aborting" << __LINE__ << std::endl;
            transaction->release_acquired_locks();
            return false;
        }
        it->second.lock = lock;
    }

    auto wv = region->increment_version_clock();

    // Validate read set.
    if (wv != transaction->rv + 1) {
        for (const auto& v: transaction->read_set) {
            auto wl = v.lock->get_version_number();
            if (v.lock->locked() || wl > transaction->rv) {
                // std::cerr << "Aborting" << __LINE__ << std::endl;
                // transaction->release_acquired_locks(transaction->write_set.size());
                transaction->release_acquired_locks();
                return false;
            }
        }
    }

    // Commit writes and release locks.
    // for (const auto& v: transaction->write_set) {
    //     std::memcpy(v.location, v.value, region->align);
    //     v.lock->set_version_number(wv);
    // }
    for (const auto& v: transaction->write_set) {
        std::memcpy(v.first, v.second.value, region->align);
        v.second.lock->set_version_number(wv);
        v.second.lock->release_lock();
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

    region_t *region = (region_t *) shared;
    for (size_t i = 0; i < size; i += region->align) {
        const void *src = (const char *) source + i;
        void *dst = (char *) target + i;
        lock_t *lock = region->get_lock_table_entry(src);
        if (transaction->is_ro) {
            std::memcpy(dst, src, region->align);
        } else {
            // auto it = std::find(transaction->write_set.begin(), transaction->write_set.end(), const_cast<void *>(src));
            auto it = transaction->write_set.find(const_cast<void *>(src));
            if (it != transaction->write_set.end()) {
                std::memcpy(dst, it->second.value, region->align);
            } else {
                transaction->read_set.push_back({src, lock});
                std::memcpy(dst, src, region->align);
            }
            // transaction->read_set.push_back({src, lock});
        }

        bool locked = lock->locked();
        uint32_t version_number = lock->get_version_number();

        bool stop = locked || version_number > transaction->rv;
        if (stop) {
            return false;
        }
    }

    return true;    
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared, tx_t tx, void const *source, size_t size, void *target) noexcept {
    auto *transaction = (transaction_t *) tx;

    assert(!transaction->is_ro);

    region_t *region = (region_t *) shared;
    for (size_t i = 0; i < size; i += region->align) {
        const void *src = (const char *) source + i;
        void *dst = (char *) target + i;
        void *temp = (void *) malloc(region->align);
        std::memcpy(temp, src, region->align);
        transaction->write_set[dst] = {temp, nullptr};

        // auto it = std::find(transaction->write_set.begin(), transaction->write_set.end(), const_cast<void *>(dst));
        // if (it != transaction->write_set.end()) {
        //     transaction->write_set.erase(it);
        // }
        // transaction->write_set.push_back({dst, temp, region->get_lock_table_entry(dst)});
    }

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
bool tm_free(shared_t shared, tx_t unused(tx), void* segment) noexcept {
    // struct segment_node_t* sn = (struct segment_node_t*) ((uintptr_t) segment - sizeof(segment_node_t));

    // // Remove from the linked list
    // if (sn->prev) sn->prev->next = sn->next;
    // else ((struct region_t*) shared)->allocs = sn->next;
    // if (sn->next) sn->next->prev = sn->prev;

    // free(sn);
    return true;
}