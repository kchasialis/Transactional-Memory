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
#include <set>
#include <unordered_map>

// Internal headers
#include "tm.hpp"
#include "macros.h"

// constexpr size_t pow2(size_t pow)
// {
//     return (pow >= sizeof(unsigned int)*8) ? 0 :
//         pow == 0 ? 1 : 2 * pow2(pow - 1);
// }

// constexpr size_t NUM_LOCKS = pow2(20);
// constexpr size_t SPINLOCK_TRIES = 10;
// constexpr uint64_t HASH_MASK = 0x3FFFFC; 

struct lock_t {
    std::atomic<uint64_t> versioned_lock;
    // std::atomic<uint32_t> version_number;
    // std::atomic<bool> lock;

    // lock_t() : version_number(0), lock(0) {}
    lock_t() : versioned_lock(0) {}

    bool acquire_lock() {
        uint64_t vl = versioned_lock.load();
        if (vl & 0x1) {
            return false;
        }

        return versioned_lock.compare_exchange_strong(vl, vl | 0x1);
        // size_t tries = 0;
        // while (tries < SPINLOCK_TRIES) {
        //     if (versioned_lock.compare_exchange_strong(vl, vl | 0x1)) {
        //         return true;
        //     }
        //     tries++;
        // }

        // return false;
        // uint64_t expected = versioned_lock.load();
        // uint64_t desired = expected | 0x1;  // Desire it to be locked.
        // // Bounded spinlock.
        // size_t tries = 0;
        // while (tries < SPINLOCK_TRIES) {
        //     if (versioned_lock.compare_exchange_strong(expected, desired)) {
        //         // Lock acquired.
        //         return true;
        //     }
        //     tries++;
        // }

        // Lock not acquired.
        // return false;
    }

    uint64_t get_versioned_lock() {
        return versioned_lock.load();
    }

    void release_lock() {
        versioned_lock.fetch_sub(1);
    }

    void set_version_number(uint64_t new_version_number) {
        // Shifting the number left causes the lock-bit to be 0 which is what we want in this case.
        return versioned_lock.store(new_version_number << 1);
    }
};

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
    const void *value;
};

struct read_set_value_t {
    const void *location;
    lock_t *lock;

    bool operator==(void *loc) {
        return this->location == loc;
    }
};

struct transaction_t {
    std::map<void *, write_map_value_t> write_set;
    std::vector<read_set_value_t> read_set;
    bool is_ro;  // Is read-only.
    uint64_t rv;  // Read version number.

    // void release_acquired_locks() {
    //     for (auto it = write_set.begin(); it != write_set.end(); it++) {
    //         if (it->second.lock != nullptr) {
    //             it->second.lock->release_lock();
    //         }
    //     }
    // }
};

struct segment_node_t {
    struct segment_node_t* prev;
    struct segment_node_t* next;
};
typedef struct segment_node_t* segment_list;

struct region_t {
    std::atomic<uint64_t> version_clock;
    std::unordered_map<void *, lock_t *> lock_map;
    // lock_t lock_table[NUM_LOCKS];
    size_t size;
    size_t align;
    void *start;
    segment_list allocs;

    region_t(size_t sz, size_t alg, void *st) : version_clock(0), size(sz), 
        align(alg), start(st), allocs(nullptr) {

        std::memset(start, 0, size);
        for (size_t i = 0; i < size; i += align) {
            set_lock_table_entry((char *) start + i);
        }
    }

    uint64_t get_version_clock() const {
        return version_clock.load();
    }

    uint64_t increment_version_clock() {
        return version_clock.fetch_add(1);
    }

    void set_start(void *st) {
        start = st;
    }

    void set_lock_table_entry(void *location) {
        lock_map[location] = new lock_t;
    }

    lock_t *get_lock_table_entry(void *location) {
        //  try {
        //     return lock_map.at(location);
        // }
        // catch (const std::out_of_range& oor) {
        //     std::cerr << "Out of Range error: " << oor.what() << '\n';
        // }
        return lock_map[location];
    }
};

// Returns true if the lock not locked and lock's version number is <= rv.
// Stores the lock's version number in version_number. 
static bool validate_lock_version_number(lock_t *lock, uint64_t rv, uint64_t& version_number) {
    uint64_t versioned_lock = lock->get_versioned_lock();
    // Locked?
    if (versioned_lock & 0x1) {
        return false;
    }
    // Version number > rv?
    version_number = versioned_lock >> 1;
    if (version_number > rv) {
        return false;
    }

    return true;
}

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) noexcept {
    void *start;
    
    // We allocate the shared memory buffer such that its words are correctly
    // aligned.
    if (posix_memalign(&start, align, size) != 0) {
        return invalid_shared;
    }

    auto *region = new (std::nothrow) region_t(size, align, start);
    if (unlikely(region == nullptr)) {
        free(start);
        return invalid_shared;
    }

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
    for (auto it = transaction->write_set.begin(); it != transaction->write_set.end(); it++) {
        lock_t *lock = region->get_lock_table_entry(it->first);
        if (!lock->acquire_lock()) {
            
            // Release acquired locks.
            while (it != transaction->write_set.begin()) {
                --it;
                region->get_lock_table_entry(it->first)->release_lock();
            }
            // std::cerr << "Aborting" << __LINE__ << std::endl;
            // transaction->release_acquired_locks();
            return false;
        }
    }

    auto wv = region->increment_version_clock() + 1;

    // Validate read set.
    if (wv != transaction->rv + 1) {
        for (const auto& v: transaction->read_set) {
            uint64_t version_number;
            if (!validate_lock_version_number(v.lock, transaction->rv, version_number)) {

                for (auto it = transaction->write_set.begin(); it != transaction->write_set.end(); it++) {
                    lock_t *lock = region->get_lock_table_entry(it->first);
                    lock->release_lock();
                }

                // transaction->release_acquired_locks();
                // std::cerr << "Aborting" << __LINE__ << std::endl;
                return false;
            }
            // auto wl = v.lock->get_version_number();
            // if (v.lock->locked() || wl > transaction->rv) {
            //     // std::cerr << "Aborting" << __LINE__ << std::endl;
            //     // transaction->release_acquired_locks(transaction->write_set.size());
            //     transaction->release_acquired_locks();
            //     return false;
            // }
        }
    }

    // Commit writes and release locks.
    // for (const auto& v: transaction->write_set) {
    //     std::memcpy(v.location, v.value, region->align);
    //     v.lock->set_version_number(wv);
    // }
    for (const auto& v: transaction->write_set) {
        std::memcpy(v.first, v.second.value, region->align);
        lock_t *lock = region->get_lock_table_entry(v.first);
        lock->set_version_number(wv);
        // v.second.lock->set_version_number(wv);
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
    assert(size % region->align == 0);

    uint64_t version_number;
    for (size_t i = 0; i < size; i += region->align) {
        const void *src = (const char *) source + i;
        void *dst = (char *) target + i;
        lock_t *lock = region->get_lock_table_entry(const_cast<void *>(src));
        if (transaction->is_ro) {         
            if (!validate_lock_version_number(lock, transaction->rv, version_number)) {
                return false;
            }
            std::memcpy(dst, src, region->align);
            uint64_t post_wv = lock->get_versioned_lock();
            if ((post_wv & 0x1) || (version_number != (post_wv >> 1))) {
                return false;
            }
        } else {
            auto it = transaction->write_set.find(const_cast<void *>(src));
            if (it != transaction->write_set.end()) {
                std::memcpy(dst, it->second.value, region->align);
                continue;
            } else {
                if (!validate_lock_version_number(lock, transaction->rv, version_number)) {
                    return false;
                }
                std::memcpy(dst, src, region->align);
                uint64_t post_wv = lock->get_versioned_lock();
                if ((post_wv & 0x1) || (version_number != (post_wv >> 1))) {
                    return false;
                }
            }

            transaction->read_set.push_back({src, lock});
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
    assert(size % region->align == 0);
    for (size_t i = 0; i < size; i += region->align) {
        const void *src = (const char *) source + i;
        void *dst = (char *) target + i;
        void *temp = (void *) malloc(region->align);
        std::memcpy(temp, src, region->align);
        transaction->write_set[dst] = {temp};
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
    region_t *region = (struct region_t *) shared;
    sn->prev = nullptr;
    sn->next = ((struct region_t*) shared)->allocs;
    if (sn->next) sn->next->prev = sn;
    region->allocs = sn;

    void *segment = (void*) ((uintptr_t) sn + sizeof(struct segment_node_t));
    std::memset(segment, 0, size);
    *target = segment;

    for (size_t i = 0; i < size; i += region->align) {
        region->set_lock_table_entry((char *) segment + i);
    }

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
