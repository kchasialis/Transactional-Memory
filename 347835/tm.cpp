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
#include <cstdlib>

// Internal headers
#include "tm.hpp"
#include "macros.h"
#include "stm_types.hpp"

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

static bool abort(tx_t tx) {
    auto *transaction = (transaction_t *) tx;

    delete transaction;

    return false;
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

    // Acquire locks for write set in order.
    region_t *region = ((region_t *) shared);
    for (auto it = transaction->write_set.begin(); it != transaction->write_set.end(); it++) {
        lock_t *lock = region->get_lock_table_entry(it->first);
        if (!lock->acquire_lock()) {
            // Release (acquired) locks.
            while (it != transaction->write_set.begin()) {
                --it;
                region->get_lock_table_entry(it->first)->release_lock();
            }
            return abort(tx);
        }
    }

    auto wv = region->increment_version_clock() + 1;

    if (wv != transaction->rv + 1) {
        // Validate read set.
        for (const auto& v: transaction->read_set) {
            uint64_t version_number;
            if (!validate_lock_version_number(v.lock, transaction->rv, version_number)) {
                for (auto it = transaction->write_set.begin(); it != transaction->write_set.end(); it++) {
                    lock_t *lock = region->get_lock_table_entry(it->first);
                    lock->release_lock();
                }
                return abort(tx);
            }
        }
    }

    // Write to memory, update version number and release locks.
    for (const auto& v: transaction->write_set) {
        std::memcpy(v.first, v.second, region->align);
        lock_t *lock = region->get_lock_table_entry(v.first);
        lock->set_version_number(wv);
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

    uint64_t version_number;
    for (size_t i = 0; i < size; i += region->align) {
        const void *src = (const char *) source + i;
        void *dst = (char *) target + i;
        lock_t *lock = region->get_lock_table_entry(const_cast<void *>(src));
        if (transaction->is_ro) {         
            if (!validate_lock_version_number(lock, transaction->rv, version_number)) {
                return abort(tx);
            }
            std::memcpy(dst, src, region->align);
            uint64_t post_wv = lock->get_versioned_lock();
            if ((post_wv & 0x1) || (version_number != (post_wv >> 1))) {
                return abort(tx);
            }
        } else {
            auto it = transaction->write_set.find(const_cast<void *>(src));
            if (it != transaction->write_set.end()) {
                std::memcpy(dst, it->second, region->align);
                continue;
            } else {
                if (!validate_lock_version_number(lock, transaction->rv, version_number)) {
                    return abort(tx);
                }
                std::memcpy(dst, src, region->align);
                uint64_t post_wv = lock->get_versioned_lock();
                if ((post_wv & 0x1) || (version_number != (post_wv >> 1))) {
                    return abort(tx);
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

    region_t *region = (region_t *) shared;
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
    region_t *region = (struct region_t*) shared;
    size_t align = region->align;
    align = align < sizeof(struct segment_node_t*) ? sizeof(void*) : align;

    struct segment_node_t* sn;
    if (unlikely(posix_memalign((void**)&sn, align, sizeof(struct segment_node_t) + size) != 0)) // Allocation failed
        return Alloc::nomem;

    
    region->allocs_lock.lock();
    // Insert in the linked list
    sn->prev = nullptr;
    sn->next = region->allocs;
    if (sn->next) sn->next->prev = sn;
    region->allocs = sn;
    region->allocs_lock.unlock();

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
bool tm_free(shared_t unused(shared), tx_t unused(tx), void* unused(segment)) noexcept {
    return true;
}
