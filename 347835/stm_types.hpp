#pragma once

#include <atomic>
#include <algorithm>
#include <map>
#include <vector>
#include <cstring>

struct shared_lock_t {
    using Mutex = ::std::atomic<bool>;
    Mutex mutex;

    shared_lock_t(bool m) : mutex(m) {}

    void lock() {
        bool expected = false;
        while (!mutex.compare_exchange_weak(expected, true, ::std::memory_order_acquire, ::std::memory_order_relaxed)) {
            expected = false;
            while (mutex.load(::std::memory_order_relaxed));
        }
    }

    void unlock() {
        mutex.store(false, ::std::memory_order_release);
    }    
};

struct lock_t {
    std::atomic<uint64_t> versioned_lock;

    lock_t() : versioned_lock(0) {}

    bool acquire_lock() {
        uint64_t vl = versioned_lock.load();
        if (vl & 0x1) {
            return false;
        }

        return versioned_lock.compare_exchange_strong(vl, vl | 0x1);
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


constexpr size_t pow2(size_t pow)
{
    return (pow >= sizeof(unsigned int)*8) ? 0 :
        pow == 0 ? 1 : 2 * pow2(pow - 1);
}

constexpr size_t NUM_LOCKS = pow2(22);

struct read_set_value_t {
    const void *location;
    lock_t *lock;

    bool operator==(void *loc) {
        return this->location == loc;
    }
};

struct transaction_t {
    using write_map_value_t = uint64_t;
    std::map<void *, write_map_value_t> write_set; // Write set, ordered by smaller memory locations.
    std::vector<read_set_value_t> read_set;
    bool is_ro;
    uint64_t rv;  // Read version number.

    // ~transaction_t() {
    //     // Free malloc'd values in the write_set.
    //     for (const auto& v: write_set) {
    //         free(v.second);
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
    lock_t lock_table[NUM_LOCKS];
    size_t size;
    size_t align;
    void *start;
    shared_lock_t allocs_lock;
    segment_list allocs;

    region_t(size_t sz, size_t alg, void *st) : version_clock(0), size(sz), 
        align(alg), start(st), allocs_lock(false), allocs(nullptr) {

        std::memset(start, 0, size);
    }

    uint64_t get_version_clock() const {
        return version_clock.load();
    }

    uint64_t increment_version_clock() {
        return version_clock.fetch_add(1);
    }

    lock_t *get_lock_table_entry(void *location) {
        std::hash<const void*> hash;
        return &lock_table[hash(location) % NUM_LOCKS];
    }
};