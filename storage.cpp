#include <boost/atomic/atomic.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/anonymous_shared_memory.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/managed_external_buffer.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include <boost/interprocess/containers/flat_map.hpp>
#include <boost/interprocess/containers/list.hpp>
#include <boost/interprocess/containers/map.hpp>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/ranked_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index_container.hpp>

#include <boost/archive/text_oarchive.hpp>

#include <boost/variant.hpp>

#include <boost/interprocess/smart_ptr/unique_ptr.hpp>

#include <boost/interprocess/sync/interprocess_sharable_mutex.hpp>
#include <boost/interprocess/sync/sharable_lock.hpp>

#include <boost/functional/hash.hpp>
#include <boost/optional.hpp>
#include <boost/unordered_map.hpp>
#include <functional>

//#include <boost/interprocess/smart_ptr/unique_ptr.hpp>

#include <atomic>
#include <iostream>
#include <memory>
#include <string>

#include <stdio.h>
#include <time.h>

extern "C" {
#include "SAPI.h"
#include "ext/standard/php_var.h"
#include "php.h"
#include "zend_smart_str.h"
}

#include "storage.hpp"

namespace b   = ::boost;
namespace bip = b::interprocess;
namespace bmi = b::multi_index;
namespace ba  = b::archive;

// Initial shared memory
typedef bip::managed_external_buffer memory_t;
// typedef bip::managed_shared_memory memory_t;
typedef memory_t::segment_manager segment_manager_t;

// A general-purpose allocator.
typedef bip::allocator<void, segment_manager_t> void_allocator_t;

// Shared memory strings
typedef bip::allocator<char, segment_manager_t> string_allocator_t;
typedef bip::basic_string<char, std::char_traits<char>, string_allocator_t> string_t;

// A cache entry and its components
typedef string_t address_t;
typedef string_t serialized_t;
typedef b::variant<b::blank, serialized_t, long, double> value_t;
struct cache_entry {
    address_t address;
    value_t data;

    time_t expiration = 0;
    time_t last_used  = 0;

    cache_entry(const char* address_, const size_t address_len, const void_allocator_t& a)
        : address(address_, address_len, a)
    {
    }

    bool
    operator<(const cache_entry& e) const
    {
        return address < e.address;
    }

    bool
    operator<(const address_t& a) const
    {
        return address < a;
    }
};
typedef bip::allocator<cache_entry, segment_manager_t> cache_entry_allocator_t;

// Use MultiIndex for the cache
struct entry_address {
};
struct entry_expiration {
};
struct entry_last_used {
};

typedef b::multi_index_container<
  cache_entry,
  bmi::indexed_by<
    // bmi::ordered_unique<bmi::tag<entry_address>, bmi::identity<cache_entry> >,
    bmi::ordered_unique<bmi::tag<entry_address>, bmi::member<cache_entry, address_t, &cache_entry::address>>,
    bmi::ordered_non_unique<bmi::tag<entry_expiration>, bmi::member<cache_entry, time_t, &cache_entry::expiration>>,
    bmi::ranked_non_unique<bmi::tag<entry_last_used>, bmi::member<cache_entry, time_t, &cache_entry::last_used>>>,
  cache_entry_allocator_t>
  lru_cache_t;

typedef lru_cache_t::index<entry_address>::type lru_cache_by_address_t;
typedef lru_cache_t::index<entry_expiration>::type lru_cache_by_expiration_t;
typedef lru_cache_t::index<entry_last_used>::type lru_cache_by_last_used_t;

class zval_visitor : public boost::static_visitor<>
{
  public:
    void
    operator()(const b::blank& data, zval* dst) const
    {
        ZVAL_NULL(dst);
    }

    void
    operator()(const long& l, zval* dst) const
    {
        ZVAL_LONG(dst, l);
    }

    void
    operator()(const double& l, zval* dst) const
    {
        ZVAL_DOUBLE(dst, l);
    }

    void
    operator()(const serialized_t& ser, zval* dst) const
    {
        const unsigned char* tmp = (unsigned char*) ser.c_str();
        php_unserialize_data_t var_hash;
        PHP_VAR_UNSERIALIZE_INIT(var_hash);
        if (!php_var_unserialize(dst, &tmp, (unsigned char*) ser.c_str() + ser.size(), &var_hash)) {
            PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
            // @TODO: Convert to exception or err string?
            php_error_docref(NULL, E_WARNING, "Error unserializing at offset %ld of %ld bytes",
                             (zend_long)(tmp - (unsigned char*) ser.c_str()), (zend_long) ser.size());
            ZVAL_FALSE(dst);
        }
        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
    }
};

class cost_visitor : public boost::static_visitor<size_t>
{
  public:
    size_t
    operator()(const b::blank& data) const
    {
        return 0;
    }

    size_t
    operator()(const serialized_t& ser) const
    {
        return ser.size();
    }

    template <typename T>
    size_t
    operator()(const T& operand) const
    {
        return sizeof(T);
    }
};

class increment_visitor : public boost::static_visitor<b::optional<value_t>>
{
  public:
    b::optional<value_t>
    operator()(const long& i, long step) const
    {
        zval zstep;
        zval zcurrent;
        value_t ret;

        // php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Converting to ZVAL_LONG");

        ZVAL_LONG(&zcurrent, i);
        ZVAL_LONG(&zstep, step);

        // php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Adding");
        fast_long_add_function(&zcurrent, &zcurrent, &zstep);

        // php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Converting back to variant");
        if (Z_TYPE(zcurrent) == IS_LONG) {
            ret = Z_LVAL(zcurrent);
            return ret;
        } else if (Z_TYPE(zcurrent) == IS_DOUBLE) {
            ret = Z_DVAL(zcurrent);
            return ret;
        }

        return b::none;
    }

    // template <typename T>
    // b::optional<value_t> operator()(const T & operand, long step ) const
    //{
    //   return b::none;
    //}

    b::optional<value_t>
    operator()(const b::blank& b, long step) const
    {
        return b::none;
    }

    b::optional<value_t>
    operator()(const serialized_t& ser, long step) const
    {
        return b::none;
    }
};

struct set_entry_value {
    set_entry_value(value_t value)
        : val(value)
    {
    }

    void
    operator()(cache_entry& e)
    {
        e.data = val;
    }

  private:
    value_t val;
};

class cas_match_visitor : public boost::static_visitor<bool>
{
  public:
    bool
    operator()(const long& i, long expected) const
    {
        return (i == expected);
    }

    template <typename T>
    bool
    operator()(const T& operand, long expected) const
    {
        return false;
    }
};

class uc_storage
{
  protected:
    size_t m_capacity;
    boost::atomic<size_t> m_used;
    bip::mapped_region m_region;
    memory_t m_segment;
    void_allocator_t m_allocator;
    std::unique_ptr<lru_cache_t> m_cache;
    bip::interprocess_sharable_mutex m_cache_mutex;

    // === No Locking ===

    size_t
    get_cost(const cache_entry& entry)
    {
        return b::apply_visitor(cost_visitor(), entry.data);
    }

    // === Shared Locking ===

    b::optional<lru_cache_by_address_t::iterator>
    get_iterator(const char* address, const size_t address_len)
    {
        struct sized_c_str {
            const char* address;
            const size_t address_len;

            sized_c_str(const char* address_, const size_t address_len_)
                : address(address_)
                , address_len(address_len_)
            {
            }
        };

        struct compare_addresses {
            bool
            operator()(const sized_c_str& s0, const address_t& s1) const
            {
                return std::memcmp(s0.address, s1.c_str(), std::min(s0.address_len, s1.size())) < 0;
            }

            bool
            operator()(const address_t& s0, const sized_c_str& s1) const
            {
                return std::memcmp(s0.c_str(), s1.address, std::min(s0.size(), s1.address_len)) < 0;
            }
        };

        sized_c_str lookup_addr(address, address_len);
        bip::sharable_lock<bip::interprocess_sharable_mutex> lock(m_cache_mutex);
        lru_cache_by_address_t::iterator it = m_cache->get<entry_address>().find(lookup_addr, compare_addresses());

        // Compare here so it's not necessary for the caller to lock to see
        // if the result of the lookup is "not found."
        if (m_cache->end() == it) {
            return b::none;
        }

        // @TODO: Technically, we should use a wrapper to ensure locking on
        // iterator dereference, but it's also known to be safe:
        // "Strictly speaking, iterator dereference should also be
        // lockguarded, although I can say unofficially that unguarded
        // dereference is OK." --Joaquín M López Muñoz
        return it;
    }

    bool
    needs_bump(const lru_cache_t::iterator& it)
    {
        bip::sharable_lock<bip::interprocess_sharable_mutex> lock(m_cache_mutex);

        const lru_cache_t::size_type rank  = m_cache->get<entry_last_used>().find_rank(it->last_used);
        const lru_cache_t::size_type count = m_cache->get<entry_last_used>().size();

        // If the entry is in oldest 25% used.
        return (rank < (count * 0.25));
    }

    // === Exclusive Locking ==

    bool
    bump(const lru_cache_t::iterator& it)
    {
        struct bump_cache_entry_last_used {
            bump_cache_entry_last_used(time_t last_used)
                : new_last_used(last_used)
            {
            }

            void
            operator()(cache_entry& e)
            {
                e.last_used = new_last_used;
            }

          private:
            time_t new_last_used;
        };

        bip::scoped_lock<bip::interprocess_sharable_mutex> lock(m_cache_mutex);
        return m_cache->modify(it, bump_cache_entry_last_used(time(0)));
    }

    // === Exclusive Lock Already Held ==

    bool
    free_space(const bip::scoped_lock<bip::interprocess_sharable_mutex>& lock, size_t space_needed)
    {
        assert(lock.owns());

        // If we have enough space, it's a trivial success.
        if (space_needed <= m_capacity - m_used) {
            return true;
        }

        // If the entry is too large to fit the cache, do nothing and fail.
        // @TODO: Also reject items that are move than N% of the cache size?
        if (space_needed > m_capacity) {
            return false;
        }

        // First, evict everything that can expire and is expired, up to the space needed.
        time_t now = time(0);
        lru_cache_by_expiration_t::iterator it_l =
          m_cache->get<entry_expiration>().lower_bound(1); // Exclude non-expiring items.
        lru_cache_by_expiration_t::iterator it_u = m_cache->get<entry_expiration>().upper_bound(now);
        for (auto i = it_l; i != it_u; ++i) {
            m_used -= get_cost(*i);
            m_cache->get<entry_expiration>().erase(i);
        }

        // See if we have enough space yet.
        if (m_capacity - m_used >= space_needed) {
            return true;
        }

        // If we still need more space, evict the least recently used items.
        for (auto i = m_cache->get<entry_last_used>().begin(); i != m_cache->get<entry_last_used>().end(); ++i) {
            m_used -= get_cost(*i);
            m_cache->get<entry_last_used>().erase(i);

            // Stop evicting once we have enough space.
            if (m_capacity - m_used >= space_needed) {
                return true;
            }
        }

        // We shouldn't ever reach this point because we've emptied the
        // entire cache, but the item is too big.
        return false;
    }

    // === Indirect Locking (in Called Functions) ===

    // Returns true if the entry has (or has been made to have) an
    // appropriate last_used rank.
    bool
    bump_if_necessary(const lru_cache_t::iterator& it)
    {
        const bool needs_a_bump = needs_bump(it);
        if (needs_a_bump) {
            return bump(it);
        }
        return true;
    }

  public:
    uc_storage(size_t capacity)
        : m_cache_mutex()
        , m_capacity(capacity)
        , m_region(bip::anonymous_shared_memory(capacity * 2))
        , m_segment(bip::create_only, m_region.get_address(), m_region.get_size())
        , m_allocator(m_segment.get_segment_manager())
        , m_used(0)
        , m_cache(m_segment.construct<lru_cache_t>(bip::anonymous_instance)(lru_cache_t::ctor_args_list(), m_allocator))
    {
    }

    ~uc_storage()
    {
    }
    // === No Locking ===

    size_t
    capacity() const
    {
        return m_capacity;
    }

    // === Exclusive Locking ===

    void
    clear()
    {
        bip::scoped_lock<bip::interprocess_sharable_mutex> lock(m_cache_mutex);
        m_cache->clear();
    }

    bool
    store(cache_entry&& e, bool exclusive = false)
    {
        bip::scoped_lock<bip::interprocess_sharable_mutex> lock(m_cache_mutex);

        bool success = free_space(lock, get_cost(e));
        if (!success) {
            return false;
        }

        // Attempt to insert. This will fail if the entry already exists.
        std::pair<lru_cache_by_address_t::iterator, bool> res = m_cache->get<entry_address>().insert(std::move(e));

        // std::pair<lru_cache_by_address_t::iterator,bool> res = m_cache->get<entry_address>().emplace(addr, addr_len,
        // val, val_size, expiration, m_allocator);

        // Replace on collision, using the matching entry as the position.
        if (!exclusive && !res.second) {
            res.second = m_cache->get<entry_address>().replace(res.first, std::move(e));
        }

        return res.second;
    }

    b::optional<value_t>
    increment(lru_cache_by_address_t::iterator& it, long step)
    {
        auto bound_visitor    = std::bind(increment_visitor(), std::placeholders::_1, step);
        auto next_value_maybe = b::apply_visitor(bound_visitor, it->data);

        // If there is no current, eligible value, we cannot increment.
        if (b::none == next_value_maybe) {
            return b::none;
        }

        value_t next_value = *next_value_maybe;

        // Apply the increment.
        bump_if_necessary(it);
        bip::scoped_lock<bip::interprocess_sharable_mutex> lock(m_cache_mutex);

        m_cache->modify(it, set_entry_value(next_value));
        return next_value;
    }

    bool
    del(const char* addr, const size_t addr_len)
    {
        auto it_optional = get_iterator(addr, addr_len);
        if (b::none == it_optional) {
            return false;
        }

        // Only grab an exclusive lock if we actually need to erase it.
        bip::scoped_lock<bip::interprocess_sharable_mutex> lock(m_cache_mutex);
        m_cache->get<entry_address>().erase(*it_optional);
        return true;
    }

    // === Shared Locking ===

    bool
    empty()
    {
        bip::sharable_lock<bip::interprocess_sharable_mutex> lock(m_cache_mutex);
        return m_cache->empty();
    }

    size_t
    size()
    {
        bip::sharable_lock<bip::interprocess_sharable_mutex> lock(m_cache_mutex);
        return m_cache->size();
    }

    void
    dump()
    {
        bip::sharable_lock<bip::interprocess_sharable_mutex> lock(m_cache_mutex);

        for (auto i = m_cache->begin(); i != m_cache->end(); ++i) {
            std::cout << i->address << "=" << i->data << std::endl;
            // std::string k(i->address.begin(), i->address.end());
            // std::string v(i->serialized.begin(), i->serialized.end());
        }
    }

    // === Indirect Locking (in Called Functions) ===

    bool
    contains(const char* address, const size_t address_len)
    {
        return b::none != get_iterator(address, address_len);
    }

    bool
    get(const char* addr, const size_t addr_len, zval* dst)
    {
        auto it_optional = get_iterator(addr, addr_len);

        if (b::none == it_optional) {
            ZVAL_FALSE(dst);
            return false;
        }

        bump_if_necessary(*it_optional);

        auto bound_visitor = std::bind(zval_visitor(), std::placeholders::_1, dst);
        b::apply_visitor(bound_visitor, (*it_optional)->data);
        return true;
    }

    bool
    store(const char* addr,
          const size_t addr_len,
          const char* val,
          const size_t val_size,
          const time_t expiration = 0,
          bool exclusive          = false)
    {
        cache_entry entry(addr, addr_len, m_allocator);
        serialized_t s(val, val_size, m_allocator);
        entry.data       = std::move(s);
        entry.expiration = expiration;
        return store(std::move(entry), exclusive);
    }

    bool
    store(const char* addr, const size_t addr_len, const long val, const time_t expiration = 0, bool exclusive = false)
    {
        cache_entry entry(addr, addr_len, m_allocator);
        entry.data       = val;
        entry.expiration = expiration;
        return store(std::move(entry), exclusive);
    }

    bool
    increment_or_initialize(const char* addr, const size_t addr_len, long step, zval* dst)
    {
        auto it_optional = get_iterator(addr, addr_len);
        b::optional<value_t> next_value;

        // If there's no value yet, initialize it to the step value.
        if (b::none == it_optional) {
            next_value = step;
            if (!store(addr, addr_len, step)) {
                return false;
            }
        } else {
            next_value = increment(*it_optional, step);
            if (b::none == next_value) {
                return false;
            }
        }

        // Convert to a zval
        auto bound_visitor = std::bind(zval_visitor(), std::placeholders::_1, dst);
        b::apply_visitor(bound_visitor, *next_value);
        return true;
    }

    bool
    cas(const char* addr, const size_t addr_len, long next, long expected)
    {
        auto it_optional = get_iterator(addr, addr_len);

        // If there's no value there, succeed without comparison.
        if (b::none == it_optional) {
            return store(addr, addr_len, next);
        }

        // If the value doesn't match what's expected (or is the wrong type), fail.
        auto bound_visitor = std::bind(cas_match_visitor(), std::placeholders::_1, expected);
        if (!b::apply_visitor(bound_visitor, (*it_optional)->data)) {
            return false;
        }

        // Store the new value.
        return store(addr, addr_len, next);
    }
};

extern "C" {

uc_storage_t
uc_storage_init(size_t size, char** errptr)
{
    *errptr = NULL;

    try {
        uc_storage* storage_inst = new uc_storage(size);
        return storage_inst;
    } catch (bip::interprocess_exception& ex) {
        asprintf(errptr, "Error while initializing interprocess storage: %s", ex.what());
    }
    return 0;
}

size_t
uc_storage_size(uc_storage_t st_opaque, char** errptr)
{
    uc_storage* st = static_cast<uc_storage*>(st_opaque);
    *errptr        = NULL;
    return st->size();
}

int
uc_storage_increment(
  uc_storage_t st_opaque, const char* address, size_t address_len, long step, zval** dst, char** errptr)
{
    uc_storage* st = static_cast<uc_storage*>(st_opaque);
    *errptr        = NULL;
    return st->increment_or_initialize(address, address_len, step, *dst);
}

int
uc_storage_cas(uc_storage_t st_opaque, const char* address, size_t address_len, long next, long expected, char** errptr)
{
    uc_storage* st = static_cast<uc_storage*>(st_opaque);
    *errptr        = NULL;
    return st->cas(address, address_len, next, expected);
}

int
uc_storage_store(uc_storage_t st_opaque,
                 const char* address,
                 size_t address_len,
                 const char* data,
                 size_t data_size,
                 time_t expiration,
                 int exclusive,
                 char** errptr)
{
    uc_storage* st = static_cast<uc_storage*>(st_opaque);
    *errptr        = NULL;
    return st->store(address, address_len, data, data_size, expiration, exclusive);
}

int
uc_storage_store_long(uc_storage_t st_opaque,
                      const char* address,
                      size_t address_len,
                      const long data,
                      time_t expiration,
                      int exclusive,
                      char** errptr)
{
    uc_storage* st = static_cast<uc_storage*>(st_opaque);
    *errptr        = NULL;
    bool success;
    success = st->store(address, address_len, data, expiration, exclusive);
    return success;
}

int
uc_storage_get(uc_storage_t st_opaque, const char* address, size_t address_len, zval** dst, char** errptr)
{
    uc_storage* st = static_cast<uc_storage*>(st_opaque);
    *errptr        = NULL;
    bool success   = st->get(address, address_len, *dst);
    return success;
}

int
uc_storage_exists(uc_storage_t st_opaque, const char* address, size_t address_len, char** errptr)
{
    uc_storage* st = static_cast<uc_storage*>(st_opaque);
    *errptr        = NULL;
    return st->contains(address, address_len);
}

int
uc_storage_delete(uc_storage_t st_opaque, const char* address, size_t address_len, char** errptr)
{
    uc_storage* st = static_cast<uc_storage*>(st_opaque);
    *errptr        = NULL;
    return st->del(address, address_len);
}

void
uc_storage_clear(uc_storage_t st_opaque, char** errptr)
{
    uc_storage* st = static_cast<uc_storage*>(st_opaque);
    *errptr        = NULL;
    st->clear();
}

void
uc_storage_dump(uc_storage_t st_opaque, char** errptr)
{
    uc_storage* st = static_cast<uc_storage*>(st_opaque);
    *errptr        = NULL;
    st->dump();
}

void
uc_string_free(char* strptr)
{
    free(strptr);
}

} // extern "C"
