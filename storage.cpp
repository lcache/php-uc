#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/containers/string.hpp>

#include <boost/interprocess/sync/interprocess_upgradable_mutex.hpp>
#include <boost/interprocess/sync/sharable_lock.hpp>
#include <boost/interprocess/sync/upgradable_lock.hpp>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread/thread_time.hpp>

#include <boost/optional.hpp>
#include <boost/variant.hpp>

// "Safe mode" enables internal locks that break in interprocess memory.
//#define BOOST_MULTI_INDEX_ENABLE_SAFE_MODE
//#define BOOST_MULTI_INDEX_ENABLE_INVARIANT_CHECKING

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/ranked_index.hpp>
#include <boost/multi_index/hashed_index.hpp>

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
#include <syslog.h>
}

#include "storage.hpp"

namespace b   = ::boost;
namespace bip = b::interprocess;
namespace bmi = b::multi_index;
namespace ba  = b::archive;

// Initial shared memory
typedef bip::managed_shared_memory memory_t;

// Shared memory strings (with allocator)
typedef bip::managed_shared_memory::allocator<char>::type string_allocator_t;
typedef bip::basic_string<char, std::char_traits<char>, string_allocator_t> string_t;

// Extend string_t to allow construction from a zend_string.
class zstring_t : public string_t
{
  public:
    zstring_t(const zend_string& data, const allocator_type& a)
        : string_t(ZSTR_VAL(&data), ZSTR_LEN(&data), a)
    {
    }
};

//typedef bip::managed_shared_memory::allocator<void>::type void_allocator_t;
typedef bip::allocator<void, memory_t::segment_manager> void_allocator_t;

// A cache entry and its components
typedef zstring_t address_t;
typedef zstring_t serialized_t;
typedef b::variant<b::blank, serialized_t, long, double> value_t;
struct cache_entry {
    address_t address;
    value_t data;

    time_t expiration = 0;
    time_t last_used  = 0;

    cache_entry(const zend_string& addr, const void_allocator_t& a)
        : address(addr, a)
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
typedef bip::managed_shared_memory::allocator<cache_entry>::type cache_entry_allocator_t;

// Index tags for MultiIndex
struct entry_address {
};
struct entry_expiration {
};
struct entry_last_used {
};

// A replacement for std::less that supports comparing with zend_string.
struct address_less {
    bool
    operator()(const address_t& s0, const address_t& s1) const
    {
        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "address_less: Same");
        return s0 < s1;
    }

    bool
    operator()(const zend_string& s0, const address_t& s1) const
    {
        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "address_less: zend_string s0");
        return std::memcmp(ZSTR_VAL(&s0), s1.c_str(), std::min(ZSTR_LEN(&s0), s1.size())) < 0;
    }

    bool
    operator()(const address_t& s0, const zend_string& s1) const
    {
        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "address_less: zend_string s1");
        return std::memcmp(s0.c_str(), ZSTR_VAL(&s1), std::min(s0.size(), ZSTR_LEN(&s1))) < 0;
    }
};

struct address_equal {
    bool
    operator()(const address_t& s0, const address_t& s1) const
    {
        return s0 == s1;
    }

    bool
    operator()(const zend_string& s0, const address_t& s1) const
    {
        return std::memcmp(ZSTR_VAL(&s0), s1.c_str(), std::min(ZSTR_LEN(&s0), s1.size())) == 0;
    }

    bool
    operator()(const address_t& s0, const zend_string& s1) const
    {
        return std::memcmp(s0.c_str(), ZSTR_VAL(&s1), std::min(s0.size(), ZSTR_LEN(&s1))) == 0;
    }
};

struct address_hash {
    std::size_t operator()(const address_t& s0) const
    {
        return boost::hash_range(s0.c_str(), s0.c_str() + s0.size());
    }

    std::size_t operator()(const zend_string& s0) const
    {
        return boost::hash_range(ZSTR_VAL(&s0), ZSTR_VAL(&s0) + ZSTR_LEN(&s0));
    }
};

typedef b::multi_index_container<
  cache_entry,
  bmi::indexed_by<
    bmi::hashed_unique<bmi::tag<entry_address>, bmi::member<cache_entry, address_t, &cache_entry::address>, address_hash, address_equal>,
    bmi::ordered_non_unique<bmi::tag<entry_expiration>, bmi::member<cache_entry, time_t, &cache_entry::expiration>>,
    bmi::ranked_non_unique<bmi::tag<entry_last_used>, bmi::member<cache_entry, time_t, &cache_entry::last_used>>>,
  cache_entry_allocator_t>
  lru_cache_t;

typedef lru_cache_t::index<entry_address>::type lru_cache_by_address_t;
typedef lru_cache_t::index<entry_expiration>::type lru_cache_by_expiration_t;
typedef lru_cache_t::index<entry_last_used>::type lru_cache_by_last_used_t;

class zval_visitor : public boost::static_visitor<zval>
{
  public:
    zval
    operator()(const b::blank& data) const
    {
        zval ret;
        ZVAL_NULL(&ret);
        return ret;
    }

    zval
    operator()(const long& l) const
    {
        zval ret;
        ZVAL_LONG(&ret, l);
        return ret;
    }

    zval
    operator()(const double& l) const
    {
        zval ret;
        ZVAL_DOUBLE(&ret, l);
        return ret;
    }

    zval
    operator()(const serialized_t& ser) const
    {
        zval ret;
        const unsigned char* tmp = (unsigned char*) ser.c_str();
        php_unserialize_data_t var_hash;
        PHP_VAR_UNSERIALIZE_INIT(var_hash);
        if (!php_var_unserialize(&ret, &tmp, (unsigned char*) ser.c_str() + ser.size(), &var_hash)) {
            PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
            // @TODO: Convert to exception or err string?
            php_error_docref(NULL, E_WARNING, "Error unserializing at offset %ld of %ld bytes",
                             (zend_long)(tmp - (unsigned char*) ser.c_str()), (zend_long) ser.size());
            ZVAL_FALSE(&ret);
        }
        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
        return ret;
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
    operator()(const long& i, const long step) const
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
    operator()(const b::blank& b, const long step) const
    {
        return b::none;
    }

    b::optional<value_t>
    operator()(const serialized_t& ser, const long step) const
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

typedef bip::sharable_lock<bip::interprocess_upgradable_mutex> shared_lock_t;
typedef bip::scoped_lock<bip::interprocess_upgradable_mutex> exclusive_lock_t;
typedef bip::upgradable_lock<bip::interprocess_upgradable_mutex> upgradable_lock_t;
typedef b::variant<shared_lock_t, exclusive_lock_t, upgradable_lock_t> shared_lock_or_stronger_t;

class uc_storage
{
  protected:
    mutable bip::interprocess_upgradable_mutex m_cache_mutex;
    const size_t m_capacity;
    std::atomic<size_t> m_used;
    void_allocator_t m_allocator;
    lru_cache_t m_cache;

    // Precondition: Lock held if reference to shared memory.
    size_t
    get_cost(const cache_entry& entry) const
    {
        return b::apply_visitor(cost_visitor(), entry.data);
    }

    // Precondition: Lock held if reference to shared memory.
    bool
    is_fresh(const cache_entry& entry, const time_t now) const
    {
        return (now == 0 || entry.expiration == 0 || entry.expiration < now);
    }

    // Precondition: Shared lock held.
    bool
    needs_bump(const lru_cache_t::iterator& it) const
    {
        const auto rank  = m_cache.get<entry_last_used>().find_rank(it->last_used);
        const auto count = m_cache.get<entry_last_used>().size();

        // If the entry is in oldest 25% used.
        return (rank < (count * 0.25));
    }

    // Precondition: Exclusive lock held
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

        return m_cache.modify(it, bump_cache_entry_last_used(time(0)));
    }

    // Precondition: No locks held.
    bool
    free_space(size_t space_needed, const time_t now)
    {
        // If we have enough space, it's a trivial success.
        if (space_needed <= m_capacity - m_used) {
            return true;
        }

        // If the entry is too large to fit the cache, do nothing and fail.
        // @TODO: Also reject items that are move than N% of the cache size?
        if (space_needed > m_capacity) {
            return false;
        }

        auto abs_time = b::get_system_time() + b::posix_time::milliseconds(100);
        exclusive_lock_t lock(m_cache_mutex, abs_time);
        if (!lock) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "free_space: Timeout");
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Timed out while acquiring lock in free_space().");
            return false;
        }

        // First, evict everything that can expire and is expired, up to the space needed.
        lru_cache_by_expiration_t::iterator it_l =
          m_cache.get<entry_expiration>().lower_bound(1); // Exclude non-expiring items.
        lru_cache_by_expiration_t::iterator it_u = m_cache.get<entry_expiration>().upper_bound(now);
        for (auto i = it_l; i != it_u; ++i) {
            m_used -= get_cost(*i);
            m_cache.get<entry_expiration>().erase(i);
        }

        // See if we have enough space yet.
        if (m_capacity - m_used >= space_needed) {
            return true;
        }

        // If we still need more space, evict the least recently used items.
        for (auto i = m_cache.get<entry_last_used>().begin(); i != m_cache.get<entry_last_used>().end(); ++i) {
            m_used -= get_cost(*i);
            m_cache.get<entry_last_used>().erase(i);

            // Stop evicting once we have enough space.
            if (m_capacity - m_used >= space_needed) {
                return true;
            }
        }

        // We shouldn't ever reach this point because we've emptied the
        // entire cache, but the item is too big.
        return false;
    }

  public:
    uc_storage(size_t capacity, const void_allocator_t& allocator)
        : m_capacity(capacity)
        , m_allocator(allocator)
        , m_used(0)
        , m_cache(lru_cache_t::ctor_args_list(), allocator)
    {
        //std::cerr << "Storage has been initialized." << std::endl;
    }

    ~uc_storage()
    {
        //std::cerr << "Storage is being destroyed." << std::endl;
    }

    // Precondition: No locks held.
    size_t
    capacity() const
    {
        return m_capacity;
    }

    // Precondition: No locks held.
    bool
    clear()
    {
        auto abs_time = b::get_system_time() + b::posix_time::milliseconds(100);
        exclusive_lock_t lock(m_cache_mutex, abs_time);

        if (!lock) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "clear: Timeout");
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Timed out while acquiring lock in clear().");
            return false;
        }

        m_cache.clear();
        return true;
    }

    // Precondition: No locks held.
    success_t
    store_exclusive(cache_entry e, const time_t now)
    {
        bool success = free_space(get_cost(e), now);
        if (!success) {
            return false;
        }

        // We use an upgradable lock here because, if exclusive == true,
        // then we may not need to block reads at all. But, if we need to
        // upgrade, then it must be done atomically. So, we cannot start with
        // a shared lock.
        upgradable_lock_t ulock(m_cache_mutex);
        auto it = m_cache.get<entry_address>().find(e.address);
        if (m_cache.end() == it || !is_fresh(*it, now)) {
            // We actually have to perform the insertion, so we now wait on
            // shared locks to release.
            exclusive_lock_t xlock(std::move(ulock));

            //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Inserting: %s", e.address.c_str());

            std::pair<lru_cache_by_address_t::iterator, bool> res = m_cache.get<entry_address>().insert(std::move(e));
            //std::pair<lru_cache_by_address_t::iterator, bool> res = m_cache.get<entry_address>().insert(e);

            //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Success? %d", res.second);

            return res.second;
        }
        return false;
    }

    // Precondition: No locks held.
    success_t
    store(cache_entry e, const time_t now)
    {
        bool success = free_space(get_cost(e), now);
        if (!success) {
            return false;
        }

        //auto abs_time = b::get_system_time() + b::posix_time::milliseconds(100);
        exclusive_lock_t lock(m_cache_mutex /*, abs_time*/);

        //if (!lock) {
        //    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "store: Timeout");
        //    php_error_docref(NULL TSRMLS_CC, E_ERROR, "Timed out while acquiring lock in store().");
        //    return false;
        //}

        std::pair<lru_cache_by_address_t::iterator, bool> res = m_cache.get<entry_address>().insert(std::move(e));
        //std::pair<lru_cache_by_address_t::iterator, bool> res = m_cache.get<entry_address>().insert(e);

        // Replace on collision, using the matching entry as the position.
        if (!res.second) {
            res.second = m_cache.get<entry_address>().replace(res.first, std::move(e));
            //res.second = m_cache.get<entry_address>().replace(res.first, e);
        }
        return res.second;
    }

    // Precondition: No locks held.
    success_t
    del(const zend_string& addr, const time_t now)
    {
        //std::cerr << "Deletion: ULock" << std::endl << std::flush;
        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Deletion: ULock");
        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Deletion: XLock for %p", this);
        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Deletion: ULock");
        auto abs_time = b::get_system_time() + b::posix_time::milliseconds(100);
        upgradable_lock_t ulock(m_cache_mutex, abs_time);
        //exclusive_lock_t xlock(m_cache_mutex, abs_time);

        if (!ulock) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "del: Timeout");
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Timed out while acquiring lock in del().");
            return false;
        }

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Owns? %d", xlock.owns());

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Deletion: Lookup");
        //std::cerr << "Deletion: Lookup" << std::endl << std::flush;
        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Deltion: Lookup");
        //auto idx = m_cache.get<entry_address>();

        //address_t a(addr, m_allocator); // @TODO: Need this versus addr lookup?

        auto& idx = m_cache.get<entry_address>();
        auto it = idx.find(addr);
        if (m_cache.end() != it) {
            //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Deletion: XLock");
            //std::cerr << "Deletion: XLock" << std::endl << std::flush;
            //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Deletion: XLock");
            // Upgrade to an exclusive lock now that we actually need to delete.
            //exclusive_lock_t xlock(std::move(ulock));
            //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Deletion: Erase");
            //std::cerr << "Deletion: Erase" << std::endl << std::flush;

            //address_t a(addr, m_allocator);

            idx.erase(it);
            //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Deletion: Done");
            //std::cerr << "Deletion: Done" << std::endl << std::flush;
            //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Deletion: Done.");
            return true;
        }

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Deletion: Not Found");

        return false;
    }

    // Precondition: No locks held.
    bool
    empty() const
    {
        shared_lock_t lock(m_cache_mutex);
        return m_cache.empty();
    }

    // Precondition: No locks held.
    size_t
    size() const
    {
        shared_lock_t lock(m_cache_mutex);
        return m_cache.size();
    }

    // Precondition: No locks held.
    void
    dump() const
    {
        shared_lock_t lock(m_cache_mutex);
        for (auto i = m_cache.begin(); i != m_cache.end(); ++i) {
            std::cout << i->address << "=" << i->data << std::endl;
            // std::string k(i->address.begin(), i->address.end());
            // std::string v(i->serialized.begin(), i->serialized.end());
        }
    }

    // Precondition: No locks held.
    bool
    contains(const zend_string& addr, const time_t now) const
    {
        shared_lock_t slock(m_cache_mutex);
        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Contains: Lookup");
        auto it = m_cache.get<entry_address>().find(addr);
        return (m_cache.end() != it && is_fresh(*it, now));
    }

    // Precondition: No locks held.
    zval_and_success
    get(const zend_string& addr, const time_t now)
    {
        zval_and_success ret;
        auto abs_time = b::get_system_time() + b::posix_time::milliseconds(100);
        shared_lock_t slock(m_cache_mutex, abs_time);
        //exclusive_lock_t xlock(m_cache_mutex, abs_time);

        if (!slock.owns()) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "get: Timeout");
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "Timed out while acquiring lock in get().");
            ZVAL_FALSE(&(ret.val));
            ret.success = false;
            return ret;
        }

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Get: Lookup");
        auto it = m_cache.get<entry_address>().find(addr);

        if (m_cache.end() != it && is_fresh(*it, now)) {
            ret.val     = b::apply_visitor(zval_visitor(), it->data);
            ret.success = true;

            if (needs_bump(it)) {
                // Bumping in the LRU is best-effort. This conversion will only
                // succeed if other shared locks aren't held.
                exclusive_lock_t xlock(std::move(slock), bip::try_to_lock);
                if (xlock) {
                    bump(it);
                }
            }

            return ret;
        }

        ZVAL_FALSE(&(ret.val));
        ret.success = false;
        return ret;
    }

    // Precondition: No locks held.
    success_t
    store(const zend_string& addr, const zval& val, const time_t now, const time_t expiration = 0, const bool exclusive = false)
    {
        //auto segment = m_allocator.get_segment_manager();
        //bip::unique_ptr<cache_entry> entry = segment->construct<cache_entry>(bip::anonymous_instance)(addr, m_allocator);

        // @TODO: Delay cache_entry construction and, when needed, create it in the shared memory segment.

        cache_entry entry(addr, m_allocator);
        entry.expiration = expiration;

        if (Z_TYPE_P(&val) == IS_LONG) {
            entry.data = Z_LVAL(val);
        } else {
            smart_str strbuf = { 0 };
            php_serialize_data_t var_hash;
            PHP_VAR_SERIALIZE_INIT(var_hash);
            php_var_serialize(&strbuf, (zval*) &val, &var_hash);
            PHP_VAR_SERIALIZE_DESTROY(var_hash);

            // A null string from serialization indicates that serialization failed.
            if (strbuf.s == NULL) {
                return 0;
            }

            // An exception indicates a serialization failure.
            if (EG(exception)) {
                smart_str_free(&strbuf);
                return 0;
            }

            serialized_t s(*strbuf.s, m_allocator);
            smart_str_free(&strbuf);
            entry.data = std::move(s);
        }

        if (exclusive) {
            return store_exclusive(std::move(entry), now);
        }
        return store(std::move(entry), now);
    }

    // Precondition: No locks held.
    success_t
    store(const zend_string& addr, const long val, const time_t now)
    {
        cache_entry entry(addr, m_allocator);
        entry.data       = val;
        entry.expiration = 0;
        return store(std::move(entry), now);
    }

    // Precondition: No locks held.
    zval_and_success
    increment_or_initialize(const zend_string& addr, const long step, const time_t now)
    {
        zval_and_success ret;
        upgradable_lock_t ulock(m_cache_mutex);
        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "increment_or_initialize: Lookup");
        auto it = m_cache.get<entry_address>().find(addr);
        b::optional<value_t> next_value;

        ret.success = false;

        // If there's no value yet, initialize it to the step value.
        if (m_cache.end() == it || !is_fresh(*it, now)) {
            cache_entry entry(addr, m_allocator);
            entry.data = step;
            exclusive_lock_t xlock(std::move(ulock));
            std::pair<lru_cache_by_address_t::iterator, bool> res = m_cache.get<entry_address>().insert(std::move(entry));
            assert(res.second);  // Insertion should always succeed because of the iterator lookup.
            ZVAL_LONG(&ret.val, step);
            ret.success = true;
            return ret;
        }

        auto bound_visitor    = std::bind(increment_visitor(), std::placeholders::_1, step);
        auto next_value_maybe = b::apply_visitor(bound_visitor, it->data);

        // We can only increment if there was a valid value to increment
        // already.
        if (b::none != next_value_maybe) {
            value_t next_value = *next_value_maybe;
            exclusive_lock_t xlock(std::move(ulock));
            m_cache.modify(it, set_entry_value(next_value));
            ret.val     = b::apply_visitor(zval_visitor(), next_value);
            ret.success = true;

            if (needs_bump(it)) {
                bump(it);
            }

            return ret;
        }

        ZVAL_NULL(&ret.val);
        return ret;
    }

    // Precondition: No locks held.
    success_t
    cas(const zend_string& addr, const long next, const long expected, const time_t now)
    {
        upgradable_lock_t ulock(m_cache_mutex);

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "cas: Lookup");
        auto it = m_cache.get<entry_address>().find(addr);

        // If there's no value there, succeed without comparison.
        if (m_cache.end() == it || !is_fresh(*it, now)) {
            cache_entry entry(addr, m_allocator);
            entry.data = next;
            exclusive_lock_t xlock(std::move(ulock));
            std::pair<lru_cache_by_address_t::iterator, bool> res = m_cache.get<entry_address>().insert(std::move(entry));
            assert(res.second);
            return true;
        }

        // If the value doesn't match what's expected (or is the wrong type), fail.
        auto bound_visitor = std::bind(cas_match_visitor(), std::placeholders::_1, expected);
        if (!b::apply_visitor(bound_visitor, it->data)) {
            return false;
        }

        // Store the new value.
        exclusive_lock_t xlock(std::move(ulock));
        m_cache.modify(it, set_entry_value(next));
        return true;
    }
};

bip::offset_ptr<uc_storage> get_storage()
{
    static bip::offset_ptr<uc_storage> storage = nullptr;

    if (nullptr == storage) {
        try {
            memory_t* segment = new memory_t(bip::open_only, "uc");
            storage = segment->find<uc_storage>("storage").first;
            //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Found storage at %p", storage);
            return storage;
        } catch (const std::exception& ex) {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Exception while connecting to interprocess storage: %s", ex.what());
        }
    }

    return storage;
}

extern "C" {

// Precondition: Before forking.
success_t
uc_storage_init(const size_t size)
{

    //struct shm_remove
    //{
    //    shm_remove() { bip::shared_memory_object::remove("php-uc"); }
    //    ~shm_remove(){ bip::shared_memory_object::remove("php-uc"); }
    //} remover;

    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Removing existing shared storage...");

    bip::shared_memory_object::remove("uc");

    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Initializing shared storage of size %lu...", size);

    try {
       memory_t segment(bip::create_only, "uc", size * 2);
       uc_storage* storage = segment.construct<uc_storage>("storage")(size, segment.get_segment_manager());
       //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Initialized storage at %p", storage);
       return true;
    } catch (const std::exception& ex) {
       php_error_docref(NULL TSRMLS_CC, E_ERROR, "Exception while initializing interprocess storage: %s", ex.what());
    }

    return false;
}

// Precondition: After forking (if forking)
uc_storage_t
uc_storage_get_handle()
{
    return nullptr;
}

size_t
uc_storage_size(uc_storage_t st_opaque)
{
    //uc_storage* st = static_cast<uc_storage*>(st_opaque);
    //memory_t* segment = get_segment();
    //memory_t segment(bip::open_only, "uc");
    auto st = get_storage();
    try {
        return st->size();
        //return st->lock_and_get_zero();
    } catch (const std::exception& ex) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Exception in uc_storage_size: %s", ex.what());
    }

    return 0;
}

zval_and_success
uc_storage_increment(uc_storage_t st_opaque, const zend_string* address, const long step, const time_t now)
{
    auto st = get_storage();
    try {
        return st->increment_or_initialize(*address, step, now);
    } catch (const std::exception& ex) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Exception in uc_storage_increment: %s", ex.what());
    }

    zval_and_success failure = {0};
    return failure;
}

success_t
uc_storage_cas(uc_storage_t st_opaque, const zend_string* address, const long next, const long expected, const time_t now)
{
    auto st = get_storage();
    try {
        return st->cas(*address, next, expected, now);
    } catch (const std::exception& ex) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Exception in uc_storage_cas: %s", ex.what());
    }
    return 0;
}

success_t
uc_storage_store(
  uc_storage_t st_opaque, const zend_string* address, const zval* data, time_t expiration, zend_bool exclusive, const time_t now)
{
    auto st = get_storage();
    try {
        return st->store(*address, *data, now, expiration, exclusive);
    } catch (const std::exception& ex) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Exception in uc_storage_store: %s", ex.what());
    }
    return 0;
}

zval_and_success
uc_storage_get(uc_storage_t st_opaque, const zend_string* address, const time_t now)
{
    auto st = get_storage();
    try {
        return st->get(*address, now);
    } catch (const std::exception& ex) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Exception in uc_storage_get: %s", ex.what());
    }

    zval_and_success failure = {0};
    return failure;
}

success_t
uc_storage_exists(uc_storage_t st_opaque, const zend_string* address, const time_t now)
{
    auto st = get_storage();
    try {
        return st->contains(*address, now);
    } catch (const std::exception& ex) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Exception in uc_storage_exists: %s", ex.what());
    }

    return 0;
}

success_t
uc_storage_delete(uc_storage_t st_opaque, const zend_string* address, const time_t now)
{
    auto st = get_storage();
    try {
        return st->del(*address, now);
    } catch (const std::exception& ex) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Exception in uc_storage_delete: %s", ex.what());
    }

    return 0;
}

void
uc_storage_clear(uc_storage_t st_opaque)
{
    auto st = get_storage();
    try {
        st->clear();
    } catch (const std::exception& ex) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Exception in uc_storage_clear: %s", ex.what());
    }
}

void
uc_storage_dump(uc_storage_t st_opaque)
{
    auto st = get_storage();
    try {
        st->dump();
    } catch (const std::exception& ex) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Exception in uc_storage_dump: %s", ex.what());
    }
}

} // extern "C"
