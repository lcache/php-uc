#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/managed_external_buffer.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/containers/string.hpp>

#include <boost/interprocess/sync/interprocess_upgradable_mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
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

#define UC_CLIMATE_COUNT 3

namespace b   = ::boost;
namespace bip = b::interprocess;
namespace bmi = b::multi_index;
namespace ba  = b::archive;

// Initial shared memory
typedef bip::managed_shared_memory memory_t;
typedef bip::managed_external_buffer climate_memory_t;

// Shared memory strings (with allocator)
typedef climate_memory_t::allocator<char>::type string_allocator_t;
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

class serialized_t
{
  protected:
    string_t data;

  public:
    serialized_t(const zval& val, const string_allocator_t& a)
    : data(a)
    {
        smart_str strbuf = { 0 };
        php_serialize_data_t var_hash;
        PHP_VAR_SERIALIZE_INIT(var_hash);
        php_var_serialize(&strbuf, (zval*) &val, &var_hash);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);

        // A null string from serialization indicates that serialization failed.
        if (strbuf.s == NULL) {
            throw std::runtime_error("Serialization buffer is empty.");
        }

        // An exception indicates a serialization failure.
        if (EG(exception)) {
            smart_str_free(&strbuf);
            throw std::runtime_error("PHP serializer generated an exception.");
        }

        string_t s(ZSTR_VAL(strbuf.s), ZSTR_LEN(strbuf.s), a);
        smart_str_free(&strbuf);
        data = std::move(s);
    }

    const char* c_str() const
    {
        return data.c_str();
    }

    std::size_t size() const
    {
        return data.size();
    }

};

//typedef bip::managed_shared_memory::allocator<void>::type void_allocator_t;
typedef bip::allocator<void, memory_t::segment_manager> void_allocator_t;
typedef bip::allocator<void, climate_memory_t::segment_manager> void_climate_allocator_t;

// A cache entry and its components
typedef zstring_t address_t;
//typedef zstring_t serialized_t;

typedef b::variant<b::blank, serialized_t, long, double> value_t;
struct cache_entry {
    address_t address;
    value_t data;

    time_t expiration = 0;

    cache_entry(const void_climate_allocator_t& a, const zend_string& addr, const zval& val, const time_t exp)
        : address(addr, a)
        , expiration(exp)
    {
        if (Z_TYPE_P(&val) == IS_LONG) {
            data = Z_LVAL(val);
        } else {
            // If we have no special case, serialize.
            serialized_t s(val, a);
            data = std::move(s);
        }

    }

    cache_entry(const void_climate_allocator_t& a, const zend_string& addr, const long val)
        : address(addr, a)
        , data(val)
    {
    }

/*
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
*/
};
typedef climate_memory_t::allocator<cache_entry>::type cache_entry_allocator_t;

// Index tags for MultiIndex
struct entry_address {
};
struct entry_expiration {
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
    bmi::ordered_non_unique<bmi::tag<entry_expiration>, bmi::member<cache_entry, time_t, &cache_entry::expiration>>
  >,
  cache_entry_allocator_t>
  lru_cache_t;

typedef lru_cache_t::index<entry_address>::type lru_cache_by_address_t;
typedef lru_cache_t::index<entry_expiration>::type lru_cache_by_expiration_t;

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
    void_allocator_t m_allocator;
    std::size_t m_climate_size;
    std::size_t m_coldest_climate_idx;
    std::array<climate_memory_t, UC_CLIMATE_COUNT> m_climates;
    std::array<bip::offset_ptr<lru_cache_t>, UC_CLIMATE_COUNT> m_climate_data;

    size_t
    get_cost(const cache_entry& entry) const
    {
        return b::apply_visitor(cost_visitor(), entry.data);
    }

    bool
    is_fresh(const cache_entry& entry, const time_t now) const
    {
        return (now == 0 || entry.expiration == 0 || entry.expiration < now);
    }

    // Precondition: Exclusive lock held.
    std::size_t
    heat(const std::size_t current_climate_idx, lru_cache_t::iterator& it)
    {
        const std::size_t next_heat_idx = (current_climate_idx + 1) % UC_CLIMATE_COUNT;

        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "heat: requested from %lu to %lu", current_climate_idx, next_heat_idx);

        // If heating would overflow to the coldest, don't do anything.
        if (m_coldest_climate_idx == next_heat_idx) {
            //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "heat: %lu is already the hottest climate", current_climate_idx);
            return current_climate_idx;
        }

        // Copy to the new heat level.
        try {
            // Other climates should not possess the same address we're heating.
            // So, this should always succeed.
            /*std::pair<lru_cache_by_address_t::iterator, bool> res =*/
            auto res = m_climate_data[next_heat_idx]->get<entry_address>().insert(*it);
            if (!res.second) {
                php_error_docref(NULL TSRMLS_CC, E_ERROR, "heat: unexpected failure from %lu to %lu", current_climate_idx, next_heat_idx);
                return current_climate_idx;
            }

            // Erase the old copy.
            m_climate_data[current_climate_idx]->get<entry_address>().erase(it);

            // @TODO: Remove this explicit invalidation.
            it = m_climate_data[current_climate_idx]->end();
        } catch(const bip::bad_alloc& e) {
            //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "heat: insufficient space to heat from %lu to %lu; cooling", current_climate_idx, next_heat_idx);
            // Since there's no space, do some cooling.
            global_cooling();
            return current_climate_idx;
            // @TODO: Retry heating the item? Or just wait until next chance?
        }

        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "heat: success from %lu to %lu", current_climate_idx, next_heat_idx);
        return next_heat_idx;
    }

    // Precondition: Exclusive lock held.
    void
    evict_expired(const time_t now)
    {
        for (std::size_t idx = 0; idx < UC_CLIMATE_COUNT; ++idx) {
            lru_cache_by_expiration_t::iterator it_l =
              m_climate_data[idx]->get<entry_expiration>().lower_bound(1); // Exclude non-expiring items.
            lru_cache_by_expiration_t::iterator it_u = m_climate_data[idx]->get<entry_expiration>().upper_bound(now);
            for (auto i = it_l; i != it_u; ++i) {
                m_climate_data[idx]->get<entry_expiration>().erase(i);
            }
        }
    }

    // Precondition: Exclusive lock held.
    void global_cooling()
    {
        php_error_docref(NULL TSRMLS_CC, E_NOTICE, "global_cooling");

        // Reset the current coldest climate (soon to be hottest).
        climate_memory_t climate(bip::create_only, &m_climates[m_coldest_climate_idx], m_climate_size);
        m_climate_data[m_coldest_climate_idx] = climate.construct<lru_cache_t>(bip::unique_instance) (lru_cache_t::ctor_args_list(), climate.get_segment_manager());
        m_climates[m_coldest_climate_idx] = std::move(climate);

        // Rotate the climate roles.
        m_coldest_climate_idx = (m_coldest_climate_idx + 1) % UC_CLIMATE_COUNT;
    }

    // Precondition: Shared lock held.
    auto get_hottest(const zend_string& addr, const time_t now = 0) const
    {
        b::optional<std::pair<std::size_t, lru_cache_t::iterator>> retval = b::none;

        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "get_hottest: searching for address %s", ZSTR_VAL(&addr));

        // Start with the hottest climate and move colder.
        for (std::size_t attempts = 0; attempts < UC_CLIMATE_COUNT; ++attempts) {
            const size_t climate_idx = (attempts + UC_CLIMATE_COUNT - 1) % UC_CLIMATE_COUNT;
            //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "get_hottest: searching climate %lu", climate_idx);
            auto& climate_addresses = m_climate_data[climate_idx]->get<entry_address>();
            auto it = climate_addresses.find(addr);
            if (climate_addresses.end() != it && is_fresh(*it, now)) {
                retval = std::pair<std::size_t, lru_cache_t::iterator>(climate_idx, it);
                //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "get_hottest: found in climate %lu", climate_idx);
                return retval;
            }
        }

        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "get_hottest: not found");
        return retval;
    }

    // Precondition: No locks held.
    success_t emplace_with_cooling(const zend_string& addr, const zval& val, const time_t now, const bool replace, const time_t expiration) {
        upgradable_lock_t ulock(m_cache_mutex);
        exclusive_lock_t xlock;  // Holder so we can upgrade without losing scope.

        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "emplace_with_cooling: addr=%s, now=%lu, replace=%lu, expiration=%lu", ZSTR_VAL(&addr), now, replace, expiration);

        // Check for collisions in hotter climates.
        // Handle matches as follows:
        //  * If we're replacing *or* the entry is stale, erase.
        //  * Otherwise, fail.
        for (std::size_t i = 0; i < UC_CLIMATE_COUNT - 1; ++i) {
            std::size_t climate_idx = (i + UC_CLIMATE_COUNT - 1) % UC_CLIMATE_COUNT;
            auto& climate_addresses = m_climate_data[climate_idx]->get<entry_address>();
            auto it = climate_addresses.find(addr);
            if (climate_addresses.end() != it) {
                if (replace || !is_fresh(*it, now)) {
                    if (!xlock.owns()) {
                        // It's not possible to move-assign+upgrade. So, we
                        // move-construct+upgrade and then move-assign.
                        exclusive_lock_t temp_xlock(std::move(ulock));
                        xlock = std::move(temp_xlock);
                    }
                    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "emplace_with_cooling: erasing same address in climate %lu (b/c replace or stale)", climate_idx);
                    climate_addresses.erase(it);
                } else {
                    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "emplace_with_cooling: !replace and collision with hotter");
                    return false;
                }
            }
        }

        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "emplace_with_cooling: address %s was not found (or was erased) in the hotter climates", ZSTR_VAL(&addr));

        // Attempt to insert a number of times equal to the count of climates.
        // Each time, run "global cooling" to potentially succeed on the next
        // attempt.
        for (std::size_t attempts = 0; attempts < UC_CLIMATE_COUNT; ++attempts) {
            // Alias the current, coldest climate.
            auto& coldest_addresses = m_climate_data[m_coldest_climate_idx]->get<entry_address>();

            // Try to find an existing, matching item.
            auto it = coldest_addresses.find(addr);

            if (it != coldest_addresses.end()) {
                if (replace) {
                    // Upgrade to exclusive if we haven't yet.
                    if (!xlock.owns()) {
                        // It's not possible to move-assign+upgrade. So, we
                        // move-construct+upgrade and then move-assign.
                        exclusive_lock_t temp_xlock(std::move(ulock));
                        xlock = std::move(temp_xlock);
                    }

                    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "emplace_with_cooling: erasing address %s from the coldest climate", ZSTR_VAL(&addr));

                    // If we can replace, erase the current item so emplace will
                    // succeed.
                    coldest_addresses.erase(it);
                } else {
                    // If we can't replace, fail because we will expect a
                    // collision.
                    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "emplace_with_cooling: !replace and collision with coldest");
                    return false;
                }
            }

            // Upgrade to exclusive if we haven't yet.
            if (!xlock.owns()) {
                exclusive_lock_t temp_xlock(std::move(ulock));
                xlock = std::move(temp_xlock);
            }

            try {
                //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "emplace_with_cooling: attempting emplace with climate %lu", m_coldest_climate_idx);
                auto res = coldest_addresses.emplace(m_climates[m_coldest_climate_idx].get_segment_manager(), addr, val, expiration);
                if (!res.second) {
                    php_error_docref(NULL TSRMLS_CC, E_ERROR, "emplace_with_cooling: unexpected collision in climate %lu for address %s", m_coldest_climate_idx, ZSTR_VAL(&addr));
                    return false;
                }
                return true;
            } catch (bip::bad_alloc) {
                // If there was insufficient space in the coldest climate,
                // run cooling to potentially have success next time. Only
                // bother to do this if we're not on the final attempt.
                if (attempts < UC_CLIMATE_COUNT - 1) {
                    global_cooling();  // Will alter m_coldest_climate_idx.
                }
            }
        }

        // If we reach this point, we've flushed everything and *still* can't
        // allocate the item. The item must be too big.
        // @TODO: Implement an earlier check for size to avoid cache flushing
        // attacks.
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "emplace_with_cooling: too big");
        return false;
    }

  public:
    uc_storage(memory_t& segment)
    : m_allocator(segment.get_segment_manager())
    , m_climate_size((segment.get_free_memory() - 4096) / UC_CLIMATE_COUNT)
    , m_coldest_climate_idx(0)
    {
        // Create the climates, with each boxed into "external" buffers.
        for (std::size_t climate_idx = 0; climate_idx < UC_CLIMATE_COUNT; ++climate_idx) {
            auto climate_raw = segment.allocate_aligned(m_climate_size, sizeof(std::size_t));
            climate_memory_t climate(bip::create_only, climate_raw, m_climate_size);

            // Despite being inside sub-segments, the lru_cache_t objects should maintain their relative positions within the main segment.
            m_climate_data[climate_idx] = climate.construct<lru_cache_t>(bip::unique_instance) (lru_cache_t::ctor_args_list(), climate.get_segment_manager());
            m_climates[climate_idx] = std::move(climate);
        }

        //std::cerr << "Storage has been initialized." << std::endl;
    }

    ~uc_storage()
    {
        //std::cerr << "Storage is being destroyed." << std::endl;
    }

    // Precondition: No locks held.
    success_t
    clear()
    {
        //auto abs_time = b::get_system_time() + b::posix_time::milliseconds(100);
        exclusive_lock_t lock(m_cache_mutex/*, abs_time*/);

        //if (!lock) {
        //    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "clear: Timeout");
        //    php_error_docref(NULL TSRMLS_CC, E_ERROR, "Timed out while acquiring lock in clear().");
        //    return false;
        //}

        // By "cooling" the same number of times as there are climates, the cache
        // will be left empty.
        for (std::size_t climate_idx = 0; climate_idx < UC_CLIMATE_COUNT; ++climate_idx) {
            global_cooling();
        }

        return true;
    }

    // Precondition: No locks held.
    success_t
    store_exclusive(const zend_string& addr, const zval& val, const time_t now)
    {
        return emplace_with_cooling(addr, val, now, false, 0);
    }

    // Precondition: No locks held.
    success_t
    store(const zend_string& addr, const zval& val, const time_t now, const time_t expiration)
    {
        return emplace_with_cooling(addr, val, now, true, expiration);
    }

    // Precondition: No locks held.
    success_t
    del(const zend_string& addr, const time_t now)
    {
        //std::cerr << "Deletion: ULock" << std::endl << std::flush;
        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Deletion: ULock");
        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Deletion: XLock for %p", this);
        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Deletion: ULock");
        //auto abs_time = b::get_system_time() + b::posix_time::milliseconds(100);
        upgradable_lock_t ulock(m_cache_mutex/*, abs_time*/);
        exclusive_lock_t xlock;
        //exclusive_lock_t xlock(m_cache_mutex, abs_time);

        //if (!ulock) {
        //    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "del: Timeout");
        //    php_error_docref(NULL TSRMLS_CC, E_ERROR, "Timed out while acquiring lock in del().");
        //    return false;
        //}

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Owns? %d", xlock.owns());

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Deletion: Lookup");
        //std::cerr << "Deletion: Lookup" << std::endl << std::flush;
        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Deltion: Lookup");
        //auto idx = m_cache.get<entry_address>();

        //address_t a(addr, m_allocator); // @TODO: Need this versus addr lookup?

        // @TODO: Technically, we should be able to start with the hottest
        // climate (moving colder) and return if we delete something.
        success_t success = false;

        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "del: address %s", ZSTR_VAL(&addr));

        for (std::size_t climate_idx = 0; climate_idx < UC_CLIMATE_COUNT; ++climate_idx) {
            auto& climate_addresses = m_climate_data[climate_idx]->get<entry_address>();
            auto it = climate_addresses.find(addr);
            if (climate_addresses.end() != it) {
                if (!xlock.owns()) {
                    exclusive_lock_t temp_xlock(std::move(ulock));
                    xlock = std::move(temp_xlock);
                }
                //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "del: removing address %s from climate %lu", ZSTR_VAL(&addr), climate_idx);
                climate_addresses.erase(it);
                success = true;
            }
        }

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Deletion: Not Found");

        return success;
    }

    // Precondition: No locks held.
    bool
    empty() const
    {
        shared_lock_t lock(m_cache_mutex);
        for (std::size_t idx = 0; idx < UC_CLIMATE_COUNT; ++idx) {
            auto& climate = m_climate_data[idx];
            if (!climate->empty()) {
                return false;
            }
        }
        return true;
    }

    // Precondition: No locks held.
    size_t
    size() const
    {
        shared_lock_t lock(m_cache_mutex);
        size_t size = 0;
        for (std::size_t idx = 0; idx < UC_CLIMATE_COUNT; ++idx) {
            auto& climate = m_climate_data[idx];
            size += climate->size();
        }
        return size;
    }

    // Precondition: No locks held.
    void
    dump() const
    {
        //shared_lock_t lock(m_cache_mutex);
        //for (auto i = m_cache.begin(); i != m_cache.end(); ++i) {
            //std::cout << i->address << ": " << i->data << std::endl;
            // std::string k(i->address.begin(), i->address.end());
            // std::string v(i->serialized.begin(), i->serialized.end());
        //}
    }

    // Precondition: No locks held.
    bool
    contains(const zend_string& addr, const time_t now) const
    {
        shared_lock_t slock(m_cache_mutex);
        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Contains: Lookup");

        auto maybe = get_hottest(addr, now);
        return (b::none != maybe);
    }

    // Precondition: No locks held.
    zval_and_success
    get(const zend_string& addr, const time_t now)
    {
        zval_and_success ret;
        //auto abs_time = b::get_system_time() + b::posix_time::milliseconds(100);
        shared_lock_t slock(m_cache_mutex /*, abs_time*/);
        //exclusive_lock_t xlock(m_cache_mutex, abs_time);

        //if (!slock.owns()) {
        //    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "get: Timeout");
        //    php_error_docref(NULL TSRMLS_CC, E_WARNING, "Timed out while acquiring lock in get().");
        //    ZVAL_FALSE(&(ret.val));
        //    ret.success = false;
        //    return ret;
        //}

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Get: Lookup");

        // Start with the hottest climate and move colder.
        for (std::size_t attempts = 0; attempts < UC_CLIMATE_COUNT; ++attempts) {
            const size_t climate_idx = (attempts + UC_CLIMATE_COUNT - 1) % UC_CLIMATE_COUNT;
            auto& climate_addresses = m_climate_data[climate_idx]->get<entry_address>();
            auto it = climate_addresses.find(addr);
            if (climate_addresses.end() != it && is_fresh(*it, now)) {
                ret.val     = b::apply_visitor(zval_visitor(), it->data);
                ret.success = true;

                // Check if we found a match in anything but the hottest climate.
                // While heat() will never overflow (to coldest), we can avoid an
                // exclusive lock by checking early.
                if (attempts > 0) {
                    // Bumping heat is best-effort. This conversion will only
                    // succeed if other shared locks aren't held.
                    exclusive_lock_t xlock(std::move(slock), bip::try_to_lock);
                    if (xlock) {
                        heat(climate_idx, it);
                    }
                }
                return ret;

            }
        }

        ZVAL_FALSE(&(ret.val));
        ret.success = false;
        return ret;
    }

    // Precondition: No locks held.
    success_t
    store(const zend_string& addr, const zval& val, const time_t now, const bool exclusive = false, const time_t expiration = 0)
    {
        if (exclusive) {
            return store_exclusive(addr, val, now);
        }
        return store(addr, val, now, expiration);
    }

    // Precondition: No locks held.
    //success_t
    //store(const zend_string& addr, const long val, const time_t now)
    //{
    //    value_t data = val;
    //    return store(addr, std::move(data), now);
    //}

    // Precondition: No locks held.
    zval_and_success
    increment_or_initialize(const zend_string& addr, const long step, const time_t now)
    {
        zval_and_success ret;
        upgradable_lock_t ulock(m_cache_mutex);
        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "increment_or_initialize: Lookup");
        b::optional<value_t> next_value;
        auto maybe = get_hottest(addr, 0);

        // @TODO: Check for expiration somewhere. We can't offload it to get_hottest()
        // because we need to guarantee emplace success on b::none.

        ret.success = false;

        // If there's no value yet, initialize it to the step value in the coldest climate.
        if (b::none == maybe) {
            exclusive_lock_t xlock(std::move(ulock));
            //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Storing new value of %ld", step);

            for (std::size_t attempts = 0; attempts < UC_CLIMATE_COUNT; ++attempts) {
                // Alias the current, coldest climate.
                auto& coldest_addresses = m_climate_data[m_coldest_climate_idx]->get<entry_address>();
                try {
                    auto res = coldest_addresses.emplace(m_climates[m_coldest_climate_idx].get_segment_manager(), addr, step);
                    if (!res.second) {
                        php_error_docref(NULL TSRMLS_CC, E_ERROR, "increment_or_initialize: unexpected failure initializing %s to value %ld", ZSTR_VAL(&addr), step);
                        //auto maybe_it = get_hottest(addr, 0);
                        //if (b::none != maybe_it) {
                        //    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "increment_or_initialize: get_hottest found a collision");
                        //}

                        //auto it = coldest_addresses.find(addr);
                        //if (coldest_addresses.end() != it) {
                        //    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "increment_or_initialize: found a collision");
                        //}
                        ret.success = false;
                        return ret;
                    }
                    ZVAL_LONG(&ret.val, step);
                    ret.success = true;
                    return ret;
                } catch (bip::bad_alloc) {
                    if (attempts < UC_CLIMATE_COUNT - 1) {
                        global_cooling();
                    }
                }
            }
        }

        auto found = *maybe;
        auto bound_visitor    = std::bind(increment_visitor(), std::placeholders::_1, step);
        auto next_value_maybe = b::apply_visitor(bound_visitor, found.second->data);

        // We can only increment if there was a valid value to increment
        // already.
        if (b::none != next_value_maybe) {
            value_t next_value = *next_value_maybe;
            exclusive_lock_t xlock(std::move(ulock));

            //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Updating value by step %ld.", step);

            // @TODO: It's probably safe to assume this won't throw bad_alloc,
            // but it would be good to make sure. Fix when adding the optimization
            // in the TODO below.
            m_climate_data[found.first]->modify(found.second, set_entry_value(next_value));
            ret.val     = b::apply_visitor(zval_visitor(), next_value);
            ret.success = true;

            // @TODO: Rather than increment in place and heat, we should write
            // directly to the climate one hotter than the current.
            /*auto new_heat =*/ heat(found.first, found.second);
            //if (new_heat == found.first) {
                //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "increment_or_initialize: no heating completed from %lu", found.first);
            //}

            return ret;
        }

        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "increment_or_initialize: failure");

        ZVAL_NULL(&ret.val);
        return ret;
    }

    // Precondition: No locks held.
    success_t
    cas(const zend_string& addr, const long next, const long expected, const time_t now)
    {
        upgradable_lock_t ulock(m_cache_mutex);

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "cas: Lookup");
        auto maybe = get_hottest(addr, 0);
        //auto it = m_cache.get<entry_address>().find(addr);

        // @TODO: Check for expiration somewhere. We can't offload it to get_hottest()
        // because we need to guarantee emplace success on b::none.

        // If there's no value present, succeed without comparison (just emplace).
        if (b::none == maybe) {
            exclusive_lock_t xlock(std::move(ulock));

            for (std::size_t attempts = 0; attempts < UC_CLIMATE_COUNT; ++attempts) {
                // Alias the current, coldest climate.
                auto& coldest_addresses = m_climate_data[m_coldest_climate_idx]->get<entry_address>();
                try {
                    coldest_addresses.emplace(m_climates[m_coldest_climate_idx].get_segment_manager(), addr, next);
                } catch (bip::bad_alloc) {
                    if (attempts < UC_CLIMATE_COUNT - 1) {
                        global_cooling();
                    }
                }
            }

            return true;
        }

        auto found = *maybe;


        // If the value doesn't match what's expected (or is the wrong type), fail.
        auto bound_visitor = std::bind(cas_match_visitor(), std::placeholders::_1, expected);
        if (!b::apply_visitor(bound_visitor, found.second->data)) {
            return false;
        }

        // Store the new value.
        exclusive_lock_t xlock(std::move(ulock));
        m_climate_data[found.first]->modify(found.second, set_entry_value(next));

        // @TODO: Rather than alter in place and heat, we should write
        // directly to the climate one hotter than the current.
        heat(found.first, found.second);
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
    try {
       memory_t segment(bip::create_only, "uc", size);
       /*uc_storage* storage = */segment.construct<uc_storage>("storage")(segment);
       //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Initialized storage at %p", storage);
    } catch (const std::exception& ex) {
       php_error_docref(NULL TSRMLS_CC, E_ERROR, "Exception while initializing coordinating storage: %s", ex.what());
       return false;
    }

    return true;
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
        return st->store(*address, *data, now, exclusive, expiration);
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

