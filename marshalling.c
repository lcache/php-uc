#include "marshalling.h"
#include <syslog.h>
#include <string.h>
#include <errno.h>

#define UC_MAGIC 19840311

int uc_read_metadata(const char* val, size_t val_len, uc_metadata_t* meta) {
    uc_metadata_t m = {0};

    if (NULL != meta) {
        *meta = m;
    }

    if (val_len < sizeof(m)) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "uc_read_metadata: value (len %lu) is shorter than expected metadata (len %lu).", val_len, sizeof(m));
        return EINVAL;
    }

    // Copy metadata into the struct.
    //m = (uc_metadata_t) (val + val_len - sizeof(m));
    memcpy(&m, (void *) (val + val_len - sizeof(m)), sizeof(m));

    if (m.magic != UC_MAGIC) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "uc_read_metadata: magic number (%u) does not match expected value (%u).", m.magic, UC_MAGIC);

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "Size: %zu", val_len);
        //for(size_t i=0; i < val_len; i++) {
        //    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "%02x ", val[i]);
        //}

        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "OP:  %d", m.op);
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "TS:  %lu", m.modified);
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "TTL: %lu", m.ttl);
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "VER: %lu", m.version);
        return EINVAL;
    }

    if (m.version > 1) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Metadata (version %lu) exceeds known versions.", m.version);
        return EINVAL;
    }

    if (m.op == kCAS && m.value_type != kLong) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Inc or CAS operation has non-long value type: %d", m.value_type);
        return EINVAL;
    }

    if (m.op == kInc || m.op == kCAS || m.value_type == kNone) {
        if (val_len > sizeof(m)) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Inc or CAS operation has extra bytes: %lu", val_len - sizeof(m));
            return EINVAL;
        }
    }

    if (m.op == kDelete && m.value_type != kNone) {
        if (val_len > sizeof(m)) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Delete operation has a value.");
            return EINVAL;
        }
    }


    if (NULL != meta) {
        *meta = m;
    }

    return 0;
}

int uc_metadata_is_fresh(uc_metadata_t meta, time_t now) {
    // Entries with no TTL are always fresh.
    if (meta.ttl == 0) {
        return 1;
    }

    // Entries with a TTL of 1984 should go down the memory hole.
    if (meta.ttl == 1984) {
        return 0;
    }

    // Check the time elapsed since last modification.
    if (meta.modified + meta.ttl >= now) {
        return 1;
    }

    return 0;
}

int uc_strip_metadata(const char* val, size_t *val_len, uc_metadata_t* meta) {
    int retval;

    retval = uc_read_metadata(val, *val_len, meta);
    if (0 != retval) {
        return retval;
    }

    *val_len -= sizeof(*meta);

    return 0;
}

void uc_print_metadata(const char *val, size_t val_len) {
    uc_metadata_t meta;
    uc_read_metadata(val, val_len, &meta);
    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "OP:  %d", meta.op);
    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "TS:  %lu", meta.modified);
    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "TTL: %lu", meta.ttl);
    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "VER: %lu", meta.version);
}

int uc_init_metadata(uc_metadata_t* meta)
{
    meta->version = 1;
    meta->magic = UC_MAGIC;
    return 0;
}
