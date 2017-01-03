#include "marshalling.h"
#include <syslog.h>
#include <string.h>
#include <errno.h>

#define UC_MAGIC 19840311

int uc_read_metadata(const char* val, size_t val_len, uc_metadata_t* meta) {
    // @TODO: Move errors to a *err parameter.
    if (val_len < sizeof(*meta)) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Value (len %lu) is shorter than expected metadata (len %lu).", val_len, sizeof(*meta));
        return EIO;
    }

    // Copy metadata into the struct.
    memcpy(meta, (void *) (val + val_len - sizeof(*meta)), sizeof(*meta));

    if (meta->magic != UC_MAGIC) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Magic number (%u) does not match expected value (%u).", meta->magic, UC_MAGIC);
        return EIO;
    }

    if (meta->version > 1) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Metadata (version %lu) exceeds known versions.", meta->version);
        return EIO;
    }

    if (meta->op == kCAS && meta->value_type != kLong) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Inc or CAS operation has non-long value type: %d", meta->value_type);
        return EIO;
    }

    if (meta->op == kInc || meta->op == kCAS || meta->value_type == kNone) {
        if (val_len > sizeof(*meta)) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "Inc or CAS operation has extra bytes: %lu", val_len - sizeof(*meta));
            return EIO;
        }
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
