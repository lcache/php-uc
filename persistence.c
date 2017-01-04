#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "persistence.h"
#include "marshalling.h"

static void uc_filter_destory(void* arg) {}
static const char* uc_filter_name(void* arg) { return "ttl"; }
static unsigned char uc_filter_filter(void* arg, int level, const char* key, size_t key_length, const char* existing_value, size_t value_length,
                                      char** new_value, size_t* new_value_length, unsigned char* value_changed) {
    uc_metadata_t meta;
    int retval;

    //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "uc_filter_filter: filtering key: %s", key);

    retval = uc_read_metadata(existing_value, value_length, &meta);
    // Keep entries on parsing failure.
    if (0 != retval) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_WARNING), "uc_filter_filter: failed uc_read_metadata: %s; retaining", strerror(retval));
        return 0;
    }

    // Prune stale entries with TTLs.
    if (!uc_metadata_is_fresh(meta, time(NULL))) {
        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "uc_filter_filter: removing");
        return 1;
    }

    //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "uc_filter_filter: retaining");
    return 0;
}

static void merge_op_destroy(void* arg) { }
static const char* merge_op_name(void* arg) {
    return "php-uc";
}
static char* merge_op_full_merge(void* arg, const char* key, size_t key_length, const char* existing_value, size_t existing_value_length, const char* const* operands_list, const size_t* operands_list_length, int num_operands, unsigned char* success, size_t* new_value_length) {
    uc_metadata_t meta = {0};
    uc_metadata_t merge_op_meta;
    int status_ok;
    int retval;
    const char* new_data;
    size_t new_data_len;

    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "merge_op_full_merge: attempting full merge");

    if (existing_value != NULL) {
        status_ok = uc_strip_metadata(existing_value, &existing_value_length, &meta);

        // Fail on invalid metadata.
        if (!status_ok) {
            *success = 0;
            return NULL;
        }
    }

    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "merge_op_full_merge: loaded existing value");

    // In the degenerate case of no operands, succeed and return the original value.
    *success = 1;
    new_data = existing_value;
    new_data_len = existing_value_length;

    // Iterate through the merge operands.
    for (size_t i = 0; i < num_operands; i++) {
        retval = uc_read_metadata(operands_list[i], operands_list_length[i], &merge_op_meta);

        // Fail on invalid metadata.
        if (0 != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "merge_op_full_merge: failed uc_read_metadata: %s", strerror(retval));
            *success = 0;
            return NULL;
        }

        if (merge_op_meta.op == kInc) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "kInc");

            meta.value_type = kLong;
            meta.value += merge_op_meta.cas_value_or_inc;
            meta.modified = merge_op_meta.modified;
            if (!meta.created) {
                meta.created = meta.modified;
            }

            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "merge_op_full_merge: new value: %ld", meta.value);

            // Counters never have anything outside metadata.
            new_data = NULL;
            new_data_len = 0;
        }
        else if (merge_op_meta.op == kAdd) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "kAdd");

            if (existing_value == NULL) {
                meta = merge_op_meta;
                new_data = operands_list[i];
                new_data_len = operands_list_length[i];
            }
        }
        else if (merge_op_meta.op == kCAS) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "kCAS");

            // Compare. If the expected value is the current one, replace it.
            if (meta.value_type == kLong && meta.value == merge_op_meta.cas_value_or_inc) {
                meta = merge_op_meta;

                // CAS values never have anything outside metadata.
                new_data = NULL;
                new_data_len = 0;
            }
        } else {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "merge_op_full_merge: unknown meta.op: %d", meta.op);

            // Unexpected value for meta.op.
            *success = 0;
            return NULL;
        }
    }

    // Combine the data and metadata into a single value.
    *new_value_length = new_data_len + sizeof(meta);
    char *new_value = malloc(*new_value_length);
    if (new_data) {
        memcpy(new_value, &new_data, new_data_len);
    }
    memcpy(new_value + new_data_len, &meta, sizeof(meta));

    return new_value;
}

static char* merge_op_partial_merge(void* arg, const char* key, size_t key_length, const char* const* operands_list, const size_t* operands_list_length, int num_operands, unsigned char* success, size_t* new_value_length) {

    uc_metadata_t meta;
    long net_counter_value = 0;
    int status_ok;
    int retval;

    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "Attempting partial merge.");

    for (size_t i = 0; i < num_operands; i++) {
        retval = uc_read_metadata(operands_list[i], operands_list_length[i], &meta);

        // Fail on invalid metadata.
        if (0 != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "merge_op_partial_merge: failed uc_read_metadata: %s", strerror(retval));
            *success = 0;
            return NULL;
        }

        // Fail on encountering anything other than increment operations.
        if (meta.op != kInc) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "merge_op_partial_merge: non-kInc operation, abandoning partial merge");
            *success = 0;
            return NULL;
        }

        // Aggregate the counter data.
        net_counter_value += meta.value;
    }

    // Use the most recent metadata, but apply the net counter delta.
    meta.value = net_counter_value;

    // Allocate and return a fresh value.
    *new_value_length = sizeof(meta);
    *success = 1;
    char* result = (char*) malloc(sizeof(meta));
    memcpy(result, &meta, sizeof(meta));
    return result;
}

int uc_persistence_init(const char* storage_directory, uc_persistence_t* p)
{
    char* err = NULL;

    // Initialize the database.
    rocksdb_mergeoperator_t* merge_op;
    const char* cf_names[1] = {"default"};
    const rocksdb_options_t* cf_opts[1];
    rocksdb_column_family_handle_t* cfs_h[1];

    p->db_options = rocksdb_options_create();
    p->cf_options = rocksdb_options_create();
    cf_opts[0] = p->cf_options;

    rocksdb_options_set_create_if_missing(p->db_options, 1);
    rocksdb_options_set_create_missing_column_families(p->db_options, 1);
    //rocksdb_options_set_compression(p->db_options, /* rocksdb::kSnappyCompression */ 0x1);
    //rocksdb_options_set_allow_concurrent_memtable_write(p->db_options, 0);
    //rocksdb_options_set_info_log_level(p->db_options, /* InfoLogLevel::DEBUG_LEVEL */ 2);

    // Apply the TTL-enforcing compaction filter.
    p->cfilter = rocksdb_compactionfilter_create(NULL, uc_filter_destory, uc_filter_filter, uc_filter_name);
    rocksdb_options_set_compaction_filter(p->cf_options, p->cfilter);

    // Apply the merge operator.
    merge_op = rocksdb_mergeoperator_create(NULL, merge_op_destroy, merge_op_full_merge, merge_op_partial_merge, NULL, merge_op_name);
    rocksdb_options_set_merge_operator(p->cf_options, merge_op);

    //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "About to open the database.");

    p->db_h = rocksdb_open_column_families(p->db_options, storage_directory, 1, cf_names, cf_opts, cfs_h, &err);
    p->cf_h = cfs_h[0];

    if (err != NULL) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Opening the user cache database failed: %s", err);
        return EIO;
    }

    // @TODO: Check for a clean shutdown. If not, clear the DB.

    rocksdb_free(err);
    err = NULL;

    return 0;
}

int uc_persistence_destroy(uc_persistence_t* p)
{
    // @TODO: Record that there's a clean shutdown and sync.

    rocksdb_column_family_handle_destroy(p->cf_h);
    rocksdb_close(p->db_h);
    rocksdb_options_destroy(p->db_options);
    //rocksdb_compactionfilter_destroy(p->cfilter);
    rocksdb_options_destroy(p->cf_options);
    return 0;
}
