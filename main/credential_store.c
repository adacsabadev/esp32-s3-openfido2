#include "credential.h"
#include "flash_storage.h"
#include "ctaphid.h"
#include "platform.h"
#include "log.h"
#include "nvs.h"
#include <stddef.h>
#include <string.h>

#define ACTIVE_LIMIT 2048u
#define DELETED_LIMIT 2048u
#define INDEX_COUNT (ACTIVE_LIMIT + DELETED_LIMIT)
#define HEADER_BYTES 4096u
#define BANK_MAGIC 0x4244464fu
#define RECORD_MAGIC 0x5244464fu
#define FORMAT_VERSION 2u
#define COMMITTED 0x434f4d54u
#define USED 1u
#define DELETED 2u
#define CREDENTIAL_MAGIC 0x32444946u
#define CREDENTIAL_COMMIT 0x434f4d54u

/* Identical to the previous NVS blob, for migration only. */
typedef struct {
    bool used, deleted, discoverable;
    credential cred;
    uint8_t user_id[64];
    uint32_t user_id_len;
    uint8_t rp_id[253];
    uint16_t rp_id_len;
    uint8_t user_name[64];
    uint16_t user_name_len;
} legacy_slot;

typedef struct {
    bool used, deleted, discoverable;
    credential cred;
    uint8_t user_id[64];
    uint32_t user_id_len;
    uint8_t rp_id[253];
    uint16_t rp_id_len;
    uint8_t user_name[64];
    uint16_t user_name_len;
    uint8_t display_name[64];
    uint16_t display_name_len;
} credential_slot;

typedef struct {
    uint32_t magic, version, generation, checkpoint_records;
    uint32_t record_bytes, reserved, checksum, commit;
} bank_header;

typedef struct {
    uint32_t magic, index;
    credential_slot slot;
    uint32_t checksum, commit;
} disk_record;

typedef struct { uint32_t magic,index; legacy_slot slot; uint32_t checksum,commit; } legacy_record;

typedef struct {
    uint32_t offset, flags;
    uint32_t id_prefix, rp_prefix;
} index_entry;

_Static_assert(sizeof(legacy_slot) == 540, "Credential migration layout changed");
_Static_assert(sizeof(disk_record) == 620, "Flash record layout changed");
_Static_assert(sizeof(bank_header) == 32, "Bank header layout changed");
_Static_assert(HEADER_BYTES + INDEX_COUNT * sizeof(disk_record) <
               FLASH_STORAGE_BANK_BYTES, "Bank cannot hold both key sets");

#define RECORD_COUNT ((FLASH_STORAGE_BANK_BYTES - HEADER_BYTES) / sizeof(disk_record))
static index_entry entries[INDEX_COUNT]; /* 64 KiB; no private-key database in RAM. */
static uint32_t active_count, deleted_count, tail, generation;
static flash_storage_region current_bank;
static bool ready;
static uint32_t current_format,revision;

static uint32_t prefix(const uint8_t bytes[4])
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void storage_yield(void)
{
    ctaphid_processing_tick();
    platform_idle();
}

static uint32_t crc32(const void *data, size_t length)
{
    static const uint32_t table[16] = {
        0x00000000,0x1db71064,0x3b6e20c8,0x26d930ac,
        0x76dc4190,0x6b6b51f4,0x4db26158,0x5005713c,
        0xedb88320,0xf00f9344,0xd6d6a3e8,0xcb61b38c,
        0x9b64c2b0,0x86d3d2d4,0xa00ae278,0xbdbdf21c
    };
    uint32_t crc = UINT32_MAX;
    const uint8_t *bytes = data;
    while (length--) {
        crc ^= *bytes++;
        crc = (crc >> 4) ^ table[crc & 15];
        crc = (crc >> 4) ^ table[crc & 15];
    }
    return ~crc;
}

static bool erased(const void *data, size_t length)
{
    const uint8_t *bytes = data;
    while (length--) if (*bytes++ != 0xff) return false;
    return true;
}

static size_t record_offset(uint32_t ordinal)
{
    return HEADER_BYTES + ordinal * sizeof(disk_record);
}

static bool valid_slot(const credential_slot *slot)
{
    return slot->used && slot->user_id_len <= sizeof slot->user_id &&
        slot->rp_id_len <= sizeof slot->rp_id &&
        slot->user_name_len <= sizeof slot->user_name &&
        slot->display_name_len <= sizeof slot->display_name &&
        (!slot->discoverable || slot->user_id_len != 0);
}

static bool valid_record(const disk_record *record)
{
    return record->commit == COMMITTED && record->magic == RECORD_MAGIC &&
        record->index < INDEX_COUNT &&
        record->checksum == crc32(record, offsetof(disk_record, checksum)) &&
        valid_slot(&record->slot);
}

static bool valid_header(const bank_header *header)
{
    return header->magic == BANK_MAGIC && (header->version == FORMAT_VERSION || header->version == 1) &&
        header->generation != 0 && header->generation != UINT32_MAX &&
        header->record_bytes == (header->version == 1 ? sizeof(legacy_record) : sizeof(disk_record)) &&
        header->checkpoint_records <= INDEX_COUNT &&
        header->checksum == crc32(header, offsetof(bank_header, checksum));
}

static void index_record(const disk_record *record, uint32_t offset)
{
    index_entry *entry = &entries[record->index];
    if (entry->flags & USED) {
        if (entry->flags & DELETED) deleted_count--;
        else active_count--;
    }
    entry->offset = offset;
    entry->flags = USED | (record->slot.deleted ? DELETED : 0);
    entry->id_prefix = prefix(record->slot.cred.id);
    entry->rp_prefix = prefix(record->slot.cred.rp);
    if (record->slot.deleted) deleted_count++;
    else active_count++;
}

/* Read the old format until a complete new bank has been published. */
static bool read_disk_record(flash_storage_region bank,uint32_t offset,
                              uint32_t format,disk_record *record)
{
    if(format != 1)return flash_storage_read(bank,offset,record,sizeof *record);
    legacy_record old;
    if(!flash_storage_read(bank,offset,&old,sizeof old))return false;
    memset(record,0,sizeof *record);
    if(erased(&old,sizeof old)){memset(record,0xff,sizeof *record);return true;}
    record->magic=old.magic;record->index=old.index;record->commit=old.commit;
    if(old.commit != COMMITTED)return true;
    if(old.checksum != crc32(&old,offsetof(legacy_record,checksum)))return false;
    memcpy(&record->slot,&old.slot,offsetof(legacy_slot,user_name_len)+sizeof old.slot.user_name_len);
    record->checksum=crc32(record,offsetof(disk_record,checksum));
    return true;
}

static bool read_entry(unsigned index, credential_slot *slot)
{
    disk_record record;
    if (index >= INDEX_COUNT || !(entries[index].flags & USED) ||
        !read_disk_record(current_bank,entries[index].offset,current_format,&record) ||
        !valid_record(&record) || record.index != index) {
        ready = false;
        return false;
    }
    *slot = record.slot;
    return true;
}

/* The checkpoint must be intact. Only an uncommitted tail write may be skipped.
   Never fall back to an older counter after committed-data corruption. */
static bool load_bank(flash_storage_region bank, const bank_header *header)
{
    memset(entries, 0, sizeof entries);
    active_count = deleted_count = tail = 0;
    current_bank = bank;
    generation = header->generation;
    current_format=header->version;
    for (uint32_t ordinal = 0; ordinal < (FLASH_STORAGE_BANK_BYTES-HEADER_BYTES)/header->record_bytes; ordinal++) {
        disk_record record;
        uint32_t offset = HEADER_BYTES+ordinal*header->record_bytes;
        if (!read_disk_record(bank,offset,header->version,&record)) return false;
        if (erased(&record, sizeof record)) {
            if (ordinal < header->checkpoint_records) return false;
            tail = ordinal;
            return active_count <= ACTIVE_LIMIT && deleted_count <= DELETED_LIMIT;
        }
        tail = ordinal + 1;
        if (record.commit != COMMITTED) {
            if (ordinal < header->checkpoint_records) return false;
            continue; /* Consume a torn tail slot; do not program over it. */
        }
        if (!valid_record(&record)) return false;
        index_record(&record, offset);
        if (!(ordinal & 63u)) storage_yield();
    }
    return active_count <= ACTIVE_LIMIT && deleted_count <= DELETED_LIMIT;
}

static bool prepare_bank(flash_storage_region bank, uint32_t next_generation,
                         uint32_t checkpoint_records)
{
    bank_header header = {
        .magic = BANK_MAGIC, .version = FORMAT_VERSION,
        .generation = next_generation, .checkpoint_records = checkpoint_records,
        .record_bytes = sizeof(disk_record), .reserved = 0,
        .commit = UINT32_MAX
    };
    header.checksum = crc32(&header, offsetof(bank_header, checksum));
    if (!flash_storage_erase(bank) ||
        !flash_storage_program(bank, 0, &header, offsetof(bank_header, commit))) return false;
    bank_header verify;
    return flash_storage_read(bank, 0, &verify, sizeof verify) &&
        !memcmp(&header, &verify, sizeof header);
}

static bool write_record(flash_storage_region bank, uint32_t ordinal,
                         unsigned index, const credential_slot *slot)
{
    disk_record record = {0}, verify;
    record.magic = RECORD_MAGIC;
    record.index = index;
    record.slot = *slot;
    record.checksum = crc32(&record, offsetof(disk_record, checksum));
    record.commit = UINT32_MAX;
    size_t offset = record_offset(ordinal);
    if (ordinal >= RECORD_COUNT ||
        !flash_storage_program(bank, offset, &record, offsetof(disk_record, commit)) ||
        !flash_storage_read(bank, offset, &verify, sizeof verify) ||
        memcmp(&record, &verify, sizeof record)) return false;
    uint32_t commit = COMMITTED;
    if (!flash_storage_program(bank, offset + offsetof(disk_record, commit),
                               &commit, sizeof commit)) return false;
    record.commit = COMMITTED;
    return flash_storage_read(bank, offset, &verify, sizeof verify) &&
        !memcmp(&record, &verify, sizeof record);
}

static bool commit_bank(flash_storage_region bank)
{
    bank_header header;
    if (!flash_storage_read(bank, 0, &header, sizeof header) || !valid_header(&header))
        return false;
    for (uint32_t i = 0; i < header.checkpoint_records; i++) {
        disk_record record;
        if (!flash_storage_read(bank, record_offset(i), &record, sizeof record) ||
            !valid_record(&record)) return false;
        if (!(i & 63u)) storage_yield();
    }
    uint32_t commit = COMMITTED;
    if (!flash_storage_program(bank, offsetof(bank_header, commit),
                               &commit, sizeof commit) ||
        !flash_storage_read(bank, 0, &header, sizeof header) ||
        header.commit != COMMITTED || !valid_header(&header)) return false;
    return load_bank(bank, &header);
}

static void legacy_key(unsigned index, char key[7])
{
    static const char hex[] = "0123456789abcdef";
    memcpy(key, "cred00", 7);
    key[4] = hex[index >> 4];
    key[5] = hex[index & 15];
}

static bool cleanup_legacy(void)
{
    nvs_handle_t handle;
    esp_err_t status = nvs_open("openfido", NVS_READWRITE, &handle);
    if (status != ESP_OK) return false;
    for (unsigned i = 0; i <= 16; i++) {
        char key[7];
        legacy_key(i < 16 ? i : 0, key);
        status = nvs_erase_key(handle, i == 16 ? "credential" : key);
        if (status != ESP_OK && status != ESP_ERR_NVS_NOT_FOUND) break;
    }
    if (status == ESP_OK || status == ESP_ERR_NVS_NOT_FOUND) status = nvs_commit(handle);
    nvs_close(handle);
    return status == ESP_OK;
}

static bool read_legacy(nvs_handle_t handle, const char *key,
                        credential_slot *slot, bool *found)
{
    memset(slot, 0, sizeof *slot);
    size_t length = sizeof(legacy_slot);
    esp_err_t status = nvs_get_blob(handle, key, slot, &length);
    *found = status == ESP_OK;
    if (status == ESP_ERR_NVS_NOT_FOUND) return true;
    return status == ESP_OK && length == sizeof(legacy_slot) &&
        (!slot->used || valid_slot(slot));
}

static bool initialize_from_legacy(void)
{
    nvs_handle_t handle;
    if (nvs_open("openfido", NVS_READWRITE, &handle) != ESP_OK) return false;
    uint32_t count = 0;
    bool collection_found = false;
    credential_slot slot;
    for (unsigned i = 0; i < 16; i++) {
        char key[7]; bool found;
        legacy_key(i, key);
        if (!read_legacy(handle, key, &slot, &found)) { nvs_close(handle); return false; }
        collection_found |= found;
        if (found && slot.used) count++;
    }
    if (!collection_found) {
        bool found;
        if (!read_legacy(handle, "credential", &slot, &found)) {
            nvs_close(handle); return false;
        }
        if (found && slot.used) count = 1;
    }
    if (!prepare_bank(FLASH_STORAGE_JOURNAL, 1, count)) { nvs_close(handle); return false; }
    unsigned ordinal = 0;
    for (unsigned i = 0; i < (collection_found ? 16u : 1u); i++) {
        char key[7]; bool found;
        legacy_key(i, key);
        if (!read_legacy(handle, collection_found ? key : "credential", &slot, &found) ||
            (found && slot.used && !write_record(FLASH_STORAGE_JOURNAL, ordinal,
                                                 ordinal, &slot))) {
            nvs_close(handle); return false;
        }
        if (found && slot.used) ordinal++;
    }
    nvs_close(handle);
    return commit_bank(FLASH_STORAGE_JOURNAL);
}

bool credential_store_init(void)
{
    ready = false;
    if (!flash_storage_validate_layout()) return false;
    bank_header headers[2];
    bool valid[2];
    for (unsigned i = 0; i < 2; i++) {
        if (!flash_storage_read((flash_storage_region)i, 0, &headers[i], sizeof headers[i]))
            return false;
        valid[i] = valid_header(&headers[i]) && headers[i].commit == COMMITTED;
        if (headers[i].commit == COMMITTED && !valid[i]) {
            log_puts("ERR committed credential bank header is corrupt\r\n");
            return false;
        }
    }
    bool ok;
    if (valid[0] || valid[1]) {
        unsigned selected = valid[1] && (!valid[0] ||
            headers[1].generation > headers[0].generation) ? 1u : 0u;
        ok = load_bank((flash_storage_region)selected, &headers[selected]);
    } else {
        /* Only fresh flash or interrupted first initialization may import NVS. */
        for (unsigned i = 0; i < 2; i++) {
            if (!erased(&headers[i], sizeof headers[i]) &&
                headers[i].generation != 1 && headers[i].generation != UINT32_MAX)
                return false;
        }
        ok = initialize_from_legacy();
    }
    ready=ok;
    if(ok && current_format==1)ok=credential_compact();
    if (!ok || !cleanup_legacy()) {
        log_puts("ERR credential database recovery failed; refusing rollback\r\n");
        return false;
    }
    ready = true;
    revision++;
    log_puts("Credential database ready: 2048 active + 2048 deleted; dual 4 MiB banks\r\n");
    return true;
}

typedef enum { KEEP_ALL, KEEP_ACTIVE, KEEP_EXCEPT, KEEP_NONE } retain_mode;
static bool retain(unsigned index, retain_mode mode, unsigned excluded)
{
    return (entries[index].flags & USED) && mode != KEEP_NONE &&
        (mode != KEEP_ACTIVE || !(entries[index].flags & DELETED)) &&
        (mode != KEEP_EXCEPT || index != excluded);
}

static bool rotate_bank(retain_mode mode, unsigned excluded, bool erase_old)
{
    if (!ready || generation >= UINT32_MAX - 1u) {
        log_debug_printf("bank rotation rejected ready=%s generation=%u",
                         ready?"yes":"no",(unsigned)generation);
        return false;
    }
    flash_storage_region old = current_bank;
    flash_storage_region next = old == FLASH_STORAGE_JOURNAL ?
        FLASH_STORAGE_SNAPSHOT : FLASH_STORAGE_JOURNAL;
    uint32_t count = 0;
    for (unsigned i = 0; i < INDEX_COUNT; i++) count += retain(i, mode, excluded);
    log_debug_printf("bank rotation begin old=%u next=%u generation=%u->%u retain_mode=%u records=%u erase_old=%s",
                     (unsigned)old,(unsigned)next,(unsigned)generation,
                     (unsigned)(generation+1),(unsigned)mode,(unsigned)count,
                     erase_old?"yes":"no");
    if (!prepare_bank(next, generation + 1, count)) { ready = false; return false; }
    uint32_t ordinal = 0;
    for (unsigned i = 0; i < INDEX_COUNT; i++) {
        if (!retain(i, mode, excluded)) continue;
        credential_slot slot;
        if (!read_entry(i, &slot) || !write_record(next, ordinal++, i, &slot)) {
            ready = false; return false;
        }
        if (!(ordinal & 63u)) storage_yield();
    }
    if (!commit_bank(next)) { ready = false; return false; }
    if (erase_old && !flash_storage_erase(old)) { ready = false; return false; }
    revision++;
    log_debug_printf("bank rotation complete current=%u generation=%u records=%u result=ok",
                     (unsigned)current_bank,(unsigned)generation,(unsigned)count);
    return true;
}

static bool persist(unsigned index, const credential_slot *slot)
{
    if (!ready) return false;
    if (tail >= RECORD_COUNT && !rotate_bank(KEEP_ALL, 0, false)) return false;
    if (!write_record(current_bank, tail, index, slot)) {
        ready = false; /* Reboot rescans a possibly committed/torn final write. */
        return false;
    }
    log_debug_printf("journal append bank=%u ordinal=%u index=%u state=%s counter=%u result=ok",
                     (unsigned)current_bank,(unsigned)tail,index,
                     slot->deleted?"deleted":"active",(unsigned)slot->cred.counter);
    disk_record record = { .index = index, .slot = *slot };
    index_record(&record, (uint32_t)record_offset(tail++));
    revision++;
    return true;
}

static int free_index(void)
{
    for (unsigned i = 0; i < INDEX_COUNT; i++) if (!(entries[i].flags & USED)) return (int)i;
    return -1;
}

static int find_identity(const uint8_t id[32], const uint8_t rp[32])
{
    uint32_t id_prefix = prefix(id), rp_prefix = prefix(rp);
    for (unsigned i = 0; i < INDEX_COUNT; i++) {
        if (!(entries[i].flags & USED) || entries[i].id_prefix != id_prefix ||
            entries[i].rp_prefix != rp_prefix) continue;
        credential_slot slot;
        if (!read_entry(i, &slot)) return -1;
        if (!memcmp(slot.cred.id, id, 32) && !memcmp(slot.cred.rp, rp, 32)) return (int)i;
    }
    return -1;
}

bool credential_lookup(const uint8_t id[32], const uint8_t rp[32], credential *out)
{
    if (!ready || !id || !rp || !out) return false;
    int index = find_identity(id, rp);
    credential_slot slot;
    if (index < 0 || (entries[index].flags & DELETED) || !read_entry(index, &slot))
        return false;
    *out = slot.cred;
    return true;
}

bool credential_lookup_resident(const uint8_t rp[32], credential *out,
                                uint8_t user_id[64], uint32_t *user_id_len)
{
    if (!ready || !rp || !out || !user_id || !user_id_len) return false;
    uint32_t rp_prefix = prefix(rp);
    for (unsigned i = 0; i < INDEX_COUNT; i++) {
        if (!(entries[i].flags & USED) || (entries[i].flags & DELETED) ||
            entries[i].rp_prefix != rp_prefix) continue;
        credential_slot slot;
        if (!read_entry(i, &slot)) return false;
        if (!slot.discoverable || memcmp(slot.cred.rp, rp, 32)) continue;
        *out = slot.cred;
        memcpy(user_id, slot.user_id, slot.user_id_len);
        *user_id_len = slot.user_id_len;
        return true;
    }
    return false;
}

bool credential_save(credential *c)
{
    if (!ready || !c) return false;
    int index = find_identity(c->id, c->rp);
    credential_slot candidate = {0};
    if (index >= 0) {
        if ((entries[index].flags & DELETED) || !read_entry(index, &candidate)) return false;
    } else {
        if (active_count >= ACTIVE_LIMIT || (index = free_index()) < 0) return false;
        candidate.used = true;
    }
    candidate.cred = *c;
    return persist(index, &candidate);
}

bool credential_room_for(uint32_t count)
{
    return ready && count <= ACTIVE_LIMIT - active_count;
}

bool credential_room_for_resident(uint32_t rp_id_len, uint32_t user_name_len)
{
    return rp_id_len > 0 && rp_id_len <= 253 && user_name_len <= 64 && credential_room_for(1);
}

bool credential_save_resident(credential *c, const uint8_t *user_id,
                              uint32_t user_id_len, const uint8_t *rp_id,
                              uint32_t rp_id_len, const uint8_t *user_name,
                              uint32_t user_name_len)
{
    return credential_save_resident_with_display(c,user_id,user_id_len,rp_id,rp_id_len,
                                                 user_name,user_name_len,NULL,0);
}

bool credential_save_resident_with_display(credential *c,const uint8_t *user_id,
 uint32_t user_id_len,const uint8_t *rp_id,uint32_t rp_id_len,
 const uint8_t *user_name,uint32_t user_name_len,
 const uint8_t *display_name,uint32_t display_name_len)
{
    if (!ready || !c || !user_id || !user_id_len || user_id_len > 64 ||
        !rp_id || !rp_id_len || rp_id_len > 253 || user_name_len > 64 ||
        (user_name_len && !user_name) || display_name_len>64 ||
        (display_name_len && !display_name)) return false;
    int index = find_identity(c->id, c->rp);
    if (index >= 0 && (entries[index].flags & DELETED)) return false;
    if (index < 0 && (active_count >= ACTIVE_LIMIT || (index = free_index()) < 0)) return false;
    credential_slot candidate = {0};
    candidate.used = candidate.discoverable = true;
    candidate.cred = *c;
    memcpy(candidate.user_id, user_id, user_id_len);
    candidate.user_id_len = user_id_len;
    memcpy(candidate.rp_id, rp_id, rp_id_len);
    candidate.rp_id_len = (uint16_t)rp_id_len;
    if (user_name_len) memcpy(candidate.user_name, user_name, user_name_len);
    candidate.user_name_len = (uint16_t)user_name_len;
    if(display_name_len)memcpy(candidate.display_name,display_name,display_name_len);
    candidate.display_name_len=display_name_len;
    return persist(index, &candidate);
}

uint32_t credential_list_count(void)
{
    return ready ? active_count + deleted_count : 0;
}

bool credential_list_get(uint32_t index, credential_summary *out)
{
    if (!ready || !out) return false;
    for (unsigned i = 0; i < INDEX_COUNT; i++) {
        if (!(entries[i].flags & USED)) continue;
        if (index--) continue;
        credential_slot slot;
        if (!read_entry(i, &slot)) return false;
        memset(out, 0, sizeof *out);
        memcpy(out->id, slot.cred.id, 32);
        memcpy(out->rp, slot.cred.rp, 32);
        out->counter = slot.cred.counter;
        out->discoverable = slot.discoverable;
        out->deleted = slot.deleted;
        out->labels_available = slot.rp_id_len != 0;
        memcpy(out->rp_id, slot.rp_id, slot.rp_id_len);
        memcpy(out->user_name, slot.user_name, slot.user_name_len);
        out->rp_id_len = slot.rp_id_len;
        out->user_name_len = slot.user_name_len;
        return true;
    }
    return false;
}

void credential_get_journal_stats(credential_journal_stats *out)
{
    if (!out) return;
    out->active = active_count;
    out->deleted = deleted_count;
    out->used_slots = active_count + deleted_count;
    out->free_slots = ACTIVE_LIMIT - active_count;
    out->deleted_free_slots = DELETED_LIMIT - deleted_count;
    out->generation = generation;
    out->journal_free_records = RECORD_COUNT - tail;
}

static credential_result selector_match(const uint8_t id[4], const uint8_t rp[4],
                                        unsigned *index)
{
    if (!ready) return CREDENTIAL_FLASH_ERROR;
    bool found = false;
    uint32_t id_prefix = prefix(id), rp_prefix = prefix(rp);
    for (unsigned i = 0; i < INDEX_COUNT; i++) {
        if ((entries[i].flags & USED) && entries[i].id_prefix == id_prefix &&
            entries[i].rp_prefix == rp_prefix) {
            if (found) return CREDENTIAL_AMBIGUOUS;
            found = true; *index = i;
        }
    }
    return found ? CREDENTIAL_OK : CREDENTIAL_NOT_FOUND;
}

static credential_result set_flag(const uint8_t id[4], const uint8_t rp[4],
                                  bool discoverable, bool value)
{
    unsigned index = 0;
    credential_result result = selector_match(id, rp, &index);
    if (result != CREDENTIAL_OK) return result;
    credential_slot candidate;
    if (!read_entry(index, &candidate)) return CREDENTIAL_FLASH_ERROR;
    if (discoverable) {
        if (value && !candidate.user_id_len) return CREDENTIAL_NO_USER_HANDLE;
        candidate.discoverable = value;
    } else {
        if (candidate.deleted == value) return CREDENTIAL_OK;
        if (value ? deleted_count >= DELETED_LIMIT : active_count >= ACTIVE_LIMIT)
            return CREDENTIAL_NO_SPACE;
        candidate.deleted = value;
    }
    return persist(index, &candidate) ? CREDENTIAL_OK : CREDENTIAL_FLASH_ERROR;
}

credential_result credential_delete(const uint8_t id[4], const uint8_t rp[4])
{ return set_flag(id, rp, false, true); }
credential_result credential_undelete(const uint8_t id[4], const uint8_t rp[4])
{ return set_flag(id, rp, false, false); }
credential_result credential_set_discoverable(const uint8_t id[4], const uint8_t rp[4], bool enabled)
{ return set_flag(id, rp, true, enabled); }

credential_result credential_purge(const uint8_t id[4], const uint8_t rp[4])
{
    unsigned index = 0;
    credential_result result = selector_match(id, rp, &index);
    if (result != CREDENTIAL_OK) return result;
    if (!(entries[index].flags & DELETED)) return CREDENTIAL_NOT_FOUND;
    return rotate_bank(KEEP_EXCEPT, index, true) ? CREDENTIAL_OK : CREDENTIAL_FLASH_ERROR;
}

credential_result credential_dump_lookup(const uint8_t id[4], const uint8_t rp[4],
                                         credential_dump *out)
{
    unsigned index = 0;
    credential_result result = selector_match(id, rp, &index);
    if (result != CREDENTIAL_OK || !out) return result == CREDENTIAL_OK ?
        CREDENTIAL_NOT_FOUND : result;
    credential_slot slot;
    if (!read_entry(index, &slot)) return CREDENTIAL_FLASH_ERROR;
    memset(out, 0, sizeof *out);
    out->address = flash_storage_address(current_bank, entries[index].offset +
        offsetof(disk_record, slot) + offsetof(credential_slot, cred));
    out->record_valid = true; /* The enclosing flash record CRC was verified. */
    memcpy(out->record, &slot.cred, sizeof slot.cred);
    if (slot.user_id_len) {
        /* Preserve the console's legacy 144-byte resident view. */
        uint32_t magic = 0x32524446u, sequence = slot.cred.sequence, commit = COMMITTED;
        memcpy(out->resident_record, &magic, 4);
        memcpy(out->resident_record + 4, &sequence, 4);
        memcpy(out->resident_record + 8, slot.cred.id, 32);
        memcpy(out->resident_record + 40, slot.user_id, slot.user_id_len);
        memcpy(out->resident_record + 104, &slot.user_id_len, 4);
        crypto_hash(out->resident_record, 108, out->resident_record + 108);
        memcpy(out->resident_record + 140, &commit, 4);
        out->has_resident = out->resident_valid = true;
        /* This resident view is synthesized, not a separately mapped record. */
    }
    return CREDENTIAL_OK;
}

bool credential_backup_get(uint32_t ordinal, credential_backup *out)
{
    if (!ready || !out) return false;
    for (unsigned i = 0; i < INDEX_COUNT; i++) {
        if (!(entries[i].flags & USED)) continue;
        if (ordinal--) continue;
        credential_slot slot;
        if (!read_entry(i, &slot)) return false;
        memset(out, 0, sizeof *out);
        out->cred = slot.cred;
        memcpy(out->user_id, slot.user_id, slot.user_id_len);
        memcpy(out->rp_id, slot.rp_id, slot.rp_id_len);
        memcpy(out->user_name, slot.user_name, slot.user_name_len);
        memcpy(out->display_name, slot.display_name, slot.display_name_len);
        out->user_id_len = (uint16_t)slot.user_id_len;
        out->rp_id_len = slot.rp_id_len;
        out->user_name_len = slot.user_name_len;
        out->display_name_len = slot.display_name_len;
        out->discoverable = slot.discoverable;
        out->deleted = slot.deleted;
        return true;
    }
    return false;
}

credential_result credential_backup_import(const credential_backup *backup)
{
    if (!ready || !backup || backup->user_id_len > sizeof backup->user_id ||
        backup->rp_id_len > sizeof backup->rp_id ||
        backup->user_name_len > sizeof backup->user_name ||
        backup->display_name_len > sizeof backup->display_name ||
        (backup->discoverable && !backup->user_id_len)) return CREDENTIAL_INVALID;
    uint8_t public_x[32], public_y[32];
    if (!crypto_public_key(&backup->cred, public_x, public_y))
        return CREDENTIAL_INVALID;
    memset(public_x, 0, sizeof public_x);
    memset(public_y, 0, sizeof public_y);

    credential_slot candidate = {0}, existing = {0};
    int index = find_identity(backup->cred.id, backup->cred.rp);
    bool replacing = index >= 0;
    if (replacing) {
        if (!read_entry((unsigned)index, &existing)) return CREDENTIAL_FLASH_ERROR;
        if (memcmp(existing.cred.secret, backup->cred.secret,
                   sizeof existing.cred.secret)) return CREDENTIAL_CONFLICT;
        if (existing.deleted != backup->deleted) {
            if (backup->deleted && deleted_count >= DELETED_LIMIT)
                return CREDENTIAL_NO_SPACE;
            if (!backup->deleted && active_count >= ACTIVE_LIMIT)
                return CREDENTIAL_NO_SPACE;
        }
    } else if ((backup->deleted ? deleted_count >= DELETED_LIMIT :
                active_count >= ACTIVE_LIMIT) || (index = free_index()) < 0) {
        return CREDENTIAL_NO_SPACE;
    }

    candidate.used = true;
    candidate.deleted = backup->deleted;
    candidate.discoverable = backup->discoverable;
    candidate.cred = backup->cred;
    if (replacing && existing.cred.counter > candidate.cred.counter)
        candidate.cred.counter = existing.cred.counter;
    candidate.cred.magic = CREDENTIAL_MAGIC;
    candidate.cred.commit = CREDENTIAL_COMMIT;
    crypto_hash(&candidate.cred, offsetof(credential, digest), candidate.cred.digest);
    memcpy(candidate.user_id, backup->user_id, backup->user_id_len);
    memcpy(candidate.rp_id, backup->rp_id, backup->rp_id_len);
    memcpy(candidate.user_name, backup->user_name, backup->user_name_len);
    memcpy(candidate.display_name, backup->display_name, backup->display_name_len);
    candidate.user_id_len = backup->user_id_len;
    candidate.rp_id_len = backup->rp_id_len;
    candidate.user_name_len = backup->user_name_len;
    candidate.display_name_len = backup->display_name_len;
    return persist((unsigned)index, &candidate) ? CREDENTIAL_OK : CREDENTIAL_FLASH_ERROR;
}

bool credential_erase_all(void) { return rotate_bank(KEEP_NONE, 0, true); }
bool credential_compact(void) { return rotate_bank(KEEP_ALL, 0, false); }
bool credential_purge_deleted(void) { return rotate_bank(KEEP_ACTIVE, 0, true); }

uint32_t credential_storage_revision(void) { return revision; }
credential_result credential_management_get(uint32_t index,credential_management_info *out)
{
    if(!ready)return CREDENTIAL_FLASH_ERROR;
    if(!out || index>=INDEX_COUNT || !(entries[index].flags&USED) ||
       (entries[index].flags&DELETED))return CREDENTIAL_NOT_FOUND;
    credential_slot slot;
    if(!read_entry(index,&slot))return CREDENTIAL_FLASH_ERROR;
    if(!slot.discoverable)return CREDENTIAL_NOT_FOUND;
    memset(out,0,sizeof *out);
    credential_summary *v=&out->summary;
    memcpy(v->id,slot.cred.id,32);memcpy(v->rp,slot.cred.rp,32);
    memcpy(v->rp_id,slot.rp_id,slot.rp_id_len);v->rp_id_len=slot.rp_id_len;
    memcpy(v->user_name,slot.user_name,slot.user_name_len);v->user_name_len=slot.user_name_len;
    v->counter=slot.cred.counter;v->discoverable=true;v->labels_available=slot.rp_id_len!=0;
    memcpy(out->user_id,slot.user_id,slot.user_id_len);out->user_id_len=slot.user_id_len;
    memcpy(out->display_name,slot.display_name,slot.display_name_len);
    out->display_name_len=slot.display_name_len;
    return CREDENTIAL_OK;
}
credential_result credential_management_find(const uint8_t id[32],uint32_t *index,
                                              credential_management_info *out)
{
    if(!ready)return CREDENTIAL_FLASH_ERROR;
    for(unsigned i=0;i<INDEX_COUNT;i++){
        if(!(entries[i].flags&USED) || (entries[i].flags&DELETED) ||
           entries[i].id_prefix!=prefix(id))continue;
        credential_result r=credential_management_get(i,out);
        if(r==CREDENTIAL_FLASH_ERROR)return r;
        if(r==CREDENTIAL_OK && !memcmp(out->summary.id,id,32)){*index=i;return r;}
    }
    return CREDENTIAL_NOT_FOUND;
}
credential_result credential_management_delete(uint32_t index)
{
    credential_management_info info;
    credential_result r=credential_management_get(index,&info);
    if(r!=CREDENTIAL_OK)return r;
    if(deleted_count>=DELETED_LIMIT)return CREDENTIAL_NO_SPACE;
    credential_slot slot;
    if(!read_entry(index,&slot))return CREDENTIAL_FLASH_ERROR;
    slot.deleted=true;
    return persist(index,&slot)?CREDENTIAL_OK:CREDENTIAL_FLASH_ERROR;
}
credential_result credential_management_update(uint32_t index,const uint8_t *name,
 uint32_t name_len,const uint8_t *display,uint32_t display_len)
{
    credential_management_info info;
    credential_result r=credential_management_get(index,&info);
    if(r!=CREDENTIAL_OK)return r;
    if(name_len>64 || display_len>64)return CREDENTIAL_NO_SPACE;
    credential_slot slot;
    if(!read_entry(index,&slot))return CREDENTIAL_FLASH_ERROR;
    memset(slot.user_name,0,sizeof slot.user_name);memset(slot.display_name,0,sizeof slot.display_name);
    if(name_len)memcpy(slot.user_name,name,name_len);
    if(display_len)memcpy(slot.display_name,display,display_len);
    slot.user_name_len=name_len;slot.display_name_len=display_len;
    return persist(index,&slot)?CREDENTIAL_OK:CREDENTIAL_FLASH_ERROR;
}
bool credential_management_public_key(uint32_t index,uint8_t x[32],uint8_t y[32])
{
    credential_slot slot;
    if(!ready || index>=INDEX_COUNT || !(entries[index].flags&USED) ||
       (entries[index].flags&DELETED) || !read_entry(index,&slot))return false;
    bool ok=slot.discoverable && crypto_public_key(&slot.cred,x,y);
    memset(&slot,0,sizeof slot);return ok;
}
