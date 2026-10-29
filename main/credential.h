#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef struct {
 uint32_t magic,sequence;
 uint8_t id[32],rp[32],secret[32];
 uint32_t counter;
 uint8_t digest[32];
 uint32_t commit;
} credential;
typedef struct {
 uint8_t id[32],rp[32];
 uint8_t rp_id[253],user_name[64];
 uint32_t counter;
 uint16_t rp_id_len,user_name_len;
 bool labels_available;
 bool discoverable,deleted;
} credential_summary;
typedef enum {
 CREDENTIAL_OK,
 CREDENTIAL_NOT_FOUND,
 CREDENTIAL_AMBIGUOUS,
 CREDENTIAL_NO_USER_HANDLE,
 CREDENTIAL_NO_SPACE,
 CREDENTIAL_FLASH_ERROR,
 CREDENTIAL_INVALID,
 CREDENTIAL_CONFLICT
} credential_result;
typedef struct {
 uint32_t active,deleted,used_slots,free_slots;
 uint32_t deleted_free_slots,generation,journal_free_records;
} credential_journal_stats;
typedef struct {
 uint32_t address,resident_address;
 uint8_t record[144],resident_record[144];
 bool has_resident,record_valid,resident_valid;
} credential_dump;
typedef struct {
 credential cred;
 uint8_t user_id[64],rp_id[253],user_name[64],display_name[64];
 uint16_t user_id_len,rp_id_len,user_name_len,display_name_len;
 bool discoverable,deleted;
} credential_backup;
bool credential_storage_init(void);
bool credential_store_init(void);
bool credential_lookup(const uint8_t id[32],const uint8_t rp[32],credential*out);
bool credential_lookup_resident(const uint8_t rp[32],credential*out,
                                uint8_t user_id[64],uint32_t*user_id_len);
bool credential_save(credential*c);
bool credential_room_for_resident(uint32_t rp_id_len,uint32_t user_name_len);
bool credential_save_resident(credential*c,const uint8_t*user_id,uint32_t user_id_len,
                              const uint8_t*rp_id,uint32_t rp_id_len,
                              const uint8_t*user_name,uint32_t user_name_len);
bool credential_save_resident_with_display(credential*c,const uint8_t*user_id,uint32_t user_id_len,
 const uint8_t*rp_id,uint32_t rp_id_len,const uint8_t*user_name,uint32_t user_name_len,
 const uint8_t*display_name,uint32_t display_name_len);
bool credential_room_for(uint32_t slots);
uint32_t credential_list_count(void);
bool credential_list_get(uint32_t index,credential_summary*out);
void credential_get_journal_stats(credential_journal_stats*out);
credential_result credential_delete(const uint8_t id_prefix[4],const uint8_t rp_prefix[4]);
credential_result credential_undelete(const uint8_t id_prefix[4],const uint8_t rp_prefix[4]);
credential_result credential_set_discoverable(const uint8_t id_prefix[4],
                                              const uint8_t rp_prefix[4],bool enabled);
credential_result credential_dump_lookup(const uint8_t id_prefix[4],
                                         const uint8_t rp_prefix[4],
                                         credential_dump*out);
bool credential_backup_get(uint32_t index,credential_backup*out);
credential_result credential_backup_import(const credential_backup*backup);
bool credential_erase_all(void);
bool credential_compact(void);
credential_result credential_purge(const uint8_t id_prefix[4],const uint8_t rp_prefix[4]);
bool credential_purge_deleted(void);
int crypto_random(void *ctx,uint8_t*out,size_t n);
void crypto_hash(const void*p,size_t n,uint8_t out[32]);
bool crypto_generate(credential*c,uint8_t x[32],uint8_t y[32]);
bool crypto_sign(const credential*c,const uint8_t*data,size_t n,uint8_t sig[80],size_t*len);
bool crypto_public_key(const credential*c,uint8_t x[32],uint8_t y[32]);
typedef struct {
 credential_summary summary;
 uint8_t user_id[64],display_name[64];
 uint32_t user_id_len,display_name_len;
} credential_management_info;
/* Physical indices are opaque cursors. Only active discoverable keys qualify. */
credential_result credential_management_get(uint32_t index,credential_management_info*out);
credential_result credential_management_find(const uint8_t id[32],uint32_t*index,
                                              credential_management_info*out);
credential_result credential_management_delete(uint32_t index);
credential_result credential_management_update(uint32_t index,const uint8_t*name,
 uint32_t name_len,const uint8_t*display,uint32_t display_len);
bool credential_management_public_key(uint32_t index,uint8_t x[32],uint8_t y[32]);
uint32_t credential_storage_revision(void);
#define CREDENTIAL_MANAGEMENT_SLOTS 4096u
