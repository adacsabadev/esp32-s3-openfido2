#include "../../main/credential_store.c"

/* Production database code runs against NOR flash (1->0 programming,
   sector erase) and transactionally staged legacy NVS. Fault injection tears
   individual writes/erases, including checkpoint publication and purge. */
typedef struct { bool used; char key[16]; size_t length; uint8_t data[640]; } blob;
static blob disk[20], staged[20], disk_backup[20];
static uint8_t flash[2][FLASH_STORAGE_BANK_BYTES];
static uint8_t flash_backup[2][FLASH_STORAGE_BANK_BYTES];
static int mutation, cut_at = -1, cut_mode;

__attribute__((noinline,noipa)) void *memcpy(void *d,const void *s,size_t n)
{ uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d; }
__attribute__((noinline,noipa)) void *memset(void *d,int c,size_t n)
{ uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d; }
__attribute__((noinline,noipa)) int memcmp(const void *a,const void *b,size_t n)
{ const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0; }
static bool equal(const char *a,const char *b)
{ while(*a&&*a==*b){a++;b++;}return *a==*b; }
static int find_blob(blob *set,const char *key)
{ for(unsigned i=0;i<20;i++)if(set[i].used&&equal(set[i].key,key))return (int)i;return -1; }
void log_puts(const char *text) { (void)text; }
void log_debug_printf(const char *format, ...) { (void)format; }
#ifndef TEST_WITH_HID
void ctaphid_processing_tick(void) {}
#endif
void platform_idle(void) {}
void crypto_hash(const void *p,size_t n,uint8_t out[32])
{ uint32_t crc=crc32(p,n);for(unsigned i=0;i<8;i++)memcpy(out+i*4,&crc,4); }

esp_err_t nvs_open(const char *name,int mode,nvs_handle_t *h)
{ (void)name;(void)mode;memcpy(staged,disk,sizeof disk);*h=1;return ESP_OK; }
esp_err_t nvs_set_blob(nvs_handle_t h,const char *key,const void *data,size_t n)
{
 (void)h;if(n>640)return 9;int i=find_blob(staged,key);
 if(i<0)for(unsigned j=0;j<20;j++)if(!staged[j].used){i=(int)j;break;}
 if(i<0)return 9;memset(&staged[i],0,sizeof staged[i]);
 staged[i].used=true;staged[i].length=n;
 for(unsigned j=0;key[j];j++)staged[i].key[j]=key[j];
 memcpy(staged[i].data,data,n);return ESP_OK;
}
esp_err_t nvs_get_blob(nvs_handle_t h,const char *key,void *data,size_t *n)
{
 (void)h;int i=find_blob(staged,key);if(i<0)return ESP_ERR_NVS_NOT_FOUND;
 if(*n<staged[i].length)return 9;
 *n=staged[i].length;memcpy(data,staged[i].data,*n);return ESP_OK;
}
esp_err_t nvs_erase_key(nvs_handle_t h,const char *key)
{
 (void)h;int i=find_blob(staged,key);if(i<0)return ESP_ERR_NVS_NOT_FOUND;
 memset(&staged[i],0,sizeof staged[i]);return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t h)
{ (void)h;memcpy(disk,staged,sizeof disk);return ESP_OK; }
void nvs_close(nvs_handle_t h) { (void)h; }

bool flash_storage_validate_layout(void) { return true; }
size_t flash_storage_region_size(flash_storage_region bank)
{ return (unsigned)bank<2?FLASH_STORAGE_BANK_BYTES:0; }
uint32_t flash_storage_region_start(flash_storage_region bank)
{ return 0x800000u+(unsigned)bank*FLASH_STORAGE_BANK_BYTES; }
uint32_t flash_storage_address(flash_storage_region bank,size_t offset)
{ return flash_storage_region_start(bank)+(uint32_t)offset; }
static bool range(flash_storage_region bank,size_t offset,size_t size)
{ return (unsigned)bank<2&&offset<=FLASH_STORAGE_BANK_BYTES&&size<=FLASH_STORAGE_BANK_BYTES-offset; }
bool flash_storage_read(flash_storage_region bank,size_t offset,void *out,size_t size)
{ if(!range(bank,offset,size))return false;memcpy(out,flash[bank]+offset,size);return true; }
bool flash_storage_program(flash_storage_region bank,size_t offset,const void *data,size_t size)
{
 if(!range(bank,offset,size)||offset%4||size%4)return false;
 bool fail=mutation++==cut_at;
 size_t count=fail?(cut_mode==0?0:cut_mode==1?size/2:size):size;
 const uint8_t *bytes=data;
 for(size_t i=0;i<count;i++){
  if((flash[bank][offset+i]&bytes[i])!=bytes[i])return false;
  flash[bank][offset+i]&=bytes[i];
 }
 return !fail;
}
bool flash_storage_erase(flash_storage_region bank)
{
 for(size_t offset=0;offset<FLASH_STORAGE_BANK_BYTES;offset+=0x10000){
  bool fail=mutation++==cut_at;
  size_t count=fail?(cut_mode==0?0:cut_mode==1?0x8000:0x10000):0x10000;
  memset(flash[bank]+offset,0xff,count);if(fail)return false;
 }
 return true;
}
bool flash_storage_is_erased(flash_storage_region bank,size_t offset,size_t size)
{ return range(bank,offset,size)&&erased(flash[bank]+offset,size); }

#define CHECK(expr) do { if(!(expr))return __LINE__; } while(0)
static credential make_credential(uint32_t id)
{ credential c={0};memcpy(c.id,&id,4);c.rp[0]=77;c.counter=1;return c; }
static bool add(credential *c)
{ const uint8_t user[]={4,5,6};return credential_save_resident(c,user,3,
 (const uint8_t *)"example.test",12,(const uint8_t *)"tester",6); }
static void fresh(void)
{ memset(flash,0xff,sizeof flash);memset(disk,0,sizeof disk);cut_at=-1;mutation=0; }
static void snapshot(void)
{ memcpy(flash_backup,flash,sizeof flash);memcpy(disk_backup,disk,sizeof disk); }
static void restore(void)
{ memcpy(flash,flash_backup,sizeof flash);memcpy(disk,disk_backup,sizeof disk);cut_at=-1;mutation=0; }
static bool seed_blob(const char *key,const void *data,size_t size)
{
 nvs_handle_t h;if(nvs_open("openfido",NVS_READWRITE,&h)!=ESP_OK)return false;
 bool ok=nvs_set_blob(h,key,data,size)==ESP_OK&&nvs_commit(h)==ESP_OK;nvs_close(h);return ok;
}

int test_basic(void)
{
 fresh();CHECK(credential_store_init());CHECK(credential_list_count()==0);
 credential c[3];for(unsigned i=0;i<3;i++){c[i]=make_credential(i+1);CHECK(add(&c[i]));}
 CHECK(credential_list_count()==3);
 credential_summary summary;credential found;
 for(unsigned i=0;i<3;i++){
  CHECK(credential_list_get(i,&summary));CHECK(!memcmp(summary.id,c[i].id,32));
  CHECK(credential_lookup(c[i].id,c[i].rp,&found));
 }
 CHECK(!credential_list_get(3,&summary));
 c[1].counter=8;CHECK(credential_save(&c[1]));
 CHECK(credential_list_get(1,&summary)&&summary.discoverable&&summary.counter==8&&summary.user_name_len==6);
 CHECK(credential_store_init());CHECK(credential_list_count()==3);
 CHECK(credential_lookup(c[1].id,c[1].rp,&found)&&found.counter==8);
 CHECK(credential_delete(c[1].id,c[1].rp)==CREDENTIAL_OK);
 CHECK(!credential_lookup(c[1].id,c[1].rp,&found));
 credential_journal_stats stats;credential_get_journal_stats(&stats);
 CHECK(stats.active==2&&stats.deleted==1&&stats.free_slots==2046&&stats.deleted_free_slots==2047);
 CHECK(credential_compact());CHECK(credential_store_init());
 CHECK(credential_list_count()==3);
 CHECK(credential_undelete(c[1].id,c[1].rp)==CREDENTIAL_OK);
 CHECK(credential_lookup(c[1].id,c[1].rp,&found)&&found.counter==8);
 CHECK(credential_set_discoverable(c[1].id,c[1].rp,false)==CREDENTIAL_OK);
 CHECK(credential_save(&c[1]));
 CHECK(credential_list_get(1,&summary)&&!summary.discoverable&&summary.labels_available);
 CHECK(credential_delete(c[1].id,c[1].rp)==CREDENTIAL_OK);
 CHECK(credential_purge(c[0].id,c[0].rp)==CREDENTIAL_NOT_FOUND);
 CHECK(credential_purge(c[1].id,c[1].rp)==CREDENTIAL_OK);
 CHECK(credential_undelete(c[1].id,c[1].rp)==CREDENTIAL_NOT_FOUND);
 CHECK(credential_list_count()==2);
 CHECK(credential_delete(c[0].id,c[0].rp)==CREDENTIAL_OK);
 CHECK(credential_purge_deleted());CHECK(credential_store_init());
 CHECK(credential_list_count()==1&&credential_lookup(c[2].id,c[2].rp,&found));
 const uint8_t pin_hash[16]={11};CHECK(seed_blob("pin_hash",pin_hash,16));
 CHECK(credential_erase_all());CHECK(credential_list_count()==0);
 CHECK(find_blob(disk,"pin_hash")>=0);CHECK(credential_store_init());
 CHECK(credential_list_count()==0);
 c[0]=make_credential(99);c[1]=c[0];c[1].id[4]=1;
 CHECK(add(&c[0])&&add(&c[1]));
 CHECK(credential_delete(c[0].id,c[0].rp)==CREDENTIAL_AMBIGUOUS);
 CHECK(credential_erase_all());
 return 0;
}

int test_backup_import(void)
{
 fresh();CHECK(credential_store_init());
 credential active=make_credential(41),deleted=make_credential(42),found;
 memset(active.secret,0x41,sizeof active.secret);active.counter=17;
 memset(deleted.secret,0x42,sizeof deleted.secret);deleted.counter=23;
 CHECK(add(&active));CHECK(credential_save(&deleted));
 CHECK(credential_delete(deleted.id,deleted.rp)==CREDENTIAL_OK);
 credential_backup first,second;
 CHECK(credential_backup_get(0,&first));CHECK(credential_backup_get(1,&second));
 CHECK(first.discoverable&&!first.deleted&&first.user_id_len==3&&first.rp_id_len==12);
 CHECK(!second.discoverable&&second.deleted);
 CHECK(credential_erase_all());CHECK(credential_list_count()==0);
 CHECK(credential_backup_import(&second)==CREDENTIAL_OK);
 CHECK(credential_backup_import(&first)==CREDENTIAL_OK);
 CHECK(credential_lookup(active.id,active.rp,&found)&&found.counter==17);
 CHECK(!credential_lookup(deleted.id,deleted.rp,&found));
 credential_journal_stats stats;credential_get_journal_stats(&stats);
 CHECK(stats.active==1&&stats.deleted==1);
 first.cred.counter=1;
 CHECK(credential_backup_import(&first)==CREDENTIAL_OK);
 CHECK(credential_lookup(active.id,active.rp,&found)&&found.counter==17);
 first.cred.secret[0]^=1;
 CHECK(credential_backup_import(&first)==CREDENTIAL_CONFLICT);
 first.cred.secret[0]^=1;first.discoverable=true;first.user_id_len=0;
 CHECK(credential_backup_import(&first)==CREDENTIAL_INVALID);
 CHECK(credential_store_init());CHECK(credential_lookup(active.id,active.rp,&found));
 return 0;
}

int test_migration(void)
{
 fresh();
 const uint8_t pin_hash[16]={11};CHECK(seed_blob("pin_hash",pin_hash,16));
 for(unsigned i=0;i<3;i++){
  legacy_slot old={0};old.used=true;old.cred=make_credential(i+1);
  old.deleted=i==1;char key[7];legacy_key(i,key);
  CHECK(seed_blob(key,&old,sizeof old));
 }
 snapshot();
 for(int mode=0;mode<3;mode++)for(int cut=0;cut<74;cut++){
  restore();cut_at=cut;cut_mode=mode;(void)credential_store_init();
  cut_at=-1;CHECK(credential_store_init());
  CHECK(credential_list_count()==3);
  credential_journal_stats stats;credential_get_journal_stats(&stats);
  CHECK(stats.active==2&&stats.deleted==1);
  CHECK(find_blob(disk,"pin_hash")>=0&&find_blob(disk,"cred00")<0&&find_blob(disk,"cred01")<0);
 }
 fresh();legacy_slot old={0};old.used=true;old.cred=make_credential(42);
 CHECK(seed_blob("credential",&old,sizeof old));CHECK(credential_store_init());
 credential found;CHECK(credential_lookup(old.cred.id,old.cred.rp,&found));
 CHECK(find_blob(disk,"credential")<0);
 return 0;
}

int test_powerloss(void)
{
 fresh();CHECK(credential_store_init());
 credential c[3];for(unsigned i=0;i<3;i++){c[i]=make_credential(i+1);CHECK(add(&c[i]));}
 c[0].counter=99;CHECK(credential_save(&c[0]));
 CHECK(credential_delete(c[1].id,c[1].rp)==CREDENTIAL_OK);snapshot();
 for(int mode=0;mode<3;mode++)for(int cut=0;cut<3;cut++){
  restore();CHECK(credential_store_init());cut_at=cut;cut_mode=mode;mutation=0;
  c[0].counter=100;(void)credential_save(&c[0]);cut_at=-1;
  CHECK(credential_store_init());credential found;
  CHECK(credential_lookup(c[0].id,c[0].rp,&found));
  CHECK(found.counter==99||found.counter==100);CHECK(credential_list_count()==3);
  if(found.counter==99){c[0].counter=101;CHECK(credential_save(&c[0]));CHECK(credential_store_init());
   CHECK(credential_lookup(c[0].id,c[0].rp,&found)&&found.counter==101);}
 }
 /* The old complete bank remains authoritative until the new header commits.
    After publication, including during old-bank erasure, use the newer bank. */
 for(int purge=0;purge<2;purge++)for(int mode=0;mode<3;mode++)for(int cut=0;cut<138;cut++){
  restore();CHECK(credential_store_init());cut_at=cut;cut_mode=mode;mutation=0;
  if(purge)(void)credential_purge_deleted();else (void)credential_compact();
  cut_at=-1;CHECK(credential_store_init());credential found;
  CHECK(credential_lookup(c[0].id,c[0].rp,&found)&&found.counter==99);
  CHECK(credential_lookup(c[2].id,c[2].rp,&found));
  if(!purge){CHECK(credential_list_count()==3);
   CHECK(credential_undelete(c[1].id,c[1].rp)==CREDENTIAL_OK);}
  else CHECK(credential_list_count()==2||credential_list_count()==3);
 }
 restore();CHECK(credential_store_init());CHECK(credential_compact());
 /* A damaged committed checkpoint must fail closed, not roll counters back. */
 flash[current_bank][HEADER_BYTES+offsetof(disk_record,slot)+offsetof(credential_slot,cred)+104]^=1;
 CHECK(!credential_store_init());
 restore();CHECK(credential_store_init());
 flash[current_bank][entries[0].offset+offsetof(disk_record,checksum)]^=1;
 CHECK(!credential_store_init());
 return 0;
}

int test_capacity(void)
{
 fresh();CHECK(credential_store_init());credential c,found;
 for(unsigned i=1;i<=2048;i++){c=make_credential(i);CHECK(add(&c));}
 CHECK(!credential_room_for(1));c=make_credential(2049);CHECK(!add(&c));
 for(unsigned i=1;i<=2048;i++){c=make_credential(i);CHECK(credential_delete(c.id,c.rp)==CREDENTIAL_OK);}
 CHECK(credential_room_for(2048));CHECK(credential_list_count()==2048);
 for(unsigned i=2049;i<=4096;i++){c=make_credential(i);CHECK(add(&c));}
 credential_journal_stats stats;credential_get_journal_stats(&stats);
 CHECK(stats.active==2048&&stats.deleted==2048&&stats.free_slots==0&&stats.deleted_free_slots==0);
 CHECK(credential_list_count()==4096);
 c=make_credential(2049);CHECK(credential_delete(c.id,c.rp)==CREDENTIAL_NO_SPACE);
 c=make_credential(1);CHECK(credential_undelete(c.id,c.rp)==CREDENTIAL_NO_SPACE);
 c=make_credential(5000);CHECK(!add(&c));
 /* Force automatic compaction with every active/deleted slot occupied. */
 c=make_credential(2049);uint32_t updates=stats.journal_free_records+1;
 for(uint32_t i=0;i<updates;i++){c.counter=i+2;CHECK(credential_save(&c));}
 CHECK(generation==2);CHECK(credential_store_init());
 CHECK(credential_lookup(c.id,c.rp,&found)&&found.counter==c.counter);
 credential_summary summary;
 CHECK(credential_list_get(4095,&summary));CHECK(!credential_list_get(4096,&summary));
 CHECK(credential_purge_deleted());CHECK(credential_store_init());
 CHECK(credential_list_count()==2048);
 credential_get_journal_stats(&stats);
 CHECK(stats.active==2048&&stats.deleted==0&&stats.deleted_free_slots==2048);
 c=make_credential(5000);CHECK(!add(&c)); /* Active quota still full. */
 c=make_credential(2049);CHECK(credential_delete(c.id,c.rp)==CREDENTIAL_OK);
 c=make_credential(5000);CHECK(add(&c));
 CHECK(credential_store_init());CHECK(credential_lookup(c.id,c.rp,&found));
 return 0;
}

bool crypto_public_key(const credential*c,uint8_t x[32],uint8_t y[32])
{ memcpy(x,c->secret,32);memcpy(y,c->secret,32);return true; }

int test_bank_migration(void)
{
 fresh();
 bank_header header={.magic=BANK_MAGIC,.version=1,.generation=9,
  .checkpoint_records=3,.record_bytes=sizeof(legacy_record),.commit=COMMITTED};
 header.checksum=crc32(&header,offsetof(bank_header,checksum));
 memcpy(flash[0],&header,sizeof header);
 for(unsigned i=0;i<3;i++){
  legacy_record record={.magic=RECORD_MAGIC,.index=i,.commit=COMMITTED};
  record.slot.used=true;record.slot.discoverable=true;record.slot.deleted=i==1;
  record.slot.cred=make_credential(i+1);record.slot.cred.counter=80+i;
  record.slot.user_id_len=3;memcpy(record.slot.user_id,"uid",3);
  record.slot.rp_id_len=12;memcpy(record.slot.rp_id,"example.test",12);
  record.slot.user_name_len=6;memcpy(record.slot.user_name,"tester",6);
  record.checksum=crc32(&record,offsetof(legacy_record,checksum));
  memcpy(flash[0]+HEADER_BYTES+i*sizeof record,&record,sizeof record);
 }
 snapshot();
 for(int mode=0;mode<3;mode++)for(int cut=0;cut<74;cut++){
  restore();cut_at=cut;cut_mode=mode;(void)credential_store_init();
  cut_at=-1;CHECK(credential_store_init());
  CHECK(current_format==2&&generation==10&&active_count==2&&deleted_count==1);
  credential c=make_credential(1),found;
  CHECK(credential_lookup(c.id,c.rp,&found)&&found.counter==80);
  credential_management_info info;CHECK(credential_management_get(0,&info)==CREDENTIAL_OK);
  CHECK(info.user_id_len==3&&!memcmp(info.user_id,"uid",3));
  CHECK(info.summary.user_name_len==6&&info.display_name_len==0);
  c=make_credential(2);CHECK(credential_undelete(c.id,c.rp)==CREDENTIAL_OK);
  CHECK(credential_lookup(c.id,c.rp,&found)&&found.counter==81);
 }
 restore();flash[0][HEADER_BYTES+offsetof(legacy_record,checksum)]^=1;
 CHECK(!credential_store_init());
 return 0;
}
