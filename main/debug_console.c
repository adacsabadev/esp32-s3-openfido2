#include "debug_console.h"
#include "ble_fido.h"
#include "credential.h"
#include "log.h"
#include "pin_uv.h"
#include "platform.h"
#include "usb_composite.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define COMMAND_CAP 1024u
#define TX_LOW_WATER 256u
#define KEY_BACKUP_BYTES 569u
#define KEY_BACKUP_DATA_BYTES 565u
#define KEY_BACKUP_B64_BYTES 760u

static char command[COMMAND_CAP];
static uint32_t command_length;
static bool discarding,listing,exporting;
static uint32_t list_index,list_count;

static void append_text(char*out,uint32_t*used,const char*text){
 while(*text)out[(*used)++]=*text++;
}

static void append_u32(char*out,uint32_t*used,uint32_t value){
 char digits[10];uint32_t count=0;
 do{digits[count++]=(char)('0'+value%10u);value/=10u;}while(value);
 while(count)out[(*used)++]=digits[--count];
}

static void append_hex(char*out,uint32_t*used,const uint8_t*value,uint32_t length){
 static const char digits[]="0123456789abcdef";
 for(uint32_t i=0;i<length;i++){
  out[(*used)++]=digits[value[i]>>4];out[(*used)++]=digits[value[i]&15u];
 }
}

static void log_quoted_label(const uint8_t*value,uint16_t length){
 static const char digits[]="0123456789abcdef";
 char chunk[64];uint32_t used=0;
 chunk[used++]='"';
 for(uint32_t i=0;i<length;i++){
  uint8_t byte=value[i];
  if(byte<0x20u||byte==0x7fu||byte=='"'||byte=='\\'){
   if(used+4u>=sizeof chunk){chunk[used]=0;log_puts(chunk);used=0;}
   chunk[used++]='\\';chunk[used++]='x';
   chunk[used++]=digits[byte>>4];chunk[used++]=digits[byte&15u];
  }else{
   if(used+1u>=sizeof chunk){chunk[used]=0;log_puts(chunk);used=0;}
   chunk[used++]=(char)byte;
  }
 }
 if(used+2u>=sizeof chunk){chunk[used]=0;log_puts(chunk);used=0;}
 chunk[used++]='"';chunk[used]=0;log_puts(chunk);
}

static void append_hex32(char*out,uint32_t*used,uint32_t value){
 static const char digits[]="0123456789abcdef";
 for(int shift=28;shift>=0;shift-=4)out[(*used)++]=digits[(value>>shift)&15u];
}

static uint32_t read_le32(const uint8_t*bytes){
 return (uint32_t)bytes[0]|((uint32_t)bytes[1]<<8)|
        ((uint32_t)bytes[2]<<16)|((uint32_t)bytes[3]<<24);
}

static uint16_t read_le16(const uint8_t*bytes){
 return (uint16_t)bytes[0]|((uint16_t)bytes[1]<<8);
}

static void write_le16(uint8_t*bytes,uint16_t value){
 bytes[0]=(uint8_t)value;bytes[1]=(uint8_t)(value>>8);
}

static void write_le32(uint8_t*bytes,uint32_t value){
 bytes[0]=(uint8_t)value;bytes[1]=(uint8_t)(value>>8);
 bytes[2]=(uint8_t)(value>>16);bytes[3]=(uint8_t)(value>>24);
}

static uint32_t backup_crc32(const void*data,size_t length){
 static const uint32_t table[16]={
  0x00000000,0x1db71064,0x3b6e20c8,0x26d930ac,
  0x76dc4190,0x6b6b51f4,0x4db26158,0x5005713c,
  0xedb88320,0xf00f9344,0xd6d6a3e8,0xcb61b38c,
  0x9b64c2b0,0x86d3d2d4,0xa00ae278,0xbdbdf21c};
 uint32_t crc=UINT32_MAX;const uint8_t*bytes=data;
 while(length--){crc^=*bytes++;crc=(crc>>4)^table[crc&15];crc=(crc>>4)^table[crc&15];}
 return ~crc;
}

static void base64_encode(const uint8_t*input,uint32_t length,char*output){
 static const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 uint32_t in=0,out=0;
 while(in+3u<=length){
  uint32_t value=((uint32_t)input[in]<<16)|((uint32_t)input[in+1]<<8)|input[in+2];in+=3;
  output[out++]=alphabet[value>>18];output[out++]=alphabet[(value>>12)&63];
  output[out++]=alphabet[(value>>6)&63];output[out++]=alphabet[value&63];
 }
 if(in<length){
  uint32_t remaining=length-in,value=(uint32_t)input[in]<<16;
  if(remaining==2)value|=(uint32_t)input[in+1]<<8;
  output[out++]=alphabet[value>>18];output[out++]=alphabet[(value>>12)&63];
  output[out++]=remaining==2?alphabet[(value>>6)&63]:'=';output[out++]='=';
 }
 output[out]=0;
}

static int base64_value(char c){
 if(c>='A'&&c<='Z')return c-'A';
 if(c>='a'&&c<='z')return c-'a'+26;
 if(c>='0'&&c<='9')return c-'0'+52;
 if(c=='+')return 62;
 if(c=='/')return 63;
 return -1;
}

static bool base64_decode_key(const char*input,uint8_t output[KEY_BACKUP_BYTES]){
 size_t length=strlen(input);uint32_t out=0;
 if(length!=KEY_BACKUP_B64_BYTES||length%4||input[length-1]!='='||input[length-2]=='=')return false;
 for(size_t i=0;i<length;i+=4){
  int a=base64_value(input[i]),b=base64_value(input[i+1]);
  int c=input[i+2]=='='?-1:base64_value(input[i+2]);
  int d=input[i+3]=='='?-1:base64_value(input[i+3]);
  bool last=i+4==length;
  if(a<0||b<0||(!last&&(c<0||d<0))||(last&&(c<0||input[i+3]!='='))||
     (last&&(c&3)))return false;
  uint32_t value=((uint32_t)a<<18)|((uint32_t)b<<12)|((uint32_t)c<<6)|
                 (d<0?0u:(uint32_t)d);
  output[out++]=(uint8_t)(value>>16);output[out++]=(uint8_t)(value>>8);
  if(d>=0)output[out++]=(uint8_t)value;
 }
 return out==KEY_BACKUP_BYTES;
}

static void serialize_backup(const credential_backup*key,uint8_t out[KEY_BACKUP_BYTES]){
 memset(out,0,KEY_BACKUP_BYTES);memcpy(out,"OFK1",4);out[4]=1;
 out[5]=(key->discoverable?1u:0u)|(key->deleted?2u:0u);
 write_le32(out+8,key->cred.sequence);memcpy(out+12,key->cred.id,32);
 memcpy(out+44,key->cred.rp,32);memcpy(out+76,key->cred.secret,32);
 write_le32(out+108,key->cred.counter);write_le16(out+112,key->user_id_len);
 write_le16(out+114,key->rp_id_len);write_le16(out+116,key->user_name_len);
 write_le16(out+118,key->display_name_len);memcpy(out+120,key->user_id,64);
 memcpy(out+184,key->rp_id,253);memcpy(out+437,key->user_name,64);
 memcpy(out+501,key->display_name,64);
 write_le32(out+565,backup_crc32(out,KEY_BACKUP_DATA_BYTES));
}

static bool deserialize_backup(const uint8_t in[KEY_BACKUP_BYTES],credential_backup*key){
 if(memcmp(in,"OFK1",4)||in[4]!=1||(in[5]&~3u)||in[6]||in[7]||
    read_le32(in+565)!=backup_crc32(in,KEY_BACKUP_DATA_BYTES))return false;
 memset(key,0,sizeof *key);key->discoverable=(in[5]&1u)!=0;key->deleted=(in[5]&2u)!=0;
 key->cred.sequence=read_le32(in+8);memcpy(key->cred.id,in+12,32);
 memcpy(key->cred.rp,in+44,32);memcpy(key->cred.secret,in+76,32);
 key->cred.counter=read_le32(in+108);key->user_id_len=read_le16(in+112);
 key->rp_id_len=read_le16(in+114);key->user_name_len=read_le16(in+116);
 key->display_name_len=read_le16(in+118);memcpy(key->user_id,in+120,64);
 memcpy(key->rp_id,in+184,253);memcpy(key->user_name,in+437,64);
 memcpy(key->display_name,in+501,64);
 return key->user_id_len<=64&&key->rp_id_len<=253&&key->user_name_len<=64&&
        key->display_name_len<=64&&(!key->discoverable||key->user_id_len);
}

static void print_exported_key(uint32_t index){
 credential_backup key;uint8_t binary[KEY_BACKUP_BYTES];char encoded[KEY_BACKUP_B64_BYTES+1];
 if(!credential_backup_get(index,&key)){log_puts("ERR key export failed\r\n");exporting=false;return;}
 log_puts("# rp_id=");
 if(key.rp_id_len)log_quoted_label(key.rp_id,key.rp_id_len);else log_puts("unknown");
 log_puts(" user_name=");
 if(key.user_name_len)log_quoted_label(key.user_name,key.user_name_len);else log_puts("unknown");
 log_puts("\r\n");
 log_debug_printf("export record=%u state=%s discoverable=%s counter=%u rp_id_bytes=%u user_name_bytes=%u",
                  (unsigned)(index+1),key.deleted?"deleted":"active",
                  key.discoverable?"yes":"no",(unsigned)key.cred.counter,
                  (unsigned)key.rp_id_len,(unsigned)key.user_name_len);
 serialize_backup(&key,binary);base64_encode(binary,sizeof binary,encoded);
 log_puts("key ");log_puts(encoded);log_puts("\r\n");
 memset(&key,0,sizeof key);memset(binary,0,sizeof binary);memset(encoded,0,sizeof encoded);
}

static void print_dump_raw_record(const char*label,uint32_t address,
                                  const uint8_t*record){
 char line[80];uint32_t used;
 log_puts(label);log_puts(" address=0x");
 used=0;append_hex32(line,&used,address);line[used]=0;log_puts(line);log_puts("\r\n");
 for(uint32_t offset=0;offset<144;offset+=16){
  used=0;append_hex32(line,&used,address+offset);
  append_text(line,&used," +");append_hex32(line,&used,offset);
  append_text(line,&used,": ");
  append_hex(line,&used,record+offset,16);append_text(line,&used,"\r\n");
  line[used]=0;log_puts(line);
 }
}

static void print_dump_raw(const credential_dump*dump){
 print_dump_raw_record("Credential record",dump->address,dump->record);
 if(dump->has_resident)
  print_dump_raw_record("Resident record",dump->resident_address,dump->resident_record);
 else log_puts("Resident record: none found\r\n");
}

static void print_dump_field(const char*label,const uint8_t*data,uint32_t length){
 char line[160];uint32_t used=0;
 append_text(line,&used,label);append_hex(line,&used,data,length);
 line[used]=0;log_puts(line);log_puts("\r\n");
}

static void print_dump_formatted(const credential_dump*dump){
 const uint8_t*record=dump->record;
 uint32_t magic=read_le32(record),sequence=read_le32(record+4);
 log_puts("Credential record at 0x");
 char line[80];uint32_t used=0;append_hex32(line,&used,dump->address);
 line[used]=0;log_puts(line);log_puts("\r\n");
 log_puts(magic==0x32444946u?" type=active\r\n":
          magic==0x33444946u?" type=deleted tombstone\r\n":" type=invalid\r\n");
 used=0;append_text(line,&used,"sequence=0x");append_hex32(line,&used,sequence);
 append_text(line,&used,(sequence&0x80000000u)?" (resident-linked)\r\n":" (ordinary)\r\n");
 line[used]=0;log_puts(line);
 print_dump_field("credential_id=",record+8,32);
 print_dump_field("rp_id_sha256=",record+40,32);
 print_dump_field("private_scalar=",record+72,32);
 used=0;append_text(line,&used,"counter=");append_u32(line,&used,read_le32(record+104));
 append_text(line,&used," digest_valid=");
 append_text(line,&used,dump->record_valid?"yes\r\n":"no\r\n");
 line[used]=0;log_puts(line);
 print_dump_field("stored_record_digest=",record+108,32);
 used=0;append_text(line,&used,"commit=0x");append_hex32(line,&used,read_le32(record+140));
 append_text(line,&used,"\r\n");line[used]=0;log_puts(line);
 if(!dump->has_resident){log_puts("resident_record=none found\r\n");return;}
 const uint8_t*resident=dump->resident_record;
 used=0;append_text(line,&used,"resident_record_address=0x");
 append_hex32(line,&used,dump->resident_address);append_text(line,&used,"\r\n");
 line[used]=0;log_puts(line);
 used=0;append_text(line,&used,"resident_magic=0x");
 append_hex32(line,&used,read_le32(resident));append_text(line,&used," sequence=");
 append_u32(line,&used,read_le32(resident+4));append_text(line,&used,"\r\n");
 line[used]=0;log_puts(line);
 uint32_t user_id_len=read_le32(resident+104);
 used=0;append_text(line,&used,"user_id_length=");append_u32(line,&used,user_id_len);
 append_text(line,&used," resident_digest_valid=");
 append_text(line,&used,dump->resident_valid?"yes\r\n":"no\r\n");
 line[used]=0;log_puts(line);
 if(user_id_len<=64)print_dump_field("user_handle=",resident+40,user_id_len);
 else log_puts("user_handle=invalid length\r\n");
 print_dump_field("stored_resident_digest=",resident+108,32);
 used=0;append_text(line,&used,"resident_commit=0x");
 append_hex32(line,&used,read_le32(resident+140));append_text(line,&used,"\r\n");
 line[used]=0;log_puts(line);
}

static void print_key(uint32_t index){
 credential_summary key;char line[112];uint32_t used=0;
 if(!credential_list_get(index,&key))return;
 append_text(line,&used,"key id=");append_hex(line,&used,key.id,4);
 append_text(line,&used," rp=");append_hex(line,&used,key.rp,4);
 append_text(line,&used,key.deleted?" state=deleted":" state=active");
 append_text(line,&used," counter=");append_u32(line,&used,key.counter);
 if(!key.deleted)append_text(line,&used,key.discoverable?" discoverable=yes":" discoverable=no");
 append_text(line,&used,"\r\n");
 line[used]=0;log_puts(line);
 log_puts("  rp_id=");
 if(key.labels_available){
  log_quoted_label(key.rp_id,key.rp_id_len);
  log_puts(" user_name=");
  if(key.user_name_len)log_quoted_label(key.user_name,key.user_name_len);
  else log_puts("unknown");
 }else log_puts("unknown user_name=unknown");
 log_puts("\r\n");
}

static int hex_value(char c){
 if(c>='0'&&c<='9')return c-'0';
 if(c>='a'&&c<='f')return c-'a'+10;
 if(c>='A'&&c<='F')return c-'A'+10;
 return -1;
}

static bool parse_hex4(const char*text,uint8_t bytes[4]){
 for(uint32_t i=0;i<4;i++){
  int high=hex_value(text[i*2]),low=hex_value(text[i*2+1]);
  if(high<0||low<0)return false;
  bytes[i]=(uint8_t)((high<<4)|low);
 }
 return true;
}

static bool parse_selector(const char*text,uint8_t id[4],uint8_t rp[4],
                           const char**tail){
 if(strlen(text)<17||text[8]!=' '||!parse_hex4(text,id)||!parse_hex4(text+9,rp))return false;
 if(text[17]&&text[17]!=' ')return false;
 *tail=text+17;
 return true;
}

static void report_credential_result(credential_result result){
 switch(result){
 case CREDENTIAL_OK:log_puts("OK\r\n");break;
 case CREDENTIAL_NOT_FOUND:log_puts("ERR matching credential state not found\r\n");break;
 case CREDENTIAL_AMBIGUOUS:log_puts("ERR fingerprint pair is ambiguous; use distinct fingerprints\r\n");break;
 case CREDENTIAL_NO_USER_HANDLE:log_puts("ERR no stored user handle; re-enroll to enable discoverability\r\n");break;
 case CREDENTIAL_NO_SPACE:log_puts("ERR active or deleted key capacity is full; delete an active key or explicitly purge deleted keys\r\n");break;
 case CREDENTIAL_FLASH_ERROR:log_puts("ERR flash operation failed\r\n");break;
 case CREDENTIAL_INVALID:log_puts("ERR invalid key backup\r\n");break;
 case CREDENTIAL_CONFLICT:log_puts("ERR key identity exists with different private key\r\n");break;
 }
}

static bool valid_pin(const char*pin,size_t length){
 if(length<4||length>63)return false;
 for(size_t i=0;i<length;i++)if(pin[i]<'0'||pin[i]>'9')return false;
 return true;
}

static const char*command_name(const char*text){
 if(!strcmp(text,"help"))return "help";
 if(!strcmp(text,"debug")||!strcmp(text,"debug on")||!strcmp(text,"debug off"))return "debug";
 if(!strcmp(text,"status"))return "status";
 if(!strcmp(text,"ble status"))return "ble status";
 if(!strcmp(text,"ble pair"))return "ble pair";
 if(!strcmp(text,"keys list"))return "keys list";
 if(!strcmp(text,"keys export"))return "keys export";
 if(!strncmp(text,"keys import ",12))return "keys import";
 if(!strncmp(text,"keys dump raw ",14))return "keys dump raw";
 if(!strncmp(text,"keys dump formatted ",20))return "keys dump formatted";
 if(!strcmp(text,"keys erase-all confirm"))return "keys erase-all";
 if(!strcmp(text,"keys compact confirm"))return "keys compact";
 if(!strcmp(text,"keys purge-deleted confirm"))return "keys purge-deleted";
 if(!strncmp(text,"keys purge ",11))return "keys purge";
 if(!strcmp(text,"pin status"))return "pin status";
 if(!strcmp(text,"pin delete confirm"))return "pin delete";
 if(!strncmp(text,"keys delete ",12))return "keys delete";
 if(!strncmp(text,"keys undelete ",14))return "keys undelete";
 if(!strncmp(text,"keys discoverable ",18))return "keys discoverable";
 if(!strncmp(text,"pin set ",8))return "pin set";
 if(!strncmp(text,"pin change ",11))return "pin change";
 return "unsupported";
}

static void execute_command(void){
 command[command_length]=0;
 listing=exporting=false;
 if(!command_length)return;
 const char*name=command_name(command);
 log_puts("Console command begin: ");log_puts(name);log_puts("\r\n");
 if(!strcmp(command,"help")){
  log_puts("General\r\n");
  log_puts("  help                                  Show this command reference\r\n");
  log_puts("  status                                Show uptime, key counts and journal space\r\n");
  log_puts("\r\nDebug logging\r\n");
  log_puts("  debug                                 Show whether verbose logging is enabled\r\n");
  log_puts("  debug on                              Enable and persist verbose flash logging\r\n");
  log_puts("  debug off                             Disable and persist verbose flash logging\r\n");
  log_puts("\r\nBluetooth\r\n");
  log_puts("  ble status                            Show BLE connection, pairing and bond state\r\n");
  log_puts("  ble pair                              Open the BLE pairing window for 60 seconds\r\n");
  log_puts("\r\nKeys - inspect and back up\r\n");
  log_puts("  keys list                             List active and deleted credential records\r\n");
  log_puts("  keys export                           Export all records as commented OFK1 backups\r\n");
  log_puts("  keys import <base64>                  Validate and restore one OFK1 backup record\r\n");
  log_puts("  keys dump raw <id8> <rp8>            Show raw flash bytes for one credential\r\n");
  log_puts("  keys dump formatted <id8> <rp8>      Decode flash fields for one credential\r\n");
  log_puts("\r\nKeys - state and storage\r\n");
  log_puts("  keys delete <id8> <rp8>              Move an active key to deleted state\r\n");
  log_puts("  keys undelete <id8> <rp8>            Restore a deleted key to active state\r\n");
  log_puts("  keys discoverable <id8> <rp8> on|off Change resident/discoverable visibility\r\n");
  log_puts("  keys compact confirm                 Reclaim journal history; retain deleted keys\r\n");
  log_puts("  keys purge <id8> <rp8> confirm       Permanently remove one deleted key\r\n");
  log_puts("  keys purge-deleted confirm           Permanently remove every deleted key\r\n");
  log_puts("  keys erase-all confirm               Permanently remove all keys; keep the PIN\r\n");
  log_puts("\r\nPIN\r\n");
  log_puts("  pin status                            Show whether a PIN is configured\r\n");
  log_puts("  pin set <4-63 digits>                 Configure the initial numeric PIN\r\n");
  log_puts("  pin change <old> <new>                Replace the configured numeric PIN\r\n");
  log_puts("  pin delete confirm                   Remove the configured PIN verifier\r\n");
 }else if(!strcmp(command,"debug")){
  log_puts(log_debug_enabled()?"Debug logging is on\r\n":"Debug logging is off\r\n");
 }else if(!strcmp(command,"debug on")||!strcmp(command,"debug off")){
  bool enabled=!strcmp(command,"debug on");
  if(log_debug_set(enabled))log_puts(enabled?"Debug logging enabled and saved\r\n":
                                            "Debug logging disabled and saved\r\n");
  else log_puts("ERR debug setting could not be saved\r\n");
 }else if(!strcmp(command,"ble status")){
  ble_fido_log_status();
 }else if(!strcmp(command,"ble pair")){
  log_puts(ble_fido_pairing_start()?"BLE pairing mode enabled for 60 seconds\r\n":
           "ERR BLE is not ready or the bond store is full\r\n");
 }else if(!strcmp(command,"pin status")){
  log_puts(pin_uv_configured()?"PIN is configured\r\n":"PIN is not configured\r\n");
 }else if(command_length>=8&&!memcmp(command,"pin set ",8)){
  size_t length=command_length-8;
  if(!valid_pin(command+8,length))log_puts("ERR PIN must contain 4-63 ASCII digits\r\n");
  else if(pin_uv_configured())log_puts("ERR PIN already set; use pin change <old> <new>\r\n");
  else if(pin_uv_set_from_console((const uint8_t*)command+8,length))log_puts("PIN verifier stored\r\n");
  else log_puts("ERR PIN verifier could not be stored\r\n");
 }else if(command_length>11&&!memcmp(command,"pin change ",11)){
  char*old_pin=command+11;char*separator=strchr(old_pin,' ');
  if(!separator||strchr(separator+1,' '))log_puts("ERR use pin change <old> <new>\r\n");
  else{
   size_t old_length=(size_t)(separator-old_pin),new_length=strlen(separator+1);
   *separator=0;
   if(!valid_pin(old_pin,old_length)||!valid_pin(separator+1,new_length))
    log_puts("ERR old and new PINs must each contain 4-63 ASCII digits\r\n");
   else if(!pin_uv_configured())log_puts("ERR PIN is not configured; use pin set <new>\r\n");
   else if(pin_uv_change_from_console((const uint8_t*)old_pin,old_length,
                                     (const uint8_t*)separator+1,new_length))
    log_puts("PIN updated\r\n");
   else log_puts("ERR old PIN incorrect or new PIN could not be stored\r\n");
  }
 }else if(!strcmp(command,"pin delete confirm")){
  if(!pin_uv_configured())log_puts("PIN is not configured\r\n");
  else if(pin_uv_delete())log_puts("PIN deleted\r\n");
  else log_puts("ERR PIN erase failed\r\n");
 }else if(!strcmp(command,"status")){
  credential_journal_stats stats;credential_get_journal_stats(&stats);
  char line[192];uint32_t used=0;
  append_text(line,&used,"uptime_ms=");append_u32(line,&used,platform_millis());
  append_text(line,&used," keys_active=");append_u32(line,&used,stats.active);
  append_text(line,&used," keys_deleted=");append_u32(line,&used,stats.deleted);
  append_text(line,&used," journal_used_slots=");append_u32(line,&used,stats.used_slots);
  append_text(line,&used," journal_free_slots=");append_u32(line,&used,stats.free_slots);
  append_text(line,&used," cdc_rx_dropped=");append_u32(line,&used,usb_cdc_rx_dropped());
  append_text(line,&used," cdc_tx_dropped=");append_u32(line,&used,usb_cdc_tx_dropped());
  append_text(line,&used,"\r\n");line[used]=0;log_puts(line);
  used=0;
  append_text(line,&used,"active_capacity=2048 deleted_capacity=2048 deleted_free_slots=");
  append_u32(line,&used,stats.deleted_free_slots);
  append_text(line,&used," bank_generation=");append_u32(line,&used,stats.generation);
  append_text(line,&used," journal_free_records=");append_u32(line,&used,stats.journal_free_records);
  append_text(line,&used,"\r\n");line[used]=0;log_puts(line);
 }else if(!strcmp(command,"keys list")){
  list_index=0;list_count=credential_list_count();listing=true;
  if(!list_count){log_puts("No credential records\r\n");listing=false;}
  else{
   char line[72];uint32_t used=0;
   append_text(line,&used,"Credential records: ");append_u32(line,&used,list_count);
   append_text(line,&used,"; id/rp are 4-byte fingerprints\r\n");
   line[used]=0;log_puts(line);
  }
 }else if(!strcmp(command,"keys export")){
  list_index=0;list_count=credential_list_count();exporting=true;
  log_debug_printf("export begin records=%u",(unsigned)list_count);
  if(!list_count){log_puts("No credential records\r\n");exporting=false;}
  else{
   char line[64];uint32_t used=0;append_text(line,&used,"Exported key records: ");
   append_u32(line,&used,list_count);append_text(line,&used,"\r\n");line[used]=0;log_puts(line);
  }
 }else if(command_length>12&&!memcmp(command,"keys import ",12)){
  uint8_t binary[KEY_BACKUP_BYTES];credential_backup key;
  if(!base64_decode_key(command+12,binary)||!deserialize_backup(binary,&key))
   log_puts("ERR invalid padded Base64 key backup\r\n");
  else{
   log_debug_printf("import decoded state=%s discoverable=%s counter=%u rp_id_bytes=%u user_name_bytes=%u",
                    key.deleted?"deleted":"active",key.discoverable?"yes":"no",
                    (unsigned)key.cred.counter,(unsigned)key.rp_id_len,
                    (unsigned)key.user_name_len);
   credential_result result=credential_backup_import(&key);
   log_debug_printf("import complete result=%u",(unsigned)result);
   report_credential_result(result);
  }
  memset(binary,0,sizeof binary);memset(&key,0,sizeof key);
 }else if(command_length>20&&!memcmp(command,"keys dump formatted ",20)){
  uint8_t id[4],rp[4];const char*tail;
  if(!parse_selector(command+20,id,rp,&tail)||*tail)
   log_puts("ERR use keys dump formatted <id8> <rp8>\r\n");
  else{
   credential_dump dump;credential_result result=credential_dump_lookup(id,rp,&dump);
   if(result!=CREDENTIAL_OK)report_credential_result(result);
   else print_dump_formatted(&dump);
  }
 }else if(command_length>14&&!memcmp(command,"keys dump raw ",14)){
  uint8_t id[4],rp[4];const char*tail;
  if(!parse_selector(command+14,id,rp,&tail)||*tail)
   log_puts("ERR use keys dump raw <id8> <rp8>\r\n");
  else{
   credential_dump dump;credential_result result=credential_dump_lookup(id,rp,&dump);
   if(result!=CREDENTIAL_OK)report_credential_result(result);
   else print_dump_raw(&dump);
  }
 }else if(!strcmp(command,"keys erase-all confirm")){
  log_debug_printf("erase-all requested");
  if(credential_erase_all())log_puts("All credentials erased; PIN unchanged\r\n");
  else log_puts("ERR credential-sector erase failed\r\n");
 }else if(!strcmp(command,"keys compact confirm")){
  log_debug_printf("compaction requested");
  if(credential_compact())log_puts("Credential database compacted; deleted keys retained for undelete\r\n");
  else log_puts("ERR compaction failed; recovery snapshot retained if needed; reboot and check status\r\n");
 }else if(!strcmp(command,"keys purge-deleted confirm")){
  log_debug_printf("purge-deleted requested");
  if(credential_purge_deleted())log_puts("Deleted keys permanently purged; active keys and PIN unchanged\r\n");
  else log_puts("ERR purge failed; reboot and check status\r\n");
 }else if(command_length>11&&!memcmp(command,"keys purge ",11)){
  uint8_t id[4],rp[4];const char*tail;
  if(!parse_selector(command+11,id,rp,&tail)||strcmp(tail," confirm"))
   log_puts("ERR use keys purge <id8> <rp8> confirm (deleted keys only)\r\n");
  else{
   log_debug_printf("purge requested id=%02x%02x%02x%02x rp=%02x%02x%02x%02x",
                    id[0],id[1],id[2],id[3],rp[0],rp[1],rp[2],rp[3]);
   report_credential_result(credential_purge(id,rp));
  }
 }else if(command_length>12&&!memcmp(command,"keys delete ",12)){
  uint8_t id[4],rp[4];const char*tail;
  if(!parse_selector(command+12,id,rp,&tail)||*tail)log_puts("ERR use keys delete <id8> <rp8>\r\n");
  else report_credential_result(credential_delete(id,rp));
 }else if(command_length>14&&!memcmp(command,"keys undelete ",14)){
  uint8_t id[4],rp[4];const char*tail;
  if(!parse_selector(command+14,id,rp,&tail)||*tail)log_puts("ERR use keys undelete <id8> <rp8>\r\n");
  else report_credential_result(credential_undelete(id,rp));
 }else if(command_length>18&&!memcmp(command,"keys discoverable ",18)){
  uint8_t id[4],rp[4];const char*tail;
  if(!parse_selector(command+18,id,rp,&tail)||
     (strcmp(tail," on")&&strcmp(tail," off")))
   log_puts("ERR use keys discoverable <id8> <rp8> on|off\r\n");
  else report_credential_result(credential_set_discoverable(id,rp,!strcmp(tail," on")));
 }else{
  log_puts("ERR unsupported command; send help\r\n");
 }
 log_puts("Console command end: ");log_puts(name);log_puts("\r\n");
 memset(command,0,sizeof command);
 command_length=0;
}

void debug_console_poll(void){
 uint8_t byte;
 while(usb_cdc_read(&byte)){
  if(byte=='\r')continue;
  if(byte=='\n'){
   if(discarding)log_puts("ERR command too long; discarded\r\n");
   else execute_command();
   discarding=false;command_length=0;
  }else if(!discarding){
   if(command_length+1u>=COMMAND_CAP)discarding=true;
   else command[command_length++]=(char)byte;
  }
 }
 if(listing&&usb_cdc_pending()<TX_LOW_WATER){
  if(list_index<list_count)print_key(list_index++);
  else{log_puts("End of credential list\r\n");listing=false;}
 }
 if(exporting&&usb_cdc_pending()<TX_LOW_WATER){
  if(list_index<list_count)print_exported_key(list_index++);
  else{log_debug_printf("export complete records=%u",(unsigned)list_count);
       log_puts("End of key export\r\n");exporting=false;}
 }
}
