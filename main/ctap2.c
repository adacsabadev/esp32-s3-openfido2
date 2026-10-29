#include "ctap2.h"
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif
#include "cbor_min.h"
#include "credential.h"
#include "pin_uv.h"
#include "cred_mgmt.h"
#include "log.h"
#include "indicators.h"
#include "platform.h"
#include <string.h>
static uint8_t request_copy[1200],client_hash[32],rp_hash[32];
static uint8_t operation;
static bool excluded,presence_required;
static uint32_t started;
static credential selected;
static uint8_t selected_user_id[64];
static uint32_t selected_user_id_len;
static uint8_t selected_rp_id[253],selected_user_name[64];
static uint32_t selected_rp_id_len,selected_user_name_len;
static uint8_t selected_display_name[64];
static uint32_t selected_display_name_len;
/* Stable model identity, shared by this project's devices; UUID byte order.
   adacdef0-3644-43dd-84da-d27bda711983. Never derive from a board serial. */
static const uint8_t aaguid[16]={
 0xad,0xac,0xde,0xf0,0x36,0x44,0x43,0xdd,
 0x84,0xda,0xd2,0x7b,0xda,0x71,0x19,0x83
};
static bool operation_uv_verified;
/* Intentional user policy: RAM-only retries reset to 8 on reboot to avoid
   accidental persistent lockout. Do not persist without an explicit request.
   See MEMORY.md. The configured PIN verifier is stored separately in NVS. */
static uint8_t pin_retries=8;
static uint8_t pin_token[32],pin_cipher[80],pin_hash[32],pin_auth[32];
static uint16_t error(uint8_t*out,uint8_t code){out[0]=code;return 1;}
static uint16_t assertion_error(uint8_t*out,uint8_t code,const char*reason){
 log_puts("CTAP2 GetAssertion rejected: ");log_puts(reason);log_puts("\r\n");
 return error(out,code);
}
static uint16_t pin_error(uint8_t*out,uint8_t code){out[0]=code;return 1;}
static void be32(uint8_t*p,uint32_t n){p[0]=(uint8_t)(n>>24);p[1]=(uint8_t)(n>>16);p[2]=(uint8_t)(n>>8);p[3]=(uint8_t)n;}
static bool bytes_field(cb_view map,int key,const char*name,unsigned type,cb_view*out){
 cb_view v;return cb_find(map,key,name,&v)&&cb_bytes(v,type,out);
}
static bool text_is(cb_view v,const char*s){cb_view t;return cb_bytes(v,3,&t)&&t.n==strlen(s)&&!memcmp(t.p,s,t.n);}
static bool pin_fields(cb_view root,uint8_t shared[32]){
 cb_view protocol,agreement,xv,yv;int64_t number;uint8_t x[32],y[32];
 if(!cb_find(root,1,0,&protocol)||!cb_int(protocol,&number)||number!=1
  ||!cb_find(root,3,0,&agreement)
  ||!cb_find(agreement,1,0,&protocol)||!cb_int(protocol,&number)||number!=2
  ||!cb_find(agreement,3,0,&protocol)||!cb_int(protocol,&number)||number!=-25
  ||!cb_find(agreement,-1,0,&protocol)||!cb_int(protocol,&number)||number!=1
  ||!bytes_field(agreement,-2,0,2,&xv)||xv.n!=32
  ||!bytes_field(agreement,-3,0,2,&yv)||yv.n!=32)return false;
 memcpy(x,xv.p,32);memcpy(y,yv.p,32);
 bool ok=pin_uv_derive_shared_secret(x,y,shared);
 memset(x,0,sizeof x);memset(y,0,sizeof y);return ok;
}
static uint16_t client_pin_dispatch_inner(cb_view root,uint8_t*out,uint16_t cap){
 cb_view value,auth_view,new_pin_view,old_hash_view;int64_t protocol,subcommand;
 if(!cb_find(root,1,0,&value)||!cb_int(value,&protocol)||protocol!=1
  ||!cb_find(root,2,0,&value)||!cb_int(value,&subcommand))return pin_error(out,0x02);
 cb_writer writer={out,cap,1,false};out[0]=0;
 if(subcommand==1){
  cb_head(&writer,5,1);cb_num(&writer,3);cb_num(&writer,pin_retries);
 }else if(subcommand==2){
  uint8_t x[32],y[32];
  if(!pin_uv_get_key_agreement(x,y))return pin_error(out,0x7f);
  cb_head(&writer,5,1);cb_num(&writer,1);cb_head(&writer,5,5);
  cb_num(&writer,1);cb_num(&writer,2);cb_num(&writer,3);cb_num(&writer,-25);
  cb_num(&writer,-1);cb_num(&writer,1);cb_num(&writer,-2);cb_blob(&writer,2,x,32);
  cb_num(&writer,-3);cb_blob(&writer,2,y,32);
  memset(x,0,sizeof x);memset(y,0,sizeof y);
 }else if(subcommand==3||subcommand==4||subcommand==5||subcommand==9){
  uint8_t shared[32],permissions=3,token_rp[32];bool bound=false;
  if(subcommand==9){
   cb_view field,rp;int64_t requested;
   if(!cb_find(root,9,0,&field))return pin_error(out,0x14);
   if(!cb_int(field,&requested)||requested<=0||requested>255)return pin_error(out,0x02);
   if(requested&0x38)return pin_error(out,0x40);
   permissions=(uint8_t)requested&7;
   if(cb_find(root,10,0,&field)){
    if(!cb_bytes(field,3,&rp)||!rp.n||rp.n>253||memchr(rp.p,0,rp.n))return pin_error(out,0x02);
    crypto_hash(rp.p,rp.n,token_rp);bound=true;
   }
   if((permissions&3)&&!bound)return pin_error(out,0x14);
  }
  if(!pin_fields(root,shared))return pin_error(out,0x33);
  if(subcommand==3||subcommand==4){
   if(subcommand==3&&pin_uv_configured()){memset(shared,0,32);return pin_error(out,0x33);}
   if(subcommand==4&&!pin_uv_configured()){memset(shared,0,32);return pin_error(out,0x35);}
   if(!bytes_field(root,4,0,2,&auth_view)||auth_view.n!=16
    ||!bytes_field(root,5,0,2,&new_pin_view)||new_pin_view.n!=64){
    memset(shared,0,32);return pin_error(out,0x02);
   }
   memcpy(pin_cipher,new_pin_view.p,64);
   size_t auth_length=64;
   if(subcommand==4){
    if(!bytes_field(root,6,0,2,&old_hash_view)||old_hash_view.n!=16){memset(shared,0,32);return pin_error(out,0x02);}
    memcpy(pin_cipher+64,old_hash_view.p,16);auth_length=80;
   }
   pin_uv_hmac(shared,pin_cipher,auth_length,pin_auth);
   if(memcmp(pin_auth,auth_view.p,16)){memset(shared,0,32);memset(pin_cipher,0,sizeof pin_cipher);memset(pin_auth,0,sizeof pin_auth);return pin_error(out,0x33);}
   if(!pin_uv_crypt(false,shared,new_pin_view.p,64,pin_cipher)){
    memset(shared,0,32);memset(pin_cipher,0,sizeof pin_cipher);memset(pin_auth,0,sizeof pin_auth);return pin_error(out,0x7f);
   }
   size_t pin_length=0;while(pin_length<64&&pin_cipher[pin_length])pin_length++;
   bool valid=pin_length>=4&&pin_length<=63;
   for(size_t i=0;valid&&i<pin_length;i++)valid=pin_cipher[i]>='0'&&pin_cipher[i]<='9';
   for(size_t i=pin_length;valid&&i<64;i++)valid=pin_cipher[i]==0;
   if(subcommand==4){
    uint8_t old_hash[16];memset(old_hash,0,sizeof old_hash);
    if(!pin_uv_crypt(false,shared,old_hash_view.p,16,old_hash))valid=false;
    if(valid&&!pin_uv_check_pin_hash(old_hash))valid=false;
    memset(old_hash,0,sizeof old_hash);
   }
   if(!valid){memset(shared,0,32);memset(pin_cipher,0,sizeof pin_cipher);memset(pin_auth,0,sizeof pin_auth);return pin_error(out,0x31);}
   crypto_hash(pin_cipher,pin_length,pin_hash);
   bool saved=pin_uv_set_pin_hash(pin_hash);
   memset(shared,0,32);memset(pin_cipher,0,sizeof pin_cipher);memset(pin_hash,0,sizeof pin_hash);memset(pin_auth,0,sizeof pin_auth);
   if(!saved)return pin_error(out,0x7f);
   pin_uv_clear_token();pin_retries=8;cb_head(&writer,5,0);
  }else{
   pin_uv_clear_token();
   if(!pin_uv_configured()){memset(shared,0,32);return pin_error(out,0x35);}
   if(!bytes_field(root,6,0,2,&old_hash_view)||old_hash_view.n!=16){memset(shared,0,32);return pin_error(out,0x02);}
   if(!pin_uv_crypt(false,shared,old_hash_view.p,16,pin_hash)){
    memset(shared,0,32);return pin_error(out,0x7f);
   }
   if(!pin_retries){memset(shared,0,32);memset(pin_hash,0,sizeof pin_hash);return pin_error(out,0x32);}
   if(!pin_uv_check_pin_hash(pin_hash)){
    if(pin_retries)pin_retries--;
    memset(shared,0,32);memset(pin_hash,0,sizeof pin_hash);
    return pin_error(out,pin_retries?0x31:0x32);
   }
   if(crypto_random(0,pin_token,sizeof pin_token)||!pin_uv_set_scoped_token(pin_token,permissions,bound?token_rp:NULL)
    ||!pin_uv_crypt(true,shared,pin_token,sizeof pin_token,pin_cipher)){
    memset(shared,0,32);memset(pin_token,0,sizeof pin_token);memset(pin_hash,0,sizeof pin_hash);
    pin_uv_clear_token();return pin_error(out,0x7f);
   }
   cb_head(&writer,5,1);cb_num(&writer,2);cb_blob(&writer,2,pin_cipher,32);
   memset(shared,0,32);memset(pin_token,0,sizeof pin_token);memset(pin_hash,0,sizeof pin_hash);memset(pin_cipher,0,sizeof pin_cipher);
   pin_retries=8;
  }
 }else return pin_error(out,0x3e);
 if(writer.failed)return pin_error(out,0x7f);
 return (uint16_t)writer.used;
}
static uint16_t client_pin_dispatch(cb_view root,uint8_t*out,uint16_t cap){
 cb_view subcommand_value={0,0};int64_t subcommand=0;
 cb_find(root,2,0,&subcommand_value);cb_int(subcommand_value,&subcommand);
 uint16_t length=client_pin_dispatch_inner(root,out,cap);
 uint8_t status=length?out[0]:0xff;
 log_puts("CTAP2 clientPIN subcommand=");
 log_puts(subcommand==1?"getRetries":subcommand==2?"getKeyAgreement":
          subcommand==3?"setPIN":subcommand==4?"changePIN":
          subcommand==5?"getPINToken":subcommand==9?"getPINTokenWithPermissions":"unsupported");
 log_puts(" status=0x");
 static const char hex[]="0123456789ABCDEF";
 char code[3]={hex[status>>4],hex[status&15u],0};log_puts(code);log_puts("\r\n");
 return length;
}
static uint8_t pin_uv_authorize(cb_view root,bool make,bool required){
 cb_view encoded_auth,auth,protocol;int64_t number;
 bool has_auth=cb_find(root,make?8:6,0,&encoded_auth);
 bool has_protocol=cb_find(root,make?9:7,0,&protocol);
 operation_uv_verified=false;
 if(has_auth!=has_protocol){log_puts("CTAP2 PIN/UV auth rejected: auth/protocol pair incomplete\r\n");return 0x33;}
 if(!has_auth){
  if(required)log_puts("CTAP2 PIN/UV auth rejected: UV required without token auth\r\n");
  return required?(pin_uv_configured()?0x36:0x35):0;
 }
 if(!pin_uv_configured()){log_puts("CTAP2 PIN/UV auth rejected: PIN not configured\r\n");return 0x35;}
 if(!cb_int(protocol,&number)||number!=1||!cb_bytes(encoded_auth,2,&auth)||auth.n!=16){
  log_puts("CTAP2 PIN/UV auth rejected: malformed parameter\r\n");return 0x33;
 }
 if(!pin_uv_verify_token_auth(client_hash,32,auth.p)){log_puts("CTAP2 PIN/UV auth rejected: token HMAC mismatch\r\n");return 0x33;}
 if(!pin_uv_authorize_rp(make?1:2,rp_hash))return 0x33;
 operation_uv_verified=true;return 0;
}
static uint16_t get_info(uint8_t*out,uint16_t cap){
 cb_writer w={out,cap,1,false};out[0]=0;
 bool configured=pin_uv_configured();
 cb_head(&w,5,6);
 cb_num(&w,1);cb_head(&w,4,2);cb_text(&w,"FIDO_2_0");cb_text(&w,"U2F_V2");
 cb_num(&w,3);cb_blob(&w,2,aaguid,16);
 cb_num(&w,4); cb_head(&w,5,5);
 cb_text(&w,"rk");cb_head(&w,7,21);
 cb_text(&w,"up");cb_head(&w,7,21);
 cb_text(&w,"credMgmt");cb_head(&w,7,21);
 cb_text(&w,"clientPin");cb_head(&w,7,configured?21:20);
 cb_text(&w,"pinUvAuthToken");cb_head(&w,7,21);
 cb_num(&w,5);cb_num(&w,1200);
 cb_num(&w,6);cb_head(&w,4,1);cb_num(&w,1);
 cb_num(&w,9);
#if defined(CONFIG_BT_ENABLED) && defined(CONFIG_BT_NIMBLE_ENABLED)
 cb_head(&w,4,2);cb_text(&w,"usb");cb_text(&w,"ble");
#else
 cb_head(&w,4,1);cb_text(&w,"usb");
#endif
 log_puts(configured?"CTAP2 GetInfo: ES256, discoverable credentials, PIN/UV enabled\r\n":"CTAP2 GetInfo: ES256, discoverable credentials, PIN not configured\r\n");
 if(w.failed)return error(out,0x7f);
 return (uint16_t)w.used;
}
static bool find_credential(cb_view list,const uint8_t rp[32],credential*out){
 cb_view entry,id,type;
 for(unsigned i=0;cb_at(list,i,&entry);i++){
  if(!bytes_field(entry,0,"id",2,&id)||id.n!=32)continue;
  if(!cb_find(entry,0,"type",&type)||!text_is(type,"public-key"))continue;
  if(credential_lookup(id.p,rp,out))return true;
 }return false;
}
uint16_t ctap2_dispatch(const uint8_t*req,uint16_t n,uint8_t*out,uint16_t cap,uint32_t channel){
 if(!cap)return 0;
 if(!n)return error(out,0x03);
 bool get_assertion=req[0]==2;
 if(req[0]==1)log_puts("CTAP2 MakeCredential request received\r\n");
 if(get_assertion)log_puts("CTAP2 GetAssertion request received\r\n");
 if(operation)return get_assertion?assertion_error(out,0x06,"another operation is active"):error(out,0x06);
 if(req[0]==0x0a){
  if(n>sizeof request_copy)return error(out,0x39);
  memcpy(request_copy,req,n);cb_view root={request_copy+1,(size_t)n-1};
  if(!cb_valid(root)||(root.p[0]>>5)!=5){cred_mgmt_cancel();return error(out,0x12);}
  return cred_mgmt_dispatch(root,out,cap,channel);
 }
 cred_mgmt_cancel();
 if(req[0]==6){
  if(n>sizeof request_copy)return pin_error(out,0x39);
  memcpy(request_copy,req,n);cb_view pin_root={request_copy+1,(size_t)n-1};
  if(!cb_valid(pin_root)||(pin_root.p[0]>>5)!=5)return pin_error(out,0x12);
  return client_pin_dispatch(pin_root,out,cap);
 }
 if(req[0]==4){if(n!=1)return error(out,0x03);return get_info(out,cap);}
 if(req[0]!=1&&req[0]!=2)return error(out,0x01);
 if(n>sizeof request_copy)return get_assertion?assertion_error(out,0x03,"request exceeds buffer"):error(out,0x03);
 memcpy(request_copy,req,n);cb_view root={request_copy+1,(size_t)n-1},v,rp,hash,list;
 if(!cb_valid(root)||(root.p[0]>>5)!=5)return get_assertion?assertion_error(out,0x12,"invalid CBOR map"):error(out,0x12);
 bool make=req[0]==1,uv_required=false;
 if(!bytes_field(root,make?1:2,0,2,&hash)||hash.n!=32)return get_assertion?assertion_error(out,0x14,"clientDataHash missing or not 32 bytes"):error(out,0x14);
 memcpy(client_hash,hash.p,32);
 if(make){cb_view entity,user,uid,parameters,param,alg,type,user_name;
  if(!cb_find(root,2,0,&entity)||!bytes_field(entity,0,"id",3,&rp))return error(out,0x14);
  if(!cb_find(root,3,0,&user)||!bytes_field(user,0,"id",2,&uid)||!uid.n||uid.n>64)return error(out,0x14);
  if(!rp.n||rp.n>sizeof selected_rp_id||memchr(rp.p,0,rp.n))return error(out,0x02);
  selected_rp_id_len=(uint32_t)rp.n;
  memcpy(selected_rp_id,rp.p,rp.n);
  selected_user_name_len=0;
  if(cb_find(user,0,"name",&user_name)){
   if(!cb_bytes(user_name,3,&user_name)||
      user_name.n>sizeof selected_user_name)return error(out,0x14);
   selected_user_name_len=(uint32_t)user_name.n;
   memcpy(selected_user_name,user_name.p,user_name.n);
  }
  selected_display_name_len=0;
  if(cb_find(user,0,"displayName",&user_name)){
   if(!cb_bytes(user_name,3,&user_name)||user_name.n>sizeof selected_display_name)return error(out,0x14);
   selected_display_name_len=user_name.n;memcpy(selected_display_name,user_name.p,user_name.n);
  }
  if(!cb_find(root,4,0,&parameters)||(parameters.p[0]>>5)!=4)return error(out,0x14);
  bool es256=false;
  for(unsigned i=0;cb_at(parameters,i,&param);i++){
   int64_t a;if(cb_find(param,0,"alg",&alg)&&cb_int(alg,&a)&&a==-7&&cb_find(param,0,"type",&type)&&text_is(type,"public-key"))es256=true;
  }if(!es256)return error(out,0x26);
 }else if(!bytes_field(root,1,0,3,&rp))return assertion_error(out,0x14,"RP ID missing or not text");
 if(!rp.n||rp.n>253||memchr(rp.p,0,rp.n))return get_assertion?assertion_error(out,0x02,"RP ID length or contents invalid"):error(out,0x02);
 crypto_hash(rp.p,rp.n,rp_hash);
 if(cb_find(root,make?6:4,0,&v))return get_assertion?assertion_error(out,0x33,"extensions are unsupported"):error(out,0x33);
 presence_required=true;
 if(cb_find(root,make?7:5,0,&v)){
  cb_view opt;bool b;
  if((v.p[0]>>5)!=5)return get_assertion?assertion_error(out,0x11,"options are not a map"):error(out,0x11);
  if(cb_find(v,0,"rk",&opt)){if(!cb_bool(opt,&b))return get_assertion?assertion_error(out,0x11,"rk option is not boolean"):error(out,0x11);if(b&&!make)return assertion_error(out,0x2b,"rk is not valid for GetAssertion");}
  if(cb_find(v,0,"uv",&opt)){
   if(!cb_bool(opt,&b))return get_assertion?assertion_error(out,0x11,"uv option is not boolean"):error(out,0x11);
  uv_required=b;
  }
  if(cb_find(v,0,"up",&opt)){
   if(!cb_bool(opt,&b))return get_assertion?assertion_error(out,0x11,"up option is not boolean"):error(out,0x11);
   if(!b&&make)return error(out,0x2c);
   if(!b)presence_required=false;
  }
 }
 uint8_t pin_status=pin_uv_authorize(root,make,uv_required);
 if(pin_status){
  if(!get_assertion)log_puts("CTAP2 MakeCredential rejected: PIN/UV authorization failed\r\n");
  return get_assertion?assertion_error(out,pin_status,"PIN/UV authorization failed"):error(out,pin_status);
 }
 excluded=false;selected_user_id_len=0;
 memset(selected_user_id,0,sizeof selected_user_id);memset(&selected,0,sizeof selected);
 if(make){
  cb_view user,uid;
  if(!cb_find(root,3,0,&user)||!bytes_field(user,0,"id",2,&uid)||!uid.n||uid.n>sizeof selected_user_id)return error(out,0x14);
  memcpy(selected_user_id,uid.p,uid.n);selected_user_id_len=(uint32_t)uid.n;
  if(cb_find(root,5,0,&list)){
   if((list.p[0]>>5)!=4)return error(out,0x11);
   excluded=find_credential(list,rp_hash,&selected);
  }
  if(!excluded&&!credential_room_for_resident(selected_rp_id_len,
                                               selected_user_name_len))
   return error(out,0x28);
  log_puts("CTAP2 MakeCredential: waiting for blue USER button\r\n");
 }else{
  if(cb_find(root,3,0,&list)){
   if((list.p[0]>>5)!=4)return assertion_error(out,0x11,"allowList is not an array");
   if(!find_credential(list,rp_hash,&selected))return assertion_error(out,0x2e,"no matching credential in allowList for RP");
  }else{
   if(!credential_lookup_resident(rp_hash,&selected,selected_user_id,&selected_user_id_len))return assertion_error(out,0x2e,"no resident credential found for RP");
  }
  if(selected.counter==UINT32_MAX)return assertion_error(out,0x7f,"credential counter exhausted");
  log_puts(presence_required?"CTAP2 GetAssertion: waiting for blue USER button\r\n":"CTAP2 GetAssertion: proceeding without user presence as requested\r\n");
 }
 operation=make?1:2;started=platform_millis();
 if(presence_required)presence_begin();
 return 0;
}
int ctap2_waiting(void){return operation!=0;}
void ctap2_cancel(void){cred_mgmt_cancel();operation=0;operation_uv_verified=false;presence_cancel();presence_required=true;memset(&selected,0,sizeof selected);memset(selected_user_id,0,sizeof selected_user_id);selected_user_id_len=0;memset(selected_rp_id,0,sizeof selected_rp_id);selected_rp_id_len=0;memset(selected_user_name,0,sizeof selected_user_name);selected_user_name_len=0;memset(client_hash,0,32);log_puts("CTAP2 cancelled\r\n");}
uint16_t ctap2_poll(uint8_t*out,uint16_t cap){
 if(!operation||!cap)return 0;
 if((uint32_t)(platform_millis()-started)>=30000){ctap2_cancel();return error(out,0x2f);}
 if(presence_required&&!presence_take())return 0;
 uint8_t op=operation;operation=0;
 if(presence_required && operation_uv_verified)pin_uv_clear_token();
 if(excluded)return error(out,0x19);
 log_puts(presence_required?"CTAP2 presence approved; computing ES256 response\r\n":"CTAP2 computing ES256 response without user presence\r\n");
 uint8_t auth[256],signed_data[288],sig[80],x[32],y[32];size_t auth_len=37,siglen=0;
 memcpy(auth,rp_hash,32); auth[32]=(uint8_t)((op==1?0x41:(presence_required?0x01:0x00))|(operation_uv_verified?0x04:0));
 if(op==1){
  memset(&selected,0,sizeof selected);memcpy(selected.rp,rp_hash,32);
  if(crypto_random(0,selected.id,32)||!crypto_generate(&selected,x,y))goto fail;
  selected.counter=0;be32(auth+33,0);memcpy(auth+37,aaguid,16);auth[53]=0;auth[54]=32;memcpy(auth+55,selected.id,32);
  cb_writer key={auth,sizeof auth,87,false};cb_head(&key,5,5);
  cb_num(&key,1);cb_num(&key,2);cb_num(&key,3);cb_num(&key,-7);
  cb_num(&key,-1);cb_num(&key,1);cb_num(&key,-2);cb_blob(&key,2,x,32);cb_num(&key,-3);cb_blob(&key,2,y,32);
  if(key.failed)goto fail;
  auth_len=key.used;
 }else{selected.counter++;be32(auth+33,selected.counter);}
 memcpy(signed_data,auth,auth_len);memcpy(signed_data+auth_len,client_hash,32);
 if(!crypto_sign(&selected,signed_data,auth_len+32,sig,&siglen))goto fail;
 cb_writer w={out,cap,1,false};out[0]=0;
 if(op==1){
  cb_head(&w,5,3);
  cb_num(&w,1);cb_text(&w,"packed");cb_num(&w,2);cb_blob(&w,2,auth,auth_len);
  cb_num(&w,3);cb_head(&w,5,2);cb_text(&w,"alg");cb_num(&w,-7);cb_text(&w,"sig");cb_blob(&w,2,sig,siglen);
 }else{
  cb_head(&w,5,selected_user_id_len?4:3);
  cb_num(&w,1);cb_head(&w,5,2);cb_text(&w,"id");cb_blob(&w,2,selected.id,32);cb_text(&w,"type");cb_text(&w,"public-key");
  cb_num(&w,2);cb_blob(&w,2,auth,auth_len);cb_num(&w,3);cb_blob(&w,2,sig,siglen);
  if(selected_user_id_len){
   cb_num(&w,4);cb_head(&w,5,1);cb_text(&w,"id");cb_blob(&w,2,selected_user_id,selected_user_id_len);
  }
 }
 if(w.failed||(op==1?!credential_save_resident_with_display(&selected,selected_user_id,
      selected_user_id_len,selected_rp_id,selected_rp_id_len,
      selected_user_name,selected_user_name_len,selected_display_name,selected_display_name_len):!credential_save(&selected)))goto fail;
 presence_required=true;operation_uv_verified=false;memset(&selected,0,sizeof selected);memset(selected_user_id,0,sizeof selected_user_id);selected_user_id_len=0;memset(selected_rp_id,0,sizeof selected_rp_id);selected_rp_id_len=0;memset(selected_user_name,0,sizeof selected_user_name);selected_user_name_len=0;memset(client_hash,0,32);
 log_puts(op==1?"MakeCredential success: credential persisted\r\n":"GetAssertion success: signature and counter persisted\r\n");
 return (uint16_t)w.used;
fail:
 presence_required=true;operation_uv_verified=false;memset(&selected,0,sizeof selected);memset(selected_user_id,0,sizeof selected_user_id);selected_user_id_len=0;memset(selected_rp_id,0,sizeof selected_rp_id);selected_rp_id_len=0;memset(selected_user_name,0,sizeof selected_user_name);selected_user_name_len=0;memset(client_hash,0,32);log_puts("CTAP2 crypto/storage failure\r\n");return error(out,0x7f);
}
