/* Production CTAP, CM, CBOR, storage and token state. Only hardware/crypto mocked. */
#include "test_store.c"
#include "../../main/ctap2.h"
#include "../../main/cbor_min.h"
#include "../../main/cred_mgmt.h"
#include "../../main/fido_ble_framing.h"
#include "../../main/pin_uv.h"
#include "../../main/ctaphid.h"

static uint32_t now;
static bool configured=true;
static bool pressed;
static unsigned wink_requests;
void indicators_wink(void) { wink_requests++; }
static uint8_t hid_reports[24][64];
static unsigned hid_report_count;
void usb_fido_hid_write(const uint8_t *report,uint32_t length)
{ if(length==64&&hid_report_count<24)memcpy(hid_reports[hid_report_count++],report,64); }
void usb_composite_tx_poll(void) {}
void ble_fido_processing_tick(void) {}
uint32_t platform_millis(void) { return now; }
__attribute__((noinline,noipa)) size_t strlen(const char*s)
{ size_t n=0;while(s[n])n++;return n; }
void *memchr(const void*p,int c,size_t n)
{ const uint8_t*b=p;while(n--){if(*b==(uint8_t)c)return (void*)b;b++;}return 0; }
void presence_begin(void) { pressed=false; }
void presence_cancel(void) { pressed=false; }
void indicators_result(bool success) { (void)success; }
bool presence_take(void) { bool value=pressed;pressed=false;return value; }
bool pin_uv_configured(void) { return configured; }
bool pin_uv_check_pin_hash(const uint8_t h[16]) { return h[0]==42; }
bool pin_uv_set_pin_hash(const uint8_t h[16]) { (void)h;return true; }
bool pin_uv_get_key_agreement(uint8_t x[32],uint8_t y[32])
{ memset(x,1,32);memset(y,2,32);return true; }
bool pin_uv_derive_shared_secret(const uint8_t x[32],const uint8_t y[32],uint8_t out[32])
{ (void)x;(void)y;memset(out,7,32);return true; }
bool pin_uv_crypt(bool e,const uint8_t k[32],const uint8_t*p,size_t n,uint8_t*out)
{ (void)e;(void)k;memcpy(out,p,n);return true; }
bool pin_uv_hmac(const uint8_t k[32],const uint8_t*p,size_t n,uint8_t*out)
{ crypto_hash(p,n,out);for(unsigned i=0;i<32;i++)out[i]^=k[i];return true; }
int crypto_random(void*c,uint8_t*out,size_t n)
{ (void)c;memset(out,17,n);return 0; }
static uint32_t generated;
static bool fail_crypto;
static uint8_t last_signed[600];
static size_t last_signed_length;
bool crypto_generate(credential*c,uint8_t*x,uint8_t*y)
{ if(fail_crypto)return false;memset(c->secret,23,32);memset(c->id,0,32);
  generated++;memcpy(c->id,&generated,4);memset(x,3,32);memset(y,4,32);return true; }
bool crypto_sign(const credential*c,const uint8_t*d,size_t n,uint8_t*s,size_t*l)
{ (void)c;if(fail_crypto||n>sizeof last_signed)return false;memcpy(last_signed,d,n);last_signed_length=n;memset(s,5,64);*l=64;return true; }

static uint8_t token[32]={19},cm_request[1200],cm_response[1200],params_buf[800];
static uint16_t cm(unsigned sub,cb_view params,bool auth,uint32_t channel)
{
    cb_writer w={cm_request,sizeof cm_request,1,false};cm_request[0]=10;
    cb_head(&w,5,1+(params.n!=0)+(auth?2:0));cb_num(&w,1);cb_num(&w,sub);
    if(params.n){cb_num(&w,2);memcpy(cm_request+w.used,params.p,params.n);w.used+=params.n;}
    if(auth){
        uint8_t data[801],mac[32];data[0]=sub;size_t n=1;
        if(sub>=4){memcpy(data+1,params.p,params.n);n+=params.n;}
        pin_uv_hmac(token,data,n,mac);
        cb_num(&w,3);cb_num(&w,1);cb_num(&w,4);cb_blob(&w,2,mac,16);
    }
    return ctap2_dispatch(cm_request,w.used,cm_response,sizeof cm_response,channel);
}
static cb_view params_rp(const uint8_t rp[32])
{
    cb_writer w={params_buf,sizeof params_buf,0,false};
    cb_head(&w,5,1);cb_num(&w,1);cb_blob(&w,2,rp,32);
    return (cb_view){params_buf,w.used};
}
static cb_view params_key(const credential*c,bool update,const uint8_t*uid,size_t uidlen,
                          const char*name,const char*display)
{
    cb_writer w={params_buf,sizeof params_buf,0,false};
    cb_head(&w,5,update?2:1);cb_num(&w,2);cb_head(&w,5,2);
    cb_text(&w,"id");cb_blob(&w,2,c->id,32);cb_text(&w,"type");cb_text(&w,"public-key");
    if(update){cb_num(&w,3);cb_head(&w,5,1+(name!=0)+(display!=0));
        cb_text(&w,"id");cb_blob(&w,2,uid,uidlen);
        if(name){cb_text(&w,"name");cb_text(&w,name);}
        if(display){cb_text(&w,"displayName");cb_text(&w,display);}
    }
    return (cb_view){params_buf,w.used};
}
static int response_number(int key)
{ cb_view root={cm_response+1,sizeof cm_response-1},v;int64_t n=-1;
  if(!cb_find(root,key,0,&v)||!cb_int(v,&n))return -1;return n; }

int test_credential_management(void)
{
    fresh();now=0;CHECK(credential_store_init());pin_uv_clear_token();cred_mgmt_cancel();
    credential c[5];
    for(unsigned i=0;i<5;i++){c[i]=make_credential(i+1);if(i==2)c[i].rp[0]=88;CHECK(add(&c[i]));}
    CHECK(credential_set_discoverable(c[3].id,c[3].rp,false)==CREDENTIAL_OK);
    CHECK(credential_delete(c[4].id,c[4].rp)==CREDENTIAL_OK);
    cb_view none={0};
    CHECK(cm(1,none,false,7)==1&&cm_response[0]==0x36);
    CHECK(pin_uv_set_token(token));CHECK(cm(1,none,true,7)==1&&cm_response[0]==0x33);
    CHECK(pin_uv_set_scoped_token(token,4,0));
    CHECK(cm(1,none,true,7)>1&&cm_response[0]==0&&response_number(1)==3&&response_number(2)==2044);
    token[0]++;CHECK(cm(1,none,true,7)==1&&cm_response[0]==0x33);token[0]--;
    CHECK(cm(3,none,false,7)==1&&cm_response[0]==0x30);
    CHECK(cm(2,none,true,7)>1&&cm_response[0]==0&&response_number(5)==2);
    CHECK(cm(3,none,false,8)==1&&cm_response[0]==0x30);
    CHECK(cm(2,none,true,7)>1);CHECK(cm(3,none,false,7)>1&&cm_response[0]==0);
    CHECK(cm(3,none,false,7)==1&&cm_response[0]==0x2e);
    CHECK(cm(4,params_rp(c[0].rp),true,7)>1&&cm_response[0]==0&&response_number(9)==2);
    CHECK(cm(5,none,false,7)>1&&cm_response[0]==0);
    CHECK(cm(5,none,false,7)==1&&cm_response[0]==0x2e);
    CHECK(cm(4,params_rp(c[0].rp),true,7)>1);c[0].counter=9;CHECK(credential_save(&c[0]));
    CHECK(cm(5,none,false,7)==1&&cm_response[0]==0x30);
    CHECK(pin_uv_set_scoped_token(token,4,c[0].rp));
    CHECK(cm(1,none,true,7)==1&&cm_response[0]==0x33);
    CHECK(cm(2,none,true,7)==1&&cm_response[0]==0x33);
    CHECK(cm(4,params_rp(c[2].rp),true,7)==1&&cm_response[0]==0x33);
    CHECK(cm(6,params_key(&c[2],false,0,0,0,0),true,7)==1&&cm_response[0]==0x33);
    CHECK(cm(4,params_rp(c[0].rp),true,7)>1&&cm_response[0]==0);
    CHECK(pin_uv_set_scoped_token(token,4,0));
    CHECK(cm(5,none,false,7)==1&&cm_response[0]==0x30);
    uint8_t uid[]={4,5,6},wrong[]={4,5,7};
    CHECK(cm(7,params_key(&c[0],true,wrong,3,"new","New Name"),true,7)==1&&cm_response[0]==2);
    CHECK(cm(7,params_key(&c[0],true,uid,3,"new","New Name"),true,7)==1&&cm_response[0]==0);
    credential_management_info info;uint32_t index;
    CHECK(credential_store_init());
    CHECK(credential_management_find(c[0].id,&index,&info)==CREDENTIAL_OK);
    CHECK(info.summary.user_name_len==3&&!memcmp(info.summary.user_name,"new",3));
    CHECK(info.display_name_len==8&&!memcmp(info.display_name,"New Name",8));
    CHECK(info.summary.counter==9);
    CHECK(cm(7,params_key(&c[0],true,uid,3,0,0),true,7)==1&&cm_response[0]==0);
    CHECK(credential_management_get(index,&info)==CREDENTIAL_OK);
    CHECK(info.summary.user_name_len==0&&info.display_name_len==0);
    /* Full-ID matching remains correct when console prefixes collide. */
    credential collision=c[0];collision.id[4]=1;CHECK(add(&collision));
    CHECK(cm(6,params_key(&collision,false,0,0,0,0),true,7)==1&&cm_response[0]==0);
    credential found;CHECK(credential_lookup(c[0].id,c[0].rp,&found));
    CHECK(!credential_lookup(collision.id,collision.rp,&found));
    CHECK(credential_store_init());credential_journal_stats stats;credential_get_journal_stats(&stats);
    CHECK(stats.deleted==2);CHECK(cm(6,params_key(&collision,false,0,0,0,0),true,7)==1&&cm_response[0]==0x2e);
    CHECK(cm(6,params_key(&c[3],false,0,0,0,0),true,7)==1&&cm_response[0]==0x2e);
    CHECK(pin_uv_set_scoped_token(token,4,0));now=30000;
    CHECK(cm(1,none,true,7)==1&&cm_response[0]==0x33);
    now=0;CHECK(pin_uv_set_token(token));
    CHECK(pin_uv_authorize_rp(1,c[0].rp));CHECK(!pin_uv_authorize_rp(2,c[2].rp));
    CHECK(!pin_uv_token_has_permission(4));
    return 0;
}

int test_scoped_client_pin(void)
{
    now=0;pin_uv_clear_token();
    uint8_t hash[16]={42},x[32]={1},y[32]={2};
    cb_writer w={cm_request,sizeof cm_request,1,false};cm_request[0]=6;
    cb_head(&w,5,5);cb_num(&w,1);cb_num(&w,1);cb_num(&w,2);cb_num(&w,9);
    cb_num(&w,3);cb_head(&w,5,5);cb_num(&w,1);cb_num(&w,2);cb_num(&w,3);cb_num(&w,-25);
    cb_num(&w,-1);cb_num(&w,1);cb_num(&w,-2);cb_blob(&w,2,x,32);cb_num(&w,-3);cb_blob(&w,2,y,32);
    cb_num(&w,6);cb_blob(&w,2,hash,16);cb_num(&w,9);cb_num(&w,4);
    CHECK(ctap2_dispatch(cm_request,w.used,cm_response,sizeof cm_response,7)>1&&cm_response[0]==0);
    CHECK(pin_uv_token_permits(4,0)&&!pin_uv_token_has_permission(1));
    cm_request[w.used-1]=1;CHECK(ctap2_dispatch(cm_request,w.used,cm_response,sizeof cm_response,7)==1&&cm_response[0]==0x14);
    cm_request[w.used-1]=8;CHECK(ctap2_dispatch(cm_request,w.used,cm_response,sizeof cm_response,7)==1&&cm_response[0]==0x40);
    cm_request[w.used-1]=0;CHECK(ctap2_dispatch(cm_request,w.used,cm_response,sizeof cm_response,7)==1&&cm_response[0]==2);
    cm_request[0]=4;CHECK(ctap2_dispatch(cm_request,1,cm_response,sizeof cm_response,7)>1);
    cb_view root={cm_response+1,sizeof cm_response-1},v,option;bool b;
    CHECK(cb_find(root,4,0,&v));CHECK(cb_find(v,0,"credMgmt",&option)&&cb_bool(option,&b)&&b);
    CHECK(cb_find(v,0,"pinUvAuthToken",&option)&&cb_bool(option,&b)&&b);
    CHECK(!cb_find(v,0,"uv",&option)); /* No built-in biometric verifier. */
    return 0;
}

int test_cm_capacity(void)
{
    fresh();now=0;CHECK(credential_store_init());
    credential c;
    for(unsigned i=0;i<2048;i++){
        c=make_credential(i+1);CHECK(add(&c));
    }
    CHECK(pin_uv_set_scoped_token(token,4,0));cb_view none={0};
    CHECK(cm(1,none,true,7)>1&&response_number(1)==2048&&response_number(2)==0);
    CHECK(cm(2,none,true,7)>1&&response_number(5)==1);
    CHECK(cm(4,params_rp(c.rp),true,7)>1&&response_number(9)==2048);
    for(unsigned i=1;i<2048;i++)CHECK(cm(5,none,false,7)>1&&cm_response[0]==0);
    CHECK(cm(5,none,false,7)==1&&cm_response[0]==0x2e);
    return 0;
}

int test_authenticator_identity(void)
{
    static const uint8_t expected[16]={0xad,0xac,0xde,0xf0,0x36,0x44,0x43,0xdd,
                                     0x84,0xda,0xd2,0x7b,0xda,0x71,0x19,0x83};
    cm_request[0]=4;
    uint16_t length=ctap2_dispatch(cm_request,1,cm_response,sizeof cm_response,7);
    CHECK(length>1&&cm_response[0]==0);
    cb_view root={cm_response+1,length-1},value,aaguid,transports,transport;
    CHECK(cb_valid(root));
    CHECK(cb_find(root,3,0,&value)&&cb_bytes(value,2,&aaguid));
    CHECK(aaguid.n==16&&!memcmp(aaguid.p,expected,16));
    CHECK(cb_find(root,9,0,&transports)&&cb_at(transports,0,&value));
    CHECK(cb_bytes(value,3,&transport)&&transport.n==3&&!memcmp(transport.p,"usb",3));
#if defined(CONFIG_BT_ENABLED) && defined(CONFIG_BT_NIMBLE_ENABLED)
    CHECK(cb_at(transports,1,&value)&&cb_bytes(value,3,&transport));
    CHECK(transport.n==3&&!memcmp(transport.p,"ble",3));
    CHECK(!cb_at(transports,2,&value));
#else
    CHECK(!cb_at(transports,1,&value));
#endif
    fresh();CHECK(credential_store_init());pin_uv_clear_token();
    uint8_t hash[32]={1},uid[]={4,5,6};
    cb_writer w={cm_request,sizeof cm_request,1,false};cm_request[0]=1;
    cb_head(&w,5,4);cb_num(&w,1);cb_blob(&w,2,hash,32);
    cb_num(&w,2);cb_head(&w,5,1);cb_text(&w,"id");cb_text(&w,"example.test");
    cb_num(&w,3);cb_head(&w,5,1);cb_text(&w,"id");cb_blob(&w,2,uid,3);
    cb_num(&w,4);cb_head(&w,4,1);cb_head(&w,5,2);
    cb_text(&w,"alg");cb_num(&w,-7);cb_text(&w,"type");cb_text(&w,"public-key");
    CHECK(ctap2_dispatch(cm_request,w.used,cm_response,sizeof cm_response,7)==0&&ctap2_waiting());
    pressed=true;length=ctap2_poll(cm_response,sizeof cm_response);
    CHECK(length>1&&cm_response[0]==0);
    root=(cb_view){cm_response+1,length-1};CHECK(cb_valid(root));
    CHECK(cb_find(root,2,0,&value)&&cb_bytes(value,2,&value)&&value.n>=55);
    CHECK(!memcmp(value.p+37,expected,16));
    return 0;
}

static uint8_t emitted_fragments[4][32];
static uint16_t emitted_lengths[4];
static uint8_t emitted_count;

static bool capture_fragment(const uint8_t *fragment,uint16_t length,void *context)
{
    (void)context;
    if(emitted_count>=4||length>sizeof emitted_fragments[0])return false;
    memcpy(emitted_fragments[emitted_count],fragment,length);
    emitted_lengths[emitted_count++]=length;
    return true;
}

int test_ble_framing(void)
{
    fido_ble_reassembly state;fido_ble_reassembly_reset(&state);
    const uint8_t first[]={0x83,0,5,1,2};
    fido_ble_fragment_outcome value=fido_ble_receive_fragment(&state,first,sizeof first,10);
    CHECK(value.result==FIDO_BLE_FRAGMENT_MORE&&state.active&&state.used==2);
    const uint8_t continuation[]={0,3,4,5};
    value=fido_ble_receive_fragment(&state,continuation,sizeof continuation,11);
    CHECK(value.result==FIDO_BLE_FRAGMENT_COMPLETE&&value.command==0x83);
    CHECK(state.size==5&&!memcmp(state.data,"\x01\x02\x03\x04\x05",5));

    fido_ble_reassembly_reset(&state);
    value=fido_ble_receive_fragment(&state,first,sizeof first,20);
    CHECK(value.result==FIDO_BLE_FRAGMENT_MORE);
    const uint8_t wrong_sequence[]={1,3};
    value=fido_ble_receive_fragment(&state,wrong_sequence,sizeof wrong_sequence,21);
    CHECK(value.result==FIDO_BLE_FRAGMENT_ERROR&&value.error==4&&!state.active);

    value=fido_ble_receive_fragment(&state,first,sizeof first,30);
    CHECK(value.result==FIDO_BLE_FRAGMENT_MORE);
    CHECK(!fido_ble_reassembly_timed_out(&state,3029,3000));
    CHECK(fido_ble_reassembly_timed_out(&state,3030,3000));

    uint8_t payload[40];for(unsigned i=0;i<sizeof payload;i++)payload[i]=(uint8_t)i;
    emitted_count=0;memset(emitted_lengths,0,sizeof emitted_lengths);
    CHECK(fido_ble_emit_frame(0x81,payload,sizeof payload,20,capture_fragment,0));
    CHECK(emitted_count==3&&emitted_lengths[0]==20&&emitted_lengths[1]==20&&emitted_lengths[2]==5);
    CHECK(emitted_fragments[0][0]==0x81&&emitted_fragments[0][1]==0&&emitted_fragments[0][2]==40);
    CHECK(emitted_fragments[1][0]==0&&emitted_fragments[2][0]==1);
    CHECK(!memcmp(emitted_fragments[0]+3,payload,17));
    CHECK(!memcmp(emitted_fragments[1]+1,payload+17,19));
    CHECK(!memcmp(emitted_fragments[2]+1,payload+36,4));
    return 0;
}

#include "../../main/u2f.h"
#include "../../main/u2f_attestation.h"

static bool sw(uint16_t length,uint16_t expected)
{ return length==2&&cm_response[0]==(expected>>8)&&cm_response[1]==(expected&255); }

static void register_request(void)
{
    memset(cm_request,0,sizeof cm_request);cm_request[1]=1;cm_request[6]=64;
    memset(cm_request+7,31,32);memset(cm_request+39,41,32);
}

static void auth_request(const uint8_t handle[36],uint8_t control)
{
    memset(cm_request,0,sizeof cm_request);cm_request[1]=2;cm_request[2]=control;cm_request[6]=101;
    memset(cm_request+7,51,32);memset(cm_request+39,41,32);
    cm_request[71]=36;memcpy(cm_request+72,handle,36);
}

int test_u2f_operations(void)
{
    fresh();CHECK(credential_store_init());u2f_cancel(0);now=100;
    register_request();
    CHECK(sw(u2f_dispatch(cm_request,71,cm_response,sizeof cm_response,7),0x6985));
    CHECK(u2f_waiting()&&credential_list_count()==0);
    pressed=true;
    CHECK(sw(u2f_dispatch(cm_request,71,cm_response,sizeof cm_response,8),0x6985));
    uint16_t length=u2f_dispatch(cm_request,71,cm_response,sizeof cm_response,7);
    CHECK(length>200&&cm_response[length-2]==0x90&&cm_response[length-1]==0);
    CHECK(cm_response[0]==5&&cm_response[1]==4&&cm_response[66]==36);
    uint8_t handle[36];memcpy(handle,cm_response+67,36);
    CHECK(!memcmp(handle,"U2F\x01",4));
    CHECK(last_signed_length==166&&last_signed[0]==0);
    CHECK(!memcmp(last_signed+1,cm_request+39,32)&&!memcmp(last_signed+33,cm_request+7,32));
    CHECK(!memcmp(last_signed+65,handle,36)&&!memcmp(last_signed+101,cm_response+1,65));
    CHECK(!u2f_waiting()&&credential_list_count()==1);
    credential key;CHECK(credential_lookup(handle+4,cm_request+39,&key)&&key.counter==0);
    credential_summary summary;CHECK(credential_list_get(0,&summary)&&!summary.discoverable);
    auth_request(handle,7);
    CHECK(sw(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7),0x6985)&&!u2f_waiting());
    cm_request[39]^=1;
    CHECK(sw(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7),0x6a80));cm_request[39]^=1;
    cm_request[72]^=1;
    CHECK(sw(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7),0x6a80));cm_request[72]^=1;
    cm_request[2]=3;
    CHECK(sw(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7),0x6985));
    pressed=true;
    /* A new challenge cannot reuse an earlier cm_request's approval. */
    cm_request[7]^=1;
    CHECK(sw(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7),0x6985));
    CHECK(sw(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7),0x6985));
    pressed=true;length=u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7);
    CHECK(length==71&&cm_response[0]==1&&cm_response[4]==1&&cm_response[69]==0x90);
    CHECK(last_signed_length==69&&!memcmp(last_signed,cm_request+39,32));
    CHECK(!memcmp(last_signed+32,cm_response,5)&&!memcmp(last_signed+37,cm_request+7,32));
    CHECK(credential_store_init());
    CHECK(credential_lookup(handle+4,cm_request+39,&key)&&key.counter==1);
    cm_request[2]=8;length=u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7);
    CHECK(length==71&&cm_response[0]==0&&cm_response[4]==2);
    CHECK(credential_store_init()&&credential_lookup(handle+4,cm_request+39,&key)&&key.counter==2);
    key.counter=UINT32_MAX;CHECK(credential_save(&key));
    CHECK(sw(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7),0x6f00));
    return 0;
}

int test_u2f_failures(void)
{
    fresh();CHECK(credential_store_init());u2f_cancel(0);now=0;
    register_request();
    CHECK(sw(u2f_dispatch(cm_request,71,cm_response,sizeof cm_response,7),0x6985));
    pressed=true;now=30000;u2f_poll();CHECK(!u2f_waiting());
    CHECK(sw(u2f_dispatch(cm_request,71,cm_response,sizeof cm_response,7),0x6985));
    CHECK(sw(u2f_dispatch(cm_request,71,cm_response,sizeof cm_response,7),0x6985));
    u2f_cancel(8);CHECK(u2f_waiting());u2f_cancel(7);CHECK(!u2f_waiting());
    CHECK(sw(u2f_dispatch(cm_request,71,cm_response,sizeof cm_response,7),0x6985));
    pressed=true;fail_crypto=true;
    CHECK(sw(u2f_dispatch(cm_request,71,cm_response,sizeof cm_response,7),0x6f00));
    fail_crypto=false;CHECK(credential_list_count()==0&&!u2f_waiting());
    CHECK(sw(u2f_dispatch(cm_request,71,cm_response,sizeof cm_response,7),0x6985));
    pressed=true;CHECK(u2f_dispatch(cm_request,71,cm_response,sizeof cm_response,7)>200);
    uint8_t handle[36];memcpy(handle,cm_response+67,36);
    auth_request(handle,8);credential key;
    fail_crypto=true;
    CHECK(sw(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7),0x6f00));
    fail_crypto=false;
    CHECK(credential_lookup(handle+4,cm_request+39,&key)&&key.counter==0);
    /* Tear the counter append: no success cm_response; reboot retains the old counter. */
    cut_at=mutation;cut_mode=1;
    CHECK(sw(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7),0x6f00));
    cut_at=-1;CHECK(credential_store_init());
    CHECK(credential_lookup(handle+4,cm_request+39,&key)&&key.counter==0);
    CHECK(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7)==71&&cm_response[4]==1);
    CHECK(credential_store_init()&&credential_lookup(handle+4,cm_request+39,&key)&&key.counter==1);
    /* Cut every write of the next counter append, including a fully written
       commit that reports failure. Recovered counters may advance, never roll back. */
    snapshot();mutation=0;
    CHECK(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7)==71&&cm_response[4]==2);
    int writes=mutation;CHECK(writes>0);
    for(int mode=0;mode<3;mode++)for(int at=0;at<writes;at++){
        restore();CHECK(credential_store_init());mutation=0;cut_at=at;cut_mode=mode;
        CHECK(sw(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7),0x6f00));
        cut_at=-1;CHECK(credential_store_init());
        CHECK(credential_lookup(handle+4,cm_request+39,&key)&&(key.counter==1||key.counter==2));
        uint32_t recovered=key.counter;
        CHECK(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7)==71&&cm_response[4]==recovered+1);
        CHECK(credential_store_init()&&credential_lookup(handle+4,cm_request+39,&key)&&key.counter==recovered+1);
    }
    CHECK(credential_delete(handle+4,cm_request+39)==CREDENTIAL_OK);
    CHECK(sw(u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7),0x6a80));
    return 0;
}

int test_u2f_apdu(void)
{
    uint8_t cm_request[10]={0,3,0,0,0,0,0},cm_response[10];
    CHECK(u2f_dispatch(cm_request,7,cm_response,sizeof cm_response,7)==8);
    CHECK(!memcmp(cm_response,"U2F_V2\x90\x00",8));
    CHECK(u2f_dispatch(cm_request,9,cm_response,sizeof cm_response,7)==8);
    CHECK(u2f_dispatch(cm_request,8,cm_response,sizeof cm_response,7)==2&&cm_response[0]==0x67);
    for(unsigned n=0;n<7;n++)
        CHECK(u2f_dispatch(cm_request,n,cm_response,sizeof cm_response,7)==2&&cm_response[0]==0x67);
    cm_request[0]=1;
    CHECK(u2f_dispatch(cm_request,7,cm_response,sizeof cm_response,7)==2&&cm_response[0]==0x6e);
    cm_request[0]=0;cm_request[2]=1;
    CHECK(u2f_dispatch(cm_request,7,cm_response,sizeof cm_response,7)==2&&cm_response[0]==0x6a&&cm_response[1]==0x86);
    cm_request[2]=0;cm_request[6]=1;
    CHECK(u2f_dispatch(cm_request,8,cm_response,sizeof cm_response,7)==2&&cm_response[0]==0x67);
    cm_request[4]=cm_request[5]=cm_request[6]=255;
    CHECK(u2f_dispatch(cm_request,7,cm_response,sizeof cm_response,7)==2&&cm_response[0]==0x67);
    cm_request[4]=cm_request[5]=cm_request[6]=0;
    for(unsigned ins=1;ins<=2;ins++){
        cm_request[1]=(uint8_t)ins;
        CHECK(u2f_dispatch(cm_request,7,cm_response,sizeof cm_response,7)==2&&(cm_response[0]==0x67||cm_response[0]==0x6a));
    }
    cm_request[1]=3;
    CHECK(u2f_dispatch(cm_request,7,cm_response,2,7)==2&&cm_response[0]==0x67);
    cm_response[0]=0xa5;
    CHECK(!u2f_dispatch(cm_request,7,cm_response,1,7)&&cm_response[0]==0xa5);
    CHECK(!u2f_dispatch(cm_request,7,0,10,7));
    CHECK(u2f_dispatch(0,7,cm_response,10,7)==2&&cm_response[0]==0x67);
    return 0;
}

/* Entry points for run_u2f_crypto.py's independent P-256 verification. */
static void hid_request(uint32_t channel,uint8_t command,const uint8_t *data,uint16_t size)
{
    uint8_t report[64]={0};unsigned offset=0;uint8_t sequence=0;
    report[0]=(uint8_t)(channel>>24);report[1]=(uint8_t)(channel>>16);
    report[2]=(uint8_t)(channel>>8);report[3]=(uint8_t)channel;
    report[4]=command;report[5]=(uint8_t)(size>>8);report[6]=(uint8_t)size;
    unsigned n=size>57?57:size;if(n)memcpy(report+7,data,n);offset=n;
    ctaphid_receive(report);
    while(offset<size){
        memset(report+4,0,60);report[4]=sequence++;n=size-offset;if(n>59)n=59;
        memcpy(report+5,data+offset,n);offset+=n;ctaphid_receive(report);
    }
}

static uint32_t hid_channel(void)
{
    uint8_t nonce[8]={1,2,3,4,5,6,7,8};hid_report_count=0;
    hid_request(0xffffffff,0x86,nonce,8);
    if(hid_report_count!=1||hid_reports[0][4]!=0x86||hid_reports[0][23]!=5)return 0;
    return ((uint32_t)hid_reports[0][15]<<24)|((uint32_t)hid_reports[0][16]<<16)|
           ((uint32_t)hid_reports[0][17]<<8)|hid_reports[0][18];
}

int test_u2f_hid(void)
{
    fresh();CHECK(credential_store_init());ctaphid_init();now=0;
    uint32_t first=hid_channel(),second=hid_channel();CHECK(first&&second&&first!=second);
    wink_requests=0;hid_report_count=0;hid_request(first,0x88,0,0);
    CHECK(wink_requests==1&&hid_report_count==1&&hid_reports[0][4]==0x88&&hid_reports[0][6]==0);
    uint8_t invalid_wink=1;hid_report_count=0;hid_request(first,0x88,&invalid_wink,1);
    CHECK(wink_requests==1&&hid_report_count==1&&hid_reports[0][4]==0xbf&&hid_reports[0][7]==3);
    register_request();hid_report_count=0;
    hid_request(first,0x83,cm_request,71);
    CHECK(hid_report_count==1&&hid_reports[0][4]==0x83&&hid_reports[0][7]==0x69&&u2f_waiting());
    /* CTAP2 must not steal the pending physical touch. */
    uint8_t info=4;hid_report_count=0;hid_request(second,0x90,&info,1);
    CHECK(hid_report_count==1&&hid_reports[0][4]==0xbf&&hid_reports[0][7]==6);
    pressed=true;hid_report_count=0;hid_request(second,0x83,cm_request,71);
    CHECK(hid_report_count==1&&hid_reports[0][7]==0x69);
    hid_report_count=0;hid_request(first,0x83,cm_request,71);
    CHECK(hid_report_count>1&&hid_reports[0][4]==0x83&&hid_reports[0][7]==5);
    CHECK(!u2f_waiting()&&credential_list_count()==1);
    /* Cancellation applies only to the owner channel. */
    register_request();hid_request(first,0x83,cm_request,71);CHECK(u2f_waiting());
    hid_request(second,0x91,0,0);CHECK(u2f_waiting());
    hid_request(first,0x91,0,0);CHECK(!u2f_waiting());
    hid_request(first,0x83,cm_request,71);CHECK(u2f_waiting());
    uint8_t nonce[8]={0};hid_request(first,0x86,nonce,8);CHECK(!u2f_waiting());
    /* Filling the channel table must not evict a touch owner. */
    hid_request(first,0x83,cm_request,71);CHECK(u2f_waiting());
    for(unsigned i=0;i<12;i++)CHECK(hid_channel()!=0);
    pressed=true;hid_report_count=0;hid_request(first,0x83,cm_request,71);
    CHECK(hid_report_count>1&&hid_reports[0][4]==0x83&&hid_reports[0][7]==5);
    CHECK(!u2f_waiting()&&credential_list_count()==2);
    hid_report_count=0;hid_request(first,0x90,&info,1);
    CHECK(hid_report_count>0&&hid_reports[0][4]==0x90&&hid_reports[0][7]==0);
    return 0;
}

int test_u2f_crypto_prepare(void)
{ fresh();u2f_cancel(0);now=0;register_request();return credential_store_init()?0:1; }
int test_u2f_crypto_register(void)
{ return u2f_dispatch(cm_request,71,cm_response,sizeof cm_response,7); }
int test_u2f_crypto_authenticate(void)
{ return u2f_dispatch(cm_request,108,cm_response,sizeof cm_response,7); }
