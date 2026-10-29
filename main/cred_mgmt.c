#include "cred_mgmt.h"
#include "credential.h"
#include "pin_uv.h"
#include "platform.h"
#include "ctaphid.h"
#include <string.h>

/* Enumeration stores indices, never private keys. One session owns a channel. */
static uint16_t indices[2048];
static uint32_t prefixes[2048];
static uint32_t owner,stamp,token_generation,db_revision;
static unsigned count,cursor,mode;
static uint8_t enumeration_rp[32],auth_message[1200];
static credential_management_info info,other;

void cred_mgmt_cancel(void) { mode=count=cursor=0; }
static uint16_t fail(uint8_t*out,uint8_t code) { out[0]=code;return 1; }
static bool bytes(cb_view map,int key,const char*name,unsigned major,cb_view*out)
{ cb_view value;return cb_find(map,key,name,&value)&&cb_bytes(value,major,out); }
static uint8_t result_code(credential_result r)
{ return r==CREDENTIAL_OK?0:r==CREDENTIAL_NO_SPACE?0x28:r==CREDENTIAL_NOT_FOUND?0x2e:0x7f; }

static uint8_t authorize(cb_view root,uint8_t sub,cb_view params)
{
    cb_view value,auth;int64_t protocol;
    if(!cb_find(root,4,NULL,&value))return 0x36;
    if(!cb_bytes(value,2,&auth)||auth.n!=16)return 0x33;
    if(!cb_find(root,3,NULL,&value))return 0x14;
    if(!cb_int(value,&protocol)||protocol!=1)return 0x02;
    size_t length=1;
    auth_message[0]=sub;
    if(sub>=4){
        if(!params.p)return 0x14;
        if(params.n>sizeof auth_message-1)return 0x39;
        memcpy(auth_message+1,params.p,params.n);length+=params.n;
    }
    bool valid=pin_uv_verify_token_auth(auth_message,length,auth.p);
    memset(auth_message,0,length);
    return valid?0:0x33;
}

static uint8_t collect(bool rps,const uint8_t rp[32])
{
    count=cursor=0;
    for(uint32_t i=0;i<CREDENTIAL_MANAGEMENT_SLOTS;i++){
        credential_result r=credential_management_get(i,&info);
        if(r==CREDENTIAL_NOT_FOUND)continue;
        if(r!=CREDENTIAL_OK)return 0x7f;
        if(!rps && memcmp(info.summary.rp,rp,32))continue;
        bool duplicate=false;uint32_t prefix;
        memcpy(&prefix,info.summary.rp,sizeof prefix);
        if(rps)for(unsigned j=0;j<count;j++){
            if(prefixes[j]!=prefix)continue;
            if(credential_management_get(indices[j],&other)!=CREDENTIAL_OK)return 0x7f;
            if(!memcmp(info.summary.rp,other.summary.rp,32)){duplicate=true;break;}
        }
        if(!duplicate){
            if(count>=2048)return 0x7f;
            indices[count]=i;prefixes[count++]=prefix;
        }
        if(!(i&31)) { ctaphid_processing_tick();platform_idle(); }
    }
    return count?0:0x2e;
}

static uint16_t emit(uint8_t*out,uint16_t capacity,bool first)
{
    if(cursor>=count)return fail(out,0x2e);
    uint32_t index=indices[cursor];
    if(credential_management_get(index,&info)!=CREDENTIAL_OK){cred_mgmt_cancel();return fail(out,0x7f);}
    cb_writer w={out,capacity,1,false};out[0]=0;
    credential_summary *v=&info.summary;
    if(mode==2){
        cb_head(&w,5,first?3:2);
        cb_num(&w,3);cb_head(&w,5,v->rp_id_len?1:0);
        if(v->rp_id_len){cb_text(&w,"id");cb_blob(&w,3,v->rp_id,v->rp_id_len);}
        cb_num(&w,4);cb_blob(&w,2,v->rp,32);
        if(first){cb_num(&w,5);cb_num(&w,count);}
    }else{
        uint8_t x[32],y[32];
        if(!credential_management_public_key(index,x,y)){cred_mgmt_cancel();return fail(out,0x7f);}
        cb_head(&w,5,first?5:4);
        cb_num(&w,6);cb_head(&w,5,1+(v->user_name_len!=0)+(info.display_name_len!=0));
        cb_text(&w,"id");cb_blob(&w,2,info.user_id,info.user_id_len);
        if(v->user_name_len){cb_text(&w,"name");cb_blob(&w,3,v->user_name,v->user_name_len);}
        if(info.display_name_len){cb_text(&w,"displayName");cb_blob(&w,3,info.display_name,info.display_name_len);}
        cb_num(&w,7);cb_head(&w,5,2);cb_text(&w,"id");cb_blob(&w,2,v->id,32);
        cb_text(&w,"type");cb_text(&w,"public-key");
        cb_num(&w,8);cb_head(&w,5,5);
        cb_num(&w,1);cb_num(&w,2);cb_num(&w,3);cb_num(&w,-7);
        cb_num(&w,-1);cb_num(&w,1);cb_num(&w,-2);cb_blob(&w,2,x,32);
        cb_num(&w,-3);cb_blob(&w,2,y,32);
        if(first){cb_num(&w,9);cb_num(&w,count);}
        cb_num(&w,10);cb_num(&w,1); /* Default policy: user verification optional. */
    }
    if(w.failed){cred_mgmt_cancel();return fail(out,0x7f);}
    cursor++;stamp=platform_millis();
    return (uint16_t)w.used;
}

uint16_t cred_mgmt_dispatch(cb_view root,uint8_t*out,uint16_t capacity,uint32_t channel)
{
    cb_view value,params={0},rp={0},descriptor,id,type,user,uid,name={0},display={0};
    int64_t sub;
    if(!cb_find(root,1,NULL,&value))return fail(out,0x14);
    if(!cb_int(value,&sub)||sub<1||sub>7){cred_mgmt_cancel();return fail(out,0x3e);}
    if(sub==3||sub==5){
        if(!mode || mode!=(sub==3?2:4) || owner!=channel ||
           token_generation!=pin_uv_token_generation() || db_revision!=credential_storage_revision() ||
           (uint32_t)(platform_millis()-stamp)>=30000 ||
           !pin_uv_token_permits(4,mode==2?NULL:enumeration_rp)){
            cred_mgmt_cancel();return fail(out,0x30);
        }
        return emit(out,capacity,false);
    }
    cred_mgmt_cancel();
    if(cb_find(root,2,NULL,&params) && (params.p[0]>>5)!=5)return fail(out,0x11);
    uint8_t status=authorize(root,(uint8_t)sub,params);
    if(status)return fail(out,status);
    /* Permission is checked before searching the database. */
    if(sub==1||sub==2){
        if(!pin_uv_token_permits(4,NULL))return fail(out,0x33);
    }else if(sub==4){
        if(!bytes(params,1,NULL,2,&rp))return fail(out,0x14);
        if(rp.n!=32)return fail(out,0x02);
        if(!pin_uv_token_permits(4,rp.p))return fail(out,0x33);
        memcpy(enumeration_rp,rp.p,32);
    }else if(!pin_uv_token_has_permission(4))return fail(out,0x33);
    if(sub==1){
        uint32_t resident=0;
        for(uint32_t i=0;i<CREDENTIAL_MANAGEMENT_SLOTS;i++){
            credential_result r=credential_management_get(i,&info);
            if(r==CREDENTIAL_OK)resident++;
            else if(r!=CREDENTIAL_NOT_FOUND)return fail(out,0x7f);
        }
        credential_journal_stats stats;credential_get_journal_stats(&stats);
        cb_writer w={out,capacity,1,false};out[0]=0;
        cb_head(&w,5,2);cb_num(&w,1);cb_num(&w,resident);cb_num(&w,2);cb_num(&w,stats.free_slots);
        return w.failed?fail(out,0x7f):(uint16_t)w.used;
    }
    if(sub==2||sub==4){
        status=collect(sub==2,sub==4?enumeration_rp:NULL);
        if(status)return fail(out,status);
        owner=channel;mode=(unsigned)sub;stamp=platform_millis();
        token_generation=pin_uv_token_generation();db_revision=credential_storage_revision();
        return emit(out,capacity,true);
    }
    if(!cb_find(params,2,NULL,&descriptor)||!bytes(descriptor,0,"id",2,&id)||
       !bytes(descriptor,0,"type",3,&type))return fail(out,0x14);
    if(id.n!=32 || type.n!=10 || memcmp(type.p,"public-key",10))return fail(out,0x02);
    uint32_t index;
    credential_result r=credential_management_find(id.p,&index,&info);
    if(r!=CREDENTIAL_OK)return fail(out,result_code(r));
    if(!pin_uv_token_permits(4,info.summary.rp))return fail(out,0x33);
    if(sub==6)return fail(out,result_code(credential_management_delete(index)));
    if(!cb_find(params,3,NULL,&user)||!bytes(user,0,"id",2,&uid))return fail(out,0x14);
    if(uid.n!=info.user_id_len||memcmp(uid.p,info.user_id,uid.n))return fail(out,0x02);
    if(cb_find(user,0,"name",&value) && !cb_bytes(value,3,&name))return fail(out,0x11);
    if(cb_find(user,0,"displayName",&value) && !cb_bytes(value,3,&display))return fail(out,0x11);
    if(name.n>64||display.n>64)return fail(out,0x28);
    return fail(out,result_code(credential_management_update(index,name.p,name.n,display.p,display.n)));
}
