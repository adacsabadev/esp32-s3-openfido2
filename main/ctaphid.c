#include "ctaphid.h"
#include "ble_fido.h"
#include "ctap2.h"
#include "u2f.h"
#include "usb_composite.h"
#include "platform.h"
#include "log.h"
#include "indicators.h"
#include <string.h>
#include <stdbool.h>
#define CAP 1200u
enum{PING=0x81,MSG=0x83,INIT=0x86,WINK=0x88,CBOR=0x90,CANCEL=0x91,KEEPALIVE=0xbb,ERROR=0xbf};
static struct{uint32_t cid,time;uint16_t size,used;uint8_t cmd,seq;bool active;uint8_t data[CAP];}rx;
typedef struct{uint32_t cid,last_used;} channel;
static channel channels[8];
static uint32_t next_cid,channel_clock,pending_cid,keepalive_time;
static uint8_t response[CAP];
static bool pending;
static uint32_t be32(const uint8_t*p){return((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static void cidput(uint8_t*p,uint32_t c){p[0]=(uint8_t)(c>>24);p[1]=(uint8_t)(c>>16);p[2]=(uint8_t)(c>>8);p[3]=(uint8_t)c;}
static int channel_find(uint32_t cid){
 if(!cid||cid==0xffffffffu)return -1;
 for(unsigned i=0;i<8;i++)if(channels[i].cid==cid){channels[i].last_used=++channel_clock;return (int)i;}
 return -1;
}
static bool known(uint32_t cid){return channel_find(cid)>=0;}
static bool allocate_channel(uint32_t*assigned){
 unsigned slot=8;uint32_t oldest_age=0;
 for(unsigned i=0;i<8;i++){
  if(!channels[i].cid){slot=i;break;}
  if((rx.active&&rx.cid==channels[i].cid)||(pending&&pending_cid==channels[i].cid)||u2f_channel_active(channels[i].cid))continue;
  uint32_t age=channel_clock-channels[i].last_used;
  if(slot==8||age>oldest_age){slot=i;oldest_age=age;}
 }
 if(slot==8)return false;
 uint32_t cid;
 do{
  cid=next_cid++;
 }while(!cid||cid==0xffffffffu||channel_find(cid)>=0);
 channels[slot].cid=cid;channels[slot].last_used=++channel_clock;
 *assigned=cid;return true;
}
static void log_byte(uint8_t value){
 static const char hex[]="0123456789ABCDEF";
 char text[3]={hex[value>>4],hex[value&15u],0};log_puts(text);
}
static void log_command(uint8_t cmd){
 switch(cmd){
 case PING:log_puts("PING");break;
 case MSG:log_puts("MSG");break;
 case INIT:log_puts("INIT");break;
 case WINK:log_puts("WINK");break;
 case CBOR:log_puts("CBOR");break;
 case CANCEL:log_puts("CANCEL");break;
 case KEEPALIVE:log_puts("KEEPALIVE");break;
 case ERROR:log_puts("ERROR");break;
 default:log_puts("unsupported 0x");log_byte(cmd);break;
 }
}
static void send(uint32_t cid,uint8_t cmd,const uint8_t*p,uint16_t n){
 if(cmd==ERROR)indicators_result(false);
 else if(cmd==CBOR&&n)indicators_result(p[0]==0);
 log_puts("CTAPHID TX ");log_command(cmd);log_puts("\r\n");
 uint8_t f[64]={0};uint16_t sent=0,count=n>57?57:n;uint8_t seq=0;
 cidput(f,cid);f[4]=cmd;f[5]=(uint8_t)(n>>8);f[6]=(uint8_t)n;memcpy(f+7,p,count);usb_fido_hid_write(f,64);sent=count;
 while(sent<n){memset(f,0,64);cidput(f,cid);f[4]=seq++;count=(uint16_t)(n-sent);if(count>59)count=59;memcpy(f+5,p+sent,count);usb_fido_hid_write(f,64);sent=(uint16_t)(sent+count);}
}
static void err(uint32_t cid,uint8_t code){send(cid,ERROR,&code,1);}
static void dispatch(void){
 rx.active=false;
 log_puts("CTAPHID dispatch ");log_command(rx.cmd);log_puts("\r\n");
 switch(rx.cmd){
 case PING:send(rx.cid,PING,rx.data,rx.size);break;
 case WINK:if(rx.size)err(rx.cid,3);else{indicators_wink();send(rx.cid,WINK,response,0);}break;
 case MSG:{
  if(ctap2_waiting()){err(rx.cid,6);break;}
  uint16_t n=u2f_dispatch(rx.data,rx.size,response,sizeof response,rx.cid);
  if(n)send(rx.cid,MSG,response,n);else err(rx.cid,3);
  break;
 }
 case CBOR:{
  if(ctap2_waiting()||u2f_waiting()){err(rx.cid,6);break;}
  uint16_t n=ctap2_dispatch(rx.data,rx.size,response,sizeof response,rx.cid);
  if(n)send(rx.cid,CBOR,response,n);
  else if(ctap2_waiting()){pending=true;pending_cid=rx.cid;keepalive_time=platform_millis()-100;}
  else{response[0]=3;send(rx.cid,CBOR,response,1);}break;
 }
 default:err(rx.cid,1);break;
 }
}
void ctaphid_init(void){u2f_cancel(0);memset(&rx,0,sizeof rx);memset(channels,0,sizeof channels);next_cid=0x01020304;channel_clock=0;pending=false;}
void ctaphid_poll(void){
 u2f_poll();
 uint32_t now=platform_millis();
 if(rx.active&&(uint32_t)(now-rx.time)>=3000){log_puts("CTAPHID reassembly timed out\r\n");rx.active=false;err(rx.cid,5);}
 if(pending){
  if((uint32_t)(now-keepalive_time)>=100){uint8_t status=2;send(pending_cid,KEEPALIVE,&status,1);keepalive_time=now;}
  uint16_t n=ctap2_poll(response,sizeof response);
  if(n){send(pending_cid,CBOR,response,n);pending=false;}
 }
}
void ctaphid_processing_tick(void){
 if(pending&&(uint32_t)(platform_millis()-keepalive_time)>=100){
  uint8_t status=1;send(pending_cid,KEEPALIVE,&status,1);keepalive_time=platform_millis();
 }
 usb_composite_tx_poll();
 ble_fido_processing_tick();
}
void ctaphid_receive(const uint8_t f[64]){
 uint32_t cid=be32(f);uint8_t cmd=f[4];
 if(cmd&0x80){
  log_puts("CTAPHID RX ");log_command(cmd);log_puts(" len=");
  log_byte(f[5]);log_byte(f[6]);log_puts("\r\n");
 }else if(!rx.active){
  indicators_result(false);
  log_puts("CTAPHID RX unexpected continuation\r\n");
 }
 if(cmd==INIT){
  uint16_t n=((uint16_t)f[5]<<8)|f[6];if(n!=8){log_puts("CTAPHID INIT rejected: nonce length\r\n");err(cid,3);return;}
  uint32_t assigned=cid;
  if(cid==0xffffffffu){if(!allocate_channel(&assigned)){log_puts("CTAPHID INIT rejected: no idle channel available\r\n");err(cid,6);return;}}
  else if(!known(cid)){log_puts("CTAPHID INIT rejected: unallocated channel\r\n");err(cid,0x0b);return;}
  if(rx.active&&rx.cid==cid)rx.active=false;
  u2f_cancel(cid);
  if(pending&&pending_cid==cid){ctap2_cancel();pending=false;}
  uint8_t init[17];memcpy(init,f+7,8);cidput(init+8,assigned);init[12]=2;init[13]=1;init[14]=0;init[15]=0;init[16]=0x05;
  send(cid,INIT,init,17);log_puts("CTAPHID INIT channel ready\r\n");return;
 }
 if(!known(cid)){log_puts("CTAPHID rejected: unallocated channel\r\n");err(cid,0x0b);return;}
 if(cmd==CANCEL){
  if(f[5]||f[6]){log_puts("CTAPHID CANCEL rejected: nonzero length\r\n");err(cid,3);return;}
  u2f_cancel(cid);
  if(pending&&pending_cid==cid){ctap2_cancel();pending=false;response[0]=0x2d;send(cid,CBOR,response,1);}
  return;
 }
 if(pending){log_puts("CTAPHID rejected: transaction already pending\r\n");err(cid,6);return;}
 if(cmd&0x80){
  if(rx.active){log_puts("CTAPHID rejected: command during reassembly\r\n");err(cid,6);return;}
  uint16_t n=((uint16_t)f[5]<<8)|f[6];if(n>CAP){log_puts("CTAPHID rejected: message too large\r\n");err(cid,3);return;}
  rx.cid=cid;rx.cmd=cmd;rx.size=n;rx.used=n>57?57:n;rx.seq=0;rx.time=platform_millis();rx.active=true;memcpy(rx.data,f+7,rx.used);
 }else{
  if(!rx.active)return;
  if(rx.cid!=cid){log_puts("CTAPHID rejected: continuation channel mismatch\r\n");err(cid,6);return;}
  if(cmd!=rx.seq){log_puts("CTAPHID rejected: continuation sequence mismatch\r\n");rx.active=false;err(cid,4);return;}
  uint16_t n=(uint16_t)(rx.size-rx.used);if(n>59)n=59;
  memcpy(rx.data+rx.used,f+5,n);rx.used=(uint16_t)(rx.used+n);rx.seq++;rx.time=platform_millis();
 }
 if(rx.used==rx.size)dispatch();
}
