#include "cbor_min.h"
#include <string.h>
static bool head(cb_view v,unsigned *m,uint64_t*n,size_t*h){
 if(!v.n)return false;
 *m=v.p[0]>>5;unsigned a=v.p[0]&31;*h=1;
 if(a<24){*n=a;return true;}
 if(a>27)return false;
 unsigned bytes=1u<<(a-24);if(v.n<1u+bytes)return false;
 *n=0;for(unsigned i=0;i<bytes;i++)*n=(*n<<8)|v.p[1+i];
 if((bytes==1&&*n<24)||(bytes==2&&*n<=255)||(bytes==4&&*n<=65535)||(bytes==8&&*n<=UINT32_MAX))return false;
 *h+=bytes;return true;
}
static bool span(cb_view v,size_t*out,unsigned depth){
 unsigned m;uint64_t n;size_t h;if(depth>8||!head(v,&m,&n,&h))return false;
 if(m==2||m==3){if(n>v.n-h)return false;h+=(size_t)n;}
 else if(m==4||m==5){if(n>128)return false;uint64_t count=n*(m==5?2:1);
  /* Rescan earlier pairs instead of keeping 1 KiB of key arrays per
     recursive frame. Map keys are restricted to integers and text. */
  size_t pairs_start=h;
  for(uint64_t i=0;i<count;i++){size_t s;cb_view sub={v.p+h,v.n-h};if(!span(sub,&s,depth+1))return false;
   if(m==5&&!(i&1)){
    if((sub.p[0]>>5)!=0&&(sub.p[0]>>5)!=1&&(sub.p[0]>>5)!=3)return false;
    size_t previous=pairs_start;
    for(uint64_t j=0;j<i/2;j++){
     unsigned km;uint64_t kn;size_t kh,vs;
     cb_view key={v.p+previous,v.n-previous};
     if(!head(key,&km,&kn,&kh))return false;
     if(km==3){if(kn>key.n-kh)return false;kh+=(size_t)kn;}
     else if(km>1)return false;
     if(kh==s&&!memcmp(key.p,sub.p,s))return false;
     previous+=kh;
     cb_view value={v.p+previous,v.n-previous};
     if(!span(value,&vs,depth+1))return false;
     previous+=vs;
    }
   }h+=s;
  }
 }else if(m==6|| (m==7&&v.p[0]!=0xf4&&v.p[0]!=0xf5&&v.p[0]!=0xf6))return false;
 *out=h;return true;
}
bool cb_valid(cb_view v){size_t n;return span(v,&n,0)&&n==v.n;}
bool cb_int(cb_view v,int64_t*out){unsigned m;uint64_t n;size_t h;if(!head(v,&m,&n,&h)||m>1||n>INT64_MAX||h!=v.n)return false;*out=m?-(int64_t)n-1:(int64_t)n;return true;}
bool cb_bytes(cb_view v,unsigned major,cb_view*out){unsigned m;uint64_t n;size_t h;if(!head(v,&m,&n,&h)||m!=major||n!=v.n-h)return false;out->p=v.p+h;out->n=(size_t)n;return true;}
bool cb_bool(cb_view v,bool*out){if(v.n!=1||(v.p[0]!=0xf4&&v.p[0]!=0xf5))return false;*out=v.p[0]==0xf5;return true;}
bool cb_find(cb_view v,int key,const char*text,cb_view*out){
 unsigned m;uint64_t n;size_t pos;if(!head(v,&m,&n,&pos)||m!=5||n>128)return false;bool found=false;
 for(uint64_t i=0;i<n;i++){size_t ks,vs;cb_view k={v.p+pos,v.n-pos};if(!span(k,&ks,0))return false;k.n=ks;pos+=ks;
  cb_view value={v.p+pos,v.n-pos};if(!span(value,&vs,0))return false;value.n=vs;pos+=vs;
  bool match=false;if(text){cb_view s;if(cb_bytes(k,3,&s))match=s.n==strlen(text)&&!memcmp(s.p,text,s.n);}else{int64_t x;if(cb_int(k,&x))match=x==key;}
  if(match){if(found)return false;*out=value;found=true;}
 }return found;
}
bool cb_at(cb_view v,unsigned index,cb_view*out){unsigned m;uint64_t n;size_t pos;if(!head(v,&m,&n,&pos)||m!=4||index>=n||n>128)return false;
 for(unsigned i=0;i<=index;i++){size_t s;cb_view sub={v.p+pos,v.n-pos};if(!span(sub,&s,0))return false;if(i==index){sub.n=s;*out=sub;return true;}pos+=s;}return false;
}
static void put(cb_writer*w,uint8_t b){if(w->used>=w->n){w->failed=true;return;}w->p[w->used++]=b;}
void cb_head(cb_writer*w,unsigned m,uint32_t n){if(n<24)put(w,(uint8_t)((m<<5)|n));else if(n<=255){put(w,(uint8_t)((m<<5)|24));put(w,(uint8_t)n);}else if(n<=65535){put(w,(uint8_t)((m<<5)|25));put(w,(uint8_t)(n>>8));put(w,(uint8_t)n);}else{put(w,(uint8_t)((m<<5)|26));for(int i=3;i>=0;i--)put(w,(uint8_t)(n>>(i*8)));}}
void cb_num(cb_writer*w,int n){cb_head(w,n<0?1:0,(uint32_t)(n<0?-1-n:n));}
void cb_blob(cb_writer*w,unsigned m,const void*p,size_t n){cb_head(w,m,(uint32_t)n);const uint8_t*b=p;for(size_t i=0;i<n;i++)put(w,b[i]);}
void cb_text(cb_writer*w,const char*s){cb_blob(w,3,s,strlen(s));}
