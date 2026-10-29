#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct {const uint8_t *p;size_t n;} cb_view;
typedef struct {uint8_t *p;size_t n,used;bool failed;} cb_writer;
bool cb_valid(cb_view v);
bool cb_int(cb_view v,int64_t *out);
bool cb_bytes(cb_view v,unsigned major,cb_view *out);
bool cb_bool(cb_view v,bool *out);
bool cb_find(cb_view map,int key,const char *text,cb_view *out);
bool cb_at(cb_view array,unsigned index,cb_view *out);
void cb_head(cb_writer*w,unsigned major,uint32_t n);
void cb_num(cb_writer*w,int n);
void cb_blob(cb_writer*w,unsigned major,const void*p,size_t n);
void cb_text(cb_writer*w,const char*s);
