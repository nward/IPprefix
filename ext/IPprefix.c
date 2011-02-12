/* 1531, Fri 29 Aug 08 (NZST)

   IPprefix.c: IPprefix class, useful stuff for IP addresses and prefixes

   Copyright (C) 2007-2009, Nevil Brownlee, U Auckland | CAIDA | WAND */

#include <stdint.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "ruby.h"
//#include "../../rlt_conf.h"

#define IP4_ADDR_LEN   4
#define IP6_ADDR_LEN  16

#define IP4_LAST_BIT   31
#define IP6_LAST_BIT  127

static uint8_t b_mask[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
static uint8_t p_mask[8] = { 0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };

VALUE ipPref;  /* Global so we can use Check_Type( ,ipPref) */

static VALUE pr_init(int argc, VALUE *argv, VALUE self) {
   VALUE pa[3];
   rb_scan_args(argc, argv, "12", &pa[0], &pa[1], &pa[2]);
   if (argc < 1 || argc > 3) rb_raise(rb_eArgError,
      "IPprefix.new called with < 1 or > 3 arguments!");

   int version = NUM2INT(pa[0]);
   if (version != 4 && version != 6) rb_raise(rb_eArgError,
      "IPprefix.new: version must be 4 or 6!");
   rb_iv_set(self, "@version", pa[0]);
   int slen = version == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;

   if (argc == 1) {  /* Create null prefix (root key for new ptrie) */
      char null[IP6_ADDR_LEN] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
      rb_iv_set(self, "@addr", rb_str_new(null, slen));
      rb_iv_set(self, "@length", INT2FIX(0));
      }
   else {
      uint8_t *ap = (uint8_t *)RSTRING_PTR(pa[1]);
      int alen = RSTRING_LEN(pa[1]);
      if (version == 4 && alen > 4) rb_raise(rb_eArgError,
         "IPprefix.new: string length >4 for an IPv4 address!");
      else if (version == 6 && alen > 16) rb_raise(rb_eArgError,
         "IPprefix.new: string length >a16for an IPv6 address!");
      if (alen == slen) rb_iv_set(self, "@addr", pa[1]);
      else {
         char as[IP6_ADDR_LEN] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
         memcpy(as, ap, alen);
         rb_iv_set(self, "@addr", rb_str_new(as, slen));
         }

      if (argc == 3) rb_iv_set(self, "@length", pa[2]);
      else  rb_iv_set(self, "@length", Qnil);
      }
   return self;
   }

static VALUE pr_version(VALUE self) {
   return rb_iv_get(self, "@version");
   }

static VALUE pr_addr(VALUE self) {
   return rb_iv_get(self, "@addr");
   }

static VALUE pr_length(VALUE self) {  /* ||k|| (may be nil) */
   return rb_iv_get(self, "@length");
   }

static VALUE pr_set_length(VALUE self, VALUE length) {
   int w = NUM2INT(length);
   int ver = FIX2INT(rb_iv_get(self, "@version"));
   if (w < 0) rb_raise(rb_eArgError,
      "IPprefix.length=  length must be >= 0!");
   if (ver == 4 && w > IP4_ADDR_LEN*8) rb_raise(rb_eArgError,
      "IPprefix.length=  IPv4 length must be <= %d!", IP4_ADDR_LEN*8);
   else if (ver == 6 && w > IP6_ADDR_LEN*8) rb_raise(rb_eArgError,
      "IPprefix.length=  IPv6 length must be <= %d!", IP6_ADDR_LEN*8);

   rb_iv_set(self, "@length", length);
   return length;
   }

static VALUE pr_addr_equal(VALUE self, VALUE sa) {
   int vs = FIX2INT(rb_iv_get(self, "@version"));
   if (vs != FIX2INT(rb_iv_get(sa, "@version"))) rb_raise(rb_eArgError,
      "IPprefix.equal: Versions must be the same (4 or 6)");
   int nb = vs == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;
   VALUE vsa = rb_iv_get(self, "@addr");
   VALUE vaa = rb_iv_get(sa, "@addr");
   uint8_t *sp = (uint8_t *)RSTRING_PTR(vsa);
   uint8_t *ap = (uint8_t *)RSTRING_PTR(vaa);
   return memcmp(sp, ap, nb) == 0 ? Qtrue : Qfalse;
   }

static VALUE pr_addr_compare(VALUE self, VALUE sa) {
   int vs = FIX2INT(rb_iv_get(self, "@version"));
   if (vs != FIX2INT(rb_iv_get(sa, "@version"))) rb_raise(rb_eArgError,
      "IPprefix.compare: Versions must be the same (4 or 6)");
   int nb = vs == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;
   VALUE s_v = rb_iv_get(self, "@addr");
   VALUE a_v = rb_iv_get(sa, "@addr");
   uint8_t *sp = (uint8_t *)RSTRING_PTR(s_v);
   uint8_t *ap = (uint8_t *)RSTRING_PTR(a_v);
   int r = memcmp(sp, ap, nb);
   if (r != 0) return INT2FIX(r < 0 ? -1 : +1);
   else return INT2FIX(0);
   }

static VALUE pr_width(VALUE self) {  /* |k| = length-1 */
   VALUE w = rb_iv_get(self, "@length");
   if (w == Qnil) rb_raise(rb_eArgError,
      "IPprefix.width: length nil, can't get width");
   return INT2FIX(FIX2INT(w)-1);
   }

static VALUE pr_preceq(VALUE self, VALUE v_arg) {  /* precedes or equals */
   int vs = FIX2INT(rb_iv_get(self, "@version"));
   if (vs != FIX2INT(rb_iv_get(v_arg, "@version"))) rb_raise(rb_eArgError,
      "IPprefix.first_bit_different: Versions must be same version (4 or 6)");
   int nb = vs == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;
   VALUE s_v = rb_iv_get(self, "@length");
   VALUE a_v = rb_iv_get(v_arg, "@length");
   if (s_v == Qnil || a_v == Qnil) rb_raise(rb_eArgError,
      "IPprefix.first_bit_different: either or both lengthis  nil");
   int s_len = FIX2INT(s_v);
   if (s_len > FIX2INT(a_v)) return Qfalse;  /* Widths not <= */

   uint8_t *sp = (uint8_t *)RSTRING_PTR(rb_iv_get(self, "@addr"));
   uint8_t *ap = (uint8_t *)RSTRING_PTR(rb_iv_get(v_arg, "@addr"));
   int j, r;
   uint8_t xor;
   for (j = 0; j != nb; ++j)
      if (ap[j] != sp[j]) break;
   r = j*8; 
   if (r >= s_len) return Qtrue;  /* They differ at or after min_len */
   xor = ap[j] ^ sp[j];
   while ((xor & 0x80) == 0) {
      r += 1;  xor <<= 1;
      }
   return r >= s_len ? Qtrue : Qfalse;  /* first_bit_different > width */
   }

static VALUE pr_equal(VALUE self, VALUE v_arg) {
   int v = FIX2INT(rb_iv_get(self, "@version"));
   if (v != FIX2INT(rb_iv_get(v_arg, "@version"))) rb_raise(rb_eArgError,
      "IPprefix.equal: Versions must be same version (4 or 6)");
   VALUE s_v = rb_iv_get(self, "@length");
   VALUE a_v = rb_iv_get(v_arg, "@length");
   if (s_v == Qnil || a_v == Qnil) rb_raise(rb_eArgError,
      "IPprefix.equal: either or both length nil");
   int s_len = FIX2INT(s_v);
   if (s_len != FIX2INT(a_v)) return Qfalse;
   int nb = v == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;
   uint8_t *sp = (uint8_t *)RSTRING_PTR(rb_iv_get(self, "@addr"));
   uint8_t *ap = (uint8_t *)RSTRING_PTR(rb_iv_get(v_arg, "@addr"));
   int j;
   for (j = 0; j != nb; ++j)
      if (ap[j] != sp[j]) break;
   if (j == nb) return Qtrue;  /* All bits same */
   return ((ap[j] ^ sp[j]) & p_mask[s_len%8]) == 0 ? Qtrue : Qfalse;
   }

static VALUE pr_first_bit_differ(VALUE self, VALUE v_arg) {
   int v = FIX2INT(rb_iv_get(self, "@version"));
   if (v != FIX2INT(rb_iv_get(v_arg, "@version"))) rb_raise(rb_eArgError,
      "IPprefix.first_bit_different: Versions must be same version (4 or 6)");
   int nb = v == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;
   VALUE s_v = rb_iv_get(self, "@length");
   VALUE a_v = rb_iv_get(v_arg, "@length");
   if (s_v == Qnil || a_v == Qnil) rb_raise(rb_eArgError,
      "IPprefix.first_bit_different: either or both length is nil"); 
   int s_len = FIX2INT(s_v), a_len = FIX2INT(a_v);
   uint8_t *sp = (uint8_t *)RSTRING_PTR(rb_iv_get(self, "@addr"));
   uint8_t *ap = (uint8_t *)RSTRING_PTR(rb_iv_get(v_arg, "@addr"));
   int min_len = s_len < a_len ? s_len : a_len;
   int j, r;
   uint8_t xor;
   for (j = 0; j != nb; ++j)
      if (ap[j] != sp[j]) break;
   if (j*8 >= min_len)  /* They differ at or after min_len */
      return INT2NUM(min_len);
   xor = ap[j] ^ sp[j];
   r = j*8; 
   while ((xor & 0x80) == 0) {
      r += 1;  xor <<= 1;
      }
   return INT2FIX(r >= min_len ? min_len : r);
   }

static VALUE pr_bit_set(VALUE self, VALUE v_arg) {
   VALUE v = FIX2INT(rb_iv_get(self, "@version"));
   int last_bit = v == 4 ? IP4_LAST_BIT : IP6_LAST_BIT;
   int n = NUM2INT(v_arg);  /* 0-org */
   if (n < 0)  /* Special case: <root> node has bit_index -1 */
        /* Always returns true, so <root> stays at top of the tree */
        return Qtrue;
   else if (n > last_bit)  /* Past last byte of key (string), always false */
      return Qfalse;
   else {
      uint8_t *ap = (uint8_t *)RSTRING_PTR(rb_iv_get(self, "@addr"));
      return(ap[n/8] & b_mask[n%8]) != 0 ? Qtrue : Qfalse;
      }
   }

static VALUE pr_complement(VALUE self) {
   VALUE ver = rb_iv_get(self, "@version");
   int nb = FIX2INT(ver) == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;
   uint8_t *sp = (uint8_t *)RSTRING_PTR(rb_iv_get(self, "@addr"));
   VALUE len = rb_iv_get(self, "@length");
   uint8_t a[IP6_ADDR_LEN];  int j;
   for (j = 0; j != nb; ++j) a[j] = ~sp[j];
   VALUE rk_argv[] = { ver, rb_str_new((char *)a, nb), len };
   return rb_class_new_instance(3, rk_argv, ipPref);
   }

static char *strmov(char *d, char *s) {
   while (*s != '\0') *d++ = *s++;
   return d;
   }

static char v6a[60];
static char *v6addr_to_s(uint8_t *in6a)
{  /* Returns pointer to next byte in v6a 
      Code from NeTraMet's nmc_pars.c */
   char buf[10];  /* RFC 2373: IPv6 Address Architecture */
   char *d = v6a;
   char *a = (char *)in6a;
   int j, k, st,len, stx,lenx;
   uint32_t v, a2[8];

   stx = st = len = lenx = 0;
   for (k = j = 0; j != 16; j += 2) {
      v =  ntohs(*(uint16_t *)&a[j]);
      a2[k++] = v;          /* Build array of two-byte pairs */
      if (v == 0) ++len;
      else {
         if (len > lenx) {  /* Find longest run of zero pairs */
            stx = st;  lenx = len;
	    }
         st = k;  len = 0;
         }
      }

   if (len > lenx) {
      stx = st;  lenx = len;
      }
   if (lenx != 0 && stx == 0) {  /* Longest run at left */
      d = strmov(d, ":");  j = lenx;
      }
   else {
      sprintf(buf, "%x", a2[0]);
      d = strmov(d,buf);  j = 1;
      }
   for (; j < 8; ) {
      if (lenx != 0 && j == stx) {
         d = strmov(d,":");  j += lenx;
         }
      else {
         sprintf(buf, ":%x", a2[j]);
         d = strmov(d, buf);  ++j;
         }
      }
   if (j == stx+lenx) d = strmov(d, ":");  /* Longest run at right */
   *d = '\0';
   return d;
   }

static VALUE pr_to_s(VALUE self) {
   int ver = FIX2INT(rb_iv_get(self, "@version"));
   VALUE addr = rb_iv_get(self, "@addr");
   uint8_t *ap = (uint8_t *)RSTRING_PTR(addr);
   VALUE length = rb_iv_get(self, "@length");
   int w = length == Qnil ? -1 : FIX2INT(length);

   if (ver == 4) {
      if (w < 0) sprintf(v6a, "%u.%u.%u.%u",
         ap[0],ap[1],ap[2],ap[3]);
      else sprintf(v6a, "%u.%u.%u.%u/%u",
         ap[0],ap[1],ap[2],ap[3], w);
      }
   else {
      char *v6e = v6addr_to_s(ap);
      if (w >= 0) sprintf(v6e, "/%u", w);
      }
   return rb_str_new2(v6a);
   }

static uint16_t get_nbr(char **str, int *rem, int *base) {
   char *s = *str;
   int len = *rem, b = *base, j,k, c, n;

   for (j = 0; j != len; ++j) {
      c = s[j];
      if (c == '.') {
 	 if (!b) b = 10;  break;
         if (b == 16) rb_raise(rb_eArgError,
            "IPprefix.from_s: can't have . in IPv6 address!");
         }
      if (c == ':') {
 	 if (!b) b = 16;  break;
         if (b == 10) rb_raise(rb_eArgError,
            "IPprefix.from_s: can't have : in IPv4 address!");
         }
      if (c == '/') break;
      if (!isdigit(c) && isxdigit(c)) {
 	 if (!b) { b = 16; }
         }
      if (b == 10 && !isdigit(c)) rb_raise(rb_eArgError,
         "IPprefix.from_s: non-decimal digit in IPv4 address!");
      else if (!isxdigit(c)) rb_raise(rb_eArgError,
         "IPprefix.from_s: non-hex digit in IPv6 address!");
      if (!isxdigit(c)) {
         rb_raise(rb_eArgError,
            "IPprefix.from_s: non-(hex) digit found!");
         }
      }

   for (n = k = 0; k != j; ++k) {
      c = s[k];
      if (c >= '0' && c <= '9') n = n*b + (c-'0');
      else  if (c >= 'a' && c <= 'f') n = n*b + (10 + c-'a');
      else n = n*b + (10 + c-'A');
      }

   *str = &s[j];  *rem = len-j;  *base = b;
   return n;
   }

static VALUE pr_from_s(VALUE self, VALUE v_str) {
   VALUE pa[3] = { Qnil, Qnil, Qnil };
   char *str = RSTRING_PTR(v_str), *sp;
   int len = RSTRING_LEN(v_str);
   int base, n, x, dcx, havedcx, y, argc;
   char a[16], *a2p;  uint16_t a2[8];

   memset(a, 0, sizeof(a));
   sp = str;
   havedcx = dcx = 0;
   if (sp[0] == ':') {
      if (sp[1] == ':') {
         base = 16; havedcx = 1;  dcx = -1;
         sp += 2;  len -= 2;
         }
      else rb_raise(rb_eArgError,
	 "IPprefix.from_s: can't start an IPv6 address with : !");
      }
   else {
      base = 0;  havedcx = 0;
      }

   n = get_nbr(&sp, &len, &base);

   if (base == 10) {  /* IPv4 prefix */   
      for (x = 0; x != 4; ++x) {
	 if (n > 255) rb_raise(rb_eArgError,
	    "IPprefix.from_s: integer > 255 in IPv4 address!");
	 a[x] = n;
         if (len == 0) break;
         sp += 1; len -= 1;
         n = get_nbr(&sp, &len, &base);
         if (len == 0 || *sp == '/') {
	    a[x+1] = n;  break;
	    }
         }
      pa[0] = INT2FIX(4);
      pa[1] = rb_str_new(a, 4);
      if (len == 0) argc = 2;
      else if (*sp == '/') {
         argc = 3;
         sp += 1; len -= 1;
         n = get_nbr(&sp, &len, &base);
         if (n > 32) rb_raise(rb_eArgError,
            "IPprefix.from_s: IPv4 prefix length > 32!");
         pa[2] = INT2FIX(n);
	 }
      else rb_raise(rb_eArgError,
         "IPprefix.from_s: more than 4 integers in IPv4 address!");
      }
   else if (base == 16) {  /* IPv6 prefix */
      memset(a2, 0, sizeof(a2));
      for (x = 0; x != 8; ++x) {
	 if (n > 0xFFFF) rb_raise(rb_eArgError,
	    "IPprefix.from_s: integer > 0xFFFF in IPv6 address!");
	  a2[x] = ntohs((uint16_t)n);  /* Nathan, 13 Aug 09 */
          if (len == 0 || *sp == '/') {
	    /* x += 1;  a2[x] = ntohs((uint16_t)n);  Nathan, 13 Aug 09 */
            break;
	    }
         sp += 1; len -= 1;  /* Skip the delimiter */
         n = get_nbr(&sp, &len, &base);
         if (sp[1] == ':') {
            if (havedcx) rb_raise(rb_eArgError,
               "IPprefix.from_s: can only have one :: in an IPv6 address!");
 	    dcx = x+1;  havedcx = 1;
	    sp += 1;  len -= 1;
            }
         }
      a2p = (char *)a2;
      if (!havedcx) memcpy(a, a2p, 16);
      else {
	 if (dcx >= 0) memcpy(a, a2p, (dcx+1)*2);
         y = (x-dcx)*2;    
         memcpy(a + (16-y), a2p + (dcx+1)*2, y);
         }
      pa[0] = INT2FIX(6);
      pa[1] = rb_str_new(a, 16);
      if (len == 0) argc = 2;
      else if (*sp == '/') {
         argc = 3;
         sp += 1; len -= 1;  base = 10;
         n = get_nbr(&sp, &len, &base);
         if (n > 128) rb_raise(rb_eArgError,
            "IPprefix.from_s: IPv6 prefix length > 128!");
         pa[2] = INT2FIX(n);
	 }
      else rb_raise(rb_eArgError,
         "IPprefix.from_s: more than 8 hex numbers in IPv6 address!");
      }
    else rb_raise(rb_eArgError,
       "IPprefix.from_s: can't tell whether address is IPv4 or IPv6!");

   VALUE vp = rb_class_new_instance(argc, pa, ipPref);
   return vp;
   }

void Init_IPprefix() {
   ipPref = rb_define_class("IPprefix", rb_cObject);
   /* from_s is a class function */
   rb_define_module_function(ipPref, "from_s", pr_from_s, 1);

   rb_define_method(ipPref, "initialize", pr_init, -1);
   rb_define_method(ipPref, "version", pr_version, 0);
   rb_define_method(ipPref, "addr", pr_addr, 0);
   rb_define_method(ipPref, "length", pr_length, 0);  /* ||k|| */
   rb_define_method(ipPref, "length=", pr_set_length, 1);
   rb_define_method(ipPref, "==", pr_addr_equal, 1);  /* Only compare addrs */
   rb_define_method(ipPref, "<=>", pr_addr_compare, 1);
   rb_define_method(ipPref, "to_s", pr_to_s, 0);

   /* Following methods check that length is non-nil (for IP prefix testing) */
   rb_define_method(ipPref, "width", pr_width, 0);   /*  |k|  = length-1 */
   rb_define_method(ipPref, "prefix?", pr_preceq, 1);
   rb_define_method(ipPref, "equal", pr_equal, 1);
   rb_define_method(ipPref, "bit_set?", pr_bit_set, 1);
   rb_define_method(ipPref, "first_bit_different", pr_first_bit_differ, 1);
   rb_define_method(ipPref, "complement", pr_complement, 0);
   }
