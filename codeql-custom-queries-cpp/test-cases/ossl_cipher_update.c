#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct ruby_string {
    char *ptr;
    long len;
    long capacity;
} ruby_string;

typedef ruby_string *VALUE;
typedef unsigned long ID;
typedef struct evp_cipher_ctx_st {
    int dummy;
} EVP_CIPHER_CTX;

#define Qnil ((VALUE)0)
#define Qtrue ((VALUE)1)
#define Qfalse ((VALUE)2)

#define RB_GC_GUARD(v) do { (void)0; } while (0)
#define NIL_P(v) ((v) == Qnil)
#define RTEST(v) (!NIL_P(v))
#define StringValue(v) ((void)(v))
#define RSTRING_PTR(v) ((v)->ptr)
#define RSTRING_LEN(v) ((v)->len)
#define RSTRING_LENINT(v) ((int)RSTRING_LEN(v))

static inline long
rb_str_capacity(VALUE str)
{
    return str->capacity;
}

static VALUE
rb_str_new(const char *ptr, long len)
{
    ruby_string *s = (ruby_string *)malloc(sizeof(ruby_string));
    s->capacity = len;
    s->len = len;
    s->ptr = (char *)calloc((size_t)(len > 0 ? len : 1), 1);
    if (ptr && len > 0) {
        memcpy(s->ptr, ptr, (size_t)len);
    }
    return s;
}

static void
rb_str_modify(VALUE str)
{
    str->len = str->capacity;
}

static void
rb_str_modify_expand(VALUE str, long add)
{
    str->capacity += add;
    str->len += add;
    str->ptr = (char *)realloc(str->ptr, (size_t)(str->capacity > 0 ? str->capacity : 1));
}

static void
rb_str_set_len(VALUE str, long len)
{
    str->len = len;
}

static VALUE
rb_attr_get(VALUE obj, ID id)
{
    (void)obj;
    (void)id;
    return Qtrue;
}

static void
rb_scan_args(int argc, VALUE *argv, const char *fmt, VALUE *v1, VALUE *v2)
{
    (void)fmt;
    *v1 = argc > 0 ? argv[0] : Qnil;
    *v2 = argc > 1 ? argv[1] : Qnil;
}

static VALUE rb_eRangeError = (VALUE)4;
static VALUE eCipherError = (VALUE)5;
static ID id_key_set = (ID)6;
static EVP_CIPHER_CTX dummy_ctx;

static void
ossl_raise(VALUE exc, const char *fmt, ...)
{
    (void)exc;
    (void)fmt;
}

#define GetCipher(obj, ctx) do { (void)(obj); (ctx) = &dummy_ctx; } while (0)

#define EVP_MAX_BLOCK_LENGTH 32
static int
EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *out_len,
                 const unsigned char *in, int in_len)
{
    (void)ctx;
    if (out && in) memcpy(out, in, (size_t)in_len);
    if (out_len) *out_len = in_len;
    return 1;
}

static int
ossl_cipher_update_long(EVP_CIPHER_CTX *ctx, unsigned char *out, long *out_len_ptr,
			const unsigned char *in, long in_len)
{
    int out_part_len;
    int limit = INT_MAX / 2 + 1;
    long out_len = 0;

    do {
	int in_part_len = in_len > limit ? limit : (int)in_len;

	if (!EVP_CipherUpdate(ctx, out ? (out + out_len) : 0,
			      &out_part_len, in, in_part_len))
	    return 0;

	out_len += out_part_len;
	in += in_part_len;
    } while ((in_len -= limit) > 0);

    if (out_len_ptr)
	*out_len_ptr = out_len;

    return 1;
}

/*
 *  call-seq:
 *     cipher.update(data [, buffer]) -> string or buffer
 *
 *  Encrypts data in a streaming fashion. Hand consecutive blocks of data
 *  to the #update method in order to encrypt it. Returns the encrypted
 *  data chunk. When done, the output of Cipher#final should be additionally
 *  added to the result.
 *
 *  If _buffer_ is given, the encryption/decryption result will be written to
 *  it. _buffer_ will be resized automatically.
 */
static VALUE
ossl_cipher_update(int argc, VALUE *argv, VALUE self)
{
    RB_GC_GUARD(self);
    RB_GC_GUARD(str);
    RB_GC_GUARD(data);
    EVP_CIPHER_CTX *ctx;
    unsigned char *in;
    long in_len, out_len;
    VALUE data, str;

    rb_scan_args(argc, argv, "11", &data, &str);

    if (!RTEST(rb_attr_get(self, id_key_set)))
	ossl_raise(eCipherError, "key not set");

    StringValue(data);
    in = (unsigned char *)RSTRING_PTR(data);
    in_len = RSTRING_LEN(data);
    GetCipher(self, ctx);

    /*
     * As of OpenSSL 3.2, there is no reliable way to determine the required
     * output buffer size for arbitrary cipher modes.
     * https://github.com/openssl/openssl/issues/22628
     *
     * in_len+block_size is usually sufficient, but AES key wrap with padding
     * ciphers require in_len+15 even though they have a block size of 8 bytes.
     *
     * Using EVP_MAX_BLOCK_LENGTH (32) as a safe upper bound for ciphers
     * currently implemented in OpenSSL, but this can change in the future.
     */
    if (in_len > LONG_MAX - EVP_MAX_BLOCK_LENGTH) {
	ossl_raise(rb_eRangeError,
		   "data too big to make output buffer: %ld bytes", in_len);
    }
    out_len = in_len + EVP_MAX_BLOCK_LENGTH;

    if (NIL_P(str)) {
        str = rb_str_new(0, out_len);
    } else {
        StringValue(str);
        if ((long)rb_str_capacity(str) >= out_len)
            rb_str_modify(str);
        else
            rb_str_modify_expand(str, out_len - RSTRING_LEN(str));
    }

    if (!ossl_cipher_update_long(ctx, (unsigned char *)RSTRING_PTR(str), &out_len, in, in_len))
	ossl_raise(eCipherError, NULL);
    assert(out_len <= RSTRING_LEN(str));
    rb_str_set_len(str, out_len);

    return str;
}

int
main(void)
{
    VALUE self = rb_str_new("cipher", 6);

    VALUE data1 = rb_str_new("hello", 5);
    VALUE argv1[] = { data1 };
    VALUE out1 = ossl_cipher_update(1, argv1, self);
    printf("update(data) len=%ld, bytes=\"%.*s\"\n",
           RSTRING_LEN(out1), (int)RSTRING_LEN(out1), RSTRING_PTR(out1));

    VALUE data2 = rb_str_new("world", 5);
    VALUE buffer = rb_str_new("buf", 3);
    VALUE argv2[] = { data2, buffer };
    VALUE out2 = ossl_cipher_update(2, argv2, self);
    printf("update(data, buffer) len=%ld, bytes=\"%.*s\"\n",
           RSTRING_LEN(out2), (int)RSTRING_LEN(out2), RSTRING_PTR(out2));

    return 0;
}
