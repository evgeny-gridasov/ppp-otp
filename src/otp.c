#include <stdio.h>
#include <stdint.h>
#include <endian.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#ifndef htobe64
#include <netinet/in.h>
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <pppd/pppd.h>
#include <pppd/chap-new.h>
#include <pppd/chap_ms.h>

#include "base32.h"
#include "hex.h"

char pppd_version[] = VERSION;

static char *DEFAULT_OTP_SECRETS = "/etc/ppp/otp-secrets";

static char *otp_secrets = NULL;
static int otp_slop = 180;

static int totp_t0 = 0;
static int totp_step = 30;
static int totp_digits = 6;

static int motp_step = 10;


typedef struct user_entry user_entry_t;

struct user_entry {
    char name[MAXWORDLEN];
    char server[MAXWORDLEN];
    char secret[MAXWORDLEN];
    char addr[MAXWORDLEN];
};

typedef struct otp_params otp_params_t;

struct otp_params {
    const char *method;
    const char *hash;
    const char *encoding;
    const char *key;
    const char *pin;
    const char *udid;
};


#if DEBUG

#define LOG(format, ...) logmessage(format, ## __VA_ARGS__)

static FILE *logfp = NULL;

static void
logmessage(const char *format, ...)
{
    if (NULL == logfp) {
        logfp = fopen("/tmp/otp.log", "a+");
    }

    va_list va;

    va_start(va, format);
    vfprintf(logfp, format, va);
    va_end(va);
}

#else

#define LOG(format, ...)

#endif

#ifndef htobe64

static uint64_t
htobe64(uint64_t value)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint32_t low = htonl(value);
    uint32_t high = htonl(value >> 32);
    return (((uint64_t)low) << 32) | high;
#elif __BYTE_ORDER == __BIG_ENDIAN
    return value;
#else
#error "Unknown BYTE_ORDER"
#endif
}

#endif

static int
set_otp_secrets(char **argv)
{
    if ('/' != argv[0][0]) {
        option_error("otp_secrets must be full path");
        return 0;
    }

    free(otp_secrets);
    otp_secrets  = strdup(argv[0]);
    if (!otp_secrets) {
        novm("otp_secrets argument");
        return 0;
    }

    return 1;
}


static void
seek_eoln(FILE *secrets_file)
{
    while (!feof(secrets_file) && '\n' != fgetc(secrets_file)) {
        // Do nothing
    }
}


static int
read_word(FILE *secrets_file, char word[MAXWORDLEN])
{
    char ch = 0;
    char *p = word;
    char *q = word + MAXWORDLEN - 1;
    char quote = 0;

    while (!feof(secrets_file) && isspace((ch = fgetc(secrets_file)))) {
        // Do nothing
    }

    while (!feof(secrets_file)) {
        if (quote) {
            if (ch == quote) {
                quote = 0;
            }
            else {
                *p++ = ch;
            }
        }
        else if (isspace(ch) || '#' == ch) {
            *p = *q = 0;
            return ch;
        }
        else if ('\'' == ch || '"' == ch) {
            quote = ch;
        }
        else if ('\\' == ch) {
            *p = fgetc(secrets_file);
            if ('\n' != *p) {
                ++p;
            }
        }
        else {
            *p++ = ch;
        }

        if (p > q) {
            return -1;
        }

        ch = fgetc(secrets_file);
    }

    return -1;
}


static int
read_user_entry(FILE *secrets_file, user_entry_t *user_entry)
{
    int rc;

retry:
    if (feof(secrets_file)) {
        return -1;
    }

    rc = read_word(secrets_file, user_entry->name);
    if ('#' == rc || -1 == rc) {
        seek_eoln(secrets_file);
        goto retry;
    }

    if ('\n' == rc) {
        goto retry;
    }

    rc = read_word(secrets_file, user_entry->server);
    if ('#' == rc || -1 == rc) {
        seek_eoln(secrets_file);
        goto retry;
    }

    if ('\n' == rc) {
        goto retry;
    }

    rc = read_word(secrets_file, user_entry->secret);
    if ('#' == rc || -1 == rc) {
        seek_eoln(secrets_file);
        goto retry;
    }

    if ('\n' == rc) {
        goto retry;
    }

    rc = read_word(secrets_file, user_entry->addr);
    if (-1 == rc) {
        seek_eoln(secrets_file);
        goto retry;
    }

    if ('\n' != rc) {
        seek_eoln(secrets_file);
    }

    return 0;
}


static int
split_secret(char *secret, otp_params_t *otp_params)
{
    char *p = secret;

    otp_params->method = p;
    if (NULL == (p = strchr(p, ':'))) {
        return -1;
    }
    *p++ = 0;

    otp_params->hash = p;
    if (NULL == (p = strchr(p, ':'))) {
        return -1;
    }
    *p++ = 0;

    otp_params->encoding = p;
    if (NULL == (p = strchr(p, ':'))) {
        return -1;
    }
    *p++ = 0;

    otp_params->key = p;
    if (NULL == (p = strchr(p, ':'))) {
        return -1;
    }
    *p++ = 0;

    otp_params->pin = p;
    if (NULL != (p = strchr(p, ':'))) {
        *p++ = 0;
    }

    otp_params->udid = p;

    if (p && strchr(p, ':')) {
        return -1;
    }

    return 0;
}


static int
otp_chap_check()
{
    return 1;
}


static int
otp_chap_verify(char *name, char *ourname, int id,
        struct chap_digest_type *digest, unsigned char *challenge,
        unsigned char *response, char *message, int message_space)
{
    FILE *secrets_file;
    user_entry_t user_entry;
    otp_params_t otp_params;

    const EVP_MD *otp_digest;
    EVP_MD_CTX ctx;
    char secret[256];
    int i, secret_len;
    int ok = 0;

    if (NULL == otp_secrets) {
        otp_secrets = DEFAULT_OTP_SECRETS;
    }

    secrets_file = fopen(otp_secrets, "r");
    if (NULL == secrets_file) {
        LOG("Failed to open %s\n", otp_secrets);
        goto done;
    }

    while (!feof(secrets_file)) {
        if (read_user_entry(secrets_file, &user_entry)) {
            continue;
        }

        if (strcmp(name, user_entry.name)) {
            continue;
        }

        break;
    }

    /* Handle non-otp passwords before trying to parse out otp fields */
    if (!strncasecmp(user_entry.secret, "plain:", sizeof("plain:") - 1)) {
        const char *password = user_entry.secret + sizeof("plain:") - 1;

        ok = digest->verify_response(id, name, (uint8_t *)password,
            strlen(password), challenge, response, message, message_space);
        goto done;
    }

    if (split_secret(user_entry.secret, &otp_params)) {
        goto done;
    }

    otp_digest = EVP_get_digestbyname(otp_params.hash);
    if (!otp_digest) {
        LOG("Unknown digest '%s'\n", otp_params.hash);
        goto done;
    }

    unsigned int key_len;
    const void * otp_key;
    
    if (!strcasecmp(otp_params.encoding, "base32")) {
	uint8_t base32[256];
        key_len = base32_decode((uint8_t *) otp_params.key, base32, sizeof(base32)); 
        otp_key = base32;
    } else
    if (!strcasecmp(otp_params.encoding, "hex")) {
  	uint8_t hex[256];
  	key_len = hex_decode(otp_params.key, hex, sizeof(hex));
  	otp_key = hex;
    } else
    if (!strcasecmp(otp_params.encoding, "text")) {
        otp_key = otp_params.key;
        key_len = strlen(otp_params.key);
    } else {
        LOG("Unknown encoding '%s'\n", otp_params.encoding);
        goto done;
    }
    unsigned int user_pin = atoi(otp_params.pin);

    uint64_t T, Tn;
    uint8_t mac[EVP_MAX_MD_SIZE];
    unsigned maclen;

    if (!strncasecmp("totp", otp_params.method, 4)) {
        HMAC_CTX hmac;
        const uint8_t *otp_bytes;
        uint32_t otp, divisor = 1;
        int tstep = totp_step;
        int tdigits = totp_digits;
        if (!strcasecmp("totp-60-6", otp_params.method)) {
            tstep = 60;
            tdigits = 6;
        }
        int range = otp_slop / tstep;

        T = (time(NULL) - totp_t0) / tstep;

        for (i = 0; i < tdigits; ++i) {
            divisor *= 10;
        }

        for (i = -range; !ok && i <= range; ++i) {
            Tn = htobe64(T + i);

            HMAC_CTX_init(&hmac);
            HMAC_Init_ex(&hmac, otp_key, key_len, otp_digest, NULL);
            HMAC_Update(&hmac, (uint8_t *)&Tn, sizeof(Tn));
            HMAC_Final(&hmac, mac, &maclen);

            otp_bytes = mac + (mac[maclen - 1] & 0x0f);
            otp = ((otp_bytes[0] & 0x7f) << 24) | (otp_bytes[1] << 16) |
                  (otp_bytes[2] << 8) | otp_bytes[3];
            otp %= divisor;

            secret_len = snprintf(secret, sizeof(secret),
                    "%04u%0*u", user_pin, tdigits, otp);

            ok = digest->verify_response(id, name, (uint8_t *)secret,
                    secret_len, challenge, response, message, message_space);
        }
    }
    else if (!strcasecmp("motp", otp_params.method)) {
        char buf[64];
        int n;
        int range = otp_slop / motp_step;

        T = time(NULL) / motp_step;

        for (i = -range; !ok && i <= range; ++i) {
            EVP_MD_CTX_init(&ctx);
            EVP_DigestInit_ex(&ctx, otp_digest, NULL);
            n = sprintf(buf, "%" PRIu64, T + i);
            EVP_DigestUpdate(&ctx, buf, n);
            EVP_DigestUpdate(&ctx, otp_key, key_len);
            n = sprintf(buf, "%u", user_pin);
            EVP_DigestUpdate(&ctx, buf, n);
            if (otp_params.udid) {
                int udid_len = strlen(otp_params.udid);
                EVP_DigestUpdate(&ctx, otp_params.udid, udid_len);
            }
            EVP_DigestFinal_ex(&ctx, mac, &maclen);
            EVP_MD_CTX_cleanup(&ctx);

            secret_len = snprintf(secret, sizeof(secret),
                    "%02x%02x%02x", mac[0], mac[1], mac[2]);

            ok = digest->verify_response(id, name, (uint8_t *)secret,
                    secret_len, challenge, response, message, message_space);
        }
    }
    else {
        LOG("Unknown OTP method %s\n", otp_params.method);
    }

done:
    memset(secret, 0, sizeof(secret));

    if (NULL != secrets_file) {
        fclose(secrets_file);
    }

    if (!ok) {
        error("No OTP secret found for authenticating %q", name);
    }

    return ok;
}


static int
otp_allowed_address(u_int32_t addr)
{
    // TODO: Check settings file
    return 1;
}


static void
otp_on_exit(void *user, int arg)
{
}


static option_t otp_options[] = {
    {
        .name = "otp_secrets",
        .type = o_special,
        .addr = (void *)&set_otp_secrets,
        .description = "Path to otp secrets file",
        .flags = OPT_PRIV
    },
    {
        .name = "otp_slop",
        .type = o_int,
        .addr = &otp_slop,
        .description = "Maximum allowed clock slop",
        .flags = OPT_PRIV | OPT_LIMITS,
        .lower_limit = 0,
        .upper_limit = 600
    },

    {
        .name = "totp_t0",
        .type = o_int,
        .addr = &totp_t0,
        .description = "T0 value for TOTP",
        .flags = OPT_PRIV | OPT_LLIMIT,
        .lower_limit = 0
    },
    {
        .name = "totp_step",
        .type = o_int,
        .addr = &totp_step,
        .description = "Step value for TOTP",
        .flags = OPT_PRIV | OPT_LLIMIT,
        .lower_limit = 60
    },
    {
        .name = "totp_digits",
        .type = o_int,
        .addr = &totp_digits,
        .description = "Number of digits to use from TOTP hash",
        .flags = OPT_PRIV | OPT_LIMITS,
        .lower_limit = 2,
        .upper_limit = 9
    },

    {
        .name = "motp_step",
        .type = o_int,
        .addr = &motp_step,
        .description = "Step value for MOTP",
        .flags = OPT_PRIV | OPT_LLIMIT,
        .lower_limit = 60
    },

    { NULL }
};


void
plugin_init()
{
    OpenSSL_add_all_digests();

    chap_check_hook = otp_chap_check;
    chap_verify_hook = otp_chap_verify;
    allowed_address_hook = otp_allowed_address;

    chap_mdtype_all &= (MDTYPE_MICROSOFT | MDTYPE_MICROSOFT_V2);

    add_notifier(&exitnotify, otp_on_exit, NULL);

    add_options(otp_options);

    info("OTP plugin initialized");
}

