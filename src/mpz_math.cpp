#include <gmpxx.h>
#include <assert.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "../include/mpz_math.h"

gmp_randstate_t RANDSTATE;

void legendre(mpz_t &ret, const mpz_t &a, const mpz_t &p)
{
    mpz_t v;
    mpz_init(v);
    mpz_sub_ui(v, p, 1);    //v = p - 1
    mpz_fdiv_q_ui(v, v, 2); //v = v // 2
    mpz_powm(ret, a, v, p); // ret =  pow(a, (p - 1) // 2, p)
    mpz_clear(v);
}

//https://github.com/hvy/integer-factorization/blob/80e73f8910b827d7d17221f829426a15088648c7/src/test.c
void tonelli_shanks(mpz_t &x, const mpz_t &n, const mpz_t &p)
{
    mpz_t v;
    mpz_init(v);
    legendre(v, n, p);
    bool is_square_mod_p = (mpz_cmp_ui(v, 1) == 0);
    mpz_clear(v);
    if (!is_square_mod_p)
    {
        gmp_printf("square = %Zd and p =  %Zd is not a square (mod p)  \n", n, p);
        assert(is_square_mod_p);
    }

    mpz_t two, minus_one, p_minus_one, q, s, z, c, r, t, m, tmp, tmp2, t_sqrt, b;

    mpz_init_set_ui(two, 2);
    mpz_init_set_ui(minus_one, -1);
    mpz_init(p_minus_one);
    mpz_init(q);
    mpz_init_set_ui(s, 0);
    mpz_init_set_ui(z, 2);
    mpz_init(c);
    mpz_init(r);
    mpz_init(t);
    mpz_init(m);
    mpz_init(tmp);
    mpz_init(tmp2);
    mpz_init(t_sqrt);
    mpz_init(b);

    mpz_sub_ui(p_minus_one, p, 1);
    mpz_set(q, p_minus_one);
    while (0 != mpz_even_p(q) /* while q is even */)
    {
        mpz_add_ui(s, s, 1);
        mpz_divexact_ui(q, q, 2);
    }

    /* Find the quadratic non-residue */
    while (-1 != mpz_legendre(z, p))
    {
        mpz_add_ui(z, z, 1);
    }

    mpz_powm(c, z, q, p);
    mpz_add_ui(tmp, q, 1); /* q is odd, so tmp will be even */
    mpz_divexact_ui(tmp, tmp, 2);
    mpz_powm(r, n, tmp, p);
    mpz_powm(t, n, q, p);
    mpz_set(m, s);

    while (1)
    {
        if (0 == mpz_cmp_ui(t, 1) /* t == 1 */)
        {
            mpz_set(x, r);
            break;
        }
        else
        {
            long msl = mpz_get_si(m);
            for (long i = 0; i < msl; ++i)
            {
                mpz_pow_ui(tmp, two, i);
                mpz_powm(t_sqrt, t, tmp, p);
                if (0 == mpz_cmp_ui(t_sqrt, 1) /* t^(1/2) == 1 */)
                {
                    mpz_pow_ui(tmp, two, msl - i - 1);
                    mpz_powm(b, c, tmp, p);
                    mpz_mul(r, r, b);
                    mpz_mod(r, r, p);
                    mpz_pow_ui(tmp, b, 2);
                    mpz_mul(t, t, tmp);
                    mpz_mod(t, t, p);
                    mpz_mod(c, tmp, p);
                    mpz_set_ui(m, i);
                    break;
                }
            }
        }
    }

    mpz_clear(two);
    mpz_clear(minus_one);
    mpz_clear(p_minus_one);
    mpz_clear(q);
    mpz_clear(s);
    mpz_clear(z);
    mpz_clear(c);
    mpz_clear(r);
    mpz_clear(t);
    mpz_clear(m);
    mpz_clear(tmp);
    mpz_clear(tmp2);
    mpz_clear(t_sqrt);
    mpz_clear(b);
}

std::string str2hex_str(const std::string &op)
{
    unsigned char hexChars[] = "0123456789abcdef";
    unsigned int a, b;
    std::string hex_rop;

    for (int i = 0; i < op.size(); ++i)
    {
        unsigned char c = op[i];
        a = (c >> 4) & 0x0f;
        b = c & 0x0f;
        hex_rop.push_back(hexChars[a]);
        hex_rop.push_back(hexChars[b]);
    }

    return hex_rop;
}

std::string hex_str2str(const std::string &hex_op)
{
    std::string rop;
    int len = hex_op.size();
    int start = 0;
    if (len % 2 == 1)
    {
        unsigned char v = 0;
        unsigned char c = hex_op[0];
        if (c >= '0' && c <= '9')
            v += (c - '0');
        else if (c >= 'a' && c <= 'f')
            v += (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v += (c - 'A' + 10);

        rop.push_back(v);
        start++;
    }

    for (int i = start; i < len; i += 2)
    {
        unsigned char v = 0;

        unsigned char c = hex_op[i];
        if (c >= '0' && c <= '9')
            v += (c - '0') * 16;
        else if (c >= 'a' && c <= 'f')
            v += (c - 'a' + 10) * 16;
        else if (c >= 'A' && c <= 'F')
            v += (c - 'A' + 10) * 16;

        c = hex_op[i + 1];
        if (c >= '0' && c <= '9')
            v += (c - '0');
        else if (c >= 'a' && c <= 'f')
            v += (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v += (c - 'A' + 10);

        rop.push_back(v);
    }
    return rop;
}

std::string mpz2str(const mpz_t &op, const int base)
{

    unsigned int len = mpz_sizeinbase(op, base) + 2;
    char *rop = new char[len];
    mpz_get_str(rop, base, op);
    std::string dec_str(rop);
    delete (rop);
    return dec_str;
}

std::string sha256(const std::string &message)
{
    unsigned char hash[32];

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message.c_str(), message.size());
    SHA256_Final(hash, &ctx);

    std::string digest((char *)hash, 32);
    return digest;
}

std::string hmac_sha256(const std::string &key, const std::string &data)
{
    unsigned char hash[32];
    uint32_t hash_value_len = 0;
#if (OPENSSL_VERSION_NUMBER >= 0x10100001L)
    HMAC_CTX *ctx;

    ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.c_str(), key.size(), EVP_sha256(), NULL);
    HMAC_Update(ctx, (unsigned char *)data.c_str(), data.size());
    HMAC_Final(ctx, (unsigned char *)hash, &hash_value_len);
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX ctx;

    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key.c_str(), key.size(), EVP_sha256(), NULL);
    HMAC_Update(&ctx, (unsigned char *)data.c_str(), data.size());
    HMAC_Final(&ctx, (unsigned char *)hash, &hash_value_len);
    HMAC_CTX_cleanup(&ctx);
#endif

    std::string digest((char *)hash, 32);
    return digest;
}

std::string transmute_u32_to_u8str(const unsigned int n, const U32Kind mode)
{
    std::string u8str(4, 0);
    if (mode == U32Kind::BE)
    {

        u8str[0] = (n >> 24) & 0xff;
        u8str[1] = (n >> 16) & 0xff;
        u8str[2] = (n >> 8) & 0xff;
        u8str[3] = n & 0xff;
    }
    else //默认为小端
    {

        u8str[3] = (n >> 24) & 0xff;
        u8str[2] = (n >> 16) & 0xff;
        u8str[1] = (n >> 8) & 0xff;
        u8str[0] = n & 0xff;
    }

    return u8str;
}