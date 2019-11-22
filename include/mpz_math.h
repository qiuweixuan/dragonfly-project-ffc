#ifndef MPZ_MATH
#define MPZ_MATH

#include <gmpxx.h>

void legendre(mpz_t &ret, const mpz_t &a, const mpz_t &p);

//https://github.com/hvy/integer-factorization/blob/80e73f8910b827d7d17221f829426a15088648c7/src/test.c
void tonelli_shanks(mpz_t &x, const mpz_t &n, const mpz_t &p);

std::string str2hex_str(const std::string &op);

std::string hex_str2str(const std::string &hex_op);

std::string mpz2str(const mpz_t &op, const int base);

std::string sha256(const std::string &message);

std::string hmac_sha256(const std::string &key, const std::string &data);

extern gmp_randstate_t RANDSTATE;

enum class U32Kind
{
    BE,
    LE,
};

std::string transmute_u32_to_u8str(const unsigned int n, const U32Kind mode);

#endif