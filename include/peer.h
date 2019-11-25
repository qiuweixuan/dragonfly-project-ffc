#ifndef PEER_H
#define PEER_H

#include <string>
#include <gmpxx.h>

class Peer
{
public:
    std::string password;
    std::string mac_address;
    std::string name;

    mpz_t prime;
    mpz_t order;
    bool safe_prime;
    mpz_t password_element;

    mpz_t priv;
    mpz_t mask;
    mpz_t scalar;
    mpz_t element;

    mpz_t peer_scalar;
    mpz_t peer_element;
    std::string peer_mac;
    std::string ss_hex;

    std::string kck;
    std::string pmk;
    std::string pmkid;

public:
    Peer(const std::string &password, const std::string &mac_address, const std::string &name);
    ~Peer();

    // void initiate(std::string peer_mac, int k = 40);
    void initiate(std::string peer_mac, int k = 1);
    std::string compute_hashed_password(const int &counter);
    void key_derivation_function(mpz_t &result_key, const std::string &base, const std::string &str_for_seed, const unsigned int &n);
    void commit_exchange();
    void commit_exchange(const std::string &priv_hex, const std::string &mask_hex);
    std::string compute_shared_secret(const mpz_t &peer_scalar, const mpz_t &peer_element);
    void confirm_exchange(const std::string &peer_token);

    std::string sha256_prf_bits(const std::string &key, const std::string &label, const std::string &data, const int &buf_len_bits);
    void scalar_op(mpz_t &rop, const mpz_t &op_exp, const mpz_t &op_base);
    void element_op(mpz_t &rop, const mpz_t &op1, const mpz_t &op2);
    void inverse_op(mpz_t &rop, const mpz_t &op);
};

#endif