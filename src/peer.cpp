#include <gmpxx.h>
#include <openssl/sha.h>
#include <string>
#include <cstdio>
#include <iostream>
#include <algorithm>
#include <assert.h>
#include <ctime>
#include "../include/peer.h"
#include "../include/mpz_math.h"

static const unsigned char dh_group5_prime[192] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static const unsigned char dh_group5_order[192] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xE4, 0x87, 0xED, 0x51, 0x10, 0xB4, 0x61, 0x1A,
    0x62, 0x63, 0x31, 0x45, 0xC0, 0x6E, 0x0E, 0x68,
    0x94, 0x81, 0x27, 0x04, 0x45, 0x33, 0xE6, 0x3A,
    0x01, 0x05, 0xDF, 0x53, 0x1D, 0x89, 0xCD, 0x91,
    0x28, 0xA5, 0x04, 0x3C, 0xC7, 0x1A, 0x02, 0x6E,
    0xF7, 0xCA, 0x8C, 0xD9, 0xE6, 0x9D, 0x21, 0x8D,
    0x98, 0x15, 0x85, 0x36, 0xF9, 0x2F, 0x8A, 0x1B,
    0xA7, 0xF0, 0x9A, 0xB6, 0xB6, 0xA8, 0xE1, 0x22,
    0xF2, 0x42, 0xDA, 0xBB, 0x31, 0x2F, 0x3F, 0x63,
    0x7A, 0x26, 0x21, 0x74, 0xD3, 0x1B, 0xF6, 0xB5,
    0x85, 0xFF, 0xAE, 0x5B, 0x7A, 0x03, 0x5B, 0xF6,
    0xF7, 0x1C, 0x35, 0xFD, 0xAD, 0x44, 0xCF, 0xD2,
    0xD7, 0x4F, 0x92, 0x08, 0xBE, 0x25, 0x8F, 0xF3,
    0x24, 0x94, 0x33, 0x28, 0xF6, 0x72, 0x2D, 0x9E,
    0xE1, 0x00, 0x3E, 0x5C, 0x50, 0xB1, 0xDF, 0x82,
    0xCC, 0x6D, 0x24, 0x1B, 0x0E, 0x2A, 0xE9, 0xCD,
    0x34, 0x8B, 0x1F, 0xD4, 0x7E, 0x92, 0x67, 0xAF,
    0xC1, 0xB2, 0xAE, 0x91, 0xEE, 0x51, 0xD6, 0xCB,
    0x0E, 0x31, 0x79, 0xAB, 0x10, 0x42, 0xA9, 0x5D,
    0xCF, 0x6A, 0x94, 0x83, 0xB8, 0x4B, 0x4B, 0x36,
    0xB3, 0x86, 0x1A, 0xA7, 0x25, 0x5E, 0x4C, 0x02,
    0x78, 0xBA, 0x36, 0x04, 0x65, 0x11, 0xB9, 0x93,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static const unsigned char dh_group15_prime[384] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
    0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
    0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
    0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D,
    0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
    0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
    0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
    0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D,
    0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7,
    0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
    0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
    0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
    0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64,
    0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C,
    0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
    0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
    0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
    0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x3A, 0xD2, 0xCA,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const unsigned char dh_group15_order[384] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xE4, 0x87, 0xED, 0x51, 0x10, 0xB4, 0x61, 0x1A,
    0x62, 0x63, 0x31, 0x45, 0xC0, 0x6E, 0x0E, 0x68,
    0x94, 0x81, 0x27, 0x04, 0x45, 0x33, 0xE6, 0x3A,
    0x01, 0x05, 0xDF, 0x53, 0x1D, 0x89, 0xCD, 0x91,
    0x28, 0xA5, 0x04, 0x3C, 0xC7, 0x1A, 0x02, 0x6E,
    0xF7, 0xCA, 0x8C, 0xD9, 0xE6, 0x9D, 0x21, 0x8D,
    0x98, 0x15, 0x85, 0x36, 0xF9, 0x2F, 0x8A, 0x1B,
    0xA7, 0xF0, 0x9A, 0xB6, 0xB6, 0xA8, 0xE1, 0x22,
    0xF2, 0x42, 0xDA, 0xBB, 0x31, 0x2F, 0x3F, 0x63,
    0x7A, 0x26, 0x21, 0x74, 0xD3, 0x1B, 0xF6, 0xB5,
    0x85, 0xFF, 0xAE, 0x5B, 0x7A, 0x03, 0x5B, 0xF6,
    0xF7, 0x1C, 0x35, 0xFD, 0xAD, 0x44, 0xCF, 0xD2,
    0xD7, 0x4F, 0x92, 0x08, 0xBE, 0x25, 0x8F, 0xF3,
    0x24, 0x94, 0x33, 0x28, 0xF6, 0x72, 0x2D, 0x9E,
    0xE1, 0x00, 0x3E, 0x5C, 0x50, 0xB1, 0xDF, 0x82,
    0xCC, 0x6D, 0x24, 0x1B, 0x0E, 0x2A, 0xE9, 0xCD,
    0x34, 0x8B, 0x1F, 0xD4, 0x7E, 0x92, 0x67, 0xAF,
    0xC1, 0xB2, 0xAE, 0x91, 0xEE, 0x51, 0xD6, 0xCB,
    0x0E, 0x31, 0x79, 0xAB, 0x10, 0x42, 0xA9, 0x5D,
    0xCF, 0x6A, 0x94, 0x83, 0xB8, 0x4B, 0x4B, 0x36,
    0xB3, 0x86, 0x1A, 0xA7, 0x25, 0x5E, 0x4C, 0x02,
    0x78, 0xBA, 0x36, 0x04, 0x65, 0x0C, 0x10, 0xBE,
    0x19, 0x48, 0x2F, 0x23, 0x17, 0x1B, 0x67, 0x1D,
    0xF1, 0xCF, 0x3B, 0x96, 0x0C, 0x07, 0x43, 0x01,
    0xCD, 0x93, 0xC1, 0xD1, 0x76, 0x03, 0xD1, 0x47,
    0xDA, 0xE2, 0xAE, 0xF8, 0x37, 0xA6, 0x29, 0x64,
    0xEF, 0x15, 0xE5, 0xFB, 0x4A, 0xAC, 0x0B, 0x8C,
    0x1C, 0xCA, 0xA4, 0xBE, 0x75, 0x4A, 0xB5, 0x72,
    0x8A, 0xE9, 0x13, 0x0C, 0x4C, 0x7D, 0x02, 0x88,
    0x0A, 0xB9, 0x47, 0x2D, 0x45, 0x55, 0x62, 0x16,
    0xD6, 0x99, 0x8B, 0x86, 0x82, 0x28, 0x3D, 0x19,
    0xD4, 0x2A, 0x90, 0xD5, 0xEF, 0x8E, 0x5D, 0x32,
    0x76, 0x7D, 0xC2, 0x82, 0x2C, 0x6D, 0xF7, 0x85,
    0x45, 0x75, 0x38, 0xAB, 0xAE, 0x83, 0x06, 0x3E,
    0xD9, 0xCB, 0x87, 0xC2, 0xD3, 0x70, 0xF2, 0x63,
    0xD5, 0xFA, 0xD7, 0x46, 0x6D, 0x84, 0x99, 0xEB,
    0x8F, 0x46, 0x4A, 0x70, 0x25, 0x12, 0xB0, 0xCE,
    0xE7, 0x71, 0xE9, 0x13, 0x0D, 0x69, 0x77, 0x35,
    0xF8, 0x97, 0xFD, 0x03, 0x6C, 0xC5, 0x04, 0x32,
    0x6C, 0x3B, 0x01, 0x39, 0x9F, 0x64, 0x35, 0x32,
    0x29, 0x0F, 0x95, 0x8C, 0x0B, 0xBD, 0x90, 0x06,
    0x5D, 0xF0, 0x8B, 0xAB, 0xBD, 0x30, 0xAE, 0xB6,
    0x3B, 0x84, 0xC4, 0x60, 0x5D, 0x6C, 0xA3, 0x71,
    0x04, 0x71, 0x27, 0xD0, 0x3A, 0x72, 0xD5, 0x98,
    0xA1, 0xED, 0xAD, 0xFE, 0x70, 0x7E, 0x88, 0x47,
    0x25, 0xC1, 0x68, 0x90, 0x54, 0x9D, 0x69, 0x65,
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

Peer::Peer(const std::string &password, const std::string &mac_address, const std::string &name)
{
    this->password = password;
    this->mac_address = mac_address;
    this->name = name;

    this->safe_prime = true;
    mpz_init(password_element);

    mpz_init_set_str(this->prime, "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff", 16);
    mpz_init_set_str(this->order, "7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba3604650c10be19482f23171b671df1cf3b960c074301cd93c1d17603d147dae2aef837a62964ef15e5fb4aac0b8c1ccaa4be754ab5728ae9130c4c7d02880ab9472d45556216d6998b8682283d19d42a90d5ef8e5d32767dc2822c6df785457538abae83063ed9cb87c2d370f263d5fad7466d8499eb8f464a702512b0cee771e9130d697735f897fd036cc504326c3b01399f643532290f958c0bbd90065df08babbd30aeb63b84c4605d6ca371047127d03a72d598a1edadfe707e884725c16890549d69657fffffffffffffff", 16);

    mpz_init(this->priv);
    mpz_init(this->mask);
    mpz_init(this->scalar);
    mpz_init(this->element);
    mpz_init(this->peer_scalar);
    mpz_init(this->peer_element);
}

Peer::~Peer()
{

    mpz_clear(this->priv);
    mpz_clear(this->mask);
    mpz_clear(this->scalar);
    mpz_clear(this->element);

    mpz_clear(this->prime);
    mpz_clear(this->order);
    mpz_clear(this->password_element);

    mpz_clear(this->peer_scalar);
    mpz_clear(this->peer_element);
}

void Peer::initiate(std::string peer_mac, int k)
{

    /* 
    """
        See algorithm in https://tools.ietf.org/html/rfc7664
        in section 3.2.1
    """
     */
    this->peer_mac = peer_mac;

    // int n = mpz_sizeinbase(this->prime, 2) + 64;
    int n = sizeof(dh_group15_prime) * 8;
    gmp_printf("n = %d\n", n);

    const std::string str_for_seed = "SAE Hunting and Pecking";

    mpz_t exp;
    mpz_init(exp);

    //Derivation of the Password Element
    mpz_t temp, seed;
    mpz_init(temp), mpz_init(seed);

    int found = 0;
    for (int counter = 1; counter <= k || found == 0; counter++)
    {
        //base = H(max(Alice,Bob) | min(Alice,Bob) , password | counter)
        std::string base = this->compute_hashed_password(counter);

        std::cout << "pwd-seed = " << str2hex_str(base) << std::endl;

        // temp = KDF-n(base, "Dragonfly Hunting And Pecking")
        this->key_derivation_function(temp, base, str_for_seed, n);
        gmp_printf("pwd-value = %Zx\n", temp);

        //seed = (temp mod(p - 1)) + 1 mpz_sub_ui(seed, this->prime, 1);
        /* 
        mpz_sub_ui(seed, this->prime, 1);
        mpz_mod(seed, temp, seed);
        mpz_add_ui(seed, seed, 1);
        */
        mpz_mod(seed, temp, this->prime);

        //gmp_printf("seed = %Zx\n", seed);

        //temp = seed ^ ((prime - 1) / order) mod prime
        if (this->safe_prime)
        {
            /*
            * exp = (prime - 1) / 2 for the group used here, so this becomes:
            * password_element (temp) = seed ^ 2 modulo prime
            */
            mpz_set_ui(exp, 2);
        }
        else
        {
            /* Calculate exponent: (prime - 1) / order */
            mpz_sub_ui(exp, this->prime, 1);
            mpz_div(exp, exp, this->order);
        }
        // gmp_printf("exp = %Zx\n", exp);
        mpz_powm(temp, seed, exp, this->prime);
        //gmp_printf("temp = %Zx\n", temp);

        if (mpz_cmp_ui(temp, 1) > 0)
        {
            mpz_set(this->password_element, temp);
            found = 1;
        }
    }
    gmp_printf("[%s]  password_element = %Zx\n", this->name.c_str(), this->password_element);
    mpz_clear(temp), mpz_clear(seed), mpz_clear(exp);
}

//base = H(max(Alice,Bob) | min(Alice,Bob) | password | counter)
std::string Peer::compute_hashed_password(const int &counter)
{
    std::string max_addr = std::max(this->mac_address, this->peer_mac);
    std::string min_addr = std::min(this->mac_address, this->peer_mac);

    auto &&max_addr_vec = mac2vec(max_addr);
    std::string addr1 = std::string(max_addr_vec.begin(), max_addr_vec.end());
    auto &&min_addr_vec = mac2vec(min_addr);
    std::string addr2 = std::string(min_addr_vec.begin(), min_addr_vec.end());

    std::string key = addr1 + addr2;
    std::cout << "key:" << str2hex_str(key) << std::endl;

    std::string message = this->password + std::string(1, (char)counter);
    std::cout << "message:" << str2hex_str(message) << std::endl;

    std::string digest = hmac_sha256(key, message);
    std::cout << "digest:" << str2hex_str(digest) << std::endl;
    return digest;
}

void Peer::key_derivation_function(mpz_t &result_key, const std::string &base, const std::string &str_for_seed, const unsigned int &n)
{

    // std::string combined_seed = base + str_for_seed;
    // std::string seed_digest = sha256(combined_seed);
    //std::cout << "seed_key:" << str2hex_str(seed_digest) << std::endl;

    std::string data((char *)dh_group15_prime, sizeof(dh_group15_prime));
    std::string key_buf = sha256_prf_bits(base, str_for_seed, data, n);

    std::string hex_key = str2hex_str(key_buf);
    std::cout << "sha256_prf_bits hex_key:" << hex_key << std::endl;
    mpz_init_set_str(result_key, hex_key.c_str(), 16);
}

std::string Peer::sha256_prf_bits(const std::string &key, const std::string &label, const std::string &data, const int &buf_len_bits)
{

    const uint16_t buf_len = (buf_len_bits + 7) / 8;
    std::string message;
    std::string bits_u8str = transmute_u16_to_u8str(buf_len_bits, U32Kind::LE);

    std::cout << "key:" << str2hex_str(key) << std::endl;

    message.append(label);
    std::cout << "label:" << str2hex_str(label) << std::endl;
    message.append(data);
    std::cout << "data:" << str2hex_str(data) << std::endl;
    message.append(bits_u8str);
    std::cout << "bits_u8str:" << str2hex_str(bits_u8str) << std::endl;
    unsigned int message_pre_len = message.size();
    // std::cout << "message:" << str2hex_str(message) << std::endl;

    unsigned int mac_len = 32;
    unsigned int pos = 0;
    uint16_t count = 1;
    char *key_buf = new char[buf_len];
    while (pos < buf_len)
    {

        int message_len = mac_len;
        if (buf_len - pos < mac_len)
        {
            message_len = buf_len - pos;
        }

        // message.resize(message_pre_len);

        std::string count_u8str = transmute_u16_to_u8str(count, U32Kind::LE);
        std::cout << "count_u8str:" << str2hex_str(count_u8str) << std::endl;
        //std::cout << "count:" << count << std::endl;

        //message.append(count_u8str);
        std::string handle_message = count_u8str + message;

        std::string key_digest = hmac_sha256(key, handle_message);
        //std::cout << "key_digest:" << str2hex_str(key_digest) << std::endl;
        memcpy(key_buf + pos, key_digest.c_str(), message_len);
        pos += message_len;
        count++;
    }

    std::string result_str_buf(key_buf, buf_len);
    delete (key_buf);
    return result_str_buf;
}

void Peer::commit_exchange()
{

    //# each party chooses two random numbers, private and mask
    mpz_urandomm(this->priv, RANDSTATE, this->order);
    if (mpz_cmp_ui(this->priv, 2) < 0)
    {
        mpz_set_ui(this->priv, 2);
    }
    mpz_urandomm(this->mask, RANDSTATE, this->order);
    if (mpz_cmp_ui(this->mask, 2) < 0)
    {
        mpz_set_ui(this->mask, 2);
    }

    gmp_printf("Private = %Zx \n", this->priv);
    gmp_printf("Mask = %Zx \n", this->mask);

    // scalar = (private + mask) modulo q
    mpz_add(this->scalar, this->priv, this->mask);
    mpz_mod(this->scalar, this->scalar, this->order);

    /* 
        # If the scalar is less than two (2), the private and mask MUST be
        # thrown away and new values generated.  Once a valid scalar and
        # Element are generated, the mask is no longer needed and MUST be
        # irretrievably destroyed. 
    */
    assert(mpz_cmp_ui(this->scalar, 2) >= 0);

    //Element = inverse(scalar-op(mask, PE))
    mpz_powm(this->element, this->password_element, this->mask, this->prime);
    // gmp_printf("powm = %Zx \n", this->element);
    mpz_invert(this->element, this->element, this->prime);

    gmp_printf("Sending scalar and element to the Peer! \n");
    gmp_printf("Scalar = %Zx \n", this->scalar);
    gmp_printf("Element = %Zx \n", this->element);
}

void Peer::commit_exchange(const std::string &priv_hex, const std::string &mask_hex)
{

    //# each party chooses two random numbers, private and mask
    /* 
    mpz_urandomm(this->priv, RANDSTATE, this->order);
    if (mpz_cmp_ui(this->priv, 2) < 0)
    {
        mpz_set_ui(this->priv, 2);
    }
    mpz_urandomm(this->mask, RANDSTATE, this->order);
    if (mpz_cmp_ui(this->mask, 2) < 0)
    {
        mpz_set_ui(this->mask, 2);
    } 
    */

    mpz_set_str(this->priv, priv_hex.c_str(), 16);
    mpz_set_str(this->mask, mask_hex.c_str(), 16);

    gmp_printf("Private = %Zx \n", this->priv);
    gmp_printf("Mask = %Zx \n", this->mask);

    // scalar = (private + mask) modulo q
    mpz_add(this->scalar, this->priv, this->mask);
    mpz_mod(this->scalar, this->scalar, this->order);

    /* 
        # If the scalar is less than two (2), the private and mask MUST be
        # thrown away and new values generated.  Once a valid scalar and
        # Element are generated, the mask is no longer needed and MUST be
        # irretrievably destroyed. 
    */
    assert(mpz_cmp_ui(this->scalar, 2) >= 0);

    //Element = inverse(scalar-op(mask, PE))
    mpz_powm(this->element, this->password_element, this->mask, this->prime);
    // gmp_printf("powm = %Zx \n", this->element);
    mpz_invert(this->element, this->element, this->prime);

    gmp_printf("Sending scalar and element to the Peer! \n");
    gmp_printf("Scalar = %Zx \n", this->scalar);
    gmp_printf("Element = %Zx \n", this->element);
}

std::string Peer::compute_shared_secret(const mpz_t &peer_scalar, const mpz_t &peer_element)
{

    /*
	 * K = scalar-op(private, (elem-op(scalar-op(peer-commit-scalar, PWE),
	 *                                        PEER-COMMIT-ELEMENT)))
	 * If K is identity element (one), reject.
	 * k = F(K) (= x coordinate)
	 */

    mpz_t ss;
    mpz_init(ss);
    // ss = scalar-op(peer-commit-scalar, PWE)
    //    = PWE ^ peer-commit-scalar
    scalar_op(ss, peer_scalar, this->password_element);
    gmp_printf("[%s] Shared Secret ss = %Zx \n", this->name.c_str(), ss);

    // ss = elem-op(ss,PEER-COMMIT-ELEMENT)
    //    = ss * PEER-COMMIT-ELEMENT
    element_op(ss, ss, peer_element);
    gmp_printf("[%s] Shared Secret ss = %Zx \n", this->name.c_str(), ss);

    // ss = scalar-op(private, ss);
    //    = ss ^ private;
    scalar_op(ss, this->priv, ss);
    gmp_printf("[%s] Shared Secret ss = %Zx \n", this->name.c_str(), ss);

    /* keyseed = H(<0>32, k)
	 * KCK || PMK = KDF-512(keyseed, "SAE KCK and PMK",
	 *                      (commit-scalar + peer-commit-scalar) modulo r)
	 * PMKID = L((commit-scalar + peer-commit-scalar) modulo r, 0, 128)
	 */
    mpz_t scalar_result;
    mpz_init(scalar_result);

    mpz_add(scalar_result, this->scalar, peer_scalar);
    mpz_mod(scalar_result, scalar_result, this->order);
    gmp_printf("[%s] scalar = %Zx \n", this->name.c_str(), this->scalar);
    gmp_printf("[%s] peer_scalar = %Zx \n", this->name.c_str(), peer_scalar);
    gmp_printf("[%s] scalar_result = %Zx \n", this->name.c_str(), scalar_result);

    std::string scalar_hex = hex_str2str(mpz2str(scalar_result, 16));

    printf("[%s] scalar_hex = \n", this->name.c_str());
    for (size_t i = 0; i < scalar_hex.size(); i++)
    {
        printf("%0x", (unsigned char)scalar_hex[i]);
    }
    printf("\n");

    std::string null_key(32, 0);
    std::string ss_hex = hex_str2str(mpz2str(ss, 16));
    printf("[%s] ss_hex = \n", this->name.c_str());
    for (size_t i = 0; i < ss_hex.size(); i++)
    {
        printf("%0x", (unsigned char)ss_hex[i]);
    }
    printf("\n");
    std::string keyseed = hmac_sha256(null_key, ss_hex);

    std::string str_for_seed = "SAE KCK and PMK";
    std::string key_buf = sha256_prf_bits(keyseed, str_for_seed, scalar_hex, 64 * 8);
    this->kck = std::string(key_buf.c_str(), 32);
    this->pmk = std::string(key_buf.c_str() + 32, 32);
    this->pmkid = std::string(16, '0');
    // std::string kck = std::string(key_buf.c_str(), 32);
    // std::string pmk = std::string(key_buf.c_str() + 32, 32);
    // std::string pmkid = std::string(16, '0');
    for (size_t i = 0; i < scalar_hex.size() && i < 16; i++)
    {
        this->pmkid[i] = scalar_hex[i];
    }

    printf("[%s] KCK = %s\n", this->name.c_str(), str2hex_str(this->kck).c_str());
    printf("[%s] Pairwise Master Key(PMK) = %s \n", this->name.c_str(), str2hex_str(this->pmk).c_str());
    printf("[%s] PMKID = %s \n", this->name.c_str(), str2hex_str(this->pmkid).c_str());

    std::string token_message;
    token_message += ss_hex;
    // printf("[%s] ss_hex = %s \n", this->name.c_str(), str2hex_str(ss_hex).c_str());
    token_message += hex_str2str(mpz2str(scalar, 16));
    // printf("[%s] scalar_hex = %s \n", this->name.c_str(), mpz2str(scalar, 16).c_str());
    token_message += hex_str2str(mpz2str(peer_scalar, 16));
    // printf("[%s] peer_scalar_hex = %s \n", this->name.c_str(), mpz2str(peer_scalar, 16).c_str());
    token_message += hex_str2str(mpz2str(element, 16));
    token_message += hex_str2str(mpz2str(peer_element, 16));
    //printf("[%s] TokenMessage = %s \n", this->name.c_str(), str2hex_str(token_message).c_str());

    std::string token = hmac_sha256(kck, token_message);
    printf("[%s] Token = %s \n", this->name.c_str(), str2hex_str(token).c_str());

    mpz_set(this->peer_scalar, peer_scalar);
    mpz_set(this->peer_element, peer_element);
    this->ss_hex = ss_hex;

    mpz_clear(scalar_result);
    mpz_clear(ss);
    return token;
}

void Peer::confirm_exchange(const std::string &peer_token)
{
    std::string peer_message;
    peer_message += ss_hex;
    peer_message += hex_str2str(mpz2str(peer_scalar, 16));
    peer_message += hex_str2str(mpz2str(scalar, 16));
    peer_message += hex_str2str(mpz2str(peer_element, 16));
    peer_message += hex_str2str(mpz2str(element, 16));

    std::string peer_token_computed = hmac_sha256(kck, peer_message);

    printf("[%s] Computed Token from Peer = %s \n", this->name.c_str(), str2hex_str(peer_token_computed).c_str());
    printf("[%s] Received Token from Peer = %s \n", this->name.c_str(), str2hex_str(peer_token).c_str());
}

void Peer::scalar_op(mpz_t &rop, const mpz_t &op_exp, const mpz_t &op_base)
{
    mpz_powm(rop, op_base, op_exp, this->prime);
}

void Peer::element_op(mpz_t &rop, const mpz_t &op1, const mpz_t &op2)
{
    mpz_mul(rop, op1, op2);
    mpz_mod(rop, rop, this->prime);
}

void Peer::inverse_op(mpz_t &rop, const mpz_t &op)
{

    mpz_invert(rop, op, this->prime);
}