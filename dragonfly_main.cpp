#include <gmpxx.h>
#include <assert.h>
#include <iostream>
#include <cstdio>
#include <random>
#include "include/point.h"
#include "include/curve.h"
#include "include/mpz_math.h"
#include "include/peer.h"
using namespace std;

int main()
{
    gmp_randinit_default(RANDSTATE);

    // Peer sta("abc1238", "44:67:2D:2C:91:A6", "STA");
    // Peer ap("abc1238", "44:37:2C:2F:91:36", "AP");

    Peer sta("abcdefgh", "02:00:00:00:01:00", "STA");
    Peer ap("abcdefgh", "02:00:00:00:00:00", "AP");

    gmp_printf("---------------------------------------------------\n");
    gmp_printf("Starting hunting and pecking to derive PE...\n");
    gmp_printf("---------------------------------------------------\n");
    sta.initiate(ap.mac_address);
    gmp_printf("---------------------------------------------------\n");
    ap.initiate(sta.mac_address);

    gmp_printf("---------------------------------------------------\n");
    gmp_printf("Starting dragonfly commit exchange...\n");
    gmp_printf("---------------------------------------------------\n");
    sta.commit_exchange();
    gmp_printf("---------------------------------------------------\n");
    ap.commit_exchange();

    gmp_printf("---------------------------------------------------\n");
    gmp_printf("Computing shared secret...\n");
    gmp_printf("---------------------------------------------------\n");

    string sta_token = sta.compute_shared_secret(ap.scalar, ap.element);
    gmp_printf("---------------------------------------------------\n");
    string ap_token = ap.compute_shared_secret(sta.scalar, sta.element);

    gmp_printf("---------------------------------------------------\n");
    gmp_printf("Confirm Exchange...\n");
    sta.confirm_exchange(ap_token);
    gmp_printf("---------------------------------------------------\n");
    ap.confirm_exchange(sta_token);

    return 0;
}