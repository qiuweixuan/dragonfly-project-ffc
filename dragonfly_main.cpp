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
    srand(time(NULL));

    mpz_t a, b, c, d;
    mpz_init(a);
    mpz_init(b);
    mpz_init(c);
    mpz_init(d);
    //计算2的1000次方
    mpz_init_set_ui(a, 2);
    mpz_pow_ui(c, a, 1000);
    gmp_printf("c = %Zd\n", c);

    //计算12345678900987654321*98765432100123456789
    mpz_init_set_str(b, "41577311594322086732010735089046630069560194285817217577730709794461777884595", 10); //10进制
    mpz_init_set_str(c, "76884956397045344220809746629001649093037950200943055203735601445031516197751", 10);
    mpz_mul(d, b, c);
    gmp_printf("d = %Zd\n", d);

    //计算除法
    // mpz_init_set_str(c, "9", 10);
    // mpz_init_set_str(b, "2", 10);//10进制
    mpz_fdiv_q(d, c, b); //向下整除
    gmp_printf("mpz_fdiv_q:d = %Zd\n", d);

    legendre(d, b, c);
    gmp_printf("legendre:d = %Zd\n", d);

    tonelli_shanks(d, b, c);
    gmp_printf("tonelli_shanks:d = %Zd\n", d);

    EllipticCurve ec(
        "56698187605326110043627228396178346077120614539475214109386828188763884139993",
        "17577232497321838841075697789794520262950426058923084567046852300633325438902",
        "76884956397045344220809746629001649093037950200943055203735601445031516197751", 10);
    mpz_t x;

    mpz_init_set_str(x, "44636889021951429617878751535492807962563326887208848194489661399766546537096", 10);
    ec.curve_equation(d, x);
    gmp_printf("curve_equation :d = %Zd\n", d);
    mpz_clear(x);

    bool is_QR;
    is_QR = ec.is_quadratic_residue(d);
    gmp_printf("is_quadratic_residue : d = %d\n", is_QR);

    mpz_init_set_str(x, "1128969709662994286855259741431387894916776047019745036539814346559507564901", 10);
    is_QR = ec.is_quadratic_residue(x);
    gmp_printf("is_quadratic_residue :d = %d\n", is_QR);
    mpz_clear(x);

    Point p(
        "11245091364210913538031558554069068295821326089979728553744121109670093869553",
        "58227085528211006908619226448297745234381220210201339909209560974723630792484",
        10);
    bool is_on_curve = ec.is_point_on_curve(p);
    gmp_printf("is_point_on_curve :d = %d\n", is_on_curve);

    mpz_init_set_str(x, "31585362742042248681507141308670880101726446859422047342877633324024259170673", 10);
    ec.inv_mod_p(d, x);
    gmp_printf("inv_mod_p :d = %Zd\n", d);

    Point p1(
        "63463127379121579880278198109336113474044035466585342005071192132059818598209",
        "16558137935435870897706968960488825780425063076841601361802226641039654238867",
        10);
    Point p2;
    ec.ec_point_inv(p2, p1);
    gmp_printf("ec_point_inv :x = %Zd , y = %Zd \n", p2.x, p2.y);

    Point p3(
        "44798834989657919863089174096808959741372081687640931490811108075146543214623",
        " 32552174646444655060134058623257090394879394920791321656975553975238125448510",
        10);
    Point p4;
    ec.ec_point_double_add(p4, p3);
    gmp_printf("ec_point_double_add :x = %Zd , y = %Zd \n", p4.x, p4.y);

    p1.set_x("19255648800734979802927059587974852932026844473492005743471589635415939677617", 10);
    p1.set_y("5347230032267046714807334904413528386238164048132981468634421549716907951517", 10);
    p2.set_x("53966716554608051077465919234931511423879734331111662366752677474299058504440", 10);
    p2.set_y("8117559023792801597289705548012874557664944241595251311237145384718921880283", 10);
    ec.ec_point_add(p4, p1, p2);
    gmp_printf("ec_point_add :x = %Zd , y = %Zd \n", p4.x, p4.y);

    p3.set_x("72639184339425654576555087557111920487359235746629312591395173225124908193763", 10);
    p3.set_y("15224464906049663749133738389570345770876661096229951121126739762545982893453", 10);
    mpz_init_set_str(x, "30365056390190848852943231209253184370325221626750165764764158042136144461840", 10);
    ec.ec_point_scalar_mul(p4, x, p3);
    mpz_clear(x);
    gmp_printf("ec_point_scalar_mul :x = %Zd , y = %Zd \n", p4.x, p4.y);

    p3.set_x("1104832230923804541019855326938339287498267286713819743046729009762879975423", 10);
    p3.set_y("52921860843340567879358341355783097105123683025468323692090409904865326996090", 10);
    mpz_init_set_str(x, "25568832556651077009177958848123513550279603375538798880147678520829252774745", 10);
    ec.ec_point_scalar_mul(p4, x, p3);
    mpz_clear(x);
    gmp_printf("ec_point_scalar_mul :x = %Zd , y = %Zd \n", p4.x, p4.y);
    

    gmp_printf("---------------------------------------------------\n");
    Peer sta("abc1238", "44:67:2D:2C:91:A6", "STA");
    Peer ap("abc1238", "44:37:2C:2F:91:36", "AP");

    gmp_printf("Starting hunting and pecking to derive PE...\n");
    sta.initiate(ap.mac_address);
    ap.initiate(sta.mac_address);

    gmp_printf("---------------------------------------------------\n");
    gmp_printf("Starting dragonfly commit exchange...\n");
    sta.commit_exchange();
    ap.commit_exchange();

    gmp_printf("---------------------------------------------------\n");
    gmp_printf("Computing shared secret...\n");
    string sta_token = sta.compute_shared_secret(ap.element, ap.scalar, ap.mac_address);
    gmp_printf("---------------------------------------------------\n");
    string ap_token = ap.compute_shared_secret(sta.element, sta.scalar, sta.mac_address);
    
    gmp_printf("---------------------------------------------------\n");
    gmp_printf("Confirm Exchange...\n");
    sta.confirm_exchange(ap_token);
    gmp_printf("---------------------------------------------------\n");
    ap.confirm_exchange(sta_token);


    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(c);
    mpz_clear(d);
    return 0;
}