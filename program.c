#include <stdio.h>
#include <time.h>
#include <string.h>
#include <openssl/bn.h>

int main(int argc, char *argv[])
{
    BIGNUM *q, *alpha, *x, *y, *k, *K, *C1, *C2, *numeric_message, *K_inverse, *result;
    BN_CTX *ctx;
    q = BN_new();
    alpha = BN_new();
    x = BN_new();
    y = BN_new();
    k = BN_new();
    K = BN_new();
    C1 = BN_new();
    C2 = BN_new();
    numeric_message = BN_new();
    K_inverse = BN_new();
    result = BN_new();
    ctx = BN_CTX_new();
    char *q_string, *alpha_string, *x_string, *y_string, *C1_string, *C2_string;
    char message[100] = {0}, decrypted_message[100] = {0};

    BN_dec2bn(&q, "145986658057247093610553226301656270110572558420992"
                  "842834418659087920127363286402958873450102590247005"
                  "184458784228409504215515177101261068643152057778375"
                  "905234395678842560981428747703212845164206653384278"
                  "128820893574962079479507685471473600970372205813671"
                  "778091838985319476268641116612305376795786735049773"
                  "503");
    BN_dec2bn(&alpha, "585342776684282608752703760510393058002961919069111"
                      "147894967651106466288110353159205676532120094753797"
                      "787506565252543035007247466441962756148253305791827"
                      "870602801809735559554243558495085704977176662308542"
                      "160668305644188609650998575326053734737586157595937"
                      "937727018912437726025014982207282222938584092609593"
                      "37");
    BN_rand_range(x, q);
    BN_mod_exp(y, alpha, x, q, ctx);

    x_string = BN_bn2hex(x);
    printf("==========================================================================================\n");
    printf("Private key for the session is: %s\n", x_string);
    printf("==========================================================================================\n\n\n");
    q_string = BN_bn2hex(q);
    alpha_string = BN_bn2hex(alpha);
    y_string = BN_bn2hex(y);
    printf("==========================================================================================\n");
    printf("Public key for the session is: (%s, %s, %s)\n", q_string, alpha_string, y_string);
    printf("==========================================================================================\n\n\n");

    printf("==========================================================================================\n");
    printf("Enter message upto 1000 characters:\n");
    scanf("%99[^\n]s", &message);
    BN_bin2bn(message, strlen(message), numeric_message);
    printf("==========================================================================================\n\n\n");

    BN_rand_range(k, q);
    BN_mod_exp(K, y, k, q, ctx);
    BN_mod_exp(C1, alpha, k, q, ctx);
    BN_mod_mul(C2, K, numeric_message, q, ctx);

    C1_string = BN_bn2hex(C1);
    C2_string = BN_bn2hex(C2);
    printf("==========================================================================================\n");
    printf("Encrypted message is: (%s, %s)\n", C1_string, C2_string);
    printf("==========================================================================================\n\n\n");

    BN_zero(K);
    BN_mod_exp(K, C1, x, q, ctx);
    BN_mod_inverse(K_inverse, K, q, ctx);
    BN_mod_mul(result, C2, K_inverse, q, ctx);

    BN_bn2bin(result, decrypted_message);
    printf("==========================================================================================\n");
    printf("Decrypted message is: %s\n", decrypted_message);
    printf("==========================================================================================\n\n\n");

    OPENSSL_free(x_string);
    OPENSSL_free(y_string);
    OPENSSL_free(q_string);
    OPENSSL_free(alpha_string);
    OPENSSL_free(C1_string);
    OPENSSL_free(C2_string);
    BN_free(q);
    BN_free(alpha);
    BN_free(x);
    BN_free(y);
    BN_free(k);
    BN_free(K);
    BN_free(C1);
    BN_free(C2);
    BN_free(numeric_message);
    BN_free(K_inverse);
    BN_free(result);
    BN_CTX_free(ctx);
}