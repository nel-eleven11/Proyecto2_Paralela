#define _POSIX_C_SOURCE 199309L
// bruteforce_seq.c — Sequential version (no MPI)
// Compilar: gcc -std=c11 -O3 -Wall -Wextra -pedantic bruteforce_seq.c -lcrypto -o bruteforce_seq

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

// carga proveedores default y legacy de openssl
static int ensure_providers(void) {
    static int done = 0;
    static OSSL_PROVIDER *prov_default = NULL;
    static OSSL_PROVIDER *prov_legacy  = NULL;
    if (done) return 1;
    prov_default = OSSL_PROVIDER_load(NULL, "default");
    prov_legacy  = OSSL_PROVIDER_load(NULL, "legacy");
    done = (prov_default != NULL && prov_legacy != NULL);
    return done;
}

// obtiene el cifrador des ecb desde openssl
static EVP_CIPHER *fetch_des_ecb(void) {
    if (!ensure_providers()) return NULL;
    return EVP_CIPHER_fetch(NULL, "DES-ECB", NULL);
}

// convierte entero a llave des de 8 bytes con paridad impar
static void long_to_des8(uint64_t key, unsigned char out8[8]) {
    uint64_t k = 0;
    for (int i = 0; i < 8; ++i) {
        key <<= 1;
        k += (key & (0xFEULL << (i * 8)));
    }
    for (int i = 0; i < 8; ++i) {
        unsigned char b = (unsigned char)((k >> (i*8)) & 0xFFu);
        unsigned char data = (unsigned char)(b & 0xFEu);
        int ones = 0; for (int j = 1; j < 8; ++j) ones += (data >> j) & 1;
        unsigned char parity = (ones % 2 == 0) ? 1u : 0u;
        out8[i] = (unsigned char)(data | parity);
    }
}

// ejecuta des ecb sin padding para cifrar o descifrar
static int des_ecb_do(int enc, uint64_t keylong,
                      const unsigned char *in, int len,
                      unsigned char *out) {
    EVP_CIPHER *cipher = fetch_des_ecb();
    if (!cipher) return 0;

    unsigned char key8[8];
    long_to_des8(keylong, key8);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { EVP_CIPHER_free(cipher); return 0; }

    int ok = 1;
    if (enc) {
        ok &= (EVP_EncryptInit_ex(ctx, cipher, NULL, key8, NULL) == 1);
        ok &= (EVP_CIPHER_CTX_set_padding(ctx, 0), 1);
        int outl=0, fin=0;
        ok &= (EVP_EncryptUpdate(ctx, out, &outl, in, len) == 1);
        EVP_EncryptFinal_ex(ctx, out + outl, &fin);
    } else {
        ok &= (EVP_DecryptInit_ex(ctx, cipher, NULL, key8, NULL) == 1);
        ok &= (EVP_CIPHER_CTX_set_padding(ctx, 0), 1);
        int outl=0, fin=0;
        ok &= (EVP_DecryptUpdate(ctx, out, &outl, in, len) == 1);
        EVP_DecryptFinal_ex(ctx, out + outl, &fin);
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

// api compatible que descifra en el mismo buffer
void decrypt(long key, char *ciph, int len) {
    if (!des_ecb_do(0, (uint64_t)key, (const unsigned char*)ciph, len, (unsigned char*)ciph)) {
        fprintf(stderr, "OpenSSL DES-ECB decrypt init failed\n");
        exit(3);
    }
}

// api compatible que cifra en el mismo buffer
void encrypt(long key, char *plain, int len) {
    if (!des_ecb_do(1, (uint64_t)key, (const unsigned char*)plain, len, (unsigned char*)plain)) {
        fprintf(stderr, "OpenSSL DES-ECB encrypt init failed\n");
        exit(3);
    }
}

// subcadena objetivo por defecto para la busqueda
static const char *search = " the ";

int tryKey(long key, char *ciph, int len){
    char *tmp = (char*)malloc((size_t)len + 1);
    if (!tmp) return 0;
    memcpy(tmp, ciph, len);
    tmp[len] = 0;
    decrypt(key, tmp, len);
    int ok = (strstr(tmp, search) != NULL);
    free(tmp);
    return ok;
}

// cifrado embebido de prueba de 16 bytes
static unsigned char cipher_builtin[] =
    {108,245,65,63,125,200,150,66,17,170,207,170,34,31,70,215};

// lee archivo binario completo en memoria
static int read_file(const char *path, unsigned char **buf, int *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -2; }
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return -3; }
    rewind(f);
    *buf = (unsigned char*)malloc((size_t)sz);
    if (!*buf) { fclose(f); return -4; }
    size_t n = fread(*buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) { free(*buf); *buf=NULL; return -5; }
    *len = (int)n;
    return 0;
}

// muestra banner informativo al inicio
static void banner(void){
    puts("============================================================");
    puts("  BruteDES • Sequential Version");
    puts("============================================================\n");
}

// imprime uso y notas de ejecucion
static void usage(const char *p){
    banner();
    fprintf(stderr,
      "USO:\n"
      "  %s [-c cipher.bin] [-L low] [-U up] [-s substring]\n"
      "NOTAS:\n"
      "  - Si no pasas -c, usa el cifrado embebido (16 bytes).\n"
      "  - Búsqueda por defecto: \" the \". Cambia con -s \"texto\".\n"
      "  - Rango por defecto: [0, 2^24).\n", p);
}

// obtiene tiempo en segundos
static double get_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

// bucle principal
int main(int argc, char *argv[]){
    uint64_t upper = (1ULL<<24), lower = 0;
    unsigned char *cipher = NULL;
    int ciphlen = 0;
    const char *arg_search = NULL;

    for (int i=1;i<argc;i++){
        if (!strcmp(argv[i], "-c") && i+1<argc){
            const char *p = argv[++i];
            if (read_file(p, &cipher, &ciphlen) != 0){
                fprintf(stderr, "ERROR leyendo %s\n", p);
                return 2;
            }
        } else if (!strcmp(argv[i], "-L") && i+1<argc){
            lower = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "-U") && i+1<argc){
            upper = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "-s") && i+1<argc){
            arg_search = argv[++i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")){
            usage(argv[0]);
            return 0;
        }
    }
    if (arg_search) search = arg_search;

    // usa cifrado embebido si no se proporciona archivo
    if (!cipher){
        ciphlen = (int)sizeof(cipher_builtin);
        cipher = (unsigned char*)malloc((size_t)ciphlen);
        memcpy(cipher, cipher_builtin, (size_t)ciphlen);
    }

    // valida que el cifrado sea multiplo de ocho bytes
    if (ciphlen % 8 != 0){
        fprintf(stderr, "ERROR: longitud de cifrado no es múltiplo de 8 (%d)\n", ciphlen);
        return 3;
    }

    banner();

    printf("→ BRUTEFORCE SEQUENTIAL\n");
    printf("  • Subcadena: \"%s\"\n", search);
    printf("  • Rango    : [%" PRIu64 ", %" PRIu64 ")\n\n", lower, upper);

    // prepara contadores
    uint64_t found = UINT64_MAX;
    uint64_t tests = 0;

    double t0 = get_time();

    // recorre el rango probando llaves
    for (uint64_t k=lower; k<upper; ++k){
        tests++;
        if (tryKey((long)k, (char*)cipher, ciphlen)){
            found = k;
            break;
        }
    }

    double t1 = get_time();
    double elapsed = t1 - t0;

    // imprime resultados
    if (found != UINT64_MAX){
        unsigned char *plain = (unsigned char*)malloc((size_t)ciphlen+1);
        memcpy(plain, cipher, (size_t)ciphlen);
        decrypt((long)found, (char*)plain, ciphlen);
        plain[ciphlen]=0;

        puts("  • Resultado: ✔ Llave encontrada");
        printf("    - Llave   : %" PRIu64 "\n", found);
        printf("    - Texto   : %s\n", (char*)plain);
        free(plain);
    } else {
        puts("  • Resultado: ✘ No encontrada.");
    }

    puts("\n  • Resumen");
    printf("    - Llaves probadas : %" PRIu64 "\n", tests);
    printf("    - Tiempo total    : %.6f s\n", elapsed);
    if (elapsed > 0.0) {
        printf("    - Throughput      : %.0f claves/s\n", (double)tests / elapsed);
    }
    puts("");

    free(cipher);
    return 0;
}
