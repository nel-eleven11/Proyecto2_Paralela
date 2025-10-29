#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <mpi.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

// Funciones auxiliares para actualización de la implementación
// Carga proveedores default y legacy de OpenSSL
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

// Obtiene el cifrador DES-ECB desde OpenSSL
static EVP_CIPHER *fetch_des_ecb(void) {
    if (!ensure_providers()) return NULL;
    return EVP_CIPHER_fetch(NULL, "DES-ECB", NULL);
}

// Convierte entero a llave DES de 8 bytes con paridad impar
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

// Ejecuta DES-ECB sin padding para cifrar o descifrar
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

// Descifra en el mismo buffer
void decrypt(long key, char *ciph, int len) {
    if (!des_ecb_do(0, (uint64_t)key, (const unsigned char*)ciph, len, (unsigned char*)ciph)) {
        fprintf(stderr, "OpenSSL DES-ECB decrypt init failed\n");
        MPI_Abort(MPI_COMM_WORLD, 3);
    }
}

// Cifra en el mismo buffer
void encrypt(long key, char *plain, int len) {
    if (!des_ecb_do(1, (uint64_t)key, (const unsigned char*)plain, len, (unsigned char*)plain)) {
        fprintf(stderr, "OpenSSL DES-ECB encrypt init failed\n");
        MPI_Abort(MPI_COMM_WORLD, 3);
    }
}

// Subcadena objetivo por defecto para la busqueda
static const char *search = " the ";

// Prueba una llave descifrando y buscando la subcadena
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

// Cifrado embebido de prueba (16 bytes): "Save the planet"
static unsigned char cipher_builtin[] =
    {108,245,65,63,125,200,150,66,17,170,207,170,34,31,70,215};

// Lee archivo binario completo en memoria
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

// Escribe buffer a archivo binario
static int write_file(const char *path, const unsigned char *buf, int len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = fwrite(buf, 1, (size_t)len, f);
    fclose(f);
    if (n != (size_t)len) return -2;
    return 0;
}

int main(int argc, char *argv[]){
    int N, id;
    uint64_t upper = (1ULL<<24), lower = 0;
    unsigned char *cipher = NULL; int ciphlen = 0;
    const char *arg_search = NULL;

    // Modo cifrado
    int encrypt_mode = 0;
    const char *input_file = NULL;
    const char *output_file = NULL;
    uint64_t encrypt_key = 0;

    for (int i=1;i<argc;i++){
        if (!strcmp(argv[i], "-e")){
            encrypt_mode = 1;
        } else if (!strcmp(argv[i], "-i") && i+1<argc){
            input_file = argv[++i];
        } else if (!strcmp(argv[i], "-o") && i+1<argc){
            output_file = argv[++i];
        } else if (!strcmp(argv[i], "-k") && i+1<argc){
            encrypt_key = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "-c") && i+1<argc){
            const char *p = argv[++i];
            if (read_file(p, &cipher, &ciphlen) != 0){
                fprintf(stderr, "ERROR leyendo %s\n", p); return 2;
            }
        } else if (!strcmp(argv[i], "-L") && i+1<argc){
            lower = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "-U") && i+1<argc){
            upper = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "-s") && i+1<argc){
            arg_search = argv[++i];
        }     
    }
    if (arg_search) search = arg_search;

    MPI_Init(NULL, NULL);
    MPI_Comm comm = MPI_COMM_WORLD;
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    // ========== MODO CIFRADO ==========
    if (encrypt_mode) {
        if (!input_file || !output_file) {
            if (id == 0) {
                fprintf(stderr, "ERROR: Modo cifrado requiere -i <input> y -o <output>\n");
            }
            MPI_Finalize();
            return 1;
        }

        if (id == 0) {
            printf("ENCRYPTION MODE\n");
            printf("  Input file  : %s\n", input_file);
            printf("  Output file : %s\n", output_file);
            printf("  Key         : %" PRIu64 "\n\n", encrypt_key);

            unsigned char *plaintext = NULL;
            int plainlen = 0;
            if (read_file(input_file, &plaintext, &plainlen) != 0) {
                fprintf(stderr, "ERROR: No se pudo leer %s\n", input_file);
                MPI_Abort(comm, 2);
            }

            // Padding a multiplo de 8 bytes (requerido por DES)
            int padded_len = ((plainlen + 7) / 8) * 8;
            unsigned char *padded = (unsigned char*)malloc(padded_len);
            memcpy(padded, plaintext, plainlen);
            for (int i = plainlen; i < padded_len; i++) {
                padded[i] = ' ';
            }
            free(plaintext);

            encrypt((long)encrypt_key, (char*)padded, padded_len);

            if (write_file(output_file, padded, padded_len) != 0) {
                fprintf(stderr, "ERROR: No se pudo escribir %s\n", output_file);
                free(padded);
                MPI_Abort(comm, 3);
            }

            printf("Encryption successful!\n");
            printf("  Original size : %d bytes\n", plainlen);
            printf("  Encrypted size: %d bytes (with padding)\n\n", padded_len);

            free(padded);
        }

        MPI_Finalize();
        return 0;
    }

    // Usa cifrado embebido si no se proporciona archivo
    if (!cipher){
        ciphlen = (int)sizeof(cipher_builtin);
        cipher = (unsigned char*)malloc((size_t)ciphlen);
        memcpy(cipher, cipher_builtin, (size_t)ciphlen);
    }

    if (ciphlen % 8 != 0){
        fprintf(stderr, "ERROR: longitud de cifrado no es múltiplo de 8 (%d)\n", ciphlen);
        MPI_Finalize();
        return 3;
    }


    // Particion estatica: divide el rango equitativamente entre procesos
    uint64_t total = (upper > lower) ? (upper - lower) : 0;
    uint64_t per   = total / (uint64_t)N;
    uint64_t extra = total % (uint64_t)N;

    uint64_t uid = (uint64_t)id;
    uint64_t add = (uid < extra) ? uid : extra;
    uint64_t myL = lower + per*uid + add;
    uint64_t myU = myL + per + (uid < extra);

    // Variables para coordinacion y metricas
    uint64_t found = UINT64_MAX;
    uint64_t local_tests = 0;
    int status_code = 0;
    int found_rank = -1;

    // Recepcion no bloqueante para terminacion temprana
    MPI_Request req; MPI_Status st;
    MPI_Irecv(&found, 1, MPI_UINT64_T, MPI_ANY_SOURCE, 777, comm, &req);

    double t0 = MPI_Wtime();

    // Bucle de busqueda en el subrango asignado
    for (uint64_t k=myL; k<myU; ++k){
        int flag=0; MPI_Test(&req, &flag, &st);
        if (flag) { status_code = 1; break; }

        local_tests++;
        if (tryKey((long)k, (char*)cipher, ciphlen)){
            found = k; status_code = 2; found_rank = id;
            // Notifica a todos los procesos que se encontro la llave
            for (int p=0;p<N;p++) MPI_Send(&found, 1, MPI_UINT64_T, p, 777, comm);
            break;
        }
    }

    double t1 = MPI_Wtime();
    double local_time = t1 - t0;

    // Limpieza de comunicacion no bloqueante
    int completed=0; MPI_Test(&req, &completed, &st);
    if (!completed){ MPI_Cancel(&req); MPI_Wait(&req, &st); }

    // Recopila metricas de todos los procesos en rank 0
    double   *times_all  = NULL;
    uint64_t *tests_all  = NULL, *L_all = NULL, *U_all = NULL;
    int      *status_all = NULL, *rank_found_all = NULL;
    if (id==0) {
        times_all  = (double*)   malloc(sizeof(double)*N);
        tests_all  = (uint64_t*) malloc(sizeof(uint64_t)*N);
        L_all      = (uint64_t*) malloc(sizeof(uint64_t)*N);
        U_all      = (uint64_t*) malloc(sizeof(uint64_t)*N);
        status_all = (int*)      malloc(sizeof(int)*N);
        rank_found_all = (int*)  malloc(sizeof(int)*N);
    }
    MPI_Gather(&local_time, 1, MPI_DOUBLE,   times_all, 1, MPI_DOUBLE,   0, comm);
    MPI_Gather(&local_tests,1, MPI_UINT64_T, tests_all, 1, MPI_UINT64_T, 0, comm);
    MPI_Gather(&myL,        1, MPI_UINT64_T, L_all,     1, MPI_UINT64_T, 0, comm);
    MPI_Gather(&myU,        1, MPI_UINT64_T, U_all,     1, MPI_UINT64_T, 0, comm);
    MPI_Gather(&status_code,1, MPI_INT,      status_all,1, MPI_INT,      0, comm);
    MPI_Gather(&found_rank, 1, MPI_INT,      rank_found_all,1, MPI_INT,  0, comm);

    // Imprime reporte desde rank 0
    if (id==0){
        printf("BRUTEFORCE MPI - STATIC SCHEDULER\n");
        printf("  Processes : %d\n", N);
        printf("  Substring : \"%s\"\n", search);
        printf("  Range     : [%" PRIu64 ", %" PRIu64 ")\n\n", lower, upper);

        puts("PROCESS DETAILS");
        puts("  RANK |     START       END   |   TESTS    |  STATUS           |  TIME(s)");
        puts("  -----+-----------------------+------------+-------------------+---------");

        uint64_t sum_tests = 0;
        double tmax = 0.0;
        int who_found = -1;

        for (int r=0; r<N; ++r) {
            const char *stxt = (status_all[r]==2) ? "FOUND"
                               : (status_all[r]==1) ? "STOP(SIGNAL)"
                               : "DONE(RANGE)";
            printf("    %4d | %10" PRIu64 " %10" PRIu64 " | %10" PRIu64 " | %-17s | %7.4f\n",
                   r, L_all[r], U_all[r], tests_all[r], stxt, times_all[r]);
            sum_tests += tests_all[r];
            if (times_all[r] > tmax) tmax = times_all[r];
            if (status_all[r]==2) who_found = r;
        }

        if (found != UINT64_MAX){
            unsigned char *plain = (unsigned char*)malloc((size_t)ciphlen+1);
            memcpy(plain, cipher, (size_t)ciphlen);
            decrypt((long)found, (char*)plain, ciphlen);
            plain[ciphlen]=0;

            puts("\nRESULT: KEY FOUND");
            printf("  Rank      : %d\n", (who_found>=0?who_found:rank_found_all[0]));
            printf("  Key       : %" PRIu64 "\n", found);
            printf("  Plaintext : %s\n", (char*)plain);
            free(plain);
        } else {
            puts("\nRESULT: KEY NOT FOUND");
        }

        puts("\nGLOBAL SUMMARY");
        printf("  Total keys tested : %" PRIu64 "\n", sum_tests);
        printf("  Total time        : %.6f s\n", tmax);
        puts("");

        free(times_all); free(tests_all); free(L_all); free(U_all);
        free(status_all); free(rank_found_all);
    }

    free(cipher);
    MPI_Barrier(comm);
    MPI_Finalize();
    return 0;
}
