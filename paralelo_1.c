#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <mpi.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

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
// Replica el patrón usado históricamente con rpc/des_crypt.h
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
        MPI_Abort(MPI_COMM_WORLD, 3);
    }
}

// api compatible que cifra en el mismo buffer
void encrypt(long key, char *plain, int len) {
    if (!des_ecb_do(1, (uint64_t)key, (const unsigned char*)plain, len, (unsigned char*)plain)) {
        fprintf(stderr, "OpenSSL DES-ECB encrypt init failed\n");
        MPI_Abort(MPI_COMM_WORLD, 3);
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

// escribe buffer a archivo binario
static int write_file(const char *path, const unsigned char *buf, int len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = fwrite(buf, 1, (size_t)len, f);
    fclose(f);
    if (n != (size_t)len) return -2;
    return 0;
}

// bucle principal
int main(int argc, char *argv[]){
    int N, id;
    uint64_t upper = (1ULL<<24), lower = 0;
    unsigned char *cipher = NULL; int ciphlen = 0;
    const char *arg_search = NULL;
    uint64_t chunk_size = (1ULL << 16); // Default: 65536

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
        } else if (!strcmp(argv[i], "-B") && i+1<argc){
            chunk_size = strtoull(argv[++i], NULL, 0);
        } 
    }
    if (arg_search) search = arg_search;

    // inicializa mpi y obtiene tamano y rank
    MPI_Init(NULL, NULL);
    MPI_Comm comm = MPI_COMM_WORLD;
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    // MODO CIFRADO
    if (encrypt_mode) {
        if (!input_file || !output_file) {
            if (id == 0) {
                fprintf(stderr, "ERROR: Modo cifrado requiere -i <input> y -o <output>\n");
            }
            MPI_Finalize();
            return 1;
        }

        if (id == 0) {
            printf("MODO CIFRADO\n");
            printf("  Archivo entrada : %s\n", input_file);
            printf("  Archivo salida  : %s\n", output_file);
            printf("  Llave           : %" PRIu64 "\n\n", encrypt_key);

            // Leer archivo de texto
            unsigned char *plaintext = NULL;
            int plainlen = 0;
            if (read_file(input_file, &plaintext, &plainlen) != 0) {
                fprintf(stderr, "ERROR: No se pudo leer %s\n", input_file);
                MPI_Abort(comm, 2);
            }

            // Ajustar tamaño a múltiplo de 8 (padding con espacios)
            int padded_len = ((plainlen + 7) / 8) * 8;
            unsigned char *padded = (unsigned char*)malloc(padded_len);
            memcpy(padded, plaintext, plainlen);
            for (int i = plainlen; i < padded_len; i++) {
                padded[i] = ' '; // padding con espacios
            }
            free(plaintext);

            // Cifrar
            encrypt((long)encrypt_key, (char*)padded, padded_len);

            // Escribir archivo cifrado
            if (write_file(output_file, padded, padded_len) != 0) {
                fprintf(stderr, "ERROR: No se pudo escribir %s\n", output_file);
                free(padded);
                MPI_Abort(comm, 3);
            }

            printf("Cifrado exitoso!\n");
            printf("  Tamaño original : %d bytes\n", plainlen);
            printf("  Tamaño cifrado  : %d bytes (con padding)\n\n", padded_len);

            free(padded);
        }

        MPI_Finalize();
        return 0;
    }

    // usa cifrado embebido si no se proporciona archivo
    if (!cipher){
        ciphlen = (int)sizeof(cipher_builtin);
        cipher = (unsigned char*)malloc((size_t)ciphlen);
        memcpy(cipher, cipher_builtin, (size_t)ciphlen);
    }
    // valida que el cifrado sea multiplo de ocho bytes
    if (ciphlen % 8 != 0){
        fprintf(stderr, "ERROR: longitud de cifrado no es múltiplo de 8 (%d)\n", ciphlen);
        MPI_Finalize();
        return 3;
    }


    // --- DYNAMIC SCHEDULER WITH RMA ---
    // Create MPI_Win with global counter for next_key
    MPI_Win win;
    uint64_t *next_key_ptr = NULL;

    if (id == 0) {
        MPI_Win_allocate(sizeof(uint64_t), sizeof(uint64_t),
                         MPI_INFO_NULL, comm, &next_key_ptr, &win);
        *next_key_ptr = lower; // Initialize to lower bound
    } else {
        MPI_Win_allocate(0, sizeof(uint64_t), MPI_INFO_NULL, comm, &next_key_ptr, &win);
    }
    MPI_Win_lock_all(0, win);

    // --- Early termination communication (same as original) ---
    uint64_t found = UINT64_MAX;
    MPI_Request req;
    MPI_Status st;
    int recv_done = 0;
    MPI_Irecv(&found, 1, MPI_UINT64_T, MPI_ANY_SOURCE, 777, comm, &req);

    // --- Synchronize start ---
    MPI_Barrier(comm);
    double t0 = MPI_Wtime();

    // --- Dynamic chunk-based search ---
    uint64_t local_tests = 0;
    int status_code = 0; // 0=done(no more work), 1=stopped(signal), 2=found
    int found_rank = -1;

    for (;;) {
        // Check if someone already found the key
        if (!recv_done) {
            int flag = 0;
            MPI_Test(&req, &flag, &st);
            if (flag) {
                recv_done = 1;
                status_code = 1;
                break;
            }
        }

        // Atomically reserve a chunk: base = fetch_and_add(next_key, chunk_size)
        uint64_t base = 0;
        uint64_t increment = chunk_size;
        MPI_Fetch_and_op(&increment, &base, MPI_UINT64_T, 0, 0, MPI_SUM, win);
        MPI_Win_flush(0, win); // Ensure consistency

        // Check if we're beyond the upper bound (no more work)
        if (base >= upper) {
            status_code = 0; // Done, no more work
            break;
        }

        uint64_t end = base + chunk_size;
        if (end > upper) end = upper;

        // Process this chunk
        for (uint64_t k = base; k < end; ++k) {
            // Quick check for termination signal
            if (!recv_done) {
                int flag = 0;
                MPI_Test(&req, &flag, &st);
                if (flag) {
                    recv_done = 1;
                    status_code = 1;
                    break;
                }
            } else break;

            // Try this key
            local_tests++;
            if (tryKey((long)k, (char*)cipher, ciphlen)) {
                found = k;
                status_code = 2;
                found_rank = id;

                // Notify all processes
                for (int p = 0; p < N; ++p) {
                    MPI_Send(&found, 1, MPI_UINT64_T, p, 777, comm);
                }
                break;
            }
        }

        if (recv_done || status_code > 0) break;
    }

    double t1 = MPI_Wtime();
    double local_time = t1 - t0;

    // Clean up non-blocking receive
    int completed = 0;
    MPI_Test(&req, &completed, &st);
    if (!completed) {
        MPI_Cancel(&req);
        MPI_Wait(&req, &st);
    }

    // Clean up RMA window
    MPI_Win_unlock_all(win);
    MPI_Win_free(&win);

    // --- Gather metrics from all processes ---
    double   *times_all  = NULL;
    uint64_t *tests_all  = NULL;
    int      *status_all = NULL;
    int      *rank_found_all = NULL;
    uint64_t *chunks_processed = NULL;

    if (id == 0) {
        times_all  = (double*)   malloc(sizeof(double) * N);
        tests_all  = (uint64_t*) malloc(sizeof(uint64_t) * N);
        status_all = (int*)      malloc(sizeof(int) * N);
        rank_found_all = (int*)  malloc(sizeof(int) * N);
        chunks_processed = (uint64_t*) malloc(sizeof(uint64_t) * N);
    }

    uint64_t local_chunks = (local_tests > 0) ? ((local_tests + chunk_size - 1) / chunk_size) : 0;

    MPI_Gather(&local_time, 1, MPI_DOUBLE,   times_all, 1, MPI_DOUBLE,   0, comm);
    MPI_Gather(&local_tests, 1, MPI_UINT64_T, tests_all, 1, MPI_UINT64_T, 0, comm);
    MPI_Gather(&status_code, 1, MPI_INT,      status_all, 1, MPI_INT,      0, comm);
    MPI_Gather(&found_rank,  1, MPI_INT,      rank_found_all, 1, MPI_INT,  0, comm);
    MPI_Gather(&local_chunks, 1, MPI_UINT64_T, chunks_processed, 1, MPI_UINT64_T, 0, comm);

    // --- Report from rank 0 ---
    if (id == 0) {
        printf("BRUTEFORCE MPI - DYNAMIC SCHEDULER (RMA + CHUNKS)\n");
        printf("  Procesos    : %d\n", N);
        printf("  Subcadena   : \"%s\"\n", search);
        printf("  Rango       : [%" PRIu64 ", %" PRIu64 ")\n", lower, upper);
        printf("  Chunk size  : %" PRIu64 "\n\n", chunk_size);

        puts("DETALLE POR PROCESO");
        puts("  RANK |   TESTS    | CHUNKS |  STATUS           |  TIME(s)");
        puts("  -----+------------+--------+-------------------+---------");

        uint64_t sum_tests = 0;
        double tmax = 0.0;
        int who_found = -1;

        for (int r = 0; r < N; ++r) {
            const char *stxt = (status_all[r] == 2) ? "FOUND"
                               : (status_all[r] == 1) ? "STOP(SIGNAL)"
                               : "DONE(NO_WORK)";
            printf("    %4d | %10" PRIu64 " | %6" PRIu64 " | %-17s | %7.4f\n",
                   r, tests_all[r], chunks_processed[r], stxt, times_all[r]);
            sum_tests += tests_all[r];
            if (times_all[r] > tmax) tmax = times_all[r];
            if (status_all[r] == 2) who_found = r;
        }

        if (found != UINT64_MAX) {
            unsigned char *plain = (unsigned char*)malloc((size_t)ciphlen + 1);
            memcpy(plain, cipher, (size_t)ciphlen);
            decrypt((long)found, (char*)plain, ciphlen);
            plain[ciphlen] = 0;

            puts("\nRESULTADO: LLAVE ENCONTRADA");
            printf("  Rank         : %d\n", (who_found >= 0 ? who_found : rank_found_all[0]));
            printf("  Llave        : %" PRIu64 "\n", found);
            printf("  Texto plano  : %s\n", (char*)plain);
            free(plain);
        } else {
            puts("\nRESULTADO: LLAVE NO ENCONTRADA");
        }

        puts("\nRESUMEN GLOBAL");
        printf("  Llaves probadas totales  : %" PRIu64 "\n", sum_tests);
        printf("  Tiempo total (max rank)  : %.6f s\n", tmax);

        // Calculate efficiency metrics
        uint64_t total_range = upper - lower;
        double efficiency = (sum_tests > 0) ? (100.0 * (double)sum_tests / (double)total_range) : 0.0;
        printf("  Eficiencia (claves/rango): %.2f%%\n", efficiency);
        printf("  Throughput agregado      : %.2f M keys/s\n",
               (sum_tests / tmax) / 1e6);
        puts("");

        free(times_all);
        free(tests_all);
        free(status_all);
        free(rank_found_all);
        free(chunks_processed);
    }

    // libera recursos y finaliza mpi
    free(cipher);
    MPI_Barrier(comm);
    MPI_Finalize();
    return 0;
}
