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

static EVP_CIPHER *fetch_des_ecb(void) {
    if (!ensure_providers()) return NULL;
    return EVP_CIPHER_fetch(NULL, "DES-ECB", NULL);
}

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

void decrypt(long key, char *ciph, int len) {
    if (!des_ecb_do(0, (uint64_t)key, (const unsigned char*)ciph, len, (unsigned char*)ciph)) {
        fprintf(stderr, "OpenSSL DES-ECB decrypt init failed\n");
        MPI_Abort(MPI_COMM_WORLD, 3);
    }
}

void encrypt(long key, char *plain, int len) {
    if (!des_ecb_do(1, (uint64_t)key, (const unsigned char*)plain, len, (unsigned char*)plain)) {
        fprintf(stderr, "OpenSSL DES-ECB encrypt init failed\n");
        MPI_Abort(MPI_COMM_WORLD, 3);
    }
}

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

static unsigned char cipher_builtin[] =
    {108,245,65,63,125,200,150,66,17,170,207,170,34,31,70,215};

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

static int write_file(const char *path, const unsigned char *buf, int len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = fwrite(buf, 1, (size_t)len, f);
    fclose(f);
    if (n != (size_t)len) return -2;
    return 0;
}

// Work stealing structures
typedef struct {
    uint64_t start;
    uint64_t end;
} work_chunk;

// Tag definitions
#define TAG_WORK_REQUEST 100
#define TAG_WORK_CHUNK 101
#define TAG_TERMINATE 102
#define TAG_FOUND_KEY 103

int main(int argc, char *argv[]){
    int N, id;
    uint64_t upper = (1ULL<<24), lower = 0;
    unsigned char *cipher = NULL; int ciphlen = 0;
    const char *arg_search = NULL;
    uint64_t chunk_size = (1ULL << 16); // Tamaño inicial de chunk
    int steal_enabled = 1; // Habilitar work stealing
    int steal_threshold = 10; // Porcentaje de trabajo restante para empezar a robar

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
        } else if (!strcmp(argv[i], "--no-steal")){
            steal_enabled = 0;
        }
    }
    if (arg_search) search = arg_search;

    MPI_Init(NULL, NULL);
    MPI_Comm comm = MPI_COMM_WORLD;
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    // MODO CIFRADO (igual que antes)
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

            unsigned char *plaintext = NULL;
            int plainlen = 0;
            if (read_file(input_file, &plaintext, &plainlen) != 0) {
                fprintf(stderr, "ERROR: No se pudo leer %s\n", input_file);
                MPI_Abort(comm, 2);
            }

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

            printf("Cifrado exitoso!\n");
            printf("  Tamaño original : %d bytes\n", plainlen);
            printf("  Tamaño cifrado  : %d bytes (con padding)\n\n", padded_len);

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

    // --- WORK STEALING ALGORITHM ---
    
    // Variables locales de trabajo
    uint64_t found = UINT64_MAX;
    uint64_t local_tests = 0;
    int status_code = 0; // 0=working, 1=terminated, 2=found
    int found_rank = -1;
    
    // Cola local de trabajo (chunks)
    #define MAX_LOCAL_QUEUE 10
    work_chunk local_queue[MAX_LOCAL_QUEUE];
    int queue_front = 0;
    int queue_back = 0;
    int queue_size = 0;
    
    // Asignación inicial estática (similar a naive)
    uint64_t total_range = upper - lower;
    uint64_t base_chunk_size = total_range / (uint64_t)N;
    uint64_t remainder = total_range % (uint64_t)N;
    
    uint64_t my_start = lower + base_chunk_size * (uint64_t)id;
    uint64_t my_end = my_start + base_chunk_size;
    if (id == N-1) {
        my_end += remainder; // El último proceso toma el resto
    }
    
    // Dividir trabajo inicial en chunks más pequeños
    uint64_t current_pos = my_start;
    while (current_pos < my_end && queue_size < MAX_LOCAL_QUEUE) {
        uint64_t chunk_end = current_pos + chunk_size;
        if (chunk_end > my_end) chunk_end = my_end;
        
        local_queue[queue_back].start = current_pos;
        local_queue[queue_back].end = chunk_end;
        queue_back = (queue_back + 1) % MAX_LOCAL_QUEUE;
        queue_size++;
        current_pos = chunk_end;
    }
    
    // Comunicación para terminación temprana
    MPI_Request term_req;
    MPI_Irecv(&found, 1, MPI_UINT64_T, MPI_ANY_SOURCE, TAG_FOUND_KEY, comm, &term_req);
    
    // Sincronizar inicio
    MPI_Barrier(comm);
    double t0 = MPI_Wtime();
    
    // Bucle principal de work stealing
    int idle = 0;
    int termination_sent = 0;
    
    while (status_code == 0) {
        // Procesar chunk local si hay trabajo
        if (queue_size > 0) {
            idle = 0;
            
            // Tomar chunk de la cola
            work_chunk current = local_queue[queue_front];
            queue_front = (queue_front + 1) % MAX_LOCAL_QUEUE;
            queue_size--;
            
            // Procesar el chunk
            for (uint64_t k = current.start; k < current.end && status_code == 0; ++k) {
                // Verificar si alguien ya encontró la llave
                int term_flag = 0;
                MPI_Test(&term_req, &term_flag, MPI_STATUS_IGNORE);
                if (term_flag) {
                    status_code = 1; // Terminado por señal
                    break;
                }
                
                local_tests++;
                if (tryKey((long)k, (char*)cipher, ciphlen)) {
                    found = k;
                    status_code = 2; // Encontrado
                    found_rank = id;
                    
                    // Notificar a todos los procesos
                    for (int p = 0; p < N; ++p) {
                        if (p != id) {
                            MPI_Send(&found, 1, MPI_UINT64_T, p, TAG_FOUND_KEY, comm);
                        }
                    }
                    break;
                }
            }
            
            // Si nos quedamos con poco trabajo, intentar robar
            if (steal_enabled && queue_size <= 1 && status_code == 0) {
                // Enviar solicitudes de trabajo a procesos aleatorios
                for (int attempt = 0; attempt < N/2 && queue_size < MAX_LOCAL_QUEUE/2; attempt++) {
                    int target = (id + 1 + attempt) % N; // Simple round-robin
                    if (target == id) continue;
                    
                    MPI_Send(&id, 1, MPI_INT, target, TAG_WORK_REQUEST, comm);
                    
                    // Esperar respuesta con timeout
                    MPI_Request steal_req;
                    work_chunk stolen_chunk;
                    int got_work = 0;
                    
                    MPI_Irecv(&stolen_chunk, sizeof(work_chunk), MPI_BYTE, 
                             target, TAG_WORK_CHUNK, comm, &steal_req);
                    
                    // Esperar un tiempo corto por respuesta
                    MPI_Status steal_status;
                    int steal_completed = 0;
                    MPI_Test(&steal_req, &steal_completed, &steal_status);
                    
                    if (!steal_completed) {
                        double start_wait = MPI_Wtime();
                        while (MPI_Wtime() - start_wait < 0.001) { // Timeout de 1ms
                            MPI_Test(&steal_req, &steal_completed, &steal_status);
                            if (steal_completed) break;
                        }
                    }
                    
                    if (steal_completed) {
                        // Verificar si es chunk válido
                        if (stolen_chunk.start < stolen_chunk.end) {
                            local_queue[queue_back] = stolen_chunk;
                            queue_back = (queue_back + 1) % MAX_LOCAL_QUEUE;
                            queue_size++;
                            got_work = 1;
                        }
                    } else {
                        MPI_Cancel(&steal_req);
                        MPI_Wait(&steal_req, MPI_STATUS_IGNORE);
                    }
                    
                    if (got_work) break;
                }
            }
        } else {
            // Sin trabajo local - modo idle
            if (!idle) {
                idle = 1;
                // Intentar robar trabajo inmediatamente
                for (int attempt = 0; attempt < N && queue_size == 0; attempt++) {
                    int target = (id + attempt) % N;
                    if (target == id) continue;
                    
                    MPI_Send(&id, 1, MPI_INT, target, TAG_WORK_REQUEST, comm);
                    
                    MPI_Request steal_req;
                    work_chunk stolen_chunk;
                    MPI_Irecv(&stolen_chunk, sizeof(work_chunk), MPI_BYTE, 
                             target, TAG_WORK_CHUNK, comm, &steal_req);
                    
                    MPI_Status steal_status;
                    int steal_completed;
                    MPI_Wait(&steal_req, &steal_status);
                    
                    if (stolen_chunk.start < stolen_chunk.end) {
                        local_queue[queue_back] = stolen_chunk;
                        queue_back = (queue_back + 1) % MAX_LOCAL_QUEUE;
                        queue_size++;
                        break;
                    }
                }
            }
            
            // Si todavía no hay trabajo, verificar terminación
            if (queue_size == 0) {
                // Verificar mensajes entrantes
                MPI_Status status;
                int msg_available;
                MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &msg_available, &status);
                
                if (msg_available) {
                    if (status.MPI_TAG == TAG_WORK_REQUEST) {
                        // Alguien nos pide trabajo - responder aunque no tengamos
                        int requester;
                        MPI_Recv(&requester, 1, MPI_INT, status.MPI_SOURCE, 
                                TAG_WORK_REQUEST, comm, MPI_STATUS_IGNORE);
                        
                        work_chunk empty_chunk = {0, 0};
                        MPI_Send(&empty_chunk, sizeof(work_chunk), MPI_BYTE, 
                                requester, TAG_WORK_CHUNK, comm);
                    } else if (status.MPI_TAG == TAG_FOUND_KEY) {
                        uint64_t temp_found;
                        MPI_Recv(&temp_found, 1, MPI_UINT64_T, status.MPI_SOURCE, 
                                TAG_FOUND_KEY, comm, MPI_STATUS_IGNORE);
                        status_code = 1;
                    }
                } else {
                    // No hay mensajes y no hay trabajo - posible terminación
                    int all_idle;
                    int local_idle = (queue_size == 0) ? 1 : 0;
                    MPI_Allreduce(&local_idle, &all_idle, 1, MPI_INT, MPI_LAND, comm);
                    
                    if (all_idle && !termination_sent) {
                        status_code = 1;
                        termination_sent = 1;
                    }
                }
            }
        }
        
        // Manejar solicitudes de trabajo de otros procesos
        MPI_Status req_status;
        int req_available;
        MPI_Iprobe(MPI_ANY_SOURCE, TAG_WORK_REQUEST, comm, &req_available, &req_status);
        
        if (req_available && queue_size > 1) { // Solo dar trabajo si tenemos suficiente
            int requester;
            MPI_Recv(&requester, 1, MPI_INT, req_status.MPI_SOURCE, 
                    TAG_WORK_REQUEST, comm, MPI_STATUS_IGNORE);
            
            // Dar la mitad de nuestro trabajo
            int chunks_to_give = queue_size / 2;
            if (chunks_to_give > 0) {
                work_chunk chunk_to_send = local_queue[queue_front];
                queue_front = (queue_front + 1) % MAX_LOCAL_QUEUE;
                queue_size--;
                
                MPI_Send(&chunk_to_send, sizeof(work_chunk), MPI_BYTE, 
                        requester, TAG_WORK_CHUNK, comm);
            } else {
                work_chunk empty_chunk = {0, 0};
                MPI_Send(&empty_chunk, sizeof(work_chunk), MPI_BYTE, 
                        requester, TAG_WORK_CHUNK, comm);
            }
        }
    }
    
    double t1 = MPI_Wtime();
    double local_time = t1 - t0;
    
    // Limpiar comunicación
    MPI_Cancel(&term_req);
    MPI_Wait(&term_req, MPI_STATUS_IGNORE);
    
    // Recopilar métricas
    double *times_all = NULL;
    uint64_t *tests_all = NULL;
    int *status_all = NULL;
    int *rank_found_all = NULL;
    int *queue_sizes = NULL;
    
    if (id == 0) {
        times_all = (double*)malloc(sizeof(double) * N);
        tests_all = (uint64_t*)malloc(sizeof(uint64_t) * N);
        status_all = (int*)malloc(sizeof(int) * N);
        rank_found_all = (int*)malloc(sizeof(int) * N);
        queue_sizes = (int*)malloc(sizeof(int) * N);
    }
    
    MPI_Gather(&local_time, 1, MPI_DOUBLE, times_all, 1, MPI_DOUBLE, 0, comm);
    MPI_Gather(&local_tests, 1, MPI_UINT64_T, tests_all, 1, MPI_UINT64_T, 0, comm);
    MPI_Gather(&status_code, 1, MPI_INT, status_all, 1, MPI_INT, 0, comm);
    MPI_Gather(&found_rank, 1, MPI_INT, rank_found_all, 1, MPI_INT, 0, comm);
    MPI_Gather(&queue_size, 1, MPI_INT, queue_sizes, 1, MPI_INT, 0, comm);
    
    // Reporte desde rank 0
    if (id == 0) {
        printf("BRUTEFORCE MPI - WORK STEALING ALGORITHM\n");
        printf("  Procesos      : %d\n", N);
        printf("  Subcadena     : \"%s\"\n", search);
        printf("  Rango         : [%" PRIu64 ", %" PRIu64 ")\n", lower, upper);
        printf("  Chunk size    : %" PRIu64 "\n", chunk_size);
        printf("  Work stealing : %s\n\n", steal_enabled ? "ENABLED" : "DISABLED");
        
        puts("DETALLE POR PROCESO");
        puts("  RANK |   TESTS    | QUEUE |  STATUS           |  TIME(s)");
        puts("  -----+------------+-------+-------------------+---------");
        
        uint64_t sum_tests = 0;
        double tmax = 0.0;
        int who_found = -1;
        
        for (int r = 0; r < N; ++r) {
            const char *stxt = (status_all[r] == 2) ? "FOUND"
                               : (status_all[r] == 1) ? "TERMINATED"
                               : "UNKNOWN";
            printf("    %4d | %10" PRIu64 " | %5d | %-17s | %7.4f\n",
                   r, tests_all[r], queue_sizes[r], stxt, times_all[r]);
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
        
        double efficiency = (sum_tests > 0) ? (100.0 * (double)sum_tests / (double)total_range) : 0.0;
        printf("  Eficiencia (claves/rango): %.2f%%\n", efficiency);
        printf("  Throughput agregado      : %.2f M keys/s\n", (sum_tests / tmax) / 1e6);
        
        // Calcular balance de carga
        uint64_t avg_tests = sum_tests / N;
        uint64_t max_diff = 0;
        for (int r = 0; r < N; r++) {
            uint64_t diff = (tests_all[r] > avg_tests) ? tests_all[r] - avg_tests : avg_tests - tests_all[r];
            if (diff > max_diff) max_diff = diff;
        }
        double load_balance = 100.0 * (1.0 - (double)max_diff / (double)avg_tests);
        printf("  Balance de carga         : %.2f%%\n", load_balance);
        puts("");
        
        free(times_all);
        free(tests_all);
        free(status_all);
        free(rank_found_all);
        free(queue_sizes);
    }
    
    free(cipher);
    MPI_Barrier(comm);
    MPI_Finalize();
    return 0;
}