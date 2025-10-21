
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>
#include <limits.h>  // LONG_MAX

static const char search_str[] = " the ";

// --- Cifrado/descifrado (1 bloque DES-ECB con OpenSSL) ---
void decrypt(long key, char *ciph, int len){
    (void)len; // en esta demo se procesa 1 bloque (8 bytes)
    DES_cblock des_key;
    memcpy(&des_key, &key, 8);
    DES_key_schedule schedule;
    DES_set_key_unchecked(&des_key, &schedule); // API DES está deprecada en OpenSSL 3 (warning)
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_DECRYPT);
}

void encrypt(long key, char *ciph, int len){
    (void)len; // en esta demo se procesa 1 bloque (8 bytes)
    DES_cblock des_key;
    memcpy(&des_key, &key, 8);
    DES_key_schedule schedule;
    DES_set_key_unchecked(&des_key, &schedule); // API DES está deprecada en OpenSSL 3 (warning)
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_ENCRYPT);
}

// Prueba de clave: descifra (1 bloque) y busca el patrón " the "
int tryKey(long key, const unsigned char *ciph, int len){
    char temp[32]; // suficiente para 1–2 bloques en esta demo
    if (len > (int)sizeof(temp)-1) len = (int)sizeof(temp)-1;
    memcpy(temp, ciph, len);
    temp[len] = 0;
    decrypt(key, temp, len);
    return strstr((char *)temp, search_str) != NULL;
}

// Cipher de ejemplo (último byte 0 como centinela para strlen en el código original)
static unsigned char cipher[] = {
    108, 245,  65,  63, 125, 200, 150,  66,
     17, 170, 207, 170,  34,  31,  70, 215,
      0
};

int main(int argc, char *argv[]){
    MPI_Init(&argc, &argv);

    int N = 0, id = 0;
    MPI_Comm comm = MPI_COMM_WORLD;
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    // --- Configuración del espacio de claves ---
    // Por defecto 2^56; si se pasa un argumento entero n (1..56), usa 2^n para ensayos.
    int bits = 56;
    if (argc >= 2) {
        int b = atoi(argv[1]);
        if (b >= 1 && b <= 56) bits = b;
        if (id == 0 && (b < 1 || b > 56))
            fprintf(stderr, "Aviso: bits fuera de rango, usando 56.\n");
    }
    unsigned long long upper = (bits == 64) ? 0ULL : (1ULL << bits); // límite superior (no inclusivo)

    // Longitud del cifrado: usa strlen como en el código original
    const int ciphlen = (int)strlen((char*)cipher);

    // --- Partición balanceada [mylower, myupper) ---
    unsigned long long range = (upper + (unsigned long long)N - 1ULL) / (unsigned long long)N; // ceil
    unsigned long long mylower = (unsigned long long)id * range;
    unsigned long long myupper = (unsigned long long)(id + 1) * range;
    if (myupper > upper) myupper = upper;

    // --- Comunicación para terminación temprana ---
    long found_key = 0;                 // clave encontrada (0 = no encontrada aún)
    MPI_Request req;
    MPI_Status  st;
    int recv_done = 0;
    MPI_Irecv(&found_key, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

    // --- Sincronización de inicio para mediciones coherentes ---
    MPI_Barrier(comm);
    double t0 = MPI_Wtime();

    // --- Búsqueda secuencial ---
    unsigned long long local_checks = 0ULL;
    int local_found = 0;
    double t_found_local = 0.0; // instante en que ESTE rank encontró (si aplica)
    double t_done_local  = 0.0; // instante en que ESTE rank detuvo la búsqueda (recibió aviso o encontró)

    for (unsigned long long i = mylower; i < myupper; ++i) {
        // ¿Algún otro ya envió la clave? (poll no bloqueante)
        if (!recv_done) {
            int flag = 0;
            MPI_Test(&req, &flag, &st);
            if (flag) {
                recv_done = 1;
                t_done_local = MPI_Wtime();
                break; // dejar de explorar
            }
        }

        // Probar una clave
        if (tryKey((long)i, cipher, ciphlen)) {
            found_key = (long)i;
            local_found = 1;
            t_found_local = MPI_Wtime();

            // Notificar a todos no-bloqueante
            MPI_Request *sreqs = (MPI_Request*)malloc(sizeof(MPI_Request) * (size_t)N);
            for (int node = 0; node < N; ++node) {
                MPI_Isend(&found_key, 1, MPI_LONG, node, 0, comm, &sreqs[node]);
            }
            MPI_Waitall(N, sreqs, MPI_STATUSES_IGNORE);
            free(sreqs);

            t_done_local = t_found_local; // este rank detiene inmediatamente
            break;
        }
        local_checks++;
    }

    // Último chequeo de recepción si no se detuvo antes
    if (t_done_local == 0.0) {
        int flag = 0;
        MPI_Test(&req, &flag, &st);
        if (flag && found_key != 0) {
            recv_done = 1;
            t_done_local = MPI_Wtime();
        } else {
            t_done_local = MPI_Wtime();
        }
    }

    // Asegurar no dejar pendiente el Irecv
    if (!recv_done) {
        MPI_Cancel(&req);
        MPI_Request_free(&req);
    } else {
        MPI_Request_free(&req);
    }

    // --- Métricas globales ---
    double search_time_min_found = (local_found ? (t_found_local - t0) : 1e300);
    double search_time_any_found = 0.0; // min real entre ranks
    double search_time_all_done  = t_done_local - t0; // tiempo en que ESTE rank terminó
    double search_time_max_done  = 0.0; // max entre ranks (todos notificados)

    unsigned long long global_checks = 0ULL;

    int my_winner_rank = local_found ? id : 999999999;
    int winner_rank = -1;

    MPI_Reduce(&local_checks, &global_checks, 1, MPI_UNSIGNED_LONG_LONG, MPI_SUM, 0, comm);
    MPI_Reduce(&search_time_min_found, &search_time_any_found, 1, MPI_DOUBLE, MPI_MIN, 0, comm);
    MPI_Reduce(&search_time_all_done,  &search_time_max_done,  1, MPI_DOUBLE, MPI_MAX, 0, comm);
    MPI_Reduce(&my_winner_rank, &winner_rank, 1, MPI_INT, MPI_MIN, 0, comm);

    // Rank 0: imprimir resultados y descifrar para verificar
    if (id == 0) {
        long local_found_key = found_key;

        // Acordar la clave encontrada (mínimo valor > 0)
        long candidate = (local_found_key > 0) ? local_found_key : LONG_MAX;
        long agreed    = LONG_MAX;
        MPI_Allreduce(&candidate, &agreed, 1, MPI_LONG, MPI_MIN, comm);
        if (agreed != LONG_MAX) local_found_key = agreed;

        // Descifrar y mostrar (se usa el primer bloque como en la demo original)
        unsigned char tmp[32];
        int out_len = ciphlen;
        if (out_len > (int)sizeof(tmp)-1) out_len = (int)sizeof(tmp)-1;
        memcpy(tmp, cipher, out_len);
        tmp[out_len] = 0;

        if (local_found_key != 0 && local_found_key != LONG_MAX) {
            decrypt(local_found_key, (char*)tmp, out_len);
            printf("=== Resultado ===\n");
            printf("Procesos:                   %d\n", N);
            printf("Espacio buscado:            2^%d claves\n", bits);
            printf("Rank que encontró:          %d\n", winner_rank);
            printf("Clave encontrada (dec):     %ld\n", local_found_key);
            printf("Clave encontrada (hex):     0x%016lx\n", (unsigned long)local_found_key);
            printf("Tiempo (encontrar):         %.6f s\n", search_time_any_found);
            printf("Tiempo (todos notificados): %.6f s\n", search_time_max_done);
            printf("Claves probadas (global):   %llu\n", (unsigned long long)global_checks);
            if (search_time_any_found > 0.0)
                printf("Throughput aprox (al encontrar): %.0f claves/s\n",
                       (double)global_checks / search_time_any_found);
            if (search_time_max_done > 0.0)
                printf("Throughput (hasta notificar a todos): %.0f claves/s\n",
                       (double)global_checks / search_time_max_done);
            printf("Texto (primer bloque):      \"%s\"\n", (char*)tmp);
            printf("=================\n");
        } else {
            printf("No se encontró clave en el espacio 2^%d (o no llegó notificación).\n", bits);
        }
    }

    MPI_Finalize();
    return 0;
}
