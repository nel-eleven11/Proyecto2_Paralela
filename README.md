# Proyecto2_Paralela

---

# Autores:

- Nelson García Bravatti 22343
- Gabriel PAz Gonzalez 221089
- Joaquín Puente 22296

---

# Compilar/Correr

bruteforce.c:

```bash
# Compile with MPI and OpenSSL
mpicc -O3 -std=c11 bruteforce.c -lcrypto -o bruteforce
```

```bash
# Run with 4 processes
mpirun -np 4 ./bruteforce
```

```bash
# Run with 8 processes
mpirun -np 8 ./bruteforce
```

---