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
mpicc bruteforce.c -o program -lssl -lcrypto
```

```bash
# Run with 4 processes
mpirun -np 4 ./program
```

```bash
# Run with 8 processes
mpirun -np 8 ./program
```