# Proyecto2_Paralela

---

# Autores:

- Nelson García Bravatti 22343
- Gabriel PAz Gonzalez 221089
- Joaquín Puente 22296

---
## Reporte del Proyecto:

```
https://uvggt-my.sharepoint.com/:w:/r/personal/gar22434_uvg_edu_gt/Documents/Proyecto%202%20Paralela.docx?d=w71cd1c17acea47cd9f756227f4592fef&csf=1&web=1&e=RkroSI
```

---

# Compilar/Correr

## Compilación

### bruteforce.c (Planificador Estático)

```bash
# Compilar con MPI y OpenSSL
mpicc -std=c11 -O3 -Wall -Wextra -pedantic bruteforce.c -lcrypto -o bruteforce
```

### paralelo_1.c (Planificador Dinámico con RMA + Chunks)

```bash
# Compilar con MPI y OpenSSL
mpicc -std=c11 -O3 -Wall -Wextra -pedantic paralelo_1.c -lcrypto -o paralelo_1
```

```bash
# Compilar con MPI y OpenSSL
mpicc -std=c11 -O3 -Wall -Wextra -pedantic paralelo_2.c -lcrypto -o paralelo_2
```

## Ejecución

### Modo 1: Cifrado de Archivos

Cifra un archivo de texto usando una llave privada:

```bash
# Con bruteforce (planificador estático)
mpirun -np 1 ./bruteforce -e -i mensaje.txt -o cifrado.bin -k 123456

# Con paralelo_1 (planificador dinámico)
mpirun -np 1 ./paralelo_1 -e -i mensaje.txt -o cifrado.bin -k 123456

#Con paralelo_2 
mpirun -np 1 ./paralelo_2 -e -i mensaje.txt -o cifrado.bin -k 123456
```

**Parámetros:**
- `-e` : Activa el modo cifrado
- `-i <archivo>` : Archivo de texto de entrada
- `-o <archivo>` : Archivo binario de salida (cifrado)
- `-k <número>` : Llave numérica para cifrar

### Modo 2: Descifrado / Bruteforce

Encuentra la llave mediante fuerza bruta:

#### bruteforce.c (Planificador Estático)

```bash
# Con cifrado embebido por defecto
mpirun -np 4 ./bruteforce

# Con archivo cifrado personalizado
mpirun -np 8 ./bruteforce -c cifrado.bin -L 0 -U 16777216 -s "texto"
```

#### paralelo_1.c (Planificador Dinámico - Recomendado)

```bash
# Con cifrado embebido por defecto
mpirun -np 4 --mca osc ^ucx ./paralelo_1

# Con archivo cifrado personalizado y chunk personalizado
mpirun -np 8 --mca osc ^ucx ./paralelo_1 -c cifrado.bin -L 0 -U 16777216 -s "texto" -B 65536
```

#### paralelo_2.c
```bash
# Con cifrado embebido por defecto
mpirun -np 4 --mca osc ^ucx ./paralelo_2

# Con archivo cifrado personalizado y chunk personalizado
mpirun -np 8 --mca osc ^ucx ./paralelo_2 -c cifrado.bin -L 0 -U 16777216 -s "texto" -B 65536
```

**Parámetros:**
- `-c <archivo>` : Archivo cifrado para descifrar
- `-L <número>` : Límite inferior del rango de búsqueda (default: 0)
- `-U <número>` : Límite superior del rango de búsqueda (default: 2^24)
- `-s <texto>` : Subcadena a buscar en el texto descifrado (default: " the ")
- `-B <número>` : Tamaño del chunk (solo paralelo_1, default: 65536)

**Nota:** `--mca osc ^ucx` suprime advertencias de MPI UCX (opcional).

### Ejemplos Completos

```bash
# 1. Cifrar un archivo
echo "Save the planet and protect our environment!" > mensaje.txt
mpirun -np 1 ./paralelo_1 -e -i mensaje.txt -o secreto.bin -k 999999

# 2. Encontrar la llave con bruteforce dinámico
mpirun -np 4 --mca osc ^ucx ./paralelo_1 -c secreto.bin -L 990000 -U 1000000 -s "planet"

# 3. Comparar con bruteforce estático
mpirun -np 4 ./bruteforce -c secreto.bin -L 990000 -U 1000000 -s "planet"
```

---
