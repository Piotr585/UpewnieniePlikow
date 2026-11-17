#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// --- WYBÓR ODPOWIEDNICH BIBLIOTEK W ZALEŻNOŚCI OD SYSTEMU ---
#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #define PATH_SEPARATOR "\\"
#else
    #include <dirent.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #define PATH_SEPARATOR "/"
    #define MAX_PATH 4096
#endif

// --- IMPLEMENTACJA ALGORYTMU SHA-256 ---
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) | ((uint32_t)data[j+2] << 8) | ((uint32_t)data[j+3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += (uint32_t)ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8));
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8));
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8));
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8));
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8));
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8));
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8));
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8));
    }
}

int oblicz_sha256_pliku(const char *sciezka_pliku, char *output_hex) {
    FILE *f = fopen(sciezka_pliku, "rb");
    if (!f) return 0;

    SHA256_CTX ctx;
    sha256_init(&ctx);

    unsigned char buffer[65536];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), f)) != 0) {
        sha256_update(&ctx, buffer, bytes);
    }
    fclose(f);

    unsigned char hash[32];
    sha256_final(&ctx, hash);

    for (int i = 0; i < 32; i++) {
        sprintf(output_hex + (i * 2), "%02x", hash[i]);
    }
    output_hex[64] = '\0';
    return 1;
}

// --- FUNKCJA SPRAWDZAJĄCA CZY PLIK ISTNIEJE (CROSS-PLATFORM) ---
int czy_plik_istnieje(const char *sciezka) {
    #if defined(_WIN32) || defined(_WIN64)
        DWORD attrs = GetFileAttributesA(sciezka);
        return (attrs != INVALID_FILE_ATTRIBUTES);
    #else
        struct stat buffer;
        return (stat(sciezka, &buffer) == 0);
    #endif
}

// --- GŁÓWNA LOGIKA PRZETWARZANIA KATALOGU ---
void przemianuj_pliki_na_hash(const char *katalog) {
    int zmienione = 0;
    int pominiete = 0;

#if defined(_WIN32) || defined(_WIN64)
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", katalog);

    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(search_path, &find_data);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Błąd: Nie można otworzyć katalogu '%s'.\n", katalog);
        return;
    }

    printf("Przetwarzanie katalogu (Windows): %s\n\n", katalog);

    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        char *nazwa_pliku = find_data.cFileName;
#else
    DIR *dir = opendir(katalog);
    if (!dir) {
        printf("Błąd: Nie można otworzyć katalogu '%s'.\n", katalog);
        return;
    }

    printf("Przetwarzanie katalogu (Linux/macOS): %s\n\n", katalog);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char stara_sciezka_temp[MAX_PATH];
        snprintf(stara_sciezka_temp, sizeof(stara_sciezka_temp), "%s%s%s", katalog, PATH_SEPARATOR, entry->d_name);
        
        struct stat st;
        if (stat(stara_sciezka_temp, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        char *nazwa_pliku = entry->d_name;
#endif

        // Wyciąganie i normalizacja rozszerzenia (na małe litery)
        char *kropka = strrchr(nazwa_pliku, '.');
        char rozszerzenie[32] = "";
        if (kropka && kropka != nazwa_pliku) {
            strcpy(rozszerzenie, kropka);
            for (int i = 0; rozszerzenie[i]; i++) {
                if (rozszerzenie[i] >= 'A' && rozszerzenie[i] <= 'Z') {
                    rozszerzenie[i] += 32;
                }
            }
        }

        char stara_sciezka[MAX_PATH];
        char nowa_sciezka[MAX_PATH];
        char hash_hex[65];

        snprintf(stara_sciezka, sizeof(stara_sciezka), "%s%s%s", katalog, PATH_SEPARATOR, nazwa_pliku);

        if (oblicz_sha256_pliku(stara_sciezka, hash_hex)) {
            char nowa_nazwa[MAX_PATH];
            snprintf(nowa_nazwa, sizeof(nowa_nazwa), "%s%s", hash_hex, rozszerzenie);
            snprintf(nowa_sciezka, sizeof(nowa_sciezka), "%s%s%s", katalog, PATH_SEPARATOR, nowa_nazwa);

            if (czy_plik_istnieje(nowa_sciezka)) {
                char short_hash[13];
                strncpy(short_hash, hash_hex, 12);
                short_hash[12] = '\0';
                printf("[DUPLIKAT/POMINIĘTO] %s -> Plik o sumie %s... już istnieje.\n", nazwa_pliku, short_hash);
                pominiete++;
                continue;
            }

            if (rename(stara_sciezka, nowa_sciezka) == 0) {
                printf("[OK] %s  --->  %s\n", nazwa_pliku, nowa_nazwa);
                zmienione++;
            } else {
                printf("[BŁĄD] Nie udało się zmienić nazwy pliku: %s\n", nazwa_pliku);
            }
        } else {
            printf("[BŁĄD] Nie udało się odczytać pliku: %s\n", nazwa_pliku);
        }

#if defined(_WIN32) || defined(_WIN64)
    } while (FindNextFileA(hFind, &find_data) != 0);
    FindClose(hFind);
#else
    }
    closedir(dir);
#endif

    printf("\nGotowe! Zmieniono nazwę: %d, Pominięto (duplikaty): %d\n", zmienione, pominiete);
}

int main() {
    #if defined(_WIN32) || defined(_WIN64)
        SetConsoleOutputCP(65001); // Poprawne wyświetlanie polskich znaków w konsoli Windows
    #endif

    char folder_docelowy[MAX_PATH];
    printf("Podaj ścieżkę do folderu ze zdjęciami: ");
    
    if (fgets(folder_docelowy, sizeof(folder_docelowy), stdin)) {
        folder_docelowy[strcspn(folder_docelowy, "\r\n")] = 0;

        // Czyszczenie cudzysłowów
        size_t len = strlen(folder_docelowy);
        if (len > 0 && (folder_docelowy[0] == '"' || folder_docelowy[0] == '\'')) {
            memmove(folder_docelowy, folder_docelowy + 1, len);
            len--;
        }
        if (len > 0 && (folder_docelowy[len - 1] == '"' || folder_docelowy[len - 1] == '\'')) {
            folder_docelowy[len - 1] = '\0';
        }

        przemianuj_pliki_na_hash(folder_docelowy);
    }

    printf("\nNaciśnij Enter, aby zakończyć...");
    getchar();
    return 0;
}