# ElGamal

**Autor: Maksym Vatset**

Implementacja kryptosystemu ElGamala w języku Go: szyfrowanie, deszyfrowanie, podpis cyfrowy i weryfikacja.

## Wymagania

- Go 1.18+

## Kompilacja

```bash
go build -o elgamal elgamal.go
```

## Użycie

### 1. Przygotowanie pliku `elgamal.txt`

Plik musi zawierać dwie linie: liczbę pierwszą `p` oraz generator `g`:

```
1665997633093155705263923663680487185948531888850484859473375695734301776192932338784530163
170057347237941209366519667629336535698946063913573988287540019819022183488419112350737049
```

### 2. Generowanie kluczy

```bash
./elgamal -k
```

Tworzy pliki `private.txt` i `public.txt`.

### 3. Szyfrowanie

```bash
echo "12345678901234567890" > plain.txt
./elgamal -e
```

Tworzy `crypto.txt`. Jeśli `m >= p` — program zgłasza błąd.

### 4. Deszyfrowanie

```bash
./elgamal -d
```

Tworzy `decrypt.txt`.

### 5. Podpis cyfrowy

```bash
cp plain.txt message.txt
./elgamal -s
```

Tworzy `signature.txt`.

### 6. Weryfikacja podpisu

```bash
./elgamal -v
```

Wypisuje `T` (poprawny) lub `N` (niepoprawny) na ekran i zapisuje do `verify.txt`.

## Opcje

| Flaga | Działanie |
|-------|-----------|
| `-k`  | Generowanie pary kluczy |
| `-e`  | Szyfrowanie wiadomości |
| `-d`  | Deszyfrowanie kryptogramu |
| `-s`  | Tworzenie podpisu cyfrowego |
| `-v`  | Weryfikacja podpisu |

## Pliki wejściowe / wyjściowe

| Flaga | Odczytuje | Zapisuje |
|-------|-----------|----------|
| `-k`  | `elgamal.txt` | `private.txt`, `public.txt` |
| `-e`  | `public.txt`, `plain.txt` | `crypto.txt` |
| `-d`  | `private.txt`, `crypto.txt` | `decrypt.txt` |
| `-s`  | `private.txt`, `message.txt` | `signature.txt` |
| `-v`  | `public.txt`, `message.txt`, `signature.txt` | `verify.txt` |
