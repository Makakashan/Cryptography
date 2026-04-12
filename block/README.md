Created by **Maksym Vatset**

# Block ECB/CBC BMP — guide

Program reads:

- `plain.bmp` (required)
- `key.txt` (optional)

Program writes:

- `ecb_crypto.bmp`
- `cbc_crypto.bmp`

## Build

```sh
go build -o block block.go
```

OR

```sh
chmod +x build.sh
./build.sh
```

## Run

```sh
./block
```

If `key.txt` is missing, program uses internal default key.

## Notes

- ECB and CBC modes are implemented manually in code.
- No built-in block cipher mode APIs are used.
- Input BMP must be uncompressed (`BI_RGB`), 8-bit or 24-bit.
- Output BMP files are saved as 8-bit grayscale.

---
