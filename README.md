# Scanner CVE PHP & React

- **CVE-2026-109618 / CVE-2026-109619** (PHP multipart parsing)
- **CVE-2025-55182 / CVE-2025-66478** (React Server Components / Next.js RCE)

## Mulai Cepat

```powershell
# 1. Instal dependensi
pip install -r requirements.txt

# 2. Scan satu target (PHP + React)
python scanner.py -u https://example.com

# 3. Pemindaian Banyak Target dari Berkas
python scanner.py -l hosts.txt --mode all -o hasil.json

# 4. Lihat semua opsi
python scanner.py -h
```

Jika dijalankan tanpa argumen, scanner akan menampilkan panduan pemakaian singkat.

## Fitur

- **Satu Perintah** — Memungkinkan pemindaian kedua jenis kerentanan sekaligus menggunakan opsi `--mode all` (mode bawaan).
- **Fleksibel** — Mendukung pemindaian satu URL atau beberapa URL yang tercantum dalam berkas `.txt`.
- **Mode Pemindaian Khusus** — Memungkinkan pemindaian khusus untuk PHP atau React.
- **Deteksi Cerdas** — Mendukung identifikasi lingkungan `mod_php`, PHP-FPM, serta Next.js App Router dan Pages Router.
- **Baseline dan Fingerprinting** — Melakukan permintaan awal untuk mengidentifikasi keberadaan WAF/CDN dan mekanisme challenge sebelum menentukan hasil pemindaian.
- **Pembatasan Laju dan Percobaan Ulang** — Mengatur frekuensi permintaan serta mengulangi permintaan yang mengalami kesalahan sementara dengan jeda bertahap (*backoff*).
- **Dukungan Proxy Opsional** — Memungkinkan seluruh mesin pemindai menggunakan proxy HTTP/HTTPS atau terhubung langsung tanpa proxy.
- **Opsi Bypass WAF** — Menyediakan opsi `--waf-bypass` dan `--vercel-waf-bypass` untuk pemindaian React. Penggunaannya memerlukan opsi `--rce`.
- **Keluaran Terstruktur** — Mendukung penyimpanan hasil pemindaian dalam format JSON, termasuk informasi fingerprint.
- **Pemindaian Multithread** — Memungkinkan beberapa target dipindai secara bersamaan untuk meningkatkan efisiensi.
- **Keamanan sebagai Pengaturan Bawaan** — Verifikasi TLS diaktifkan secara bawaan. Pemindaian React menggunakan pemeriksaan *side-channel* yang aman, kecuali jika opsi `--rce` diaktifkan.
- **Penggunaan Khusus Laboratorium** — Verifikasi TLS dapat dinonaktifkan menggunakan opsi `-k` apabila diperlukan untuk pengujian di lingkungan laboratorium yang terkendali.

## Persyaratan

- Python 3.9 atau lebih baru (Python 3.11+ untuk proxy HTTPS ke target HTTPS)
- Windows / Linux / macOS

Instal dependensi:

```bash
pip install -r requirements.txt
```

## Cara Penggunaan

### 1) Lihat panduan

```powershell
python scanner.py
# atau
python scanner.py -h
```

### 2) Scan satu target

```powershell
# Scan keduanya (PHP + React) - default
python scanner.py -u https://example.com

# Hanya scan PHP
python scanner.py -u https://example.com --mode php

# Hanya scan React (safe side-channel, default)
python scanner.py -u https://example.com --mode react

# React dengan RCE PoC (hanya untuk target berizin)
python scanner.py -u https://example.com --mode react --rce
```

### 3) Pemindaian Banyak Target dari Berkas

Buat file `hosts.txt` berisi satu URL per baris:

```text
https://example1.com
https://example2.com
http://192.168.1.100
```

Lalu jalankan:

```powershell
python scanner.py -l hosts.txt --mode all -t 15 -o hasil.json
```

### 4) Pilihan yang Berguna

```powershell
# Tampilkan alasan dan cuplikan respons
python scanner.py -u https://example.com -v

# Hanya tampilkan target yang RENTAN
python scanner.py -l hosts.txt -q

# Tambahkan header kustom (bisa berulang)
python scanner.py -u https://example.com -H "Authorization: Bearer token123"

# Uji path khusus
python scanner.py -u https://example.com --path /api --path /_next

# Nonaktifkan verifikasi TLS (khusus lab/internal)
python scanner.py -u https://example.com -k

# Batasi laju permintaan dan atur retry
python scanner.py -l hosts.txt --rate-limit 5 --retries 3 --retry-backoff 1

# Jalankan semua permintaan lewat proxy HTTP/HTTPS
python scanner.py -u https://example.com --proxy http://127.0.0.1:8080

# Proxy dengan autentikasi Basic
python scanner.py -u https://example.com --proxy http://user:pass@127.0.0.1:8080

# Lewati baseline/fingerprint WAF
python scanner.py -u https://example.com --no-baseline

# Simpan SEMUA hasil (termasuk yang tidak rentan/galat)
python scanner.py -l hosts.txt --all-results -o hasil-lengkap.json
```

## Opsi Khusus

### Khusus PHP (`--mode php`)

| Opsi | Keterangan |
|---|---|
| `--sapi {auto,mod_php,fpm}` | Menentukan aturan interpretasi sinyal crash. `auto` akan mendeteksi otomatis. |
| `--path`, `--path-file` | Bisa mengarahkan ke file PHP lain (mis. `/phpinfo.php`, `/index.php`) |

### Khusus React/Next.js (`--mode react`)

| Opsi | Keterangan |
|---|---|
| `--safe-check` | Deteksi side-channel yang lebih aman (default, tanpa RCE PoC). |
| `--rce` | Mengaktifkan RCE PoC check. Lebih intrusif; hanya untuk target berizin. |
| `--windows` | Menggunakan payload PowerShell untuk lingkungan Windows (memerlukan `--rce`). |
| `--waf-bypass` | Menambahkan data junk untuk mengelabui inspeksi body WAF (memerlukan `--rce`, default 128KB). |
| `--waf-bypass-size KB` | Mengatur ukuran junk data (mis. `256`). |
| `--vercel-waf-bypass` | Menggunakan varian payload khusus untuk bypass WAF Vercel (RCE PoC; memerlukan `--rce`). |

### Opsi Jaringan

| Opsi | Keterangan |
|---|---|
| `--rate-limit N` | Maksimal `N` permintaan/detik secara global (default `0` = tanpa batas). |
| `--retries N` | Jumlah percobaan ulang untuk timeout, koneksi gagal, `429/502/503/504` (default `2`, maksimal `10`). Probe PHP yang sudah dikirim tidak diulang. |
| `--retry-backoff DETIK` | Jeda dasar backoff eksponensial dengan jitter (default `0.5`, maksimal `60`). |
| `--proxy URL` | Proxy HTTP/HTTPS untuk semua permintaan, mis. `http://127.0.0.1:8080`. Bisa memakai kredensial `http://user:pass@host:port`. Tanpa opsi ini berjalan langsung tanpa proxy. |
| `--no-baseline` | Lewati permintaan baseline/fingerprint WAF. |

Proxy SOCKS belum didukung. Proxy HTTPS ke target HTTPS memakai `CONNECT`; jika proxy memakai TLS sendiri, gunakan URL `https://`. Kredensial di URL akan di-encode otomatis oleh scanner. Kombinasi proxy HTTPS + target HTTPS memerlukan Python 3.11 atau lebih baru.

Header `Proxy-Authorization` yang diberikan lewat `-H` akan diabaikan agar tidak bocor ke target. Gunakan kredensial pada URL `--proxy`.

## Batasan dan Catatan

- Probe PHP dapat memicu kehabisan memori pada PHP yang sudah dipatch jika `memory_limit` rendah. Hasil `[RENTAN]` sebaiknya dikonfirmasi dengan versi PHP dan konfigurasi server; ini batasan deteksi aktif dari upstream.
- PHP tidak mengikuti redirect. React mengikuti redirect hanya ke host yang sama dan tidak menurunkan HTTPS ke HTTP.
- Query string dan fragment pada `-u` tidak dipertahankan oleh scanner saat ini. Jika endpoint membutuhkan query, gunakan alat/proxy tambahan atau sesuaikan path secara manual.
- Baseline hanya memakai `GET`; target yang mewajibkan autentikasi atau hanya merespons `POST` bisa tidak terdeteksi sebagai WAF/CDN pada baseline.

## Penjelasan Status Hasil

| Status | Arti | Keterangan |
|---|---|---|
| `[RENTAN]` | Rentan terdeteksi | Terdapat indikator kerentanan untuk salah satu atau kedua CVE. |
| `[TIDAK RENTAN]` | Tidak rentan | Tidak ditemukan indikator kerentanan pada pengujian yang dilakukan. |
| `[TIDAK KONKLUSIF]` | Tidak bisa disimpulkan | Bisa karena diblokir WAF/CDN, redirect tidak terduga, atau respons tidak jelas. Jika baseline terdeteksi diblokir WAF/challenge, hasil "tidak rentan" otomatis diubah menjadi status ini. |
| `[GALAT]` | Kesalahan koneksi/permintaan | Timeout, koneksi gagal, SSL error, dll. Perlu dicek koneksi atau sertifikat. |

## Struktur Hasil JSON

Jika menggunakan `-o`, hasil akan disimpan dalam format seperti ini:

```json
{
  "scan_time": "2026-10-23T...",
  "mode": "all",
  "total_results": 1,
  "saved_results": 1,
  "summary": {
    "total_scanned": 1,
    "vulnerable": 1,
    "not_vulnerable": 0,
    "inconclusive": 0,
    "errors": 0
  },
  "results": [
    {
      "host": "https://example.com",
      "vulnerable": true,
      "verdict": "VULNERABLE",
      "status_code": 500,
      "error": null,
      "reason": null,
      "fingerprint": {
        "status_code": 200,
        "server": "nginx",
        "tech": ["Next.js"],
        "waf": ["Cloudflare"],
        "challenge": false,
        "blocked": false,
        "reason": "WAF/CDN terdeteksi: Cloudflare"
      },
      "findings": [
        {
          "engine": "php",
          "cve": "CVE-2026-109618 / CVE-2026-109619",
          "vulnerable": false,
          "verdict": "NO SIGNAL"
        },
        {
          "engine": "react",
          "cve": "CVE-2025-55182 / CVE-2025-66478",
          "vulnerable": true,
          "verdict": "VULNERABLE",
          "reason": "indikator kerentanan ditemukan pada respons"
        }
      ],
      "timestamp": "2026-10-23T..."
    }
  ]
}
```

## Tips Penggunaan

- **Scan massal** - Gunakan `-t` secukupnya (10-20) dan pertimbangkan `--rate-limit` agar tidak terlalu agresif.
- **Target spesifik** - Jika tahu aplikasinya berbasis Next.js, coba `--mode react` terlebih dahulu. Jika PHP tradisional, coba `--mode php`.
- **WAF aktif** - Perhatikan baris fingerprint/baseline. Jika diblokir, hasil bisa menjadi `TIDAK KONKLUSIF`; eskalasi ke `--rce` (React) hanya bila Anda berwenang.
- **Debugging trafik** - Arahkan `--proxy` ke Burp/ZAP (mis. `http://127.0.0.1:8080`) untuk memeriksa request/response. Pastikan Anda berwenang atas target dan proxy tersebut.
- **Periksa bukti** - Gunakan `-v` untuk melihat alasan verdict dan cuplikan respons saat menganalisis hasil yang mencurigakan. Request yang direkam (dengan body besar dipotong) dan data fingerprint juga tersimpan di JSON.
- **Validasi lokal** - Sangat disarankan untuk menguji di lingkungan lab/localhost terlebih dahulu sebelum scan ke target lain.

## Peringatan Etis & Hukum

**PENTING:** Hanya jalankan scanner ini terhadap sistem yang **benar-benar milik Anda** atau yang telah mendapatkan **izin tertulis eksplisit** untuk diuji.

Penggunaan tanpa izin dapat melanggar hukum yang berlaku di yurisdiksi Anda. Pengembang tidak bertanggung jawab atas penyalahgunaan tools ini.
