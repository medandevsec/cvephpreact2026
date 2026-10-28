# Scanner CVE PHP, React, Node.js & NGINX

![Hasil Scan](CVEPHPREACTNODEJSNGINX.png)

- **CVE-2026-109618 / CVE-2026-109619** (PHP multipart parsing)
- **CVE-2025-55182 / CVE-2025-66478** (React Server Components / Next.js RCE)
- **CVE-2026-42211** (React Router Framework Mode, deteksi pasif)
- **CVE-2026-111497** (Node.js Brotli decoder, deteksi pasif + PoC opsional)
- **CVE-2026-42945** (NGINX `rewrite_module`, deteksi versi pasif + probe opsional)

## Mulai Cepat

```powershell
# 1. Instal dependensi
pip install -r requirements.txt

# 2. Scan satu target (PHP + React + React Router + Node.js + NGINX)
python scanner.py -u https://example.com

# 3. Pemindaian Banyak Target dari Berkas
python scanner.py -l hosts.txt --mode all -o result.json

# 4. Lihat semua opsi
python scanner.py -h
```

Jika dijalankan tanpa argumen, scanner akan menampilkan panduan pemakaian singkat.

## Fitur

- **Satu Perintah** — Memungkinkan pemindaian beberapa jenis kerentanan sekaligus menggunakan opsi `--mode all` (mode bawaan).
- **Fleksibel** — Mendukung pemindaian satu URL atau beberapa URL yang tercantum dalam berkas `.txt`.
- **Mode Pemindaian Khusus** — Memungkinkan pemindaian khusus untuk PHP, React/Next.js, React Router, Node.js, atau NGINX.
- **Deteksi Cerdas** — Mendukung identifikasi lingkungan `mod_php`, PHP-FPM, CodeIgniter (cookie `ci_session`/`csrf_cookie_name`), Next.js App Router dan Pages Router, React Router Framework Mode, serta indikasi NGINX/OpenResty dan versi NGINX OSS.
- **Deteksi React Router (Pasif)** — Mendeteksi Framework Mode dan versi React Router untuk CVE-2026-42211, tanpa mengirim payload eksploitasi. Hasil maksimal `TIDAK KONKLUSIF` karena eksploitasi memerlukan prototype pollution di aplikasi target.
- **Deteksi Node.js (Pasif + PoC)** — Deteksi pasif indikator Node.js, serta PoC decoder Brotli opsional (`--nodejs-poc`) untuk CVE-2026-111497. PoC mengirim body Brotli valid sebagai kontrol negatif, lalu vektor malformed, dan membedakan `FORMAT_BLOCK_LENGTH_1` (rentan) dari `FORMAT_BLOCK_SWITCH` (sudah dipatch); hanya untuk target berizin.
- **Deteksi NGINX (Pasif + Probe)** — Membaca versi `nginx` dari header/body untuk CVE-2026-42945. Probe opsional (`--nginx-poc`) mengirim kontrol negatif URI panjang lalu satu path overflow untuk mendeteksi crash/restart worker; reset pada kontrol negatif membatalkan probe. Tidak mengirim payload RCE dan hanya untuk target berizin.
- **Deteksi CMS** — Mencocokkan signature pasif pada cookie, header, dan body untuk 42 CMS, termasuk WordPress, Drupal, Joomla, Magento, Shopify, serta CMS lokal seperti Lokomedia, AuraCMS, PopojiCMS, FiyoCMS, CMSID, OpenSID, dan CiFireCMS. CMS berbasis PHP otomatis menandai `PHP`.
- **Baseline dan Fingerprinting** — Melakukan permintaan awal untuk mengidentifikasi WAF/CDN, mekanisme challenge, dan teknologi yang terlihat (`PHP`, `CodeIgniter`, `React`, `Node.js`, `NGINX`, `Next.js`, `React Router`, CMS) beserta tingkat keyakinan dan buktinya. Ringkasan teknologi selalu ditampilkan; bukti rinci muncul dengan `-v`.
- **Pembatasan Laju dan Percobaan Ulang** — Mengatur frekuensi permintaan serta mengulangi permintaan yang mengalami kesalahan sementara dengan jeda bertahap (*backoff*).
- **Dukungan Proxy Opsional** — Memungkinkan seluruh mesin pemindai menggunakan proxy HTTP/HTTPS atau terhubung langsung tanpa proxy.
- **Opsi Bypass WAF** — Menyediakan opsi `--waf-bypass` dan `--vercel-waf-bypass` untuk pemindaian React. Penggunaannya memerlukan opsi `--rce`.
- **Keluaran Terstruktur** — Mendukung penyimpanan hasil pemindaian dalam format JSON, termasuk informasi fingerprint.
- **Pemindaian Multithread** — Memungkinkan beberapa target dipindai secara bersamaan untuk meningkatkan efisiensi.
- **Keamanan sebagai Pengaturan Bawaan** — Verifikasi TLS diaktifkan secara bawaan. Pemindaian React menggunakan pemeriksaan *side-channel* yang aman, kecuali jika opsi `--rce` diaktifkan.
- **Penggunaan Khusus Laboratorium** — Verifikasi TLS dapat dinonaktifkan menggunakan opsi `-k` apabila diperlukan untuk pengujian di lingkungan laboratorium yang terkendali.
- **CA Bundle Kustom** - Opsi `--ca-bundle FILE` menambahkan CA/intermediate PEM ke trust store bawaan tanpa mematikan verifikasi TLS. Berguna untuk server dengan rantai sertifikat tidak lengkap atau CA internal.
- **Trust Store Sistem** - Opsi `--system-ca` memakai trust store CA sistem operasi, sehingga hasilnya bisa sama dengan browser/curl ketika certifi tidak memiliki intermediate yang dipakai server.

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
# Scan semuanya (PHP + React + React Router + Node.js + NGINX) - default
python scanner.py -u https://example.com

# Hanya scan PHP
python scanner.py -u https://example.com --mode php

# Hanya scan React/Next.js (safe side-channel, default)
python scanner.py -u https://example.com --mode react

# React/Next.js dengan RCE PoC (hanya untuk target berizin)
python scanner.py -u https://example.com --mode react --rce

# Hanya deteksi pasif React Router (CVE-2026-42211)
python scanner.py -u https://example.com --mode react-router

# Hanya deteksi pasif Node.js (CVE-2026-111497)
python scanner.py -u https://example.com --mode nodejs

# Node.js dengan PoC decoder Brotli (hanya untuk target berizin)
python scanner.py -u https://example.com --mode nodejs --nodejs-poc

# Hanya deteksi versi NGINX (CVE-2026-42945)
python scanner.py -u https://example.com --mode nginx

# NGINX dengan probe overflow (hanya untuk target berizin)
python scanner.py -u https://example.com --mode nginx --nginx-poc --path /api
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
python scanner.py -l hosts.txt --mode all -t 15 -o result.json
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

# PoC decoder Brotli Node.js pada endpoint yang mendekode body (target berizin)
python scanner.py -u https://example.com/api/ingest --mode nodejs --nodejs-poc

# Probe overflow NGINX pada path rewrite (target berizin)
python scanner.py -u https://example.com --mode nginx --nginx-poc --path /api

# Tambahkan intermediate/CA khusus tanpa mematikan verifikasi TLS
python scanner.py -u https://example.com --ca-bundle intermediate.pem

# Gunakan trust store CA sistem (mis. Windows) tanpa mematikan verifikasi TLS
python scanner.py -u https://example.com --system-ca

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
python scanner.py -l hosts.txt --all-results -o all-results.json
```

## Opsi Khusus

### Deteksi Teknologi

Fingerprint baseline menampilkan ringkasan seperti:

```text
-> Teknologi: PHP=tidak terlihat; React=terdeteksi; Node.js=terindikasi; NGINX=tidak terlihat; Next.js=terdeteksi
```

Status `terdeteksi` berarti ada bukti langsung dari header, cookie, atau body. `terindikasi` berarti disimpulkan dari teknologi lain, misalnya Node.js dari Next.js atau PHP dari CodeIgniter. Cookie CodeIgniter seperti `ci_session` dan `csrf_cookie_name` juga dihitung sebagai sinyal PHP. `tidak terlihat` **bukan** berarti teknologi tersebut tidak digunakan: header `Server` dapat disembunyikan, dan WAF/CDN dapat menutupi backend. Jika baseline diblokir, ringkasan menambahkan `baseline diblokir; hasil tidak lengkap`. Gunakan `-v` untuk melihat bukti dan tingkat keyakinan setiap teknologi.

### Deteksi CMS

Scanner memakai catalog `CMS_SIGNATURES` berisi 42 signature pasif. Setiap signature dapat memakai nama cookie, header, dan marker body; CMS berbasis PHP juga menambahkan sinyal `PHP`. Contoh:

```text
-> Teknologi: PHP=terdeteksi; WordPress=terdeteksi; NGINX=terdeteksi
```

CMS yang didukung: WordPress, Drupal, Joomla, Magento, Shopify, Wix, Squarespace, Ghost, TYPO3, Craft CMS, Umbraco, PrestaShop, OpenCart, Moodle, MediaWiki, Discourse, phpBB, vBulletin, XenForo, Blogger, HubSpot CMS, Webflow, Grav, October CMS, Bitrix, Tilda, Weebly, Jimdo, Duda, Google Sites, Lokomedia, AuraCMS, PopojiCMS, FiyoCMS, CMSID, Balitbang, OpenSID, CiFireCMS, Swarakalibata, SukaCMS, GeniXCMS, dan Semar CMS.

“CMS Lokal” bukan satu produk tunggal, sehingga dideteksi melalui signature masing-masing produk. Deteksi tetap bersifat *signature-based*: CMS kustom, halaman yang di-cache/CDN, atau situs yang menyembunyikan semua marker dapat tidak terdeteksi. Gunakan `-v` untuk melihat nama CMS, confidence, sumber sinyal, dan bukti yang cocok.

### Khusus PHP (`--mode php`)

| Opsi | Keterangan |
|---|---|
| `--sapi {auto,mod_php,fpm}` | Menentukan aturan interpretasi sinyal crash. `auto` akan mendeteksi otomatis. |
| `--path`, `--path-file` | Bisa mengarahkan ke file PHP lain (mis. `/phpinfo.php`, `/index.php`) |

Pada `--mode all`, jika baseline mendeteksi Next.js tanpa indikator PHP, scanner melewati engine PHP dan mencatat temuan `NOT APPLICABLE` (`skipped: true`) agar probe multipart tidak dikirim ke aplikasi non-PHP. Gate ini tidak aktif untuk `--mode php`, path yang berakhiran `.php`, target dengan indikator PHP (`X-Powered-By: PHP`, `PHPSESSID`, `ci_session`, `csrf_cookie_name`), baseline yang diblokir, atau `--no-baseline`.

Scanner selalu mengirim kontrol multipart minimal lebih dulu. Kontrol harus menghasilkan HTTP 2xx; jika `X-Powered-By` menunjukkan versi PHP yang sudah dipatch, pemindaian probe dihentikan dan hasilnya `[TIDAK RENTAN]` tanpa mengirim body besar. Jika versi belum dipatch atau tidak diketahui, scanner mengirim probe 1/8/20 MiB.

`[RENTAN]` untuk PHP hanya dilaporkan jika ada bukti kuat:

- fatal error in-band `Allowed memory size ... exhausted ... in Unknown`;
- probe menghasilkan HTTP 500 body kosong, koneksi reset, atau HTTP 502/503/504, **dan** kontrol valid multipart dengan ukuran sama berhasil (HTTP 2xx);
- probe HTTP 200 body kosong, **dan** kontrol valid multipart ukuran sama menghasilkan respons normal dengan body;
- `X-Powered-By` menunjukkan versi PHP yang belum dipatch (fallback versi).

HTTP 500 body kosong tanpa kontrol pembanding yang berhasil **tidak lagi** dianggap `[RENTAN]`; hasilnya `[TIDAK KONKLUSIF]` karena bisa berasal dari error aplikasi, WAF, atau batas ukuran request. Timeout dan kegagalan kontrol pembanding juga menghasilkan `[TIDAK KONKLUSIF]`. Kontrol pembanding hanya dikirim setelah respons mencurigakan, sehingga target normal tidak menerima body besar tambahan.

### Khusus React/Next.js (`--mode react`)

| Opsi | Keterangan |
|---|---|
| `--safe-check` | Deteksi side-channel yang lebih aman (default, tanpa RCE PoC). |
| `--rce` | Mengaktifkan RCE PoC check. Lebih intrusif; hanya untuk target berizin. |
| `--windows` | Menggunakan payload PowerShell untuk lingkungan Windows (memerlukan `--rce`). |
| `--waf-bypass` | Menambahkan data junk untuk mengelabui inspeksi body WAF (memerlukan `--rce`, default 128KB). |
| `--waf-bypass-size KB` | Mengatur ukuran junk data (mis. `256`). |
| `--vercel-waf-bypass` | Menggunakan varian payload khusus untuk bypass WAF Vercel (RCE PoC; memerlukan `--rce`). |

### Khusus React Router (`--mode react-router`)

| Opsi | Keterangan |
|---|---|
| `--path`, `--path-file` | Path yang diperiksa untuk halaman Framework Mode (default `/`). |
| `--timeout` | Timeout permintaan React Router (default `10` detik). |

Deteksi bersifat pasif: scanner mengambil halaman, mencari marker Framework Mode (`__reactRouterContext`, `__reactRouterManifest`, `__reactRouterRouteModules`), lalu mencoba membaca versi dari halaman, header, atau `/__manifest`. Tidak ada payload eksploitasi yang dikirim. CVE-2026-42211 hanya dapat dieksploitasi jika aplikasi sudah memiliki prototype pollution, sehingga hasil `[RENTAN]` tidak pernah dilaporkan untuk CVE ini.

### Khusus Node.js (`--mode nodejs`)

| Opsi | Keterangan |
|---|---|
| `--nodejs-poc` | Mengaktifkan PoC decoder Brotli CVE-2026-111497. Mengirim vektor `oob-base` dan `oob-extended` sebagai body `Content-Encoding: br`. Hanya untuk target yang berizin. |
| `--path`, `--path-file` | Endpoint yang diuji (default mengikuti path URL; gunakan endpoint yang mendekode body, mis. `/api/ingest`). |
| `--timeout` | Timeout permintaan Node.js (default `10` detik). |

Tanpa `--nodejs-poc`, scanner hanya mencari indikator Node.js (`x-powered-by`, `Server`, body, atau marker Next.js seperti `/_next/static/`, `__NEXT_DATA__`, `self.__next_f`) dan tidak mengirim payload. Dengan `--nodejs-poc`, scanner mengirim body Brotli valid (`{"ok":true}`) sebagai kontrol negatif, lalu vektor Brotli malformed dan membaca sinyal error decoder:

- Kontrol negatif normal → scanner mengirim vektor `oob-base` dan `oob-extended`.
- Kontrol error, diblokir, menghasilkan `5xx`, atau memuat marker decoder → PoC tidak dikirim, hasil `[TIDAK KONKLUSIF]`.
- `FORMAT_BLOCK_LENGTH_1` / `ERROR_FORMAT_BLOCK_LENGTH_1` pada vektor → decoder melanjutkan state tidak valid, hasil `[RENTAN]`.
- `FORMAT_BLOCK_SWITCH` / `ERROR_FORMAT_BLOCK_SWITCH` pada semua vektor → decoder menolak input, hasil `[TIDAK RENTAN]`.
- Error disembunyikan, endpoint tidak mendekode Brotli, atau timeout → `[TIDAK KONKLUSIF]`.

PoC ini adalah *decoder trigger*, bukan remote RCE. Publikasi PoC menunjukkan DoS dapat terjadi dan remote blind RCE tidak reliabel karena ASLR/layout. Jangan mengaktifkan `--nodejs-poc` terhadap sistem produksi tanpa izin; payload dapat menyebabkan decoder hang.

### Khusus NGINX (`--mode nginx`)

| Opsi | Keterangan |
|---|---|
| `--nginx-poc` | Mengaktifkan probe overflow CVE-2026-42945. Mengirim kontrol negatif URI panjang lalu satu path yang memicu `rewrite ... ?...` dan `set` capture pada path yang diuji. Probe overflow dapat memicu crash/restart worker; hanya untuk target berizin. |
| `--path`, `--path-file` | Path yang diuji (default `/`). Probe hanya dikirim ke satu path: path kustom/deteksi, atau `/api` jika URL target hanya root dan `--path` tidak diberikan (lokasi rewrite yang umum). |
| `--timeout` | Timeout permintaan NGINX (default `10` detik). |

Tanpa `--nginx-poc`, scanner hanya membaca versi NGINX dari header `Server` atau body dan membandingkannya dengan rentang terdampak:

- NGINX OSS `0.6.27` sampai `1.30.0` → `[TIDAK KONKLUSIF]` (versi terdampak, probe belum dijalankan).
- NGINX OSS `1.30.1` / `1.31.0+` → `[TIDAK RENTAN]`.
- NGINX OSS lebih lama dari `0.6.27` → `[TIDAK RENTAN]` (di luar rentang terdampak).
- NGINX/OpenResty tanpa versi yang jelas → `[TIDAK KONKLUSIF]`.
- Tidak ada indikator NGINX → `[TIDAK RENTAN]`.

Dengan `--nginx-poc`, probe hanya dijalankan jika target terindikasi NGINX, versi tidak diketahui atau berada di rentang terdampak, dan baseline tidak diblokir. Sebelum probe overflow, scanner mengirim **kontrol negatif**: URI sepanjang payload tetapi tanpa pola overflow. Jika kontrol negatif gagal/reset, ditolak (`400/403/413/414/429`), atau menghasilkan `5xx`, probe overflow tidak dikirim dan hasilnya `[TIDAK KONKLUSIF]`. Jika kontrol negatif normal, scanner mengirim satu probe overflow lalu melakukan request liveness:

- Kontrol negatif normal, probe menghasilkan error koneksi/reset, **dan** server kembali merespons → `[RENTAN]`.
- Probe mendapat respons normal, server tidak pulih, atau kontrol negatif gagal → `[TIDAK KONKLUSIF]`.
- Versi sudah dipatch, bukan NGINX, atau baseline diblokir → probe dilewati dan hasil pasif digunakan.

CVE-2026-42945 adalah heap buffer overflow pada `ngx_http_rewrite_module` yang diperkenalkan sekitar tahun 2008. Bug terjadi karena ketidaksesuaian panjang string pada dua tahap pemrosesan `rewrite` ketika `is_args` dan `ngx_escape_uri(NGX_ESCAPE_ARGS)` digunakan; publikasi riset menunjukkan overwrite struktur cleanup dapat berujung RCE. Scanner ini **tidak** mengirim heap spray atau payload RCE. Probe hanya mendeteksi crash/restart worker, sehingga `[RENTAN]` berarti target merespons seperti rentan, bukan bukti eksekusi kode.

### Opsi Jaringan

| Opsi | Keterangan |
|---|---|
| `--rate-limit N` | Maksimal `N` permintaan/detik secara global (default `0` = tanpa batas). |
| `--retries N` | Jumlah percobaan ulang untuk timeout, koneksi gagal, `429/502/503/504` (default `2`, maksimal `10`). Probe PHP yang sudah dikirim tidak diulang. |
| `--retry-backoff DETIK` | Jeda dasar backoff eksponensial dengan jitter (default `0.5`, maksimal `60`). |
| `--proxy URL` | Proxy HTTP/HTTPS untuk semua permintaan, mis. `http://127.0.0.1:8080`. Bisa memakai kredensial `http://user:pass@host:port`. Tanpa opsi ini berjalan langsung tanpa proxy. |
| `--ca-bundle FILE` | Tambahkan sertifikat CA/intermediate PEM ke trust store bawaan. Isi berkas digabung dengan CA bawaan, jadi cukup berisi intermediate yang belum dikirim server. Saling eksklusif dengan `--system-ca` dan `-k`. |
| `--system-ca` | Gunakan trust store CA sistem operasi. Berguna jika browser/curl berhasil tetapi scanner gagal karena certifi tidak memiliki intermediate. Saling eksklusif dengan `--ca-bundle` dan `-k`. |
| `--no-baseline` | Lewati permintaan baseline/fingerprint WAF. |

Proxy SOCKS belum didukung. Proxy HTTPS ke target HTTPS memakai `CONNECT`; jika proxy memakai TLS sendiri, gunakan URL `https://`. Kredensial di URL akan di-encode otomatis oleh scanner. Kombinasi proxy HTTPS + target HTTPS memerlukan Python 3.11 atau lebih baru.

Header `Proxy-Authorization` yang diberikan lewat `-H` akan diabaikan agar tidak bocor ke target. Gunakan kredensial pada URL `--proxy`.

### TLS dan Sertifikat

Scanner memakai CA bawaan `requests`/`certifi` dan memverifikasi TLS secara default. Browser atau `curl` di Windows dapat berhasil karena memakai Windows trust store, sedangkan scanner gagal jika server tidak mengirim intermediate certificate yang diperlukan.

Jika muncul error `verifikasi TLS gagal; rantai sertifikat/CA target tidak dapat diverifikasi`, ada dua opsi aman:

```powershell
# Tambahkan intermediate/CA tertentu (digabung dengan CA bawaan)
python scanner.py -u https://example.com --ca-bundle intermediate.pem

# Gunakan trust store CA sistem operasi (mis. Windows)
python scanner.py -u https://example.com --system-ca
```

Berkas `--ca-bundle` digabung dengan CA bawaan, sehingga cukup berisi intermediate yang hilang. Jika Anda mengelola server, perbaikan utamanya adalah memasang rantai sertifikat lengkap (leaf + intermediate) di web server. Opsi `-k` hanya untuk lab/internal karena mematikan verifikasi TLS dan membuat scanner rentan terhadap MITM.

## Batasan dan Catatan

- Probe PHP dapat memicu kehabisan memori pada PHP yang sudah dipatch jika `memory_limit` rendah. Fatal error in-band tetap dilaporkan `[RENTAN]`; jika kontrol valid multipart juga gagal, hasilnya `[TIDAK KONKLUSIF]`. Konfirmasi dengan versi PHP, log server, dan konfigurasi `memory_limit`.
- Saat respons PHP mencurigakan, scanner mengirim satu kontrol valid multipart tambahan dengan ukuran sama (1/8/20 MiB). Ini menambah trafik hanya pada jalur yang dicurigai, tetapi dapat membebani server dengan batas memori rendah.
- PHP tidak mengikuti redirect. React dan React Router mengikuti redirect hanya ke host yang sama dan tidak menurunkan HTTPS ke HTTP.
- Query string dan fragment pada `-u` tidak dipertahankan oleh scanner saat ini. Jika endpoint membutuhkan query, gunakan alat/proxy tambahan atau sesuaikan path secara manual.
- Baseline hanya memakai `GET`; target yang mewajibkan autentikasi atau hanya merespons `POST` bisa tidak terdeteksi sebagai WAF/CDN pada baseline.
- Deteksi teknologi bersifat pasif. `tidak terlihat` bukan bukti bahwa PHP/NGINX/Node.js tidak digunakan; konfigurasi `server_tokens off`, reverse proxy, CDN/WAF, atau halaman challenge dapat menyembunyikan backend.
- `status_code` pada level host diambil dari baseline/fingerprint jika tersedia, bukan dari respons probe. Jika baseline gagal (mis. TLS), status host tidak diisi dari finding agar tidak menyesatkan; status per engine tetap tersimpan di masing-masing finding. Probe PHP yang menerima HTTP 500 juga tidak lagi menampilkan 500 pada baris host ketika halaman baseline merespons 200.
- Temuan PHP yang dilewati karena gate Next.js memakai `verdict: NOT APPLICABLE`, `vulnerable: false`, `skipped: true`, dan `skip_reason`. Label terminalnya tetap `[TIDAK RENTAN]` karena engine tidak relevan, bukan karena probe membuktikan target aman.
- Deteksi CVE-2026-42211 bersifat pasif dan bergantung pada marker Framework Mode. Aplikasi yang memakai Declarative/Data Mode, membungkus HTML secara agresif, atau menyembunyikan versi dapat dilaporkan `TIDAK RENTAN`/`TIDAK KONKLUSIF` secara keliru. Konfirmasi versi `react-router` melalui `package.json` atau artefak build.
- CVE-2026-42211 memerlukan prototype pollution yang sudah ada di kode aplikasi. Deteksi versi rentan **bukan** bukti bahwa target dapat dieksploitasi.
- Versi React Router sering tidak tersedia di HTML produksi. Jika versi tidak diketahui, hasilnya `TIDAK KONKLUSIF`, bukan `RENTAN`.
- PoC Node.js (`--nodejs-poc`) hanya efektif jika endpoint benar-benar mendekode body dengan `Content-Encoding: br` (mis. `body-parser`/Express 5) dan mengekspos nama error decoder. Banyak aplikasi menyembunyikan detail error sehingga hasilnya `TIDAK KONKLUSIF`.
- Kontrol negatif Node.js memakai body Brotli valid tanpa marker. Jika kontrol error, diblokir (`401/403/406/407/429`), menghasilkan `5xx`, atau memuat marker decoder, vektor PoC tidak dikirim. HTTP `400/415/422` tanpa marker masih dianggap kontrol lolos karena dapat berupa penolakan di level aplikasi; ini tidak membuktikan body benar-benar didekode.
- Deteksi pasif Node.js bergantung pada marker (`x-powered-by`, `Server`, body, atau Next.js). Aplikasi Node.js yang menyembunyikan semua marker dapat dilaporkan `TIDAK RENTAN` secara keliru; gunakan `--nodejs-poc` pada endpoint yang relevan untuk verifikasi tambahan.
- `--nodejs-poc` mengirim stream Brotli malformed yang dapat memicu decoder hang/DoS pada versi rentan. Gunakan hanya terhadap target yang Anda miliki/berwenang, dan hindari sistem produksi.
- Remote blind RCE CVE-2026-111497 tidak diimplementasikan. Publikasi PoC menunjukkan RCE lokal memerlukan layout deterministik; remote blind RCE tidak reliabel karena ASLR dan tidak adanya address leak.
- Deteksi NGINX bergantung pada header `Server` atau body yang menampilkan versi. Konfigurasi `server_tokens off`, reverse proxy/CDN di depan NGINX, atau OpenResty tanpa versi dapat membuat hasil `[TIDAK KONKLUSIF]`.
- NGINX Plus menampilkan versi basis OSS pada header `Server`, bukan patch level R32/R35/R36. Scanner tidak dapat memastikan patch Plus dari header; gunakan `nginx -V` atau dashboard Plus dan perlakukan hasil sebagai `[TIDAK KONKLUSIF]` bila relevan.
- Di belakang load balancer/CDN, probe dan liveness dapat mengenai instance berbeda. Reset koneksi pada probe yang diikuti liveness sukses tidak selalu membuktikan worker NGINX yang sama crash; konfirmasi dengan log server.
- Reset koneksi dari WAF/proxy pada URI panjang dapat menyerupai crash worker. Scanner mengirim kontrol negatif URI panjang; jika kontrol juga reset/ditolak, probe overflow tidak dikirim. WAF yang hanya memblokir pola `+` tetap perlu verifikasi manual dan pencocokan log NGINX.
- `--nginx-poc` bersifat intrusif dan dapat memicu crash/restart worker NGINX, terutama pada versi terdampak. Probe tidak membuktikan RCE dan tidak boleh dijalankan terhadap produksi tanpa izin dan jendela pengujian yang disetujui.
- Probe NGINX hanya dikirim ke satu path (path kustom atau `/api` untuk target root). Path yang tidak cocok dengan konfigurasi `rewrite` dapat menghasilkan `[TIDAK KONKLUSIF]`; verifikasi manual diperlukan.

## Penjelasan Status Hasil

| Status | Arti | Keterangan |
|---|---|---|
| `[RENTAN]` | Rentan terdeteksi | Terdapat indikator kuat kerentanan untuk salah satu CVE yang didukung. Hanya muncul jika ada sinyal crash/indikator eksploitasi yang jelas. **CVE-2026-42211** tidak pernah menghasilkan status ini karena deteksi pasif. **CVE-2026-111497** hanya dapat menghasilkan status ini jika `--nodejs-poc` aktif, kontrol negatif valid normal, dan respons vektor mengekspos `FORMAT_BLOCK_LENGTH_1`. **CVE-2026-42945** hanya dapat menghasilkan status ini jika `--nginx-poc` aktif, kontrol negatif normal, dan probe menghasilkan crash/reset yang diikuti pemulihan server. **PHP** hanya dapat menghasilkan status ini jika ditemukan fatal memory error in-band, kontrol valid multipart ukuran sama berhasil setelah respons crash (500 body kosong/reset/502-504), respons 200 body kosong dengan kontrol valid berbody, atau `X-Powered-By` menunjukkan versi yang belum dipatch. |
| `[TIDAK RENTAN]` | Tidak rentan | Tidak ditemukan indikator kerentanan berdasarkan pengujian. Pada engine pasif (React Router, Node.js, NGINX), status ini berarti tidak ada marker/indikasi yang relevan terdeteksi, versi NGINX sudah dipatch, atau versi berada di luar rentang terdampak. Dengan `--nodejs-poc`, status ini berarti kontrol negatif normal dan decoder menolak semua vektor dengan `FORMAT_BLOCK_SWITCH`. Untuk PHP, status ini juga muncul jika `X-Powered-By` menunjukkan versi yang sudah dipatch. |
| `[TIDAK KONKLUSIF]` | Tidak bisa disimpulkan | Cukup indikasi untuk dicurigai, namun **tidak cukup bukti** untuk menyimpulkan rentan atau tidak. Penyebab umum: diblokir WAF/CDN (mis. Cloudflare), probe ditolak (`400/403/413/429`), redirect tidak terduga, respons kosong/tidak jelas, baseline terdeteksi *challenge*, atau untuk deteksi pasif versi tidak terungkap (contoh React Router tanpa versi, Node.js terindikasi tanpa versi, NGINX terdampak/versi tidak diketahui). Pada `--nodejs-poc`, status ini muncul jika kontrol negatif gagal/diblokir/menghasilkan marker, endpoint tidak mendekode Brotli, kode error decoder tidak diekspos, atau terjadi timeout. Pada `--nginx-poc`, status ini muncul jika kontrol negatif gagal/ditolak, probe tidak menghasilkan crash yang dapat dipastikan, atau server tidak pulih. Pada PHP, status ini muncul jika probe timeout, HTTP 500 body kosong tanpa kontrol pembanding yang berhasil, atau kontrol valid multipart ikut gagal/kosong sehingga crash tidak dapat dibedakan dari error biasa. Jika baseline mendeteksi diblokir/challenge, hasil "tidak rentan" bisa diubah menjadi status ini di level host. |
| `[GALAT]` | Kesalahan koneksi/permintaan | Timeout, koneksi gagal, SSL error, atau kesalahan tak terduga saat pengujian. Perlu dicek koneksi, sertifikat, atau proxy. Jika penyebabnya rantai sertifikat tidak lengkap, gunakan `--ca-bundle FILE` atau `--system-ca`; `-k` hanya untuk lab. |

Status host `[TIDAK RENTAN]` juga dapat muncul ketika engine PHP dilewati pada target Next.js tanpa indikator PHP. Periksa `findings[].skipped` dan `findings[].skip_reason` untuk membedakan engine yang benar-benar diuji dari engine yang tidak relevan.

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
      "status_code": 200,
      "error": null,
      "reason": null,
      "fingerprint": {
        "status_code": 200,
        "server": "nginx",
        "tech": ["NGINX", "Next.js", "React Router", "React", "Node.js"],
        "tech_details": [
          {
            "name": "NGINX",
            "confidence": "high",
            "evidence": ["Server: nginx/1.30.0"],
            "sources": ["header"],
            "version": "1.30.0"
          },
          {
            "name": "Next.js",
            "confidence": "high",
            "evidence": ["header: x-nextjs-cache", "body: self.__next_f"],
            "sources": ["header", "body"]
          },
          {
            "name": "React",
            "confidence": "high",
            "evidence": ["Next.js"],
            "sources": ["inferred"]
          },
          {
            "name": "Node.js",
            "confidence": "medium",
            "evidence": ["Next.js runtime"],
            "sources": ["inferred"]
          },
          {
            "name": "React Router",
            "confidence": "high",
            "evidence": ["versi 7.13.1"],
            "sources": ["header/body"],
            "version": "7.13.1"
          }
        ],
        "tech_summary": "PHP=tidak terlihat; React=terdeteksi; Node.js=terindikasi; NGINX=terdeteksi; Next.js=terdeteksi; React Router=terdeteksi",
        "router_version": "7.13.1",
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
          "verdict": "NOT APPLICABLE",
          "status_code": 200,
          "skipped": true,
          "skip_reason": "target terdeteksi Next.js tanpa indikator PHP; probe PHP tidak dijalankan pada mode all"
        },
        {
          "engine": "react",
          "cve": "CVE-2025-55182 / CVE-2025-66478",
          "vulnerable": true,
          "verdict": "VULNERABLE",
          "reason": "indikator kerentanan ditemukan pada respons"
        },
        {
          "engine": "react-router",
          "cve": "CVE-2026-42211",
          "vulnerable": null,
          "verdict": "INCONCLUSIVE",
          "reason": "React Router Framework Mode terdeteksi dengan versi 7.13.1 (rentang terdampak 7.0.0-7.14.1)",
          "framework": {
            "detected": true,
            "mode": "framework",
            "version": "7.13.1",
            "affected": true,
            "manifest_path": "/__manifest",
            "manifest_checked": true,
            "evidence": ["__reactroutercontext", "manifest"]
          }
        },
        {
          "engine": "nodejs",
          "cve": "CVE-2026-111497",
          "vulnerable": true,
          "verdict": "RENTAN",
          "status_code": 500,
          "reason": "PoC Node.js Brotli (oob-base): decoder mengembalikan FORMAT_BLOCK_LENGTH_1",
          "evidence": ["nextjs"]
        },
        {
          "engine": "nginx",
          "cve": "CVE-2026-42945",
          "vulnerable": null,
          "verdict": "INCONCLUSIVE",
          "status_code": 200,
          "server": "nginx/1.30.0",
          "version": "1.30.0",
          "version_affected": true,
          "reason": "NGINX 1.30.0 berada di rentang terdampak (0.6.27-1.30.0); konfigurasi rewrite+set dengan capture belum diverifikasi. Gunakan --nginx-poc untuk probe (intrusif)."
        }
      ],
      "timestamp": "2026-10-23T..."
    }
  ]
}
```

Pada fingerprint, JSON memuat `tech`, `tech_details`, dan `tech_summary`. Setiap entri `tech_details` berisi `name`, `confidence` (`high`/`medium`/`low`), `evidence`, `sources`, dan `version` jika tersedia. Teknologi yang tidak terlihat tetap ditandai `tidak terlihat` pada `tech_summary`; ini bukan klaim negatif, terutama jika `blocked: true`.

Pada temuan PHP, JSON juga memuat `control`, `probes`, `differential`, `differential_request`, `suspicion`, `powered_by`, `sapi`, `skipped`, dan `skip_reason` untuk keperluan audit. `differential` hanya terisi jika scanner mengirim kontrol valid multipart pembanding; `suspicion` menyimpan sinyal yang belum cukup untuk menyimpulkan `[RENTAN]`. Temuan dengan `skipped: true` dan `verdict: NOT APPLICABLE` berarti engine tidak dijalankan karena tidak relevan dengan fingerprint, bukan karena probe berhasil membuktikan target aman. Pada temuan Node.js dengan `--nodejs-poc`, JSON juga memuat `control_passed`, `control_status_code`, `control_error`, `control_marker`, `control_request`, dan `control_response` untuk keperluan audit. Pada temuan NGINX dengan `--nginx-poc`, JSON juga memuat `control_tested_url`, `control_tested_path`, `control_status_code`, `control_crash_like`, `control_passed`, `probe_error`, dan `liveness_recovered` untuk keperluan audit.

## Pengujian

Jalankan tes regresi lokal untuk PHP, CodeIgniter, CMS (WordPress/Drupal/Joomla/lokal), integritas catalog CMS, React, React Router, Node.js, NGINX, fingerprint teknologi, gate PHP, dan status host (memakai mock/fake response, tidak mengirim payload ke target):

```powershell
python -m unittest discover -s tests -v
```

## Tips Penggunaan

- **Scan massal** - Gunakan `-t` secukupnya (10-20) dan pertimbangkan `--rate-limit` agar tidak terlalu agresif.
- **Target spesifik** - Jika tahu aplikasinya berbasis Next.js, coba `--mode react` terlebih dahulu. Jika React Router Framework Mode, gunakan `--mode react-router`. Jika PHP tradisional, coba `--mode php`. Jika Node.js/Express, coba `--mode nodejs`. Jika NGINX, gunakan `--mode nginx`.
- **Node.js PoC** - Gunakan `--nodejs-poc` hanya pada endpoint yang menerima body `Content-Encoding: br` (mis. API upload/ingest). Scanner mengirim kontrol Brotli valid lebih dulu; jika kontrol menghasilkan marker/status blokir, vektor PoC dibatalkan. Jika endpoint tidak mendekode Brotli, hasilnya `TIDAK KONKLUSIF`. Jangan arahkan PoC ke produksi tanpa izin.
- **NGINX PoC** - Gunakan `--nginx-poc` hanya pada target berizin dan jendela pengujian yang disetujui. Probe dapat memicu restart worker; mulai dari `--mode nginx` tanpa probe untuk melihat versi, lalu aktifkan probe bila diperlukan. Kontrol negatif URI panjang membantu menyingkirkan reset dari WAF/proxy, tetapi hasil `[RENTAN]` tetap perlu dikonfirmasi dengan log/error NGINX dan versi paket.
- **React Router** - Gunakan `-v` untuk melihat marker/versi yang terdeteksi. Jika hasil `TIDAK KONKLUSIF` karena versi tidak diketahui, verifikasi manual melalui `package.json` atau artefak build (`react-router >= 7.14.2` aman).
- **WAF aktif** - Perhatikan baris fingerprint/baseline. Jika diblokir, hasil bisa menjadi `TIDAK KONKLUSIF`; eskalasi ke `--rce` (React) hanya bila Anda berwenang.
- **Debugging trafik** - Arahkan `--proxy` ke Burp/ZAP (mis. `http://127.0.0.1:8080`) untuk memeriksa request/response. Pastikan Anda berwenang atas target dan proxy tersebut.
- **Periksa bukti** - Gunakan `-v` untuk melihat alasan verdict dan cuplikan respons saat menganalisis hasil yang mencurigakan. Request yang direkam (dengan body besar dipotong) dan data fingerprint juga tersimpan di JSON.
- **Validasi lokal** - Sangat disarankan untuk menguji di lingkungan lab/localhost terlebih dahulu sebelum scan ke target lain.

## Peringatan Etis & Hukum

**PENTING:** Hanya jalankan scanner ini terhadap sistem yang **benar-benar milik Anda** atau yang telah mendapatkan **izin tertulis eksplisit** untuk diuji.

Penggunaan tanpa izin dapat melanggar hukum yang berlaku di yurisdiksi Anda. Pengembang tidak bertanggung jawab atas penyalahgunaan tools ini.
