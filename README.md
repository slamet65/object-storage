# objstore

Server object storage single-node yang kompatibel dengan S3 API, ditulis dengan Go.
Bisa dipakai dengan aws-cli, AWS SDK, rclone, dan klien S3 lain, baik path-style maupun
virtual-hosted-style.

## Menjalankan

```bash
export OBJSTORE_ACCESS_KEY=<access key pilihan Anda>
export OBJSTORE_SECRET_KEY=<secret key pilihan Anda>
go run ./cmd/objstore --addr :9000 --data ./data
```

| Flag | Kunci di file konfigurasi | Default | Keterangan |
|---|---|---|---|
| `--addr` | `addr` | `:9000` | Alamat listen |
| `--data` | `data` | `./data` | Folder penyimpanan |
| `--region` | `region` | `us-east-1` | Region yang dilaporkan ke klien |
| `--domain` | `domain` | kosong | Domain dasar untuk virtual-hosted-style (`bucket.domain`) |
| `--tls-cert` | `tls_cert` | kosong | Sertifikat TLS (PEM); mengaktifkan HTTPS bersama `--tls-key` |
| `--tls-key` | `tls_key` | kosong | Kunci privat TLS (PEM) |
| `--max-buckets` | `max_buckets` | `1000` | Jumlah bucket maksimum; `0` berarti tanpa batas |
| `--lifecycle-interval` | `lifecycle_interval` | `1h` | Jeda antar putaran lifecycle; `0` mematikannya |
| `--config` | | kosong | File konfigurasi JSON |

Flag yang diberikan eksplisit mengalahkan file konfigurasi, dan file konfigurasi mengalahkan nilai bawaan.
Kredensial hanya dibaca dari environment, tidak dari file konfigurasi. Contoh file:

```json
{
  "addr": ":9443",
  "data": "/var/lib/objstore",
  "domain": "s3.contoh.com",
  "tls_cert": "/etc/objstore/cert.pem",
  "tls_key": "/etc/objstore/key.pem"
}
```

Kalau server ditaruh di belakang reverse proxy, teruskan header `Host` apa adanya, karena header itu ikut
ditandatangani klien.

`GET /-/healthz` menjawab `ok` tanpa autentikasi, untuk pemeriksaan kesehatan.

Batas bawaan: 5 GiB per PutObject dan per part, 5 TiB per object multipart, 8192 byte metadata pengguna
per object.

## Token dan izin

Kredensial dari `OBJSTORE_ACCESS_KEY` / `OBJSTORE_SECRET_KEY` adalah kredensial **root**: admin penuh
atas semua bucket, dipakai untuk bootstrap. Untuk aplikasi, buat token dengan izin secukupnya.

| Izin | Baca object dan daftar | Tulis/hapus object | Buat/hapus bucket | Kelola token |
|---|---|---|---|---|
| `object-read` | ya | | | |
| `object-read-write` | ya | ya | | |
| `admin-read` | ya | | | lihat daftar |
| `admin-read-write` | ya | ya | ya | ya |

Token bisa dibatasi ke bucket tertentu. Permintaan ke bucket di luar cakupan dijawab `AccessDenied`,
termasuk untuk bucket yang tidak ada, dan ListBuckets hanya menampilkan bucket dalam cakupan. Mengelola
token butuh `admin-read-write` tanpa batasan bucket.

```bash
export OBJSTORE_ACCESS_KEY=... OBJSTORE_SECRET_KEY=...   # root, atau token admin-read-write
objstore token create --name aplikasi --permission object-read-write --bucket foto --ttl 720h
objstore token list
objstore token rotate <id>
objstore token disable <id>
objstore token delete <id>
```

`token create` dan `token rotate` mencetak `access_key_id` dan `secret_access_key`. Secret hanya muncul
saat itu; setelahnya hanya bisa dirotasi. Rotasi, penonaktifan, dan penghapusan berlaku seketika.
Perintah klien memakai `--endpoint` (atau `OBJSTORE_ENDPOINT`), dan `--ca-cert` untuk server HTTPS
bersertifikat sendiri.

### Kredensial sementara

Token mana pun bisa menerbitkan kredensial sementara dari dirinya sendiri, dengan izin dan bucket yang
tidak melebihi miliknya, masa berlaku paling lama 7 hari, dan bisa dipersempit sampai prefix atau object:

```bash
objstore temp-credentials --permission object-read --ttl 1h --bucket foto --prefix 2025/
```

Hasilnya `access_key_id`, `secret_access_key`, dan `session_token`, dipakai sebagai
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, dan `AWS_SESSION_TOKEN`. Kredensial sementara tidak
disimpan di server, tidak bisa menerbitkan kredensial lain, dan gugur saat token induknya dirotasi,
dinonaktifkan, dihapus, atau kedaluwarsa. Dengan cakupan prefix, daftar object hanya boleh diminta
dengan `prefix` di bawah prefix yang diizinkan.

### Master key

Secret token disimpan terenkripsi (AES-256-GCM) dengan master key 32 byte. Master key diambil dari
`OBJSTORE_MASTER_KEY` (base64); kalau tidak diisi, dibuat acak di `data/master.key` saat pertama kali
server dijalankan. Tanpa master key yang sama, semua token dan kredensial sementara tidak bisa dipakai,
jadi cadangkan bersama data. Menyimpannya di luar folder data (lewat environment) melindungi secret
token bila hanya `meta.db` yang bocor.

### API admin

CLI di atas memanggil API JSON di `/-/admin/`, yang diautentikasi dengan SigV4 seperti API S3:

| Method dan path | Fungsi |
|---|---|
| `GET tokens` | Daftar token (tanpa secret) |
| `POST tokens` | Buat token: `name`, `permission`, `buckets`, `ttl_seconds` |
| `GET tokens/{id}` | Lihat satu token |
| `DELETE tokens/{id}` | Cabut token |
| `POST tokens/{id}/rotate` | Ganti secret |
| `POST tokens/{id}/disable`, `.../enable` | Nonaktifkan atau aktifkan |
| `GET buckets/{nama}` | Konfigurasi bucket (publik, domain, CORS, lifecycle, lock) |
| `PUT buckets/{nama}/public` | Atur akses publik: `public`, `domains` |
| `PUT buckets/{nama}/lock` | Ganti aturan lock: `rules` |
| `POST temp-credentials` | Terbitkan kredensial sementara: `ttl_seconds`, `permission`, `buckets`, `prefixes`, `objects` |
| `GET whoami` | Identitas pemanggil |

## Konfigurasi bucket

### CORS

Diatur lewat API S3 (`put-bucket-cors`, `get-bucket-cors`, `delete-bucket-cors`); butuh token admin.
Preflight `OPTIONS` dijawab tanpa autentikasi, dan respons permintaan dari origin yang diizinkan,
termasuk respons error, membawa header `Access-Control-Allow-Origin`.

```bash
aws --endpoint-url http://localhost:9000 s3api put-bucket-cors --bucket foto --cors-configuration file://cors.json
```

### Akses publik dan custom domain

```bash
objstore bucket public foto --enable --domain cdn.contoh.com
objstore bucket public foto --disable
objstore bucket show foto
```

Bucket publik melayani `GET` dan `HEAD` object tanpa autentikasi. Listing, penulisan, dan penghapusan
tetap butuh token. Custom domain memetakan nama host ke bucket, sehingga object dilayani dari akar path
(`https://cdn.contoh.com/2025/gambar.jpg`); arahkan DNS domain itu ke server ini. Satu domain hanya bisa
dipakai satu bucket. `--domain` mengganti seluruh daftar domain, jadi sebutkan semuanya setiap kali.

### Lifecycle

Diatur lewat API S3 (`put-bucket-lifecycle-configuration` dan pasangannya). Aksi yang didukung:
kedaluwarsa (`Expiration` dengan `Days` atau `Date`), transisi ke `STANDARD_IA`, dan
`AbortIncompleteMultipartUpload`, masing-masing dengan filter prefix. Filter tag/ukuran dan aksi versi
lama dijawab `NotImplemented`.

Aturan dijalankan pekerja latar tiap `--lifecycle-interval`. `Days` dihitung tepat N×24 jam sejak object
ditulis, tidak dibulatkan ke tengah malam seperti di S3. Pekerja tidak menyimpan keadaan dan memindai
ulang tiap putaran, jadi restart di tengah putaran tidak menghilangkan pekerjaan.

### Storage class

`STANDARD` dan `STANDARD_IA` diterima lewat `x-amz-storage-class` dan tampil di listing serta HEAD.
Saat ini hanya label: penyimpanan fisiknya sama.

### Bucket lock

Aturan retensi per prefix yang melarang penghapusan dan penimpaan object, termasuk oleh root dan oleh
lifecycle. Tiga mode: `age` (sekian hari sejak object ditulis), `date` (sampai tanggal tertentu), dan
`indefinite` (selama aturannya ada).

```json
[
  {"id": "arsip", "enabled": true, "prefix": "arsip/", "mode": "age", "days": 365},
  {"id": "audit", "enabled": true, "prefix": "audit/", "mode": "date", "until": "2030-01-01T00:00:00Z"}
]
```

```bash
objstore bucket lock foto --file lock.json
objstore bucket lock foto --clear
```

Perintah ini mengganti seluruh aturan. Aturan bisa dicabut kapan saja oleh token `admin-read-write`,
jadi ini pengaman terhadap kesalahan dan skrip yang keliru, bukan kunci kepatuhan yang tidak bisa dibuka.

## Contoh dengan aws-cli

```bash
export AWS_ACCESS_KEY_ID=$OBJSTORE_ACCESS_KEY AWS_SECRET_ACCESS_KEY=$OBJSTORE_SECRET_KEY AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://localhost:9000 s3 mb s3://foto
aws --endpoint-url http://localhost:9000 s3 cp gambar.jpg s3://foto/2025/gambar.jpg
aws --endpoint-url http://localhost:9000 s3 ls s3://foto --recursive
aws --endpoint-url http://localhost:9000 s3 presign s3://foto/2025/gambar.jpg --expires-in 600
```

Presigned URL harus SigV4. aws-cli v2 sudah begitu; aws-cli v1 membuat URL SigV2 secara default, jadi
jalankan dulu `aws configure set default.s3.signature_version s3v4`.

## Yang didukung

- **Bucket:** ListBuckets, CreateBucket, HeadBucket, DeleteBucket, GetBucketLocation, CORS, lifecycle,
  akses publik, custom domain, bucket lock.
- **Object:** PutObject, GetObject (Range, `partNumber`, If-Match, If-None-Match, If-Modified-Since,
  If-Unmodified-Since), HeadObject, DeleteObject, DeleteObjects, CopyObject (termasuk
  `x-amz-copy-source-if-*`), metadata `x-amz-meta-*`.
- **Tulis bersyarat:** `If-None-Match: *` dan `If-Match` pada PutObject, CopyObject, dan
  CompleteMultipartUpload, diperiksa secara atomik saat commit.
- **List:** ListObjectsV2 dan ListObjects V1 dengan prefix, delimiter, pagination, `encoding-type=url`.
- **Multipart:** Create, UploadPart, UploadPartCopy, Complete, Abort, ListParts, ListMultipartUploads.
- **Auth:** SigV4 lewat header dan presigned URL; body `UNSIGNED-PAYLOAD`, SHA-256, dan aws-chunked
  (bertanda tangan maupun dengan trailer checksum). Banyak token dengan empat tingkat izin dan cakupan
  bucket, serta kredensial sementara dengan `X-Amz-Security-Token`.
- **Integritas:** `Content-MD5` dan `x-amz-checksum-{crc32,crc32c,crc64nvme,sha1,sha256}` diperiksa saat
  upload. Checksum disimpan dan dikembalikan pada GET/HEAD dengan `x-amz-checksum-mode: ENABLED`; object
  multipart mendapat checksum gabungan (`COMPOSITE`).

## Yang belum didukung

- Versioning, ACL, bucket policy, tagging (dijawab `NotImplemented`).
- Checksum seluruh-object untuk multipart (`FULL_OBJECT`, termasuk CRC64NVME); object multipart hanya
  mendapat checksum gabungan, atau tidak sama sekali bila part-nya memakai CRC64NVME.
- Checksum yang dihitung server bila klien tidak mengirimnya.
- Replikasi atau erasure coding; ini satu node dengan satu disk.

## Tata letak data

```
data/meta.db              metadata (bbolt): bucket, object, multipart upload, token
data/master.key           master key, kalau OBJSTORE_MASTER_KEY tidak diisi
data/blobs/ab/cd/<id>     isi object; nama file acak, tidak berasal dari key
data/tmp/                 file sementara selama upload
```

Upload ditulis ke `tmp`, di-fsync, di-rename ke `blobs`, lalu metadata di-commit. Object hasil multipart
merujuk langsung ke blob tiap part tanpa penyalinan. Blob yang gagal dihapus karena masih dibaca (terjadi
di Windows) dicoba lagi tiap 30 detik, dan blob yang tidak dirujuk metadata (sisa crash) dibersihkan
setiap kali server start.

## Test

```bash
go test ./...
```

Integration test di `internal/s3api` menjalankan server sungguhan dan mengujinya dengan `aws-sdk-go-v2`
lewat HTTP dan HTTPS. Workflow `.github/workflows/ci.yml` menjalankan `go vet` dan test di Linux (dengan
race detector) dan Windows.
