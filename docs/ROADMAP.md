# Roadmap: menuju fitur setara Cloudflare R2

Dokumen ini memetakan fitur R2 ke pekerjaan yang perlu dilakukan di objstore, dibagi per fase dengan
kriteria selesai. Daftar fitur R2 ditulis dari ingatan, belum dicocokkan ulang dengan dokumentasi R2
terbaru; cek ulang detail (terutama batas ukuran dan nama izin token) sebelum mengerjakan tiap fase.

Ukuran pekerjaan: **S** = kecil (satu area kode), **M** = sedang (beberapa paket + test), **L** = besar
(perubahan arsitektur).

## 1. Posisi sekarang vs R2

| Area | R2 | objstore sekarang |
|---|---|---|
| Bucket dan object dasar | Ada | Ada |
| Multipart (termasuk UploadPartCopy) | Ada | Ada |
| ListObjects V1/V2 | Ada | Ada |
| SigV4 header + presigned URL | Ada | Ada |
| Checksum upload (CRC32/CRC32C/CRC64NVME/SHA1/SHA256) | Diperiksa dan disimpan | Diperiksa dan disimpan; multipart hanya checksum gabungan |
| Conditional write (`If-None-Match: *`, `If-Match` pada PUT) | Ada | Ada |
| Virtual-hosted-style (`bucket.host`) | Ada | Ada |
| Banyak token dengan izin dan cakupan bucket | Ada | Ada |
| Kredensial sementara (TTL, cakupan prefix) | Ada | Ada |
| Bucket publik + custom domain | Ada | Ada (tanpa cache/CDN) |
| CORS per bucket | Ada | Ada |
| Lifecycle (kedaluwarsa, abort multipart, pindah kelas) | Ada | Ada |
| Storage class Standard / Infrequent Access | Ada | Ada sebagai label |
| Bucket lock (aturan retensi) | Ada | Ada |
| Enkripsi at rest + SSE-C | Ada | Belum |
| Event notification | Ada (ke Queues) | Belum |
| Metrik, pemakaian, audit log | Ada | Hanya access log |
| Dashboard dan CLI admin | Ada | Belum |
| Migrasi (Super Slurper, Sippy) | Ada | Belum |
| Durabilitas multi-lokasi, konsistensi kuat | Ada | Satu node, satu disk |
| Location hint / jurisdiction | Ada | Tidak relevan sebelum multi-node |

Yang **tidak** ada di R2 dan karena itu tidak perlu dikejar: ACL object/bucket, bucket policy gaya IAM,
object tagging, versioning, upload form POST, replikasi lintas bucket gaya S3.

Yang ada di R2 tetapi **di luar cakupan** proyek ini: binding Workers, R2 Data Catalog (Iceberg) dan R2 SQL,
jaringan edge/CDN global, model tagihan.

## 2. Keputusan yang perlu diambil dulu

Jawaban atas tiga hal ini mengubah urutan dan desain:

1. **Target deployment: satu mesin (sudah diputuskan).** Bagian multi-node di Fase 7 tidak dikerjakan;
   yang tersisa hanya erasure coding antar-disk, dan itu opsional.
2. **Pemakai:** hanya Anda, atau banyak pengguna/aplikasi dengan izin berbeda? Menentukan kedalaman Fase 1.
3. **Antarmuka admin:** cukup CLI + REST, atau perlu dashboard web?

## 3. Fase

### Fase 0: Pengerasan fondasi (S–M)

Menutup celah kompatibilitas S3 pada fitur yang sudah ada, sebelum menambah fitur baru.

**Status: sebagian besar selesai.** Semua butir di bawah sudah dikerjakan dan teruji, kecuali tiga hal:

- Suite kompatibilitas pihak ketiga (`s3-tests` atau `mint`) belum dipasang. Keduanya butuh Docker, dan
  `s3-tests` butuh lebih dari satu kredensial, jadi paling masuk akal dikerjakan setelah Fase 1.
- Workflow CI sudah ditulis tetapi belum pernah dijalankan, karena repo belum punya remote. Akibatnya
  race detector juga belum pernah dijalankan.
- Checksum seluruh-object untuk multipart (termasuk CRC64NVME) belum ada; object multipart mendapat
  checksum gabungan saja.

- Conditional write: `If-None-Match: *` dan `If-Match` pada PutObject dan CompleteMultipartUpload;
  header `x-amz-copy-source-if-*` pada CopyObject.
- Simpan checksum object dan part; kembalikan pada GET/HEAD saat `x-amz-checksum-mode: ENABLED`.
- Virtual-hosted-style: opsi `--domain`, bucket diambil dari header `Host`.
- Pagination ListMultipartUploads (`key-marker`, `upload-id-marker`, `max-uploads`, `delimiter`).
- `partNumber` pada GetObject/HeadObject.
- Batas: ukuran object dan part maksimum, metadata pengguna maksimum, jumlah bucket; tolak dengan
  kode error S3 yang benar (`EntityTooLarge`, `MetadataTooLarge`).
- File konfigurasi (selain flag/env), TLS bawaan, endpoint `/healthz`.
- Penghapusan blob yang tertunda di Windows: antrean coba-ulang, bukan menunggu restart.
- CI: `go vet`, `go test -race` (butuh cgo di runner Linux), dan suite kompatibilitas pihak ketiga
  (ceph `s3-tests` atau MinIO `mint`) dengan daftar test yang sengaja dilewati.

**Selesai jika:** suite kompatibilitas lolos untuk semua operasi yang didukung, dan rclone serta
aws-cli v2 bekerja tanpa opsi khusus selain endpoint.

### Fase 1: Token dan izin (M)

Model R2: token punya tingkat izin dan cakupan bucket; kredensial S3 diturunkan dari token.

**Status: selesai.** Semua butir di bawah sudah dikerjakan dan teruji, termasuk API admin dan CLI untuk
token (yang semula direncanakan di Fase 5). Perbedaan yang disengaja dari R2:

- Kredensial sementara diterbitkan oleh token itu sendiri (induknya adalah pemanggil), bukan oleh
  admin atas nama token lain.
- ListBuckets boleh dipanggil token apa pun dan hasilnya disaring menurut cakupan, supaya `aws s3 ls`
  tetap bekerja dengan token object.
- Belum ada audit log untuk operasi token; itu bagian Fase 5.

- Simpan banyak token di metadata: access key, secret (terenkripsi dengan master key), izin, daftar
  bucket, masa berlaku, status aktif.
- Empat tingkat izin: admin baca-tulis, admin baca, object baca-tulis, object baca. Operasi bucket
  (buat, hapus, ubah konfigurasi) hanya untuk admin.
- Cakupan: semua bucket atau daftar bucket tertentu.
- Kredensial sementara: endpoint penerbit yang menghasilkan access key + secret + session token dengan
  TTL, cakupan bucket/prefix/object, dan izin tidak melebihi token induk. Verifikasi
  `X-Amz-Security-Token` di SigV4.
- Token root dari env hanya untuk bootstrap.
- Rotasi dan pencabutan token berlaku seketika.

**Selesai jika:** token baca-saja ditolak saat menulis (`AccessDenied`), token berlingkup bucket A tidak
bisa menyentuh atau melihat bucket B, dan kredensial sementara berhenti bekerja setelah TTL.

### Fase 2: Konfigurasi bucket (M)

**Status: selesai.** Semua butir di bawah sudah dikerjakan dan teruji. Catatan:

- Akses publik dan bucket lock diatur lewat API admin dan CLI (`objstore bucket ...`), karena S3 API
  tidak punya padanannya; CORS dan lifecycle lewat API S3.
- `Days` pada lifecycle dihitung tepat N×24 jam, tidak dibulatkan ke tengah malam UTC.
- Server tidak mengurus sertifikat TLS per custom domain; pakai sertifikat yang mencakup domain itu
  atau reverse proxy.
- Aturan lock bisa dicabut admin kapan saja; belum ada mode yang tidak bisa dibuka.

- **CORS:** Put/Get/DeleteBucketCors; jawab preflight `OPTIONS` tanpa auth; tambahkan header CORS
  pada respons yang cocok dengan aturan.
- **Akses publik:** bucket bisa ditandai publik; GET/HEAD object anonim diizinkan, listing tetap
  ditolak. Pemetaan custom domain → bucket (object dilayani dari akar path).
- **Lifecycle:** Put/Get/DeleteBucketLifecycleConfiguration dengan aturan kedaluwarsa (hari atau
  tanggal, filter prefix), abort multipart yang belum selesai, dan transisi ke Infrequent Access.
  Dijalankan pekerja latar berkala yang bisa dilanjutkan setelah restart.
- **Storage class:** `STANDARD` dan `STANDARD_IA` dicatat per object, diterima lewat
  `x-amz-storage-class`, tampil di listing. Awalnya hanya label; penempatan fisik berbeda menyusul
  bila ada beberapa disk.
- **Bucket lock:** aturan retensi per prefix (sekian hari, sampai tanggal, atau tanpa batas); hapus dan
  timpa ditolak selama retensi, termasuk oleh lifecycle.

**Selesai jika:** browser bisa upload lewat presigned URL dari origin yang diizinkan; object kedaluwarsa
terhapus oleh pekerja latar; object yang terkunci tidak bisa dihapus dengan token admin sekalipun.

### Fase 3: Perlindungan data (M)

- **Enkripsi at rest:** AES-256-GCM per blob dengan kunci data acak, dibungkus master key dari file
  atau env. Format blob ber-chunk supaya Range tetap efisien. Rotasi master key tanpa menulis ulang data.
- **SSE-C:** header `x-amz-server-side-encryption-customer-*` pada PUT/GET/HEAD/Copy/multipart; kunci
  tidak pernah disimpan, hanya MD5-nya untuk verifikasi.
- **Deteksi kerusakan:** checksum per blob diperiksa saat dibaca, plus scrubber latar yang melaporkan
  blob rusak atau hilang.
- **Cadangan metadata:** snapshot `meta.db` konsisten tanpa menghentikan server, dan perintah pemulihan.
- Format blob baru berarti perlu nomor versi format dan jalur migrasi dari blob polos sekarang.

**Selesai jika:** isi `data/blobs` tidak terbaca tanpa master key; mengubah satu byte blob terdeteksi
saat GET dan oleh scrubber; pemulihan dari snapshot menghasilkan listing yang identik.

### Fase 4: Event notification (M)

- Aturan per bucket: jenis event (object dibuat lewat Put/Copy/CompleteMultipartUpload; object dihapus
  lewat Delete atau lifecycle), filter prefix dan suffix, tujuan.
- Tujuan: webhook HTTP dulu; antarmuka dibuat terbuka untuk antrean (NATS, Kafka, dsb.).
- Pengiriman at-least-once: event ditulis ke outbox di transaksi metadata yang sama dengan perubahan
  object, dikirim pekerja latar dengan coba-ulang dan backoff, lalu dead-letter setelah batas tertentu.
- Payload mengikuti bentuk event R2 (akun, bucket, key, ukuran, ETag, waktu, jenis aksi).

**Selesai jika:** mematikan server tepat setelah PUT tidak menghilangkan event; penerima yang mati
sementara tetap menerima semua event setelah hidup lagi.

### Fase 5: Operasional (M–L)

- **Metrik** Prometheus: jumlah operasi per kelas (tulis/list = kelas A, baca = kelas B, seperti R2),
  byte masuk/keluar, latensi, error per kode.
- **Pemakaian** per bucket: jumlah object dan byte, dihitung inkremental, bukan dengan memindai.
- **Audit log** untuk operasi admin (token, konfigurasi bucket) dan penolakan akses.
- **REST API admin + CLI:** kelola bucket, token, CORS, lifecycle, lock, notifikasi, pemakaian.
- **Dashboard web** (opsional, lihat keputusan 3): jelajah bucket, upload/download, kelola token.
- **Kuota** per bucket dan pembatasan laju per token.

**Selesai jika:** semua yang bisa dilakukan lewat edit konfigurasi juga bisa lewat CLI, dan angka
pemakaian cocok dengan hasil pemindaian penuh.

### Fase 6: Migrasi (S–M)

- **Impor massal** (padanan Super Slurper): job yang menyalin bucket dari S3/GCS/penyedia S3 lain,
  bisa dilanjutkan, dengan laporan object yang gagal.
- **Migrasi bertahap** (padanan Sippy): bucket dikaitkan ke sumber; GET yang tidak ditemukan diambil
  dari sumber, dikembalikan ke klien, dan disimpan lokal.

**Selesai jika:** bucket sumber berisi ribuan object tersalin dengan ETag/checksum cocok, dan job yang
diputus di tengah bisa dilanjutkan tanpa menyalin ulang dari awal.

### Fase 7: Durabilitas dan skala (L)

Inilah yang membuat R2 tahan kehilangan disk atau lokasi. Satu node tidak bisa menyamainya, apa pun
fitur API-nya.

Karena targetnya satu mesin, hanya butir pertama yang masih relevan (opsional, ukuran M–L). Butir
lainnya dicatat sebagai hal yang sengaja tidak dikerjakan. Akibatnya, ketahanan terhadap kehilangan
mesin bergantung pada cadangan di luar mesin (snapshot metadata di Fase 3 ditambah salinan blob),
bukan pada replikasi.

- **Banyak disk dalam satu node:** erasure coding (`klauspost/reedsolomon`) dengan paritas yang bisa
  diatur, penyembuhan otomatis saat disk diganti.
- **Banyak node (tidak dikerjakan):** metadata direplikasi dengan konsensus (Raft) supaya baca-setelah-tulis tetap
  konsisten kuat; data disebar antar-node dengan erasure coding atau replikasi.
- Penyeimbangan ulang saat node/disk ditambah atau dicabut; mode baca-saja saat kuorum hilang.
- **Location hint / jurisdiction:** label penempatan per bucket yang membatasi node mana yang boleh
  menyimpan datanya.
- Lapisan storage perlu dipecah menjadi antarmuka metadata dan antarmuka blob lebih dulu; sebaiknya
  pemecahan ini dilakukan di Fase 3 saat format blob berubah, supaya tidak dua kali migrasi.

**Selesai jika:** mencabut satu disk (atau mematikan satu node) saat beban berjalan tidak menyebabkan
error baca/tulis maupun kehilangan data, dan penyembuhan mengembalikan redundansi penuh.

## 4. Urutan yang disarankan

1. **Fase 0**, karena semua fase lain bertumpu padanya dan suite kompatibilitas mencegah regresi.
2. **Fase 1**, karena akses publik, admin API, dan audit log butuh model izin.
3. **Fase 2** dan **Fase 3** (boleh ditukar; dahulukan Fase 3 bila data sensitif).
4. **Fase 5** bagian metrik dan CLI, lalu **Fase 4**.
5. **Fase 6** kapan pun dibutuhkan; tidak bergantung pada fase lain selain Fase 0.
6. **Fase 7** terakhir dan hanya bagian multi-disk, bila mesinnya memang punya beberapa disk.

Fase 0 sampai 6 menghasilkan server satu node yang secara API dan fitur setara R2 untuk hampir semua
klien. Fase 7 adalah pekerjaan yang ukurannya sebanding dengan gabungan fase lain.

## 5. Risiko

- **Perubahan format di disk** (Fase 3 dan 7) butuh migrasi; makin banyak data tersimpan, makin mahal.
- **bbolt hanya satu penulis.** Cukup untuk satu node, tetapi menjadi batas throughput tulis; Fase 7
  kemungkinan menggantinya.
- **Kompatibilitas klien** sering gagal di detail (encoding, header, kode error). Suite kompatibilitas
  di Fase 0 adalah pengaman utamanya.
- **Keamanan:** begitu ada akses publik dan banyak token, server layak mendapat tinjauan keamanan
  sebelum dibuka ke internet.
