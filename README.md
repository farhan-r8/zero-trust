# Zero Trust Security - Fondasi Backend

Backend tahap ini mencakup fondasi SQLite/seed, autentikasi, Policy Engine, API Gateway, Grade Service, dan Transcript Service. Belum ada frontend.

## Kebutuhan

- Node.js 22.x dan npm 10.x.
- Windows didukung melalui prebuild `better-sqlite3`; bila prebuild platform tidak tersedia, paket memerlukan toolchain native Node.js.

## Instalasi dan inisialisasi

Jalankan instalasi dari Command Prompt pada folder proyek:

```cmd
if not exist .env copy .env.example .env
npm install
npm run db:init
npm test
```

Database dibuat pada `data\zero-trust.sqlite`. Direktori database dan log, `.env`, `node_modules`, serta `login-test.json` dikecualikan dari Git. Jalankan `npm run db:init` hanya saat menyiapkan database praktikum baru atau setelah membuat cadangan. Seed menghindari duplikasi, tetapi saat dijalankan ulang memperbarui nama/NIM/role dan hash password akun demo, mengaktifkan kembali device seed, serta menetapkan ulang dosen pengampu kelas seed. Enrollment dan nilai yang sudah ada tidak di-reset. Jangan jalankan perintah ini pada database berisi perubahan penting tanpa memahami efek tersebut.

Setelah database siap, buka tiga Command Prompt pada folder proyek dan jalankan masing-masing `npm run start:gateway`, `npm run start:grade`, dan `npm run start:transcript`.

## Konfigurasi

Nilai awal di `.env.example`: zona waktu `Asia/Jakarta`, jam akses `07:00` sampai `21:00` (kedua batas inklusif), port Gateway/Grade Service/Transcript Service `3000/3001/3002`, timeout upstream `5000` ms, dan URL balik ke Gateway `http://127.0.0.1:3000`.

Isi `JWT_SECRET` dengan minimal 32 byte acak, serta isi `GATEWAY_SECRET` dan `SERVICE_CLIENT_SECRET` dengan nilai acak yang berbeda. File `.env` lokal tidak ditimpa oleh instruksi di atas dan tidak boleh dibagikan atau di-commit.

Jalankan Gateway setelah database siap dengan `npm run start:gateway`. Gateway bind ke `127.0.0.1` pada port 3000. Tahap ini menyediakan `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, dan `POST /auth/service`. Permintaan login/refresh mengirim JSON serta `X-Device-ID`. Login menerima `username` dan `password`; refresh/logout menerima `refreshToken`; autentikasi service menerima `clientId` dan `clientSecret`. Refresh token dirotasi saat berhasil digunakan.

Modul `src/auth/tokens.js` menyediakan penerbitan dan verifikasi JWT HS256, dengan pemeriksaan issuer, audience, masa berlaku, jenis token, dan role. `src/auth/middleware.js` menyediakan middleware reusable untuk verifikasi token dan pengikatan device pengguna.

`src/policy/engine.js` mengekspor `evaluatePolicy` dan `createPolicyMiddleware`. Gateway menerapkan middleware sebelum proxy. Kedua service memverifikasi `X-Gateway-Secret`, lalu mengulang validasi JWT, device, dan kebijakan menggunakan database yang sama. Pemeriksaan secret tidak menggantikan pemeriksaan JWT. Audit mencatat keputusan kebijakan dan penolakan secret tanpa token/password/secret.

Finalisasi kelas mensyaratkan seluruh nilainya sudah terisi. Nilai final dan sync job outbox dicatat dalam satu transaksi. Jika sinkronisasi gagal, nilai tetap final dan sync job berstatus `pending`; worker Grade Service akan mencoba kembali dengan backoff. Respons finalisasi menunjukkan status `pending` sampai transkrip tersinkron. Transcript Service melakukan upsert berdasarkan `grade_id` agar retry tidak membuat duplikat.

## Akun demo

Semua akun demo memakai password praktikum di bawah ini. Ganti sebelum penggunaan di luar mesin lokal praktikum. Password di database disimpan sebagai hash bcrypt, bukan plaintext.

| Username | Role | NIM | Password demo | Device |
|---|---|---|---|---|
| `admin` | admin | - | `AdminDemo!2026` | `device-admin-001` |
| `dosen1` | dosen | - | `DosenSatu!2026` | `device-dosen1-001` |
| `dosen2` | dosen | - | `DosenDua!2026` | `device-dosen2-001` |
| `mhs1` | mahasiswa | 230001 | `MhsSatu!2026` | `device-mhs1-001` |
| `mhs2` | mahasiswa | 230002 | `MhsDua!2026` | `device-mhs2-001` |
| `mhs3` | mahasiswa | 230003 | `MhsTiga!2026` | `device-mhs3-001` |

## Data contoh dan relasi

- Kelas `KI-501` diampu `dosen1`; semua tiga mahasiswa terdaftar.
- Kelas `KI-502` diampu `dosen2`; `mhs2` dan `mhs3` terdaftar.
- Nilai contoh belum final: `mhs1` mendapat 86 pada KI-501 dan `mhs2` mendapat 91 pada KI-502. Enrollment lain memiliki nilai `NULL` sebagai data siap diisi.
- Foreign key diaktifkan pada setiap koneksi. Constraint unik mencegah enrollment, nilai per kelas-mahasiswa, device per user, transcript per nilai, dan sync job per nilai terduplikasi.

## Endpoint backend

| Method dan endpoint | Role | Aturan utama |
|---|---|---|
| `POST /auth/login` | Publik | Kredensial dan `X-Device-ID` cocok. |
| `POST /auth/refresh` | Pemegang refresh token | Token aktif, belum kedaluwarsa, device terdaftar; token dirotasi. |
| `POST /auth/logout` | Pemegang refresh token | Mencabut refresh token. |
| `POST /auth/service` | Service dengan client credentials | Menerbitkan service token 5 menit. |
| `GET /nilai` | Mahasiswa, dosen | Mahasiswa dibatasi ke miliknya; dosen harus meminta kelas yang diampu. |
| `PUT /nilai/:id` | Dosen pengampu | Nilai belum final dan jam akses terpenuhi. |
| `POST /kelas/:id/finalisasi` | Dosen pengampu | Dalam jam akses dan seluruh nilai kelas terisi; memulai sinkronisasi outbox. |
| `GET /transkrip/:nim` | Mahasiswa, admin | Mahasiswa hanya NIM sendiri; admin dapat membaca NIM mahasiswa aktif. |
| `POST /transkrip/sinkron` | Grade Service | Token service `grade-service`, scope `transcript:sync`, dan nilai final. |

Port 3001 dan 3002 bind ke loopback. Request Postman menuju port 3000; Gateway menambahkan `X-Gateway-Secret` saat meneruskan request.

## Demo Postman

Gunakan base URL `http://127.0.0.1:3000`. Jangan mengirim `X-Gateway-Secret` dari Postman.

1. Login: `POST /auth/login`, `Content-Type: application/json`, header `X-Device-ID: device-mhs1-001`, body `{"username":"mhs1","password":"<PASSWORD_DEMO>"}`. Simpan nilai respons `access_token` ke variabel lokal/private Postman `accessToken` dan `refresh_token` ke `refreshToken`; jangan menyimpan nilai token di berkas koleksi.
2. Lihat nilai mahasiswa: `GET /nilai` dengan `Authorization: Bearer <ACCESS_TOKEN>` dan `X-Device-ID`. Respons berisi `id` (ID nilai) dan `classId` (ID kelas). Catat ID numerik dari respons untuk langkah berikutnya. Untuk kelas KI-502, gunakan akun mahasiswa yang terdaftar pada kelas tersebut.
3. Login sebagai dosen pengampu, lalu lihat kelas dengan `GET /nilai?classId=<CLASS_ID>` memakai device dan access token dosen. Respons juga berisi `id` dan `classId`; gunakan `id` sebagai `<GRADE_ID>` pada `PUT /nilai/<GRADE_ID>` dengan body `{"score":88}`. Isi seluruh nilai kelas yang kosong sebelum finalisasi.
4. Finalisasi melalui `POST /kelas/<CLASS_ID>/finalisasi` dengan token dan device dosen pengampu. HTTP 200 berarti sinkron selesai; HTTP 202 berarti outbox menunggu retry.
5. Lihat transkrip dengan `GET /transkrip/230001`, memakai token mahasiswa pemilik NIM atau admin.
6. Refresh: `POST /auth/refresh`, `Content-Type: application/json`, header `X-Device-ID`, body `{"refreshToken":"{{refreshToken}}"}`. Setelah sukses, perbarui variabel lokal `accessToken` dan `refreshToken` memakai nilai baru dari respons; refresh token lama sudah dicabut saat rotasi.
7. Logout: `POST /auth/logout`, `Content-Type: application/json`, body `{"refreshToken":"{{refreshToken}}"}` memakai refresh token terkini. HTTP 204 berarti pencabutan berhasil; hapus variabel token lokal dari Postman sesudahnya.
8. Sinkronisasi normal dipanggil Grade Service menggunakan token service; endpoint publiknya `POST /transkrip/sinkron`. Bila menguji penerbitan service secara manual, kirim `POST /auth/service` dengan JSON `clientId` dan `clientSecret` dari konfigurasi lokal, lalu gunakan token respons untuk request sinkron. Jangan menyimpan credential service atau token di koleksi yang dibagikan.
9. Uji penolakan dengan NIM mahasiswa lain, kelas dosen lain, edit nilai final, token user pada sinkronisasi, atau akses port service tanpa secret Gateway. Placeholder di atas bukan nilai yang dikirim apa adanya.

## Troubleshooting

- Gateway gagal mulai: pastikan `.env` tersedia dan konfigurasi wajib sudah diisi; pastikan port 3000 tidak sedang digunakan.
- Grade/Transcript Service tidak dapat dihubungi: pastikan ketiga proses berjalan, masing-masing memakai konfigurasi database yang sama, serta port 3001 dan 3002 tersedia.
- HTTP 401 pada login/refresh atau endpoint bisnis: periksa kredensial, masa berlaku/rotasi refresh token, header `X-Device-ID`, dan kecocokan device dengan akun.
- HTTP 403: periksa role, kepemilikan kelas/NIM, status final, jam akses, atau token service dan scope.
- Finalisasi mengembalikan HTTP 409: lengkapi semua nilai kelas terlebih dahulu.
- Finalisasi mengembalikan HTTP 202: nilai sudah final, tetapi sinkronisasi masih pending; pastikan Gateway dan Transcript Service aktif agar worker dapat mencoba ulang.
- `SQLITE_BUSY` atau lock: pastikan hanya proses yang diperlukan berjalan dan hentikan service dengan Ctrl+C agar koneksi tertutup dengan baik.

## Catatan desain

Ketiga aplikasi menggunakan file SQLite yang sama. Ini menyederhanakan praktikum satu mesin, tetapi berbagi file database tidak memberi isolasi keamanan antar-service: proses yang dapat membuka file dapat membaca dan mengubah data sesuai izin sistem operasi. Foreign key menjaga konsistensi relasi, bukan otorisasi aplikasi.

README ini merangkum implementasi backend Zero Trust, konfigurasi, cara menjalankan API Gateway, Grade Service, dan Transcript Service, akun serta device demo, endpoint, alur pengujian Postman, dan cakupan pengujian otomatis. Penjelasan mengikuti perilaku dan batasan sistem yang didokumentasikan di atas.
