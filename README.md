# PcapAnalyzer ForestyTubes

PcapAnalyzer adalah dashboard analisis PCAP/PCAPNG untuk threat hunting jaringan. Project ini mengekstrak flow dari file capture, memberi skor heuristik lokal, lalu dapat meminta bantuan engine AI seperti Codex CLI, Ollama lokal, Groq, atau fallback deterministic lokal.

Fokus deteksi yang didukung meliputi beaconing C2, anomali SMTP/FTP/HTTPS outbound, multi-port C2, download payload mencurigakan, TLS SNI/DNS anomaly, dan pola traffic malware seperti stealer/RAT.

## Fitur Utama

- Upload file `.pcap` atau `.pcapng` dari browser.
- Extractor Go untuk mengubah PCAP menjadi `output.json` flow network.
- Dashboard web untuk melihat status keseluruhan, daftar temuan, metrics, MITRE mapping, dan rekomendasi tindakan.
- Engine selector:
  - `AUTO`: Remote Brain -> Codex CLI -> Groq -> Local.
  - `Codex`: OpenAI Codex CLI lokal.
  - `Groq`: API cloud Groq.
  - `Ollama`: LLM lokal via Ollama.
  - `Local`: heuristik deterministic tanpa AI eksternal.
- Adaptive learning lokal menggunakan baseline dan reputation memory.
- RAG knowledge base sederhana dari `brain/knowledge/*.txt` dan `brain/knowledge/*.md`.

## Kebutuhan

Minimal:

- Go 1.22 atau lebih baru.
- Node.js 18 atau lebih baru.
- npm.
- Browser modern.

Opsional:

- Ollama, jika ingin memakai LLM lokal.
- Codex CLI, jika ingin memakai engine Codex.
- API key Groq, jika ingin memakai Groq.
- Wireshark/tcpdump untuk membuat file capture training atau testing.

## Instalasi dan Menjalankan Project

### Linux/macOS

Jalankan:

```bash
bash setup.sh
```

Script ini akan:

1. Mengecek Go dan Node.js.
2. Build extractor Go menjadi `extractor`.
3. Menjalankan `npm install`.
4. Membuka dashboard di `http://localhost:3000`.
5. Menjalankan server Node.js.

Jika port 3000 sedang dipakai, hentikan proses lama terlebih dahulu atau pakai port lain:

```bash
PORT=3001 bash setup.sh
```

### Windows

Jalankan:

```bat
setup.bat
```

Script Windows akan build `extractor.exe`, install dependency npm, lalu menjalankan server.

## Cara Menggunakan Dashboard

1. Buka `http://localhost:3000`.
2. Pilih engine analisis di kanan atas:
   - Gunakan `Local Heuristic Only` untuk mode offline paling cepat.
   - Gunakan `Ollama` jika ingin memakai LLM lokal.
   - Gunakan `Codex` jika Codex CLI sudah login dan tersedia.
   - Gunakan `AUTO` untuk failover otomatis.
3. Klik `PILIH FILE PCAP` atau area drag-and-drop.
4. Pilih file `.pcap` atau `.pcapng`.
5. Tunggu proses ekstraksi dan analisis selesai.
6. Buka baris temuan untuk melihat detail teknis, flags, reasoning, MITRE mapping, dan rekomendasi.

## Engine AI

### Local Heuristic Only

Mode ini tidak memanggil AI. Semua analisis berasal dari rule lokal, skor heuristik, adaptive baseline, dan reputation memory. Ini pilihan terbaik untuk demo offline, testing cepat, atau lingkungan tanpa credential AI.

### Codex CLI

Engine Codex menjalankan:

```bash
codex exec -m <model> --skip-git-repo-check --ephemeral -
```

Dashboard menyediakan endpoint status:

```bash
curl http://localhost:3000/api/codex-status
```

Endpoint di atas hanya mengecek apakah `codex` tersedia. Untuk memastikan `codex exec` benar-benar bisa menjalankan model:

```bash
curl "http://localhost:3000/api/codex-status?probe=1"
```

Jika berhasil, respons akan berisi:

```json
{
  "status": "ok",
  "exec_status": "ok",
  "model": "gpt-5.5"
}
```

Default model Codex adalah `gpt-5.5`. Bisa dioverride lewat environment variable:

```bash
CODEX_DEFAULT_MODEL=gpt-5.4 bash setup.sh
```

### Groq

Groq dapat digunakan dengan dua cara:

1. Isi API key di input `Groq API Key` pada dashboard.
2. Atau set environment variable:

```bash
GROQ_API_KEY=your_key_here bash setup.sh
```

### Ollama Local AI

Ollama dipakai sebagai LLM lokal melalui endpoint default:

```text
http://localhost:11434
```

Contoh setup:

```bash
ollama pull llama3
ollama serve
```

Lalu di dashboard:

1. Pilih engine `Ollama (Local AI)`.
2. Pastikan URL `http://localhost:11434`.
3. Klik tombol refresh model.
4. Pilih model yang tersedia.
5. Upload PCAP.

Server akan memanggil Ollama lewat endpoint `/api/generate` dengan `format: "json"`.

## Training Lokal

Project ini memiliki dua konsep yang sering tertukar:

- `Training adaptive baseline`: didukung langsung oleh project ini.
- `Fine-tuning bobot LLM`: tidak dilakukan langsung oleh project ini.

Jadi perintah `npm run train` tidak melatih bobot LLM seperti Llama atau Mistral. Perintah tersebut melatih baseline lokal agar engine lebih paham pola traffic normal di lingkunganmu.

### Training Adaptive Baseline

Gunakan traffic normal sebagai baseline. Contoh alur:

```text
Capture traffic normal dengan Wireshark/tcpdump
-> simpan sebagai normal-office.pcapng
-> jalankan extractor
-> hasilnya menjadi output.json
-> jalankan npm run train
-> baseline tersimpan di brain/cache
```

Linux/macOS:

```bash
./extractor normal-office.pcapng
npm run train -- output.json
```

Windows:

```bat
extractor.exe normal-office.pcapng
npm run train -- output.json
```

Output training akan memperbarui:

```text
brain/cache/adaptive_baseline.json
brain/cache/entity_reputation.json
```

Semakin banyak capture normal yang representatif, semakin matang baseline lokalnya.

Contoh workflow yang lebih rapi:

```bash
mkdir -p datasets/baseline
./extractor normal-office-1.pcapng
cp output.json datasets/baseline/normal-office-1.json
npm run train -- datasets/baseline/normal-office-1.json

./extractor normal-office-2.pcapng
cp output.json datasets/baseline/normal-office-2.json
npm run train -- datasets/baseline/normal-office-2.json
```

Shortcut untuk melatih dari `output.json` saat ini:

```bash
npm run train:output
```

### Tips Data Training Baseline

- Gunakan traffic normal dari jaringan yang sama dengan target analisis.
- Pisahkan capture normal dan capture yang sudah diketahui berbahaya.
- Jangan memasukkan traffic malware ke baseline normal, karena dapat membuat engine menganggap pola buruk sebagai kebiasaan normal.
- Ambil beberapa kondisi: jam kerja, idle, browsing normal, DNS normal, update software, dan traffic aplikasi internal.
- Setelah baseline berubah, uji lagi dengan PCAP mencurigakan untuk melihat apakah skor dan reasoning makin stabil.

## Melatih atau Menyesuaikan LLM Lokal

Project ini tidak menyediakan pipeline fine-tuning LLM penuh. Namun ada tiga cara praktis untuk membuat LLM lokal lebih cocok untuk threat hunting PCAP:

### 1. Gunakan Knowledge Base RAG

Tambahkan file `.txt` atau `.md` ke:

```text
brain/knowledge/
```

Contoh:

```text
brain/knowledge/ioc_threat_intel.txt
brain/knowledge/phantomstealer_notes.md
brain/knowledge/internal_network_notes.md
```

Isi file bisa berupa IOC, domain, IP, malware family notes, port yang biasa dipakai, atau aturan SOC internal. Server akan memuat semua file tersebut dan menyisipkannya ke prompt AI.

Ini cara paling aman dan ringan untuk "mengajari" Codex/Ollama/Groq tanpa fine-tuning model.

### 2. Buat Model Ollama Custom dengan Modelfile

Jika ingin model lokal punya system prompt khusus, buat file `Modelfile`:

```text
FROM llama3

PARAMETER temperature 0.2

SYSTEM """
Kamu adalah analis SOC dan threat hunter jaringan.
Balas hanya JSON valid sesuai schema aplikasi.
Fokus pada C2 beaconing, exfiltration, DNS anomaly, TLS SNI anomaly, suspicious SMTP/FTP outbound, RAT, stealer, dan MITRE ATT&CK mapping.
Jangan gunakan markdown fences.
"""
```

Buat model custom:

```bash
ollama create the-eye-threat-hunter -f Modelfile
```

Jalankan Ollama:

```bash
ollama serve
```

Di dashboard, pilih engine `Ollama`, refresh model list, lalu pilih:

```text
the-eye-threat-hunter
```

Catatan: Modelfile bukan fine-tuning bobot model. Ini adalah model wrapper dengan prompt dan parameter khusus.

### 3. Fine-tuning Eksternal

Jika benar-benar ingin fine-tune bobot LLM, lakukan di luar project ini memakai workflow fine-tuning terpisah. Setelah model hasil fine-tune bisa dijalankan oleh Ollama atau server kompatibel Ollama, gunakan namanya di engine `Ollama`.

Dataset yang cocok untuk fine-tuning sebaiknya berisi pasangan:

```text
Input: flow JSON dari output extractor
Output: JSON analisis sesuai schema aplikasi
```

Tetap pastikan output selalu JSON murni, karena backend akan melakukan `JSON.parse()`.

## Knowledge Base Threat Intel

Saat analisis AI berjalan, server memuat semua file dari:

```text
brain/knowledge/
```

Format bebas, selama berupa `.txt` atau `.md`. Contoh isi:

```text
IOC PhantomStealer:
- SMTP outbound port 587 ke host asing dari endpoint non-mail-client
- Archive download -> JS execution -> outbound C2
- Reverse base64-like beaconing dengan interval stabil
```

Knowledge base ini dipakai untuk memperkaya prompt AI, bukan mengganti rule lokal.

## Endpoint API

Health check:

```bash
curl http://localhost:3000/api/health
```

Status Codex ringan:

```bash
curl http://localhost:3000/api/codex-status
```

Probe Codex penuh:

```bash
curl "http://localhost:3000/api/codex-status?probe=1"
```

List model Ollama:

```bash
curl "http://localhost:3000/api/ollama-models?url=http://localhost:11434"
```

Upload PCAP dari CLI:

```bash
curl -F "pcapFile=@sample.pcapng" \
  -H "x-engine: local" \
  http://localhost:3000/api/upload
```

Contoh upload dengan Ollama:

```bash
curl -F "pcapFile=@sample.pcapng" \
  -H "x-engine: ollama" \
  -H "x-ollama-url: http://localhost:11434" \
  -H "x-ollama-model: llama3" \
  http://localhost:3000/api/upload
```

Contoh upload dengan Codex:

```bash
curl -F "pcapFile=@sample.pcapng" \
  -H "x-engine: codex" \
  -H "x-codex-model: gpt-5.5" \
  http://localhost:3000/api/upload
```

## Struktur Project

```text
.
|-- main.go                  # Extractor PCAP/PCAPNG ke output.json
|-- server.js                # API server dan engine selector
|-- index.html               # Dashboard web
|-- setup.sh                 # Setup Linux/macOS
|-- setup.bat                # Setup Windows
|-- train-baseline.js        # Training adaptive baseline lokal
|-- core/                    # Adaptive detection pipeline
|-- brain/knowledge/         # RAG threat intel lokal
|-- brain/cache/             # Baseline dan reputation memory
`-- uploads/                 # File upload sementara
```

## Troubleshooting

### Tombol pilih file tidak membuka file picker

Reload browser. File input diposisikan di luar `dropZone`, sehingga tetap bisa dipakai walaupun area upload utama disembunyikan setelah analisis.

### Port 3000 sedang dipakai

Cek proses:

```bash
ss -ltnp | grep 3000
```

Jalankan di port lain:

```bash
PORT=3001 bash setup.sh
```

### Codex kuning atau merah

Kuning berarti status sedang dicek atau hanya binary `codex` yang terdeteksi. Gunakan probe penuh:

```bash
curl "http://localhost:3000/api/codex-status?probe=1"
```

Jika gagal, cek:

- Codex CLI sudah terinstall.
- Sudah login ke Codex.
- Model yang dipilih didukung akun Codex.
- Environment memiliki akses network yang diperlukan.

### Ollama tidak muncul modelnya

Pastikan Ollama berjalan:

```bash
ollama serve
```

Cek model:

```bash
ollama list
```

Pull model jika belum ada:

```bash
ollama pull llama3
```

### Output AI gagal diparse

Backend mengharapkan JSON murni. Pastikan model lokal tidak membalas markdown seperti:

````text
```json
...
```
````

Gunakan system prompt atau Modelfile yang memaksa output JSON murni.

## Script npm

```bash
npm start            # Menjalankan adaptive-start.js
npm run train        # Training baseline dari output.json atau file argumen
npm run train:output # Training baseline dari output.json
npm test             # Validasi sintaks file utama
```
