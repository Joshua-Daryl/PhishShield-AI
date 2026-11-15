# PhishShield AI - Phishing & Threat Detection Platform

PhishShield AI adalah platform web pendeteksi tautan (URL) dan pesan email phishing berbasis heuristik keamanan siber.

## 🚀 Fitur
- **URL Threat Scanner**: Analisis indikator phishing pada tautan web (IP literal, HTTPS, punycode, subdomain mencurigakan, kata kunci berbahaya, pemendek tautan).
- **Email & Message Scanner**: Analisis frasa mencurigakan, urgensi berlebih, permintaan kredensial/OTP, dan tautan berbahaya.
- **Admin Dashboard & Management**: Monitoring statistik total scan, level risiko, dan reset histori.
- **Multi-Role Authentication**: Akses terpisah untuk Administrator dan User.

---

## 🛠️ Instalasi & Menjalankan Lokal

1. Clone repositori:
   ```bash
   git clone https://github.com/Joshua-Daryl/PhishShield-AI.git
   cd PhishShield-AI
   ```

2. Buat dan aktifkan virtual environment:
   ```bash
   python -m venv venv
   # Di Windows:
   venv\Scripts\activate
   # Di Linux/macOS:
   source venv/bin/activate
   ```

3. Install dependensi:
   ```bash
   pip install -r requirements.txt
   ```

4. Jalankan aplikasi:
   ```bash
   python app.py
   ```
   Aplikasi akan berjalan di `http://127.0.0.1:5000`.

---

## 🌐 Panduan Hosting / Deployment

### 1. cPanel (Setup Python App / CloudLinux Passenger)
- Masuk ke cPanel > **Setup Python App** > **Create Application**.
- Pilih versi Python (3.10 / 3.11 / 3.12).
- Masukkan Application Root: direktori folder proyek Anda (misal `phishshield`).
- Masukkan Application URL: subdomain Anda (misal `phishshield.ruangnusa.web.id`).
- Application startup file: `passenger_wsgi.py`.
- Application Entry point: `application`.
- Klik **Create**.
- Buka terminal / SSH cPanel, aktifkan virtualenv, lalu jalankan:
  ```bash
  pip install -r requirements.txt
  chmod 666 phishshield.db
  chmod 775 .
  ```
- Klik **Restart Application**.

### 2. VPS (Ubuntu / Debian dengan Nginx + Gunicorn)
- Jalankan Gunicorn:
  ```bash
  gunicorn -w 2 -b 127.0.0.1:5000 wsgi:app
  ```
- Konfigurasikan reverse proxy Nginx untuk mengarahkan traffic domain ke `http://127.0.0.1:5000`.
- Pastikan izin direktori dan file SQLite dapat ditulis oleh user Nginx/Gunicorn:
  ```bash
  chmod 666 phishshield.db
  chmod 775 .
  ```

### 3. Cloud PaaS (Render / Railway / Koyeb)
- File `Procfile` sudah tersedia (`web: gunicorn wsgi:app`).
- Set environment variable `SECRET_KEY` di dashboard hosting.

---

## 👤 Akun Bawaan (Default Accounts)
- **Admin**: `admin` / `admin123`
- **User**: `user` / `user123`
