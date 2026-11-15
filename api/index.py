import os
import sys
from pathlib import Path

# Tambahkan root path project agar app.py dan modul lainnya dapat diimport
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app import app, init_db

# Pastikan inisialisasi awal database dijalankan (di /tmp jika di Vercel)
init_db()

# Vercel Serverless Function entrypoint
# Objek 'app' akan dijalankan oleh @vercel/python WSGI runner
