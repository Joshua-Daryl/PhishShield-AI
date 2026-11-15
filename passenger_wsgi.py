import sys
import os

# Set root direktori aplikasi
project_dir = os.path.dirname(os.path.abspath(__file__))
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

# Integrasi virtual environment jika ada folder venv
venv_bin = os.path.join(project_dir, "venv", "bin")
if os.path.exists(venv_bin):
    activate_this = os.path.join(venv_bin, "activate_this.py")
    if os.path.exists(activate_this):
        with open(activate_this) as f:
            exec(f.read(), dict(__file__=activate_this))

from app import app as application, init_db

# Pastikan inisialisasi database dijalankan
init_db()
