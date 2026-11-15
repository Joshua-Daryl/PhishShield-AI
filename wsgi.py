import os
from app import app, init_db

# Inisialisasi database sebelum server mulai menerima request
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
