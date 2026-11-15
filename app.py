import os
import re
import shutil
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent

# Inisialisasi Flask dengan path absolut agar Vercel & serverless dapat menemukan template & static
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

# Handle reverse proxy headers (Cloudflare, Vercel, Nginx, cPanel)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "phishshield-secret-key-change-me"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() in ("true", "1", "yes"),
    PERMANENT_SESSION_LIFETIME=86400,
)


# ==========================================
# DATABASE HELPER (SUPPORTS VERCEL SERVERLESS)
# ==========================================

def get_database_path():
    is_serverless = bool(
        os.environ.get("VERCEL")
        or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    )

    if not is_serverless:
        # Periksa apakah direktori root memiliki izin tulis
        try:
            test_file = BASE_DIR / ".write_test"
            test_file.touch()
            test_file.unlink()
        except Exception:
            is_serverless = True

    if is_serverless:
        # Vercel serverless hanya mengizinkan tulis di /tmp
        tmp_db = Path("/tmp/phishshield.db")
        seed_db = BASE_DIR / "phishshield.db"
        if not tmp_db.exists() and seed_db.exists():
            try:
                shutil.copyfile(seed_db, tmp_db)
            except Exception as e:
                app.logger.warning(f"Gagal menyalin seed db ke /tmp: {e}")
        return str(tmp_db)

    return os.environ.get("DATABASE_PATH", str(BASE_DIR / "phishshield.db"))


DATABASE = get_database_path()


def get_db():
    current_db = get_database_path()
    db_file = Path(current_db)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(current_db, timeout=30.0)
    conn.row_factory = sqlite3.Row

    try:
        if os.environ.get("VERCEL"):
            conn.execute("PRAGMA journal_mode=MEMORY;")
        else:
            conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        pass

    return conn


def init_db():
    try:
        conn = get_db()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    input_value TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    findings TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by INTEGER
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
                )
            """)

            # Migration check: make sure created_by column exists
            columns = [column[1] for column in conn.execute("PRAGMA table_info(scan_history)").fetchall()]
            if "created_by" not in columns:
                conn.execute("ALTER TABLE scan_history ADD COLUMN created_by INTEGER")

            admin_exists = conn.execute(
                "SELECT 1 FROM users WHERE username = 'admin'"
            ).fetchone()
            if not admin_exists:
                conn.execute(
                    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    ("admin", generate_password_hash("admin123"), "admin")
                )

            user_exists = conn.execute(
                "SELECT 1 FROM users WHERE username = 'user'"
            ).fetchone()
            if not user_exists:
                conn.execute(
                    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    ("user", generate_password_hash("user123"), "user")
                )

            conn.commit()
        finally:
            conn.close()

        # Set permission jika di lingkungan Linux biasa (bukan serverless)
        if os.name != "nt" and not os.environ.get("VERCEL"):
            try:
                target_db = get_database_path()
                if os.path.exists(target_db):
                    os.chmod(target_db, 0o666)
            except Exception:
                pass
    except Exception as e:
        app.logger.warning(f"Peringatan init_db: {e}")


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    try:
        conn = get_db()
        try:
            user = conn.execute(
                "SELECT * FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()
            return dict(user) if user else None
        finally:
            conn.close()
    except Exception as e:
        app.logger.error(f"Error mengambil user login: {e}")
        return None


def require_login(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))

        user = get_current_user()
        if not user:
            session.clear()
            return redirect(url_for("login"))

        return view_func(*args, **kwargs)

    return wrapper


def require_role(role):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                session.clear()
                return redirect(url_for("login"))

            if user["role"] != role:
                if user["role"] == "admin":
                    return redirect(url_for("admin_dashboard"))
                return redirect(url_for("user_dashboard"))

            return view_func(*args, **kwargs)

        return wrapper

    return decorator


# ==========================================
# PHISHING DETECTION ENGINE
# ==========================================

def analyze_url(value):
    value = value.strip()

    if len(value) > 2048:
        raise ValueError("URL terlalu panjang (maksimal 2048 karakter).")

    if not value:
        raise ValueError("URL tidak boleh kosong.")

    if not re.match(r"^https?://", value, re.I):
        raise ValueError("Masukkan URL lengkap dengan http:// atau https://")

    parsed = urlparse(value)
    host = parsed.hostname

    if not host:
        raise ValueError("Format URL tidak valid.")

    if parsed.username or parsed.password:
        raise ValueError("URL dengan informasi login tidak diterima.")

    score = 0
    findings = []

    def add_finding(points, message):
        nonlocal score
        score += points
        findings.append(message)

    ipv4_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, host):
        add_finding(25, "URL menggunakan alamat IP secara langsung.")

    if parsed.scheme != "https":
        add_finding(10, "URL tidak menggunakan protokol HTTPS.")

    if "@" in value:
        add_finding(20, "URL mengandung karakter @.")

    if host.startswith("xn--") or ".xn--" in host:
        add_finding(20, "Domain menggunakan format Punycode.")

    if len(host.split(".")) > 4:
        add_finding(15, "Domain memiliki jumlah subdomain yang tidak biasa.")

    if len(value) > 100:
        add_finding(10, "URL memiliki panjang yang tidak biasa.")

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "password",
        "account",
        "secure",
        "update",
        "banking",
        "wallet",
        "credential",
        "confirm",
    ]

    lower_url = value.lower()
    detected_words = [word for word in suspicious_words if word in lower_url]

    if detected_words:
        add_finding(
            min(20, len(detected_words) * 5),
            "URL mengandung kata yang sering ditemukan pada halaman phishing: "
            + ", ".join(detected_words),
        )

    shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"]
    if host.lower() in shorteners:
        add_finding(15, "URL menggunakan layanan pemendek tautan.")

    return calculate_result(score, findings)


def analyze_email(value):
    value = value.strip()

    if len(value) > 10000:
        raise ValueError("Teks email terlalu panjang.")

    if not value:
        raise ValueError("Teks email tidak boleh kosong.")

    score = 0
    findings = []

    def add_finding(points, message):
        nonlocal score
        score += points
        findings.append(message)

    suspicious_phrases = {
        "verify your account": 20,
        "account suspended": 25,
        "password expired": 20,
        "click here": 10,
        "urgent action": 20,
        "confirm your identity": 20,
        "claim your prize": 25,
        "limited time": 10,
        "unusual activity": 15,
        "reset your password": 15,
        "send your password": 30,
    }

    lower_text = value.lower()
    for phrase, points in suspicious_phrases.items():
        if phrase in lower_text:
            add_finding(points, f"Ditemukan frasa mencurigakan: '{phrase}'.")

    sensitive_words = ["password", "otp", "pin", "credit card", "bank account"]
    if any(word in lower_text for word in sensitive_words):
        add_finding(
            15,
            "Pesan menyebutkan informasi sensitif seperti password, OTP, PIN, atau data perbankan.",
        )

    urls = re.findall(r"https?://[^\s<>\"']+", value, re.I)
    if urls:
        add_finding(
            10,
            f"Pesan mengandung {len(urls)} tautan yang perlu diperiksa lebih lanjut.",
        )

    urgency_words = [
        "immediately",
        "within 24 hours",
        "right now",
        "segera",
        "secepatnya",
        "sekarang juga",
    ]

    if any(word in lower_text for word in urgency_words):
        add_finding(
            15,
            "Pesan menggunakan bahasa yang memberikan tekanan atau urgensi.",
        )

    return calculate_result(score, findings)


# ==========================================
# RISK CALCULATION
# ==========================================

def calculate_result(score, findings):
    score = min(score, 100)

    if score >= 50:
        level = "High Risk"
    elif score >= 25:
        level = "Suspicious"
    else:
        level = "Safe"

    if not findings:
        findings.append(
            "Tidak ditemukan indikator mencurigakan berdasarkan pemeriksaan yang tersedia."
        )

    return {"score": score, "level": level, "findings": findings}


# ==========================================
# SAVE SCAN HISTORY
# ==========================================

def save_history(scan_type, input_value, result, user_id=None):
    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO scan_history (
                scan_type,
                input_value,
                risk_score,
                risk_level,
                findings,
                created_at,
                created_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_type,
                input_value[:1000],
                result["score"],
                result["level"],
                " | ".join(result["findings"]),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                user_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ==========================================
# STATIC ASSETS ROUTE (FALLBACK FOR VERCEL)
# ==========================================

@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory(str(BASE_DIR / "static"), filename)


# ==========================================
# AUTH ROUTES
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("login.html", error="Username dan password wajib diisi.")

        try:
            conn = get_db()
            try:
                user = conn.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (username,)
                ).fetchone()
            finally:
                conn.close()

            if user and check_password_hash(user["password"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                session["username"] = user["username"]

                if user["role"] == "admin":
                    return redirect(url_for("admin_dashboard"))
                return redirect(url_for("user_dashboard"))

            return render_template("login.html", error="Username atau password salah.")
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            return render_template("login.html", error=f"Terjadi kesalahan server saat login: {str(e)}")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    if user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("user_dashboard"))


@app.route("/admin")
@require_role("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html", username=session.get("username", "admin"))


@app.route("/user")
@require_role("user")
def user_dashboard():
    return render_template("user_dashboard.html", username=session.get("username", "user"))


@app.route("/admin/reset-history", methods=["POST"])
@require_role("admin")
def reset_history():
    try:
        conn = get_db()
        try:
            conn.execute("DELETE FROM scan_history")
            conn.commit()
        finally:
            conn.close()
        return jsonify({"success": True, "message": "Riwayat scan berhasil direset."})
    except Exception as e:
        app.logger.error(f"Gagal mereset history: {e}")
        return jsonify({"success": False, "message": f"Gagal mereset riwayat: {str(e)}"}), 500


# ==========================================
# SCAN API
# ==========================================

@app.route("/api/scan", methods=["POST"])
def scan():
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "message": "Sesi login telah berakhir. Silakan login kembali."}), 401

    data = request.get_json(silent=True)
    if not data and request.form:
        data = request.form.to_dict()
    data = data or {}

    scan_type = str(data.get("type", "")).strip().lower()
    input_value = data.get("value", "")

    if not isinstance(input_value, str) or not input_value.strip():
        return jsonify({"success": False, "message": "Input pemeriksaan tidak boleh kosong."}), 400

    if scan_type not in ["url", "email"]:
        return jsonify({"success": False, "message": "Jenis pemeriksaan tidak valid (URL atau Email)."}), 400

    try:
        if scan_type == "url":
            result = analyze_url(input_value)
        else:
            result = analyze_email(input_value)

        # Simpan ke riwayat database
        try:
            save_history(scan_type, input_value, result, user_id=user["id"])
        except Exception as db_err:
            app.logger.warning(f"Gagal mencatat scan ke riwayat database: {db_err}")

        return jsonify({"success": True, "result": result})

    except ValueError as error:
        return jsonify({"success": False, "message": str(error)}), 400
    except Exception as error:
        app.logger.exception(f"Error sistem saat scan: {error}")
        return jsonify({"success": False, "message": f"Terjadi kesalahan internal server: {str(error)}"}), 500


# ==========================================
# HISTORY & STATS API
# ==========================================

@app.route("/api/history")
def history():
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "message": "Silakan login terlebih dahulu."}), 401

    try:
        conn = get_db()
        try:
            query = "SELECT * FROM scan_history"
            params = []

            if user["role"] == "user":
                query += " WHERE created_by = ?"
                params.append(user["id"])

            query += " ORDER BY id DESC LIMIT 20"
            rows = conn.execute(query, tuple(params)).fetchall()
            return jsonify([dict(row) for row in rows])
        finally:
            conn.close()
    except Exception as e:
        app.logger.error(f"Gagal mengambil riwayat scan: {e}")
        return jsonify([])


@app.route("/api/stats")
def stats():
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "message": "Silakan login terlebih dahulu."}), 401

    try:
        conn = get_db()
        try:
            query = "SELECT COUNT(*) FROM scan_history"
            params = []
            if user["role"] == "user":
                query += " WHERE created_by = ?"
                params.append(user["id"])

            total = conn.execute(query, tuple(params)).fetchone()[0]

            high_query = "SELECT COUNT(*) FROM scan_history WHERE risk_level = 'High Risk'"
            suspicious_query = "SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Suspicious'"
            safe_query = "SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Safe'"

            if user["role"] == "user":
                high_query += " AND created_by = ?"
                suspicious_query += " AND created_by = ?"
                safe_query += " AND created_by = ?"
                params = [user["id"]]

            high = conn.execute(high_query, tuple(params)).fetchone()[0]
            suspicious = conn.execute(suspicious_query, tuple(params)).fetchone()[0]
            safe = conn.execute(safe_query, tuple(params)).fetchone()[0]

            return jsonify({
                "total": total,
                "high": high,
                "suspicious": suspicious,
                "safe": safe,
            })
        finally:
            conn.close()
    except Exception as e:
        app.logger.error(f"Gagal mengambil statistik: {e}")
        return jsonify({"total": 0, "high": 0, "suspicious": 0, "safe": 0})


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "PhishShield AI",
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }), 200


# ==========================================
# GLOBAL ERROR HANDLERS (ALWAYS RETURN JSON FOR API)
# ==========================================

@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(500)
def handle_http_errors(error):
    if request.path.startswith("/api/") or request.path.startswith("/admin/reset-history") or request.is_json:
        code = getattr(error, "code", 500)
        description = getattr(error, "description", "Terjadi kesalahan pada server.")
        return jsonify({"success": False, "message": description}), code
    return error


# Inisialisasi database awal
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    debug = os.environ.get("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")

    print("===================================")
    print("       PHISHSHIELD AI")
    print("===================================")
    print(f"Server running on http://{host}:{port}")

    app.run(host=host, port=port, debug=debug)
