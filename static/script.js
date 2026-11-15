let currentType = "url";

function changeType(type) {
    currentType = type;

    document.querySelectorAll(".tab").forEach(tab => {
        tab.classList.toggle(
            "active",
            tab.dataset.type === type
        );
    });

    const input = document.getElementById("scanInput");
    const label = document.getElementById("inputLabel");
    const hint = document.getElementById("inputHint");

    if (type === "url") {
        label.textContent = "Website URL";
        input.placeholder = "https://example.com";
        input.rows = 3;
        hint.textContent = "Masukkan URL lengkap termasuk https://";
    } else {
        label.textContent = "Email or Message Content";
        input.placeholder = "Tempel teks email atau pesan mencurigakan di sini...";
        input.rows = 7;
        hint.textContent = "Tempel teks yang ingin diperiksa.";
    }

    const resultCard = document.getElementById("result");
    if (resultCard) {
        resultCard.classList.add("hidden");
    }
}


async function startScan() {
    const input = document.getElementById("scanInput");
    const value = input.value.trim();
    const button = document.getElementById("scanButton");

    if (!value) {
        alert("Silakan masukkan URL atau teks terlebih dahulu.");
        return;
    }

    button.disabled = true;
    button.textContent = "Analyzing...";

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                type: currentType,
                value: value
            })
        });

        const contentType = response.headers.get("content-type") || "";
        let data;

        if (contentType.includes("application/json")) {
            data = await response.json();
        } else {
            const errorHtml = await response.text();
            console.error("Non-JSON response from /api/scan:", errorHtml);

            if (response.status === 401) {
                alert("Sesi login Anda telah berakhir. Anda akan diarahkan ke halaman login.");
                window.location.href = "/login";
                return;
            }
            if (response.status === 403) {
                throw new Error("Akses ditolak (403 Forbidden). Permintaan mungkin diblokir oleh WAF / firewall hosting.");
            }
            if (response.status === 502 || response.status === 504) {
                throw new Error(`Server Gateway Error (${response.status}). Proses backend Python sedang tidak aktif.`);
            }
            throw new Error(`Server error (${response.status} ${response.statusText || ''}). Respon server bukan format JSON.`);
        }

        if (!response.ok || !data.success) {
            if (response.status === 401) {
                alert(data.message || "Silakan login kembali.");
                window.location.href = "/login";
                return;
            }
            throw new Error(data.message || "Pemeriksaan scan gagal.");
        }

        displayResult(data.result);
        await loadData();

    } catch (error) {
        alert(error.message);
    } finally {
        button.disabled = false;
        button.textContent = "Analyze Threat →";
    }
}


function displayResult(result) {
    const card = document.getElementById("result");
    const badge = document.getElementById("riskBadge");
    const score = document.getElementById("riskScore");
    const bar = document.getElementById("scoreBar");
    const findings = document.getElementById("findingsList");

    if (!card) return;

    card.classList.remove("hidden");

    if (score) score.textContent = result.score;
    if (badge) {
        badge.textContent = result.level;
        badge.className = "risk-badge";

        if (result.level === "High Risk") {
            badge.classList.add("badge-high");
            if (bar) bar.style.background = "#fb6666";
        } else if (result.level === "Suspicious") {
            badge.classList.add("badge-suspicious");
            if (bar) bar.style.background = "#f5c451";
        } else {
            badge.classList.add("badge-safe");
            if (bar) bar.style.background = "#36d399";
        }
    }

    if (bar) {
        bar.style.width = Math.min(Math.max(result.score, 0), 100) + "%";
    }

    if (findings) {
        findings.innerHTML = "";
        (result.findings || []).forEach(item => {
            const li = document.createElement("li");
            li.textContent = item;
            findings.appendChild(li);
        });
    }

    card.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });
}


async function loadData() {
    try {
        const statsResponse = await fetch("/api/stats");
        if (statsResponse.ok && (statsResponse.headers.get("content-type") || "").includes("application/json")) {
            const stats = await statsResponse.json();
            const totalEl = document.getElementById("totalScans");
            const highEl = document.getElementById("highRisk");
            const suspEl = document.getElementById("suspicious");
            const safeEl = document.getElementById("safeScans");

            if (totalEl) totalEl.textContent = stats.total ?? 0;
            if (highEl) highEl.textContent = stats.high ?? 0;
            if (suspEl) suspEl.textContent = stats.suspicious ?? 0;
            if (safeEl) safeEl.textContent = stats.safe ?? 0;
        }

        const historyResponse = await fetch("/api/history");
        const body = document.getElementById("historyBody");
        if (body && historyResponse.ok && (historyResponse.headers.get("content-type") || "").includes("application/json")) {
            const history = await historyResponse.json();
            body.innerHTML = "";

            if (!Array.isArray(history) || history.length === 0) {
                body.innerHTML = `
                    <tr>
                        <td colspan="5">Belum ada riwayat pemeriksaan.</td>
                    </tr>
                `;
                return;
            }

            history.forEach(item => {
                const tr = document.createElement("tr");
                const values = [
                    (item.scan_type || "").toUpperCase(),
                    item.input_value || "-",
                    (item.risk_score ?? 0) + "/100",
                    item.risk_level || "Unknown",
                    item.created_at || "-"
                ];

                values.forEach(value => {
                    const td = document.createElement("td");
                    td.textContent = value;
                    tr.appendChild(td);
                });

                body.appendChild(tr);
            });
        }
    } catch (error) {
        console.error("Gagal memuat data statistik/history:", error);
    }
}


document.addEventListener("DOMContentLoaded", () => {
    loadData();
});
