
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

        hint.textContent =
            "Enter the complete URL including https://";

    } else {

        label.textContent = "Email or Message Content";

        input.placeholder =
            "Paste suspicious email or message here...";

        input.rows = 7;

        hint.textContent =
            "Paste the text you want to analyze.";
    }

    document.getElementById("result").classList.add("hidden");
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

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.message || "Scan gagal.");
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

    card.classList.remove("hidden");

    score.textContent = result.score;

    badge.textContent = result.level;

    badge.className = "risk-badge";

    if (result.level === "High Risk") {

        badge.classList.add("badge-high");

        bar.style.background = "#fb6666";

    } else if (result.level === "Suspicious") {

        badge.classList.add("badge-suspicious");

        bar.style.background = "#f5c451";

    } else {

        badge.classList.add("badge-safe");

        bar.style.background = "#36d399";

    }

    bar.style.width = result.score + "%";

    findings.innerHTML = "";

    result.findings.forEach(item => {

        const li = document.createElement("li");

        li.textContent = item;

        findings.appendChild(li);

    });

    card.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });
}


async function loadData() {

    try {

        const statsResponse = await fetch("/api/stats");

        const stats = await statsResponse.json();

        document.getElementById("totalScans").textContent =
            stats.total;

        document.getElementById("highRisk").textContent =
            stats.high;

        document.getElementById("suspicious").textContent =
            stats.suspicious;

        document.getElementById("safeScans").textContent =
            stats.safe;


        const historyResponse = await fetch("/api/history");

        const history = await historyResponse.json();

        const body = document.getElementById("historyBody");

        body.innerHTML = "";

        if (history.length === 0) {

            body.innerHTML = `
                <tr>
                    <td colspan="5">
                        Belum ada riwayat pemeriksaan.
                    </td>
                </tr>
            `;

            return;
        }

        history.forEach(item => {

            const tr = document.createElement("tr");

            const values = [
                item.scan_type.toUpperCase(),
                item.input_value,
                item.risk_score + "/100",
                item.risk_level,
                item.created_at
            ];

            values.forEach(value => {

                const td = document.createElement("td");

                td.textContent = value;

                tr.appendChild(td);

            });

            body.appendChild(tr);

        });

    } catch (error) {

        console.error("Gagal memuat data:", error);

    }
}


document.addEventListener("DOMContentLoaded", () => {

    loadData();

});
