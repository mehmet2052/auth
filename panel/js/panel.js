/**
 * Nexus Auth Panel — Frontend JavaScript
 * API ile iletişim, lisans yönetimi, log görüntüleme.
 */

const API_BASE = "https://auth-71s4.onrender.com";
let authToken = null;
let currentPage = { licenses: 1, logs: 1 };

// ─────────────────────────────────────────────────────────────────────────────
// API Yardımcıları
// ─────────────────────────────────────────────────────────────────────────────

async function apiCall(method, path, body = null, isAdmin = true) {
    const headers = { "Content-Type": "application/json" };
    if (isAdmin && authToken) headers["Authorization"] = `Bearer ${authToken}`;

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(`${API_BASE}${path}`, opts);
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
        throw new Error(data.detail || data.error || `HTTP ${res.status}`);
    }
    return data;
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth
// ─────────────────────────────────────────────────────────────────────────────

async function doLogin() {
    const username = document.getElementById("login-user").value.trim();
    const password = document.getElementById("login-pass").value;
    const errEl = document.getElementById("login-error");
    errEl.classList.add("hidden");

    if (!username || !password) {
        errEl.textContent = "Kullanıcı adı ve şifre gerekli";
        errEl.classList.remove("hidden");
        return;
    }

    try {
        const data = await apiCall("POST", "/api/v1/admin/login",
            { username, password }, false);

        authToken = data.access_token;
        localStorage.setItem("nexus_token", authToken);

        document.getElementById("admin-name").textContent = username;
        document.getElementById("login-page").classList.add("hidden");
        document.getElementById("dashboard").classList.remove("hidden");

        loadLicenses(1);
    } catch (e) {
        errEl.textContent = e.message;
        errEl.classList.remove("hidden");
    }
}

function doLogout() {
    authToken = null;
    localStorage.removeItem("nexus_token");
    document.getElementById("dashboard").classList.add("hidden");
    document.getElementById("login-page").classList.remove("hidden");
}

// Auto-login tokeni varsa
window.addEventListener("load", () => {
    const saved = localStorage.getItem("nexus_token");
    if (saved) {
        authToken = saved;
        document.getElementById("login-page").classList.add("hidden");
        document.getElementById("dashboard").classList.remove("hidden");
        loadLicenses(1);
    }

    // Enter tuşu ile login
    document.getElementById("login-pass").addEventListener("keydown", e => {
        if (e.key === "Enter") doLogin();
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Navigasyon
// ─────────────────────────────────────────────────────────────────────────────

function showPage(name, el) {
    document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
    document.querySelectorAll(".sidebar a").forEach(a => a.classList.remove("active"));
    document.getElementById(`page-${name}`).classList.add("active");
    el.classList.add("active");

    if (name === "logs") loadLogs(1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Lisanslar
// ─────────────────────────────────────────────────────────────────────────────

async function loadLicenses(page = 1) {
    currentPage.licenses = page;
    const status = document.getElementById("filter-status").value;
    let url = `/api/v1/admin/licenses?page=${page}&page_size=20`;
    if (status) url += `&status_filter=${status}`;

    try {
        const data = await apiCall("GET", url);
        renderLicenses(data.items);
        renderPagination("lic-pagination", data.page, data.total, 20, loadLicenses);
        renderStats(data.items, data.total);
    } catch (e) {
        if (e.message.includes("401")) doLogout();
    }
}

function renderLicenses(items) {
    const tbody = document.getElementById("license-tbody");
    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#555;padding:24px">Lisans bulunamadı</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(lic => `
        <tr>
            <td style="font-family:monospace;font-size:11px">${lic.key}</td>
            <td>${licTypeLabel(lic.license_type)}</td>
            <td><span class="badge badge-${lic.status}">${lic.status}</span></td>
            <td>${fmtDate(lic.created_at)}</td>
            <td>${lic.activated_at ? fmtDate(lic.activated_at) : '-'}</td>
            <td>${lic.expires_at ? fmtDate(lic.expires_at) : '<span style="color:#9c27b0">Sınırsız</span>'}</td>
            <td>
                <button class="btn-sm" style="background:#2d1a50;color:#aaa;margin-right:4px"
                    onclick="openHwidModal('${lic.id}')">HWID Sıfırla</button>
                ${lic.status !== 'suspended' && lic.status !== 'revoked' ?
                    `<button class="btn-sm" style="background:#3a1a00;color:#ff9800;margin-right:4px"
                        onclick="suspendLic('${lic.id}')">Askıya Al</button>` : ''}
                ${lic.status !== 'revoked' ?
                    `<button class="btn-sm" style="background:#3a0000;color:#f44336"
                        onclick="revokeLic('${lic.id}')">İptal Et</button>` : ''}
            </td>
        </tr>
    `).join("");
}

function renderStats(items, total) {
    const counts = {};
    items.forEach(i => counts[i.status] = (counts[i.status] || 0) + 1);
    document.getElementById("stats-grid").innerHTML = `
        <div class="stat-card"><div class="label">Toplam (Bu Sayfa)</div><div class="value">${items.length}</div></div>
        <div class="stat-card"><div class="label">Aktif</div><div class="value" style="color:#4caf50">${counts.active||0}</div></div>
        <div class="stat-card"><div class="label">Kullanımda</div><div class="value" style="color:#2196f3">${counts.used||0}</div></div>
        <div class="stat-card"><div class="label">Süresi Dolmuş</div><div class="value" style="color:#ff9800">${counts.expired||0}</div></div>
        <div class="stat-card"><div class="label">Toplam Kayıt</div><div class="value" style="color:#8a48e6">${total}</div></div>
    `;
}

async function suspendLic(id) {
    if (!confirm("Bu lisansı askıya almak istediğinize emin misiniz?")) return;
    try {
        await apiCall("POST", `/api/v1/admin/licenses/${id}/suspend`);
        loadLicenses(currentPage.licenses);
    } catch (e) { alert(e.message); }
}

async function revokeLic(id) {
    if (!confirm("Bu lisansı kalıcı olarak iptal etmek istediğinize emin misiniz?")) return;
    try {
        await apiCall("DELETE", `/api/v1/admin/licenses/${id}`);
        loadLicenses(currentPage.licenses);
    } catch (e) { alert(e.message); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lisans Oluşturma
// ─────────────────────────────────────────────────────────────────────────────

function openCreateModal() {
    document.getElementById("create-result").textContent = "";
    document.getElementById("create-modal").classList.remove("hidden");
}

async function doCreateLicense() {
    const license_type = document.getElementById("lic-type").value;
    const count = parseInt(document.getElementById("lic-count").value);
    const note = document.getElementById("lic-note").value.trim() || null;
    const resultEl = document.getElementById("create-result");

    try {
        const items = await apiCall("POST", "/api/v1/admin/licenses",
            { license_type, count, note });

        resultEl.style.color = "#4caf50";
        resultEl.textContent = `✓ ${items.length} lisans oluşturuldu:\n` +
            items.map(i => i.key).join("\n");

        loadLicenses(1);
    } catch (e) {
        resultEl.style.color = "#f44336";
        resultEl.textContent = "Hata: " + e.message;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HWID Sıfırlama
// ─────────────────────────────────────────────────────────────────────────────

function openHwidModal(licenseId) {
    document.getElementById("hwid-license-id").value = licenseId;
    document.getElementById("hwid-reason").value = "";
    document.getElementById("hwid-modal").classList.remove("hidden");
}

async function doHwidReset() {
    const license_id = document.getElementById("hwid-license-id").value;
    const reason = document.getElementById("hwid-reason").value.trim() || null;

    try {
        await apiCall("POST", "/api/v1/admin/licenses/reset-hwid",
            { license_id, reason });
        closeModal("hwid-modal");
        loadLicenses(currentPage.licenses);
    } catch (e) { alert(e.message); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loglar
// ─────────────────────────────────────────────────────────────────────────────

async function loadLogs(page = 1) {
    currentPage.logs = page;
    try {
        const data = await apiCall("GET",
            `/api/v1/admin/logs?page=${page}&page_size=50`);
        renderLogs(data.items);
        renderPagination("log-pagination", data.page, data.total, 50, loadLogs);
    } catch (e) {
        if (e.message.includes("401")) doLogout();
    }
}

function renderLogs(items) {
    const tbody = document.getElementById("logs-tbody");
    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#555;padding:24px">Log bulunamadı</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(log => `
        <tr>
            <td style="font-size:11px;color:#888">${fmtDate(log.created_at)}</td>
            <td><span style="color:${actionColor(log.action)};font-size:12px">${log.action}</span></td>
            <td style="font-size:12px;color:#888">${log.ip_address || '-'}</td>
            <td style="font-family:monospace;font-size:11px;color:#888">
                ${log.license_id ? log.license_id.substring(0, 8) + '...' : '-'}
            </td>
            <td style="font-size:12px;color:#aaa">${log.detail || '-'}</td>
        </tr>
    `).join("");
}

// ─────────────────────────────────────────────────────────────────────────────
// Yardımcılar
// ─────────────────────────────────────────────────────────────────────────────

function closeModal(id) {
    document.getElementById(id).classList.add("hidden");
}

function renderPagination(elId, page, total, pageSize, loadFn) {
    const totalPages = Math.ceil(total / pageSize);
    const el = document.getElementById(elId);
    el.innerHTML = `
        <button onclick="${loadFn.name}(${page - 1})" ${page <= 1 ? 'disabled' : ''}>← Önceki</button>
        <span class="page-info">${page} / ${totalPages || 1}</span>
        <button onclick="${loadFn.name}(${page + 1})" ${page >= totalPages ? 'disabled' : ''}>Sonraki →</button>
    `;
}

function fmtDate(iso) {
    if (!iso) return '-';
    return new Date(iso).toLocaleString('tr-TR', {
        day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit'
    });
}

function licTypeLabel(t) {
    const labels = { '1d':'1 Gün', '3d':'3 Gün', '7d':'7 Gün',
                     '30d':'30 Gün', 'lifetime':'Sınırsız' };
    return labels[t] || t;
}

function actionColor(action) {
    if (action.includes('success') || action.includes('ok')) return '#4caf50';
    if (action.includes('fail') || action.includes('mismatch')) return '#f44336';
    if (action.includes('expired') || action.includes('suspended')) return '#ff9800';
    if (action.includes('created')) return '#2196f3';
    return '#888';
}
