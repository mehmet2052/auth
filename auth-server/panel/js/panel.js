/**
 * Nexus Auth Panel — Frontend JavaScript (Security-Hardened)
 *
 * Security features:
 *   - Token in sessionStorage (clears on tab close) + memory
 *   - Refresh token in memory only (never persisted)
 *   - CSRF token handling (fetched from server, sent in headers)
 *   - Automatic token refresh before access token expiry
 *   - Request timeout (30s)
 *   - Input sanitization on all user inputs
 *   - Event delegation (no inline handlers — CSP compliance)
 */

const API_BASE = "";
let authToken = null;
let refreshToken = null;  // Memory only — never persisted
let csrfToken = null;
let currentPage = { licenses: 1, logs: 1 };
let isRefreshing = false;
let refreshPromise = null;

// Token expiry tracking (access token = 15 min)
let tokenExpiresAt = 0;
const REFRESH_BUFFER_MS = 60_000; // Refresh 1 min before expiry

// ─────────────────────────────────────────────────────────────────────────────
// Güvenlik Yardımcıları
// ─────────────────────────────────────────────────────────────────────────────

function escapeHtml(text) {
    if (!text) return "";
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

function sanitizeInput(text) {
    if (typeof text !== "string") return "";
    // Strip HTML tags and control characters
    return text.replace(/<[^>]*>/g, "").replace(/[\x00-\x1F\x7F]/g, "").trim();
}

function sanitizeNumber(val, min = 1, max = 100) {
    const n = parseInt(val, 10);
    if (isNaN(n) || n < min) return min;
    if (n > max) return max;
    return n;
}

// ─────────────────────────────────────────────────────────────────────────────
// CSRF Token
// ─────────────────────────────────────────────────────────────────────────────

async function fetchCsrfToken() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/csrf-token`, {
            method: "GET",
            credentials: "same-origin",
        });
        if (res.ok) {
            const data = await res.json();
            csrfToken = data.csrf_token;
        }
    } catch (e) {
        console.warn("CSRF token fetch failed:", e.message);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// API Yardımcıları (with timeout, CSRF, and token refresh)
// ─────────────────────────────────────────────────────────────────────────────

async function apiCall(method, path, body = null, isAdmin = true) {
    // Auto-refresh access token if near expiry
    if (isAdmin && authToken && Date.now() > tokenExpiresAt - REFRESH_BUFFER_MS) {
        await doTokenRefresh();
    }

    const headers = { "Content-Type": "application/json" };
    if (isAdmin && authToken) headers["Authorization"] = `Bearer ${authToken}`;

    // Add CSRF token for state-changing requests
    if (csrfToken && ["POST", "PUT", "DELETE", "PATCH"].includes(method)) {
        headers["X-CSRF-Token"] = csrfToken;
    }

    // Request timeout (30s)
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);

    const opts = { method, headers, signal: controller.signal };
    if (body) opts.body = JSON.stringify(body);

    try {
        const res = await fetch(`${API_BASE}${path}`, opts);
        clearTimeout(timeout);
        const data = await res.json().catch(() => ({}));

        if (!res.ok) {
            // On 403 CSRF error, refetch token and retry once
            if (res.status === 403 && data.detail && data.detail.includes("CSRF")) {
                await fetchCsrfToken();
                headers["X-CSRF-Token"] = csrfToken;
                const retryOpts = { method, headers, signal: controller.signal };
                if (body) retryOpts.body = JSON.stringify(body);
                const retryRes = await fetch(`${API_BASE}${path}`, retryOpts);
                const retryData = await retryRes.json().catch(() => ({}));
                if (!retryRes.ok) throw new Error(retryData.detail || `HTTP ${retryRes.status}`);
                return retryData;
            }
            // On 401, attempt token refresh before logging out
            if (res.status === 401 && refreshToken && !path.includes("/refresh")) {
                const refreshed = await doTokenRefresh();
                if (refreshed) {
                    // Retry the original request with new token
                    return apiCall(method, path, body, isAdmin);
                }
            }
            if (res.status === 401) doLogout();
            throw new Error(data.detail || data.error || `HTTP ${res.status}`);
        }
        return data;
    } catch (e) {
        clearTimeout(timeout);
        if (e.name === "AbortError") {
            throw new Error("İstek zaman aşımına uğradı (30s)");
        }
        throw e;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Token Refresh
// ─────────────────────────────────────────────────────────────────────────────

async function doTokenRefresh() {
    if (!refreshToken) return false;
    if (isRefreshing) return refreshPromise;

    isRefreshing = true;
    refreshPromise = (async () => {
        try {
            const res = await fetch(`${API_BASE}/api/v1/admin/refresh`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ refresh_token: refreshToken }),
            });

            if (!res.ok) {
                doLogout();
                return false;
            }

            const data = await res.json();
            authToken = data.access_token;
            refreshToken = data.refresh_token;  // Rotate — old one revoked server-side
            tokenExpiresAt = Date.now() + 15 * 60 * 1000; // 15 min

            sessionStorage.setItem("nexus_token", authToken);
            return true;
        } catch (e) {
            console.warn("Token refresh failed:", e.message);
            doLogout();
            return false;
        } finally {
            isRefreshing = false;
            refreshPromise = null;
        }
    })();

    return refreshPromise;
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth
// ─────────────────────────────────────────────────────────────────────────────

async function doLogin() {
    const username = sanitizeInput(document.getElementById("login-user").value);
    const password = document.getElementById("login-pass").value;
    const errEl = document.getElementById("login-error");
    errEl.classList.add("hidden");

    if (!username || !password) {
        errEl.textContent = "Kullanıcı adı ve şifre gerekli";
        errEl.classList.remove("hidden");
        return;
    }

    try {
        // Fetch CSRF token before login
        await fetchCsrfToken();

        const data = await apiCall("POST", "/api/v1/admin/login",
            { username, password }, false);

        authToken = data.access_token;
        refreshToken = data.refresh_token || null;  // Memory only
        tokenExpiresAt = Date.now() + 15 * 60 * 1000;

        // Store access token in sessionStorage (clears on tab close)
        sessionStorage.setItem("nexus_token", authToken);

        document.getElementById("admin-name").textContent = escapeHtml(username);
        document.getElementById("login-page").classList.add("hidden");
        document.getElementById("dashboard").classList.remove("hidden");

        // Clear password field
        document.getElementById("login-pass").value = "";

        loadLicenses(1);
    } catch (e) {
        errEl.textContent = e.message;
        errEl.classList.remove("hidden");
    }
}

function doLogout() {
    // Revoke refresh token on server if available
    if (refreshToken) {
        fetch(`${API_BASE}/api/v1/admin/logout`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ refresh_token: refreshToken }),
        }).catch(() => {});
    }

    authToken = null;
    refreshToken = null;
    tokenExpiresAt = 0;
    csrfToken = null;
    sessionStorage.removeItem("nexus_token");
    document.getElementById("dashboard").classList.add("hidden");
    document.getElementById("login-page").classList.remove("hidden");
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-login & Event Binding
// ─────────────────────────────────────────────────────────────────────────────

window.addEventListener("load", () => {
    // Bind all event listeners (CSP compliance — no inline handlers)
    _bindEvents();

    // Check for saved token in sessionStorage
    const saved = sessionStorage.getItem("nexus_token");
    if (saved) {
        authToken = saved;
        tokenExpiresAt = Date.now() + 10 * 60 * 1000; // Assume ~10min remaining
        // Validate token by making a test request
        fetchCsrfToken().then(() => {
            return apiCall("GET", "/api/v1/admin/licenses?page=1&page_size=1");
        }).then(() => {
            document.getElementById("login-page").classList.add("hidden");
            document.getElementById("dashboard").classList.remove("hidden");
            loadLicenses(1);
        }).catch(() => {
            authToken = null;
            sessionStorage.removeItem("nexus_token");
        });
    }
});

function _bindEvents() {
    // Login button
    const btnLogin = document.getElementById("btn-login");
    if (btnLogin) btnLogin.addEventListener("click", doLogin);

    // Logout button
    const btnLogout = document.getElementById("btn-logout");
    if (btnLogout) btnLogout.addEventListener("click", doLogout);

    // Enter key on password field
    const loginPass = document.getElementById("login-pass");
    if (loginPass) loginPass.addEventListener("keydown", e => {
        if (e.key === "Enter") doLogin();
    });

    // Sidebar navigation (event delegation)
    document.querySelectorAll(".sidebar a[data-page]").forEach(a => {
        a.addEventListener("click", e => {
            e.preventDefault();
            showPage(a.dataset.page, a);
        });
    });

    // Create license button
    const btnCreateOpen = document.getElementById("btn-create-open");
    if (btnCreateOpen) btnCreateOpen.addEventListener("click", openCreateModal);

    // Create license submit
    const btnCreateSubmit = document.getElementById("btn-create-submit");
    if (btnCreateSubmit) btnCreateSubmit.addEventListener("click", doCreateLicense);

    // HWID reset submit
    const btnHwidReset = document.getElementById("btn-hwid-reset");
    if (btnHwidReset) btnHwidReset.addEventListener("click", doHwidReset);

    // Close modal buttons (data-close attribute)
    document.querySelectorAll("[data-close]").forEach(btn => {
        btn.addEventListener("click", () => closeModal(btn.dataset.close));
    });

    // Filter status dropdown
    const filterStatus = document.getElementById("filter-status");
    if (filterStatus) filterStatus.addEventListener("change", () => loadLicenses(1));

    // Event delegation for dynamically rendered action buttons
    const licTbody = document.getElementById("license-tbody");
    if (licTbody) {
        licTbody.addEventListener("click", e => {
            const btn = e.target.closest("[data-action]");
            if (!btn) return;
            const action = btn.dataset.action;
            const id = btn.dataset.id;
            if (action === "hwid-reset") openHwidModal(id);
            else if (action === "suspend") suspendLic(id);
            else if (action === "revoke") revokeLic(id);
        });
    }
}

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

    const data = await apiCall("GET", url);
    renderLicenses(data.items);
    renderPagination("lic-pagination", data.page, data.total, 20, loadLicenses);
    renderStats(data.items, data.total);
}

function renderLicenses(items) {
    const tbody = document.getElementById("license-tbody");
    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#555;padding:24px">Lisans bulunamadı</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(lic => `
        <tr>
            <td style="font-family:monospace;font-size:11px">${escapeHtml(lic.key)}</td>
            <td>${escapeHtml(licTypeLabel(lic.license_type))}</td>
            <td><span class="badge badge-${escapeHtml(lic.status)}">${escapeHtml(lic.status)}</span></td>
            <td>${escapeHtml(fmtDate(lic.created_at))}</td>
            <td>${lic.activated_at ? escapeHtml(fmtDate(lic.activated_at)) : '-'}</td>
            <td>${lic.expires_at ? escapeHtml(fmtDate(lic.expires_at)) : '<span style="color:#9c27b0">Sınırsız</span>'}</td>
            <td>
                <button class="btn-sm" style="background:#2d1a50;color:#aaa;margin-right:4px"
                    data-action="hwid-reset" data-id="${escapeHtml(lic.id)}">HWID Sıfırla</button>
                ${lic.status !== 'suspended' && lic.status !== 'revoked' ?
                    `<button class="btn-sm" style="background:#3a1a00;color:#ff9800;margin-right:4px"
                        data-action="suspend" data-id="${escapeHtml(lic.id)}">Askıya Al</button>` : ''}
                ${lic.status !== 'revoked' ?
                    `<button class="btn-sm" style="background:#3a0000;color:#f44336"
                        data-action="revoke" data-id="${escapeHtml(lic.id)}">İptal Et</button>` : ''}
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
        await apiCall("POST", `/api/v1/admin/licenses/${sanitizeInput(id)}/suspend`);
        loadLicenses(currentPage.licenses);
    } catch (e) { alert(e.message); }
}

async function revokeLic(id) {
    if (!confirm("Bu lisansı kalıcı olarak iptal etmek istediğinize emin misiniz?")) return;
    try {
        await apiCall("DELETE", `/api/v1/admin/licenses/${sanitizeInput(id)}`);
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
    const license_type = sanitizeInput(document.getElementById("lic-type").value);
    const count = sanitizeNumber(document.getElementById("lic-count").value, 1, 100);
    const note = sanitizeInput(document.getElementById("lic-note").value) || null;
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
        resultEl.textContent = "Hata: " + escapeHtml(e.message);
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
    const license_id = sanitizeInput(document.getElementById("hwid-license-id").value);
    const reason = sanitizeInput(document.getElementById("hwid-reason").value) || null;

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
    const data = await apiCall("GET",
        `/api/v1/admin/logs?page=${page}&page_size=50`);
    renderLogs(data.items);
    renderPagination("log-pagination", data.page, data.total, 50, loadLogs);
}

function renderLogs(items) {
    const tbody = document.getElementById("logs-tbody");
    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#555;padding:24px">Log bulunamadı</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(log => `
        <tr>
            <td style="font-size:11px;color:#888">${escapeHtml(fmtDate(log.created_at))}</td>
            <td><span style="color:${actionColor(log.action)};font-size:12px">${escapeHtml(log.action)}</span></td>
            <td style="font-size:12px;color:#888">${escapeHtml(log.ip_address || '-')}</td>
            <td style="font-family:monospace;font-size:11px;color:#888">
                ${log.license_id ? escapeHtml(log.license_id.substring(0, 8)) + '...' : '-'}
            </td>
            <td style="font-size:12px;color:#aaa">${escapeHtml(log.detail || '-')}</td>
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
    el.innerHTML = "";

    const prevBtn = document.createElement("button");
    prevBtn.textContent = "← Önceki";
    prevBtn.disabled = page <= 1;
    prevBtn.addEventListener("click", () => loadFn(page - 1));

    const info = document.createElement("span");
    info.className = "page-info";
    info.textContent = `${page} / ${totalPages || 1}`;

    const nextBtn = document.createElement("button");
    nextBtn.textContent = "Sonraki →";
    nextBtn.disabled = page >= totalPages;
    nextBtn.addEventListener("click", () => loadFn(page + 1));

    el.appendChild(prevBtn);
    el.appendChild(info);
    el.appendChild(nextBtn);
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
