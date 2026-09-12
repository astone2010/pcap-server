"use strict";

const API = "";
let currentUser = null;
let activeServers = [];
// Whether this page reached the server over a connection a capture may cross.
let secureTransport = true;
let savedServers = [];
let captures = [];
let viewingCaptureId = null;
let selectedPacketRow = null;

// --- helpers ---

async function api(path, options = {}) {
    const res = await fetch(path, {
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", ...(options.headers || {}) },
        ...options,
    });
    if (!res.ok) {
        let detail = "";
        try {
            detail = (await res.json()).detail;
        } catch {
            detail = res.statusText;
        }
        // A structured https_required refusal is shown in full, where the user
        // is looking, rather than reduced to "403" in a corner.
        if (detail && typeof detail === "object" && detail.code === "https_required") {
            showHttpsRefusal(detail);
            const err = new Error(detail.reason);
            err.httpsRequired = true;
            throw err;
        }
        if (detail && typeof detail === "object" && detail.code === "self_capture") {
            showBlockingAlert("Cannot capture from this machine", detail.reason,
                              detail.explanation);
            throw new Error(detail.reason);
        }
        throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    return res.status === 204 ? null : res.json();
}

// A blocked action must say so plainly. This puts the reason on screen, scrolls
// it into view and keeps it until dismissed -- an alert() is easy to click away
// without reading, and a console error is invisible.
function showHttpsRefusal(detail) {
    showBlockingAlert("Blocked: this needs an encrypted connection",
                      detail.reason || "", detail.remedy || "");
}

// One visible, dismissible panel for anything the server refuses on safety
// grounds. Deliberately not an alert(): this needs to be readable and to stay
// on screen while the user reads it.
function showBlockingAlert(title, reason, detail) {
    let box = $("https-refusal");
    if (!box) {
        box = document.createElement("div");
        box.id = "https-refusal";
        box.className = "https-refusal";
        document.body.prepend(box);
    }
    box.textContent = "";

    const titleEl = document.createElement("div");
    titleEl.className = "https-refusal-title";
    titleEl.textContent = title;

    const reasonEl = document.createElement("div");
    reasonEl.textContent = reason;

    const detailEl = document.createElement("div");
    detailEl.className = "https-refusal-remedy";
    detailEl.textContent = detail;

    const close = document.createElement("button");
    close.className = "https-refusal-close";
    close.textContent = "Dismiss";
    close.onclick = () => { box.hidden = true; };

    box.append(titleEl, reasonEl, detailEl, close);
    box.hidden = false;
    box.scrollIntoView({ behavior: "smooth", block: "center" });
}


function show(id) { document.getElementById(id).hidden = false; }
function hide(id) { document.getElementById(id).hidden = true; }
function $(id) { return document.getElementById(id); }
const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

// Quotes must be escaped too — this value gets interpolated into attributes.
function escHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

// --- theme ---

function currentTheme() {
    return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    const btn = $("theme-toggle");
    if (btn) {
        btn.textContent = theme === "light" ? "Dark" : "Light";
        btn.title = `Switch to the ${theme === "light" ? "dark" : "light"} theme`;
    }
    try {
        localStorage.setItem("theme", theme);
    } catch (e) {
        // Private window or blocked storage — the theme still applies for this page.
    }
}

function toggleTheme() {
    applyTheme(currentTheme() === "light" ? "dark" : "light");
}

// --- auth flow ---

function setBanner(kind, lead, parts) {
    const banner = $("config-banner");
    banner.textContent = "";
    banner.className = "config-banner banner-" + kind;
    const strong = document.createElement("strong");
    strong.textContent = lead;
    banner.append(strong, " ");
    for (const part of parts) {
        if (typeof part === "string") {
            banner.append(part);
        } else if (part.strong) {
            const emphasis = document.createElement("strong");
            emphasis.textContent = part.strong;
            banner.append(emphasis);
        } else {
            const code = document.createElement("code");
            code.textContent = part.code;
            banner.append(code);
        }
    }
    banner.hidden = false;
}

function checkCookieConfig(cookieSecure) {
    const httpsPage = location.protocol === "https:";
    // Browsers treat localhost as a secure context, so Secure cookies work there over plain HTTP.
    const localhost = ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);

    if (!httpsPage && cookieSecure && !localhost) {
        setBanner("danger", "Sign-in will not work on this address.", [
            "The server requires Secure cookies, but this page was loaded over plain HTTP — your browser will discard the session cookie, so sign-in appears to succeed and then every request fails. Put pcap-server behind an HTTPS reverse proxy, or set ",
            { code: "COOKIE_SECURE=false" },
            " for HTTP/LAN use and restart the container.",
        ]);
    } else if (httpsPage && !cookieSecure) {
        setBanner("warning", "Session cookies are not protected.", [
            "This page is HTTPS, but the server is running with ",
            { code: "COOKIE_SECURE=false" },
            ", so the session cookie is sent without the Secure flag and can leak over any plain-HTTP request to this host. Set ",
            { code: "COOKIE_SECURE=true" },
            " and restart the container.",
        ]);
    } else if (!httpsPage && !cookieSecure && !localhost) {
        // The override case. Sign-in works, which is exactly why this needs
        // saying: nothing looks wrong, and every request is in the clear.
        setBanner("warning", "Not encrypted \u2014 signing in here is read-only.", [
            "This page was loaded over plain HTTP, so your password and TOTP code will cross ",
            "the network in cleartext and your session cookie can be copied and replayed. ",
            "Because of that pcap-server runs read-only on this connection: you can browse ",
            "servers and view captures, but ",
            { strong: "captures cannot be downloaded, SSH keys cannot be uploaded, and nothing can be changed" },
            ". To get full access, serve pcap-server over HTTPS \u2014 either put a reverse proxy in front ",
            "(Caddy obtains and renews Let's Encrypt certificates automatically; nginx or Traefik work too) ",
            "and set ",
            { code: "TRUST_PROXY_HEADERS=true" },
            " so it recognises the proxy's TLS, then set ",
            { code: "COOKIE_SECURE=true" },
            " and restart the container.",
        ]);
    } else {
        $("config-banner").hidden = true;
    }
}

// Repo and release-notes links are shown on every screen, signed in or not, so
// the running version is always one click from its release notes.
function applyBuildLinks(status) {
    const version = status.version ? `v${status.version}` : "";
    // Signed out, the server withholds the exact version, so point at the
    // releases index rather than a tag that would give the build away.
    const releaseHref = status.release_notes_url || status.releases_url;
    const pairs = [
        ["version-link", status.release_notes_url, version],
        ["repo-link", status.repo_url, "GitHub"],
        ["auth-repo-link", status.repo_url, "GitHub"],
        ["auth-release-link", releaseHref, "Release notes"],
    ];
    for (const [id, href, label] of pairs) {
        const el = $(id);
        if (!el) continue;
        if (!href) {
            el.hidden = true;
            continue;
        }
        el.hidden = false;
        el.href = href;
        el.textContent = label;
    }
    const v = $("auth-version");
    if (v) v.textContent = version;
}

async function checkAuth() {
    const status = await api("/api/auth/status");
    checkCookieConfig(status.cookie_secure);
    applyBuildLinks(status);
    secureTransport = status.secure_transport !== false;
    renderReadOnlyNotice(status);
    renderEncryptionNotice(status);
    if (!status.has_users) {
        show("auth-screen");
        show("register-form");
        hide("login-form");
        $("auth-subtitle").textContent = "Create the first admin account to get started";
        return;
    }
    if (!status.authenticated) {
        show("auth-screen");
        hide("register-form");
        show("login-form");
        $("auth-subtitle").textContent = "Sign in to continue";
        return;
    }
    currentUser = status.user;
    if (!currentUser.totp_confirmed) {
        await showTotpSetup();
        return;
    }
    enterApp();
}

async function doRegister() {
    $("reg-error").textContent = "";
    try {
        const result = await api("/api/auth/register", {
            method: "POST",
            body: JSON.stringify({
                username: $("reg-username").value,
                password: $("reg-password").value,
            }),
        });
        if (result.needs_totp_setup) {
            hide("auth-screen");
            await showTotpSetup();
        } else {
            location.reload();
        }
    } catch (e) {
        $("reg-error").textContent = e.message;
    }
}

async function doLogin() {
    $("login-error").textContent = "";
    try {
        const result = await api("/api/auth/login", {
            method: "POST",
            body: JSON.stringify({
                username: $("login-username").value,
                password: $("login-password").value,
                totp_code: $("login-totp").value,
                trust_device: $("login-trust-device")?.checked ?? false,
            }),
        });
        if (result.needs_totp) {
            show("totp-group");
            $("login-totp").focus();
            return;
        }
        if (result.needs_totp_setup) {
            hide("auth-screen");
            await showTotpSetup();
            return;
        }
        location.reload();
    } catch (e) {
        $("login-error").textContent = e.message;
    }
}

async function showTotpSetup() {
    const data = await api("/api/auth/totp/setup");
    $("totp-qr").src = data.qr_data_uri;
    $("totp-secret-text").textContent = data.secret;
    show("totp-setup-screen");
}

async function confirmTotp() {
    $("totp-error").textContent = "";
    try {
        await api("/api/auth/totp/confirm", {
            method: "POST",
            body: JSON.stringify({ code: $("totp-confirm-code").value }),
        });
        location.reload();
    } catch (e) {
        $("totp-error").textContent = e.message;
    }
}

async function doLogout() {
    await api("/api/auth/logout", { method: "POST" });
    location.reload();
}

// --- main app ---

function enterApp() {
    hide("auth-screen");
    hide("totp-setup-screen");
    show("app-screen");
    $("user-display").textContent = currentUser.username;
    if (currentUser.is_admin) {
        $("admin-tab").hidden = false;
    }
    initTabs();
    initFlagPicker();
    loadServers();
    loadSavedServers();
    loadCaptures();
    setInterval(refreshRunningCaptures, 3000);
}

// --- tabs ---

function initTabs() {
    document.querySelectorAll(".tab").forEach((tab) => {
        tab.addEventListener("click", () => {
            document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
            document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
            tab.classList.add("active");
            $("panel-" + tab.dataset.tab).classList.add("active");
            if (tab.dataset.tab === "admin") {
                loadEncryptionStatus();
                loadAdminSettings();
                loadAdminUsers();
                loadAdminSSHKeys();
                loadAdminKnownHosts();
            }
        });
    });
}

// --- servers ---

async function loadServers() {
    try {
        activeServers = await api("/api/servers");
    } catch {
        activeServers = [];
    }
    renderServerList();
    updateServerDropdown();
}

function renderServerList() {
    const el = $("server-list");
    if (!activeServers.length) {
        el.innerHTML = '<div class="empty-state" style="padding:20px;font-size:0.8125rem">No servers added</div>';
        return;
    }
    el.innerHTML = activeServers
        .map(
            (s) => `
        <div class="server-item" data-id="${escHtml(s.id)}" onclick="selectServer('${escHtml(s.id)}')">
            <div class="name">${escHtml(s.name || s.hostname)}</div>
            <div class="detail">${escHtml(s.username)}@${escHtml(s.hostname)}:${s.port}</div>
        </div>`
        )
        .join("");
}

function selectServer(id) {
    const srv = activeServers.find((s) => s.id === id);
    if (!srv) return;
    document.querySelectorAll(".server-item").forEach((el) => el.classList.remove("active"));
    document.querySelector(`.server-item[data-id="${id}"]`)?.classList.add("active");

    $("server-form-area").innerHTML = `
        <h3>${escHtml(srv.name || srv.hostname)}</h3>
        <div class="form-group"><label>Host</label><input type="text" value="${escHtml(srv.hostname)}" disabled></div>
        <div class="form-row">
            <div class="form-group"><label>Port</label><input type="text" value="${srv.port}" disabled></div>
            <div class="form-group"><label>Username</label><input type="text" value="${escHtml(srv.username)}" disabled></div>
        </div>
        <div class="form-group"><label>SSH Key</label><input type="text" value="${escHtml(srv.ssh_key_name)}" disabled></div>
        <div class="form-actions">
            <button class="btn btn-sm btn-secondary" onclick="testServer('${escHtml(srv.id)}')">Test connection</button>
            <button class="btn btn-sm btn-secondary" onclick="prereqCheck('${escHtml(srv.id)}')">Check prerequisites</button>
            <button class="btn btn-sm btn-secondary" onclick="saveServerConfig('${escHtml(srv.id)}')">Save to profile</button>
            <button class="btn btn-sm btn-danger" onclick="removeServer('${escHtml(srv.id)}')">Remove</button>
        </div>
        <div id="server-test-result" style="margin-top:8px;font-size:0.8125rem"></div>
        <div id="prereq-result"></div>
    `;
}

// Read-only capability probe. The backend installs nothing; anything that comes
// back short is reported with a command for the operator to run themselves.
async function prereqCheck(id) {
    const box = $("prereq-result");
    if (!box) return;
    box.innerHTML = '<div class="prereq-pending"><span class="spinner"></span> Probing host (read-only)...</div>';
    try {
        const res = await api(`/api/servers/${id}/prereq-check`, { method: "POST" });
        renderPrereqs(box, res);
        await loadServers();
    } catch (e) {
        box.innerHTML = `<div class="prereq-error">${escHtml(e.message)}</div>`;
    }
}

const PREREQ_ICON = { ok: "\u2713", warn: "!", fail: "\u2717" };

function renderPrereqs(box, res) {
    box.textContent = "";
    const wrap = document.createElement("div");
    wrap.className = "prereq";

    const head = document.createElement("div");
    head.className = "prereq-head";
    const failed = res.checks.filter((c) => c.status === "fail").length;
    const warned = res.checks.filter((c) => c.status === "warn").length;
    head.textContent = failed
        ? `${failed} problem${failed > 1 ? "s" : ""} to fix before capturing`
        : warned
        ? `Ready to capture, with ${warned} thing${warned > 1 ? "s" : ""} worth knowing`
        : "Ready to capture";
    head.classList.add(failed ? "fail" : warned ? "warn" : "ok");
    wrap.append(head);

    const note = document.createElement("div");
    note.className = "prereq-readonly";
    note.textContent = "Nothing was installed or changed on the host. This check only reads.";
    wrap.append(note);

    for (const c of res.checks) {
        const row = document.createElement("div");
        row.className = `prereq-row ${c.status}`;

        const icon = document.createElement("span");
        icon.className = "prereq-icon";
        icon.textContent = PREREQ_ICON[c.status] || "?";
        row.append(icon);

        const body = document.createElement("div");
        const name = document.createElement("div");
        name.className = "prereq-name";
        name.textContent = c.name;
        const detail = document.createElement("div");
        detail.className = "prereq-detail";
        detail.textContent = c.detail;
        body.append(name, detail);

        if (c.fix) {
            const fixLabel = document.createElement("div");
            fixLabel.className = "prereq-fix-label";
            fixLabel.textContent = "Run this on the host yourself:";
            const fix = document.createElement("pre");
            fix.className = "prereq-fix";
            fix.textContent = c.fix;
            body.append(fixLabel, fix);
        }
        row.append(body);
        wrap.append(row);
    }

    if (res.tcpdump_path) {
        const path = document.createElement("div");
        path.className = "prereq-path";
        path.textContent = `Captures will run: ${res.tcpdump_path}`;
        wrap.append(path);
    }
    box.append(wrap);
}

function showAddServer() {
    loadSSHKeys().then((keys) => {
        const opts = keys.map((k) => `<option value="${escHtml(k)}">${escHtml(k)}</option>`).join("");
        $("server-form-area").innerHTML = `
            <h3>Add server</h3>
            <div class="form-group"><label>Name <span class="hint">(optional — labels captures from this host)</span></label><input type="text" id="new-srv-name" placeholder="e.g. edge-firewall"></div>
            <div class="form-group"><label>Hostname / IP</label><input type="text" id="new-srv-host"></div>
            <div class="form-row">
                <div class="form-group"><label>Port</label><input type="number" id="new-srv-port" value="22"></div>
                <div class="form-group"><label>Username</label><input type="text" id="new-srv-user" value="root"></div>
            </div>
            <div class="form-group">
                <label>SSH Key</label>
                <select id="new-srv-key">${opts || '<option value="">No keys found</option>'}</select>
            </div>
            <div class="form-group">${sudoOption("new-srv-sudo", false)}</div>
            <div class="form-actions">
                <button class="btn btn-sm btn-primary" onclick="addServer()">Add server</button>
            </div>
            <div id="add-server-error" class="error-msg"></div>
        `;
    });
}

async function loadSSHKeys() {
    try {
        return await api("/api/ssh-keys");
    } catch {
        return [];
    }
}

async function addServer() {
    $("add-server-error").textContent = "";
    try {
        await api("/api/servers", {
            method: "POST",
            body: JSON.stringify({
                name: $("new-srv-name").value,
                hostname: $("new-srv-host").value,
                port: parseInt($("new-srv-port").value) || 22,
                username: $("new-srv-user").value,
                ssh_key_name: $("new-srv-key").value,
                use_sudo: $("new-srv-sudo").checked,
            }),
        });
        await loadServers();
        $("server-form-area").innerHTML = '<div class="empty-state">Server added</div>';
    } catch (e) {
        $("add-server-error").textContent = e.message;
    }
}

async function testServer(id) {
    const el = $("server-test-result");
    el.innerHTML = '<span class="spinner"></span> Testing...';
    try {
        await api(`/api/servers/${id}/test`, { method: "POST" });
        el.innerHTML = '<span style="color:var(--success)">Connection successful</span>';
    } catch (e) {
        el.innerHTML = `<span style="color:var(--danger)">Failed: ${escHtml(e.message)}</span>`;
    }
}

async function removeServer(id) {
    await api(`/api/servers/${id}`, { method: "DELETE" });
    await loadServers();
    $("server-form-area").innerHTML = '<div class="empty-state">Server removed</div>';
}

async function saveServerConfig(id) {
    const srv = activeServers.find((s) => s.id === id);
    if (!srv) return;
    const name = prompt("Save as (name):", srv.hostname);
    if (!name) return;
    try {
        await api("/api/saved-servers", {
            method: "POST",
            body: JSON.stringify({
                name,
                hostname: srv.hostname,
                port: srv.port,
                username: srv.username,
                ssh_key_name: srv.ssh_key_name,
                use_sudo: srv.use_sudo,
            }),
        });
        loadSavedServers();
    } catch (e) {
        alert("Save failed: " + e.message);
    }
}

async function loadSavedServers() {
    try {
        const servers = await api("/api/saved-servers");
        savedServers = servers;
        const el = $("saved-server-list");
        if (!servers.length) {
            el.innerHTML = "None";
            return;
        }
        el.innerHTML = servers
            .map(
                (s) => `
            <div style="display:flex;align-items:center;gap:8px;padding:4px 0">
                <span style="flex:1">${escHtml(s.name)} (${escHtml(s.hostname)})</span>
                <button class="btn-icon" onclick="loadSavedServer('${escHtml(s.id)}')" title="Load">&#x25B6;</button>
                <button class="btn-icon" onclick="editSavedServer('${escHtml(s.id)}')" title="Edit">&#x270E;</button>
                <button class="btn-icon" onclick="deleteSavedServer('${escHtml(s.id)}')" title="Delete">&times;</button>
            </div>`
            )
            .join("");
    } catch {
        $("saved-server-list").innerHTML = "None";
    }
}

async function loadSavedServer(id) {
    try {
        await api(`/api/saved-servers/${id}/load`, { method: "POST" });
        await loadServers();
    } catch (e) {
        alert(e.message);
    }
}

const SUDO_HINT = "Needed when the SSH user isn't root. Requires passwordless sudo for tcpdump on that host.";

function sudoOption(id, checked) {
    return `
        <div class="option-row">
            <input type="checkbox" id="${escHtml(id)}"${checked ? " checked" : ""}>
            <div class="option-text">
                <label class="option-title" for="${escHtml(id)}">Run tcpdump with sudo</label>
                <span class="field-hint">${escHtml(SUDO_HINT)}</span>
            </div>
        </div>`;
}

async function editSavedServer(id) {
    const srv = savedServers.find((s) => s.id === id);
    if (!srv) return;
    const keys = await loadSSHKeys();
    const opts = keys
        .map((k) => `<option value="${escHtml(k)}"${k === srv.ssh_key_name ? " selected" : ""}>${escHtml(k)}</option>`)
        .join("");
    $("server-form-area").innerHTML = `
        <h3>Edit saved server</h3>
        <div class="form-group"><label>Name</label><input type="text" id="edit-srv-name" value="${escHtml(srv.name)}"></div>
        <div class="form-group"><label>Hostname / IP</label><input type="text" id="edit-srv-host" value="${escHtml(srv.hostname)}"></div>
        <div class="form-row">
            <div class="form-group"><label>Port</label><input type="number" id="edit-srv-port" value="${escHtml(srv.port)}"></div>
            <div class="form-group"><label>Username</label><input type="text" id="edit-srv-user" value="${escHtml(srv.username)}"></div>
        </div>
        <div class="form-group">
            <label>SSH Key</label>
            <select id="edit-srv-key">${opts || '<option value="">No keys found</option>'}</select>
        </div>
        <div class="form-group">${sudoOption("edit-srv-sudo", srv.use_sudo)}</div>
        <div class="form-actions">
            <button class="btn btn-sm btn-primary" onclick="saveSavedServerEdit('${escHtml(srv.id)}')">Save changes</button>
        </div>
        <div id="edit-server-error" class="error-msg"></div>
    `;
}

async function saveSavedServerEdit(id) {
    $("edit-server-error").textContent = "";
    try {
        await api(`/api/saved-servers/${id}`, {
            method: "PUT",
            body: JSON.stringify({
                name: $("edit-srv-name").value,
                hostname: $("edit-srv-host").value,
                port: parseInt($("edit-srv-port").value) || 22,
                username: $("edit-srv-user").value,
                ssh_key_name: $("edit-srv-key").value,
                use_sudo: $("edit-srv-sudo").checked,
            }),
        });
        await loadSavedServers();
        $("server-form-area").innerHTML = '<div class="empty-state">Saved server updated</div>';
    } catch (e) {
        $("edit-server-error").textContent = e.message;
    }
}

async function deleteSavedServer(id) {
    if (!confirm("Delete this saved server?")) return;
    await api(`/api/saved-servers/${id}`, { method: "DELETE" });
    loadSavedServers();
}

// --- capture ---

// These change how the packet list is rendered. tcpdump's display flags are
// meaningless for the capture itself, which is always written with -w.
const FLAG_HELP = {
    "-e": "Show link-layer MAC addresses as extra columns",
    "-t": "Hide the timestamp column",
    "-tt": "Timestamp as raw seconds since the epoch",
    "-ttt": "Timestamp as the delta since the previous packet",
    "-tttt": "Timestamp as a full date and time",
};

const ALLOWED_FLAGS = Object.keys(FLAG_HELP);

// The ones people reach for normally; everything else is situational.
const STANDARD_FLAGS = ["-e"];
// Of those, the ones switched on before you touch anything.
const DEFAULT_FLAGS = [];

function makeFlagChip(flag) {
    const chip = document.createElement("span");
    chip.className = "flag-chip";
    chip.dataset.flag = flag;
    chip.textContent = flag;
    if (DEFAULT_FLAGS.includes(flag)) {
        chip.classList.add("standard", "selected");
        chip.title = `${FLAG_HELP[flag]} — on by default because it's the usual standard.`;
    } else {
        chip.title = FLAG_HELP[flag];
    }
    chip.addEventListener("click", () => toggleFlag(chip));
    return chip;
}

function initFlagPicker() {
    const standard = $("flag-picker-standard");
    const niche = $("flag-picker-niche");
    standard.textContent = "";
    niche.textContent = "";
    for (const flag of ALLOWED_FLAGS) {
        const target = STANDARD_FLAGS.includes(flag) ? standard : niche;
        target.append(makeFlagChip(flag));
    }
    renderFlagHelp();
}

// One timestamp format and one resolution mode at a time.
const EXCLUSIVE_FLAG_GROUPS = [["-t", "-tt", "-ttt", "-tttt"]];

function toggleFlag(el) {
    const flag = el.dataset.flag;
    if (!el.classList.contains("selected")) {
        const group = EXCLUSIVE_FLAG_GROUPS.find((g) => g.includes(flag)) || [];
        for (const other of group) {
            if (other !== flag) {
                document.querySelector(`.flag-chip[data-flag="${other}"]`)?.classList.remove("selected");
            }
        }
    }
    el.classList.toggle("selected");
    renderFlagHelp();
    if (viewingCaptureId) loadPackets(viewingCaptureId, $("display-filter").value);
}

function renderFlagHelp() {
    const help = $("flag-help");
    help.textContent = "";
    const selected = getSelectedFlags();
    if (!selected.length) {
        help.textContent = "Hover a flag to see what it does. Selected flags are explained here.";
        return;
    }
    for (const flag of selected) {
        const row = document.createElement("div");
        const code = document.createElement("code");
        code.textContent = flag;
        row.append(code, " " + FLAG_HELP[flag]);
        if (DEFAULT_FLAGS.includes(flag)) {
            const tag = document.createElement("span");
            tag.className = "help-tag";
            tag.textContent = "standard";
            row.append(" ", tag);
        }
        help.append(row);
    }
}

function resolveNamesEnabled() {
    const el = $("resolve-names");
    return !!(el && el.checked);
}

function onResolveNamesToggled() {
    if (viewingCaptureId) loadPackets(viewingCaptureId, $("display-filter").value);
}

function getSelectedFlags() {
    return Array.from(document.querySelectorAll(".flag-chip.selected")).map(
        (el) => el.dataset.flag
    );
}

function fillSelect(sel, values, labelFor = (v) => v) {
    sel.textContent = "";
    for (const value of values) {
        const opt = document.createElement("option");
        opt.value = value;
        opt.textContent = labelFor(value);
        sel.append(opt);
    }
}

function updateServerDropdown() {
    const sel = $("cap-server");
    sel.textContent = "";
    if (!activeServers.length) {
        fillSelect(sel, [""], () => "No servers");
        fillSelect($("cap-interface"), ["any"]);
        return;
    }
    for (const srv of activeServers) {
        const opt = document.createElement("option");
        opt.value = srv.id;
        opt.textContent = srv.hostname;
        sel.append(opt);
    }
    sel.onchange = loadInterfaces;
    loadInterfaces();
}

async function loadInterfaces() {
    const serverId = $("cap-server").value;
    const sel = $("cap-interface");
    const previous = sel.value;
    if (!serverId) {
        fillSelect(sel, ["any"]);
        return;
    }
    let names;
    try {
        ({ interfaces: names } = await api(`/api/servers/${serverId}/interfaces`));
    } catch {
        // Unreachable host — leave "any" available rather than an empty dropdown.
        fillSelect(sel, ["any"]);
        return;
    }
    fillSelect(sel, names);
    if (names.includes(previous)) sel.value = previous;
}

async function startCapture() {
    const serverId = $("cap-server").value;
    if (!serverId) return alert("Add a server first");

    const body = {
        server_id: serverId,
        interface: $("cap-interface").value || "any",
        bpf_filter: $("cap-bpf").value,
    };

    const count = parseInt($("cap-count").value);
    if (count > 0) body.count = count;
    const dur = parseInt($("cap-duration").value);
    if (dur > 0) body.duration_seconds = dur;
    const snap = parseInt($("cap-snaplen").value);
    if (snap >= 0 && $("cap-snaplen").value) body.snap_len = snap;

    try {
        await api("/api/captures", { method: "POST", body: JSON.stringify(body) });
        loadCaptures();
    } catch (e) {
        alert("Capture failed: " + e.message);
    }
}

async function loadCaptures() {
    try {
        captures = await api("/api/captures");
    } catch {
        captures = [];
    }
    renderCaptures();
}

function renderCaptures() {
    const el = $("capture-list");
    if (!captures.length) {
        el.innerHTML = '<div class="empty-state">No captures yet</div>';
        return;
    }
    el.innerHTML = captures
        .map((c) => {
            // server_label is stamped at capture time, so it survives a restart
            // and outlives the server it came from.
            const srv = activeServers.find((s) => s.id === c.server_id);
            const srvName = c.server_label || (srv ? srv.hostname : c.server_id);
            const statusClass = `status-${c.status}`;
            let actions = "";
            if (c.status === "running") {
                actions = `<button class="btn btn-sm btn-secondary" onclick="stopCapture('${c.id}')">Stop</button>`;
            } else if (c.status === "completed") {
                // Downloads are refused over plain HTTP, so say why here rather
                // than letting the button fail with a 403 when clicked.
                const dl = secureTransport
                    ? `<button class="btn btn-sm btn-secondary" onclick="downloadCaptureById('${c.id}')">Download</button>`
                    : `<button class="btn btn-sm btn-secondary" disabled
                         title="Downloads require HTTPS. A pcap can contain credentials, so it is not sent over an unencrypted connection.">Download (HTTPS only)</button>`;
                actions = `<button class="btn btn-sm btn-primary" onclick="viewCapture('${c.id}')">View</button>
                           ${dl}`;
            }
            actions += ` <button class="btn btn-sm btn-danger" onclick="deleteCapture('${c.id}')">Delete</button>`;
            return `
            <div class="capture-item">
                <div class="info">
                    <div class="title">${escHtml(srvName)} &mdash; ${escHtml(c.command || "")}</div>
                    <div class="meta">
                        ID: ${c.id}
                        ${c.packet_count ? " | " + c.packet_count + " packets" : ""}
                        ${c.file_size ? " | " + (c.file_size / 1024).toFixed(1) + " KB" : ""}
                        ${c.error ? ' | <span style="color:var(--danger)">' + escHtml(c.error) + "</span>" : ""}
                    </div>
                </div>
                <span class="status-badge ${statusClass}">${c.status}</span>
                <div class="capture-actions">${actions}</div>
            </div>`;
        })
        .join("");
}

async function stopCapture(id) {
    await api(`/api/captures/${id}/stop`, { method: "POST" });
    loadCaptures();
}

async function deleteCapture(id) {
    if (!confirm("Delete this capture?")) return;
    await api(`/api/captures/${id}`, { method: "DELETE" });
    if (viewingCaptureId === id) {
        viewingCaptureId = null;
        show("viewer-empty");
        hide("packet-viewer");
    }
    loadCaptures();
}

function renderEncryptionNotice(status) {
    const el = $("encryption-notice");
    if (!el) return;
    const enc = status.encryption || {};
    el.textContent = "";
    if (enc.enabled === false) {
        const strong = document.createElement("strong");
        strong.textContent = "Captures are stored unencrypted. ";
        const rest = document.createElement("span");
        rest.textContent = "No master key is configured. A packet capture routinely contains "
            + "credentials in cleartext, so anyone who can read the captures volume or a backup "
            + "of it can read everything captured here. See Admin \u2192 Capture encryption.";
        el.append(strong, rest);
        el.className = "readonly-notice enc-notice-bad";
        el.hidden = false;
        return;
    }
    if (enc.locked) {
        const strong = document.createElement("strong");
        strong.textContent = "Encryption is locked. ";
        const rest = document.createElement("span");
        rest.textContent = "Captures cannot be taken or read until an admin enters the master "
            + "passphrase in Admin \u2192 Capture encryption.";
        el.append(strong, rest);
        el.className = "readonly-notice";
        el.hidden = false;
        return;
    }
    el.hidden = true;
}

function renderReadOnlyNotice(status) {
    const el = $("readonly-notice");
    if (!el) return;
    if (!status.read_only) {
        el.hidden = true;
        return;
    }
    el.textContent = "";
    const strong = document.createElement("strong");
    strong.textContent = "Read-only: this connection is not encrypted. ";
    const rest = document.createElement("span");
    rest.textContent = "Captures cannot be downloaded, SSH keys cannot be uploaded, and "
        + "nothing can be changed, because those would cross the network in the clear. "
        + "Viewing is allowed. Serve pcap-server over HTTPS to restore full access.";
    el.append(strong, rest);
    el.hidden = false;
}

function downloadCaptureById(id) {
    if (!secureTransport) {
        showHttpsRefusal({
            reason: "A capture routinely contains credentials in cleartext. Downloading it "
                + "over an unencrypted connection would put the whole capture on the wire.",
            remedy: "Serve pcap-server over HTTPS, then set TRUST_PROXY_HEADERS=true if a "
                + "reverse proxy terminates TLS.",
        });
        return;
    }
    window.open(`/api/captures/${id}/download`, "_blank");
}

async function refreshRunningCaptures() {
    const running = captures.filter((c) => ["running", "stopping", "transferring", "pending"].includes(c.status));
    if (!running.length) return;
    loadCaptures();
}

// --- packet viewer ---

async function viewCapture(id) {
    viewingCaptureId = id;
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelector('.tab[data-tab="viewer"]').classList.add("active");
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    $("panel-viewer").classList.add("active");

    hide("viewer-empty");
    show("packet-viewer");
    renderPacketLegend();
    $("viewer-capture-label").textContent = "Capture: " + id;
    $("display-filter").value = "";
    $("packet-detail-tree").innerHTML = '<div class="empty-state" style="font-size:0.75rem">Click a packet above</div>';
    $("hex-dump").textContent = "";

    await loadPackets(id);
}

// Wireshark-style row coloring. First match wins, so problems outrank protocols.
const PACKET_RULES = [
    {
        cls: "pkt-bad",
        label: "Problem",
        test: (p, info) => /retransmission|dup ack|out-of-order|zerowindow|window full|previous segment|port numbers reused|malformed|bad checksum|unreachable|time exceeded/i.test(info),
    },
    { cls: "pkt-reset", label: "Reset", test: (p, info) => /\brst\b/i.test(info) },
    { cls: "pkt-session", label: "Open / close", test: (p, info) => /\b(syn|fin)\b/i.test(info) },
    { cls: "pkt-arp", label: "ARP", test: (p) => p.protocol === "ARP" },
    { cls: "pkt-icmp", label: "ICMP", test: (p) => p.protocol.startsWith("ICMP") },
    { cls: "pkt-dns", label: "DNS", test: (p) => ["DNS", "MDNS", "LLMNR", "NBNS"].includes(p.protocol) },
    { cls: "pkt-http", label: "HTTP", test: (p) => p.protocol.startsWith("HTTP") },
    { cls: "pkt-tls", label: "TLS / QUIC", test: (p) => ["TLS", "SSL", "QUIC"].includes(p.protocol) },
    { cls: "pkt-udp", label: "UDP", test: (p) => p.protocol === "UDP" },
    { cls: "pkt-tcp", label: "TCP", test: (p) => p.protocol === "TCP" },
];

function packetClass(p) {
    const info = p.info || "";
    const rule = PACKET_RULES.find((r) => r.test(p, info));
    return rule ? rule.cls : "";
}

function renderPacketLegend() {
    const legend = $("packet-legend");
    if (!legend || legend.childElementCount) return;
    for (const rule of PACKET_RULES) {
        const item = document.createElement("span");
        item.className = "legend-item";
        const swatch = document.createElement("span");
        swatch.className = `legend-swatch ${rule.cls}`;
        item.append(swatch, rule.label);
        legend.append(item);
    }
}

// Each timestamp flag needs a different amount of room; without this the cell
// just ellipsises and the flag looks inert.
const TIME_WIDTH_CLASS = {
    "-t": "time-hidden",
    "-tt": "time-epoch",
    "-tttt": "time-full",
};

function applyTimeColumnWidth(flags) {
    const table = document.querySelector(".packet-table");
    if (!table) return;
    table.classList.remove(...Object.values(TIME_WIDTH_CLASS));
    for (const [flag, cls] of Object.entries(TIME_WIDTH_CLASS)) {
        if (flags.includes(flag)) {
            table.classList.add(cls);
            break;
        }
    }
}

async function loadPackets(captureId, filter = "") {
    const tbody = $("packet-tbody");
    const flags = getSelectedFlags();
    const showMac = flags.includes("-e");
    document.querySelectorAll(".col-mac").forEach((el) => { el.hidden = !showMac; });
    applyTimeColumnWidth(flags);
    const span = showMac ? 9 : 7;
    const mac = showMac ? "" : " hidden";

    tbody.innerHTML = `<tr><td colspan="${span}" style="text-align:center;padding:20px"><span class="spinner"></span> Loading...</td></tr>`;

    try {
        const query = new URLSearchParams({
            limit: "1000",
            display_filter: filter,
            flags: flags.join(","),
            resolve_names: resolveNamesEnabled() ? "true" : "false",
        });
        const data = await api(`/api/captures/${captureId}/packets?${query}`);
        if (!data.packets.length) {
            tbody.innerHTML = `<tr><td colspan="${span}" style="text-align:center;padding:20px;color:var(--text-muted)">No packets match</td></tr>`;
            return;
        }
        tbody.innerHTML = data.packets
            .map(
                (p) => `
            <tr class="${packetClass(p)}" data-frame="${p.number}" onclick="selectPacket(${p.number})">
                <td class="col-no">${p.number}</td>
                <td class="col-time" title="${escHtml(p.timestamp)}">${escHtml(p.timestamp)}</td>
                <td class="col-src" title="${escHtml(p.source)}">${escHtml(p.source)}</td>
                <td class="col-dst" title="${escHtml(p.destination)}">${escHtml(p.destination)}</td>
                <td class="col-mac"${mac}>${escHtml(p.src_mac || "")}</td>
                <td class="col-mac"${mac}>${escHtml(p.dst_mac || "")}</td>
                <td class="col-proto">${escHtml(p.protocol)}</td>
                <td class="col-len">${p.length}</td>
                <td class="col-info">${escHtml(p.info)}</td>
            </tr>`
            )
            .join("");
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="${span}" style="color:var(--danger);padding:20px">${escHtml(e.message)}</td></tr>`;
    }
}

function applyDisplayFilter() {
    if (!viewingCaptureId) return;
    loadPackets(viewingCaptureId, $("display-filter").value);
}

function downloadCapture() {
    if (!viewingCaptureId) return;
    downloadCaptureById(viewingCaptureId);
}

async function selectPacket(frameNumber) {
    if (selectedPacketRow) selectedPacketRow.classList.remove("selected");
    selectedPacketRow = document.querySelector(`tr[data-frame="${frameNumber}"]`);
    if (selectedPacketRow) selectedPacketRow.classList.add("selected");

    $("packet-detail-tree").innerHTML = '<div class="empty-state" style="font-size:0.75rem"><span class="spinner"></span></div>';
    $("hex-dump").textContent = "Loading...";

    try {
        const detail = await api(`/api/captures/${viewingCaptureId}/packets/${frameNumber}`);
        renderDetailTree(detail.layers);
        $("hex-dump").textContent = detail.hex_dump || "(no hex data)";
    } catch (e) {
        $("packet-detail-tree").innerHTML = `<div style="color:var(--danger);padding:8px">${escHtml(e.message)}</div>`;
        $("hex-dump").textContent = "";
    }
}

function renderDetailTree(layers) {
    const container = $("packet-detail-tree");
    container.innerHTML = "";
    for (const layer of layers) {
        container.appendChild(buildTreeNode(layer.name, layer.fields));
    }
}

function buildTreeNode(label, fields) {
    const node = document.createElement("div");
    node.className = "tree-node";

    const toggle = document.createElement("div");
    toggle.className = "tree-toggle";
    toggle.textContent = " " + label;
    toggle.addEventListener("click", () => {
        toggle.classList.toggle("open");
        children.classList.toggle("open");
    });
    node.appendChild(toggle);

    const children = document.createElement("div");
    children.className = "tree-children";

    if (fields) {
        for (const field of fields) {
            if (field.children && field.children.length) {
                children.appendChild(buildTreeNode(field.key, field.children));
            } else {
                const leaf = document.createElement("div");
                leaf.className = "tree-leaf";
                leaf.innerHTML = `<span class="field-name">${escHtml(field.key)}</span>: <span class="field-value">${escHtml(field.value || "")}</span>`;
                children.appendChild(leaf);
            }
        }
    }

    node.appendChild(children);
    return node;
}

// --- resizer ---

(function initResizer() {
    const resizer = $("resizer");
    if (!resizer) return;
    let startY, startH;
    resizer.addEventListener("mousedown", (e) => {
        const listContainer = document.querySelector(".packet-list-container");
        startY = e.clientY;
        startH = listContainer.offsetHeight;
        function onMove(ev) {
            const delta = ev.clientY - startY;
            listContainer.style.flex = "none";
            listContainer.style.height = Math.max(100, startH + delta) + "px";
        }
        function onUp() {
            document.removeEventListener("mousemove", onMove);
            document.removeEventListener("mouseup", onUp);
        }
        document.addEventListener("mousemove", onMove);
        document.addEventListener("mouseup", onUp);
    });
})();

// --- keyboard shortcuts ---

document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && $("display-filter") === document.activeElement) {
        applyDisplayFilter();
    }
    if (e.key === "Enter" && $("login-password") === document.activeElement) {
        doLogin();
    }
    if (e.key === "Enter" && $("reg-password") === document.activeElement) {
        doRegister();
    }
    if (e.key === "Enter" && $("totp-confirm-code") === document.activeElement) {
        confirmTotp();
    }
    if (e.key === "Enter" && $("login-totp") === document.activeElement) {
        doLogin();
    }
});


// --- encryption ---

async function loadEncryptionStatus() {
    const box = $("admin-encryption");
    if (!box) return;
    try {
        renderEncryption(box, await api("/api/admin/encryption"));
    } catch (e) {
        box.textContent = "";
        const err = document.createElement("div");
        err.className = "error-msg";
        err.textContent = e.message;
        box.append(err);
    }
}

function encryptionSummary(st) {
    if (!st.enabled) {
        return {
            level: "bad",
            headline: "Captures are stored unencrypted",
            detail: "No master key is configured and ALLOW_UNENCRYPTED_CAPTURES is set. "
                + "A packet capture routinely contains credentials in cleartext, so anyone "
                + "who can read the captures volume, a backup of it, or the disk it sits on "
                + "can read everything you have captured.",
        };
    }
    if (st.locked) {
        return {
            level: "warn",
            headline: "Locked \u2014 a passphrase is needed",
            detail: "This installation derives its key from a passphrase held only in memory, "
                + "so a restart leaves it locked. Captures cannot be read or taken until it "
                + "is unlocked.",
        };
    }
    return {
        level: "good",
        headline: "Captures are encrypted at rest",
        detail: "New captures are sealed as they arrive from the remote host, and decrypted "
            + "only in transit to the viewer or your browser \u2014 the plaintext is never "
            + "written to disk.",
    };
}

const ENCRYPTION_MODE_LABEL = {
    file: "master key file (Docker secret)",
    env: "master key from the environment",
    passphrase: "admin passphrase (held in memory only)",
    disabled: "disabled",
};

function renderEncryption(box, st) {
    box.textContent = "";
    const summary = encryptionSummary(st);

    const head = document.createElement("div");
    head.className = `enc-state enc-${summary.level}`;
    head.textContent = summary.headline;
    box.append(head);

    const detail = document.createElement("div");
    detail.className = "enc-detail";
    detail.textContent = summary.detail;
    box.append(detail);

    const facts = document.createElement("table");
    facts.className = "enc-facts";
    const rows = [["Key source", ENCRYPTION_MODE_LABEL[st.mode] || st.mode]];
    if (st.key_id) rows.push(["Key fingerprint", st.key_id]);
    rows.push(["Encrypted captures", String(st.encrypted_count)]);
    if (st.plaintext_count) {
        rows.push(["Still plaintext", `${st.plaintext_count} \u2014 these predate encryption `
            + `and could not be converted; see the container log`]);
    }
    for (const [k, v] of rows) {
        const tr = document.createElement("tr");
        const th = document.createElement("td");
        th.className = "enc-key";
        th.textContent = k;
        const td = document.createElement("td");
        td.textContent = v;
        tr.append(th, td);
        facts.append(tr);
    }
    box.append(facts);

    if (st.locked) {
        const form = document.createElement("div");
        form.className = "admin-inline-form";
        form.style.marginTop = "12px";
        const input = document.createElement("input");
        input.type = "password";
        input.id = "enc-passphrase";
        input.placeholder = "Master passphrase";
        input.style.width = "220px";
        input.autocomplete = "off";
        input.addEventListener("keydown", (e) => { if (e.key === "Enter") unlockEncryption(); });
        const btn = document.createElement("button");
        btn.className = "btn btn-sm btn-primary";
        btn.textContent = "Unlock";
        btn.onclick = unlockEncryption;
        form.append(input, btn);
        box.append(form);

        const msg = document.createElement("div");
        msg.id = "enc-msg";
        msg.className = "error-msg";
        box.append(msg);
    }

    if (!st.enabled) {
        const how = document.createElement("pre");
        how.className = "enc-howto";
        how.textContent = "openssl rand -base64 32 > secrets/master.key\n"
            + "chmod 0400 secrets/master.key\n\n"
            + "then in docker-compose.yml:\n"
            + "  environment:\n"
            + "    - MASTER_KEY_FILE=/run/secrets/pcap_master_key\n"
            + "  secrets:\n"
            + "    - pcap_master_key\n\n"
            + "Back that key up. Without it, encrypted captures cannot be recovered.";
        box.append(how);
    }
}

async function unlockEncryption() {
    const input = $("enc-passphrase");
    const msg = $("enc-msg");
    if (!input) return;
    if (msg) { msg.className = "error-msg"; msg.textContent = "Deriving key\u2026"; }
    try {
        const res = await api("/api/admin/encryption/unlock", {
            method: "POST",
            body: JSON.stringify({ passphrase: input.value }),
        });
        input.value = "";
        if (msg) {
            msg.className = "success-msg";
            msg.textContent = res.migrated
                ? `Unlocked. ${res.migrated} existing capture(s) encrypted.`
                : "Unlocked.";
        }
        await loadEncryptionStatus();
    } catch (e) {
        if (msg) { msg.className = "error-msg"; msg.textContent = e.message; }
    }
}

// --- admin panel ---

const SETTING_LABELS = {
    max_capture_seconds: "Max capture duration (seconds)",
    max_capture_packets: "Max capture packets",
    session_duration_hours: "Session duration (hours)",
    session_idle_timeout_minutes: "Session idle timeout (minutes)",
    device_trust_days: "Device trust duration (days)",
    rate_limit_max_attempts: "Rate limit max attempts",
    rate_limit_lockout_minutes: "Rate limit lockout (minutes)",
};

async function loadAdminSettings() {
    try {
        const settings = await api("/api/admin/settings");
        const el = $("admin-settings");
        el.innerHTML = Object.entries(SETTING_LABELS)
            .map(([key, label]) => `
                <div class="setting-item">
                    <label>${escHtml(label)}</label>
                    <input type="number" id="setting-${key}" value="${escHtml(settings[key] || "")}" min="1">
                </div>
            `)
            .join("");
    } catch (e) {
        $("admin-settings").innerHTML = `<span style="color:var(--danger)">${escHtml(e.message)}</span>`;
    }
}

async function saveSettings() {
    const msgEl = $("settings-msg");
    msgEl.textContent = "";
    msgEl.className = "error-msg";
    const keys = Object.keys(SETTING_LABELS);
    try {
        for (const key of keys) {
            const input = $("setting-" + key);
            if (!input) continue;
            await api("/api/admin/settings", {
                method: "PUT",
                body: JSON.stringify({ key, value: input.value }),
            });
        }
        msgEl.textContent = "Settings saved";
        msgEl.className = "success-msg";
    } catch (e) {
        msgEl.textContent = e.message;
    }
}

async function loadAdminUsers() {
    try {
        const users = await api("/api/admin/users");
        const el = $("admin-user-list");
        if (!users.length) {
            el.innerHTML = "No users";
            return;
        }
        el.innerHTML = `<table class="admin-table">
            <thead><tr><th>Username</th><th>Admin</th><th>MFA</th><th>Created</th><th></th></tr></thead>
            <tbody>${users.map((u) => `
                <tr>
                    <td>${escHtml(u.username)}</td>
                    <td>${u.is_admin ? "Yes" : "No"}</td>
                    <td>${u.totp_confirmed ? "Yes" : "No"}</td>
                    <td>${escHtml(u.created_at || "")}</td>
                    <td>${!u.is_admin ? `<button class="btn btn-sm btn-danger" onclick="adminDeleteUser('${escHtml(u.id)}')">Delete</button>` : ""}</td>
                </tr>`).join("")}
            </tbody>
        </table>`;
    } catch (e) {
        $("admin-user-list").innerHTML = `<span style="color:var(--danger)">${escHtml(e.message)}</span>`;
    }
}

async function adminCreateUser() {
    const msgEl = $("admin-user-msg");
    msgEl.textContent = "";
    msgEl.className = "error-msg";
    const username = $("admin-new-username").value;
    const password = $("admin-new-password").value;
    if (!username || !password) {
        msgEl.textContent = "Username and password required";
        return;
    }
    try {
        await api("/api/admin/users", {
            method: "POST",
            body: JSON.stringify({ username, password }),
        });
        $("admin-new-username").value = "";
        $("admin-new-password").value = "";
        msgEl.textContent = "User created";
        msgEl.className = "success-msg";
        loadAdminUsers();
    } catch (e) {
        msgEl.textContent = e.message;
    }
}

async function adminDeleteUser(userId) {
    if (!confirm("Delete this user? This cannot be undone.")) return;
    try {
        await api(`/api/admin/users/${userId}`, { method: "DELETE" });
        loadAdminUsers();
    } catch (e) {
        $("admin-user-msg").textContent = e.message;
    }
}

async function loadAdminSSHKeys() {
    try {
        const keys = await api("/api/ssh-keys");
        const el = $("admin-ssh-keys");
        if (!keys.length) {
            el.innerHTML = '<span style="color:var(--text-muted)">No SSH keys uploaded</span>';
            return;
        }
        el.innerHTML = `<table class="admin-table">
            <thead><tr><th>Key Name</th><th></th></tr></thead>
            <tbody>${keys.map((k) => `
                <tr>
                    <td>${escHtml(k)}</td>
                    <td><button class="btn btn-sm btn-danger" onclick="adminDeleteKey('${escHtml(k)}')">Delete</button></td>
                </tr>`).join("")}
            </tbody>
        </table>`;
    } catch (e) {
        $("admin-ssh-keys").innerHTML = `<span style="color:var(--danger)">${escHtml(e.message)}</span>`;
    }
}

async function adminUploadKey() {
    const msgEl = $("admin-key-msg");
    msgEl.textContent = "";
    msgEl.className = "error-msg";
    const fileInput = $("admin-key-file");
    if (!fileInput.files.length) {
        msgEl.textContent = "Select a key file first";
        return;
    }
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    try {
        const resp = await fetch("/api/admin/ssh-keys", {
            method: "POST",
            credentials: "same-origin",
            body: formData,
        });
        if (!resp.ok) {
            const j = await resp.json().catch(() => ({}));
            throw new Error(j.detail || resp.statusText);
        }
        fileInput.value = "";
        msgEl.textContent = "Key uploaded";
        msgEl.className = "success-msg";
        loadAdminSSHKeys();
    } catch (e) {
        msgEl.textContent = e.message;
    }
}

async function adminDeleteKey(name) {
    if (!confirm(`Delete SSH key "${name}"? Servers using this key will no longer connect.`)) return;
    try {
        await api(`/api/admin/ssh-keys/${encodeURIComponent(name)}`, { method: "DELETE" });
        loadAdminSSHKeys();
    } catch (e) {
        $("admin-key-msg").textContent = e.message;
    }
}

async function loadAdminKnownHosts() {
    try {
        const hosts = await api("/api/admin/known-hosts");
        const el = $("admin-known-hosts");
        if (!hosts.length) {
            el.innerHTML = '<span style="color:var(--text-muted)">No known hosts</span>';
            return;
        }
        el.innerHTML = `<table class="admin-table">
            <thead><tr><th>Hostname</th><th>Port</th><th>Key Type</th><th>Added</th><th></th></tr></thead>
            <tbody>${hosts.map((h) => `
                <tr>
                    <td>${escHtml(h.hostname)}</td>
                    <td>${h.port}</td>
                    <td>${escHtml(h.key_type)}</td>
                    <td>${escHtml(h.added_at || "")}</td>
                    <td><button class="btn btn-sm btn-danger" onclick="adminDeleteKnownHost(${h.id})">Remove</button></td>
                </tr>`).join("")}
            </tbody>
        </table>`;
    } catch (e) {
        $("admin-known-hosts").innerHTML = `<span style="color:var(--danger)">${escHtml(e.message)}</span>`;
    }
}

async function adminScanHost() {
    const msgEl = $("admin-host-msg");
    msgEl.textContent = "";
    msgEl.className = "error-msg";
    const hostname = $("admin-scan-hostname").value.trim();
    const port = parseInt($("admin-scan-port").value) || 22;
    if (!hostname) {
        msgEl.textContent = "Hostname required";
        return;
    }
    msgEl.textContent = "Scanning...";
    msgEl.className = "success-msg";
    try {
        const result = await api("/api/admin/known-hosts/scan", {
            method: "POST",
            body: JSON.stringify({ hostname, port }),
        });
        msgEl.textContent = `Found ${result.keys.length} key(s)`;
        msgEl.className = "success-msg";
        loadAdminKnownHosts();
    } catch (e) {
        msgEl.textContent = e.message;
        msgEl.className = "error-msg";
    }
}

async function adminDeleteKnownHost(hostId) {
    if (!confirm("Remove this known host key?")) return;
    try {
        await api(`/api/admin/known-hosts/${hostId}`, { method: "DELETE" });
        loadAdminKnownHosts();
    } catch (e) {
        $("admin-host-msg").textContent = e.message;
    }
}

// --- boot ---

applyTheme(currentTheme());
checkAuth();
