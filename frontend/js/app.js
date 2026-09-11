"use strict";

const API = "";
let currentUser = null;
let activeServers = [];
let captures = [];
let viewingCaptureId = null;
let selectedPacketRow = null;

// --- helpers ---

async function api(path, opts = {}) {
    const resp = await fetch(API + path, {
        headers: { "Content-Type": "application/json", ...opts.headers },
        credentials: "same-origin",
        ...opts,
    });
    if (!resp.ok) {
        let msg;
        try {
            const j = await resp.json();
            msg = j.detail || JSON.stringify(j);
        } catch {
            msg = resp.statusText;
        }
        throw new Error(msg);
    }
    if (resp.headers.get("content-type")?.includes("json")) {
        return resp.json();
    }
    return resp;
}

function show(id) { document.getElementById(id).hidden = false; }
function hide(id) { document.getElementById(id).hidden = true; }
function $(id) { return document.getElementById(id); }
function escHtml(s) {
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
}

// --- auth flow ---

async function checkAuth() {
    const status = await api("/api/auth/status");
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
            <div class="name">${escHtml(s.hostname)}</div>
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
        <h3>${escHtml(srv.hostname)}</h3>
        <div class="form-group"><label>Host</label><input type="text" value="${escHtml(srv.hostname)}" disabled></div>
        <div class="form-row">
            <div class="form-group"><label>Port</label><input type="text" value="${srv.port}" disabled></div>
            <div class="form-group"><label>Username</label><input type="text" value="${escHtml(srv.username)}" disabled></div>
        </div>
        <div class="form-group"><label>SSH Key</label><input type="text" value="${escHtml(srv.ssh_key_name)}" disabled></div>
        <div class="form-actions">
            <button class="btn btn-sm btn-secondary" onclick="testServer('${escHtml(srv.id)}')">Test connection</button>
            <button class="btn btn-sm btn-secondary" onclick="saveServerConfig('${escHtml(srv.id)}')">Save to profile</button>
            <button class="btn btn-sm btn-danger" onclick="removeServer('${escHtml(srv.id)}')">Remove</button>
        </div>
        <div id="server-test-result" style="margin-top:8px;font-size:0.8125rem"></div>
    `;
}

function showAddServer() {
    loadSSHKeys().then((keys) => {
        const opts = keys.map((k) => `<option value="${escHtml(k)}">${escHtml(k)}</option>`).join("");
        $("server-form-area").innerHTML = `
            <h3>Add server</h3>
            <div class="form-group"><label>Hostname / IP</label><input type="text" id="new-srv-host"></div>
            <div class="form-row">
                <div class="form-group"><label>Port</label><input type="number" id="new-srv-port" value="22"></div>
                <div class="form-group"><label>Username</label><input type="text" id="new-srv-user" value="root"></div>
            </div>
            <div class="form-group">
                <label>SSH Key</label>
                <select id="new-srv-key">${opts || '<option value="">No keys found</option>'}</select>
            </div>
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
                hostname: $("new-srv-host").value,
                port: parseInt($("new-srv-port").value) || 22,
                username: $("new-srv-user").value,
                ssh_key_name: $("new-srv-key").value,
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

async function deleteSavedServer(id) {
    if (!confirm("Delete this saved server?")) return;
    await api(`/api/saved-servers/${id}`, { method: "DELETE" });
    loadSavedServers();
}

// --- capture ---

const ALLOWED_FLAGS = [
    "-n", "-nn", "-v", "-vv", "-vvv", "-e", "-q",
    "-A", "-X", "-XX", "-t", "-tt", "-ttt", "-tttt",
];

function initFlagPicker() {
    $("flag-picker").innerHTML = ALLOWED_FLAGS.map(
        (f) => `<span class="flag-chip" data-flag="${f}" onclick="toggleFlag(this)">${f}</span>`
    ).join("");
}

function toggleFlag(el) {
    el.classList.toggle("selected");
}

function getSelectedFlags() {
    return Array.from(document.querySelectorAll(".flag-chip.selected")).map(
        (el) => el.dataset.flag
    );
}

function updateServerDropdown() {
    const sel = $("cap-server");
    sel.innerHTML = activeServers
        .map((s) => `<option value="${escHtml(s.id)}">${escHtml(s.hostname)}</option>`)
        .join("");
    if (!activeServers.length) {
        sel.innerHTML = '<option value="">No servers</option>';
    }
}

async function startCapture() {
    const serverId = $("cap-server").value;
    if (!serverId) return alert("Add a server first");

    const body = {
        server_id: serverId,
        interface: $("cap-interface").value || "any",
        bpf_filter: $("cap-bpf").value,
        extra_flags: getSelectedFlags(),
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
            const srv = activeServers.find((s) => s.id === c.server_id);
            const srvName = srv ? srv.hostname : c.server_id;
            const statusClass = `status-${c.status}`;
            let actions = "";
            if (c.status === "running") {
                actions = `<button class="btn btn-sm btn-secondary" onclick="stopCapture('${c.id}')">Stop</button>`;
            } else if (c.status === "completed") {
                actions = `<button class="btn btn-sm btn-primary" onclick="viewCapture('${c.id}')">View</button>
                           <button class="btn btn-sm btn-secondary" onclick="downloadCaptureById('${c.id}')">Download</button>`;
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

function downloadCaptureById(id) {
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
    $("viewer-capture-label").textContent = "Capture: " + id;
    $("display-filter").value = "";
    $("packet-detail-tree").innerHTML = '<div class="empty-state" style="font-size:0.75rem">Click a packet above</div>';
    $("hex-dump").textContent = "";

    await loadPackets(id);
}

async function loadPackets(captureId, filter = "") {
    const tbody = $("packet-tbody");
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:20px"><span class="spinner"></span> Loading...</td></tr>';

    try {
        const data = await api(
            `/api/captures/${captureId}/packets?limit=1000&display_filter=${encodeURIComponent(filter)}`
        );
        if (!data.packets.length) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--text-muted)">No packets match</td></tr>';
            return;
        }
        tbody.innerHTML = data.packets
            .map(
                (p) => `
            <tr data-frame="${p.number}" onclick="selectPacket(${p.number})">
                <td class="col-no">${p.number}</td>
                <td class="col-time">${escHtml(p.timestamp)}</td>
                <td class="col-src">${escHtml(p.source)}</td>
                <td class="col-dst">${escHtml(p.destination)}</td>
                <td class="col-proto">${escHtml(p.protocol)}</td>
                <td class="col-len">${p.length}</td>
                <td class="col-info">${escHtml(p.info)}</td>
            </tr>`
            )
            .join("");
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" style="color:var(--danger);padding:20px">${escHtml(e.message)}</td></tr>`;
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

// --- boot ---

checkAuth();
