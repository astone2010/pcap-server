"use strict";

const API = "";
let currentUser = null;
let activeServers = [];
// DOM-only until now: re-rendering the list dropped the highlight with it.
let selectedServerId = null;
// The last /api/auth/status answer, for the pieces of UI that link out.
let authStatus = null;
// Whether this page reached the server over a connection a capture may cross.
let secureTransport = true;
let knownUsernames = [];
let captures = [];
let viewingCaptureId = null;
let selectedPacketRow = null;
// The packets the list is currently showing, so that rearranging its columns
// can redraw the table without fetching them again.
let currentPackets = [];

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
        // The API refuses a session that never finished enrolling. The normal
        // bootstrap already routes there off /api/auth/status, so reaching this
        // means a stale tab or a call that ran before the gate -- send them to
        // the enrolment screen rather than showing an opaque 403.
        if (detail && typeof detail === "object" && detail.code === "bad_display_filter") {
            const err = new Error(detail.reason);
            err.badDisplayFilter = true;
            throw err;
        }
        if (detail && typeof detail === "object" && detail.code === "totp_setup_required") {
            showTotpSetup().catch(() => {});
            throw new Error(detail.reason);
        }
        if (detail && typeof detail === "object" && detail.code === "self_capture") {
            showBlockingAlert("Cannot capture from this machine", detail.reason,
                              detail.explanation);
            throw new Error(detail.reason);
        }
        // FastAPI reports a 422 as an array of {loc, msg, type}. Dumping that as
        // JSON puts "[{\"type\":\"value_error\",\"loc\":[\"body\"..." in front of
        // the user; the msg fields are the part written for a person to read.
        if (Array.isArray(detail)) {
            const msgs = detail
                .map((d) => String(d && d.msg ? d.msg : "").replace(/^Value error, /, ""))
                .filter(Boolean);
            throw new Error(msgs.join("; ") || "the server rejected that input");
        }
        throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    return res.status === 204 ? null : res.json();
}

// A blocked action must say so plainly. This puts the reason on screen, scrolls
// it into view and keeps it until dismissed -- an alert() is easy to click away
// without reading, and a console error is invisible.
// The same advice the server sends with an https_required refusal
// (_HTTPS_REMEDY in main.py), for the refusals the page makes without asking.
const HTTPS_REMEDY = "Turn on HTTPS. Recommended: Admin \u2192 HTTPS, where pcap-server gets its "
    + "own Let's Encrypt certificate \u2014 no proxy, no inbound ports. Or put it behind a "
    + "reverse proxy (Nginx Proxy Manager, Caddy or nginx) with TRUST_PROXY_HEADERS=true; "
    + "with no domain, the proxy can use a self-signed certificate.";

function showHttpsRefusal(detail) {
    showBlockingAlert("This needs an encrypted connection",
                      detail.reason || "", detail.remedy || "", { httpsAction: true });
}

// One visible, dismissible panel for anything the server refuses on safety
// grounds. Deliberately not an alert(): this needs to be readable and to stay
// on screen while the user reads it.
function showBlockingAlert(title, reason, detail, { httpsAction = false } = {}) {
    let box = $("https-refusal");
    if (!box) {
        box = document.createElement("div");
        box.id = "https-refusal";
        box.className = "https-refusal";
        box.setAttribute("role", "alertdialog");
        document.body.prepend(box);
    }
    box.textContent = "";

    const titleEl = document.createElement("div");
    titleEl.className = "https-refusal-title";
    const icon = document.createElement("span");
    icon.className = "banner-icon";
    icon.setAttribute("aria-hidden", "true");
    titleEl.append(icon, title);

    const reasonEl = document.createElement("div");
    reasonEl.className = "https-refusal-reason";
    reasonEl.textContent = reason;

    const detailEl = document.createElement("div");
    detailEl.className = "https-refusal-remedy";
    detailEl.textContent = detail;

    const actions = document.createElement("div");
    actions.className = "https-refusal-actions";
    if (httpsAction && currentUser && currentUser.is_admin) {
        const go = document.createElement("button");
        go.type = "button";
        go.className = "btn btn-sm btn-primary";
        go.textContent = "Set up HTTPS";
        go.onclick = openHttpsSetup;
        actions.append(go);
    }
    const close = document.createElement("button");
    close.type = "button";
    close.className = "btn btn-sm btn-secondary https-refusal-close";
    close.textContent = "Dismiss";
    close.onclick = () => { box.hidden = true; };
    actions.append(close);

    box.append(titleEl, reasonEl);
    if (detail) box.append(detailEl);
    box.append(actions);
    box.hidden = false;
    box.scrollIntoView({ behavior: "smooth", block: "center" });
}


function show(id) { document.getElementById(id).hidden = false; }
function hide(id) { document.getElementById(id).hidden = true; }
function $(id) { return document.getElementById(id); }

// Event delegation for dynamically-rendered lists: a data-action/data-id
// pair on the element instead of an inline onclick="", and one listener per
// container attached once here rather than re-attached on every re-render.
// An onclick="" attribute in markup is inline script -- the browser has to
// execute it, so script-src has to allow inline execution for it to run at
// all. This (plus initStaticHandlers for the fixed elements in index.html)
// is what lets script-src drop 'unsafe-inline' entirely.
function delegate(containerId, handlers) {
    const container = $(containerId);
    if (!container) return;
    container.addEventListener("click", (e) => {
        const el = e.target.closest("[data-action]");
        if (!el || !container.contains(el)) return;
        const handler = handlers[el.dataset.action];
        if (handler) handler(el.dataset.id, el, e);
    });
}
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
        btn.textContent = theme === "light" ? "Dark" : "Flashbang";
        btn.title = theme === "light"
            ? "Switch to the dark theme"
            : "Switch to the light theme, known here as Flashbang";
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

// Inline rich text for the banners and notices: strings as text, {strong},
// {code}. Built with text nodes throughout -- nothing here is ever HTML.
function appendParts(el, parts) {
    for (const part of parts) {
        if (typeof part === "string") {
            el.append(part);
        } else if (part.strong) {
            const emphasis = document.createElement("strong");
            emphasis.textContent = part.strong;
            el.append(emphasis);
        } else if (part.code) {
            const code = document.createElement("code");
            code.textContent = part.code;
            el.append(code);
        }
    }
}

// Where the README explains the three ways to get HTTPS. The repo URL comes
// from the server, which is the only place it is configured.
function httpsGuideUrl() {
    return authStatus && authStatus.repo_url ? `${authStatus.repo_url}#https` : "";
}

// The sign-in card's banner: a headline, one or two sentences of why, and the
// fixes as a short list rather than a paragraph. It used to be one block of
// about a hundred words, which on a 400px card was taller than the form.
function setBanner(kind, title, body, fixes = []) {
    const banner = $("config-banner");
    banner.textContent = "";
    banner.className = "config-banner banner-" + kind;

    const head = document.createElement("div");
    head.className = "banner-head";
    const icon = document.createElement("span");
    icon.className = "banner-icon";
    icon.setAttribute("aria-hidden", "true");
    const strong = document.createElement("strong");
    strong.textContent = title;
    head.append(icon, strong);

    const text = document.createElement("p");
    text.className = "banner-body";
    appendParts(text, body);
    banner.append(head, text);

    if (fixes.length) {
        const list = document.createElement("ul");
        list.className = "banner-fixes";
        for (const { tag, parts } of fixes) {
            const li = document.createElement("li");
            if (tag) {
                const t = document.createElement("span");
                t.className = "banner-tag";
                t.textContent = tag;
                li.append(t);
            }
            const span = document.createElement("span");
            appendParts(span, parts);
            li.append(span);
            list.append(li);
        }
        banner.append(list);
    }

    const href = httpsGuideUrl();
    if (href) {
        const link = document.createElement("a");
        link.className = "banner-link";
        link.href = href;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = "How to set up HTTPS \u2192";
        banner.append(link);
    }
    banner.hidden = false;
}

// Said wherever COOKIE_SECURE is: docker compose reads the environment when it
// creates a container, so `restart` -- and `stop` then `start` -- keep running
// with the old value. Only `up -d`, which recreates it, applies the edit.
const RECREATE_PARTS = [
    " in ", { code: "docker-compose.yml" }, ", then run ", { code: "docker compose up -d" },
    ". A restart keeps the old value.",
];

function checkCookieConfig(cookieSecure) {
    const httpsPage = location.protocol === "https:";
    // Browsers treat localhost as a secure context, so Secure cookies work there over plain HTTP.
    const localhost = ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);

    if (!httpsPage && cookieSecure && !localhost) {
        setBanner("danger", "Sign-in will not work on this address", [
            "The server requires Secure cookies, but this page is plain HTTP, so your browser ",
            "throws the session cookie away: sign-in seems to succeed, then every request fails.",
        ], [
            { tag: "Fix", parts: ["Set ", { code: "COOKIE_SECURE=false" }, ...RECREATE_PARTS,
                " Then sign in and turn on HTTPS."] },
        ]);
    } else if (httpsPage && !cookieSecure) {
        setBanner("warning", "Session cookies are not protected", [
            "This page is HTTPS, but the session cookie is sent without the Secure flag, ",
            "so it can leak over any plain-HTTP request to this host.",
        ], [
            { tag: "Fix", parts: ["Set ", { code: "COOKIE_SECURE=true" }, ...RECREATE_PARTS] },
        ]);
    } else if (!httpsPage && !cookieSecure && !localhost) {
        // The override case. Sign-in works, which is exactly why this needs
        // saying: nothing looks wrong, and every request is in the clear.
        setBanner("warning", "Not encrypted \u2014 read-only", [
            "This page came over plain HTTP, where your password, code and session can be read ",
            "on the network. So you can sign in and look around, but ",
            { strong: "nothing can be changed or downloaded" }, " until HTTPS is on.",
        ], [
            { tag: "Recommended", parts: [{ strong: "Admin \u2192 HTTPS" },
                " \u2014 a free Let's Encrypt certificate, no proxy needed"] },
            { tag: "Or", parts: ["a reverse proxy \u2014 Nginx Proxy Manager, Caddy or nginx. ",
                "No domain? It can use a self-signed certificate"] },
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
    authStatus = status;
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
    loadUsernameList();
    applyDrawerState();
    renderFilterLibrary();
    loadCustomFilters();
    loadDisplayFilters();
    // Before the first capture is opened: the Viewer draws its headings from
    // this, and the default columns flashing into the operator's own layout
    // is exactly the kind of jump a stored preference should not cause.
    loadColumnLayout();
    syncSaveButton("btn-save-filter", "cap-bpf");
    renderFilterSuggestions("display-filter-suggestions", DISPLAY_SUGGESTIONS);
    renderFilterPreview();
    loadServers();
    loadCaptures();
    setInterval(refreshRunningCaptures, 3000);
}

// --- tabs ---

// Captures open in the Viewer, in the order they were opened. Each is a tab of
// its own on the bar, so two captures can be kept open and compared by clicking
// between them rather than going back to the list each time.
//
// One panel still does the rendering. The tabs are a way IN to a capture, not N
// independent viewers -- a second packet table and filter box per open capture
// would cost real memory for a table nobody is looking at.
let openCaptures = [];

function initTabs() {
    const bar = document.querySelector(".tab-bar");
    if (!bar) return;
    // Delegated rather than bound per tab: capture tabs come and go, and a
    // listener attached at boot cannot reach one created later.
    bar.addEventListener("click", (e) => {
        const closer = e.target.closest("[data-action='close-capture-tab']");
        if (closer && bar.contains(closer)) {
            closeCaptureTab(closer.dataset.id);
            return;
        }
        const tab = e.target.closest(".tab");
        if (!tab || !bar.contains(tab)) return;
        if (tab.dataset.captureId) {
            viewCapture(tab.dataset.captureId);
            return;
        }
        selectStaticTab(tab.dataset.tab);
    });
    // Admin is outside the bar, so delegation on it cannot reach the button.
    $("admin-tab")?.addEventListener("click", () => selectStaticTab("admin"));
    // The side list and the overview cards both carry data-admin-page.
    $("panel-admin")?.addEventListener("click", (e) => {
        const target = e.target.closest("[data-admin-page]");
        if (target) selectAdminPage(target.dataset.adminPage);
    });
}

function selectStaticTab(name) {
    if (!name) return;
    activatePanel(name);
    if (name === "admin") {
        loadEncryptionStatus();
        loadTlsStatus();
        loadAdminSettings();
        loadAdminUsers();
        loadAdminSSHKeys();
        loadAdminKnownHosts();
        loadAdminOverview();
        selectAdminPage(storedAdminPage());
    }
    // The server list carries host trust state, and host trust is changed on
    // the Admin tab next door. Without this the list was only ever fetched at
    // boot and after a server was added, edited or removed -- so trusting a
    // host in Admin and coming back here showed it as still untrusted, from a
    // copy of the data taken before the trust existed.
    if (name === "servers") {
        loadServers();
    }
}

// Shows one panel and marks one tab. Exported by nothing and called by
// everything that changes what is on screen, so there is one place that knows
// how a tab is made to look selected.
function activatePanel(name) {
    // `[data-tab]` rather than `.tab`, because Admin is a toolbar button and
    // not a tab any more. One selector covers both places a panel can be
    // selected from, so a third would not need remembering. Capture tabs carry
    // data-captureId instead and are cleared separately.
    document.querySelectorAll("[data-tab], .tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    const tab = document.querySelector(`[data-tab="${name}"]`);
    if (tab) tab.classList.add("active");
    const panel = $("panel-" + name);
    if (panel) panel.classList.add("active");
}

function renderCaptureTabs() {
    const strip = $("capture-tab-strip");
    if (!strip) return;
    strip.innerHTML = openCaptures
        .map((id) => {
            const c = captures.find((x) => x.id === id);
            // A capture always has an id and may not have a name. The short id
            // is a tab label; the full one is in the title, and in the viewer
            // label inside the panel.
            const label = c && c.name ? c.name : id.slice(0, 8);
            const full = c && c.name ? `${c.name} (${id})` : id;
            return `
            <div class="tab tab-capture${viewingCaptureId === id ? " active" : ""}"
                 data-capture-id="${escHtml(id)}" title="${escHtml(full)}">
                <span class="tab-capture-name">${escHtml(label)}</span>
                <button type="button" class="tab-close" data-action="close-capture-tab"
                        data-id="${escHtml(id)}" aria-label="Close this tab"
                        title="Close this tab. The capture itself is not touched.">&times;</button>
            </div>`;
        })
        .join("");
}

function closeCaptureTab(id) {
    const i = openCaptures.indexOf(id);
    if (i === -1) return;
    openCaptures.splice(i, 1);
    if (viewingCaptureId !== id) {
        renderCaptureTabs();
        return;
    }
    // The tab being closed is the one on screen, so something has to take its
    // place: the capture that slid into its position, else the one before it,
    // else nothing -- and nothing means the Viewer has no tabs left and should
    // not be the visible panel.
    viewingCaptureId = null;
    const next = openCaptures[i] || openCaptures[i - 1];
    if (next) {
        viewCapture(next);
        return;
    }
    renderCaptureTabs();
    selectStaticTab("capture");
}

// Called whenever the capture list is refreshed: picks up renames and
// captures deleted from under an open tab.
function syncCaptureTabs() {
    const before = openCaptures.length;
    openCaptures = openCaptures.filter((id) => captures.some((c) => c.id === id));
    if (openCaptures.length !== before && !openCaptures.includes(viewingCaptureId)) {
        // The capture being viewed was deleted elsewhere. Leaving its packets
        // on screen under a tab that no longer exists is worse than leaving.
        viewingCaptureId = null;
        selectStaticTab("capture");
    }
    renderCaptureTabs();
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
    const count = $("server-count");
    if (count) {
        count.textContent = String(activeServers.length);
        count.hidden = !activeServers.length;
    }
    if (!activeServers.length) {
        el.innerHTML = '<div class="empty-state server-list-empty">No servers added</div>';
        return;
    }
    el.innerHTML = activeServers
        .map((s) => {
            // A connection to a host with no trusted keys is refused outright,
            // so the list has to say which entries cannot be used yet --
            // otherwise the first sign of it is a capture that will not start,
            // reported from a screen that never mentioned trust. The trust
            // store itself stays admin-owned and keyed on the endpoint, since
            // several servers can point at one host and share one decision;
            // this only surfaces the state and, for an admin, the way to fix
            // it without leaving the page.
            //
            // The delegator resolves e.target.closest("[data-action]"), so the
            // nested button wins over the row and trusting does not also
            // select the server.
            const untrusted = s.host_trusted === false;
            const warning = untrusted
                ? `<div class="server-warn">
                       <span>Host not trusted &mdash; connections to it are refused.</span>
                       ${currentUser && currentUser.is_admin
                            ? `<button class="btn btn-xs btn-secondary"
                                 data-action="trust-server-host"
                                 data-id="${escHtml(s.hostname)}:${escHtml(s.port)}">Trust host</button>`
                            : "<span>Ask an admin to trust it under Admin \u2192 Known Hosts.</span>"}
                   </div>`
                : "";
            // A server the backend has proved to be this very machine. Captures
            // from it are refused, and an entry that simply failed every time
            // with no stated reason is the thing this is here to avoid. The row
            // stays: deleting someone's configuration over a finding is not
            // ours to do.
            const selfTarget = s.self_target_reason
                ? `<div class="server-warn server-warn-self">
                       <span><strong>This is the machine pcap-server runs on.</strong>
                       Captures from it are refused &mdash; ${escHtml(s.self_target_reason)}.</span>
                   </div>`
                : "";
            return `
        <div class="server-item${untrusted ? " untrusted" : ""}${s.self_target_reason ? " self-target" : ""}" data-action="select-server" data-id="${escHtml(s.id)}">
            <span class="server-dot${untrusted || s.self_target_reason ? " server-dot-warn" : ""}" aria-hidden="true"></span>
            <div class="server-item-body">
                <div class="name">${escHtml(s.name || s.hostname)}</div>
                <div class="detail">${escHtml(s.username)}@${escHtml(s.hostname)}:${escHtml(s.port)}</div>
                ${s.os_name ? `<div class="server-os">${escHtml(s.os_name)}</div>` : ""}
                ${selfTarget}
                ${warning}
            </div>
        </div>`;
        })
        .join("");
    // Re-applied after the innerHTML replacement above, which drops it.
    if (selectedServerId) {
        document.querySelector(`.server-item[data-id="${CSS.escape(selectedServerId)}"]`)
            ?.classList.add("active");
    }
}

async function trustServerHost(endpoint) {
    // Deliberately not adminTrustHost(): that reports into the Admin tab's
    // message element, which nobody standing on the Servers tab can see.
    try {
        const result = await reviewAndTrustHost(endpoint);
        if (!result) return;   // reviewed and declined -- nothing was pinned
        alert(`Pinned ${result.stored} host key(s) for ${endpoint}. It can be used now.`);
    } catch (e) {
        alert(`Could not trust ${endpoint}: ${e.message}`);
        return;
    }
    await loadServers();
}

// What the right-hand pane holds when no server is chosen: at first load (it
// is also the markup in index.html) and after the chosen one is removed.
const SERVERS_WELCOME = `
    <div class="welcome">
        <div class="welcome-mark" aria-hidden="true"><span></span><span></span><span></span></div>
        <h3>Capture from anywhere you can SSH</h3>
        <p>Pick a server on the left to test it, check it has what a capture
            needs, or start one straight away. Nothing is installed on the host.</p>
        <button type="button" class="btn btn-primary" data-action="show-add-server">+ Add a server</button>
    </div>`;

function selectServer(id) {
    const srv = activeServers.find((s) => s.id === id);
    if (!srv) return;
    selectedServerId = id;
    document.querySelectorAll(".server-item").forEach((el) => el.classList.remove("active"));
    document.querySelector(`.server-item[data-id="${CSS.escape(id)}"]`)?.classList.add("active");

    // Read as facts, not as a form. These used to be disabled inputs, which
    // look exactly like fields that ought to take typing and quietly do not;
    // Edit is the way in, and it is on the action row below.
    const untrusted = srv.host_trusted === false;
    const trust = srv.host_trusted === undefined
        ? ""
        : untrusted
            ? '<span class="pill pill-warn">Not trusted</span>'
            : '<span class="pill pill-good">Trusted</span>';
    const sid = escHtml(srv.id);
    $("server-form-area").innerHTML = `
        <div class="server-detail">
            <header class="server-detail-head">
                <div class="server-detail-title">
                    <h3>${escHtml(srv.name || srv.hostname)}</h3>
                    <div class="server-detail-endpoint">${escHtml(srv.username)}@${escHtml(srv.hostname)}:${escHtml(srv.port)}</div>
                </div>
                ${trust}
            </header>
            <dl class="server-facts">
                <div><dt>Host</dt><dd>${escHtml(srv.hostname)}</dd></div>
                <div><dt>Port</dt><dd>${escHtml(srv.port)}</dd></div>
                <div><dt>Username</dt><dd>${escHtml(srv.username)}</dd></div>
                <div><dt>SSH key</dt><dd>${escHtml(srv.ssh_key_name)}</dd></div>
                <div><dt>sudo</dt><dd>${srv.use_sudo ? "yes &mdash; tcpdump runs under sudo" : "no"}</dd></div>
                <div><dt>OS</dt><dd id="server-os">${serverOsFact(srv)}</dd></div>
            </dl>
            <div class="form-actions server-detail-actions">
                <button class="btn btn-sm btn-primary" data-action="capture-from-server" data-id="${sid}"
                        ${untrusted ? 'disabled title="This host is not trusted yet, so a capture would be refused. Trust it first."' : ""}>Capture from this server</button>
                <button class="btn btn-sm btn-secondary" data-action="test-server" data-id="${sid}">Test connection</button>
                <button class="btn btn-sm btn-secondary" data-action="prereq-check" data-id="${sid}">Check prerequisites</button>
                <button class="btn btn-sm btn-secondary" data-action="edit-server" data-id="${sid}">Edit</button>
                <button class="btn btn-sm btn-danger btn-quiet" data-action="remove-server" data-id="${sid}">Remove</button>
            </div>
            <div id="server-test-result" style="margin-top:8px;font-size:0.8125rem"></div>
            <div id="prereq-result"></div>
        </div>
    `;
}

// Read off the host by the last prerequisite check, so it can be missing or out
// of date; it says where to get it rather than leaving a blank.
function serverOsFact(srv) {
    return srv.os_name
        ? escHtml(srv.os_name)
        : '<span class="fact-unknown">not checked yet &mdash; Check prerequisites reads it</span>';
}

// The step that used to mean leaving this tab, finding the same server again in
// the Capture tab's dropdown, and hoping it was the right one of two similarly
// named hosts. The interface list is reloaded for it, as a change would.
function captureFromServer(id) {
    const sel = $("cap-server");
    if (!sel || ![...sel.options].some((o) => o.value === id)) return;
    sel.value = id;
    loadInterfaces();
    selectStaticTab("capture");
    $("cap-name")?.focus();
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
        // Only the OS fact, not a re-render of the pane: that would throw away
        // the results just drawn above it.
        const srv = activeServers.find((x) => x.id === id);
        const os = $("server-os");
        if (srv && os && selectedServerId === id) os.innerHTML = serverOsFact(srv);
    } catch (e) {
        box.innerHTML = `<div class="prereq-error">${escHtml(e.message)}</div>`;
    }
}

const PREREQ_ICON = { ok: "\u2713", warn: "!", fail: "\u2717", info: "i" };

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
            // An info row is an option, not a fault, and should not read like one.
            fixLabel.textContent = c.status === "info"
                ? "If you want it, run this on the host yourself:"
                : "Run this on the host yourself:";
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

// The SSH key picker. On a new server nothing is chosen: the browser selects
// the first <option> by default, which silently picked whichever key happened
// to sort first and made "I never chose this" the normal outcome. A blank
// option that is selected and disabled means the field starts empty, cannot be
// returned to once a real key is picked, and fails the check below until the
// operator actually decides.
const NO_KEY_CHOSEN = "";

function sshKeyPicker(idPrefix, keys, current = "") {
    if (!keys.length) {
        // Marked so serverFormProblem can tell "you have not picked one yet"
        // from "there is nothing here to pick". Both leave the select empty,
        // and telling someone to choose from a list of none is a dead end.
        return `<label>SSH Key</label>
            <select id="${idPrefix}-key" data-no-keys="1"><option value="">No keys found</option></select>
            <div class="field-hint">No SSH keys are available. Upload one in the Admin panel first.</div>`;
    }
    const opts = keys
        .map((k) => `<option value="${escHtml(k)}"${k === current ? " selected" : ""}>${escHtml(k)}</option>`)
        .join("");
    const placeholder = current
        ? ""
        : `<option value="" selected disabled>— select a key —</option>`;
    return `<label>SSH Key</label>
        <select id="${idPrefix}-key">${placeholder}${opts}</select>
        <div class="field-hint">${current
            ? "The key this server authenticates with."
            : "Open the list and choose the key this server authenticates with."}</div>`;
}

// Read alongside the reject that already happens on submit. Address checks
// catch loopback, this container's own addresses and its default gateway; the
// boot-id check catches the host's own LAN address, which no amount of
// resolving ever could. Neither can prove a target is remote, so the rule is
// still stated here, before the address is typed -- the reasoning is one click
// away. As a paragraph it was the first and largest thing on the form, above
// the field it is about.
const SELF_CAPTURE_WARNING = `
    <details class="form-warning">
        <summary><strong>Do not point this at the machine running pcap-server.</strong> <span class="form-warning-why">Why?</span></summary>
        Capturing from its own host records pcap-server's own traffic — your
        session cookie and TOTP code, and over plain HTTP your password — into a
        capture this UI then stores and serves back. On a Docker host the
        <code>any</code> interface also sweeps every other container's traffic.
        This is refused automatically: localhost, this container's own addresses
        and its gateway are caught by name, and a target that turns out to be
        running on this same kernel — a Docker host reached by its LAN address,
        say — is refused as soon as anything connects to it. Capture this host
        from a different machine.
    </details>`;

function showAddServer() {
    // The list kept the last server highlighted while its pane showed a form
    // for a different, not-yet-existing one.
    selectedServerId = null;
    document.querySelectorAll(".server-item.active").forEach((el) => el.classList.remove("active"));
    Promise.all([loadSSHKeys(), loadUsernames()]).then(([keys, usernames]) => {
        // A datalist suggests without constraining: previous usernames are offered,
        // and a new one can still be typed straight over them.
        $("server-form-area").innerHTML = `
            <h3>Add server</h3>
            ${SELF_CAPTURE_WARNING}
            <div class="form-group"><label>Name <span class="hint">(optional — labels captures from this host)</span></label><input type="text" id="new-srv-name" placeholder="e.g. edge-firewall"></div>
            <div class="form-group"><label>Hostname / IP</label><input type="text" id="new-srv-host"></div>
            <div class="form-row">
                <div class="form-group"><label>Port</label><input type="number" id="new-srv-port" value="22"></div>
                <div class="form-group">
                    ${usernamePicker("new-srv", "")}
                </div>
            </div>
            <div class="form-group">${sshKeyPicker("new-srv", keys)}</div>
            <div class="form-group">${sudoOption("new-srv-sudo", false)}</div>
            <div class="form-actions">
                <button class="btn btn-sm btn-primary" data-action="add-server">Add server</button>
                <button class="btn btn-sm btn-secondary" data-action="probe-test">Test connection</button>
                <button class="btn btn-sm btn-secondary" data-action="probe-prereq">Check prerequisites</button>
            </div>
            <div id="add-server-error" class="error-msg"></div>
            <div id="server-test-result" style="margin-top:8px;font-size:0.8125rem"></div>
            <div id="prereq-result"></div>
        `;
        bindUsernamePicker("new-srv");
    });
}

async function loadUsernames() {
    try {
        knownUsernames = await api("/api/usernames");
    } catch {
        knownUsernames = [];
    }
    return knownUsernames;
}

// The username field used to be a bare text box backed by a <datalist>. A
// datalist draws no arrow and no hint, so a stored username was invisible
// unless you happened to type its first letter -- the feature was there and
// nobody could find it. A real <select> shows what is stored; the sentinel
// option swaps in a text box when the name you want is not on the list yet.
// Cannot collide with a real entry: a stored username must match
// [A-Za-z0-9_][A-Za-z0-9._@-]{0,63}, so a leading "+" is unrepresentable.
const NEW_USERNAME = "+new";

// Same rule as the SSH key picker, for the same reason. A <select> selects its
// first option, so on a new server this arrived with whichever name was used
// most recently already filled in and the text box hidden -- and the only way
// to a new name was the last entry in a dropdown nobody had a reason to open.
// The field read as locked to the stored list, and adding a username through
// the Admin panel first looked like the required route. It isn't, and never
// was; the field just never said so.
//
// So: nothing is preselected when there is no current value. The placeholder is
// disabled, so it cannot be chosen back once a real answer is given, and
// serverFormProblem refuses an empty one.
function usernamePicker(idPrefix, current) {
    const stored = knownUsernames.map((u) => u.username);
    const known = current && stored.includes(current);
    const opts = stored
        .map((u) => `<option value="${escHtml(u)}"${u === current ? " selected" : ""}>${escHtml(u)}</option>`)
        .join("");
    // With nothing stored there is only one path, so take it rather than making
    // someone pick "+ New username" out of a list of one.
    const onlyNew = !stored.length;
    // A current value absent from the list is a name typed earlier, being edited.
    const useNew = onlyNew || Boolean(current && !known);
    const needsPlaceholder = !useNew && !known;
    return `
        <label>Username</label>
        <select id="${idPrefix}-user-select">
            ${needsPlaceholder ? `<option value="" selected disabled>\u2014 select or add \u2014</option>` : ""}
            ${opts}
            <option value="${NEW_USERNAME}"${useNew ? " selected" : ""}>+ New username\u2026</option>
        </select>
        <input type="text" id="${idPrefix}-user" value="${escHtml(useNew ? (current || "") : "")}"
               placeholder="e.g. serveradmin" autocomplete="off"${useNew ? "" : " hidden"}>
        <div class="field-hint">${onlyNew
            ? "The first username you use is saved and offered next time."
            : "Pick a saved username, or choose \u201c+ New username\u201d to type one \u2014 it is saved to SSH usernames for next time."}</div>`;
}

// The select is the source of truth unless "+ New username" is chosen.
function usernameValue(idPrefix) {
    const sel = $(`${idPrefix}-user-select`);
    if (!sel || sel.value === NEW_USERNAME) return $(`${idPrefix}-user`).value.trim();
    return sel.value;
}

// A <select> reports through change, not click, so this cannot go through the
// container's click delegation like the buttons around it.
function bindUsernamePicker(idPrefix) {
    const sel = $(`${idPrefix}-user-select`);
    const box = $(`${idPrefix}-user`);
    if (!sel || !box) return;
    sel.onchange = () => {
        box.hidden = sel.value !== NEW_USERNAME;
        if (!box.hidden) box.focus();
    };
}

// What the form is missing before it is worth sending anywhere. Shared by add,
// test and prereq: a probe against a server with no key chosen fails deep in
// the SSH layer with a message about a missing file, which reads as a broken
// tool rather than an unanswered question.
function serverFormProblem(idPrefix) {
    if (!$(`${idPrefix}-host`).value.trim()) return "Enter a hostname or IP address.";
    const key = $(`${idPrefix}-key`);
    if (key.dataset.noKeys) {
        return "No SSH keys have been uploaded yet. Add one under Admin → SSH keys, "
            + "then come back to this form.";
    }
    if (!key.value) return "Choose an SSH key from the list.";
    if (!usernameValue(idPrefix)) return "Enter a username.";
    return "";
}

// The add form's details, as the API wants them. Shared by add, test and
// prereq so all three always probe exactly what the form says.
function addFormServer() {
    return {
        name: $("new-srv-name").value,
        hostname: $("new-srv-host").value,
        port: parseInt($("new-srv-port").value) || 22,
        username: usernameValue("new-srv"),
        ssh_key_name: $("new-srv-key").value,
        use_sudo: $("new-srv-sudo").checked,
    };
}

async function probeTest() {
    const el = $("server-test-result");
    const problem = serverFormProblem("new-srv");
    if (problem) {
        el.innerHTML = `<span style="color:var(--danger)">${escHtml(problem)}</span>`;
        return;
    }
    $("add-server-error").textContent = "";
    el.innerHTML = '<span class="spinner"></span> Testing...';
    try {
        el.innerHTML = renderTestResult(await api("/api/probe/test", {
            method: "POST", body: JSON.stringify(addFormServer()),
        }));
    } catch (e) {
        el.innerHTML = `<span style="color:var(--danger)">Failed: ${escHtml(e.message)}</span>`;
    }
}

async function probePrereq() {
    const box = $("prereq-result");
    const problem = serverFormProblem("new-srv");
    if (problem) {
        box.innerHTML = `<div class="prereq-error">${escHtml(problem)}</div>`;
        return;
    }
    $("add-server-error").textContent = "";
    box.innerHTML = '<div class="prereq-pending"><span class="spinner"></span> Probing host (read-only)...</div>';
    try {
        renderPrereqs(box, await api("/api/probe/prereq-check", {
            method: "POST", body: JSON.stringify(addFormServer()),
        }));
    } catch (e) {
        box.innerHTML = `<div class="prereq-error">${escHtml(e.message)}</div>`;
    }
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
    const problem = serverFormProblem("new-srv");
    if (problem) {
        $("add-server-error").textContent = problem;
        return;
    }
    try {
        const added = await api("/api/servers", {
            method: "POST",
            body: JSON.stringify(addFormServer()),
        });
        await loadServers();
        // The stored-username list sits on this tab now, so a name introduced
        // by this server has to appear in it without a reload.
        loadUsernameList();
        // Straight to the server's own page: testing and the prerequisite check
        // are the usual next step, and they live there.
        selectServer(added.id);
    } catch (e) {
        $("add-server-error").textContent = e.message;
    }
}

async function testServer(id) {
    const el = $("server-test-result");
    el.innerHTML = '<span class="spinner"></span> Testing...';
    try {
        el.innerHTML = renderTestResult(await api(`/api/servers/${id}/test`, { method: "POST" }));
    } catch (e) {
        el.innerHTML = `<span style="color:var(--danger)">Failed: ${escHtml(e.message)}</span>`;
    }
}

// Which host key the handshake settled on, and whether a stronger one was
// already stored for this host. A weaker choice is worth seeing but never
// blocks: the connection is verified either way.
function renderTestResult(res) {
    let html = '<span style="color:var(--success)">Connection successful</span>';
    if (res.host_key_algorithm) {
        html += `<div style="color:var(--text-secondary);margin-top:4px">`
            + `Host key: <code>${escHtml(res.host_key_algorithm)}</code></div>`;
    }
    if (res.stronger_available) {
        html += `<div style="color:var(--warning,#d29922);margin-top:4px">`
            + `Negotiated <code>${escHtml(res.host_key_algorithm)}</code> although this host also `
            + `offers <code>${escHtml(res.stronger_available)}</code>, which is stronger. `
            + `Not a problem for this connection — but if the host still carries an old `
            + `<code>ssh-rsa</code> key, consider removing it from its sshd config.</div>`;
    }
    return html;
}

async function removeServer(id) {
    await api(`/api/servers/${id}`, { method: "DELETE" });
    await loadServers();
    selectedServerId = null;
    $("server-form-area").innerHTML = SERVERS_WELCOME;
}

const SUDO_HINT = "Only when the SSH user isn't root and tcpdump has no file capabilities (cap_net_raw), which let it capture without sudo. Needs passwordless sudo scoped to tcpdump on that host — not blanket NOPASSWD: ALL. Check prerequisites prints the commands for either.";

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

async function editServer(id) {
    const srv = activeServers.find((s) => s.id === id);
    if (!srv) return;
    const [keys, usernames] = await Promise.all([loadSSHKeys(), loadUsernames()]);
    $("server-form-area").innerHTML = `
        <h3>Edit ${escHtml(srv.name || srv.hostname)}</h3>
        <div class="form-group"><label>Name <span class="hint">(optional — labels captures from this host)</span></label><input type="text" id="edit-srv-name" value="${escHtml(srv.name)}"></div>
        <div class="form-group"><label>Hostname / IP</label><input type="text" id="edit-srv-host" value="${escHtml(srv.hostname)}"></div>
        <div class="form-row">
            <div class="form-group"><label>Port</label><input type="number" id="edit-srv-port" value="${escHtml(srv.port)}"></div>
            <div class="form-group">
                ${usernamePicker("edit-srv", srv.username)}
            </div>
        </div>
        <div class="form-group">${sshKeyPicker("edit-srv", keys, srv.ssh_key_name)}</div>
        <div class="form-group">${sudoOption("edit-srv-sudo", srv.use_sudo)}</div>
        <div class="form-actions">
            <button class="btn btn-sm btn-primary" data-action="save-server-edit" data-id="${escHtml(srv.id)}">Save changes</button>
            <button class="btn btn-sm btn-secondary" data-action="select-server" data-id="${escHtml(srv.id)}">Cancel</button>
        </div>
        <div id="edit-server-error" class="error-msg"></div>
    `;
    bindUsernamePicker("edit-srv");
}

async function saveServerEdit(id) {
    $("edit-server-error").textContent = "";
    const problem = serverFormProblem("edit-srv");
    if (problem) {
        $("edit-server-error").textContent = problem;
        return;
    }
    try {
        await api(`/api/servers/${id}`, {
            method: "PUT",
            body: JSON.stringify({
                name: $("edit-srv-name").value,
                hostname: $("edit-srv-host").value,
                port: parseInt($("edit-srv-port").value) || 22,
                username: usernameValue("edit-srv"),
                ssh_key_name: $("edit-srv-key").value,
                use_sudo: $("edit-srv-sudo").checked,
            }),
        });
        await loadServers();
        loadUsernameList();
        selectServer(id);
    } catch (e) {
        $("edit-server-error").textContent = e.message;
    }
}

// --- capture filter library ---
//
// The expressions people actually reach for, grouped so they can be found by
// the name of the thing rather than by remembering a port number. Everything
// here is BPF -- a capture filter, applied by tcpdump on the remote host. The
// viewer's display filter is a different language and lives behind its own
// help drawer.
//
// Ports are written out rather than relying on tcpdump's service-name lookup:
// `port domain` resolves through /etc/services on the target, which is one more
// thing that can differ between hosts and quietly change what gets recorded.
const FILTER_LIBRARY = [
    {
        group: "Hosts and networks",
        note: "Substitute your own addresses. `host` matches either direction; `src` and `dst` pin it.",
        filters: [
            ["Traffic to or from a host", "host 10.0.0.1"],
            ["From a host only", "src host 10.0.0.1"],
            ["To a host only", "dst host 10.0.0.1"],
            ["Between two hosts", "host 10.0.0.1 and host 10.0.0.2"],
            ["A whole subnet", "net 192.168.1.0/24"],
            ["Leaving a subnet", "src net 192.168.1.0/24 and not dst net 192.168.1.0/24"],
            ["Everything except one host", "not host 10.0.0.1"],
            ["Exclude your own SSH session", "not (tcp port 22 and host 10.0.0.1)"],
            ["One MAC address", "ether host 00:11:22:33:44:55"],
            ["IPv6 only", "ip6"],
        ],
    },
    {
        group: "Windows and Active Directory",
        note: "Domain traffic. Kerberos and LDAP answer on both TCP and UDP, so both are matched.",
        filters: [
            ["Kerberos", "port 88"],
            ["Kerberos password change", "port 464"],
            ["LDAP", "port 389"],
            ["LDAPS", "tcp port 636"],
            ["Global Catalog", "tcp port 3268 or tcp port 3269"],
            ["All AD authentication and directory", "port 88 or port 389 or tcp port 636 or tcp port 3268 or tcp port 3269"],
            ["SMB / CIFS", "tcp port 445"],
            ["SMB including legacy NetBIOS", "tcp port 445 or port 137 or port 138 or tcp port 139"],
            ["RPC endpoint mapper", "tcp port 135"],
            ["WinRM", "tcp port 5985 or tcp port 5986"],
            ["RDP", "tcp port 3389"],
            // NTLMSSP has no port of its own -- it is carried inside SMB, RPC,
            // LDAP and HTTP, at an offset that moves with the enclosing
            // protocol. BPF matches fixed offsets, so there is no capture
            // filter for it. What there is: record the transports it
            // negotiates over, then read `ntlmssp` as a DISPLAY filter in the
            // Viewer, which is where the dissector can actually find it.
            ["NTLM's transports (read with the ntlmssp display filter)",
             "tcp port 445 or tcp port 135 or tcp port 389 or tcp port 80 or tcp port 443"],
            ["DFS and netlogon on one host", "host 10.0.0.10 and (tcp port 445 or port 88)"],
        ],
    },
    {
        group: "Name resolution and core services",
        filters: [
            ["DNS", "port 53"],
            ["DNS to one resolver", "host 8.8.8.8 and port 53"],
            ["DNS over TLS", "tcp port 853"],
            ["mDNS", "udp port 5353"],
            ["LLMNR", "udp port 5355"],
            ["NetBIOS name service", "udp port 137"],
            ["DHCP", "port 67 or port 68"],
            ["DHCPv6", "port 546 or port 547"],
            ["NTP", "udp port 123"],
            ["Syslog", "udp port 514"],
            ["SNMP", "udp port 161 or udp port 162"],
            ["TFTP", "udp port 69"],
        ],
    },
    {
        group: "Web and APIs",
        filters: [
            ["HTTP", "tcp port 80"],
            ["HTTPS", "tcp port 443"],
            ["HTTP/3 and QUIC", "udp port 443"],
            ["Web on any common port", "tcp port 80 or tcp port 443 or tcp port 8080 or tcp port 8443"],
            ["Web traffic to one host", "host 10.0.0.20 and (tcp port 80 or tcp port 443)"],
            ["Proxy ports", "tcp port 3128 or tcp port 8888"],
        ],
    },
    {
        group: "Mail",
        filters: [
            ["SMTP", "tcp port 25"],
            ["SMTP submission", "tcp port 587 or tcp port 465"],
            ["IMAP", "tcp port 143 or tcp port 993"],
            ["POP3", "tcp port 110 or tcp port 995"],
            ["All mail", "tcp port 25 or tcp port 465 or tcp port 587 or tcp port 143 or tcp port 993 or tcp port 110 or tcp port 995"],
        ],
    },
    {
        group: "Remote access and management",
        filters: [
            ["SSH", "tcp port 22"],
            ["Telnet", "tcp port 23"],
            ["FTP control and data", "tcp port 21 or tcp port 20"],
            ["VNC", "tcp portrange 5900-5910"],
            ["RDP", "tcp port 3389"],
            ["IPMI", "udp port 623"],
        ],
    },
    {
        group: "Databases",
        filters: [
            ["MySQL and MariaDB", "tcp port 3306"],
            ["PostgreSQL", "tcp port 5432"],
            ["Microsoft SQL Server", "tcp port 1433"],
            ["Oracle", "tcp port 1521"],
            ["Redis", "tcp port 6379"],
            ["MongoDB", "tcp port 27017"],
            ["Elasticsearch", "tcp port 9200"],
        ],
    },
    {
        group: "Network infrastructure",
        filters: [
            ["ARP", "arp"],
            ["ICMP", "icmp"],
            ["ICMPv6", "icmp6"],
            ["One VLAN", "vlan 100"],
            ["Any tagged VLAN traffic", "vlan"],
            ["Broadcast", "broadcast"],
            ["Multicast", "multicast"],
            ["IGMP", "igmp"],
            ["BGP", "tcp port 179"],
            ["OSPF", "proto 89"],
            ["VRRP", "proto 112"],
            ["LLDP", "ether proto 0x88cc"],
        ],
    },
    {
        group: "Voice and video",
        filters: [
            ["SIP", "port 5060 or port 5061"],
            ["RTP and RTCP, typical range", "udp portrange 10000-20000"],
            ["H.323", "tcp port 1720"],
        ],
    },
    {
        group: "TCP behaviour",
        note: "Byte-level matching against the flags field. Useful for finding connection attempts and resets without recording the payload.",
        filters: [
            ["Connection attempts, SYN only", "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"],
            ["Any SYN, including the reply", "tcp[tcpflags] & tcp-syn != 0"],
            ["Resets", "tcp[tcpflags] & tcp-rst != 0"],
            ["Connection setup and teardown only", "tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0"],
            ["Packets carrying payload", "tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"],
        ],
    },
    {
        group: "Size and shape",
        note: "Handy when you want evidence a conversation happened without recording what was said.",
        filters: [
            ["Small packets only", "less 128"],
            ["Large packets only", "greater 1000"],
            ["Headers only, any traffic", "less 96"],
            ["Non-IP traffic", "not ip and not ip6"],
            // Two halves of one test, because a fragment is either flagged as
            // having more behind it or sits at a non-zero offset. The first
            // fragment of a set has MF set and offset 0; every later one has a
            // non-zero offset. Matching only the offset misses the first
            // fragment, which is the one carrying the headers.
            ["Fragmented packets, all of them",
             "ip[6] & 0x20 != 0 or ip[6:2] & 0x1fff != 0"],
            // Worth its own row: these are what arrives when the first
            // fragment went missing, and they are unreadable on their own.
            ["Fragments after the first", "ip[6:2] & 0x1fff != 0"],
        ],
    },
];


// The library is written label -> expression. The capture list needs the
// reverse: a stored filter, read back off a finished capture, turned into the
// name an operator would recognise. Derived from the same constant rather than
// written out a second time, so a filter can never be offered under one name
// and then listed under another.
//
// First writer wins. A few expressions appear in two groups -- RDP is under
// both Windows and Remote access -- and the earlier group is the one that
// placed it deliberately.
const FILTER_NAMES = (() => {
    const names = new Map();
    for (const group of FILTER_LIBRARY) {
        for (const entry of group.filters) {
            const key = entry[1].trim();
            if (!names.has(key)) names.set(key, entry[0]);
        }
    }
    return names;
})();

// What a capture's filter badge prints.
//
// An EXACT match against the library, and nothing cleverer. Recognising
// `tcp port 443` inside `tcp port 443 and host 10.0.0.1` and calling the
// capture "HTTPS" would name it after the broader half of its own filter, and
// working out how much narrower it really is means a second BPF model living
// in the frontend next to the one in bpfCheckExpression. An expression the
// library does not know is shown verbatim instead, which is never wrong -- the
// CSS truncates it and the title carries it in full.
function filterDisplayName(expr) {
    const trimmed = (expr || "").trim();
    const name = FILTER_NAMES.get(trimmed);
    // `named` decides the typeface, and the distinction is worth drawing: a
    // library name is prose, a bare expression is code, and setting "Kerberos"
    // in a monospace face beside a status badge reads as neither.
    return name
        ? { text: name, named: true }
        : { text: trimmed, named: false };
}


function filterBadge(expr) {
    const { text, named } = filterDisplayName(expr);
    if (!text) return "";
    const cls = named ? "badge-filter" : "badge-filter badge-filter-raw";
    // The title carries the expression in full and unnamed, because that is
    // what the capture actually ran with -- the badge may be truncated, and a
    // library name is a description of the filter rather than the filter.
    const title = `Capture filter \u2014 only packets matching this were recorded:\n${expr}`;
    return `<span class="status-badge ${cls}" title="${escHtml(title)}">${escHtml(text)}</span>`;
}

let filterLibraryQuery = "";

// The operator's own saved filters. Private to the account, fetched rather than
// built in, and rendered as the first group of the library so that "the filter
// I saved last week" is the first thing in the list rather than the last.
let customFilters = [];

async function loadCustomFilters() {
    try {
        customFilters = await api("/api/filters");
    } catch (e) {
        // A library that is eighty-odd built-in expressions and no saved ones
        // is still a usable library, so this does not get an alert. It renders
        // what it has.
        customFilters = [];
    }
    renderFilterLibrary();
}

// Rendered apart from FILTER_LIBRARY rather than folded into it: these rows
// carry a Delete the built-in ones cannot have, and giving every row an owner
// flag to switch on would put the difference in eighty-odd places instead of
// one.
function renderCustomFilterGroup(q) {
    const rows = customFilters.filter(
        (f) => !q
            || f.label.toLowerCase().includes(q)
            || f.expression.toLowerCase().includes(q),
    );
    if (!rows.length) return "";
    return `
        <section class="filter-group filter-group-own">
            <h4>Your filters</h4>
            <p class="field-hint">Saved from the field above, and visible only to you.</p>
            <table class="filter-table">
                ${rows.map((f) => `
                <tr>
                    <td class="filter-label">${escHtml(f.label)}</td>
                    <td class="filter-expr"><code>${escHtml(f.expression)}</code></td>
                    <td class="filter-use">
                        <button type="button" class="btn btn-sm btn-secondary"
                                data-action="use-library-filter" data-id="${escHtml(f.expression)}">Use</button>
                        <button type="button" class="btn btn-sm btn-danger"
                                data-action="delete-custom-filter" data-id="${escHtml(f.id)}"
                                title="Forget this saved filter. Captures already taken with it are untouched.">&times;</button>
                    </td>
                </tr>`).join("")}
            </table>
        </section>`;
}

function renderFilterLibrary() {
    const el = $("filter-library");
    if (!el) return;
    const q = filterLibraryQuery.trim().toLowerCase();
    const own = renderCustomFilterGroup(q);
    const groups = FILTER_LIBRARY
        .map((g) => ({
            ...g,
            filters: g.filters.filter(([label, expr]) =>
                !q || label.toLowerCase().includes(q) || expr.toLowerCase().includes(q)
                   || g.group.toLowerCase().includes(q)),
        }))
        .filter((g) => g.filters.length);

    if (!groups.length && !own) {
        el.innerHTML = `<div class="empty-state" style="padding:24px">Nothing matches "${escHtml(filterLibraryQuery)}"</div>`;
        return;
    }

    el.innerHTML = own + groups
        .map((g) => `
        <section class="filter-group">
            <h4>${escHtml(g.group)}</h4>
            ${g.note ? `<p class="field-hint">${escHtml(g.note)}</p>` : ""}
            <table class="filter-table">
                ${g.filters.map(([label, expr]) => `
                <tr>
                    <td class="filter-label">${escHtml(label)}</td>
                    <td class="filter-expr"><code>${escHtml(expr)}</code></td>
                    <td class="filter-use">
                        <button type="button" class="btn btn-sm btn-secondary"
                                data-action="use-library-filter" data-id="${escHtml(expr)}">Use</button>
                    </td>
                </tr>`).join("")}
            </table>
        </section>`)
        .join("");
}

// Straight into the Capture form, which is the only place a capture filter can
// be used -- copying it to a clipboard would leave the user to paste it there
// themselves.
//
// The library used to be a tab, so this had to switch tabs to show the field it
// had just filled in. It now sits under that field, so there is no journey to
// make: collapse the list and the answer is on screen above it, which is also
// the only feedback that the click did anything.
// BPF's combinators are spelled as words here. libpcap accepts `&&` and `||`
// for the same expressions, so this is a matter of looking like the thing it
// was built from: every row in the library and every example in the man page
// uses the words, and a composed filter that switched notation would read as
// something the operator had not chosen.
//
// There was a harder reason once -- validate_bpf refused `&` and `|`
// outright. That ban also refused every tcpflags filter the library offers,
// so it was narrowed to the characters that have no place in BPF at all.
//
// Both sides are parenthesised. Without that, adding "or port 53" to
// "tcp port 80 and host 10.0.0.1" silently rebinds the whole expression:
// `a and b or c` is `(a and b) or c`, which is not what anyone picking a
// second filter off a list is asking for.
function combineBpf(current, expr, mode) {
    current = (current || "").trim();
    if (mode === "replace" || !current) return expr;
    if (mode === "not") return `not (${expr})`;
    return `(${current}) ${mode} (${expr})`;
}

// The expression as it stands, shown inside the library.
//
// This is the feedback the collapse used to provide. The library closed itself
// on every choice because the field it fills is above it, so nothing else
// confirmed the click had landed -- but that made picking a second filter a
// matter of reopening the list, which is most of the work in building one up.
// Reading rather than writing: the field stays the single source of truth, and
// this follows it whether the change came from a library row or somebody
// typing.
function renderFilterPreview() {
    const bar = $("filter-preview");
    const box = $("cap-bpf");
    if (!bar || !box) return;
    const value = box.value.trim();
    bar.hidden = !value;
    const expr = $("filter-preview-expr");
    if (expr) expr.textContent = value;
}

// Everything that changes the BPF field goes through here -- typing, a library
// row, the Clear button -- so the preview bar never falls out of step with it.
function onBpfFilterChanged() {
    renderFilterPreview();
    syncSaveButton("btn-save-filter", "cap-bpf");
}

// A Save button beside an empty box offers to save nothing, so it is not shown
// until there is something to save.
function syncSaveButton(buttonId, boxId) {
    const btn = $(buttonId);
    const box = $(boxId);
    if (btn && box) btn.hidden = !box.value.trim();
}

function applyBpfFilter(expr, mode) {
    const box = $("cap-bpf");
    if (!box) return;
    box.value = combineBpf(box.value, expr, mode);
    // Deliberately no longer collapses the library, and deliberately does not
    // steal focus into the field either: both of them move the page out from
    // under someone who is part-way through choosing several filters.
    onBpfFilterChanged();
}

// --- BPF combination checking -------------------------------------------
//
// A port-level model of a capture filter, used to answer one question before
// the operator commits to it: would joining these two expressions with `and`
// produce something that matches nothing?
//
// This is the same reasoning backend/bpf.py does, and the BACKEND IS THE
// AUTHORITY -- it also compiles the expression with the real tcpdump, which
// this cannot do. What this copy buys is timing: it runs with no round trip,
// so the menu can carry the warning at the moment of the click rather than
// after a capture has already been started and wasted.
//
// Keep the two in step. If the model changes here it changes there, and the
// calibration cases in bpf.py's docstring are the shared spec.
//
// Sound, not complete: it stays quiet about anything it does not fully
// understand, because a false warning on a filter somebody meant teaches them
// to click through every warning after it.

const BPF_PROTOCOLS = ["tcp", "udp", "sctp"];
const BPF_MAX_CANDIDATE_PORTS = 64;

function bpfTokenize(expr) {
    return (expr || "").toLowerCase().match(/\(|\)|[^\s()]+/g) || [];
}

// Split on `ops` at paren depth zero. null when the parens do not balance --
// tcpdump reports that far better than this can, so it is not our error.
function bpfSplitTop(tokens, ops) {
    const parts = [[]];
    let depth = 0;
    for (const tok of tokens) {
        if (tok === "(") depth++;
        else if (tok === ")") { depth--; if (depth < 0) return null; }
        else if (depth === 0 && ops.includes(tok)) { parts.push([]); continue; }
        parts[parts.length - 1].push(tok);
    }
    return depth === 0 ? parts : null;
}

// Drop brackets that wrap the WHOLE list. `(a) and (b)` also starts with `(`
// and ends with `)`, so the partner has to be checked or the result is
// nonsense.
function bpfStripParens(tokens) {
    while (tokens.length >= 2 && tokens[0] === "(" && tokens[tokens.length - 1] === ")") {
        const inner = tokens.slice(1, -1);
        let depth = 0, ok = true;
        for (const tok of inner) {
            if (tok === "(") depth++;
            else if (tok === ")" && --depth < 0) { ok = false; break; }
        }
        if (!ok || depth !== 0) return tokens;
        tokens = inner;
    }
    return tokens;
}

// `[proto] [src|dst] port N`, or null for anything else. null is returned
// generously: every caller reads it as "constrains nothing", which can only
// make the check quieter.
function bpfParseAlternative(tokens) {
    tokens = bpfStripParens(tokens);
    if (!tokens.length) return null;
    let proto = null, slots = ["src", "dst"], i = 0;
    if (BPF_PROTOCOLS.includes(tokens[i])) proto = tokens[i++];
    else if (["ip", "ip6", "arp", "rarp", "ether", "vlan", "mpls"].includes(tokens[i])) return null;
    if (tokens[i] === "src" || tokens[i] === "dst") slots = [tokens[i++]];
    if (i >= tokens.length) return null;
    const keyword = tokens[i++];
    const rest = tokens.slice(i);
    if (keyword === "port" && rest.length === 1 && /^\d+$/.test(rest[0])) {
        return { ports: new Set([parseInt(rest[0], 10)]), slots, proto };
    }
    if (keyword === "portrange" && rest.length === 1) {
        const m = /^(\d+)-(\d+)$/.exec(rest[0]);
        if (m) {
            const lo = parseInt(m[1], 10), hi = parseInt(m[2], 10);
            if (lo <= hi && hi - lo <= BPF_MAX_CANDIDATE_PORTS) {
                const ports = new Set();
                for (let p = lo; p <= hi; p++) ports.add(p);
                return { ports, slots, proto };
            }
        }
    }
    // Named ports (`port domain`) are not resolved: the mapping lives in
    // /etc/services on the TARGET, which the browser cannot read.
    return null;
}

function bpfRender(tokens) {
    return tokens.join(" ").replace(/\( /g, "(").replace(/ \)/g, ")").trim();
}

// Every port constraint an `and`-chain imposes, however it is bracketed.
// Recursive because the filter library produces exactly that shape:
// `((port 88) and (port 464)) and (...)` after three picks.
function bpfCollect(tokens) {
    tokens = bpfStripParens(tokens);
    if (!tokens.length) return [];

    // `or` binds loosest. A disjunction of port terms collapses into one
    // constraint with several alternatives; anything else constrains nothing
    // we can pin down, since satisfying either branch satisfies the whole.
    const orGroups = bpfSplitTop(tokens, ["or", "||"]);
    if (!orGroups) return [];
    if (orGroups.length > 1) {
        const alts = orGroups.map(bpfParseAlternative);
        if (alts.length && alts.every((a) => a)) {
            return [{ alternatives: alts, source: bpfRender(tokens) }];
        }
        return [];
    }

    const andGroups = bpfSplitTop(tokens, ["and", "&&"]);
    if (!andGroups) return [];
    if (andGroups.length > 1) return andGroups.flatMap(bpfCollect);

    const stripped = bpfStripParens(tokens);
    if (stripped.length !== tokens.length) return bpfCollect(stripped);

    const alt = bpfParseAlternative(tokens);
    return alt ? [{ alternatives: [alt], source: bpfRender(tokens) }] : [];
}

function bpfConstraints(expr) {
    const tokens = bpfTokenize(expr);
    if (!tokens.length) return null;
    // `not` turns a constraint into its complement and this model has no
    // representation for that. One anywhere is enough to stand down.
    if (tokens.some((t) => t === "not" || t === "!")) return null;
    return bpfCollect(tokens);
}

function bpfConstraintPorts(c) {
    const out = new Set();
    for (const alt of c.alternatives) for (const p of alt.ports) out.add(p);
    return out;
}

function bpfHolds(c, proto, src, dst) {
    return c.alternatives.some((alt) =>
        (alt.proto === null || alt.proto === proto) &&
        ((alt.slots.includes("src") && src !== null && alt.ports.has(src)) ||
         (alt.slots.includes("dst") && dst !== null && alt.ports.has(dst))));
}

// Can one packet satisfy every constraint at once? A packet offers a protocol,
// a source port and a destination port, so that is the whole search space. The
// null candidate stands for "some other port entirely", which is what keeps
// `port 80 and host X` satisfiable rather than forcing a named value.
function bpfSatisfiable(constraints) {
    if (!constraints.length) return true;
    const candidates = new Set();
    for (const c of constraints) for (const p of bpfConstraintPorts(c)) candidates.add(p);
    if (candidates.size > BPF_MAX_CANDIDATE_PORTS) return true;
    const values = [null, ...[...candidates].sort((a, b) => a - b)];
    for (const proto of BPF_PROTOCOLS) {
        for (const src of values) {
            for (const dst of values) {
                if (constraints.every((c) => bpfHolds(c, proto, src, dst))) return true;
            }
        }
    }
    return false;
}

function bpfPairwiseDisjoint(sets) {
    for (let i = 0; i < sets.length; i++) {
        for (let j = i + 1; j < sets.length; j++) {
            for (const p of sets[i]) if (sets[j].has(p)) return false;
        }
    }
    return true;
}

// null when there is nothing to say. Otherwise { code, message } -- the same
// two codes backend/bpf.py uses, so the wording stays recognisable whichever
// layer the operator meets first.
function bpfCheckExpression(expr) {
    const constraints = bpfConstraints(expr);
    if (!constraints || constraints.length < 2) return null;

    if (!bpfSatisfiable(constraints)) {
        return {
            code: "bpf_matches_nothing",
            message: "matches nothing — a packet cannot be on all these ports at once",
        };
    }

    const sets = constraints.map(bpfConstraintPorts).filter((s) => s.size);
    if (sets.length >= 2 && bpfPairwiseDisjoint(sets)) {
        return {
            code: "bpf_cross_service_only",
            message: "only matches traffic directly between these services — did you mean “or”?",
        };
    }
    return null;
}

// The same four modes the display filter's right-click menu offers, for the
// same reason: which combinator is wanted cannot be read off the click.
//
// It matters more here than it looks. The library is mostly port and protocol
// rows, where a second pick almost always means `or` -- `tcp port 80 and
// tcp port 443` matches nothing at all -- while a host row combined with a
// protocol row means `and`. A fixed default would be silently wrong for one
// of the two commonest pairings, and a BPF filter that matches nothing does
// not announce itself: the capture just runs and comes back empty.
function bpfMenuItems(expr) {
    const show = expr.length > 46 ? expr.slice(0, 45) + "\u2026" : expr;
    // The check runs on the expression that CHOOSING `and` would actually
    // produce, not on the two halves separately. That matters once a filter
    // has been built up: `(A) and (B)` may be fine while `((A) and (B)) and
    // (C)` is not, and only the assembled string can tell you which.
    const box = $("cap-bpf");
    const andWarning = bpfCheckExpression(combineBpf(box ? box.value : "", expr, "and"));
    return [
        { label: `Replace with: ${show}`, run: () => applyBpfFilter(expr, "replace") },
        // Still clickable when it is flagged. A warning the operator can
        // overrule is a warning they will read; one that takes the option away
        // is one they will resent the first time it is wrong about a filter
        // they meant. The wording carries the reason so the choice is informed
        // rather than merely permitted.
        {
            label: "  \u2026and this",
            hint: "and",
            warn: andWarning ? andWarning.message : "",
            run: () => applyBpfFilter(expr, "and"),
        },
        { label: "  \u2026or this", hint: "or", run: () => applyBpfFilter(expr, "or") },
        { label: "  Replace with NOT this", hint: "not", run: () => applyBpfFilter(expr, "not") },
    ];
}

// An empty box has nothing to combine with, so the menu would be four ways of
// spelling the same outcome. It only opens when there is a choice to make.
async function saveCurrentFilter() {
    const expr = $("cap-bpf").value.trim();
    const msg = $("save-filter-msg");
    const say = (text, bad) => {
        msg.textContent = text;
        msg.className = bad ? "hint save-filter-bad" : "hint save-filter-ok";
    };
    if (!expr) {
        say("There is nothing in the BPF field to save.", true);
        return;
    }
    // prompt() rather than a dialog, matching renameCapture: one short string,
    // and the field it names is on screen behind it.
    const label = prompt("Name for this filter", "");
    if (label === null) return;
    try {
        await api("/api/filters", {
            method: "POST",
            body: JSON.stringify({ label, expression: expr }),
        });
    } catch (e) {
        say(e.message || "Could not save that filter.", true);
        return;
    }
    await loadCustomFilters();
    // Open the library on a successful save. The saved filter has just been
    // added to a list that is collapsed by default, and a button that appears
    // to do nothing is the same bug the filter preview bar was added to fix.
    const details = $("filter-library-details");
    if (details) details.open = true;
    say(`Saved as \u201c${label.trim()}\u201d.`, false);
}

async function deleteCustomFilter(id) {
    const f = customFilters.find((x) => x.id === id);
    if (!confirm(`Forget the saved filter ${f ? `"${f.label}"` : "this"}?\n\n`
        + "Captures already taken with it are not affected.")) return;
    try {
        await api(`/api/filters/${id}`, { method: "DELETE" });
    } catch (e) {
        alert("Could not delete that filter: " + e.message);
        return;
    }
    await loadCustomFilters();
}

function useLibraryFilter(expr, el, ev) {
    const box = $("cap-bpf");
    if (!box) return;
    if (!box.value.trim()) {
        applyBpfFilter(expr, "replace");
        return;
    }
    // Without this the menu opens and shuts on the same click. The document
    // handler that dismisses it fires on any click outside #filter-menu, and
    // this click is outside it -- the menu does not exist yet. The display
    // filter's menu never hit this because it opens from a contextmenu event,
    // which fires no click at all.
    if (ev) ev.stopPropagation();
    openFilterMenu(ev ? ev.clientX : 0, ev ? ev.clientY : 0, bpfMenuItems(expr));
}

// True to go ahead. Asks only when there is something to say.
//
// Two checks stand behind this and they answer different questions. The local
// one (bpfCheckExpression) reasons about ports and catches the filter that is
// valid but useless -- `tcp port 80 and tcp port 443` compiles perfectly well
// and matches only traffic running from one to the other. The server one
// compiles the expression with the real tcpdump, which is the same verdict the
// target host will reach, and is the only thing that can speak to syntax.
//
// The server is asked first because it is the authority, and a network failure
// is not an answer: if it cannot be reached, the local check still runs and
// the capture still starts. A checker that could block a capture by being
// unavailable would be worse than no checker.
async function confirmBpfFilter(expr, iface) {
    if (!expr || !expr.trim()) return true;

    let warning = null;
    try {
        const res = await api("/api/bpf/check?bpf_filter="
            + encodeURIComponent(expr) + "&interface=" + encodeURIComponent(iface));
        warning = res && res.warning;
    } catch (e) {
        // Deliberately silent. The operator asked to start a capture, not to
        // hear about the filter checker.
    }
    if (!warning) {
        const local = bpfCheckExpression(expr);
        if (local) warning = { code: local.code, message: local.message, detail: "" };
    }
    if (!warning) return true;

    const lead = warning.code === "bpf_matches_nothing"
        ? "This capture would almost certainly come back empty."
        : "This filter may not capture what you expect.";
    return confirm(
        lead + "\n\n" + warning.message
        + (warning.detail ? "\n\n" + warning.detail : "")
        + "\n\nFilter:\n" + expr.trim()
        + "\n\nStart the capture anyway?"
    );
}

// --- capture ---

// These change how the packet list is rendered. tcpdump's display flags are
// meaningless for the capture itself, which is always written with -w.
// The zone the reader is actually in, which the container has no way to know:
// it runs on UTC, so tshark's own "local" time is UTC too.
const LOCAL_ZONE = (() => {
    try {
        return Intl.DateTimeFormat().resolvedOptions().timeZone || "your local time zone";
    } catch {
        return "your local time zone";
    }
})();

const FLAG_HELP = {
    "-e": "Show link-layer MAC addresses \u2014 worth turning on when you captured a "
        + "named interface. A capture from \"any\" is Linux cooked and carries the "
        + "sender's address but no destination, so that column stays empty",
    "-tz": `Timestamp as a full date and time in ${LOCAL_ZONE}`,
    "-t": "Hide the timestamp column",
    "-tt": "Timestamp as raw seconds since the epoch",
    "-ttt": "Timestamp as the delta since the previous packet",
    "-tttt": "Timestamp as a full date and time, UTC as the server sees it",
};

const ALLOWED_FLAGS = Object.keys(FLAG_HELP);

// The ones people reach for normally; everything else is situational.
const STANDARD_FLAGS = ["-e", "-tz"];
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
const EXCLUSIVE_FLAG_GROUPS = [["-t", "-tt", "-ttt", "-tttt", "-tz"]];

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
        // The address alone is ambiguous once there is more than one host, and
        // the name alone hides which box it actually resolves to.
        opt.textContent = srv.name ? `${srv.name} - ${srv.hostname}` : srv.hostname;
        sel.append(opt);
    }
    sel.onchange = loadInterfaces;
    loadInterfaces();
}

// tcpdump's every-link pseudo-interface. Mirrors ANY_INTERFACE in
// backend/models.py.
const ANY_INTERFACE = "any";

async function loadInterfaces() {
    const serverId = $("cap-server").value;
    const sel = $("cap-interface");
    const previous = sel.value;
    if (!serverId) {
        fillSelect(sel, [ANY_INTERFACE]);
        return;
    }
    let names;
    try {
        ({ interfaces: names } = await api(`/api/servers/${serverId}/interfaces`));
    } catch {
        // Unreachable host — leave "any" available rather than an empty dropdown.
        fillSelect(sel, [ANY_INTERFACE]);
        return;
    }
    fillSelect(sel, names);
    if (names.includes(previous)) sel.value = previous;
}

// What the confirm dialog says, and the same facts the capture record will
// carry afterwards. Built from the request body rather than from the form, so
// what is described is exactly what is about to be sent -- a summary read off
// the fields separately would be a second model of the request, free to drift
// from it.
function describeCapture(body, serverName) {
    const lines = [
        `Name:       ${body.name}`,
        `Server:     ${serverName}`,
        `Interface:  ${body.interface}`,
        `Duration:   ${body.duration_seconds ? body.duration_seconds + "s" : "the server maximum"}`,
        `Packets:    ${body.count ? body.count : "the server maximum"}`,
        `Snap length: ${body.snap_len === undefined ? "full packets" : body.snap_len + " bytes"}`,
        `Filter:     ${body.bpf_filter.trim() || "none \u2014 everything on that interface"}`,
    ];
    return lines.join("\n");
}

async function startCapture() {
    const serverId = $("cap-server").value;
    if (!serverId) return alert("Add a server first");

    // A name is required by this form and not by the API -- see CaptureRequest
    // in models.py for why the two differ. Checked before anything that costs a
    // round trip: it is answerable from the field itself.
    const nameMsg = $("cap-name-msg");
    const name = $("cap-name").value.trim();
    if (!name) {
        nameMsg.textContent = "Give this capture a name \u2014 you will be looking for it later.";
        nameMsg.className = "hint save-filter-bad";
        $("cap-name").focus();
        return;
    }
    nameMsg.textContent = "";
    nameMsg.className = "hint";

    // A filter that matches nothing does not announce itself: the capture runs
    // for its full duration and comes back empty, which reads exactly like
    // "there was no such traffic". This is the last moment it can be caught
    // before that happens. It is a warning, not a refusal -- an odd-looking
    // filter someone means is still theirs to run.
    if (!await confirmBpfFilter($("cap-bpf").value,
                                $("cap-interface").value || ANY_INTERFACE)) {
        $("cap-bpf").focus();
        return;
    }

    const body = {
        name,
        server_id: serverId,
        interface: $("cap-interface").value || ANY_INTERFACE,
        bpf_filter: $("cap-bpf").value,
    };

    const count = parseInt($("cap-count").value);
    if (count > 0) body.count = count;
    const dur = parseInt($("cap-duration").value);
    if (dur > 0) body.duration_seconds = dur;
    const snap = parseInt($("cap-snaplen").value);
    if (snap >= 0 && $("cap-snaplen").value) body.snap_len = snap;

    // Last stop before tcpdump runs on somebody else's machine.
    //
    // The form has six fields and three of them default to "the server
    // maximum" when left blank, so what is actually about to happen is not
    // legible from the form -- an empty Duration box does not look like five
    // minutes of capture. This is also where a stale field shows itself: the
    // server select and the filter both persist between captures, and starting
    // the right capture against the wrong host is the mistake that costs a
    // capture window on a production box.
    //
    // After the BPF check, not before: this describes the capture that is
    // going to run, and the check can still send the operator back to the
    // filter field.
    const serverName = $("cap-server").selectedOptions[0]?.textContent?.trim() || serverId;
    if (!confirm("Start this capture?\n\n" + describeCapture(body, serverName))) return;

    try {
        await api("/api/captures", { method: "POST", body: JSON.stringify(body) });
        // The name described one capture and is not a default for the next --
        // two captures called the same thing is exactly the unreadable list the
        // field exists to prevent. Cleared only on success: a failed start is
        // about to be retried.
        $("cap-name").value = "";
        await loadCaptures();
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

// "512.0 KB" for half a megabyte made every size in the list read as KB, and
// a multi-gigabyte capture as a seven-digit number of them.
function formatBytes(n) {
    if (!n) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
}

// Wall-clock length of a capture that has both ends recorded; "" otherwise,
// so a missing timestamp shows nothing rather than a made-up duration.
function captureDuration(c) {
    if (!c.started_at || !c.stopped_at) return "";
    const secs = Math.round((new Date(c.stopped_at) - new Date(c.started_at)) / 1000);
    if (!(secs >= 0)) return "";
    if (secs < 60) return `${secs}s`;
    const m = Math.floor(secs / 60);
    if (m < 60) return `${m}m ${secs % 60}s`;
    return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function captureStat(label, value, extra = "") {
    return `<span class="capture-stat${extra}"><span class="capture-stat-label">${label}</span>${value}</span>`;
}

// The buttons a capture offers depend on its state; `id` arrives escaped.
function captureActions(c, id) {
    let actions = "";
    if (c.status === "running") {
        // A running capture has nothing to show until it has been fetched, so
        // it gets no view button -- opening it would just be an empty viewer.
        actions = `<button class="btn btn-sm btn-secondary" data-action="stop-capture" data-id="${id}">Stop</button>`;
    } else if (c.status === "completed") {
        // Downloads are refused over plain HTTP, so say why here rather
        // than letting the button fail with a 403 when clicked.
        const dl = secureTransport
            ? `<button class="btn btn-sm btn-secondary" data-action="download-capture" data-id="${id}">Download</button>
               <button class="btn btn-sm btn-secondary" data-action="sanitize-capture" data-id="${id}"
                 title="Download a copy with credentials, addresses and names replaced">Sanitize</button>`
            : `<button class="btn btn-sm btn-secondary" disabled
                 title="Downloads require HTTPS. A pcap can contain credentials, so it is not sent over an unencrypted connection.">Download (HTTPS only)</button>`;
        actions = `<button class="btn btn-sm btn-primary" data-action="view-capture" data-id="${id}">View</button>
                   ${dl}`;
    }
    actions += ` <button class="btn btn-sm btn-secondary" data-action="rename-capture" data-id="${id}">Rename</button>`;
    actions += ` <button class="btn btn-sm btn-danger btn-quiet" data-action="delete-capture" data-id="${id}">Delete</button>`;
    return actions;
}

function renderCaptures() {
    syncCaptureTabs();
    const el = $("capture-list");
    const count = $("capture-count");
    if (count) {
        const running = captures.filter((c) => c.status === "running").length;
        count.textContent = running ? `${captures.length} \u00b7 ${running} running` : String(captures.length);
        count.hidden = !captures.length;
    }
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
            const status = escHtml(c.status);
            const id = escHtml(c.id);
            const actions = captureActions(c, id);
            const origin = `${escHtml(srvName)} &mdash; ${escHtml(c.command || "")}`;
            // A running capture reports its own count, so 0 there means "none
            // yet" rather than "not counted" and is worth showing.
            const live = c.status === "running";
            const stats = [];
            if (c.interface) stats.push(captureStat("if", escHtml(c.interface)));
            if (live || c.packet_count) {
                stats.push(captureStat("packets", `${Number(c.packet_count).toLocaleString()}${live ? " so far" : ""}`));
            }
            if (c.file_size) stats.push(captureStat("size", formatBytes(c.file_size)));
            const took = captureDuration(c);
            if (took) stats.push(captureStat("took", took));
            if (c.started_at) {
                stats.push(captureStat("started", escHtml(formatStoredAt(c.started_at))));
            }
            // The full id is still one hover away, and selectable there; eight
            // characters are enough to tell two captures apart at a glance.
            stats.push(`<span class="capture-stat capture-id" title="Capture ID: ${id}">#${escHtml(String(c.id).slice(0, 8))}</span>`);
            return `
            <div class="capture-item capture-${status}">
                <div class="info">
                    <div class="title">${c.name ? escHtml(c.name) : origin}</div>
                    ${c.name ? `<div class="meta">${origin}</div>` : ""}
                    <div class="capture-stats">${stats.join("")}</div>
                    ${c.error ? `<div class="capture-error">${escHtml(c.error)}</div>` : ""}
                </div>
                <div class="capture-badges">
                    ${c.bpf_filter ? filterBadge(c.bpf_filter) : ""}
                    <span class="status-badge status-${status}">${status}</span>
                </div>
                <div class="capture-actions">${actions}</div>
            </div>`;
        })
        .join("");
}

async function stopCapture(id) {
    await api(`/api/captures/${id}/stop`, { method: "POST" });
    loadCaptures();
}

async function renameCapture(id) {
    const current = captures.find((c) => c.id === id);
    const name = prompt("Name for this capture", current ? current.name : "");
    if (name === null) return;
    try {
        await api(`/api/captures/${id}/rename`, {
            method: "POST",
            body: JSON.stringify({ name }),
        });
    } catch (e) {
        alert("Rename failed: " + e.message);
        return;
    }
    await loadCaptures();
    if (viewingCaptureId === id) setViewerLabel(id);
}

async function deleteCapture(id) {
    const capture = captures.find((c) => c.id === id);
    const running = !!capture && ["running", "stopping", "transferring"].includes(capture.status);

    // Deleting a live capture is not the same act as deleting a finished one
    // and does not get the same one-line prompt: it ends the capture on the
    // target host, and there is no partial pcap left over to fall back on.
    const question = running
        ? "This capture is still running.\n\n"
            + "Deleting it stops tcpdump on the target host, removes the file it is "
            + "writing there, and closes the SSH session. Nothing is kept \u2014 there "
            + "is no partial capture to download afterwards.\n\n"
            + "Stop and delete it?"
        : "Delete this capture?";
    if (!confirm(question)) return;

    // Interrupting tcpdump and clearing the target takes a few seconds: it is
    // given time to flush before it is killed. Without a busy state the row
    // just sits there looking as though the click did nothing.
    const btn = document.querySelector(
        `[data-action="delete-capture"][data-id="${CSS.escape(id)}"]`,
    );
    const label = btn ? btn.textContent : "";
    if (btn) {
        btn.disabled = true;
        btn.textContent = running ? "Stopping\u2026" : "Deleting\u2026";
    }

    let result;
    try {
        result = await api(`/api/captures/${id}`, { method: "DELETE" });
    } catch (e) {
        // A failed delete used to leave the row in place with nothing said, so
        // the capture looked deleted until the next refresh brought it back.
        if (btn) {
            btn.disabled = false;
            btn.textContent = label;
        }
        alert("Delete failed: " + e.message);
        return;
    }

    if (viewingCaptureId === id) {
        viewingCaptureId = null;
        show("viewer-empty");
        hide("packet-viewer");
    }

    // The one outcome worth interrupting for: the capture is gone from here,
    // but a complete pcap is still on the target host and only the operator
    // can clear it.
    if (result && result.terminated && !result.remote_file_removed && capture && capture.remote_path) {
        alert("The capture was stopped and deleted here, but its file could not be "
            + "removed from the target host.\n\nDelete it there by hand:\n"
            + capture.remote_path);
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

// One line across the top of the app, not a paragraph: the sign-in banner has
// already explained it, and this stays on screen for the whole session. For an
// admin it carries the way out; everyone else is told who has it.
function renderReadOnlyNotice(status) {
    const el = $("readonly-notice");
    if (!el) return;
    // Signed out, the sign-in card's own banner says all of this and more.
    if (!status.read_only || !status.user) {
        el.hidden = true;
        return;
    }
    el.textContent = "";
    el.className = "readonly-notice readonly-bar";
    const tag = document.createElement("span");
    tag.className = "readonly-tag";
    tag.textContent = "Read-only";
    const text = document.createElement("span");
    text.className = "readonly-text";
    text.textContent = "Not encrypted \u2014 changes and downloads are off.";
    el.append(tag, text);
    const admin = status.user && status.user.is_admin;
    if (admin) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn btn-xs readonly-action";
        btn.textContent = "Set up HTTPS";
        btn.addEventListener("click", openHttpsSetup);
        el.append(btn);
    } else if (status.user) {
        const ask = document.createElement("span");
        ask.className = "readonly-ask";
        ask.textContent = "Ask an admin to turn on HTTPS.";
        el.append(ask);
    }
    el.hidden = false;
}

function openHttpsSetup() {
    $("https-refusal")?.setAttribute("hidden", "");
    selectStaticTab("admin");
    selectAdminPage("https");
}

function downloadCaptureById(id) {
    if (!secureTransport) {
        showHttpsRefusal({
            reason: "A capture routinely contains credentials in cleartext. Downloading it "
                + "over an unencrypted connection would put the whole capture on the wire.",
            remedy: HTTPS_REMEDY,
        });
        return;
    }
    window.open(`/api/captures/${id}/download`, "_blank");
}

async function refreshRunningCaptures() {
    const running = captures.filter((c) => ["running", "stopping", "transferring", "pending"].includes(c.status));
    if (!running.length) return;
    await loadCaptures();
}

// --- packet viewer ---

function setViewerLabel(id) {
    const c = captures.find((x) => x.id === id);
    const el = $("viewer-capture-label");
    const heading = c && c.name ? `Capture: ${c.name} (${id})` : "Capture: " + id;
    if (!c) {
        el.textContent = heading;
        return;
    }

    // Where this capture came from, and what it was selecting for -- a filter
    // narrower than you remember reads exactly like a quiet network otherwise.
    const parts = [];
    if (c.server_label) parts.push(escHtml(c.server_label));
    if (c.interface) parts.push(escHtml(c.interface));
    // Empty is not the same claim as "no filter": a capture taken before the
    // column existed also reads empty, and the two are indistinguishable here.
    // Saying nothing is the honest option -- see the migration in database.py.
    if (c.bpf_filter) {
        parts.push(`filter <code class="viewer-origin-filter">${escHtml(c.bpf_filter)}</code>`);
    }
    el.innerHTML = escHtml(heading)
        + (parts.length
            ? `<span class="viewer-capture-origin">${parts.join(" &middot; ")}</span>`
            : "");
}

async function viewCapture(id) {
    viewingCaptureId = id;
    // Opening a capture is what creates its tab. Already-open captures keep the
    // position they had rather than jumping to the end -- a strip that reorders
    // itself under the pointer is one you cannot click twice in the same place.
    if (!openCaptures.includes(id)) openCaptures.push(id);
    activatePanel("viewer");
    renderCaptureTabs();

    hide("viewer-empty");
    show("packet-viewer");
    applyStoredSplit();
    renderPacketLegend();
    setViewerLabel(id);
    $("display-filter").value = "";
    showDisplayFilterError("");
    $("packet-detail-tree").innerHTML = '<div class="empty-state" style="font-size:0.75rem">Click a packet above</div>';
    $("hex-dump").textContent = "";

    activeViewId = ALL_PACKETS_VIEW;
    savedViews = [];
    renderViewTabs();

    await Promise.all([loadPackets(id), loadSavedViews(id)]);
}

// --- saved views --------------------------------------------------------
//
// A named display filter, kept against the capture on the server. The point is
// coming back: a capture opened a week later still has "kerberos", "the
// retransmissions" and "everything to the DC" as tabs, and each one downloads
// as its own pcap containing only what it selects.
//
// Server-side, unlike the drawer and split-height state above. Those are
// per-viewer conveniences worth nothing if lost; these are named work, and the
// filtered download has to be able to read the filter server-side anyway.

// The unfiltered capture. Not a stored row -- it is what the viewer shows with
// an empty filter, so it has no id, cannot be renamed, and cannot be deleted.
const ALL_PACKETS_VIEW = "";

let savedViews = [];
let activeViewId = ALL_PACKETS_VIEW;

async function loadSavedViews(captureId) {
    try {
        savedViews = await api(`/api/captures/${captureId}/views`);
    } catch {
        // A capture still readable without its tabs is better than a viewer
        // that refuses to open because one request failed.
        savedViews = [];
    }
    renderViewTabs();
}

function renderViewTabs() {
    const el = $("view-tabs");
    if (!el) return;
    if (!savedViews.length) {
        el.hidden = true;
        el.innerHTML = "";
        return;
    }
    const tabs = [{ id: ALL_PACKETS_VIEW, name: "All packets", display_filter: "" }, ...savedViews];
    el.innerHTML = tabs
        .map((v) => {
            const selected = v.id === activeViewId;
            const actions = v.id === ALL_PACKETS_VIEW ? "" : `
                <span class="view-tab-actions">
                    <button type="button" class="view-tab-action" title="Download this view as a pcap"
                            data-action="download-view" data-id="${escHtml(v.id)}" aria-label="Download view">&darr;</button>
                    <button type="button" class="view-tab-action" title="Rename, or update to the current filter"
                            data-action="edit-view" data-id="${escHtml(v.id)}" aria-label="Edit view">&#9998;</button>
                    <button type="button" class="view-tab-action" title="Delete this view"
                            data-action="delete-view" data-id="${escHtml(v.id)}" aria-label="Delete view">&times;</button>
                </span>`;
            return `
            <button type="button" class="view-tab" role="tab" aria-selected="${selected}"
                    data-action="select-view" data-id="${escHtml(v.id)}"
                    title="${escHtml(v.display_filter || "the whole capture, unfiltered")}">
                <span class="view-tab-name">${escHtml(v.name)}</span>${actions}
            </button>`;
        })
        .join("");
    el.hidden = false;
}

function selectView(viewId) {
    // The action buttons sit inside the tab, so a click on one bubbles to the
    // tab as well. Selecting the tab you are already on is harmless; running
    // its filter again is a wasted tshark spawn.
    if (viewId === activeViewId) return;
    const view = savedViews.find((v) => v.id === viewId);
    activeViewId = view ? view.id : ALL_PACKETS_VIEW;
    $("display-filter").value = view ? view.display_filter : "";
    renderViewTabs();
    applyDisplayFilter();
}

async function saveCurrentView() {
    if (!viewingCaptureId) return;
    const filter = $("display-filter").value.trim();
    if (!filter) {
        showDisplayFilterError(
            "There is no filter to save. Type or build one first -- the unfiltered "
            + "capture is already the \"All packets\" tab."
        );
        return;
    }
    const name = prompt("Name this view", suggestViewName(filter));
    if (name === null) return;
    try {
        const view = await api(`/api/captures/${viewingCaptureId}/views`, {
            method: "POST",
            body: JSON.stringify({ name, display_filter: filter }),
        });
        savedViews.push(view);
        activeViewId = view.id;
        renderViewTabs();
        showDisplayFilterError("");
    } catch (e) {
        if (!e.httpsRequired) showDisplayFilterError(e.message);
    }
}

// The filter itself is the best default name anyone is going to type, right up
// until it is 200 characters of combinators.
function suggestViewName(filter) {
    return filter.length <= 40 ? filter : filter.slice(0, 37) + "...";
}

async function editView(viewId) {
    const view = savedViews.find((v) => v.id === viewId);
    if (!view) return;
    const name = prompt("Rename this view", view.name);
    if (name === null) return;
    const current = $("display-filter").value.trim();
    // Offered rather than assumed: the common reason to edit a view is that
    // you refined its filter in the box and want the tab to keep the new one.
    const filter = (current && current !== view.display_filter
        && confirm(`Also update this view's filter to:\n\n${current}\n\n(Cancel keeps "${view.display_filter}".)`))
        ? current
        : view.display_filter;
    try {
        const updated = await api(`/api/captures/${viewingCaptureId}/views/${viewId}`, {
            method: "PUT",
            body: JSON.stringify({ name, display_filter: filter }),
        });
        savedViews = savedViews.map((v) => (v.id === viewId ? updated : v));
        renderViewTabs();
        showDisplayFilterError("");
    } catch (e) {
        if (!e.httpsRequired) showDisplayFilterError(e.message);
    }
}

async function deleteView(viewId) {
    const view = savedViews.find((v) => v.id === viewId);
    if (!view) return;
    if (!confirm(`Delete the view "${view.name}"?\n\nThe capture itself is not affected.`)) return;
    try {
        await api(`/api/captures/${viewingCaptureId}/views/${viewId}`, { method: "DELETE" });
    } catch (e) {
        if (!e.httpsRequired) showDisplayFilterError(e.message);
        return;
    }
    savedViews = savedViews.filter((v) => v.id !== viewId);
    if (activeViewId === viewId) {
        activeViewId = ALL_PACKETS_VIEW;
        $("display-filter").value = "";
        applyDisplayFilter();
    }
    renderViewTabs();
}

function downloadView(viewId) {
    if (!secureTransport) {
        showHttpsRefusal({
            reason: "A filtered view is still packet data -- often the most sensitive slice "
                + "of a capture rather than a less sensitive one. Downloading it over an "
                + "unencrypted connection would put it on the wire in the clear.",
            remedy: HTTPS_REMEDY,
        });
        return;
    }
    window.open(`/api/captures/${viewingCaptureId}/views/${viewId}/download`, "_blank");
}

// --- sanitized downloads ---
//
// The dialog collects what to replace, starts the download the same way every
// other download starts (a navigation the browser saves), then polls for the
// summary under a random ticket. The summary is the half that matters: it is
// where the server says what it could NOT sanitize.

const SANITIZE_POLL_MS = 1500;
// The download request may not have reached the server when the first poll
// does. A ticket still unknown after this long means it never will be.
const SANITIZE_START_GRACE_MS = 20000;
let sanitizePollTimer = null;

function initSanitizeDialog() {
    const dialog = $("sanitize-dialog");
    if (!dialog) return;
    const form = $("sanitize-form");
    form.addEventListener("submit", (e) => {
        e.preventDefault();
        startSanitizedDownload();
    });
    form.addEventListener("change", syncSanitizeOptions);
    dialog.addEventListener("click", (e) => {
        if (e.target.closest("[data-sanitize=close]")) dialog.close();
    });
    dialog.addEventListener("close", () => {
        clearTimeout(sanitizePollTimer);
        sanitizePollTimer = null;
    });
}

// A sub-option means nothing without its parent, so it is disabled -- and
// unticked, so a hidden choice cannot ride along with the request.
function syncSanitizeOptions() {
    const form = $("sanitize-form");
    form.querySelectorAll("input[data-parent]").forEach((input) => {
        const parent = form.elements[input.dataset.parent];
        input.disabled = !parent.checked;
        if (!parent.checked) input.checked = false;
    });
}

function openSanitizeDialog(captureId, viewId = ALL_PACKETS_VIEW) {
    if (!secureTransport) {
        showHttpsRefusal({
            reason: "Sanitizing is best effort, so a sanitized capture is still treated as packet "
                + "data: it is not sent over an unencrypted connection either.",
            remedy: HTTPS_REMEDY,
        });
        return;
    }
    const capture = captures.find((c) => c.id === captureId);
    if (!capture || capture.status !== "completed") {
        showBlockingAlert("This capture has not finished",
                          "Only a finished capture can be sanitized.",
                          "Wait for it to finish transferring, then try again.");
        return;
    }
    const view = viewId && viewingCaptureId === captureId
        ? savedViews.find((v) => v.id === viewId)
        : null;
    const dialog = $("sanitize-dialog");
    dialog.dataset.captureId = captureId;
    dialog.dataset.viewId = view ? view.id : "";
    const title = capture.name || captureId;
    $("sanitize-target").textContent = view
        ? `${title}, only the packets in the view "${view.name}"`
        : title;
    $("sanitize-error").hidden = true;
    $("sanitize-form").hidden = false;
    $("sanitize-report").hidden = true;
    syncSanitizeOptions();
    dialog.showModal();
}

function sanitizeTicket() {
    const bytes = new Uint8Array(18);
    crypto.getRandomValues(bytes);
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_");
}

function startSanitizedDownload() {
    const dialog = $("sanitize-dialog");
    const form = $("sanitize-form");
    const captureId = dialog.dataset.captureId;
    const params = new URLSearchParams();
    let anything = false;
    for (const name of ["credentials", "ips", "keep_private", "macs", "keep_oui",
                        "hostnames", "usernames", "strip_payload"]) {
        const checked = form.elements[name].checked;
        params.set(name, checked ? "true" : "false");
        if (checked && !form.elements[name].dataset.parent) anything = true;
    }
    if (!anything) {
        const err = $("sanitize-error");
        err.textContent = "Choose at least one thing to replace.";
        err.hidden = false;
        return;
    }
    if (dialog.dataset.viewId) params.set("view", dialog.dataset.viewId);
    const ticket = sanitizeTicket();
    params.set("ticket", ticket);

    window.open(`/api/captures/${encodeURIComponent(captureId)}/sanitize?${params}`, "_blank");

    form.hidden = true;
    $("sanitize-report").hidden = false;
    $("sanitize-status").textContent = "Sanitizing\u2026 the file downloads as it is built. "
        + "What was replaced is listed here when it finishes.";
    $("sanitize-summary").textContent = "";
    pollSanitizeSummary(captureId, ticket, Date.now());
}

async function pollSanitizeSummary(captureId, ticket, startedAt) {
    const dialog = $("sanitize-dialog");
    if (!dialog.open) return;
    let entry = null;
    try {
        entry = await api(`/api/captures/${encodeURIComponent(captureId)}/sanitize/summary?ticket=${encodeURIComponent(ticket)}`);
    } catch (err) {
        if (Date.now() - startedAt > SANITIZE_START_GRACE_MS) {
            $("sanitize-status").textContent = "The sanitized download did not start: " + err.message;
            return;
        }
    }
    if (entry && entry.done) {
        renderSanitizeSummary(entry);
        return;
    }
    sanitizePollTimer = setTimeout(() => pollSanitizeSummary(captureId, ticket, startedAt), SANITIZE_POLL_MS);
}

function sanitizeRow(label, value, cls = "") {
    const row = document.createElement("div");
    row.className = "sanitize-row" + (cls ? " " + cls : "");
    const name = document.createElement("span");
    name.textContent = label;
    const count = document.createElement("span");
    count.className = "sanitize-count";
    count.textContent = value;
    row.append(name, count);
    return row;
}

function renderSanitizeSummary(entry) {
    const status = $("sanitize-status");
    const box = $("sanitize-summary");
    box.textContent = "";
    if (entry.error) {
        status.textContent = "Sanitizing failed, and the download was cut off. Do not share "
            + "the partial file. " + entry.error;
        status.classList.add("sanitize-failed");
        return;
    }
    status.classList.remove("sanitize-failed");
    const s = entry.summary;
    status.textContent = `Finished: ${s.frames.toLocaleString()} packets.`;

    const replaced = [
        ["IPv4 addresses", s.addresses.ipv4],
        ["IPv6 addresses", s.addresses.ipv6],
        ["MAC addresses", s.addresses.mac],
        ["Credentials", s.masked.credentials],
        ["Usernames", s.masked.usernames],
        ["Hostnames", s.masked.hostnames],
        ["Reverse-DNS names", s.masked.reverse_dns_names],
        ["Packets with payload stripped", s.stripped_frames],
    ].filter(([, n]) => n > 0);
    const heading = document.createElement("h3");
    heading.className = "sanitize-subhead";
    heading.textContent = replaced.length ? "Replaced" : "Nothing needed replacing";
    box.append(heading);
    for (const [label, n] of replaced) {
        box.append(sanitizeRow(label, n.toLocaleString()));
    }

    const unplaced = Object.entries(s.unplaced || {});
    if (unplaced.length) {
        const warn = document.createElement("h3");
        warn.className = "sanitize-subhead sanitize-warn";
        warn.textContent = "Found but not replaced in place";
        const why = document.createElement("p");
        why.className = "sanitize-note";
        why.textContent = "These were read from decoded, decompressed or reassembled data, which "
            + "has no fixed position in a packet. If the field carrying them was replaced (an "
            + "HTTP Authorization header, say) they went with it; otherwise they are still in "
            + "the file. Check before sharing.";
        box.append(warn, why);
        for (const [field, n] of unplaced) box.append(sanitizeRow(field, n.toLocaleString(), "sanitize-warn"));
    }

    const undissected = s.undissected || [];
    if (undissected.length) {
        const head = document.createElement("h3");
        head.className = "sanitize-subhead";
        head.textContent = "Payload no dissector understood";
        const why = document.createElement("p");
        why.className = "sanitize-note";
        why.textContent = "Only protocols Wireshark can read are searched for credentials and names. "
            + "Check what runs on these ports before sharing.";
        box.append(head, why);
        for (const u of undissected) {
            const label = u.port ? `${u.transport.toUpperCase()} port ${u.port}` : u.transport.toUpperCase();
            box.append(sanitizeRow(label, `${u.frames.toLocaleString()} packets, ${formatBytes(u.bytes)}`));
        }
    }
}

// --- statistics: Protocol Hierarchy, Conversations, Follow Stream -----------
//
// Three read-only views over a whole capture, or the slice its current
// display filter selects. Each is its own small <dialog> rather than a tab:
// they are consulted, not lived in, and a capture with none of them open
// should not carry their chrome permanently on screen.

function initStatsDialogs() {
    for (const id of ["protocol-hierarchy-dialog", "conversations-dialog", "follow-stream-dialog"]) {
        const dialog = $(id);
        dialog?.addEventListener("click", (e) => {
            if (e.target.closest("[data-close-dialog]")) dialog.close();
        });
    }
    $("conversations-dialog")?.addEventListener("click", (e) => {
        const btn = e.target.closest("[data-conv-filter]");
        if (!btn) return;
        applyBuiltFilter(btn.dataset.convFilter, "selected");
        $("conversations-dialog").close();
    });
    $("btn-follow-stream-filter")?.addEventListener("click", () => {
        const dialog = $("follow-stream-dialog");
        if (!dialog.dataset.protocol) return;
        applyBuiltFilter(`${dialog.dataset.protocol}.stream eq ${dialog.dataset.stream}`, "selected");
        dialog.close();
    });
}

async function openProtocolHierarchyDialog() {
    if (!viewingCaptureId) return;
    const dialog = $("protocol-hierarchy-dialog");
    const tree = $("protocol-hierarchy-tree");
    const filter = $("display-filter").value.trim();
    $("protocol-hierarchy-scope").textContent = filter ? `Packets matching: ${filter}` : "The whole capture";
    tree.innerHTML = '<div class="empty-state" style="font-size:0.75rem"><span class="spinner"></span></div>';
    dialog.showModal();
    try {
        const nodes = await api(
            `/api/captures/${viewingCaptureId}/protocol-hierarchy?${new URLSearchParams({ display_filter: filter })}`
        );
        tree.innerHTML = nodes.length
            ? renderHierarchyNodes(nodes, nodes[0].frames)
            : '<div class="empty-state" style="font-size:0.75rem">No packets</div>';
    } catch (e) {
        tree.innerHTML = `<div style="color:var(--danger);padding:8px">${escHtml(e.message)}</div>`;
    }
}

function renderHierarchyNodes(nodes, totalFrames, depth = 0) {
    return nodes.map((n) => {
        const pct = totalFrames ? ((n.frames / totalFrames) * 100).toFixed(1) : "0.0";
        return `
            <div class="stats-node" style="padding-left:${depth * 16}px">
                <span class="stats-node-name">${escHtml(n.name)}</span>
                <span class="stats-node-stats">frames:${n.frames.toLocaleString()} bytes:${n.bytes.toLocaleString()} (${pct}%)</span>
            </div>${renderHierarchyNodes(n.children, totalFrames, depth + 1)}`;
    }).join("");
}

async function openConversationsDialog() {
    if (!viewingCaptureId) return;
    const dialog = $("conversations-dialog");
    const filter = $("display-filter").value.trim();
    $("conversations-scope").textContent = filter ? `Packets matching: ${filter}` : "The whole capture";
    $("conversations-pairs").innerHTML = '<tr><td colspan="6" style="text-align:center;padding:12px"><span class="spinner"></span></td></tr>';
    $("conversations-endpoints").innerHTML = "";
    dialog.showModal();
    try {
        const data = await api(
            `/api/captures/${viewingCaptureId}/conversations?${new URLSearchParams({ display_filter: filter })}`
        );
        renderConversationPairs(data.conversations);
        renderConversationEndpoints(data.endpoints);
    } catch (e) {
        $("conversations-pairs").innerHTML = `<tr><td colspan="6" style="color:var(--danger)">${escHtml(e.message)}</td></tr>`;
    }
}

// A network-layer address is enough to build a filter for it -- see
// addressField, already used by the packet list's own row menu -- so the
// same button works whether the row is a conversation pair or one endpoint.
function conversationFilterButton(expr) {
    return expr
        ? `<button type="button" class="btn btn-sm btn-secondary" data-conv-filter="${escHtml(expr)}">Filter</button>`
        : "";
}

function renderConversationPairs(convs) {
    const tbody = $("conversations-pairs");
    if (!convs.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">No conversations</td></tr>';
        return;
    }
    tbody.innerHTML = convs
        .slice()
        .sort((a, b) => (b.bytes_a_to_b + b.bytes_b_to_a) - (a.bytes_a_to_b + a.bytes_b_to_a))
        .map((c) => {
            const field = addressField(c.a);
            const filterExpr = field ? `${buildFieldFilter(field, c.a)} && ${buildFieldFilter(field, c.b)}` : "";
            const totalPkts = c.packets_a_to_b + c.packets_b_to_a;
            const totalBytes = c.bytes_a_to_b + c.bytes_b_to_a;
            return `
            <tr>
                <td>${escHtml(c.a)}</td>
                <td>${escHtml(c.b)}</td>
                <td>${c.packets_a_to_b.toLocaleString()} pkts, ${formatBytes(c.bytes_a_to_b)}</td>
                <td>${c.packets_b_to_a.toLocaleString()} pkts, ${formatBytes(c.bytes_b_to_a)}</td>
                <td>${totalPkts.toLocaleString()} pkts, ${formatBytes(totalBytes)}</td>
                <td>${conversationFilterButton(filterExpr)}</td>
            </tr>`;
        }).join("");
}

function renderConversationEndpoints(endpoints) {
    const tbody = $("conversations-endpoints");
    if (!endpoints.length) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No endpoints</td></tr>';
        return;
    }
    tbody.innerHTML = endpoints
        .slice()
        .sort((a, b) => b.bytes - a.bytes)
        .map((e) => {
            const field = addressField(e.address);
            return `
            <tr>
                <td>${escHtml(e.address)}</td>
                <td>${e.packets.toLocaleString()}</td>
                <td>${formatBytes(e.bytes)}</td>
                <td>${conversationFilterButton(field ? buildFieldFilter(field, e.address) : "")}</td>
            </tr>`;
        }).join("");
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(Math.floor(hex.length / 2));
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return bytes;
}

// The same lossy ASCII rendering Wireshark's own Follow Stream dialog uses --
// printable bytes and the two line-ending characters as themselves, anything
// else as a dot. Exact bytes are still one click away, via Export bytes on
// the packet each segment came from; this view is for reading, not for
// round-tripping.
function bytesToStreamText(bytes) {
    let out = "";
    for (const b of bytes) out += (b >= 32 && b < 127) || b === 10 || b === 13 ? String.fromCharCode(b) : ".";
    return out;
}

async function openFollowStream(protocol, stream) {
    if (!viewingCaptureId) return;
    const dialog = $("follow-stream-dialog");
    dialog.dataset.protocol = protocol;
    dialog.dataset.stream = String(stream);
    $("follow-stream-title").textContent = `Follow ${protocol.toUpperCase()} Stream`;
    $("follow-stream-endpoints").textContent = "";
    $("follow-stream-body").innerHTML = '<span class="empty-state" style="font-size:0.75rem"><span class="spinner"></span></span>';
    dialog.showModal();
    try {
        const result = await api(`/api/captures/${viewingCaptureId}/stream/${protocol}/${stream}`);
        $("follow-stream-endpoints").textContent =
            `${result.a} ↔ ${result.b} • ${result.segments.length} segment${result.segments.length === 1 ? "" : "s"}`;
        $("follow-stream-body").innerHTML = result.segments.map((seg) => {
            const text = bytesToStreamText(hexToBytes(seg.hex));
            return `<span class="${seg.from_a ? "stream-a" : "stream-b"}">${escHtml(text)}</span>`;
        }).join("") || '<span class="empty-state" style="font-size:0.75rem">No data was exchanged</span>';
    } catch (e) {
        $("follow-stream-body").innerHTML = `<span style="color:var(--danger)">${escHtml(e.message)}</span>`;
    }
}

// Typing over a saved view's filter means you are no longer looking at that
// view, and the tab should stop claiming you are.
function noteFilterEditedByHand() {
    if (activeViewId === ALL_PACKETS_VIEW) return;
    const view = savedViews.find((v) => v.id === activeViewId);
    if (view && $("display-filter").value.trim() !== view.display_filter) {
        activeViewId = ALL_PACKETS_VIEW;
        renderViewTabs();
    }
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
    "-tz": "time-full",
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

// Clickable starting points for the display filter. The capture filter had a
// row of these too, until the filter library under it made them redundant --
// eight examples beside eighty-odd searchable ones.
const DISPLAY_SUGGESTIONS = [
    ["ip.addr == 10.0.0.1", "one host, either direction"],
    ["tcp.port == 443", "one TCP port"],
    ["dns", "a protocol on its own"],
    ["http.request", "requests only"],
    ["tcp.flags.syn == 1 and tcp.flags.ack == 0", "connection attempts"],
    ["tcp.analysis.retransmission", "retransmissions"],
    ["frame.len > 1000", "large frames"],
    ["!(arp or icmp)", "everything except noise"],
];

function renderFilterSuggestions(containerId, suggestions) {
    const el = $(containerId);
    if (!el) return;
    el.innerHTML = '<span class="filter-suggestions-label">Try:</span>'
        + suggestions
            .map(([expr, why]) =>
                `<button type="button" class="filter-chip" data-action="use-filter"
                         data-id="${escHtml(expr)}" title="${escHtml(why)}">${escHtml(expr)}</button>`)
            .join("");
}

// --- display-filter autocomplete ----------------------------------------
//
// The "Try:" chips are eight worked examples; they teach the shape of a filter
// and then have nothing more to offer. This is the part after that: you know
// the protocol is called something like "kerberos" or the field starts
// "tcp.analysis.", and you want the rest of the name without going to look it
// up. Protocol names come first in the list because a bare protocol is a
// complete filter on its own -- `dns` is valid where `dns.qry.name` is not.
//
// Matching is on the token under the caret, not the whole box, so it keeps
// working in the middle of `ip.addr == 10.0.0.1 && tc|`.
const DISPLAY_FILTER_PROTOCOLS = [
    ["arp", "address resolution"],
    ["bootp", "DHCP (tshark's name for it)"],
    ["data", "undissected payload"],
    ["dhcp", "DHCP"],
    ["dhcpv6", "DHCPv6"],
    ["dns", "DNS queries and answers"],
    ["eth", "Ethernet"],
    ["ftp", "FTP control"],
    ["ftp-data", "FTP transfers"],
    ["gquic", "Google QUIC"],
    ["gre", "GRE tunnel"],
    ["http", "HTTP/1.x"],
    ["http2", "HTTP/2"],
    ["icmp", "ICMP"],
    ["icmpv6", "ICMPv6"],
    ["igmp", "IGMP"],
    ["imap", "IMAP"],
    ["ip", "IPv4"],
    ["ipv6", "IPv6"],
    ["isakmp", "IKE / IPsec key exchange"],
    ["kerberos", "Kerberos"],
    ["ldap", "LDAP"],
    ["llmnr", "link-local name resolution"],
    ["lldp", "link layer discovery"],
    ["mdns", "multicast DNS"],
    ["mysql", "MySQL"],
    ["nbns", "NetBIOS name service"],
    ["nfs", "NFS"],
    ["ntlmssp", "NTLM authentication, inside SMB/RPC/LDAP/HTTP"],
    ["ntp", "NTP"],
    ["ospf", "OSPF"],
    ["pgsql", "PostgreSQL"],
    ["pop", "POP3"],
    ["quic", "QUIC"],
    ["radius", "RADIUS"],
    ["rdp", "RDP"],
    ["rtp", "RTP media"],
    ["sip", "SIP"],
    ["sll", "Linux cooked capture (tcpdump -i any)"],
    ["smb", "SMB1"],
    ["smb2", "SMB2/3"],
    ["smtp", "SMTP"],
    ["snmp", "SNMP"],
    ["ssdp", "SSDP discovery"],
    ["ssh", "SSH"],
    ["stun", "STUN / NAT traversal"],
    ["syslog", "syslog"],
    ["tcp", "TCP"],
    ["telnet", "telnet"],
    ["tftp", "TFTP"],
    ["tls", "TLS (was ssl)"],
    ["udp", "UDP"],
    ["vlan", "802.1Q VLAN"],
    ["vrrp", "VRRP"],
    ["wireguard", "WireGuard"],
    ["websocket", "WebSocket"],
];

const DISPLAY_FILTER_FIELDS = [
    ["frame.number", "packet number"],
    ["frame.len", "frame length in bytes"],
    ["frame.time", "absolute time"],
    ["frame.time_epoch", "epoch seconds"],
    ["frame.time_relative", "seconds since the first packet"],
    ["frame.protocols", "protocol stack, colon separated"],
    ["frame.contains", "raw bytes anywhere in the frame"],
    ["eth.src", "source MAC"],
    ["eth.dst", "destination MAC"],
    ["eth.addr", "either MAC"],
    ["ip.src", "source IPv4"],
    ["ip.dst", "destination IPv4"],
    ["ip.addr", "either IPv4 address"],
    ["ip.proto", "protocol number"],
    ["ip.ttl", "time to live"],
    ["ip.len", "total length"],
    ["ip.id", "identification"],
    ["ip.flags.df", "don't fragment"],
    ["ipv6.src", "source IPv6"],
    ["ipv6.dst", "destination IPv6"],
    ["ipv6.addr", "either IPv6 address"],
    ["tcp.port", "either TCP port"],
    ["tcp.srcport", "source TCP port"],
    ["tcp.dstport", "destination TCP port"],
    ["tcp.stream", "one TCP conversation by index"],
    ["tcp.seq", "sequence number"],
    ["tcp.ack", "acknowledgement number"],
    ["tcp.len", "payload bytes"],
    ["tcp.window_size", "advertised window"],
    ["tcp.flags", "all flags as a bitmask"],
    ["tcp.flags.syn", "SYN bit"],
    ["tcp.flags.ack", "ACK bit"],
    ["tcp.flags.fin", "FIN bit"],
    ["tcp.flags.reset", "RST bit"],
    ["tcp.flags.push", "PSH bit"],
    ["tcp.analysis.flags", "anything tshark flagged"],
    ["tcp.analysis.retransmission", "retransmissions"],
    ["tcp.analysis.duplicate_ack", "duplicate ACKs"],
    ["tcp.analysis.zero_window", "receiver window exhausted"],
    ["udp.port", "either UDP port"],
    ["udp.srcport", "source UDP port"],
    ["udp.dstport", "destination UDP port"],
    ["udp.stream", "one UDP conversation by index"],
    ["icmp.type", "ICMP type"],
    ["icmp.code", "ICMP code"],
    ["arp.opcode", "request (1) or reply (2)"],
    ["dns.qry.name", "queried name"],
    ["dns.qry.type", "record type"],
    ["dns.flags.response", "answer rather than query"],
    ["dns.flags.rcode", "response code"],
    ["http.request", "requests only"],
    ["http.response", "responses only"],
    ["http.request.method", "GET, POST, ..."],
    ["http.request.uri", "requested path"],
    ["http.host", "Host header"],
    ["http.response.code", "status code"],
    ["http.user_agent", "User-Agent header"],
    ["http.content_type", "Content-Type header"],
    ["tls.handshake.type", "1 = client hello, 2 = server hello"],
    ["tls.handshake.extensions_server_name", "SNI host"],
    ["tls.record.version", "record version"],
    ["tls.alert_message", "TLS alerts"],
    ["smb2.cmd", "SMB2 command"],
    ["ldap.messageID", "LDAP message id"],
    ["kerberos.CNameString", "Kerberos principal"],
    ["ntlmssp.messagetype", "NTLM negotiate / challenge / auth"],
    ["ntlmssp.auth.username", "NTLM user name"],
    ["ntlmssp.auth.domain", "NTLM domain"],
    ["ntlmssp.ntlmserverchallenge", "NTLM server challenge"],
    ["ntp.stratum", "NTP stratum"],
    ["vlan.id", "VLAN id"],
];

// Written as an operator rather than a name, so accepting one leaves the box
// in a state that is already valid syntax.
const DISPLAY_FILTER_KEYWORDS = [
    ["and", "combine, same as &&"],
    ["or", "either, same as ||"],
    ["not", "negate, same as !"],
    ["contains", "byte or string containment"],
    ["matches", "regular expression"],
    ["in", "membership: tcp.port in {80 443}"],
];

// One list, ordered by how complete an answer each entry is: a protocol name
// is a filter by itself, a field needs a comparison, a keyword needs both
// sides. Built once -- it never changes.
const DISPLAY_FILTER_VOCAB = [
    ...DISPLAY_FILTER_PROTOCOLS.map(([token, hint]) => ({ token, hint, rank: 0 })),
    ...DISPLAY_FILTER_FIELDS.map(([token, hint]) => ({ token, hint, rank: 1 })),
    ...DISPLAY_FILTER_KEYWORDS.map(([token, hint]) => ({ token, hint, rank: 2 })),
];

const AC_MAX_ITEMS = 10;

// A display-filter token: field names are dotted, and an underscore or digit
// can appear anywhere after the first character.
const AC_TOKEN = /[A-Za-z][A-Za-z0-9_.]*$/;

function displayFilterToken(value, caret) {
    const before = value.slice(0, caret);
    const match = AC_TOKEN.exec(before);
    if (!match) return null;
    return { text: match[0], start: caret - match[0].length, end: caret };
}

// Prefix matches first, then anything containing the text -- so typing "syn"
// offers tcp.flags.syn, and typing "tcp.f" offers the flags before it offers
// anything else that merely mentions them.
function displayFilterMatches(text) {
    const q = text.toLowerCase();
    const scored = [];
    for (const entry of DISPLAY_FILTER_VOCAB) {
        const at = entry.token.toLowerCase().indexOf(q);
        if (at === -1) continue;
        scored.push({ entry, prefix: at === 0 ? 0 : 1 });
    }
    scored.sort((a, b) =>
        a.prefix - b.prefix
        || a.entry.rank - b.entry.rank
        || a.entry.token.length - b.entry.token.length
        || a.entry.token.localeCompare(b.entry.token));
    return scored.slice(0, AC_MAX_ITEMS).map((s) => s.entry);
}

const filterAc = { items: [], active: -1, token: null };

function acBox() { return $("display-filter-ac"); }

function closeFilterAutocomplete() {
    const box = acBox();
    if (!box) return;
    box.hidden = true;
    box.innerHTML = "";
    filterAc.items = [];
    filterAc.active = -1;
    filterAc.token = null;
    $("display-filter")?.setAttribute("aria-expanded", "false");
}

function renderFilterAutocomplete() {
    const box = acBox();
    if (!box) return;
    box.innerHTML = filterAc.items
        .map((entry, i) => `
        <li class="filter-ac-item" role="option" data-index="${i}"
            aria-selected="${i === filterAc.active}">
            <span class="filter-ac-token">${escHtml(entry.token)}</span>
            <span class="filter-ac-hint">${escHtml(entry.hint)}</span>
        </li>`)
        .join("");
    box.hidden = false;
    $("display-filter")?.setAttribute("aria-expanded", "true");
    box.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
}

function updateFilterAutocomplete() {
    const input = $("display-filter");
    if (!input) return;
    const token = displayFilterToken(input.value, input.selectionStart ?? input.value.length);
    if (!token || token.text.length < 1) {
        closeFilterAutocomplete();
        return;
    }
    // Whatever is already typed in full is dropped from the list: accepting it
    // would change nothing, and it pushes a genuinely useful completion off
    // the bottom. Typing "tcp" therefore offers tcp.port and the rest, not
    // "tcp" again.
    const items = displayFilterMatches(token.text)
        .filter((entry) => entry.token !== token.text);
    if (!items.length) {
        closeFilterAutocomplete();
        return;
    }
    filterAc.items = items;
    filterAc.token = token;
    filterAc.active = 0;
    renderFilterAutocomplete();
}

function acceptFilterAutocomplete(index) {
    const input = $("display-filter");
    const entry = filterAc.items[index];
    const token = filterAc.token;
    if (!input || !entry || !token) return;
    const completed = input.value.slice(0, token.start) + entry.token + input.value.slice(token.end);
    input.value = completed;
    // A protocol is a complete filter on its own; a field or keyword still
    // needs something after it, so the caret lands on a space ready for it.
    const needsMore = entry.rank !== 0;
    const caret = token.start + entry.token.length;
    if (needsMore && completed.slice(caret, caret + 1) !== " ") {
        input.value = completed.slice(0, caret) + " " + completed.slice(caret);
    }
    input.setSelectionRange(caret + (needsMore ? 1 : 0), caret + (needsMore ? 1 : 0));
    closeFilterAutocomplete();
    input.focus();
}

function moveFilterAutocomplete(delta) {
    if (!filterAc.items.length) return;
    const count = filterAc.items.length;
    filterAc.active = (filterAc.active + delta + count) % count;
    renderFilterAutocomplete();
}

function initDisplayFilterAutocomplete() {
    const input = $("display-filter");
    const box = acBox();
    if (!input || !box) return;

    input.addEventListener("input", updateFilterAutocomplete);
    // Moving the caret with the arrows or a click changes which token is under
    // it, so the list has to follow rather than keep offering the old one.
    input.addEventListener("click", updateFilterAutocomplete);

    input.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && !box.hidden) {
            closeFilterAutocomplete();
            e.stopPropagation();
            return;
        }
        if (box.hidden) return;
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            moveFilterAutocomplete(e.key === "ArrowDown" ? 1 : -1);
            e.preventDefault();
            return;
        }
        if (e.key === "Enter" || e.key === "Tab") {
            acceptFilterAutocomplete(filterAc.active);
            e.preventDefault();
            // The document-level handler applies the filter on Enter. With the
            // list open, Enter means "take this completion" -- applying a
            // half-typed filter at the same moment would be two actions from
            // one keypress.
            e.stopPropagation();
        }
    });

    // mousedown, not click: the input would blur first and close the list out
    // from under the pointer before the click landed.
    box.addEventListener("mousedown", (e) => {
        const item = e.target.closest(".filter-ac-item");
        if (!item) return;
        e.preventDefault();
        acceptFilterAutocomplete(Number(item.dataset.index));
    });

    input.addEventListener("blur", closeFilterAutocomplete);
}

// Drawer state is a per-viewer convenience, so localStorage is the right home
// for it -- and it can throw or come back empty (private window, blocked site
// data), which must not stop the viewer rendering.
const DRAWER_KEY = "pcap.viewer.drawers";

function openDrawers() {
    try {
        const raw = localStorage.getItem(DRAWER_KEY);
        return raw ? new Set(JSON.parse(raw)) : new Set();
    } catch {
        return new Set();
    }
}

function saveOpenDrawers(open) {
    try {
        localStorage.setItem(DRAWER_KEY, JSON.stringify([...open]));
    } catch {
        // A remembered drawer is not worth failing over.
    }
}

function applyDrawerState() {
    const open = openDrawers();
    for (const name of ["view-options", "filter-help"]) {
        const drawer = $(`drawer-${name}`);
        const toggle = document.querySelector(`.drawer-toggle[data-id="${name}"]`);
        if (!drawer || !toggle) continue;
        const isOpen = open.has(name);
        drawer.hidden = !isOpen;
        toggle.classList.toggle("open", isOpen);
        toggle.setAttribute("aria-expanded", String(isOpen));
    }
}

function toggleDrawer(name) {
    const open = openDrawers();
    if (open.has(name)) open.delete(name);
    else open.add(name);
    saveOpenDrawers(open);
    applyDrawerState();
}

function showDisplayFilterError(message) {
    const el = $("display-filter-error");
    if (!el) return;
    // textContent, not innerHTML: this carries tshark's own output, including
    // the caret line that points at the offending token.
    el.textContent = message || "";
    el.hidden = !message;
}

const LOCAL_TIME_FORMAT = (() => {
    try {
        return new Intl.DateTimeFormat(undefined, {
            year: "numeric", month: "2-digit", day: "2-digit",
            hour: "2-digit", minute: "2-digit", second: "2-digit",
            hour12: false,
        });
    } catch {
        return null;
    }
})();

// tshark's frame.time is the capture host's local time, which in a container is
// UTC. Formatting epoch seconds here is the only way to show the zone the
// person reading the capture is actually in.
function formatLocalTime(epochSeconds) {
    const seconds = parseFloat(epochSeconds);
    if (!isFinite(seconds)) return epochSeconds;
    const when = new Date(seconds * 1000);
    if (isNaN(when.getTime())) return epochSeconds;
    const millis = String(when.getMilliseconds()).padStart(3, "0");
    if (!LOCAL_TIME_FORMAT) return `${when.toISOString()} (UTC)`;
    return `${LOCAL_TIME_FORMAT.format(when)}.${millis}`;
}

// --- the packet list's columns ---
//
// Which columns the list shows, in what order, under what titles, is a
// preference of the account rather than markup: kept server-side so it follows
// the operator to any browser, and used on every capture the way a Wireshark
// column preference is. A column is either one of the built-ins below or any
// tshark field, fetched as one more `-e` on the pass the list already runs.
//
// cls is kept per built-in because the stylesheet sizes these columns by class
// (and .col-iface is what the interface tests select on). An added column has
// no width of its own to claim, so they all share one class.

const BUILTIN_COLUMNS = {
    number: { title: "No.", cls: "col-no", shows: "Frame number" },
    time: { title: "Time", cls: "col-time", shows: "Timestamp, in the format the view flags choose" },
    source: { title: "Source", cls: "col-src", shows: "Source address" },
    destination: { title: "Destination", cls: "col-dst", shows: "Destination address" },
    interface: { title: "Interface", cls: "col-iface", shows: "Which interface the packet crossed (\"any\" captures only)" },
    src_mac: { title: "Src MAC", cls: "col-mac", shows: "Sender's link-layer address" },
    dst_mac: { title: "Dst MAC", cls: "col-mac", shows: "Destination link-layer address" },
    protocol: { title: "Protocol", cls: "col-proto", shows: "Highest-layer protocol" },
    length: { title: "Length", cls: "col-len", shows: "Frame length in bytes" },
    info: { title: "Info", cls: "col-info", shows: "Wireshark's own summary of the packet" },
};

// The layout an account starts on: what this Viewer showed before columns
// could be arranged. The MAC columns are absent for the same reason they used
// to be hidden -- the -e view flag brings them in.
const DEFAULT_COLUMN_IDS = [
    "number", "time", "source", "destination", "interface",
    "protocol", "length", "info",
];
const MAC_COLUMN_IDS = ["src_mac", "dst_mac"];

// Mirrors CUSTOM_COLUMN_PREFIX and the two caps in models.py. A layout the
// server would refuse is one this side should never have sent.
const CUSTOM_COLUMN_PREFIX = "field:";
const MAX_COLUMNS = 24;
const MAX_CUSTOM_COLUMNS = 12;
const MAX_COLUMN_TITLE = 40;

// The fields worth offering by name. Deliberately short: the point of the list
// is to save typing on the columns people actually add, not to reproduce
// tshark's registry, which the field box reaches in full anyway.
const COLUMN_PRESETS = [
    { field: "tcp.srcport", title: "Src port" },
    { field: "tcp.dstport", title: "Dst port" },
    { field: "udp.srcport", title: "UDP src port" },
    { field: "udp.dstport", title: "UDP dst port" },
    { field: "tcp.stream", title: "TCP stream" },
    { field: "tcp.flags", title: "TCP flags" },
    { field: "tcp.window_size", title: "Window" },
    { field: "tcp.analysis.ack_rtt", title: "ACK RTT" },
    { field: "ip.ttl", title: "TTL" },
    { field: "ip.id", title: "IP id" },
    { field: "ip.dsfield.dscp", title: "DSCP" },
    { field: "vlan.id", title: "VLAN" },
    { field: "frame.time_delta", title: "Delta time" },
    { field: "frame.time_epoch", title: "Epoch time" },
    { field: "dns.qry.name", title: "DNS query" },
    { field: "http.host", title: "HTTP host" },
    { field: "http.request.uri", title: "URI" },
    { field: "tls.handshake.extensions_server_name", title: "TLS SNI" },
    { field: "icmp.type", title: "ICMP type" },
];

// null until the first load, and again after a reset: "no layout" is a real
// state, distinct from "a layout that happens to match the default", and it is
// what lets a later change to the default reach anyone who never customised.
let columnLayout = null;
let columnLayoutIsDefault = true;

function isCustomColumn(id) {
    return id.startsWith(CUSTOM_COLUMN_PREFIX);
}

function defaultColumnLayout() {
    return DEFAULT_COLUMN_IDS.map((id) => ({ id, title: BUILTIN_COLUMNS[id].title, field: "" }));
}

// The layout as stored, with anything unrecognisable dropped. A column this
// build does not know is not an error worth blocking the Viewer for -- an
// older tab, or a layout saved by a newer one -- so it is skipped.
function storedColumnLayout() {
    const stored = (columnLayout || []).filter(
        (c) => c && typeof c.id === "string" && (BUILTIN_COLUMNS[c.id] || isCustomColumn(c.id)),
    );
    return stored.length ? stored : defaultColumnLayout();
}

async function loadColumnLayout() {
    try {
        const data = await api("/api/column-layout");
        columnLayoutIsDefault = !!data.default;
        columnLayout = Array.isArray(data.columns) && data.columns.length
            ? data.columns
            : defaultColumnLayout();
    } catch {
        // The Viewer is still usable on the built-in columns, and failing to
        // load a preference is not a reason to refuse to show packets.
        columnLayout = defaultColumnLayout();
        columnLayoutIsDefault = true;
    }
    // This runs during bootstrap, so a capture is not normally open yet. One
    // can be on a reload that lands straight in the Viewer, and the layout
    // arriving after the table was drawn is the case that would otherwise
    // leave the default columns on screen until something else redrew them.
    if (viewingCaptureId) redrawPacketRows();
}

// What the table actually draws: the stored layout, plus the two columns the
// -e flag adds without editing it, minus nothing -- a column that cannot be
// populated is drawn hidden rather than dropped, so the header and the cells
// stay the same length.
function effectiveColumns(flags) {
    const layout = storedColumnLayout().slice();
    if (flags.includes("-e") && !layout.some((c) => MAC_COLUMN_IDS.includes(c.id))) {
        // Where they sat before layouts existed: after Interface, or after
        // Destination on a layout with no Interface column, or at the end.
        const anchor = layout.findIndex((c) => c.id === "interface");
        const fallback = layout.findIndex((c) => c.id === "destination");
        const at = anchor >= 0 ? anchor + 1 : (fallback >= 0 ? fallback + 1 : layout.length);
        layout.splice(at, 0, ...MAC_COLUMN_IDS.map(
            (id) => ({ id, title: BUILTIN_COLUMNS[id].title, field: "" }),
        ));
    }
    // Only a capture on "any" says which interface each packet crossed: it is
    // read from the Linux cooked header, which a capture of one named
    // interface does not have. The column is hidden there rather than left to
    // print nothing on every row.
    const capture = captures.find((c) => c.id === viewingCaptureId);
    const isAny = Boolean(capture && capture.interface === ANY_INTERFACE);
    return layout.map((c) => ({
        id: c.id,
        title: c.title || BUILTIN_COLUMNS[c.id]?.title || c.field || c.id,
        field: c.field || "",
        cls: BUILTIN_COLUMNS[c.id]?.cls || "col-custom",
        hidden: c.id === "interface" && !isAny,
    }));
}

function renderColumnHeaders(columns) {
    const row = $("packet-head-row");
    if (!row) return;
    row.textContent = "";
    for (const col of columns) {
        const th = document.createElement("th");
        th.className = col.cls;
        th.dataset.col = col.id;
        th.textContent = col.title;
        th.hidden = col.hidden;
        th.draggable = true;
        th.title = col.hidden
            ? "Only a capture on \"any\" records which interface a packet crossed"
            : (col.field || BUILTIN_COLUMNS[col.id]?.shows || "");
        row.appendChild(th);
    }
}

// --- rearranging ---

// Every edit goes through here: it writes the layout the operator can see,
// which is the one including anything -e added, so moving a column never
// silently drops another.
async function applyColumnLayout(columns, { refetch = false } = {}) {
    if (!columns.length) return;
    const previous = columnLayout;
    const previousDefault = columnLayoutIsDefault;
    columnLayout = columns;
    columnLayoutIsDefault = false;
    showColumnError("");
    renderColumnDialogRows();
    // Drawn before the save lands: reordering a column should feel like moving
    // it, not like filing a request. The rollback below puts it back if the
    // server refuses.
    if (refetch && viewingCaptureId) loadPackets(viewingCaptureId, $("display-filter").value);
    else redrawPacketRows();
    try {
        await api("/api/column-layout", {
            method: "PUT",
            body: JSON.stringify({ columns }),
        });
    } catch (e) {
        columnLayout = previous;
        columnLayoutIsDefault = previousDefault;
        showColumnError(e.message);
        renderColumnDialogRows();
        if (refetch && viewingCaptureId) loadPackets(viewingCaptureId, $("display-filter").value);
        else redrawPacketRows();
    }
}

function currentColumnsForEdit() {
    // What is on screen, not what is stored: with -e on, the MAC columns are
    // part of the table the operator is rearranging, so an edit materialises
    // them into the layout rather than dropping them on the next redraw.
    return effectiveColumns(getSelectedFlags()).map(
        (c) => ({ id: c.id, title: c.title, field: c.field }),
    );
}

function moveColumn(id, delta) {
    const columns = currentColumnsForEdit();
    const from = columns.findIndex((c) => c.id === id);
    const to = from + delta;
    if (from < 0 || to < 0 || to >= columns.length) return;
    const [moved] = columns.splice(from, 1);
    columns.splice(to, 0, moved);
    applyColumnLayout(columns);
}

function dropColumn(id, beforeId) {
    const columns = currentColumnsForEdit();
    const from = columns.findIndex((c) => c.id === id);
    if (from < 0 || id === beforeId) return;
    const [moved] = columns.splice(from, 1);
    const to = beforeId ? columns.findIndex((c) => c.id === beforeId) : columns.length;
    columns.splice(to < 0 ? columns.length : to, 0, moved);
    applyColumnLayout(columns);
}

function removeColumn(id) {
    const columns = currentColumnsForEdit().filter((c) => c.id !== id);
    if (!columns.length) {
        showColumnError("A layout needs at least one column.");
        return;
    }
    applyColumnLayout(columns);
}

function renameColumn(id, title) {
    const cleaned = title.replace(/\s+/g, " ").trim().slice(0, MAX_COLUMN_TITLE);
    if (!cleaned) return;
    const columns = currentColumnsForEdit().map(
        (c) => (c.id === id ? { ...c, title: cleaned } : c),
    );
    applyColumnLayout(columns);
}

// Wireshark's "Apply as Column", reached from a field's right-click menu in the
// detail pane and from the dialog's own field box.
function addFieldColumn(field, title) {
    const id = CUSTOM_COLUMN_PREFIX + field;
    const columns = currentColumnsForEdit();
    if (columns.some((c) => c.id === id)) {
        showColumnError(`${field} is already a column.`);
        return;
    }
    if (columns.length >= MAX_COLUMNS) {
        showColumnError(`That would be more than ${MAX_COLUMNS} columns.`);
        return;
    }
    if (columns.filter((c) => isCustomColumn(c.id)).length >= MAX_CUSTOM_COLUMNS) {
        showColumnError(`At most ${MAX_CUSTOM_COLUMNS} added columns.`);
        return;
    }
    const clean = (title || field).replace(/\s+/g, " ").trim().slice(0, MAX_COLUMN_TITLE);
    // Before Info rather than after it: Info is the widest column in the table
    // and a new one appended past it starts life off the right-hand edge.
    const at = columns.findIndex((c) => c.id === "info");
    columns.splice(at < 0 ? columns.length : at, 0, { id, title: clean, field });
    // A column with no data behind it yet: this one needs the list fetching
    // again, unlike a move or a rename.
    applyColumnLayout(columns, { refetch: true });
}

function addBuiltinColumn(id) {
    const columns = currentColumnsForEdit();
    if (columns.some((c) => c.id === id) || !BUILTIN_COLUMNS[id]) return;
    if (columns.length >= MAX_COLUMNS) {
        showColumnError(`That would be more than ${MAX_COLUMNS} columns.`);
        return;
    }
    const at = columns.findIndex((c) => c.id === "info");
    columns.splice(at < 0 ? columns.length : at, 0,
        { id, title: BUILTIN_COLUMNS[id].title, field: "" });
    // src_mac and dst_mac are read from the pass only when it is asked for
    // them, so a layout that gains one needs the list fetching again.
    applyColumnLayout(columns, { refetch: MAC_COLUMN_IDS.includes(id) });
}

async function resetColumns() {
    const previous = columnLayout;
    columnLayout = defaultColumnLayout();
    columnLayoutIsDefault = true;
    showColumnError("");
    renderColumnDialogRows();
    if (viewingCaptureId) loadPackets(viewingCaptureId, $("display-filter").value);
    try {
        await api("/api/column-layout", { method: "DELETE" });
    } catch (e) {
        columnLayout = previous;
        showColumnError(e.message);
        renderColumnDialogRows();
        if (viewingCaptureId) loadPackets(viewingCaptureId, $("display-filter").value);
    }
}

// --- dragging a heading ---

let draggedColumnId = null;

function onColumnDragStart(ev) {
    const th = ev.target.closest("th[data-col]");
    if (!th) return;
    draggedColumnId = th.dataset.col;
    th.classList.add("col-dragging");
    ev.dataTransfer.effectAllowed = "move";
    // Firefox starts no drag at all without payload on the transfer.
    ev.dataTransfer.setData("text/plain", th.dataset.col);
}

function onColumnDragOver(ev) {
    const th = ev.target.closest("th[data-col]");
    if (!th || !draggedColumnId) return;
    ev.preventDefault();
    ev.dataTransfer.dropEffect = "move";
    for (const el of document.querySelectorAll("#packet-head-row .col-drop")) {
        el.classList.remove("col-drop");
    }
    if (th.dataset.col !== draggedColumnId) th.classList.add("col-drop");
}

function onColumnDrop(ev) {
    const th = ev.target.closest("th[data-col]");
    if (!th || !draggedColumnId) return;
    ev.preventDefault();
    const moved = draggedColumnId;
    clearColumnDragState();
    dropColumn(moved, th.dataset.col);
}

function clearColumnDragState() {
    draggedColumnId = null;
    for (const el of document.querySelectorAll("#packet-head-row th")) {
        el.classList.remove("col-dragging", "col-drop");
    }
}

function onColumnHeaderContextMenu(ev) {
    const th = ev.target.closest("th[data-col]");
    if (!th) return;
    ev.preventDefault();
    const id = th.dataset.col;
    const title = th.textContent;
    openFilterMenu(ev.clientX, ev.clientY, [
        { label: `Hide ${title}`, run: () => removeColumn(id) },
        { label: "Move left", run: () => moveColumn(id, -1) },
        { label: "Move right", run: () => moveColumn(id, 1) },
        { separator: true },
        { label: "Columns…", hint: "add, rename, reorder", run: () => openColumnDialog() },
        { label: "Reset to default columns", run: () => resetColumns() },
    ]);
}

// --- the Columns dialog ---

function showColumnError(message) {
    const el = $("column-error");
    if (!el) return;
    el.textContent = message;
    el.hidden = !message;
}

function openColumnDialog() {
    const dialog = $("column-dialog");
    if (!dialog) return;
    showColumnError("");
    renderColumnDialogRows();
    dialog.showModal();
}

function renderColumnAddOptions() {
    const select = $("column-add-preset");
    if (!select) return;
    const used = new Set(currentColumnsForEdit().map((c) => c.id));
    select.textContent = "";
    const blank = document.createElement("option");
    blank.value = "";
    blank.textContent = "Choose a column…";
    select.append(blank);
    const builtins = document.createElement("optgroup");
    builtins.label = "Built-in";
    for (const [id, meta] of Object.entries(BUILTIN_COLUMNS)) {
        if (used.has(id)) continue;
        const opt = document.createElement("option");
        opt.value = id;
        opt.textContent = meta.title;
        builtins.append(opt);
    }
    if (builtins.children.length) select.append(builtins);
    const fields = document.createElement("optgroup");
    fields.label = "Fields";
    for (const preset of COLUMN_PRESETS) {
        if (used.has(CUSTOM_COLUMN_PREFIX + preset.field)) continue;
        const opt = document.createElement("option");
        opt.value = CUSTOM_COLUMN_PREFIX + preset.field;
        opt.textContent = `${preset.title} — ${preset.field}`;
        fields.append(opt);
    }
    if (fields.children.length) select.append(fields);
}

function renderColumnDialogRows() {
    const body = $("column-rows");
    if (!body) return;
    const columns = currentColumnsForEdit();
    body.textContent = "";
    columns.forEach((col, index) => {
        body.append(columnDialogRow(col, index, columns.length));
    });
    renderColumnAddOptions();
    // Nothing to reset on an account that has never arranged its columns, and
    // a live button that provably does nothing is worse than a greyed one.
    const reset = $("btn-column-reset");
    if (reset) reset.disabled = columnLayoutIsDefault;
}

function columnDialogRow(col, index, count) {
    const tr = document.createElement("tr");
    tr.dataset.col = col.id;

    const handle = document.createElement("td");
    handle.className = "column-handle";
    handle.textContent = "⠿";
    handle.title = "Drag to reorder";

    const titleCell = document.createElement("td");
    const input = document.createElement("input");
    input.type = "text";
    input.value = col.title;
    input.maxLength = MAX_COLUMN_TITLE;
    input.setAttribute("aria-label", `Title for the ${col.title} column`);
    input.addEventListener("change", () => renameColumn(col.id, input.value));
    titleCell.append(input);

    const shows = document.createElement("td");
    shows.className = "column-shows";
    // A field name is the thing to show for an added column: it is what was
    // typed to create it, and what identifies it in Wireshark too.
    shows.textContent = col.field || BUILTIN_COLUMNS[col.id]?.shows || "";

    const actions = document.createElement("td");
    actions.className = "column-actions";
    actions.append(
        columnButton("↑", "Move up", () => moveColumn(col.id, -1), index === 0),
        columnButton("↓", "Move down", () => moveColumn(col.id, 1), index === count - 1),
        columnButton("✕", "Remove", () => removeColumn(col.id), count === 1, "btn-danger btn-quiet"),
    );

    tr.append(handle, titleCell, shows, actions);
    tr.draggable = true;
    tr.addEventListener("dragstart", (ev) => {
        draggedColumnId = col.id;
        ev.dataTransfer.effectAllowed = "move";
        ev.dataTransfer.setData("text/plain", col.id);
    });
    tr.addEventListener("dragover", (ev) => {
        if (draggedColumnId) ev.preventDefault();
    });
    tr.addEventListener("drop", (ev) => {
        ev.preventDefault();
        const moved = draggedColumnId;
        draggedColumnId = null;
        if (moved) dropColumn(moved, col.id);
    });
    return tr;
}

function columnButton(glyph, label, run, disabled, variant = "btn-secondary") {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `btn btn-sm ${variant}`;
    btn.textContent = glyph;
    btn.title = label;
    btn.setAttribute("aria-label", label);
    btn.disabled = !!disabled;
    btn.addEventListener("click", run);
    return btn;
}

function initColumnControls() {
    $("btn-columns")?.addEventListener("click", openColumnDialog);
    const dialog = $("column-dialog");
    dialog?.addEventListener("click", (e) => {
        if (e.target.closest("[data-close-dialog]")) dialog.close();
    });
    $("btn-column-add")?.addEventListener("click", onColumnAddClicked);
    $("column-add-field")?.addEventListener("keydown", (e) => {
        if (e.key === "Enter") onColumnAddClicked();
    });
    $("btn-column-reset")?.addEventListener("click", resetColumns);

    // The headings are rebuilt on every draw, so these are delegated to the row
    // that survives instead of re-attached to each <th>.
    const head = $("packet-head-row");
    head?.addEventListener("contextmenu", onColumnHeaderContextMenu);
    head?.addEventListener("dragstart", onColumnDragStart);
    head?.addEventListener("dragover", onColumnDragOver);
    head?.addEventListener("drop", onColumnDrop);
    head?.addEventListener("dragend", clearColumnDragState);
}

function onColumnAddClicked() {
    const typed = $("column-add-field").value.trim();
    const chosen = $("column-add-preset").value;
    if (typed) {
        const preset = COLUMN_PRESETS.find((p) => p.field === typed);
        addFieldColumn(typed, preset ? preset.title : typed);
        $("column-add-field").value = "";
        return;
    }
    if (!chosen) {
        showColumnError("Choose a column, or type a tshark field name.");
        return;
    }
    if (isCustomColumn(chosen)) {
        const field = chosen.slice(CUSTOM_COLUMN_PREFIX.length);
        const preset = COLUMN_PRESETS.find((p) => p.field === field);
        addFieldColumn(field, preset ? preset.title : field);
    } else {
        addBuiltinColumn(chosen);
    }
}

// The rows already on screen, redrawn against a layout that changed without
// the data changing -- a move, a rename, a removal. Saves a round trip and a
// spinner for an edit the browser can already satisfy.
function redrawPacketRows() {
    const tbody = $("packet-tbody");
    if (!tbody) return;
    // Before the early return: a column removed while the list is empty still
    // has to leave the headings, and packetColumns() is what draws those.
    const cols = packetColumns();
    if (!currentPackets.length) return;
    tbody.innerHTML = currentPackets.map((p) => packetRowHtml(p, cols)).join("");
}

// One renderer for the table's headings and its cells. Two of them is how a
// column quietly ends up under the wrong heading -- a MAC column drawn in one
// and not the other, a timestamp formatted two ways -- so there is one.
function packetColumns() {
    const flags = getSelectedFlags();
    const columns = effectiveColumns(flags);
    // Rendered here rather than by the caller: the headings and the cells are
    // two halves of one layout, and a renderer that draws only the cells is how
    // a column ends up under the wrong heading.
    renderColumnHeaders(columns);
    applyTimeColumnWidth(flags);
    // A MAC column can now be in the layout without the -e chip being lit, but
    // the server still reads the MAC fields only when asked for them. So the
    // request carries -e when the layout needs it, without lighting the chip:
    // the flag is a view control, and the layout is not.
    const needsMac = columns.some((c) => MAC_COLUMN_IDS.includes(c.id));
    const requestFlags = needsMac && !flags.includes("-e") ? [...flags, "-e"] : flags;
    return {
        flags,
        requestFlags,
        columns,
        localTime: flags.includes("-tz"),
        span: columns.filter((c) => !c.hidden).length,
        // The added columns this layout needs fetching, for the query string.
        fields: columns.filter((c) => c.field && isCustomColumn(c.id)).map((c) => c.field),
    };
}

// The kernel's packet type, as get_packet_list names it: short in the cell,
// spelled out on hover.
const PACKET_DIRECTION = {
    in: ["in", "received by this host"],
    out: ["out", "sent by this host"],
    broadcast: ["bcast", "broadcast"],
    multicast: ["mcast", "multicast"],
    "other-host": ["other", "addressed to another host (seen in promiscuous mode)"],
};

function interfaceCellHtml(p) {
    const [short, long] = PACKET_DIRECTION[p.direction] || ["", ""];
    const parts = [];
    if (p.interface) {
        parts.push(p.interface.startsWith("#")
            ? `interface index ${p.ifindex} (its name was not recorded)`
            : `${p.interface} (index ${p.ifindex})`);
    }
    if (long) parts.push(long);
    if (p.ifindex) parts.push(`filter: sll.ifindex == ${p.ifindex}`);
    const dir = short ? ` <span class="iface-dir">${escHtml(short)}</span>` : "";
    return `<span title="${escHtml(parts.join(" \u2014 "))}">${escHtml(p.interface)}${dir}</span>`;
}

function packetRowHtml(p, cols) {
    // Read by the row's own right-click menu, to offer Follow Stream without
    // a round trip: null on a packet outside any TCP/UDP conversation, so
    // "null" (the string a missing dataset value would otherwise read as)
    // deliberately never appears here.
    const tcpStream = p.tcp_stream ?? "";
    const udpStream = p.udp_stream ?? "";
    const cells = cols.columns.map((col) => packetCellHtml(p, col, cols)).join("");
    return `
            <tr class="${packetClass(p)}" data-frame="${p.number}"
                data-tcp-stream="${tcpStream}" data-udp-stream="${udpStream}">${cells}</tr>`;
}

// One cell. The built-in columns each render their own way -- a timestamp that
// follows the view flags, an interface that carries its index for the filter
// menu -- and everything else is the text tshark printed for that field.
function packetCellHtml(p, col, cols) {
    const attrs = `class="${col.cls}" data-col="${escHtml(col.id)}"${col.hidden ? " hidden" : ""}`;
    switch (col.id) {
        case "number":
            return `<td ${attrs} data-field="frame.number">${p.number}</td>`;
        case "time": {
            const local = cols.localTime;
            const shown = local ? formatLocalTime(p.timestamp) : p.timestamp;
            return `<td ${attrs} title="${escHtml(local ? LOCAL_ZONE : p.timestamp)}">${escHtml(shown)}</td>`;
        }
        case "source":
            return `<td ${attrs} title="${escHtml(p.source)}">${escHtml(p.source)}</td>`;
        case "destination":
            return `<td ${attrs} title="${escHtml(p.destination)}">${escHtml(p.destination)}</td>`;
        case "interface":
            return `<td ${attrs} data-ifindex="${p.ifindex || ""}" data-iface-name="${escHtml(p.interface || "")}">${interfaceCellHtml(p)}</td>`;
        case "src_mac":
            return `<td ${attrs} data-field="eth.src">${escHtml(p.src_mac || "")}</td>`;
        case "dst_mac":
            return `<td ${attrs} data-field="eth.dst">${escHtml(p.dst_mac || "")}</td>`;
        case "protocol":
            return `<td ${attrs}>${escHtml(p.protocol)}</td>`;
        case "length":
            return `<td ${attrs}>${p.length}</td>`;
        case "info":
            return `<td ${attrs}>${escHtml(p.info)}</td>`;
        default: {
            // An added column: whatever tshark printed for its field, escaped
            // like every other value here -- this is capture content, and a
            // packet can carry anything at all in a field.
            //
            // hasOwnProperty, not a plain lookup: a field named __proto__ or
            // constructor passes the field-name pattern, and a bare index into
            // the response object would return Object.prototype rather than a
            // value. The server refuses such a name when the layout is saved,
            // but the table is drawn optimistically before that answer lands.
            const values = p.values || {};
            const value = Object.prototype.hasOwnProperty.call(values, col.field)
                ? values[col.field]
                : "";
            return `<td ${attrs} data-field="${escHtml(col.field)}" title="${escHtml(value)}">${escHtml(value)}</td>`;
        }
    }
}

async function loadPackets(captureId, filter = "") {
    // Every apply, view switch and capture change comes through here, which is
    // what keeps the Save button in step with a box changed by code.
    syncSaveButton("btn-save-display-filter", "display-filter");
    const tbody = $("packet-tbody");
    const cols = packetColumns();
    const { requestFlags, span } = cols;
    currentPackets = [];

    // Kept so a rejected filter can put the packets back. The spinner replaces
    // them before the request goes out, and a filter the server refuses would
    // otherwise leave a spinner that never resolves where the list used to be.
    selectedPacketRow = null;
    setDetailVisible(false);
    const previousRows = tbody.innerHTML;
    tbody.innerHTML = `<tr><td colspan="${span}" style="text-align:center;padding:20px"><span class="spinner"></span> Loading...</td></tr>`;

    try {
        const query = new URLSearchParams({
            limit: "1000",
            display_filter: filter,
            flags: requestFlags.join(","),
            resolve_names: resolveNamesEnabled() ? "true" : "false",
            // The added columns' fields, so one pass fetches them alongside
            // the built-in ones instead of a second request per column.
            columns: cols.fields.join(","),
        });
        const data = await api(`/api/captures/${captureId}/packets?${query}`);
        showDisplayFilterError("");
        if (!data.packets.length) {
            tbody.innerHTML = `<tr><td colspan="${span}" style="text-align:center;padding:20px;color:var(--text-muted)">No packets match</td></tr>`;
            return;
        }
        // Kept so that moving, renaming or removing a column can redraw the
        // table without asking the server for packets it already has.
        currentPackets = data.packets;
        tbody.innerHTML = data.packets.map((p) => packetRowHtml(p, cols)).join("");
    } catch (e) {
        if (e.badDisplayFilter) {
            // The capture is fine and the previous list is still meaningful, so
            // put it back and show the complaint under the box that caused it.
            tbody.innerHTML = previousRows;
            showDisplayFilterError(e.message);
            return;
        }
        tbody.innerHTML = `<tr><td colspan="${span}" style="color:var(--danger);padding:20px">${escHtml(e.message)}</td></tr>`;
    }
}

// --- the operator's own display filters ---
//
// The display-filter counterpart of Your filters in the capture library: kept
// per account, usable on any capture, listed at the top of Filter help. Not a
// saved view -- a view is a tab on one capture.

let customDisplayFilters = [];

async function loadDisplayFilters() {
    try {
        customDisplayFilters = await api("/api/display-filters");
    } catch (e) {
        customDisplayFilters = [];
    }
    renderDisplayFilters();
}

function renderDisplayFilters(message = "", bad = false) {
    const el = $("display-own-filters");
    if (!el) return;
    const note = message
        ? `<span class="hint ${bad ? "save-filter-bad" : "save-filter-ok"}" role="status">${escHtml(message)}</span>`
        : "";
    if (!customDisplayFilters.length) {
        el.innerHTML = note;
        return;
    }
    el.innerHTML = `
        <div class="display-own-head"><strong>Your filters</strong> ${note}</div>
        <div class="display-own-list">
            ${customDisplayFilters.map((f) => `
            <span class="display-own-item">
                <button type="button" class="filter-chip" data-action="use-display-filter"
                        data-id="${escHtml(f.id)}" title="${escHtml(f.expression)}">${escHtml(f.label)}</button>
                <button type="button" class="display-own-delete" data-action="delete-display-filter"
                        data-id="${escHtml(f.id)}" aria-label="Forget ${escHtml(f.label)}"
                        title="Forget this saved filter">&times;</button>
            </span>`).join("")}
        </div>`;
}

async function saveCurrentDisplayFilter() {
    const expr = $("display-filter").value.trim();
    if (!expr) return;
    const label = prompt("Name for this display filter", "");
    if (label === null) return;
    try {
        await api("/api/display-filters", {
            method: "POST",
            body: JSON.stringify({ label, expression: expr }),
        });
    } catch (e) {
        if (!e.httpsRequired) showDisplayFilterError(e.message || "Could not save that filter.");
        return;
    }
    await loadDisplayFilters();
    // Open Filter help, where it landed, so the click visibly did something.
    const open = openDrawers();
    if (!open.has("filter-help")) toggleDrawer("filter-help");
    renderDisplayFilters(`Saved as \u201c${label.trim()}\u201d.`, false);
}

function useDisplayFilter(id) {
    const f = customDisplayFilters.find((x) => x.id === id);
    if (f) useFilterSuggestion(f.expression);
}

async function deleteDisplayFilter(id) {
    const f = customDisplayFilters.find((x) => x.id === id);
    if (!confirm(`Forget the saved display filter ${f ? `"${f.label}"` : "this"}?`)) return;
    try {
        await api(`/api/display-filters/${id}`, { method: "DELETE" });
    } catch (e) {
        renderDisplayFilters(e.message, true);
        return;
    }
    await loadDisplayFilters();
}

function useFilterSuggestion(expr) {
    // Replaces rather than composes. It already has composition, on the
    // right-click menu over a packet field, and these chips are its worked
    // examples -- a starting point rather than something to build onto.
    const box = $("display-filter");
    box.value = expr;
    box.focus();
    applyDisplayFilter();
}

function applyDisplayFilter() {
    if (!viewingCaptureId) return;
    loadPackets(viewingCaptureId, $("display-filter").value);
}

function downloadCapture() {
    if (!viewingCaptureId) return;
    downloadCaptureById(viewingCaptureId);
}

// Nothing selected means the detail pane has nothing to show, so it gives its
// height back to the list rather than holding a third of the window for
// "Click a packet above".
function setDetailVisible(visible) {
    $("packet-viewer")?.classList.toggle("no-selection", !visible);
    const exportBtn = $("btn-export-packet-bytes");
    if (exportBtn) exportBtn.hidden = !visible;
}

// Wireshark's Export Packet Bytes. Entirely client-side: the frame's hex is
// already here for the hex pane, so building a .bin from it costs nothing the
// server needs to do again. Named after the frame number, not the capture, so
// exporting two packets from the same capture does not silently overwrite one
// with the other in the downloads folder.
function exportPacketBytes() {
    const hex = currentDetail?.frame_hex;
    if (!hex) return;
    const bytes = new Uint8Array(Math.floor(hex.length / 2));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    const frame = selectedPacketRow?.dataset.frame || "packet";
    const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `frame-${frame}.bin`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    // Not immediately: the click above schedules the download asynchronously,
    // and revoking the URL before the browser has read it fails the save.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// The loaded frame, kept so the hex pane and the tree can find each other
// without another round trip: both are views onto this one object.
let currentDetail = null;
let selectedFieldEl = null;

async function selectPacket(frameNumber) {
    setDetailVisible(true);
    if (selectedPacketRow) selectedPacketRow.classList.remove("selected");
    selectedPacketRow = document.querySelector(`tr[data-frame="${frameNumber}"]`);
    if (selectedPacketRow) selectedPacketRow.classList.add("selected");

    $("packet-detail-tree").innerHTML = '<div class="empty-state" style="font-size:0.75rem"><span class="spinner"></span></div>';
    $("hex-dump").textContent = "Loading...";
    currentDetail = null;
    selectedFieldEl = null;

    try {
        const detail = await api(`/api/captures/${viewingCaptureId}/packets/${frameNumber}`);
        currentDetail = detail;
        renderDetailTree(detail.layers);
        renderHexPane(detail.frame_hex || "");
    } catch (e) {
        $("packet-detail-tree").innerHTML = `<div style="color:var(--danger);padding:8px">${escHtml(e.message)}</div>`;
        $("hex-dump").textContent = "";
    }
}

// --- detail tree ---

function renderDetailTree(layers) {
    const container = $("packet-detail-tree");
    container.innerHTML = "";
    for (const layer of layers) {
        container.appendChild(buildTreeNode(layer.label || layer.name, layer.fields, layer));
    }
}

// A node is a disclosure row plus its children. `field` is the PDML field the
// row stands for, so a protocol header and a nested field behave identically:
// both highlight their bytes and both can be turned into a filter.
function buildTreeNode(label, fields, field) {
    const node = document.createElement("div");
    node.className = "tree-node";

    const toggle = document.createElement("div");
    toggle.className = "tree-toggle";
    toggle.textContent = " " + label;
    applyFieldData(toggle, field);
    toggle.addEventListener("click", (ev) => {
        // The arrow expands; the label selects. Without this a click meant to
        // inspect a header collapses it instead.
        toggle.classList.toggle("open");
        children.classList.toggle("open");
        selectField(toggle, ev);
    });
    node.appendChild(toggle);

    const children = document.createElement("div");
    children.className = "tree-children";

    for (const child of fields || []) {
        // Wireshark does not draw generated duplicates such as ip.src_host
        // beside ip.src, and drawing them doubles the length of every tree.
        if (child.hidden) continue;
        if (child.children && child.children.length) {
            children.appendChild(buildTreeNode(child.label || child.name, child.children, child));
        } else {
            children.appendChild(buildTreeLeaf(child));
        }
    }

    node.appendChild(children);
    return node;
}

function buildTreeLeaf(field) {
    const leaf = document.createElement("div");
    leaf.className = "tree-leaf";
    // showname already reads "Source Port: 51234", so it is shown whole rather
    // than split back into name and value and reassembled with a colon.
    leaf.textContent = field.label || field.name;
    applyFieldData(leaf, field);
    leaf.addEventListener("click", (ev) => selectField(leaf, ev));
    return leaf;
}

function applyFieldData(el, field) {
    if (!field) return;
    if (field.name) el.dataset.field = field.name;
    if (field.value !== undefined) el.dataset.value = field.value;
    if (field.pos >= 0 && field.size > 0) {
        el.dataset.pos = field.pos;
        el.dataset.size = field.size;
        el.classList.add("has-bytes");
    }
}

// Selecting a row is what drives the hex pane. Kept separate from the click
// handler so a click in the hex pane can select a row the same way.
function selectField(el, ev) {
    if (ev) ev.stopPropagation();
    if (selectedFieldEl) selectedFieldEl.classList.remove("field-selected");
    selectedFieldEl = el;
    el.classList.add("field-selected");
    const pos = parseInt(el.dataset.pos, 10);
    const size = parseInt(el.dataset.size, 10);
    highlightBytes(Number.isNaN(pos) ? -1 : pos, Number.isNaN(size) ? 0 : size);
}

// --- hex pane ---
//
// Rendered here rather than pasted from tshark's -x output, because a single
// text node has nothing to highlight: every byte needs to be its own element
// before a field can point at it.

const HEX_BYTES_PER_ROW = 16;

function renderHexPane(frameHex) {
    const pane = $("hex-dump");
    pane.textContent = "";
    if (!frameHex) {
        pane.textContent = "(no hex data)";
        return;
    }
    const bytes = [];
    for (let i = 0; i + 1 < frameHex.length; i += 2) {
        bytes.push(parseInt(frameHex.substr(i, 2), 16));
    }

    const frag = document.createDocumentFragment();
    for (let off = 0; off < bytes.length; off += HEX_BYTES_PER_ROW) {
        const row = document.createElement("div");
        row.className = "hex-row";

        const gutter = document.createElement("span");
        gutter.className = "hex-offset";
        gutter.textContent = off.toString(16).padStart(4, "0");
        row.appendChild(gutter);

        const hexCells = document.createElement("span");
        hexCells.className = "hex-bytes";
        const asciiCells = document.createElement("span");
        asciiCells.className = "hex-ascii";

        for (let i = 0; i < HEX_BYTES_PER_ROW; i++) {
            const at = off + i;
            if (at >= bytes.length) {
                const pad = document.createElement("span");
                pad.className = "hex-pad";
                pad.textContent = "   ";
                hexCells.appendChild(pad);
                continue;
            }
            const b = bytes[at];
            const cell = document.createElement("span");
            cell.className = "hex-byte";
            cell.dataset.off = at;
            cell.textContent = b.toString(16).padStart(2, "0");
            hexCells.appendChild(cell);

            const ch = document.createElement("span");
            ch.className = "hex-char";
            ch.dataset.off = at;
            ch.textContent = b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
            asciiCells.appendChild(ch);
        }

        row.append(hexCells, asciiCells);
        frag.appendChild(row);
    }
    pane.appendChild(frag);
}

function highlightBytes(pos, size) {
    document.querySelectorAll("#hex-dump .hl").forEach((el) => el.classList.remove("hl"));
    if (pos < 0 || size <= 0) return;
    let first = null;
    for (let off = pos; off < pos + size; off++) {
        document.querySelectorAll(`#hex-dump [data-off="${off}"]`).forEach((el) => {
            el.classList.add("hl");
            if (!first) first = el;
        });
    }
    if (first) first.scrollIntoView({ block: "nearest" });
}

// The other direction: a byte in the pane finds the field that covers it. The
// innermost one wins -- every byte is inside the frame and inside its protocol
// header too, and naming those instead of the actual field would be useless.
function selectFieldAtOffset(offset) {
    let best = null;
    let bestSize = Infinity;
    document.querySelectorAll("#packet-detail-tree .has-bytes").forEach((el) => {
        const pos = parseInt(el.dataset.pos, 10);
        const size = parseInt(el.dataset.size, 10);
        if (offset >= pos && offset < pos + size && size < bestSize) {
            best = el;
            bestSize = size;
        }
    });
    if (!best) return;
    // Open every ancestor, or the row highlights somewhere the user cannot see.
    let parent = best.parentElement;
    while (parent && parent.id !== "packet-detail-tree") {
        if (parent.classList.contains("tree-children")) {
            parent.classList.add("open");
            const t = parent.previousElementSibling;
            if (t && t.classList.contains("tree-toggle")) t.classList.add("open");
        }
        parent = parent.parentElement;
    }
    selectField(best, null);
    best.scrollIntoView({ block: "nearest" });
}

// --- click-to-filter ---
//
// Values become filter expressions here. Anything that is not plainly numeric
// is quoted, because a bare string is a syntax error in a display filter and a
// value containing a space would silently truncate the expression.

// Which values go into a filter bare and which get quoted. Wireshark's syntax
// takes addresses as literals: `ip.addr == "192.168.1.50"` is a type error, not
// a string comparison, and tshark rejects the whole expression. Quoting is for
// values that really are text -- a Host header, a DNS name, a user agent.
function isBareLiteral(v) {
    if (/^(0x[0-9a-fA-F]+|-?\d+(\.\d+)?)$/.test(v)) return true;          // numbers
    if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(v)) return true;        // IPv4, with or without a prefix
    if (/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(v)) return true;      // MAC
    if (/^[0-9a-fA-F:]+(\/\d{1,3})?$/.test(v) && v.includes("::")) return true;   // IPv6, compressed
    if (/^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\/\d{1,3})?$/.test(v)) return true;  // IPv6, full
    return false;
}

// PDML reports boolean fields as show="True"/"False". The filter is written
// against 1 and 0 because that is the canonical form -- what Wireshark's own
// filter bar produces, and what every tshark takes. This tshark also accepts
// == True, so the mapping is for consistency rather than to fix a rejection.
function normaliseValue(v) {
    if (v === "True") return "1";
    if (v === "False") return "0";
    return v;
}

// The display filter rejects these characters on the way into tshark
// (packet_parser._FILTER_FORBIDDEN). Rather than relax that rule to suit
// click-to-filter, a value carrying one falls back to testing that the field is
// merely present -- a filter that is still useful and still passes validation.
const FILTER_UNSAFE = /[;$`\\]/;

function buildFieldFilter(name, value, op = "==") {
    if (!name) return "";
    if (value === undefined || value === null || value === "") return name;
    if (FILTER_UNSAFE.test(value)) return name;
    const v = normaliseValue(value);
    const literal = isBareLiteral(v) ? v : `"${v.replace(/"/g, '\\"')}"`;
    if (FILTER_UNSAFE.test(literal)) return name;
    return `${name} ${op} ${literal}`;
}

// Wireshark's Apply-as-Filter menu, with the same four combinators.
function combineFilter(expr, mode) {
    const current = $("display-filter").value.trim();
    if (mode === "selected") return expr;
    if (mode === "not") return `!(${expr})`;
    if (!current) return mode === "or" ? expr : expr;
    return mode === "and" ? `(${current}) && (${expr})` : `(${current}) || (${expr})`;
}

function applyBuiltFilter(expr, mode, run = true) {
    if (!expr) return;
    const box = $("display-filter");
    box.value = combineFilter(expr, mode);
    if (run) applyDisplayFilter();
    else box.focus();
}

// --- the right-click menu ---

function closeFilterMenu() {
    const el = $("filter-menu");
    if (el) el.remove();
}

function openFilterMenu(x, y, items) {
    closeFilterMenu();
    if (!items.length) return;
    const menu = document.createElement("div");
    menu.id = "filter-menu";
    menu.className = "filter-menu";
    for (const item of items) {
        if (item.separator) {
            const sep = document.createElement("div");
            sep.className = "filter-menu-sep";
            menu.appendChild(sep);
            continue;
        }
        const row = document.createElement("div");
        row.className = "filter-menu-item";
        row.textContent = item.label;
        if (item.hint) {
            const hint = document.createElement("span");
            hint.className = "filter-menu-hint";
            hint.textContent = item.hint;
            row.appendChild(hint);
        }
        row.addEventListener("click", () => {
            closeFilterMenu();
            item.run();
        });
        menu.appendChild(row);
        // The reason goes UNDER the option rather than in a title attribute:
        // a tooltip that needs a hover to appear is one nobody reads before
        // clicking, which is the only moment it is any use.
        if (item.warn) {
            const note = document.createElement("div");
            note.className = "filter-menu-warn";
            note.textContent = item.warn;
            menu.appendChild(note);
        }
    }
    document.body.appendChild(menu);
    // Placed after insertion so the real size is known and the menu can be
    // pulled back inside the window instead of opening off the edge.
    const r = menu.getBoundingClientRect();
    menu.style.left = Math.min(x, window.innerWidth - r.width - 8) + "px";
    menu.style.top = Math.min(y, window.innerHeight - r.height - 8) + "px";
}

function filterMenuItems(expr, label) {
    const show = expr.length > 46 ? expr.slice(0, 45) + "…" : expr;
    return [
        { label: `Apply as filter: ${show}`, run: () => applyBuiltFilter(expr, "selected") },
        // Labelled for what it does. combineFilter's "not" mode ignores the
        // current expression and replaces it with the negation, which is
        // Wireshark's "Not Selected"; the old label promised "…and not
        // selected", which would have kept the current filter and ANDed the
        // negation onto it.
        { label: "  Not selected", hint: "!( )", run: () => applyBuiltFilter(expr, "not") },
        { label: "  …and selected", hint: "&&", run: () => applyBuiltFilter(expr, "and") },
        { label: "  …or selected", hint: "||", run: () => applyBuiltFilter(expr, "or") },
        { separator: true },
        { label: "Prepare as filter", hint: "does not run", run: () => applyBuiltFilter(expr, "selected", false) },
        { label: "Copy value", run: () => navigator.clipboard?.writeText(label).catch(() => {}) },
        // Distinct from Copy value: label is the raw field value (an address, a
        // port number), expr is the filter built from it -- quoted, combined
        // with a field name, sometimes falling back to a presence check when
        // the value carries a character the filter forbids. Composing that by
        // hand is exactly the fiddly part this menu exists to skip.
        { label: "Copy as filter", run: () => navigator.clipboard?.writeText(expr).catch(() => {}) },
    ];
}

function onDetailContextMenu(ev) {
    const row = ev.target.closest(".tree-leaf, .tree-toggle");
    if (!row || !row.dataset.field) return;
    ev.preventDefault();
    selectField(row, null);
    const expr = buildFieldFilter(row.dataset.field, row.dataset.value);
    const items = filterMenuItems(expr, row.dataset.value || row.dataset.field);
    // Wireshark's Apply as Column, from the same menu and in the same place:
    // the quickest way to put a field beside every packet is from a packet
    // that already has it.
    items.push({ separator: true });
    items.push({
        label: "Apply as Column",
        hint: row.dataset.field,
        run: () => addFieldColumn(row.dataset.field, columnTitleForField(row)),
    });
    // Offered from anywhere in this packet's own tree, not only a tcp.stream
    // or udp.stream row -- the same as right-clicking its line in the packet
    // list, and the detail pane already has both indexes loaded.
    pushFollowStreamItems(
        items,
        currentDetail?.tcp_stream != null ? String(currentDetail.tcp_stream) : "",
        currentDetail?.udp_stream != null ? String(currentDetail.udp_stream) : "",
    );
    openFilterMenu(ev.clientX, ev.clientY, items);
}

// A tree row reads "Source Port: 51234", which makes a poor column heading and
// a worse one still on a field whose value is long. The part before the colon
// is the field's own name, which is what Wireshark titles the column with.
function columnTitleForField(row) {
    const label = (row.textContent || "").split(":")[0].trim();
    return label || row.dataset.field;
}

// A row in the list has no PDML behind it, so its filters are built from the
// columns themselves. Which field an address belongs to is decided by the shape
// of the address: a colon means IPv6, and a MAC is six hex pairs.
function addressField(value) {
    if (/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(value)) return "eth.addr";
    if (value.includes(":")) return "ipv6.addr";
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return "ip.addr";
    return "";
}

function onPacketRowContextMenu(ev) {
    const row = ev.target.closest("tr[data-frame]");
    if (!row) return;
    const cell = ev.target.closest("td");
    if (!cell) return;
    ev.preventDefault();

    const text = cell.textContent.trim();
    const items = [];
    if (cell.classList.contains("col-proto") && text) {
        items.push(...filterMenuItems(text.toLowerCase(), text));
    } else if (cell.classList.contains("col-len") && text) {
        items.push(...filterMenuItems(buildFieldFilter("frame.len", text), text));
    } else if (cell.classList.contains("col-no") && text) {
        items.push(...filterMenuItems(buildFieldFilter("frame.number", text), text));
    } else if (cell.classList.contains("col-iface")) {
        // Only meaningful on an "any" capture, where the column itself is
        // shown -- see packetColumns(). ifindex, not the name: the name can be
        // missing (recorded as "#N") but sll.ifindex is always there to filter
        // on, which is exactly what the cell's own tooltip already promises.
        const ifindex = cell.dataset.ifindex;
        if (ifindex) {
            const label = cell.dataset.ifaceName || `interface index ${ifindex}`;
            items.push(...filterMenuItems(buildFieldFilter("sll.ifindex", ifindex), label));
        }
    } else if (cell.dataset.field && text) {
        // A column the operator added, or one of the MAC columns: the cell
        // carries the field it was drawn from, so the filter is exact instead
        // of being guessed back out of the value's shape.
        items.push(...filterMenuItems(buildFieldFilter(cell.dataset.field, text), text));
    } else {
        const field = addressField(text);
        if (field) items.push(...filterMenuItems(buildFieldFilter(field, text), text));
    }

    // Wireshark's Conversation Filter, which is the reason most right-clicks on
    // a row happen at all: both endpoints of this exchange and nothing else.
    const src = row.querySelector(".col-src")?.textContent.trim() || "";
    const dst = row.querySelector(".col-dst")?.textContent.trim() || "";
    const sf = addressField(src);
    if (sf && sf === addressField(dst)) {
        const conv = `${buildFieldFilter(sf, src)} && ${buildFieldFilter(sf, dst)}`;
        items.push({ separator: true });
        items.push({ label: "Conversation filter", hint: `${src} ↔ ${dst}`, run: () => applyBuiltFilter(conv, "selected") });
    }
    pushFollowStreamItems(items, row.dataset.tcpStream, row.dataset.udpStream);
    openFilterMenu(ev.clientX, ev.clientY, items);
}

// Shared by the row's own menu and the detail pane's: whichever tcp.stream or
// udp.stream this packet carries, offered as "Follow ... Stream" rather than
// as a filter -- opening the reassembled conversation is a different action
// from narrowing the list to it, even though both start from the same index.
function pushFollowStreamItems(items, tcpStream, udpStream) {
    if (tcpStream !== undefined && tcpStream !== "") {
        items.push({ separator: true });
        items.push({ label: "Follow TCP Stream", run: () => openFollowStream("tcp", Number(tcpStream)) });
    }
    if (udpStream !== undefined && udpStream !== "") {
        items.push({ separator: true });
        items.push({ label: "Follow UDP Stream", run: () => openFollowStream("udp", Number(udpStream)) });
    }
}

// --- resizer ---

const SPLIT_KEY = "pcap.viewer.listHeight";
// Leave room for the detail pane's own header even when dragged to the bottom,
// so the split can never be pulled to a state with no way back.
const MIN_DETAIL_HEIGHT = 80;

function applyStoredSplit() {
    const listContainer = document.querySelector(".packet-list-container");
    if (!listContainer) return;
    let stored = null;
    try {
        stored = localStorage.getItem(SPLIT_KEY);
    } catch {
        return;
    }
    const height = parseInt(stored, 10);
    if (!height) return;
    const viewer = $("packet-viewer");
    const max = viewer ? viewer.clientHeight - MIN_DETAIL_HEIGHT : height;
    listContainer.style.flex = "none";
    listContainer.style.height = Math.max(100, Math.min(height, max)) + "px";
}

(function initResizer() {
    const resizer = $("resizer");
    if (!resizer) return;
    let startY, startH;
    resizer.addEventListener("mousedown", (e) => {
        const listContainer = document.querySelector(".packet-list-container");
        const viewer = $("packet-viewer");
        startY = e.clientY;
        startH = listContainer.offsetHeight;
        e.preventDefault();
        function onMove(ev) {
            const max = viewer.clientHeight - MIN_DETAIL_HEIGHT;
            const height = Math.max(100, Math.min(startH + ev.clientY - startY, max));
            listContainer.style.flex = "none";
            listContainer.style.height = height + "px";
        }
        function onUp() {
            document.removeEventListener("mousemove", onMove);
            document.removeEventListener("mouseup", onUp);
            try {
                localStorage.setItem(SPLIT_KEY, String(listContainer.offsetHeight));
            } catch {
                // A remembered split is not worth failing over.
            }
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
    // Enter submits the form the cursor is in.
    //
    // There is no <form> element anywhere in this UI, so none of this is the
    // browser's own behaviour -- Enter works only where something asks for it,
    // and for a long time the only things that asked were the ids listed
    // above. That list left out every field of the server form: typing a
    // hostname and pressing Enter did nothing whatsoever -- no request, no
    // error, no feedback -- which reads as a form with no way to submit it
    // rather than a missing shortcut. It left out the stored-username box on
    // the same tab too, and the Add user box under Admin.
    //
    // Naming the missing ids here would only leave out the next one, so the
    // container names its own submit button instead, in the markup, beside the
    // fields it belongs to:
    //
    //     <div data-enter-submits="#btn-add-username"> ... </div>
    //
    // The value is a selector, looked up inside that container: an id where
    // the button is fixed markup, a class where the form is rendered by JS and
    // the button has no id of its own. The button is clicked rather than its
    // handler called, so Enter and the mouse go down the same path and cannot
    // drift apart.
    if (e.key === "Enter") {
        const field = document.activeElement;
        if (!field || field.tagName === "TEXTAREA") return;
        const form = field.closest("[data-enter-submits]");
        if (!form) return;
        const submit = form.querySelector(form.dataset.enterSubmits);
        if (!submit) return;
        e.preventDefault();
        submit.click();
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

// --- admin panel: sections ---
//
// One section on screen at a time, chosen from the list down the side. Every
// section's data is still loaded when Admin opens, so switching is instant and
// the overview can say how each one stands. data-admin-page rather than
// data-tab: activatePanel() clears .active from every [data-tab] on the page.

const ADMIN_PAGES = ["overview", "https", "encryption", "users", "ssh-keys", "known-hosts", "settings"];
const ADMIN_PAGE_KEY = "pcap-admin-page";

function storedAdminPage() {
    try {
        const saved = localStorage.getItem(ADMIN_PAGE_KEY);
        return ADMIN_PAGES.includes(saved) ? saved : "overview";
    } catch {
        return "overview";
    }
}

function selectAdminPage(name) {
    if (!ADMIN_PAGES.includes(name)) name = "overview";
    for (const page of ADMIN_PAGES) {
        const el = $(`admin-page-${page}`);
        if (el) el.hidden = page !== name;
    }
    document.querySelectorAll(".admin-nav-item").forEach((b) => {
        const on = b.dataset.adminPage === name;
        b.classList.toggle("active", on);
        if (on) b.setAttribute("aria-current", "page");
        else b.removeAttribute("aria-current");
    });
    try { localStorage.setItem(ADMIN_PAGE_KEY, name); } catch { /* per-browser nicety only */ }
    if (name === "overview") loadAdminOverview();
}

// Each card: what the section is, how it stands in a few words, and a level
// that colours it. Built with textContent -- hostnames and usernames flow in.
async function loadAdminOverview() {
    const box = $("admin-overview");
    if (!box) return;
    const settle = (p) => p.then((v) => v, () => null);
    const [enc, tls, users, keys, hosts] = await Promise.all([
        settle(api("/api/admin/encryption")),
        settle(api("/api/admin/tls")),
        settle(api("/api/admin/users")),
        settle(api("/api/ssh-keys")),
        settle(api("/api/admin/host-trust")),
    ]);
    const cards = [adminHttpsCard(tls), adminEncryptionCard(enc)];
    if (users) cards.push({ page: "users", title: "Users", level: "neutral",
        state: `${users.length} account${users.length === 1 ? "" : "s"}` });
    if (keys) cards.push({ page: "ssh-keys", title: "SSH keys", level: keys.length ? "neutral" : "warn",
        state: keys.length ? `${keys.length} uploaded` : "None uploaded yet" });
    cards.push(adminHostsCard(hosts));
    cards.push({ page: "settings", title: "Settings", level: "neutral", state: "Capture, session and rate limits" });

    box.textContent = "";
    for (const c of cards) {
        const card = document.createElement("button");
        card.type = "button";
        card.className = `admin-card admin-card-${c.level}`;
        card.dataset.adminPage = c.page;
        const title = document.createElement("span");
        title.className = "admin-card-title";
        title.textContent = c.title;
        const state = document.createElement("span");
        state.className = "admin-card-state";
        state.textContent = c.state;
        card.append(title, state);
        if (c.detail) {
            const detail = document.createElement("span");
            detail.className = "admin-card-detail";
            detail.textContent = c.detail;
            card.append(detail);
        }
        box.append(card);
    }
    setAdminNavDot("https", adminHttpsCard(tls).level !== "good");
    setAdminNavDot("encryption", adminEncryptionCard(enc).level === "bad" || enc?.locked);
    setAdminNavDot("known-hosts", adminHostsCard(hosts).level === "warn");
}

function setAdminNavDot(page, on) {
    const dot = $(`admin-nav-dot-${page}`);
    if (dot) dot.hidden = !on;
}

function adminHttpsCard(st) {
    const card = { page: "https", title: "HTTPS" };
    if (!st) return { ...card, level: "neutral", state: "Status unavailable" };
    if (st.serving_https) {
        const c = st.certificate;
        return { ...card, level: "good", state: "Serving HTTPS",
                 detail: c ? `${c.names.join(", ")} · ${c.days_left} days left` : "" };
    }
    if (st.restart_needed) return { ...card, level: "warn", state: "Certificate ready — switch to HTTPS" };
    if (!st.available) return { ...card, level: "neutral", state: "Not available", detail: "Needs a master key file" };
    return { ...card, level: "bad", state: "No certificate", detail: "Plain HTTP is read-only" };
}

function adminEncryptionCard(st) {
    const card = { page: "encryption", title: "Encryption" };
    if (!st) return { ...card, level: "neutral", state: "Status unavailable" };
    if (!st.enabled) return { ...card, level: "bad", state: "Captures are not encrypted" };
    if (st.locked) return { ...card, level: "warn", state: "Locked — passphrase needed" };
    return { ...card, level: "good", state: "Encrypted at rest", detail: `${st.encrypted_count} captures` };
}

function adminHostsCard(hosts) {
    const card = { page: "known-hosts", title: "Known hosts" };
    if (!hosts) return { ...card, level: "neutral", state: "Status unavailable" };
    const untrusted = hosts.filter((h) => h.configured && !h.key_types.length).length;
    if (!hosts.length) return { ...card, level: "neutral", state: "No servers yet" };
    if (untrusted) return { ...card, level: "warn", state: `${untrusted} host${untrusted === 1 ? "" : "s"} not verified` };
    return { ...card, level: "good", state: `${hosts.length} verified` };
}

// --- admin panel ---

const SETTING_LABELS = {
    max_capture_seconds: "Max capture duration (seconds)",
    max_capture_packets: "Max capture packets",
    // Enforced since captures were first written -- each running capture holds
    // an SSH session and a local file handle -- but absent from this map, so
    // the panel never drew it and the only way to change it was the database.
    max_concurrent_captures: "Max simultaneous captures",
    session_duration_hours: "Session duration (hours)",
    session_idle_timeout_minutes: "Session idle timeout (minutes)",
    device_trust_days: "Device trust duration (days)",
    rate_limit_max_attempts: "Rate limit max attempts",
    rate_limit_lockout_minutes: "Rate limit lockout (minutes)",
    rate_limit_packets_per_min: "Packet list requests per minute",
    rate_limit_captures_per_min: "Capture start requests per minute",
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
                    <td class="admin-user-actions">
                        ${adminUserActions(u)}
                    </td>
                </tr>`).join("")}
            </tbody>
        </table>`;
    } catch (e) {
        $("admin-user-list").innerHTML = `<span style="color:var(--danger)">${escHtml(e.message)}</span>`;
    }
}

// Matched on username rather than id, because the id is not in the auth status
// payload and a username is unique anyway. The server refuses a self-reset in
// any case (admin_reset_totp); this only avoids offering a button that cannot
// work.
function adminUserActions(u) {
    const self = currentUser && u.username === currentUser.username;
    const parts = [];
    if (!self) {
        parts.push(`<button class="btn btn-sm btn-secondary" data-action="reset-mfa"
            data-id="${escHtml(u.id)}"
            title="Clear this account's two-factor authentication. They enrol again with a NEW code at their next sign-in, and are signed out everywhere in the meantime.">Reset MFA</button>`);
    }
    if (!u.is_admin) {
        parts.push(`<button class="btn btn-sm btn-danger" data-action="delete-user"
            data-id="${escHtml(u.id)}">Delete</button>`);
    }
    return parts.join(" ");
}

async function adminResetMfa(userId) {
    const row = document.querySelector(`[data-action="reset-mfa"][data-id="${CSS.escape(userId)}"]`);
    const name = row ? row.closest("tr").firstElementChild.textContent.trim() : "this user";
    // Spelled out rather than "Are you sure?": this revokes a second factor,
    // and the three consequences are not all obvious from the button.
    if (!confirm(
        `Reset two-factor authentication for ${name}?\n\n`
        + "\u2022 Their current authenticator stops working \u2014 a NEW enrolment "
        + "code is issued at their next sign-in.\n"
        + "\u2022 They are signed out of every session immediately.\n"
        + "\u2022 Every device they marked as trusted is forgotten.\n\n"
        + "Until they enrol again their account is protected by its password alone, "
        + "so do this only when you know who is asking."
    )) return;
    const msgEl = $("admin-user-msg");
    try {
        await api(`/api/admin/users/${userId}/totp/reset`, { method: "POST" });
    } catch (e) {
        msgEl.textContent = e.message;
        msgEl.className = "error-msg";
        return;
    }
    msgEl.textContent = `MFA reset for ${name}. They will enrol again at next sign-in.`;
    msgEl.className = "success-msg";
    loadAdminUsers();
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
                    <td><button class="btn btn-sm btn-danger" data-action="delete-key" data-id="${escHtml(k)}">Delete</button></td>
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

// The stored login names, on the Servers tab beside the form that offers them.
async function loadUsernameList() {
    const el = $("username-list");
    if (!el) return;
    try {
        await loadUsernames();
    } catch (e) {
        el.innerHTML = `<span style="color:var(--danger)">${escHtml(e.message)}</span>`;
        return;
    }
    if (!knownUsernames.length) {
        el.innerHTML = '<div class="empty-state" style="padding:16px;font-size:0.8125rem">'
            + "No usernames stored yet</div>";
        return;
    }
    el.innerHTML = `<table class="admin-table">
        <thead><tr><th>Username</th><th>Last used</th><th></th></tr></thead>
        <tbody>${knownUsernames.map((u) => `
            <tr>
                <td>${escHtml(u.username)}</td>
                <td>${escHtml((u.last_used_at || "").slice(0, 10) || "\u2014")}</td>
                <td>
                    <button class="btn btn-sm btn-secondary" data-action="rename-username" data-id="${escHtml(u.id)}">Rename</button>
                    <button class="btn btn-sm btn-danger" data-action="delete-username" data-id="${escHtml(u.id)}">Remove</button>
                </td>
            </tr>`).join("")}
        </tbody>
    </table>`;
}

function showUsernameMsg(text, ok = false) {
    const el = $("username-msg");
    if (!el) return;
    el.textContent = text;
    el.className = ok ? "success-msg" : "error-msg";
}

async function addStoredUsername() {
    const input = $("new-ssh-username");
    const username = input.value.trim();
    showUsernameMsg("");
    if (!username) return showUsernameMsg("Enter a username first");
    try {
        await api("/api/usernames", { method: "POST", body: JSON.stringify({ username }) });
    } catch (e) {
        return showUsernameMsg(e.message);
    }
    input.value = "";
    await loadUsernameList();
}

async function renameStoredUsername(id) {
    const current = knownUsernames.find((u) => u.id === id);
    const username = prompt("Rename stored username", current ? current.username : "");
    if (username === null) return;
    showUsernameMsg("");
    try {
        await api(`/api/usernames/${id}`, { method: "PUT", body: JSON.stringify({ username: username.trim() }) });
    } catch (e) {
        return showUsernameMsg(e.message);
    }
    await loadUsernameList();
}

async function deleteStoredUsername(id) {
    const current = knownUsernames.find((u) => u.id === id);
    const name = current ? current.username : "this username";
    // Worth spelling out: the servers keep working, so this is not the
    // destructive operation the red button implies.
    if (!confirm(`Remove "${name}" from the suggestion list?\n\n`
        + "Servers already configured with it are unaffected.")) return;
    showUsernameMsg("");
    try {
        await api(`/api/usernames/${id}`, { method: "DELETE" });
    } catch (e) {
        return showUsernameMsg(e.message);
    }
    await loadUsernameList();
}

// Driven by the servers that exist, not by a typed hostname: the hosts worth
// trusting are the ones something already connects to. Keys are shown and
// dropped per host rather than per row, because a host's keys are one set --
// removing a single row leaves the others still verifying it.
async function loadAdminKnownHosts() {
    const el = $("admin-known-hosts");
    try {
        const hosts = await api("/api/admin/host-trust");
        if (!hosts.length) {
            el.innerHTML = '<span style="color:var(--text-muted)">'
                + "No servers configured yet — add one under Servers and its host will appear here."
                + "</span>";
            return;
        }
        el.innerHTML = `<table class="admin-table">
            <thead><tr><th>Host</th><th>Used by</th><th>Host keys</th><th></th></tr></thead>
            <tbody>${hosts.map((h) => {
                const endpoint = `${escHtml(h.hostname)}:${h.port}`;
                const trusted = h.key_types.length > 0;
                // The stored-at time is shown because it is the only way to tell a
                // rescan apart from keys that were never removed: the same key types
                // come back either way, and only the timestamp moves.
                const status = trusted
                    ? `<span style="color:var(--success)">Trusted — ${escHtml(h.key_types.join(", "))}</span>`
                      + `<br><span style="color:var(--text-muted);font-size:0.75rem">`
                      + `stored ${escHtml(formatStoredAt(h.added_at))}</span>`
                    : '<span style="color:var(--warning,#d29922)">Not verified</span>';
                const used = h.configured
                    ? escHtml(h.labels)
                    : '<span style="color:var(--text-muted)">no server uses this host</span>';
                return `
                <tr>
                    <td>${endpoint}</td>
                    <td>${used}</td>
                    <td>${status}</td>
                    <td style="white-space:nowrap">
                        <button class="btn btn-sm btn-secondary" data-action="trust-host"
                            data-id="${endpoint}">${trusted ? "Review keys" : "Trust keys"}</button>
                        ${trusted ? `<button class="btn btn-sm btn-danger" data-action="forget-host"
                            data-id="${endpoint}">Forget</button>` : ""}
                    </td>
                </tr>`;
            }).join("")}
            </tbody>
        </table>`;
    } catch (e) {
        el.innerHTML = `<span style="color:var(--danger)">${escHtml(e.message)}</span>`;
    }
}

function formatStoredAt(iso) {
    if (!iso) return "unknown";
    const when = new Date(iso);
    if (isNaN(when)) return iso;
    const secs = Math.round((Date.now() - when) / 1000);
    if (secs < 10) return "just now";
    if (secs < 90) return `${secs}s ago`;
    if (secs < 5400) return `${Math.round(secs / 60)} min ago`;
    return when.toLocaleString();
}

// "host:port" as carried on the buttons. rsplit, so IPv6 literals survive.
function splitEndpoint(endpoint) {
    const i = String(endpoint).lastIndexOf(":");
    return { hostname: endpoint.slice(0, i), port: parseInt(endpoint.slice(i + 1)) || 22 };
}

// The fingerprint review both trust paths go through.
//
// Pressing Trust used to be one step: scan, and whatever answered on that
// address was pinned. The operator was shown nothing and asked only whether
// they meant to press the button. Real ssh prints the fingerprint and makes
// you type yes, because the fingerprint is the only part a human can check
// against the host itself -- that check is the entire security value of host
// key verification, and skipping it makes the whole mechanism ceremony.
//
// Returns the confirm response when keys were pinned, or null when the
// operator declined. Throws on a failed request; the two callers report
// errors in their own way, since they render into different places.
async function reviewAndTrustHost(endpoint) {
    const target = splitEndpoint(endpoint);
    const scan = await api("/api/admin/known-hosts/scan", {
        method: "POST",
        body: JSON.stringify(target),
    });

    // A key that will not parse cannot be fingerprinted, so it cannot be
    // reviewed -- it is reported and left out rather than quietly accepted on
    // the strength of the others. The API refuses these on confirm too.
    const usable = scan.keys.filter((k) => k.fingerprint);
    const skipped = scan.keys.length - usable.length;
    if (!usable.length) {
        throw new Error(`${endpoint} offered no host key that could be read`);
    }

    const listed = usable.map((k) => `    ${k.key_type}\n    ${k.fingerprint}`).join("\n\n");
    const note = skipped
        ? `\n\n${skipped} further key(s) could not be read and will not be stored.`
        : "";
    const accepted = confirm(
        `${endpoint} answered with ${usable.length} host key(s):\n\n${listed}${note}\n\n`
        + "Check these against the host itself before accepting. On "
        + `${target.hostname}, run:\n\n`
        + "    for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf $f; done\n\n"
        + "Accept these keys and verify every future connection against them?"
    );
    if (!accepted) return null;

    // The reviewed keys are sent back rather than re-scanned, so what gets
    // pinned is what was on screen a moment ago.
    return await api("/api/admin/known-hosts/confirm", {
        method: "POST",
        body: JSON.stringify({
            ...target,
            keys: usable.map((k) => ({ key_type: k.key_type, host_key: k.host_key })),
        }),
    });
}

async function adminTrustHost(endpoint) {
    const msgEl = $("admin-host-msg");
    msgEl.className = "success-msg";
    msgEl.textContent = `Asking ${endpoint} for its host keys...`;
    try {
        const result = await reviewAndTrustHost(endpoint);
        if (!result) {
            msgEl.textContent = `Nothing pinned for ${endpoint} -- the keys were not accepted.`;
            return;
        }
        // Said plainly, because the rows that reappear look identical to ones
        // that were never removed -- these were just accepted from the host.
        msgEl.textContent =
            `Pinned ${result.stored} key(s) for ${endpoint}: `
            + result.keys.map((k) => k.key_type).join(", ");
        loadAdminKnownHosts();
    } catch (e) {
        msgEl.className = "error-msg";
        msgEl.textContent = e.message;
    }
}

async function adminForgetHost(endpoint) {
    if (!confirm(`Forget the stored host keys for ${endpoint}?\n\n`
        + "Connections to it will stop being verified until you trust it again.")) return;
    const msgEl = $("admin-host-msg");
    try {
        const result = await api("/api/admin/known-hosts/forget", {
            method: "POST",
            body: JSON.stringify(splitEndpoint(endpoint)),
        });
        msgEl.className = "success-msg";
        msgEl.textContent = `Removed ${result.removed} key(s) for ${endpoint}`;
        loadAdminKnownHosts();
    } catch (e) {
        msgEl.className = "error-msg";
        msgEl.textContent = e.message;
    }
}

// --- event wiring ---

// The fixed buttons/inputs that exist in index.html from page load, each
// with a stable id. Dynamically-rendered content is wired separately, via
// delegate() in initEventDelegation, since it doesn't exist yet at boot.
function initStaticHandlers() {
    $("btn-register")?.addEventListener("click", doRegister);
    $("btn-login")?.addEventListener("click", doLogin);
    $("btn-confirm-totp")?.addEventListener("click", confirmTotp);
    $("theme-toggle")?.addEventListener("click", toggleTheme);
    $("btn-logout")?.addEventListener("click", doLogout);
    $("btn-add-server")?.addEventListener("click", showAddServer);
    $("btn-start-capture")?.addEventListener("click", startCapture);
    $("btn-save-filter")?.addEventListener("click", saveCurrentFilter);
    $("btn-apply-filter")?.addEventListener("click", applyDisplayFilter);
    $("btn-save-view")?.addEventListener("click", saveCurrentView);
    $("display-filter")?.addEventListener("input", noteFilterEditedByHand);
    $("display-filter")?.addEventListener("input",
        () => syncSaveButton("btn-save-display-filter", "display-filter"));
    $("btn-save-display-filter")?.addEventListener("click", saveCurrentDisplayFilter);
    initDisplayFilterAutocomplete();
    delegate("view-tabs", {
        "select-view": (id) => selectView(id),
        "download-view": (id) => downloadView(id),
        "edit-view": (id) => editView(id),
        "delete-view": (id) => deleteView(id),
    });
    $("btn-download-capture")?.addEventListener("click", downloadCapture);
    $("btn-sanitize-capture")?.addEventListener("click", () => {
        if (viewingCaptureId) openSanitizeDialog(viewingCaptureId, activeViewId);
    });
    initSanitizeDialog();
    $("btn-export-packet-bytes")?.addEventListener("click", exportPacketBytes);
    $("btn-protocol-hierarchy")?.addEventListener("click", openProtocolHierarchyDialog);
    $("btn-conversations")?.addEventListener("click", openConversationsDialog);
    initStatsDialogs();
    initColumnControls();
    $("resolve-names")?.addEventListener("change", onResolveNamesToggled);
    $("btn-save-settings")?.addEventListener("click", saveSettings);
    $("btn-admin-create-user")?.addEventListener("click", adminCreateUser);
    $("btn-add-username")?.addEventListener("click", addStoredUsername);
    $("btn-admin-upload-key")?.addEventListener("click", adminUploadKey);
}

// The containers themselves exist from page load even though their contents
// are replaced with innerHTML later, so delegation set up once here survives
// every re-render without needing to be re-attached.
function initEventDelegation() {
    delegate("server-list", {
        "select-server": (id) => selectServer(id),
        // Registered here, not on admin-known-hosts, because that is where the
        // button renders. delegate() bails on !container.contains(el), so a
        // handler on the wrong container is a button that looks right and does
        // nothing at all -- no request, no error.
        "trust-server-host": (id) => trustServerHost(id),
    });
    delegate("server-form-area", {
        "test-server": (id) => testServer(id),
        "prereq-check": (id) => prereqCheck(id),
        "remove-server": (id) => removeServer(id),
        "add-server": () => addServer(),
        "probe-test": () => probeTest(),
        "probe-prereq": () => probePrereq(),
        "edit-server": (id) => editServer(id),
        "save-server-edit": (id) => saveServerEdit(id),
        "select-server": (id) => selectServer(id),
        "show-add-server": () => showAddServer(),
        "capture-from-server": (id) => captureFromServer(id),
    });
    delegate("capture-list", {
        "stop-capture": (id) => stopCapture(id),
        "view-capture": (id) => viewCapture(id),
        "download-capture": (id) => downloadCaptureById(id),
        "sanitize-capture": (id) => openSanitizeDialog(id),
        "rename-capture": (id) => renameCapture(id),
        "delete-capture": (id) => deleteCapture(id),
    });
    delegate("admin-user-list", {
        "delete-user": (id) => adminDeleteUser(id),
        "reset-mfa": (id) => adminResetMfa(id),
    });
    delegate("admin-ssh-keys", {
        "delete-key": (id) => adminDeleteKey(id),
    });
    document.querySelectorAll(".drawer-toggle").forEach((el) => {
        el.addEventListener("click", () => toggleDrawer(el.dataset.id));
    });

    // --- viewer: field/byte linkage and the Apply-as-Filter menu ---
    $("packet-detail-tree")?.addEventListener("contextmenu", onDetailContextMenu);
    $("packet-tbody")?.addEventListener("contextmenu", onPacketRowContextMenu);
    $("hex-dump")?.addEventListener("click", (ev) => {
        const cell = ev.target.closest("[data-off]");
        if (cell) selectFieldAtOffset(parseInt(cell.dataset.off, 10));
    });
    // Any click elsewhere, Escape, or a scroll dismisses the menu -- a menu
    // that outlives the thing it was opened on points at the wrong packet.
    document.addEventListener("click", (ev) => {
        if (!ev.target.closest("#filter-menu")) closeFilterMenu();
    });
    document.addEventListener("keydown", (ev) => {
        if (ev.key === "Escape") closeFilterMenu();
    });
    window.addEventListener("resize", closeFilterMenu);
    $("filter-library-search")?.addEventListener("input", (e) => {
        filterLibraryQuery = e.target.value;
        renderFilterLibrary();
    });
    // The field is the source of truth, so the bar follows it however it
    // changed -- including someone typing or clearing it by hand.
    $("cap-bpf")?.addEventListener("input", onBpfFilterChanged);
    $("filter-preview-clear")?.addEventListener("click", () => {
        // Starting over is a normal part of composing, and the field can be
        // scrolled out of sight behind the list by the time you want to.
        const box = $("cap-bpf");
        if (!box) return;
        box.value = "";
        onBpfFilterChanged();
    });
    delegate("filter-library", {
        "use-library-filter": (expr, el, ev) => useLibraryFilter(expr, el, ev),
        "delete-custom-filter": (id) => deleteCustomFilter(id),
    });
    delegate("display-own-filters", {
        "use-display-filter": (id) => useDisplayFilter(id),
        "delete-display-filter": (id) => deleteDisplayFilter(id),
    });
    delegate("display-filter-suggestions", {
        "use-filter": (expr) => useFilterSuggestion(expr),
    });
    delegate("username-list", {
        "rename-username": (id) => renameStoredUsername(id),
        "delete-username": (id) => deleteStoredUsername(id),
    });
    delegate("admin-known-hosts", {
        "trust-host": (id) => adminTrustHost(id),
        "forget-host": (id) => adminForgetHost(id),
    });
    $("packet-tbody")?.addEventListener("click", (e) => {
        const row = e.target.closest("tr[data-frame]");
        if (row) selectPacket(Number(row.dataset.frame));
    });
}

// --- boot ---

applyTheme(currentTheme());
initStaticHandlers();
initEventDelegation();
checkAuth();
