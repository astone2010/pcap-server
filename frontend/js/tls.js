"use strict";

// Built-in HTTPS: Admin -> HTTPS certificate.
//
// Its own file, like its own backend package (backend/tls): everything about
// obtaining and serving a certificate is in one place. It uses three things from
// app.js -- api(), $() and secureTransport -- and app.js calls loadTlsStatus()
// when the Admin panel opens.
//
// The provider list is lego's, ~200 entries, each with the environment
// variables that provider takes. It is fetched once, the first time the panel
// opens, and never contains a stored value: the status says which settings are
// stored, not what they are.

let tlsProviders = null;
let tlsSelectedProvider = "";

async function loadTlsStatus() {
    const box = $("admin-tls");
    if (!box) return;
    try {
        if (!tlsProviders) {
            tlsProviders = (await api("/api/admin/tls/providers")).providers;
        }
        renderTls(box, await api("/api/admin/tls"));
    } catch (e) {
        box.textContent = "";
        box.append(tlsEl("div", "error-msg", e.message));
    }
}

function tlsEl(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function tlsSummary(st) {
    if (!st.available) {
        return { level: "warn", headline: "Not available on this installation", detail: st.unavailable_reason };
    }
    if (st.serving_https) {
        return { level: "good", headline: "pcap-server is serving HTTPS itself",
                 detail: "The certificate renews automatically when it has under 30 days left, "
                     + "and the renewed one is picked up without a restart." };
    }
    if (st.restart_needed) {
        return { level: "warn", headline: "Certificate ready — switch to HTTPS to use it",
                 detail: "Switching restarts pcap-server. Everyone is signed out, and you "
                     + "reconnect at the https:// address below." };
    }
    return { level: "bad", headline: "No certificate",
             detail: "Without HTTPS — from here or from a reverse proxy — pcap-server "
                 + "is read-only to anyone not on this machine." };
}

// Setup is a guided flow that stays out of the way. The page leads with how
// HTTPS stands and what can be done about it; the form only appears after "Set
// up certificate" (or "Change settings"), one step at a time.
let tlsSetupOpen = false;
let tlsStep = 1;
const TLS_STEPS = ["Domain", "DNS provider", "Request"];

let tlsLastStatus = null;

function renderTls(box, st) {
    tlsLastStatus = st;
    box.textContent = "";
    const summary = tlsSummary(st);
    box.append(tlsEl("div", `enc-state enc-${summary.level}`, summary.headline));
    box.append(tlsEl("div", "enc-detail", summary.detail));
    if (st.config || st.certificate) box.append(tlsFacts(st));
    if (st.last_error) {
        const err = tlsEl("details", "tls-last-error");
        err.open = true;
        err.append(tlsEl("summary", "", "Last attempt failed"), tlsEl("pre", "enc-howto", st.last_error));
        box.append(err);
    }
    if (st.available) box.append(tlsActions(st));
    if (st.available && tlsSetupOpen) box.append(tlsSetupWizard(st));
    const msg = tlsEl("div", "error-msg");
    msg.id = "tls-msg";
    box.append(msg);
    if (typeof loadAdminOverview === "function") loadAdminOverview();
}

function tlsFacts(st) {
    const rows = [];
    if (st.config) {
        rows.push(["Domain", st.config.domain]);
        rows.push(["Contact email", st.config.email]);
        rows.push(["DNS provider", st.config.provider_name]);
        if (st.config.staging) rows.push(["Environment", "Let's Encrypt staging (browsers will not trust it)"]);
    }
    rows.push(["Stored credentials", st.stored_credentials.length
        ? `${st.stored_credentials.join(", ")} — encrypted` : "none"]);
    if (st.certificate) {
        const c = st.certificate;
        rows.push(["Certificate", `${c.names.join(", ")} — expires ${c.not_after.slice(0, 10)} (${c.days_left} days)`]);
        rows.push(["Issuer", c.issuer]);
    }
    const facts = tlsEl("table", "enc-facts");
    for (const [k, v] of rows) {
        const tr = document.createElement("tr");
        tr.append(tlsEl("td", "enc-key", k), tlsEl("td", "", v));
        facts.append(tr);
    }
    return facts;
}

function tlsActions(st) {
    const actions = tlsEl("div", "admin-inline-form tls-status-actions");
    if (st.restart_needed) {
        const b = tlsEl("button", "btn btn-sm btn-primary", "Switch to HTTPS");
        b.addEventListener("click", () => switchToHttps(st));
        actions.append(b);
    }
    if (!tlsSetupOpen) {
        const configured = st.config || st.certificate;
        const setup = tlsEl("button", configured ? "btn btn-sm btn-secondary" : "btn btn-sm btn-primary",
                            configured ? "Change settings" : "Set up certificate");
        setup.id = "btn-tls-setup";
        setup.addEventListener("click", () => {
            tlsSetupOpen = true;
            tlsStep = 1;
            renderTls($("admin-tls"), st);
        });
        actions.append(setup);
    }
    if (st.config && st.stored_credentials.length) {
        const b = tlsEl("button", "btn btn-sm btn-secondary", "Renew now");
        b.addEventListener("click", renewCertificate);
        actions.append(b);
    }
    if (st.certificate || st.config) {
        const rm = tlsEl("button", "btn btn-sm btn-danger", "Remove");
        rm.addEventListener("click", removeCertificate);
        actions.append(rm);
    }
    return actions;
}

function tlsField(labelText, hint, control, isVariable = false) {
    const wrap = tlsEl("div", "tls-field");
    const label = tlsEl("label", isVariable ? "tls-var-name" : "", labelText);
    label.htmlFor = control.id;
    wrap.append(label, control);
    if (hint) wrap.append(tlsEl("div", "field-hint", hint));
    return wrap;
}

function tlsInput(id, { type = "text", placeholder = "", value = "" } = {}) {
    const input = tlsEl("input");
    input.id = id;
    input.type = type;
    input.placeholder = placeholder;
    input.value = value;
    return input;
}

function tlsSetupWizard(st) {
    const wrap = tlsEl("div", "tls-form tls-wizard");

    const steps = tlsEl("ol", "tls-steps");
    TLS_STEPS.forEach((name, n) => {
        const li = tlsEl("li", n + 1 === tlsStep ? "current" : (n + 1 < tlsStep ? "done" : ""), name);
        steps.append(li);
    });
    wrap.append(steps);

    const one = tlsEl("div", "tls-step");
    one.dataset.tlsStep = "1";
    one.append(tlsBasics(st));

    const two = tlsEl("div", "tls-step");
    two.dataset.tlsStep = "2";
    if (!secureTransport) two.append(tlsHttpWarning());
    two.append(tlsProviderPicker(st));

    const three = tlsEl("div", "tls-step");
    three.dataset.tlsStep = "3";
    three.append(tlsValidationDelayField(st), tlsSubmitRow(st), tlsCliHint(st));

    for (const step of [one, two, three]) {
        step.hidden = Number(step.dataset.tlsStep) !== tlsStep;
        wrap.append(step);
    }
    wrap.append(tlsWizardNav(st));
    return wrap;
}

function tlsWizardNav(st) {
    const nav = tlsEl("div", "tls-wizard-nav");
    const cancel = tlsEl("button", "btn btn-sm btn-secondary", "Cancel");
    cancel.addEventListener("click", () => { tlsSetupOpen = false; renderTls($("admin-tls"), st); });
    nav.append(cancel);
    if (tlsStep > 1) {
        const back = tlsEl("button", "btn btn-sm btn-secondary", "Back");
        back.id = "btn-tls-back";
        back.addEventListener("click", () => tlsGoToStep(tlsStep - 1));
        nav.append(back);
    }
    if (tlsStep < TLS_STEPS.length) {
        const next = tlsEl("button", "btn btn-sm btn-primary", "Next");
        next.id = "btn-tls-next";
        next.addEventListener("click", () => {
            if (tlsStep === 1 && (!$("tls-domain").value.trim() || !$("tls-email").value.trim())) {
                tlsMessage("Enter the domain and a contact email first.", false);
                return;
            }
            tlsGoToStep(tlsStep + 1);
        });
        nav.append(next);
    }
    return nav;
}

// Steps are shown and hidden rather than re-rendered, so what has been typed
// into one survives going to the next and back.
function tlsGoToStep(n) {
    tlsStep = n;
    tlsMessage("", false);
    document.querySelectorAll(".tls-wizard [data-tls-step]").forEach((el) => {
        el.hidden = Number(el.dataset.tlsStep) !== n;
    });
    document.querySelectorAll(".tls-steps li").forEach((li, k) => {
        li.className = k + 1 === n ? "current" : (k + 1 < n ? "done" : "");
    });
    const wizard = document.querySelector(".tls-wizard");
    const oldNav = wizard?.querySelector(".tls-wizard-nav");
    if (wizard && oldNav) oldNav.replaceWith(tlsWizardNav(tlsLastStatus));
}

function tlsHttpWarning() {
    const warn = tlsEl("div", "enc-notice-bad");
    warn.append(tlsEl("strong", "", "This page is on plain HTTP. "), document.createTextNode(
        "The credentials you enter here cross the network unencrypted, where anyone on the "
        + "path can read them — and a DNS API credential can change your DNS. To keep "
        + "them off the network, use the command at the bottom of this section instead."));
    return warn;
}

function tlsBasics(st) {
    const basics = tlsEl("div", "tls-grid");
    basics.append(
        tlsField("Domain", "The name you will browse to. It has to be in a DNS zone the provider below manages.",
                 tlsInput("tls-domain", { placeholder: "pcap.example.com", value: st.config?.domain || "" })),
        tlsField("Contact email", "Let's Encrypt writes here about expiry problems.",
                 tlsInput("tls-email", { type: "email", placeholder: "you@example.com", value: st.config?.email || "" })),
    );
    return basics;
}

function tlsProviderPicker(st) {
    tlsSelectedProvider = st.config?.provider || st.stored_provider || tlsSelectedProvider || "cloudflare";
    const select = tlsEl("select");
    select.id = "tls-provider";
    for (const p of tlsProviders) {
        const opt = tlsEl("option", "", p.name);
        opt.value = p.code;
        opt.selected = p.code === tlsSelectedProvider;
        select.append(opt);
    }
    const fields = tlsEl("div", "");
    fields.id = "tls-provider-fields";
    select.addEventListener("change", () => {
        tlsSelectedProvider = select.value;
        renderProviderFields(fields, st);
    });
    const group = tlsEl("div", "");
    group.append(tlsField("DNS provider", "Where the domain's DNS is hosted.", select));
    group.append(fields);
    renderProviderFields(fields, st);
    return group;
}

function tlsValidationDelayField(st) {
    const input = tlsInput("tls-validation-delay", {
        type: "number",
        placeholder: String(st.default_validation_delay || 30),
        value: st.config ? String(st.config.validation_delay) : "",
    });
    input.min = "5";
    input.max = "600";
    return tlsField("Wait before validation (seconds)",
        "How long to wait after creating the DNS record before Let's Encrypt checks it — the "
        + "same as Proxmox's validation delay or certbot's propagation seconds. Raise it if "
        + "your provider is slow to publish.", input);
}

function tlsSubmitRow(st) {
    const row = tlsEl("div", "tls-actions");
    const label = tlsEl("label", "tls-check");
    const staging = tlsInput("tls-staging", { type: "checkbox" });
    staging.checked = !!st.config?.staging;
    label.append(staging, tlsEl("span", "", "Staging — for testing: untrusted certificate, generous rate limits"));
    const go = tlsEl("button", "btn btn-sm btn-primary", st.certificate ? "Request new certificate" : "Request certificate");
    go.id = "btn-tls-request";
    go.addEventListener("click", requestCertificate);
    row.append(label, go);
    return row;
}

function tlsCliHint(st) {
    const more = tlsEl("details", "learn-more tls-cli-hint");
    more.append(tlsEl("summary", "", "Prefer the command line?"));
    more.append(tlsEl("p", "",
        "From the Docker host, in the folder holding docker-compose.yml. The credentials are "
        + "prompted for, so they never cross the network:"));
    const cli = tlsEl("pre", "enc-howto");
    cli.id = "tls-cli";
    cli.textContent = `docker compose exec -it pcap-server python -m backend.tls issue \\\n`
        + `    --domain ${st.config?.domain || "pcap.example.com"} --email ${st.config?.email || "you@example.com"}`
        + ` --provider ${tlsSelectedProvider}\n`
        + `docker compose restart pcap-server`;
    more.append(cli);
    return more;
}

function renderProviderFields(container, st) {
    container.textContent = "";
    const provider = tlsProviders.find((p) => p.code === tlsSelectedProvider);
    if (!provider) return;
    const stored = st.stored_provider === provider.code ? new Set(st.stored_credentials) : new Set();

    const cli = $("tls-cli");
    if (cli) cli.textContent = cli.textContent.replace(/--provider \S+/, `--provider ${provider.code}`);

    const docs = tlsEl("div", "field-hint");
    const link = tlsEl("a", "", `lego's guide for ${provider.name}`);
    link.href = provider.docs;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    docs.append(document.createTextNode(provider.primary?.length
        ? "The usual settings — "
        : "Which of these you need depends on how you authenticate — "),
                link, document.createTextNode(stored.size ? ". Leave a stored field blank to keep it." : "."));
    container.append(docs);

    // A provider with a recommended set shows just that set; the alternatives
    // are one click away. Otherwise every credential is shown.
    const primary = new Set(provider.primary || []);
    const main = tlsEl("div", "tls-grid");
    const other = tlsDetails("Other ways to authenticate");
    const more = tlsDetails("More settings");
    for (const v of provider.variables) {
        const field = tlsVariableField(v, stored);
        if (primary.size ? primary.has(v.name) : v.group === "credentials") main.append(field);
        else if (v.group === "credentials") other.grid.append(field);
        else more.grid.append(field);
    }
    container.append(main);
    if (other.grid.childElementCount) container.append(other.el);
    if (more.grid.childElementCount) container.append(more.el);
}

function tlsDetails(summary) {
    const el = tlsEl("details", "tls-more");
    el.append(tlsEl("summary", "", summary));
    const grid = tlsEl("div", "tls-grid");
    el.append(grid);
    return { el, grid };
}

function tlsVariableField(v, stored) {
    let control;
    if (v.kind === "file") {
        control = tlsEl("textarea");
        control.rows = 3;
        control.placeholder = stored.has(v.name) ? "stored — paste to replace" : "Paste the file's contents";
    } else {
        control = tlsEl("input");
        control.type = v.kind === "secret" ? "password" : "text";
        control.autocomplete = "off";
        control.placeholder = stored.has(v.name) ? "stored — blank keeps it" : "";
    }
    control.id = `tls-var-${v.name}`;
    control.dataset.tlsVar = v.name;
    control.spellcheck = false;
    const hint = v.kind === "file" ? `${v.description} (paste the file itself, not a path)` : v.description;
    return tlsField(v.name, hint, control, true);
}

function tlsMessage(text, ok) {
    const msg = $("tls-msg");
    if (!msg) return;
    msg.className = ok ? "success-msg" : "error-msg";
    msg.textContent = text;
}

async function requestCertificate() {
    const credentials = {};
    for (const input of document.querySelectorAll("#tls-provider-fields [data-tls-var]")) {
        const value = input.tagName === "TEXTAREA" ? input.value : input.value.trim();
        if (value) credentials[input.dataset.tlsVar] = value;
    }
    const body = {
        domain: $("tls-domain").value.trim(),
        email: $("tls-email").value.trim(),
        provider: $("tls-provider").value,
        credentials,
        staging: $("tls-staging").checked,
        validation_delay: $("tls-validation-delay").value.trim(),
    };
    const btn = $("btn-tls-request");
    if (btn) btn.disabled = true;
    tlsMessage("Requesting a certificate — this takes about a minute: the DNS record is created, then Let's Encrypt checks it after the wait…", true);
    try {
        const st = await api("/api/admin/tls/acme", { method: "POST", body: JSON.stringify(body) });
        tlsSetupOpen = false;
        renderTls($("admin-tls"), st);
        tlsMessage("Certificate issued.", true);
    } catch (e) {
        // Left open, as typed: re-rendering would clear the credentials the
        // admin just entered, and the error is usually fixed by changing one.
        tlsMessage(e.message, false);
    } finally {
        const again = $("btn-tls-request");
        if (again) again.disabled = false;
    }
}

async function renewCertificate() {
    tlsMessage("Renewing…", true);
    try {
        renderTls($("admin-tls"), await api("/api/admin/tls/renew", { method: "POST" }));
        tlsMessage("Renewed.", true);
    } catch (e) {
        await loadTlsStatus();
        tlsMessage(e.message, false);
    }
}

async function switchToHttps(st) {
    // The port the browser is using now: the host side of the compose ports:
    // line, whatever the operator chose. The same port speaks TLS afterwards.
    const port = window.location.port ? `:${window.location.port}` : "";
    const target = `https://${st.config?.domain || window.location.hostname}${port}/`;
    if (!confirm("Restart pcap-server into HTTPS?\n\nEveryone is signed out, and plain HTTP stops "
            + `answering on this port. Reconnect at:\n\n${target}`)) return;
    try {
        await api("/api/admin/tls/restart", { method: "POST" });
    } catch (e) {
        tlsMessage(e.message, false);
        return;
    }
    const box = $("admin-tls");
    box.textContent = "";
    box.append(tlsEl("div", "enc-state enc-good", "Restarting into HTTPS…"));
    const p = tlsEl("div", "enc-detail", "Give it a few seconds, then open ");
    const a = tlsEl("a", "", target);
    a.href = target;
    p.append(a);
    box.append(p);
}

async function removeCertificate() {
    if (!confirm("Remove the certificate, its key, the stored DNS credentials and the settings?\n\n"
            + "If pcap-server is serving HTTPS now it carries on until the next restart, "
            + "then comes back on plain HTTP.")) return;
    try {
        renderTls($("admin-tls"), await api("/api/admin/tls", { method: "DELETE" }));
        tlsMessage("Removed.", true);
    } catch (e) {
        tlsMessage(e.message, false);
    }
}
