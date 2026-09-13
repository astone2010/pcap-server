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

function renderTls(box, st) {
    box.textContent = "";
    const summary = tlsSummary(st);
    box.append(tlsEl("div", `enc-state enc-${summary.level}`, summary.headline));
    box.append(tlsEl("div", "enc-detail", summary.detail));
    box.append(tlsFacts(st));
    if (st.last_error) {
        box.append(tlsEl("div", "error-msg", "Last attempt failed:"));
        box.append(tlsEl("pre", "enc-howto", st.last_error));
    }
    if (st.certificate || st.config) box.append(tlsActions(st));
    if (st.available) box.append(tlsRequestForm(st));
    const msg = tlsEl("div", "error-msg");
    msg.id = "tls-msg";
    box.append(msg);
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
    const actions = tlsEl("div", "admin-inline-form");
    actions.style.marginTop = "12px";
    if (st.restart_needed) {
        const b = tlsEl("button", "btn btn-sm btn-primary", "Switch to HTTPS");
        b.addEventListener("click", () => switchToHttps(st));
        actions.append(b);
    }
    if (st.config && st.stored_credentials.length && st.available) {
        const b = tlsEl("button", "btn btn-sm btn-secondary", "Renew now");
        b.addEventListener("click", renewCertificate);
        actions.append(b);
    }
    const rm = tlsEl("button", "btn btn-sm btn-danger", "Remove");
    rm.addEventListener("click", removeCertificate);
    actions.append(rm);
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

function tlsRequestForm(st) {
    const wrap = tlsEl("div", "tls-form");
    if (!secureTransport) wrap.append(tlsHttpWarning());
    wrap.append(tlsBasics(st));
    wrap.append(tlsProviderPicker(st));
    wrap.append(tlsSubmitRow(st));
    wrap.append(...tlsCliHint(st));
    return wrap;
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
    group.append(tlsField("DNS provider",
        "Where the domain's DNS is hosted. pcap-server proves the domain is yours by creating "
        + "a TXT record there, so the machine never has to be reachable from the internet.", select));
    group.append(fields);
    renderProviderFields(fields, st);
    return group;
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
    const hint = tlsEl("div", "field-hint",
        "Or from the Docker host, which keeps the credentials off the network — they are prompted for:");
    const cli = tlsEl("pre", "enc-howto");
    cli.id = "tls-cli";
    cli.textContent = `docker compose exec -it pcap-server python -m backend.tls issue \\\n`
        + `    --domain ${st.config?.domain || "pcap.example.com"} --email ${st.config?.email || "you@example.com"}`
        + ` --provider ${tlsSelectedProvider}\n`
        + `docker compose restart pcap-server`;
    return [hint, cli];
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
    docs.append(document.createTextNode("Which of these you need depends on how you authenticate — see "),
                link, document.createTextNode(". Stored values are never shown; leave a stored field blank to keep it."));
    container.append(docs);

    const main = tlsEl("div", "tls-grid");
    const more = tlsEl("details", "tls-more");
    more.append(tlsEl("summary", "", "More settings"));
    const moreGrid = tlsEl("div", "tls-grid");
    more.append(moreGrid);

    for (const v of provider.variables) {
        const id = `tls-var-${v.name}`;
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
        control.id = id;
        control.dataset.tlsVar = v.name;
        control.spellcheck = false;
        const hint = v.kind === "file" ? `${v.description} (paste the file itself, not a path)` : v.description;
        (v.group === "credentials" ? main : moreGrid).append(tlsField(v.name, hint, control, true));
    }
    container.append(main);
    if (moreGrid.childElementCount) container.append(more);
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
    };
    const btn = $("btn-tls-request");
    if (btn) btn.disabled = true;
    tlsMessage("Requesting a certificate — this usually takes a minute or two while DNS propagates…", true);
    try {
        renderTls($("admin-tls"), await api("/api/admin/tls/acme", { method: "POST", body: JSON.stringify(body) }));
        tlsMessage("Certificate issued.", true);
    } catch (e) {
        await loadTlsStatus();
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
