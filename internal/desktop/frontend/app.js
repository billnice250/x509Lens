"use strict";
const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
let documentState = {
    name: "",
    result: { items: [], paths: [], activity: [], warnings: [] },
  },
  selected = "",
  activeTab = "general",
  fieldIndex = 0,
  pathIndex = 0,
  asn1Mode = "text",
  search = "",
  epoch = 0,
  busy = false;
const api = () => window.go.desktop.App;
const runtime = () => window.runtime;
const item = () => documentState.result.items.find((x) => x.id === selected);
const localItems = () =>
  documentState.result.items.filter(
    (x) => !["AIA_ONLINE", "AIA_CACHE", "SYSTEM_STORE"].includes(x.sourceType),
  );
const pathsForItem = () =>
  documentState.result.paths.filter((p) => (p.nodes || []).includes(selected));
const activePath = () => pathsForItem()[pathIndex] || pathsForItem()[0];
const date = (s) =>
  s
    ? new Date(s).toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "Not specified";
const friendly = (s) =>
  ({
    certificate: "Certificate",
    crl: "Certificate revocation list",
    csr: "Certificate signing request",
    "private-key": "Private key metadata",
    "public-key": "Public key",
    FILE: "File",
    PEM_BUNDLE: "PEM bundle",
    PKCS7: "PKCS#7 bundle",
    PKCS12: "PKCS#12 identity",
    AIA_ONLINE: "Downloaded issuer",
    AIA_CACHE: "Cached issuer",
    SYSTEM_STORE: "System trust store",
    SERVER_PRESENTED: "Presented by server",
  })[s] || s;
const symbol =
  '<div class="certificate-symbol" aria-hidden="true"><svg viewBox="0 0 72 80"><path d="M14 7h33l12 12v53H14z"/><path d="M47 7v14h12M24 29h25M24 37h19M24 45h11"/><circle cx="45" cy="57" r="11"/><path d="m40 57 4 4 7-8M40 67l-2 10 7-4 6 4-2-10"/></svg></div>';
const text = (v) =>
  typeof v === "object" ? JSON.stringify(v, null, 2) : String(v ?? "");
function notice(message) {
  $("notice").textContent = message || "";
  $("notice").hidden = !message;
}
function setBusy(value, message) {
  busy = value;
  document.body.classList.toggle("busy", value);
  for (const id of ["open", "server", "welcome-open", "verify", "export", "unlock"])
    if ($(id))
      $(id).disabled =
        value ||
        (["verify", "export"].includes(id) && !item()) ||
        (id === "export" && item()?.kind === "private-key");
  if (value) $("status").textContent = message || "Reviewing file…";
}
async function invoke(action, message, askPassword = false) {
  const request = ++epoch;
  setBusy(true, message);
  notice("");
  try {
    const doc = await action();
    if (request === epoch) setDocument(doc, askPassword);
  } catch (error) {
    if (request === epoch) {
      setBusy(false);
      notice(String(error));
      $("status").textContent = "Unable to complete the action";
    }
  }
}
function setDocument(doc, askPassword = false) {
  if (!doc) return;
  doc.result ||= {};
  for (const key of ["items", "paths", "activity", "warnings"])
    doc.result[key] ||= [];
  const changed = doc.name !== documentState.name;
  documentState = doc;
  if (changed || !item()) {
    const objects = localItems();
    selected =
      (
        objects.find((x) => x.kind === "certificate" && !x.details?.isCA) ||
        objects[0] ||
        doc.result.items[0]
      )?.id || "";
    activeTab = "general";
    fieldIndex = 0;
    pathIndex = 0;
    search = "";
  }
  setBusy(false);
  render();
  if (askPassword && doc.needsPassword) showPassword();
}
function property(label, value) {
  return value !== undefined && value !== null
    ? `<div class="property"><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`
    : "";
}
function badge(status, label) {
  return `<span class="badge ${status}">${esc(label)}</span>`;
}
function validity(d) {
  const now = Date.now();
  if (d.notBefore && now < new Date(d.notBefore)) return "Not yet valid";
  if (d.notAfter && now > new Date(d.notAfter)) return "Expired";
  return "Within validity period";
}
function render() {
  const object = item(),
    objects = localItems(),
    d = object?.details || {};
  $("filename").textContent = documentState.name || "X509 Lens";
  $("filemeta").textContent = documentState.name
    ? `${(documentState.size / 1024).toFixed(1)} KB · ${objects.length} ${objects.length === 1 ? "object" : "objects"}`
    : "Certificate viewer";
  $("tabs").hidden = !object;
  $("objectbar").hidden =
    objects.length < 2 && (!object || objects.some((x) => x.id === selected));
  $("objects").innerHTML = objects
    .map(
      (x) =>
        `<option value="${esc(x.id)}">${esc(x.name)} — ${esc(friendly(x.kind))}</option>`,
    )
    .join("");
  $("objects").value = selected;
  $("back").hidden = !object || objects.some((x) => x.id === selected);
  $("unlock").hidden = !documentState.needsPassword;
  $("verify").textContent = $("online").checked
    ? "Verify online"
    : "Verify offline";
  setBusy(busy);
  if (!documentState.name) {
    $("status").textContent = "Ready to open a file";
    return;
  }
  if (!object) {
    $("panel").innerHTML =
      `<div class="welcome">${symbol}<h1>${documentState.needsPassword ? "This file is password protected" : "Unable to inspect this file"}</h1><p>${esc(documentState.needsPassword ? "Unlock it to view its certificates and key metadata." : documentState.error || "No supported objects were found.")}</p>${documentState.needsPassword ? '<button id="empty-unlock" class="primary">Unlock…</button>' : ""}</div>`;
    if ($("empty-unlock")) $("empty-unlock").onclick = showPassword;
    $("status").textContent = "File opened · No objects available";
    return;
  }
  $("tab-chain").disabled = object.kind !== "certificate";
  $("tab-missing").disabled = !["certificate", "crl"].includes(object.kind);
  if (activeTab === "chain" && object.kind !== "certificate")
    activeTab = "general";
  if (activeTab === "missing" && $("tab-missing").disabled)
    activeTab = "general";
  document.querySelectorAll("[data-tab]").forEach((el) => {
    el.setAttribute("aria-selected", String(el.dataset.tab === activeTab));
    el.tabIndex = el.dataset.tab === activeTab ? 0 : -1;
  });
  $("panel").setAttribute("aria-labelledby", "tab-" + activeTab);
  $("panel").classList.toggle(
    "detail-mode",
    activeTab === "details" || activeTab === "asn1",
  );
  if (activeTab === "general") renderGeneral(object, d);
  if (activeTab === "details") renderDetails(object, d);
  if (activeTab === "asn1") renderASN1(d);
  if (activeTab === "missing") renderMissing(object, d);
  if (activeTab === "chain") renderChain(object);
  $("status").textContent = documentState.online
    ? "Online verification completed · Results are diagnostic"
    : "Local checks · No network requests";
  if (documentState.error && !documentState.needsPassword)
    notice(documentState.error);
}
function renderGeneral(object, d) {
  const p = activePath(),
    revocations = (p?.revocation || []).filter(
      (r) => r.certificate === object.id,
    ),
    state = validity(d);
  let status = "",
    statusClass = "";
  if (object.kind === "certificate") {
    status =
      state !== "Within validity period"
        ? state
        : p?.trusted
          ? "Trusted by this computer"
          : "Trust could not be established";
    statusClass =
      state !== "Within validity period" ? "bad" : p?.trusted ? "good" : "warn";
  }
  let html = `<div class="summary">${symbol}<div><div class="eyebrow">${esc(friendly(object.kind))}</div><h1>${esc(object.name)}</h1>${status ? badge(statusClass, status) : '<p class="subtle">Public information only</p>'}</div></div><div class="card"><dl class="properties">`;
  if (object.kind === "certificate") {
    html +=
      property("Issued to", d.subject) +
      property("Issued by", d.issuer) +
      property("Valid from", date(d.notBefore)) +
      property("Valid until", date(d.notAfter)) +
      property(
        "Basic constraints",
        d.basicConstraints,
      ) +
      property(
        "Path length constraint",
        d.pathLengthConstraint,
      ) +
      property(
        "Intended for",
        d.isCA
          ? "Certificate authority"
          : d.keyUsage
            ? usage(d.keyUsage)
            : undefined,
      ) +
      property(
        "Extended key usage",
        d.extKeyUsage ? usage(d.extKeyUsage) : undefined,
      );
  } else if (object.kind === "crl") {
    html +=
      property("Issued by", d.issuer) +
      property("This update", date(d.thisUpdate)) +
      property("Next update", date(d.nextUpdate)) +
      property("Revoked entries", d.count) +
      property("CRL number", d.number);
  } else if (object.kind === "csr") {
    html +=
      property("Subject", d.subject) +
      property("Signature", d.signatureAlgorithm) +
      property("Signature valid", d.signatureValid ? "Yes" : "No") +
      property("Public key", d.publicKeyAlgorithm);
  } else {
    html +=
      property("Algorithm", d.algorithm) +
      property("Key size", d.bits ? d.bits + " bits" : undefined) +
      property("Curve", d.curve || undefined) +
      property(
        "Private material",
        object.kind === "private-key"
          ? "Hidden. Only public metadata is available."
          : undefined,
      );
  }
  html += "</dl></div>";
  if (object.kind === "crl") {
    const revoked = d.revoked || [];
    html +=
      '<div class="card"><h3>Revoked certificates' +
      (revoked.length ? " · " + revoked.length : "") +
      "</h3>";
    if (revoked.length) {
      html +=
        '<input id="revoked-search" type="search" placeholder="Filter by serial number, date or reason" aria-label="Filter revoked certificates"><div class="revoked-list" id="revoked-list">' +
        revoked
          .map(
            (entry) =>
              `<div class="revoked-entry"><code>${esc(entry.serial)}</code><span>${esc(date(entry.date))}</span><span>${esc(entry.reason || "Unspecified")}</span></div>`,
          )
          .join("") +
        "</div>";
    } else {
      html +=
        '<p class="subtle">This CRL does not list any revoked certificates.</p>';
    }
    html += "</div>";
  }
  if (object.kind === "certificate") {
    html += '<div class="card"><h3>Certificate checks</h3>';
    const checks = [
      [
        "Certification path",
        p?.trusted ? "Trusted" : "Untrusted or incomplete",
      ],
      ["Validity", state],
      [
        "Revocation",
        revocations.length
          ? revocations.map((r) => r.status + " · " + r.method).join(", ")
          : "Not checked",
      ],
      ["Application purpose", "Not selected"],
    ];
    html += checks
      .map(
        ([k, v]) =>
          `<div class="assessment"><span>${esc(k)}</span><strong class="${/REVOKED|Expired|Not yet/.test(v) ? "bad" : /Trusted|Within|GOOD/.test(v) ? "good" : ""}">${esc(v)}</strong></div>`,
      )
      .join("");
    if (p?.error) html += `<p class="explanation">${esc(p.error)}</p>`;
    if (revocations.some((r) => r.detail))
      html += `<p class="explanation">${esc(revocations.map((r) => r.detail || "").join(" "))}</p>`;
    html += "</div>";
  }
  const warnings = documentState.result.warnings;
  if (warnings.length)
    html += `<details><summary>${warnings.length} inspection ${warnings.length === 1 ? "note" : "notes"}</summary><div class="explanation">${warnings.map((w) => `<p>${esc(w)}</p>`).join("")}</div></details>`;
  html += `<details><summary>Network activity${documentState.result.activity.length ? " · " + documentState.result.activity.length + " events" : " · no requests"}</summary>${documentState.result.activity.map((a) => `<div class="network-event"><strong>${esc(a.method)} · ${esc(a.status)}</strong><span>${esc(a.url)}</span><span>${esc(a.detail || "")}${a.cacheHit ? " · Cached" : ""}${a.httpStatus ? " · HTTP " + a.httpStatus : ""}${a.size ? " · " + a.size + " bytes" : ""}</span></div>`).join("")}</details>`;
  $("panel").innerHTML = html;
  if ($("revoked-search"))
    $("revoked-search").oninput = () => {
      const query = $("revoked-search").value.toLowerCase();
      document.querySelectorAll("#revoked-list .revoked-entry").forEach((row) => {
        row.hidden = !row.textContent.toLowerCase().includes(query);
      });
    };
}
function usage(value) {
  if (Array.isArray(value)) return value.join(", ") || "Not specified";
  if (typeof value === "string") return value || "Not specified";
  const flags = Number(value) || 0;
  const names = [
    [1, "Digital signature"],
    [2, "Content commitment"],
    [4, "Key encipherment"],
    [8, "Data encipherment"],
    [16, "Key agreement"],
    [32, "Certificate signing"],
    [64, "CRL signing"],
  ]
    .filter(([bit]) => flags & bit)
    .map(([, name]) => name);
  return names.join(", ") || "Not specified";
}
const labels = {
  subject: "Subject",
  issuer: "Issuer",
  serial: "Serial number",
  notBefore: "Valid from",
  notAfter: "Valid until",
  signatureAlgorithm: "Signature algorithm",
  publicKeyAlgorithm: "Public key algorithm",
  isCA: "Certificate authority",
  basicConstraints: "Basic constraints",
  maxPathLen: "Path length constraint",
  pathLengthConstraint: "Path length constraint",
  keyUsage: "Key usage",
  extKeyUsage: "Extended key usage",
  dnsNames: "DNS names",
  emails: "Email addresses",
  ips: "IP addresses",
  uris: "URIs",
  ski: "Subject key identifier",
  aki: "Authority key identifier",
  sha256: "SHA-256 fingerprint",
  sha1: "SHA-1 fingerprint",
  signatureSHA1: "Signature SHA-1",
  signatureSHA256: "Signature SHA-256",
  signatureValid: "Signature valid",
  spkiAlgorithm: "SPKI algorithm",
  spkiSHA1: "SPKI SHA-1",
  spkiSHA256: "SPKI SHA-256",
  spkiPinSHA256: "SPKI SHA-256 pin",
  spkiDER: "SPKI DER (hex)",
  ocspServers: "OCSP responders",
  issuingCertificateURLs: "Issuer download URLs",
  crlDistributionPoints: "CRL distribution points",
  rawDER: "Raw DER (hex)",
  thisUpdate: "This update",
  nextUpdate: "Next update",
  number: "CRL number",
  count: "Revoked certificate count",
  algorithm: "Algorithm",
  bits: "Key size",
  curve: "Curve",
  privateMaterialHidden: "Private material hidden",
};
function fieldsFor(object, d) {
  const fields = Object.entries(d)
    .filter(
      ([key]) =>
        !["asn1", "asn1Text", "extensions", "missingExtensions", "revoked"].includes(key),
    )
    .map(([key, value]) => [
      labels[key] || key,
      ["keyUsage", "extKeyUsage"].includes(key) ? usage(value) : text(value),
    ]);
  for (const ext of d.extensions || [])
    fields.push([
      `Extension ${ext.name ? ext.name + " · " : ""}${ext.oid}${ext.critical ? " (critical)" : ""}`,
      ext.value ? `${ext.value}\n\nDER: ${ext.der}` : ext.der,
      Boolean(ext.critical),
    ]);
  for (const entry of d.revoked || [])
    fields.push([
      "Revoked serial " + entry.serial,
      `Revocation date: ${date(entry.date)}\nReason: ${entry.reason || "Unspecified"}${entry.reasonCode !== undefined ? " (" + entry.reasonCode + ")" : ""}`,
    ]);
  if (object.attributes)
    for (const [key, value] of Object.entries(object.attributes))
      fields.push([key, value]);
  fields.push(["Source", `${friendly(object.sourceType)}\n${object.source}`]);
  return fields.filter(([k, v]) =>
    (k + " " + v).toLowerCase().includes(search.toLowerCase()),
  );
}
function renderDetails(object, d) {
  $("panel").innerHTML =
    `<div class="detail-layout"><div class="detail-tools"><input id="field-search" type="search" placeholder="Find a field or serial number" aria-label="Find a field or serial number"></div><div id="detail-body"></div></div>`;
  $("field-search").value = search;
  $("field-search").oninput = () => {
    search = $("field-search").value;
    fieldIndex = 0;
    renderDetailBody(object, d);
  };
  renderDetailBody(object, d);
}
function renderDetailBody(object, d) {
  const fields = fieldsFor(object, d);
  if (fieldIndex >= fields.length) fieldIndex = 0;
  $("detail-body").className = "detail-fields";
  $("detail-body").innerHTML =
    `<div class="fields" aria-label="Object fields">${fields.map(([key, value, critical], i) => `<button class="field ${critical ? "critical" : ""} ${i === fieldIndex ? "selected" : ""}" data-field="${i}"><span>${esc(key)}</span><span>${esc(value)}</span></button>`).join("") || '<p class="subtle">No matching fields.</p>'}</div><div class="value-title"><strong id="value-label">${esc(fields[fieldIndex]?.[0] || "Value")}</strong><button id="copy-value" ${fields.length ? "" : "disabled"}>Copy value</button></div><div class="value"><pre id="value-text">${esc(fields[fieldIndex]?.[1] || "")}</pre></div>`;
  document.querySelectorAll("[data-field]").forEach(
    (el) =>
      (el.onclick = () => {
        fieldIndex = Number(el.dataset.field);
        document
          .querySelectorAll("[data-field]")
          .forEach((x) => x.classList.toggle("selected", x === el));
        $("value-label").textContent = fields[fieldIndex][0];
        $("value-text").textContent = fields[fieldIndex][1];
      }),
  );
  $("copy-value").onclick = async () => {
    try {
      await runtime().ClipboardSetText(fields[fieldIndex][1]);
      notice("Value copied to clipboard");
    } catch (e) {
      notice(String(e));
    }
  };
}
function renderASN1(d) {
  function tree(nodes) {
    return (nodes || [])
      .map(
        (n) =>
          `<details open><summary>Tag ${n.tag} · Class ${n.class} · Offset ${n.offset} · ${n.length} bytes ${esc(n.value || "")}</summary><pre>${esc(n.hex)}</pre>${tree(n.children)}</details>`,
      )
      .join("");
  }
  $("panel").innerHTML =
    `<div class="detail-layout"><div class="detail-tools"><label for="asn1-mode" class="subtle">Representation</label><select id="asn1-mode"><option value="text">ASN.1 text</option><option value="structure">Structure and hex</option></select></div><div id="asn1-body" class="detail-asn1"></div></div>`;
  $("asn1-mode").value = asn1Mode;
  const draw = () => {
    asn1Mode = $("asn1-mode").value;
    $("asn1-body").innerHTML =
      asn1Mode === "text"
        ? `<p class="subtle">Human-readable DER representation.</p><div class="value"><pre>${esc(d.asn1Text || "ASN.1 text is not available for this object.")}</pre></div>`
        : `<p class="subtle">DER structure · Hex previews are limited to 256 bytes per node.</p><div class="asn1">${tree(d.asn1) || "ASN.1 structure is not available for this object."}</div>`;
  };
  $("asn1-mode").onchange = draw;
  draw();
}
function renderMissing(object, d) {
  const missing = d.missingExtensions || [];
  if (!["certificate", "crl"].includes(object.kind)) {
    $("panel").innerHTML =
      '<p class="subtle">Extension expectations apply to certificates and CRLs.</p>';
    return;
  }
  if (!missing.length) {
    $("panel").innerHTML =
      '<div class="card"><p>All recognized extensions are present.</p></div>';
    return;
  }
  $("panel").innerHTML =
    `<p class="subtle">These recognized extensions are not encoded in this ${object.kind}. Missing extensions are listed here instead of appearing as fields with null or default values.</p><div class="card"><dl class="properties">${missing.map((ext) => `<div class="property"><dt>${esc(ext.name)}</dt><dd><code>${esc(ext.oid)}</code></dd></div>`).join("")}</dl></div>`;
}
function renderChain(object) {
  const paths = pathsForItem(),
    p = activePath();
  if (!p) {
    $("panel").innerHTML =
      '<p class="subtle">No certification path is available for this object.</p>';
    return;
  }
  let html =
    paths.length > 1
      ? `<label class="subtle" for="path-select">Alternative certification paths</label><select class="path-select" id="path-select">${paths.map((path, i) => `<option value="${i}">Path ${i + 1} · ${path.trusted ? "Trusted" : "Untrusted or incomplete"} · ${path.nodes.length} certificates</option>`).join("")}</select>`
      : "";
  const presented = p.nodes.filter((id) => documentState.result.items.find((x) => x.id === id)?.sourceType === "SERVER_PRESENTED").length;
  const hostAdded = p.nodes.filter((id) => documentState.result.items.find((x) => x.id === id)?.sourceType === "SYSTEM_STORE").length;
  if (presented || hostAdded) html += `<div class="card"><strong>Chain comparison</strong><p class="subtle">Server presented: ${presented} certificate${presented === 1 ? "" : "s"} · Host trust resolution added: ${hostAdded} certificate${hostAdded === 1 ? "" : "s"}</p></div>`;
  html += `<div class="chain-title"><p>${badge(p.trusted ? "good" : "warn", p.trusted ? "Trusted certification path" : "Untrusted or incomplete path")}</p><small>Root → selected certificate</small></div>`;
  html += [...p.nodes]
    .reverse()
    .map((id, i) => {
      const node = documentState.result.items.find((x) => x.id === id);
      const d = node?.details || {};
      const r = (p.revocation || []).find((x) => x.certificate === id);
      return `<button class="chain-node ${id === object.id ? "active" : ""}" style="margin-left:${Math.min(i * 14, 70)}px;width:calc(100% - ${Math.min(i * 14, 70)}px)" data-node="${esc(id)}"><span class="node-symbol">▧</span><span><strong>${esc(node?.name || id)}</strong><small>${esc(friendly(node?.sourceType || "SYSTEM_STORE"))} · ${esc(validity(d))}${r ? " · " + esc(r.status) : ""}</small></span></button>`;
    })
    .join("");
  if (p.error) html += `<p class="explanation">${esc(p.error)}</p>`;
  html +=
    '<p class="subtle">Select a certificate to review its information.</p>';
  $("panel").innerHTML = html;
  if ($("path-select")) {
    $("path-select").value = String(pathIndex);
    $("path-select").onchange = () => {
      pathIndex = Number($("path-select").value);
      renderChain(object);
    };
  }
  document.querySelectorAll("[data-node]").forEach(
    (el) =>
      (el.onclick = () => {
        selected = el.dataset.node;
        activeTab = "general";
        fieldIndex = 0;
        pathIndex = 0;
        render();
      }),
  );
}
function showPassword() {
  if (busy) return;
  $("password-error").textContent = "";
  $("password").value = "";
  if (!$("password-dialog").open) $("password-dialog").showModal();
  $("password").focus();
}
function showExport() {
  if (busy || !item() || item().kind === "private-key") return;
  $("export-path").innerHTML = pathsForItem()
    .map(
      (p, i) =>
        `<option value="${i}">Path ${i + 1} · ${p.trusted ? "Trusted" : "Untrusted or incomplete"}</option>`,
    )
    .join("");
  $("export-scope").value = "object";
  $("export-format").value = "pem";
  updateExport();
  $("export-dialog").showModal();
}
function updateExport() {
  const single =
    ["der", "fingerprint"].includes($("export-format").value) ||
    item()?.kind !== "certificate";
  if (single) $("export-scope").value = "object";
  $("export-scope").disabled = single || !pathsForItem().length;
  $("export-path").disabled = $("export-scope").value === "object";
}
$("open").onclick = () => invoke(() => api().OpenFile(), "Opening file…", true);
$("welcome-open").onclick = $("open").onclick;
$("server").onclick = () => {
  $("server-endpoint").value = "";
  $("server-dialog").showModal();
  $("server-endpoint").focus();
};
$("server-cancel").onclick = () => $("server-dialog").close();
$("server-form").onsubmit = (e) => {
  e.preventDefault();
  const endpoint = $("server-endpoint").value;
  $("server-dialog").close();
  invoke(() => api().OpenServer(endpoint), "Downloading server certificate chain…");
};
$("objects").onchange = () => {
  selected = $("objects").value;
  activeTab = "general";
  fieldIndex = 0;
  pathIndex = 0;
  render();
};
$("back").onclick = () => {
  selected =
    localItems().find((x) => x.kind === "certificate" && !x.details?.isCA)
      ?.id ||
    localItems()[0]?.id ||
    "";
  activeTab = "general";
  pathIndex = 0;
  render();
};
document.querySelectorAll("[data-tab]").forEach((el) => {
  el.onclick = () => {
    activeTab = el.dataset.tab;
    render();
  };
  el.onkeydown = (e) => {
    if (!["ArrowLeft", "ArrowRight"].includes(e.key)) return;
    e.preventDefault();
    const tabs = [...document.querySelectorAll("[data-tab]")].filter(
        (x) => !x.disabled,
      ),
      i = tabs.indexOf(el),
      next =
        tabs[
          (i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length
        ];
    next.click();
    next.focus();
  };
});
$("verify").onclick = () =>
  invoke(
    () => api().Verify($("online").checked),
    $("online").checked
      ? "Checking issuers and revocation online…"
      : "Verifying offline…",
  );
$("unlock").onclick = showPassword;
$("password-cancel").onclick = () => {
  $("password").value = "";
  $("password-dialog").close();
};
$("password-dialog").addEventListener("close", () => {
  $("password").value = "";
});
$("password-form").onsubmit = async (e) => {
  e.preventDefault();
  const password = $("password").value;
  $("password").value = "";
  const button = e.submitter;
  button.disabled = true;
  try {
    const doc = await api().Unlock(password);
    if (doc.needsPassword) {
      $("password-error").textContent =
        doc.error || "Unable to unlock. Check the password and try again.";
      $("password").focus();
    } else {
      $("password-dialog").close();
      setDocument(doc);
    }
  } catch (error) {
    $("password-error").textContent = String(error);
  } finally {
    button.disabled = false;
  }
};
$("export").onclick = showExport;
$("export-cancel").onclick = () => $("export-dialog").close();
$("export-format").onchange = updateExport;
$("export-scope").onchange = updateExport;
$("export-form").onsubmit = async (e) => {
  e.preventDefault();
  const button = e.submitter;
  button.disabled = true;
  try {
    const saved = await api().Export(
      selected,
      $("export-format").value,
      $("export-scope").value,
      Number($("export-path").value || 0),
    );
    if (saved) {
      $("export-dialog").close();
      notice("Public data exported");
    }
  } catch (error) {
    notice(String(error));
    $("export-dialog").close();
  } finally {
    button.disabled = false;
  }
};
$("settings").onclick = () => $("settings-dialog").showModal();
$("settings-close").onclick = () => $("settings-dialog").close();
const systemTheme = matchMedia("(prefers-color-scheme: dark)");
function applyTheme() {
  const value = $("theme").value;
  document.documentElement.classList.toggle(
    "dark",
    value === "dark" || (value === "auto" && systemTheme.matches),
  );
  localStorage.setItem("x509lens.theme", value);
}
$("theme").value = localStorage.getItem("x509lens.theme") || localStorage.getItem("certview.theme") || "auto";
$("theme").onchange = applyTheme;
systemTheme.addEventListener("change", applyTheme);
applyTheme();
$("online").checked = (localStorage.getItem("x509lens.online") || localStorage.getItem("certview.online")) !== "false";
$("online").onchange = () => {
  localStorage.setItem("x509lens.online", String($("online").checked));
  $("verify").textContent = $("online").checked
    ? "Verify online"
    : "Verify offline";
};
document.addEventListener("dragover", (e) => e.preventDefault());
document.addEventListener("drop", (e) => e.preventDefault());
function enableWindowsShortcuts() {
  document.addEventListener("keydown", (e) => {
    if (!e.ctrlKey || e.altKey || e.metaKey) return;
    const key = e.key.toLowerCase();
    if (key === "o") {
      e.preventDefault();
      $("open").click();
    } else if (key === "s" && !$("export").disabled) {
      e.preventDefault();
      $("export").click();
    }
  });
}
async function init() {
  try {
    const environment = await runtime().Environment();
    if (environment.platform === "windows") enableWindowsShortcuts();
    runtime().EventsOn("viewer:document", (doc) => {
      epoch++;
      for (const dialog of document.querySelectorAll("dialog[open]"))
        dialog.close();
      setDocument(doc, true);
    });
    runtime().EventsOn("viewer:error", (error) => {
      epoch++;
      setBusy(false);
      notice(error);
      $("status").textContent = "Unable to open file";
    });
    runtime().EventsOn("viewer:busy", () => {
      epoch++;
      setBusy(true, "Opening file…");
    });
    runtime().EventsOn("viewer:export", showExport);
    await invoke(() => api().Ready(), "Preparing viewer…", true);
  } catch (error) {
    notice("The desktop runtime could not start: " + String(error));
    setBusy(false);
  }
}
init();
