(() => {
  "use strict";

  // Portions below are adapted from attestation-widget and tee-attestation-js.
  // Copyright (c) 2025 Distrust LLC. Licensed under the MIT License:
  // https://git.distrust.co/public/attestation-widget
  // CBOR/COSE and Nitro certificate verification run locally with WebCrypto.
  // This is deliberately separate from canaryctl's independently supplied
  // expected-PCR policy verification.
  const NITRO_ROOT_CERT = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

  function browserBytesToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function browserBytesToBase64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  function browserBase64ToBytes(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  function browserArraysEqual(left, right) {
    return left.length === right.length && left.every((value, index) => value === right[index]);
  }

  function browserDecodeCbor(bytes) {
    let offset = 0;
    const decoder = new TextDecoder();
    const readLength = (additional) => {
      if (additional < 24) return additional;
      if (additional === 24) return bytes[offset++];
      if (additional === 25) return (bytes[offset++] << 8) | bytes[offset++];
      if (additional === 26) return ((bytes[offset++] << 24) >>> 0) + (bytes[offset++] << 16) + (bytes[offset++] << 8) + bytes[offset++];
      if (additional === 27) {
        let value = 0;
        for (let i = 0; i < 8; i += 1) value = (value * 256) + bytes[offset++];
        return value;
      }
      if (additional === 31) return -1;
      throw new Error("Unsupported CBOR length");
    };
    const read = () => {
      if (offset >= bytes.length) throw new Error("Truncated CBOR input");
      const initial = bytes[offset++];
      const type = initial >> 5;
      const length = readLength(initial & 31);
      if (type === 0) return length;
      if (type === 1) return -1 - length;
      if (type === 2) {
        if (length < 0) throw new Error("Indefinite byte strings are unsupported");
        const value = bytes.slice(offset, offset + length);
        offset += length;
        return value;
      }
      if (type === 3) {
        if (length < 0) throw new Error("Indefinite text strings are unsupported");
        const value = decoder.decode(bytes.slice(offset, offset + length));
        offset += length;
        return value;
      }
      if (type === 4) {
        const value = [];
        if (length < 0) {
          while (bytes[offset] !== 255) value.push(read());
          offset += 1;
        } else {
          for (let i = 0; i < length; i += 1) value.push(read());
        }
        return value;
      }
      if (type === 5) {
        const value = Object.create(null);
        const pairs = length < 0 ? Infinity : length;
        for (let i = 0; i < pairs; i += 1) {
          if (length < 0 && bytes[offset] === 255) {
            offset += 1;
            break;
          }
          value[read()] = read();
        }
        return value;
      }
      if (type === 6) return read();
      if (type === 7 && (initial & 31) === 20) return false;
      if (type === 7 && (initial & 31) === 21) return true;
      if (type === 7 && (initial & 31) === 22) return null;
      throw new Error("Unsupported CBOR value");
    };
    const value = read();
    if (offset !== bytes.length) throw new Error("Unexpected trailing CBOR data");
    return value;
  }

  function browserEncodeCbor(value) {
    const chunks = [];
    const pushLength = (type, length) => {
      if (length < 24) chunks.push(Uint8Array.of((type << 5) | length));
      else if (length < 256) chunks.push(Uint8Array.of((type << 5) | 24, length));
      else if (length < 65_536) chunks.push(Uint8Array.of((type << 5) | 25, length >> 8, length & 255));
      else throw new Error("CBOR value is too large");
    };
    const push = (item) => {
      if (typeof item === "string") {
        const bytes = new TextEncoder().encode(item);
        pushLength(3, bytes.length);
        chunks.push(bytes);
      } else if (item instanceof Uint8Array) {
        pushLength(2, item.length);
        chunks.push(item);
      } else if (Array.isArray(item)) {
        pushLength(4, item.length);
        item.forEach(push);
      } else {
        throw new Error("Unsupported CBOR signing value");
      }
    };
    push(value);
    const size = chunks.reduce((total, chunk) => total + chunk.length, 0);
    const output = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      output.set(chunk, offset);
      offset += chunk.length;
    }
    return output;
  }

  function browserParseCertificate(der) {
    let offset = 0;
    const readByte = () => der[offset++];
    const readLength = () => {
      const first = readByte();
      if (first < 128) return first;
      const bytes = first & 127;
      let length = 0;
      for (let i = 0; i < bytes; i += 1) length = (length << 8) | readByte();
      return length;
    };
    const expectTag = (tag) => {
      if (readByte() !== tag) throw new Error("Invalid DER certificate");
      return readLength();
    };
    const skip = () => {
      readByte();
      const length = readLength();
      offset += length;
    };
    expectTag(48);
    const tbsStart = offset;
    const tbsLength = expectTag(48);
    const tbsEnd = offset + tbsLength;
    const tbsCertificate = der.slice(tbsStart, tbsEnd);
    if (der[offset] === 160) {
      offset += 1;
      const versionLength = readLength();
      offset += versionLength;
    }
    skip(); // serial number
    skip(); // signature algorithm
    skip(); // issuer
    const validityLength = expectTag(48);
    const validityEnd = offset + validityLength;
    readByte();
    const notBeforeLength = readLength();
    const notBefore = new TextDecoder().decode(der.slice(offset, offset + notBeforeLength));
    offset += notBeforeLength;
    readByte();
    const notAfterLength = readLength();
    const notAfter = new TextDecoder().decode(der.slice(offset, offset + notAfterLength));
    offset += notAfterLength;
    offset = validityEnd;
    skip(); // subject
    const publicKeyStart = offset;
    const publicKeyLength = expectTag(48);
    const publicKeyRaw = der.slice(publicKeyStart, offset + publicKeyLength);
    offset = tbsEnd;
    skip(); // signature algorithm
    if (readByte() !== 3) throw new Error("Invalid DER certificate signature");
    const signatureLength = readLength();
    if (readByte() !== 0) throw new Error("Invalid DER certificate signature");
    const signature = der.slice(offset, offset + signatureLength - 1);
    return { tbsCertificate, signature, publicKeyRaw, notBefore, notAfter };
  }

  function browserParseAsn1Time(value) {
    const raw = value.replace("Z", "");
    const year = raw.length === 12 ? (Number(raw.slice(0, 2)) >= 50 ? 1900 : 2000) + Number(raw.slice(0, 2)) : Number(raw.slice(0, 4));
    const base = raw.length === 12 ? 2 : 4;
    return Date.UTC(year, Number(raw.slice(base, base + 2)) - 1, Number(raw.slice(base + 2, base + 4)), Number(raw.slice(base + 4, base + 6)), Number(raw.slice(base + 6, base + 8)), Number(raw.slice(base + 8, base + 10)));
  }

  function browserEcdsaDerToRaw(der) {
    let offset = 0;
    if (der[offset++] !== 48) throw new Error("Invalid ECDSA certificate signature");
    let sequenceLength = der[offset++];
    if (sequenceLength & 128) offset += sequenceLength & 127;
    if (der[offset++] !== 2) throw new Error("Invalid ECDSA certificate signature");
    let rLength = der[offset++];
    let rStart = offset;
    if (der[rStart] === 0) {
      rStart += 1;
      rLength -= 1;
    }
    const r = der.slice(rStart, rStart + rLength);
    offset = rStart + rLength;
    if (der[offset++] !== 2) throw new Error("Invalid ECDSA certificate signature");
    let sLength = der[offset++];
    let sStart = offset;
    if (der[sStart] === 0) {
      sStart += 1;
      sLength -= 1;
    }
    const s = der.slice(sStart, sStart + sLength);
    const raw = new Uint8Array(96);
    raw.set(r, 48 - r.length);
    raw.set(s, 96 - s.length);
    return raw;
  }

  function browserPemToDer(pem) {
    return browserBase64ToBytes(pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, ""));
  }

  async function browserVerifyCertificateChain(certificates) {
    if (!Array.isArray(certificates) || certificates.length === 0) throw new Error("Missing AWS Nitro certificate bundle");
    let parentKey = browserParseCertificate(browserPemToDer(NITRO_ROOT_CERT)).publicKeyRaw;
    const now = Date.now();
    for (const certificateDer of certificates) {
      const certificate = browserParseCertificate(certificateDer);
      if (now < browserParseAsn1Time(certificate.notBefore) || now > browserParseAsn1Time(certificate.notAfter)) throw new Error("AWS Nitro certificate is outside its validity period");
      const key = await crypto.subtle.importKey("spki", parentKey, { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
      const verified = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, browserEcdsaDerToRaw(certificate.signature), certificate.tbsCertificate);
      if (!verified) throw new Error("AWS Nitro certificate-chain verification failed");
      parentKey = certificate.publicKeyRaw;
    }
  }

  async function browserVerifyNitro(document, nonce) {
    const cose = browserDecodeCbor(document);
    if (!Array.isArray(cose) || cose.length !== 4) throw new Error("Invalid COSE Sign1 attestation document");
    const [protectedHeader, , payloadBytes, signature] = cose;
    if (!(protectedHeader instanceof Uint8Array)
      || !(payloadBytes instanceof Uint8Array)
      || !(signature instanceof Uint8Array)) {
      throw new Error("Invalid COSE Sign1 field types");
    }
    const protectedValues = browserDecodeCbor(protectedHeader);
    if (protectedValues?.[1] !== -35) throw new Error("Attestation does not use COSE ES384");
    const payload = browserDecodeCbor(payloadBytes);
    if (!payload?.certificate) throw new Error("Attestation document has no signing certificate");
    await browserVerifyCertificateChain([...(payload.cabundle || []), payload.certificate]);
    const leaf = browserParseCertificate(payload.certificate);
    const key = await crypto.subtle.importKey("spki", leaf.publicKeyRaw, { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
    const signed = browserEncodeCbor(["Signature1", protectedHeader, new Uint8Array(0), payloadBytes]);
    const verified = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, signature, signed);
    if (!verified) throw new Error("COSE attestation signature verification failed");
    if (!(payload.nonce instanceof Uint8Array) || !browserArraysEqual(payload.nonce, nonce)) throw new Error("Browser challenge nonce did not match the attestation document");
    const pcrs = {};
    for (const index of [0, 1, 2]) {
      const value = payload.pcrs?.[index];
      if (!(value instanceof Uint8Array) || value.length !== 48) {
        throw new Error(`Attestation PCR${index} is missing or is not SHA-384 sized`);
      }
      if (value.every((byte) => byte === 0)) {
        throw new Error(`Attestation PCR${index} is all-zero/debug`);
      }
      pcrs[`PCR${index}`] = browserBytesToHex(value);
    }
    return pcrs;
  }

  function setBrowserAttestationState(container, state, summary, pcrs) {
    container.dataset.browserAttestationState = state;
    container.querySelector("[data-browser-attestation-status]").textContent = state === "checked" ? "EVIDENCE CHECKED" : state === "failed" ? "FAILED" : state === "checking" ? "CHECKING" : "NOT RUN";
    container.querySelector("[data-browser-attestation-summary]").textContent = summary;
    const runButton = container.querySelector("[data-browser-attestation-run]");
    if (runButton) runButton.disabled = state === "checking";
    const pcrContainer = container.querySelector("[data-browser-attestation-pcrs]");
    if (!pcrs) {
      pcrContainer.hidden = true;
      return;
    }
    for (const name of ["PCR0", "PCR1", "PCR2"]) {
      const output = pcrContainer.querySelector(`[data-browser-pcr="${name}"]`);
      if (output) output.textContent = pcrs[name] || "Not present";
    }
    pcrContainer.hidden = false;
  }

  let browserAttestationGeneration = 0;

  async function verifyBrowserAttestation(container) {
    const generation = ++browserAttestationGeneration;
    if (!window.isSecureContext || !window.crypto?.subtle) {
      setBrowserAttestationState(container, "failed", "This browser cannot run WebCrypto attestation verification in the current context.");
      return;
    }
    setBrowserAttestationState(container, "checking", "Generating a fresh browser challenge and requesting Canary’s Nitro attestation…");
    try {
      const nonce = crypto.getRandomValues(new Uint8Array(32));
      const response = await fetch("/attestation", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        cache: "no-store",
        body: JSON.stringify({ nonce: browserBytesToBase64(nonce) }),
      });
      if (!response.ok) throw new Error(`/attestation returned ${response.status}`);
      const body = await response.json();
      if (typeof body?.document !== "string") throw new Error("The attestation response contained no document");
      const pcrs = await browserVerifyNitro(browserBase64ToBytes(body.document), nonce);
      if (generation !== browserAttestationGeneration) return;
      setBrowserAttestationState(container, "checked", "This browser checked certificate signatures to the pinned AWS Nitro root, certificate dates, the COSE ES384 signature, and its fresh challenge nonce. Expected Canary PCR policy was not checked.", pcrs);
    } catch (error) {
      if (generation !== browserAttestationGeneration) return;
      const message = error instanceof Error ? error.message : "Browser evidence check failed";
      setBrowserAttestationState(container, "failed", `Browser evidence check failed: ${message}`);
    }
  }

  const browserAttestation = document.querySelector("[data-browser-attestation]");
  if (browserAttestation) {
    browserAttestation.querySelector("[data-browser-attestation-run]")?.addEventListener("click", () => verifyBrowserAttestation(browserAttestation));
  }

  const dialog = document.querySelector("#target-inspector");
  if (!(dialog instanceof HTMLDialogElement)) return;

  const panels = new Map(
    [...dialog.querySelectorAll("[data-panel]")].map((panel) => [panel.dataset.panel, panel]),
  );
  const tabs = [...dialog.querySelectorAll("[data-tab]")];
  const isNitroEnclave = document.body.dataset.runtimeEnvironment === "nitro_enclave";
  const HISTORY_PAGE_SIZE = 25;
  const byId = (id) => document.getElementById(id);
  let currentDeployment = null;
  let historyOffset = 0;
  let loadGeneration = 0;

  function deploymentPath(kind) {
    return `/targets/${encodeURIComponent(currentDeployment.id)}/${kind}`;
  }

  function saveKeysCommand() {
    if (!isNitroEnclave) {
      const allowHttp = window.location.protocol === "http:" ? " --allow-http" : "";
      return `# Saves observed TOFU keys; Canary attestation is skipped.\ncanaryctl save-canary-keys --canary-url ${window.location.origin} --skip-canary-attestation${allowHttp} --output canary-keys.json`;
    }
    return `caution verify --save-pcrs\n\n# Verifies fresh Canary attestation + expected PCR0/1/2, then saves the authenticated keys.\ncanaryctl save-canary-keys --canary-url ${window.location.origin} --expected-pcrs .caution/trusted_hashes.json --output canary-keys.json`;
  }

  function verificationCommand(targetId, attemptId) {
    const command = attemptId ? "verify-attempt" : "verify";
    const target = targetId ? ` \\\n  --target ${targetId}` : "";
    const attempt = attemptId ? ` \\\n  --attempt ${attemptId}` : "";
    const trust = isNitroEnclave
      ? "--expected-pcrs .caution/trusted_hashes.json"
      : `--skip-canary-attestation${window.location.protocol === "http:" ? " --allow-http" : ""}`;
    return `canaryctl ${command} \\\n  --canary-url ${window.location.origin} \\\n  ${trust}${target}${attempt}`;
  }

  function certificateCommand(origin) {
    const target = new URL(origin);
    const hostname = target.hostname;
    return `openssl s_client \\\n  -connect ${hostname}:${target.port || "443"} \\\n  -servername ${hostname} \\\n  -verify_return_error </dev/null 2>/dev/null |\nopenssl x509 -outform DER |\nshasum -a 256`;
  }

  function setCommand(element, deploymentId) {
    if (element) element.textContent = verificationCommand(deploymentId);
  }

  function renderCaddyBinding() {
    const panel = dialog.querySelector("[data-caddy-binding]");
    const isCaddy = currentDeployment.profile === "caddy";
    panel.hidden = !isCaddy;
    if (!isCaddy) return;

    const evaluated = currentDeployment.reason === "ALL_CHECKS_PASSED"
      || currentDeployment.reason === "TLS_BINDING_MISMATCH";
    panel.dataset.state = currentDeployment.status === "VERIFIED"
      ? "verified"
      : evaluated ? "failed" : "idle";
    panel.querySelector("[data-caddy-status]").textContent = currentDeployment.status === "VERIFIED"
      ? "BOUND"
      : evaluated ? "MISMATCH" : "NOT EVALUATED";
    panel.querySelector("[data-caddy-mode]").textContent = currentDeployment.tlsMode || "Unavailable";
    panel.querySelector("[data-caddy-domain]").textContent = currentDeployment.tlsDomain || "Unavailable";
    panel.querySelector("[data-caddy-attested-certfp]").textContent = currentDeployment.tlsAttestedCertfp || "Unavailable";
    panel.querySelector("[data-caddy-observed-certfp]").textContent = currentDeployment.tlsObservedCertfp || "Unavailable";
    byId("caddy-certificate-command").textContent = certificateCommand(currentDeployment.origin);
  }

  function setActiveTab(name) {
    for (const tab of tabs) {
      const active = tab.dataset.tab === name;
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
    }
    for (const [panelName, panel] of panels) panel.hidden = panelName !== name;
    if (name === "history") loadHistory();
  }

  function setHistoryState(message, state = "loading") {
    const output = panels.get("history")?.querySelector("[data-artifact-output]");
    if (!output) return;
    output.dataset.state = state;
    output.textContent = message;
  }

  async function requestJson(path) {
    const response = await fetch(path, {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const text = await response.text();
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      throw new Error(`The endpoint returned non-JSON data (${response.status}).`);
    }
    if (!response.ok) throw new Error(`The endpoint returned ${response.status}: ${value?.error || "request_failed"}.`);
    return value;
  }

  function setEvidenceClaimsState(state, status, summary) {
    const panel = dialog.querySelector("[data-evidence-claims]");
    if (!panel) return;
    panel.dataset.state = state;
    panel.querySelector("[data-evidence-claims-status]").textContent = status;
    panel.querySelector("[data-evidence-claims-summary]").textContent = summary;
    if (state !== "verified") {
      panel.querySelector("[data-evidence-claims-table]").hidden = true;
    }
  }

  function renderEvidenceClaims(value) {
    const authenticated = value?.authentication?.status === "verified"
      && value?.authentication?.nonce_status === "verified";
    if (!authenticated || !value?.observed_pcrs || !value?.expected_pcrs || !value?.pcr_matches) {
      setEvidenceClaimsState(
        "unavailable",
        "NOT AUTHENTICATED",
        "Raw evidence exists, but Canary retained no PCR values authenticated by the AWS chain, COSE signature, and probe nonce.",
      );
      return;
    }

    const panel = dialog.querySelector("[data-evidence-claims]");
    for (const row of panel.querySelectorAll("[data-evidence-pcr]")) {
      const index = row.dataset.evidencePcr;
      row.querySelector("[data-pcr-observed]").textContent = value.observed_pcrs[index] || "Not present";
      row.querySelector("[data-pcr-expected]").textContent = value.expected_pcrs[index] || "Not configured";
      const matched = value.pcr_matches[index] === true;
      const match = row.querySelector("[data-pcr-match]");
      match.dataset.match = String(matched);
      match.textContent = matched ? "MATCH" : "MISMATCH";
    }
    panel.querySelector("[data-evidence-claims-table]").hidden = false;
    setEvidenceClaimsState(
      "verified",
      "AUTHENTICATED",
      "Observed PCRs came from evidence whose AWS certificate chain, COSE signature, and fresh probe nonce Canary verified. Expected values are the configured policy.",
    );
  }

  async function loadEvidenceClaims() {
    const generation = loadGeneration;
    setEvidenceClaimsState("loading", "LOADING", "Loading authenticated measurements…");
    try {
      const value = await requestJson(deploymentPath("evidence/claims"));
      if (generation !== loadGeneration) return;
      renderEvidenceClaims(value);
    } catch (error) {
      if (generation !== loadGeneration) return;
      setEvidenceClaimsState(
        "error",
        "UNAVAILABLE",
        error instanceof Error ? error.message : "Unable to load authenticated measurements.",
      );
    }
  }

  function appendCell(row, value, className) {
    const cell = document.createElement("td");
    if (className) cell.className = className;
    cell.textContent = value ?? "—";
    row.append(cell);
  }

  function appendHistoryPagination(output, offset, count, hasOlder) {
    if (offset === 0 && !hasOlder) return;
    const pagination = document.createElement("div");
    pagination.className = "history-pagination";

    const summary = document.createElement("span");
    summary.textContent = count === 0
      ? "No attempts on this page"
      : `Attempts ${offset + 1}–${offset + count} · newest first`;
    pagination.append(summary);

    const actions = document.createElement("div");
    const newer = document.createElement("button");
    newer.className = "history-page-button";
    newer.type = "button";
    newer.dataset.historyOffset = String(Math.max(0, offset - HISTORY_PAGE_SIZE));
    newer.textContent = "Newer";
    newer.disabled = offset === 0;
    actions.append(newer);

    const older = document.createElement("button");
    older.className = "history-page-button";
    older.type = "button";
    older.dataset.historyOffset = String(offset + HISTORY_PAGE_SIZE);
    older.textContent = "Older";
    older.disabled = !hasOlder;
    actions.append(older);

    pagination.append(actions);
    output.append(pagination);
  }

  function renderHistory(value, offset) {
    const output = panels.get("history")?.querySelector("[data-artifact-output]");
    if (!output) return;
    output.dataset.state = "ready";
    output.replaceChildren();
    const returned = Array.isArray(value?.observations) ? value.observations : [];
    const hasOlder = returned.length > HISTORY_PAGE_SIZE;
    const observations = returned.slice(0, HISTORY_PAGE_SIZE);
    if (observations.length === 0) {
      const message = document.createElement("p");
      message.className = "history-empty";
      message.textContent = offset === 0
        ? "No completed probe attempts are recorded for this process lifetime."
        : "No retained attempts remain on this page.";
      output.append(message);
      appendHistoryPagination(output, offset, 0, false);
      return;
    }

    const table = document.createElement("table");
    const head = document.createElement("thead");
    const headerRow = document.createElement("tr");
    for (const label of ["Attempted", "State", "Result", "Latency", "Verify"]) {
      const th = document.createElement("th");
      th.scope = "col";
      th.textContent = label;
      headerRow.append(th);
    }
    head.append(headerRow);
    table.append(head);

    const body = document.createElement("tbody");
    for (const observation of observations) {
      const row = document.createElement("tr");
      appendCell(row, observation.attempted_at);
      appendCell(row, observation.status, `history-status history-status-${String(observation.status || "").toLowerCase()}`);
      appendCell(row, observation.attempt_reason);
      appendCell(row, observation.latency_ms == null ? "—" : `${observation.latency_ms} ms`);
      const actions = document.createElement("td");
      actions.className = "history-actions";
      const copy = document.createElement("button");
      copy.className = "copy-button";
      copy.type = "button";
      copy.dataset.copyText = verificationCommand(currentDeployment.id, observation.id);
      copy.textContent = "Copy CLI";
      actions.append(copy);
      if (observation.evidence_digest) {
        const inspect = document.createElement("button");
        inspect.className = "copy-button";
        inspect.type = "button";
        inspect.dataset.historyClaimsAttempt = observation.id;
        inspect.textContent = "PCRs";
        actions.append(inspect);
      }
      row.append(actions);
      body.append(row);
    }
    table.append(body);
    output.append(table);
    appendHistoryPagination(output, offset, observations.length, hasOlder);
  }

  function appendHistoryPcrCell(row, value, className) {
    const cell = document.createElement("td");
    if (className) cell.className = className;
    cell.textContent = value;
    row.append(cell);
  }

  function renderHistoricalClaims(detailRow, value) {
    const cell = detailRow.firstElementChild;
    cell.replaceChildren();
    if (!value?.observed_pcrs || !value?.expected_pcrs || !value?.pcr_matches) {
      cell.textContent = "This attempt has raw evidence but no PCR values authenticated by its AWS chain, COSE signature, and nonce.";
      return;
    }

    const table = document.createElement("table");
    table.className = "pcr-table history-pcr-table";
    const head = document.createElement("thead");
    const header = document.createElement("tr");
    for (const label of ["PCR", "Meaning", "Observed", "Expected", "Match"]) {
      const th = document.createElement("th");
      th.scope = "col";
      th.textContent = label;
      header.append(th);
    }
    head.append(header);
    table.append(head);
    const body = document.createElement("tbody");
    const meanings = ["Enclave image", "Kernel + bootstrap", "Application"];
    for (const index of ["0", "1", "2"]) {
      const row = document.createElement("tr");
      appendHistoryPcrCell(row, `PCR${index}`);
      appendHistoryPcrCell(row, meanings[Number(index)]);
      appendHistoryPcrCell(row, value.observed_pcrs[index]);
      appendHistoryPcrCell(row, value.expected_pcrs[index]);
      const matched = value.pcr_matches[index] === true;
      appendHistoryPcrCell(
        row,
        matched ? "MATCH" : "MISMATCH",
        `pcr-match pcr-match--${matched}`,
      );
      body.append(row);
    }
    table.append(body);
    cell.append(table);
  }

  async function toggleHistoricalClaims(button) {
    const attemptId = button.dataset.historyClaimsAttempt;
    const sourceRow = button.closest("tr");
    const existing = sourceRow?.nextElementSibling;
    if (existing?.dataset.historyClaimsFor === attemptId) {
      existing.remove();
      button.textContent = "PCRs";
      return;
    }

    const detailRow = document.createElement("tr");
    detailRow.className = "history-claims-row";
    detailRow.dataset.historyClaimsFor = attemptId;
    const detailCell = document.createElement("td");
    detailCell.colSpan = 5;
    detailCell.textContent = "Loading authenticated PCR claims…";
    detailRow.append(detailCell);
    sourceRow.after(detailRow);
    button.disabled = true;
    const generation = loadGeneration;
    try {
      const value = await requestJson(
        deploymentPath(`history/${attemptId}/evidence/claims`),
      );
      if (generation !== loadGeneration || !detailRow.isConnected) return;
      renderHistoricalClaims(detailRow, value);
      button.textContent = "Hide PCRs";
    } catch (error) {
      if (generation !== loadGeneration || !detailRow.isConnected) return;
      detailCell.textContent = error instanceof Error ? error.message : "Unable to load historical PCR claims.";
    } finally {
      button.disabled = false;
    }
  }

  async function loadHistory(offset = historyOffset, force = false) {
    const panel = panels.get("history");
    if (!panel || (!force && panel.dataset.loaded === "true") || !currentDeployment) return;
    const generation = loadGeneration;
    panel.dataset.loaded = "loading";
    setHistoryState("Loading history…");
    try {
      const value = await requestJson(
        deploymentPath(`history?offset=${offset}&limit=${HISTORY_PAGE_SIZE + 1}`),
      );
      if (generation !== loadGeneration) return;
      historyOffset = offset;
      renderHistory(value, offset);
      panel.dataset.loaded = "true";
    } catch (error) {
      if (generation !== loadGeneration) return;
      panel.dataset.loaded = "false";
      setHistoryState(error instanceof Error ? error.message : "Unable to load history.", "error");
    }
  }

  function setLink(id, kind) {
    const link = byId(id);
    if (link) link.href = deploymentPath(kind);
  }

  function openDeployment(card) {
    loadGeneration += 1;
    historyOffset = 0;
    currentDeployment = {
      id: card.dataset.targetId,
      name: card.dataset.targetName,
      origin: card.dataset.targetOrigin,
      status: card.dataset.targetStatus,
      reason: card.dataset.targetReason,
      observed: card.dataset.targetObserved || "—",
      expires: card.dataset.targetExpires,
      warning: card.dataset.targetWarning || "None",
      profile: card.dataset.targetProfile || "",
      tlsMode: card.dataset.tlsMode || "",
      tlsDomain: card.dataset.tlsDomain || "",
      tlsAttestedCertfp: card.dataset.tlsAttestedCertfp || "",
      tlsObservedCertfp: card.dataset.tlsObservedCertfp || "",
    };

    byId("inspector-kicker").textContent = currentDeployment.id;
    byId("inspector-title").textContent = currentDeployment.name;
    byId("inspector-status").textContent = currentDeployment.status;
    byId("inspector-status").className = `status-badge status-${currentDeployment.status.toLowerCase()}`;
    byId("inspector-origin").textContent = currentDeployment.origin;
    byId("inspector-reason").textContent = currentDeployment.reason;
    byId("inspector-observed").textContent = currentDeployment.observed;
    byId("inspector-expires").textContent = currentDeployment.expires;
    byId("inspector-warning").textContent = currentDeployment.warning;
    renderCaddyBinding();
    setCommand(byId("deployment-command"), currentDeployment.id);
    setLink("statement-json-link", "statement");
    setLink("evidence-json-link", "evidence");
    setLink("evidence-claims-json-link", "evidence/claims");
    setLink("history-json-link", "history");

    for (const [name, panel] of panels) {
      panel.dataset.loaded = name === "overview" ? "true" : "false";
      if (name === "history") setHistoryState("Select this view to load recorded attempts.", "idle");
    }
    setActiveTab("overview");
    dialog.showModal();
    loadEvidenceClaims();
    history.replaceState(null, "", `#deployment-${encodeURIComponent(currentDeployment.id)}`);
  }

  async function copyText(button) {
    const selector = button.dataset.copy;
    const source = selector ? document.querySelector(selector) : null;
    const text = button.dataset.copyText || source?.textContent;
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.append(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    const original = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = original; }, 1400);
  }

  document.addEventListener("click", (event) => {
    const openButton = event.target.closest("[data-open-target]");
    if (openButton) {
      const card = openButton.closest("[data-target-id]");
      if (card) openDeployment(card);
      return;
    }
    const tab = event.target.closest("[data-tab]");
    if (tab) {
      setActiveTab(tab.dataset.tab);
      return;
    }
    const historyClaimsButton = event.target.closest("[data-history-claims-attempt]");
    if (historyClaimsButton) {
      toggleHistoricalClaims(historyClaimsButton);
      return;
    }
    const historyPageButton = event.target.closest("[data-history-offset]");
    if (historyPageButton && !historyPageButton.disabled) {
      const offset = Number(historyPageButton.dataset.historyOffset);
      if (Number.isSafeInteger(offset) && offset >= 0) loadHistory(offset, true);
      return;
    }
    const copyButton = event.target.closest("[data-copy], [data-copy-text]");
    if (copyButton) copyText(copyButton);
  });

  dialog.querySelector("[data-close]")?.addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  dialog.addEventListener("close", () => {
    currentDeployment = null;
    loadGeneration += 1;
    history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  });

  for (const tab of tabs) {
    tab.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
      event.preventDefault();
      const offset = event.key === "ArrowRight" ? 1 : -1;
      const next = tabs[(tabs.indexOf(tab) + offset + tabs.length) % tabs.length];
      next.focus();
      setActiveTab(next.dataset.tab);
    });
  }

  const saveKeys = document.querySelector("#save-keys-command");
  if (saveKeys) saveKeys.textContent = saveKeysCommand();
  setCommand(document.querySelector("#all-targets-command"), null);

  let hashDeployment = "";
  try {
    hashDeployment = decodeURIComponent(window.location.hash.replace(/^#deployment-/, ""));
  } catch {
    hashDeployment = "";
  }
  if (hashDeployment && window.location.hash.startsWith("#deployment-")) {
    const card = [...document.querySelectorAll("[data-target-id]")]
      .find((candidate) => candidate.dataset.targetId === hashDeployment);
    if (card) openDeployment(card);
  }
})();
