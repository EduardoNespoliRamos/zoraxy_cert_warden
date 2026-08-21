const API = {
    status: './api/status',
    certificates: './api/certificates'
};

const POLL_INTERVAL_MS = 10000;
const modalActionButtons = ['btn-save', 'btn-validate', 'btn-sync-now', 'btn-delete'];
let currentCertName = null;
let modalOperationInFlight = false;
let statusRequest = null;
let statusRequestSequence = 0;
let statusTimer = null;
const syncingCertificates = new Set();

function getCsrfToken() {
    const meta = document.querySelector('meta[name="zoraxy.csrf.Token"]');
    return meta ? meta.getAttribute('content') : '';
}

async function fetchJSON(url, options = {}) {
    const requestOptions = { ...options, headers: { ...(options.headers || {}) } };
    const needsToken = ['POST', 'PUT', 'DELETE', 'PATCH'].includes((requestOptions.method || 'GET').toUpperCase());
    if (needsToken) {
        requestOptions.headers['X-CSRF-Token'] = getCsrfToken();
    }
    const response = await fetch(url, requestOptions);
    if (!response.ok) {
        const body = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(body.error || `HTTP ${response.status}`);
    }
    return response.json();
}

function formatDate(iso) {
    if (!iso) return 'Never';
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? 'N/A' : date.toLocaleString();
}

function formatFP(fingerprint) {
    if (!fingerprint) return 'N/A';
    return `${String(fingerprint).substring(0, 16)}...`;
}

function statusClass(status) {
    const normalized = String(status || '').toLowerCase();
    return ['healthy', 'error', 'unknown', 'disabled'].includes(normalized)
        ? `status-${normalized}`
        : 'status-unknown';
}

function appendParagraph(parent, text, className) {
    const paragraph = document.createElement('p');
    paragraph.textContent = text;
    if (className) paragraph.className = className;
    parent.appendChild(paragraph);
    return paragraph;
}

function renderOverview(data) {
    const container = document.getElementById('overview-content');
    const statusLine = document.createElement('p');
    const status = document.createElement('span');
    status.className = statusClass(data.status);
    status.textContent = data.status || 'Unknown';
    statusLine.append('Status: ', status);

    const counts = `Healthy: ${data.healthy} | Errors: ${data.errors} | Unknown: ${data.unknown} | Disabled: ${data.disabled || 0}`;
    container.replaceChildren(statusLine);
    appendParagraph(container, `Configured certificates: ${data.certificates}`);
    appendParagraph(container, counts);
}

function createActionButton(label, className, certName, action) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = className;
    button.textContent = label;
    button.dataset.certName = certName;
    button.dataset.action = action;
    button.disabled = action === 'sync' && syncingCertificates.has(certName);
    button.addEventListener('click', event => {
        const target = event.currentTarget;
        if (target.dataset.action === 'edit') {
            editCert(target.dataset.certName);
        } else {
            syncCert(target.dataset.certName);
        }
    });
    return button;
}

function renderCertificates(items) {
    const container = document.getElementById('cert-list');
    if (!Array.isArray(items) || items.length === 0) {
        const empty = document.createElement('p');
        empty.textContent = 'No certificates configured.';
        container.replaceChildren(empty);
        return;
    }

    const fragment = document.createDocumentFragment();
    items.forEach(item => {
        const card = document.createElement('div');
        card.className = 'cert-card';
        card.dataset.certName = item.name;

        const heading = document.createElement('h3');
        const status = document.createElement('span');
        status.className = statusClass(item.status);
        status.textContent = item.status || 'Unknown';
        heading.append(document.createTextNode(`${item.name} `), status);
        card.appendChild(heading);

        const metadata = document.createElement('div');
        metadata.className = 'cert-meta';
        appendParagraph(metadata, item.common_name || 'No certificate loaded');
        appendParagraph(metadata, `Issuer: ${item.issuer || 'N/A'}`);
        appendParagraph(metadata, `Expires: ${item.expires ? formatDate(item.expires) : 'N/A'} (${item.days_remaining} days remaining)`);
        appendParagraph(metadata, `Last sync: ${formatDate(item.last_successful_sync)}`);
        appendParagraph(metadata, `Source fingerprint: ${formatFP(item.source_fingerprint)}`);
        appendParagraph(metadata, `Certificate / key match: ${item.key_match ? 'Yes' : 'No'}`);
        appendParagraph(metadata, `Enabled: ${item.enabled ? 'Yes' : 'No'}`);
        appendParagraph(metadata, `Auto Sync: ${item.auto_sync ? 'Enabled' : 'Disabled'}`);
        if (item.fallback) {
            const fallback = appendParagraph(metadata, 'Fallback: Enabled');
            if (item.fallback_pending_restart) {
                const warning = document.createElement('span');
                warning.className = 'status-error';
                warning.textContent = ' (restart Zoraxy to activate)';
                fallback.appendChild(warning);
            }
        }
        if (item.status === 'Error') appendParagraph(metadata, item.message || 'Unknown error', 'error-message');
        card.appendChild(metadata);

        const actions = document.createElement('div');
        actions.className = 'cert-actions';
        actions.append(
            createActionButton('Edit', 'btn btn-primary', item.name, 'edit'),
            createActionButton('Sync Now', 'btn', item.name, 'sync')
        );
        card.appendChild(actions);
        fragment.appendChild(card);
    });
    container.replaceChildren(fragment);
}

function showStatusError(message) {
    const error = document.getElementById('status-error');
    error.textContent = `Unable to refresh status: ${message}`;
    error.classList.remove('hidden');
}

function clearStatusError() {
    const error = document.getElementById('status-error');
    error.textContent = '';
    error.classList.add('hidden');
}

async function loadStatus(options = {}) {
    if (statusRequest) {
        if (!options.abortPrevious) return statusRequest.promise;
        statusRequest.controller.abort();
    }

    const controller = new AbortController();
    const sequence = ++statusRequestSequence;
    document.getElementById('btn-refresh').disabled = true;
    const promise = (async () => {
        try {
            const data = await fetchJSON(API.status, { signal: controller.signal });
            if (sequence !== statusRequestSequence) return;
            renderOverview(data);
            renderCertificates(data.items);
            clearStatusError();
        } catch (error) {
            if (error.name !== 'AbortError' && sequence === statusRequestSequence) showStatusError(error.message);
        } finally {
            if (statusRequest && statusRequest.sequence === sequence) {
                statusRequest = null;
                document.getElementById('btn-refresh').disabled = false;
            }
        }
    })();
    statusRequest = { controller, promise, sequence };
    return promise;
}

function setModalBusy(busy) {
    modalOperationInFlight = busy;
    modalActionButtons.forEach(id => {
        document.getElementById(id).disabled = busy;
    });
}

function openModal(cert) {
    currentCertName = cert ? cert.name : null;
    document.getElementById('modal-title').textContent = cert ? 'Edit Certificate' : 'Add Certificate';
    document.getElementById('cert-original-name').value = cert ? cert.name : '';
    const nameInput = document.getElementById('cert-name');
    nameInput.value = cert ? cert.name : '';
    nameInput.readOnly = Boolean(cert);
    document.getElementById('cert-enabled').checked = cert ? cert.enabled : true;
    document.getElementById('cert-source-cert').value = cert ? cert.source.certificate : '/cert_warden_plugin/certchain0.pem';
    document.getElementById('cert-source-key').value = cert ? cert.source.private_key : '/cert_warden_plugin/key0.pem';
    document.getElementById('cert-target-dir').value = cert ? cert.destination.target_directory : '/opt/zoraxy/config/conf/certs';
    document.getElementById('cert-target-name').value = cert ? cert.destination.target_name : '';
    document.getElementById('cert-auto-sync').checked = cert ? cert.sync.auto_sync : true;
    document.getElementById('cert-filesystem-watch').checked = cert ? cert.sync.filesystem_watch : true;
    document.getElementById('cert-poll-interval').value = cert ? cert.sync.poll_interval_seconds : 10;
    document.getElementById('cert-fallback').checked = cert ? cert.fallback : false;
    document.getElementById('btn-delete').style.display = cert ? 'inline-block' : 'none';
    document.getElementById('btn-validate').style.display = cert ? 'inline-block' : 'none';
    document.getElementById('btn-sync-now').style.display = cert ? 'inline-block' : 'none';
    document.getElementById('modal-message').classList.add('hidden');
    setModalBusy(false);
    document.getElementById('modal').classList.remove('hidden');
}

function closeModal() {
    if (modalOperationInFlight) return;
    document.getElementById('modal').classList.add('hidden');
    currentCertName = null;
}

function getFormCert() {
    return {
        name: document.getElementById('cert-name').value.trim(),
        enabled: document.getElementById('cert-enabled').checked,
        source: {
            certificate: document.getElementById('cert-source-cert').value.trim(),
            private_key: document.getElementById('cert-source-key').value.trim()
        },
        destination: {
            target_directory: document.getElementById('cert-target-dir').value.trim(),
            target_name: document.getElementById('cert-target-name').value.trim()
        },
        sync: {
            auto_sync: document.getElementById('cert-auto-sync').checked,
            filesystem_watch: document.getElementById('cert-filesystem-watch').checked,
            poll_interval_seconds: parseInt(document.getElementById('cert-poll-interval').value, 10)
        },
        fallback: document.getElementById('cert-fallback').checked
    };
}

function showModalMessage(text, isError) {
    const message = document.getElementById('modal-message');
    message.textContent = text;
    message.className = `message ${isError ? 'error-message' : 'warning-message'}`;
}

async function saveCert(event) {
    event.preventDefault();
    if (modalOperationInFlight) return;
    const originalName = currentCertName;
    const cert = getFormCert();
    setModalBusy(true);
    try {
        await fetchJSON(originalName ? `${API.certificates}/${encodeURIComponent(originalName)}` : API.certificates, {
            method: originalName ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(cert)
        });
        setModalBusy(false);
        closeModal();
        await loadStatus({ abortPrevious: true });
    } catch (error) {
        showModalMessage(error.message, true);
        setModalBusy(false);
    }
}

async function deleteCert() {
    if (!currentCertName || modalOperationInFlight) return;
    const name = currentCertName;
    if (!confirm(`Delete certificate "${name}"?`)) return;
    setModalBusy(true);
    try {
        await fetchJSON(`${API.certificates}/${encodeURIComponent(name)}`, { method: 'DELETE' });
        setModalBusy(false);
        closeModal();
        await loadStatus({ abortPrevious: true });
    } catch (error) {
        showModalMessage(error.message, true);
        setModalBusy(false);
    }
}

function updateSyncButtons(name, disabled) {
    document.querySelectorAll('button[data-action="sync"]').forEach(button => {
        if (button.dataset.certName === name) button.disabled = disabled;
    });
}

async function syncCert(name, reportError = message => alert(message)) {
    if (!name || syncingCertificates.has(name)) return false;
    syncingCertificates.add(name);
    updateSyncButtons(name, true);
    try {
        await fetchJSON(`${API.certificates}/${encodeURIComponent(name)}/sync`, { method: 'POST' });
        await loadStatus({ abortPrevious: true });
        return true;
    } catch (error) {
        reportError(error.message);
        return false;
    } finally {
        syncingCertificates.delete(name);
        updateSyncButtons(name, false);
    }
}

async function syncCurrentCert() {
    if (!currentCertName || modalOperationInFlight) return;
    setModalBusy(true);
    await syncCert(currentCertName, message => showModalMessage(message, true));
    setModalBusy(false);
}

async function validateCert() {
    if (!currentCertName || modalOperationInFlight) return;
    const name = currentCertName;
    setModalBusy(true);
    try {
        await fetchJSON(`${API.certificates}/${encodeURIComponent(name)}/validate`, { method: 'POST' });
        showModalMessage('Certificate is valid', false);
        await loadStatus({ abortPrevious: true });
    } catch (error) {
        showModalMessage(error.message, true);
    } finally {
        setModalBusy(false);
    }
}

async function editCert(name) {
    try {
        const certificates = await fetchJSON(API.certificates);
        const cert = certificates.find(item => item.name === name);
        if (cert) openModal(cert);
    } catch (error) {
        alert(error.message);
    }
}

function scheduleStatusPoll(delay = POLL_INTERVAL_MS) {
    clearTimeout(statusTimer);
    if (document.hidden) return;
    statusTimer = setTimeout(runStatusPoll, delay);
}

async function runStatusPoll() {
    await loadStatus();
    // A mutation may replace an in-flight poll. Wait for the newest request
    // before starting the interval so polling can never overlap.
    while (statusRequest) await statusRequest.promise;
    scheduleStatusPoll();
}

document.getElementById('btn-refresh').addEventListener('click', () => loadStatus());
document.getElementById('btn-add').addEventListener('click', () => openModal(null));
document.querySelector('.close').addEventListener('click', closeModal);
document.getElementById('cert-form').addEventListener('submit', saveCert);
document.getElementById('btn-delete').addEventListener('click', deleteCert);
document.getElementById('btn-sync-now').addEventListener('click', syncCurrentCert);
document.getElementById('btn-validate').addEventListener('click', validateCert);
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        clearTimeout(statusTimer);
        if (statusRequest) statusRequest.controller.abort();
    } else {
        scheduleStatusPoll(0);
    }
});

runStatusPoll();
