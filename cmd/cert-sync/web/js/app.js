const API = {
    status: './api/status',
    certificates: './api/certificates',
    certWardenTest: './api/certwarden/test',
    acknowledgeFallbackRestart: './api/fallback/restart/acknowledge'
};

const POLL_INTERVAL_MS = 10000;
const modalActionButtons = ['btn-save', 'btn-validate', 'btn-sync-now', 'btn-delete'];
let currentCertName = null;
let modalOperationInFlight = false;
let statusRequest = null;
let statusRequestSequence = 0;
let statusTimer = null;
let modalReturnFocus = null;
let remoteCredentialsConfigured = false;
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
    appendParagraph(container, `Remote sources: ${data.remote_sources || 0} | Connected: ${data.remote_connected || 0} | Checking: ${data.remote_checking || 0} | Errors: ${data.remote_errors || 0}`);
    if (data.fallback_pending_restart) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn';
        button.textContent = 'Confirm Zoraxy restart';
        button.addEventListener('click', async () => {
            button.disabled = true;
            try {
                await fetchJSON(API.acknowledgeFallbackRestart, { method: 'POST' });
                await loadStatus({ abortPrevious: true });
            } catch (error) {
                showStatusError(error.message);
                button.disabled = false;
            }
        });
        container.appendChild(button);
    }
}

function createStatusGroup(name, selector) {
    const group = document.createElement('section');
    group.className = 'status-group';
    group.dataset.statusGroup = selector;
    const heading = document.createElement('h4');
    heading.textContent = name;
    group.appendChild(heading);
    return group;
}

function appendBadge(group, label, status) {
    const badge = document.createElement('span');
    badge.className = `${statusClass(status)} status-badge`;
    badge.textContent = label;
    group.appendChild(badge);
    return badge;
}

function appendQueryField(group, field, text, className) {
    const paragraph = appendParagraph(group, text, className);
    paragraph.dataset.queryField = field;
    return paragraph;
}

function renderQueryStatus(query) {
    const group = createStatusGroup('Cert Warden API', 'cert-warden-query');
    group.setAttribute('role', 'status');
    group.setAttribute('aria-live', 'polite');
    let label = 'Never checked';
    let badgeStatus = 'Unknown';
    if (query.in_progress) {
        label = 'Checking';
        badgeStatus = 'Unknown';
    } else if (String(query.status).toLowerCase() === 'healthy') {
        label = 'Connected';
        badgeStatus = 'Healthy';
    } else if (String(query.status).toLowerCase() === 'error') {
        label = 'Error';
        badgeStatus = 'Error';
    }
    appendBadge(group, label, badgeStatus).dataset.queryField = 'status';
    appendQueryField(group, 'last_attempt', `Last attempt: ${formatDate(query.last_attempt)}`);
    appendQueryField(group, 'last_success', `Last success: ${formatDate(query.last_success)}`);
    appendQueryField(group, 'next_attempt', `Next attempt: ${formatDate(query.next_attempt)}`);
    appendQueryField(group, 'latency_ms', `Latency: ${query.latency_ms === undefined ? 'N/A' : `${query.latency_ms} ms`}`);
    appendQueryField(group, 'http_status', `HTTP status: ${query.http_status || 'N/A'}`);
    appendQueryField(group, 'failure_kind', `Failure: ${query.failure_kind || 'None'}`);
    appendQueryField(group, 'message', `Message: ${query.message || 'None'}`, query.status === 'Error' ? 'status-error' : '');
    return group;
}

function renderSourceStatus(item) {
    const group = createStatusGroup('Source certificate', 'source');
    const sourceError = item.source_validation_error || item.watcher_error;
    const sourceStatus = !item.enabled ? 'Disabled' : sourceError ? 'Error' : item.last_source_validation ? 'Healthy' : 'Unknown';
    appendBadge(group, sourceStatus, sourceStatus);
    appendParagraph(group, item.common_name || 'No certificate loaded');
    appendParagraph(group, `Issuer: ${item.issuer || 'N/A'}`);
    appendParagraph(group, `Expires: ${item.expires ? formatDate(item.expires) : 'N/A'} (${item.days_remaining} days remaining)`);
    appendParagraph(group, `Last validation: ${formatDate(item.last_source_validation)}`);
    appendParagraph(group, `Fingerprint: ${formatFP(item.source_fingerprint)}`);
    if (sourceError) appendParagraph(group, sourceError, 'status-error');
    return group;
}

function renderDestinationStatus(item) {
    const group = createStatusGroup('Zoraxy destination', 'destination');
    const destinationError = item.destination_validation_error || item.sync_error;
    const destinationStatus = !item.enabled ? 'Disabled' : destinationError ? 'Error' : item.key_match ? 'Healthy' : 'Unknown';
    appendBadge(group, destinationStatus, destinationStatus);
    appendParagraph(group, `Last validation: ${formatDate(item.last_destination_validation)}`);
    appendParagraph(group, `Last sync: ${formatDate(item.last_successful_sync)}`);
    appendParagraph(group, `Fingerprint: ${formatFP(item.destination_fingerprint)}`);
    appendParagraph(group, `Source matches destination: ${item.key_match ? 'Yes' : 'No'}`);
    appendParagraph(group, `Enabled: ${item.enabled ? 'Yes' : 'No'}`);
    appendParagraph(group, `Auto Sync: ${item.auto_sync ? 'Enabled' : 'Disabled'}`);
    if (item.fallback) {
        const fallback = appendParagraph(group, 'Fallback: Enabled');
        if (item.fallback_pending_restart) {
            const warning = document.createElement('span');
            warning.className = 'status-error';
            warning.textContent = ' (restart Zoraxy to activate)';
            fallback.appendChild(warning);
        }
    }
    if (destinationError) appendParagraph(group, destinationError, 'status-error');
    return group;
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

        const groups = document.createElement('div');
        groups.className = 'status-groups';
        if (item.source_type === 'cert_warden') groups.appendChild(renderQueryStatus(item.cert_warden_query || {}));
        groups.append(renderSourceStatus(item), renderDestinationStatus(item));
        card.appendChild(groups);

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

function updateCredentialRequirements() {
    const certificateKey = document.getElementById('cert-warden-certificate-api-key');
    const privateKey = document.getElementById('cert-warden-private-key-api-key');
    const remote = document.getElementById('cert-source-type').value === 'cert_warden';
    const certificateKeyEntered = certificateKey.value.trim() !== '';
    const privateKeyEntered = privateKey.value.trim() !== '';
    const credentialsNeeded = remote && (!remoteCredentialsConfigured || certificateKeyEntered || privateKeyEntered);
    certificateKey.required = credentialsNeeded;
    privateKey.required = credentialsNeeded;
    certificateKey.setCustomValidity(remote && certificateKey.value && !certificateKeyEntered ? 'API key cannot be blank.' : '');
    privateKey.setCustomValidity(remote && privateKey.value && !privateKeyEntered ? 'API key cannot be blank.' : '');
}

function updateSourceFields(applyRemoteDefault = false) {
    const remote = document.getElementById('cert-source-type').value === 'cert_warden';
    const localFields = document.getElementById('local-source-fields');
    const remoteFields = document.getElementById('cert-warden-source-fields');
    const sourceCert = document.getElementById('cert-source-cert');
    const sourceKey = document.getElementById('cert-source-key');
    const serverURL = document.getElementById('cert-warden-server-url');
    const certificateName = document.getElementById('cert-warden-certificate-name');
    const filesystemWatch = document.getElementById('cert-filesystem-watch');
    const pollInterval = document.getElementById('cert-poll-interval');
    const validateButton = document.getElementById('btn-validate');

    localFields.hidden = remote;
    remoteFields.hidden = !remote;
    sourceCert.required = !remote;
    sourceKey.required = !remote;
    serverURL.required = remote;
    certificateName.required = remote;
    filesystemWatch.disabled = remote;
    validateButton.textContent = remote ? 'Test Connection' : 'Validate';
    validateButton.style.display = remote || currentCertName ? 'inline-block' : 'none';
    if (remote) {
        filesystemWatch.checked = false;
        pollInterval.min = '60';
        if (applyRemoteDefault && Number(pollInterval.value) < 60) pollInterval.value = '300';
    } else {
        pollInterval.min = '1';
    }
    updateCredentialRequirements();
}

function openModal(cert) {
    modalReturnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    currentCertName = cert ? cert.name : null;
    document.getElementById('modal-title').textContent = cert ? 'Edit Certificate' : 'Add Certificate';
    document.getElementById('cert-original-name').value = cert ? cert.name : '';
    const nameInput = document.getElementById('cert-name');
    nameInput.value = cert ? cert.name : '';
    nameInput.readOnly = Boolean(cert);
    document.getElementById('cert-enabled').checked = cert ? cert.enabled : true;
    const sourceType = cert && cert.source.type === 'cert_warden' ? 'cert_warden' : 'local';
    document.getElementById('cert-source-type').value = sourceType;
    document.getElementById('cert-source-cert').value = cert && cert.source.certificate ? cert.source.certificate : '/cert_warden_plugin/certchain0.pem';
    document.getElementById('cert-source-key').value = cert && cert.source.private_key ? cert.source.private_key : '/cert_warden_plugin/key0.pem';
    document.getElementById('cert-warden-server-url').value = cert && cert.source.cert_warden ? cert.source.cert_warden.server_url : '';
    document.getElementById('cert-warden-certificate-name').value = cert && cert.source.cert_warden ? cert.source.cert_warden.certificate_name : '';
    document.getElementById('cert-warden-certificate-api-key').value = '';
    document.getElementById('cert-warden-private-key-api-key').value = '';
    const credentialState = cert && cert.cert_warden_credentials;
    const certificateKeyConfigured = Boolean(credentialState && credentialState.certificate_api_key_configured);
    const privateKeyConfigured = Boolean(credentialState && credentialState.private_key_api_key_configured);
    remoteCredentialsConfigured = certificateKeyConfigured && privateKeyConfigured;
    document.getElementById('certificate-api-key-help').textContent = certificateKeyConfigured ? 'Configured. Leave blank to keep the current key.' : '';
    document.getElementById('private-key-api-key-help').textContent = privateKeyConfigured ? 'Configured. Leave blank to keep the current key.' : '';
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
    resetDeleteConfirmation();
    updateSourceFields(false);
    document.getElementById('modal').classList.remove('hidden');
    requestAnimationFrame(() => nameInput.focus());
}

function resetDeleteConfirmation() {
    clearTimeout(deleteConfirmTimer);
    const button = document.getElementById('btn-delete');
    button.dataset.confirming = '';
    button.textContent = 'Delete';
}

function closeModal() {
    if (modalOperationInFlight) return;
    document.getElementById('modal').classList.add('hidden');
    currentCertName = null;
    remoteCredentialsConfigured = false;
    resetDeleteConfirmation();
    if (modalReturnFocus && document.contains(modalReturnFocus)) modalReturnFocus.focus();
    modalReturnFocus = null;
}

function getFormCert() {
    const sourceType = document.getElementById('cert-source-type').value;
    const cert = {
        name: document.getElementById('cert-name').value.trim(),
        enabled: document.getElementById('cert-enabled').checked,
        source: sourceType === 'cert_warden' ? {
            type: 'cert_warden',
            cert_warden: {
                server_url: document.getElementById('cert-warden-server-url').value.trim(),
                certificate_name: document.getElementById('cert-warden-certificate-name').value.trim()
            }
        } : {
            type: 'local',
            certificate: document.getElementById('cert-source-cert').value.trim(),
            private_key: document.getElementById('cert-source-key').value.trim()
        },
        destination: {
            target_directory: document.getElementById('cert-target-dir').value.trim(),
            target_name: document.getElementById('cert-target-name').value.trim()
        },
        sync: {
            auto_sync: document.getElementById('cert-auto-sync').checked,
            filesystem_watch: sourceType === 'local' && document.getElementById('cert-filesystem-watch').checked,
            poll_interval_seconds: parseInt(document.getElementById('cert-poll-interval').value, 10)
        },
        fallback: document.getElementById('cert-fallback').checked
    };
    if (sourceType === 'cert_warden') {
        const certificateAPIKey = document.getElementById('cert-warden-certificate-api-key').value;
        const privateKeyAPIKey = document.getElementById('cert-warden-private-key-api-key').value;
        if (certificateAPIKey.trim() || privateKeyAPIKey.trim()) {
            cert.cert_warden_credentials = {
                certificate_api_key: certificateAPIKey,
                private_key_api_key: privateKeyAPIKey
            };
        }
    }
    return cert;
}

function showModalMessage(text, isError) {
    const message = document.getElementById('modal-message');
    message.textContent = text;
    message.className = `message ${isError ? 'error-message' : 'warning-message'}`;
}

async function saveCert() {
    if (modalOperationInFlight) return;
    const form = document.getElementById('cert-form');
    if (!form.checkValidity()) {
        form.reportValidity();
        return;
    }
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

let deleteConfirmTimer = null;

async function deleteCert() {
    if (!currentCertName || modalOperationInFlight) return;
    const name = currentCertName;
    const button = document.getElementById('btn-delete');
    if (button.dataset.confirming !== 'true') {
        button.dataset.confirming = 'true';
        const originalText = button.textContent;
        button.textContent = 'Confirm Delete';
        clearTimeout(deleteConfirmTimer);
        deleteConfirmTimer = setTimeout(() => {
            button.dataset.confirming = '';
            button.textContent = originalText;
        }, 3000);
        return;
    }
    clearTimeout(deleteConfirmTimer);
    button.dataset.confirming = '';
    button.textContent = 'Delete';
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
    if (modalOperationInFlight) return;
    const remote = document.getElementById('cert-source-type').value === 'cert_warden';
    if (!remote && !currentCertName) return;
    setModalBusy(true);
    try {
        if (remote) {
            const certificateAPIKey = document.getElementById('cert-warden-certificate-api-key').value;
            const privateKeyAPIKey = document.getElementById('cert-warden-private-key-api-key').value;
            if (!certificateAPIKey || !privateKeyAPIKey) {
                if (!currentCertName) throw new Error('Enter both API keys before testing the connection.');
                await fetchJSON(`${API.certificates}/${encodeURIComponent(currentCertName)}/validate`, { method: 'POST' });
            } else {
                await fetchJSON(API.certWardenTest, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        server_url: document.getElementById('cert-warden-server-url').value.trim(),
                        certificate_name: document.getElementById('cert-warden-certificate-name').value.trim(),
                        certificate_api_key: certificateAPIKey,
                        private_key_api_key: privateKeyAPIKey
                    })
                });
            }
            showModalMessage('Cert Warden connection and certificate are valid', false);
        } else {
            await fetchJSON(`${API.certificates}/${encodeURIComponent(currentCertName)}/validate`, { method: 'POST' });
            showModalMessage('Certificate is valid', false);
        }
        if (currentCertName) await loadStatus({ abortPrevious: true });
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
document.getElementById('cert-source-type').addEventListener('change', () => updateSourceFields(true));
document.getElementById('cert-warden-certificate-api-key').addEventListener('input', updateCredentialRequirements);
document.getElementById('cert-warden-private-key-api-key').addEventListener('input', updateCredentialRequirements);
document.getElementById('cert-form').addEventListener('submit', event => { event.preventDefault(); saveCert(); });
document.getElementById('btn-save').addEventListener('click', saveCert);
document.getElementById('btn-delete').addEventListener('click', deleteCert);
document.getElementById('btn-sync-now').addEventListener('click', syncCurrentCert);
document.getElementById('btn-validate').addEventListener('click', validateCert);
document.getElementById('modal').addEventListener('keydown', event => {
    if (event.key === 'Escape') {
        event.preventDefault();
        closeModal();
        return;
    }
    if (event.key !== 'Tab') return;
    const focusable = Array.from(document.querySelectorAll('#modal button:not(:disabled), #modal input:not(:disabled), #modal select:not(:disabled)'))
        .filter(element => element.offsetParent !== null);
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
    }
});
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        clearTimeout(statusTimer);
        if (statusRequest) statusRequest.controller.abort();
    } else {
        scheduleStatusPoll(0);
    }
});

runStatusPoll();
