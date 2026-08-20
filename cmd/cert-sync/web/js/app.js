const API = {
    status: './api/status',
    config: './api/config',
    certificates: './api/certificates'
};

let currentCertName = null;

function getCsrfToken() {
    const meta = document.querySelector('meta[name="zoraxy.csrf.Token"]');
    return meta ? meta.getAttribute('content') : '';
}

async function fetchJSON(url, options = {}) {
    const needsToken = ['POST', 'PUT', 'DELETE', 'PATCH'].includes((options.method || 'GET').toUpperCase());
    if (needsToken) {
        options.headers = options.headers || {};
        options.headers['X-CSRF-Token'] = getCsrfToken();
    }
    const res = await fetch(url, options);
    if (!res.ok) {
        const body = await res.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(body.error || `HTTP ${res.status}`);
    }
    return res.json();
}

function formatDate(iso) {
    if (!iso) return 'Never';
    const d = new Date(iso);
    return d.toLocaleString();
}

function formatFP(fp) {
    if (!fp) return 'N/A';
    return fp.substring(0, 16) + '...';
}

function renderOverview(data) {
    const el = document.getElementById('overview-content');
    el.innerHTML = `
        <p>Status: <span class="status-${data.status.toLowerCase()}">${data.status}</span></p>
        <p>Configured certificates: ${data.certificates}</p>
        <p>Healthy: ${data.healthy} | Errors: ${data.errors} | Unknown: ${data.unknown}</p>
    `;
}

function renderCertificates(items) {
    const el = document.getElementById('cert-list');
    if (items.length === 0) {
        el.innerHTML = '<p>No certificates configured.</p>';
        return;
    }
    el.innerHTML = items.map(item => `
        <div class="cert-card">
            <h3>${escapeHtml(item.name)} <span class="status-${item.status.toLowerCase()}">${item.status}</span></h3>
            <div class="cert-meta">
                <p>${escapeHtml(item.common_name || 'No certificate loaded')}</p>
                <p>Issuer: ${escapeHtml(item.issuer || 'N/A')}</p>
                <p>Expires: ${item.expires ? formatDate(item.expires) : 'N/A'} (${item.days_remaining} days remaining)</p>
                <p>Last sync: ${formatDate(item.last_successful_sync)}</p>
                <p>Source fingerprint: ${formatFP(item.source_fingerprint)}</p>
                <p>Certificate / key match: ${item.key_match ? 'Yes' : 'No'}</p>
                <p>Auto Sync: ${item.auto_sync ? 'Enabled' : 'Disabled'}</p>
                ${item.fallback ? `<p>Fallback: Enabled ${item.fallback_pending_restart ? '<span class="status-error">(restart Zoraxy to activate)</span>' : ''}</p>` : ''}
                ${item.status === 'Error' ? `<p class="error-message">${escapeHtml(item.message)}</p>` : ''}
            </div>
            <div class="cert-actions">
                <button class="btn btn-primary" onclick="editCert('${escapeHtml(item.name)}')">Edit</button>
                <button class="btn" onclick="syncCert('${escapeHtml(item.name)}')">Sync Now</button>
            </div>
        </div>
    `).join('');
}

function escapeHtml(text) {
    if (text == null) return '';
    return text.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

async function loadStatus() {
    try {
        const data = await fetchJSON(API.status);
        renderOverview(data);
        renderCertificates(data.items);
    } catch (err) {
        document.getElementById('overview-content').innerHTML = `<p class="error-message">${escapeHtml(err.message)}</p>`;
        document.getElementById('cert-list').innerHTML = '';
    }
}

function openModal(cert) {
    currentCertName = cert ? cert.name : null;
    document.getElementById('modal-title').textContent = cert ? 'Edit Certificate' : 'Add Certificate';
    document.getElementById('cert-original-name').value = cert ? cert.name : '';
    document.getElementById('cert-name').value = cert ? cert.name : '';
    document.getElementById('cert-source-cert').value = cert ? cert.source.certificate : '/cert_warden_plugin/certchain0.pem';
    document.getElementById('cert-source-key').value = cert ? cert.source.private_key : '/cert_warden_plugin/key0.pem';
    document.getElementById('cert-target-dir').value = cert ? cert.destination.target_directory : '/opt/zoraxy/config/conf/certs';
    document.getElementById('cert-target-name').value = cert ? cert.destination.target_name : '';
    document.getElementById('cert-auto-sync').checked = cert ? cert.sync.auto_sync : true;
    document.getElementById('cert-filesystem-watch').checked = cert ? cert.sync.filesystem_watch : true;
    document.getElementById('cert-poll-interval').value = cert ? cert.sync.poll_interval_seconds : 10;
    document.getElementById('cert-fallback').checked = cert ? cert.fallback : false;
    document.getElementById('btn-delete').style.display = cert ? 'inline-block' : 'none';
    document.getElementById('modal-message').classList.add('hidden');
    document.getElementById('modal').classList.remove('hidden');
}

function closeModal() {
    document.getElementById('modal').classList.add('hidden');
    currentCertName = null;
}

function getFormCert() {
    return {
        name: document.getElementById('cert-name').value.trim(),
        enabled: true,
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
    const el = document.getElementById('modal-message');
    el.textContent = text;
    el.classList.remove('hidden');
    el.className = 'message ' + (isError ? 'error-message' : 'warning-message');
}

async function saveCert(e) {
    e.preventDefault();
    const cert = getFormCert();
    try {
        if (currentCertName) {
            await fetchJSON(`${API.certificates}/${encodeURIComponent(currentCertName)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(cert)
            });
        } else {
            await fetchJSON(API.certificates, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(cert)
            });
        }
        closeModal();
        await loadStatus();
    } catch (err) {
        showModalMessage(err.message, true);
    }
}

async function deleteCert() {
    if (!currentCertName) return;
    if (!confirm(`Delete certificate "${currentCertName}"?`)) return;
    try {
        await fetchJSON(`${API.certificates}/${encodeURIComponent(currentCertName)}`, {
            method: 'DELETE'
        });
        closeModal();
        await loadStatus();
    } catch (err) {
        showModalMessage(err.message, true);
    }
}

async function syncCert(name) {
    try {
        await fetchJSON(`${API.certificates}/${encodeURIComponent(name)}/sync`, {
            method: 'POST'
        });
        await loadStatus();
    } catch (err) {
        alert(err.message);
    }
}

async function validateCert() {
    if (!currentCertName) return;
    try {
        await fetchJSON(`${API.certificates}/${encodeURIComponent(currentCertName)}/validate`, {
            method: 'POST'
        });
        showModalMessage('Certificate is valid', false);
        await loadStatus();
    } catch (err) {
        showModalMessage(err.message, true);
    }
}

async function editCert(name) {
    try {
        const certs = await fetchJSON(API.certificates);
        const cert = certs.find(c => c.name === name);
        if (cert) openModal(cert);
    } catch (err) {
        alert(err.message);
    }
}

document.getElementById('btn-refresh').addEventListener('click', loadStatus);
document.getElementById('btn-add').addEventListener('click', () => openModal(null));
document.querySelector('.close').addEventListener('click', closeModal);
document.getElementById('cert-form').addEventListener('submit', saveCert);
document.getElementById('btn-delete').addEventListener('click', deleteCert);
document.getElementById('btn-sync-now').addEventListener('click', () => {
    if (currentCertName) syncCert(currentCertName);
});
document.getElementById('btn-validate').addEventListener('click', validateCert);

loadStatus();
setInterval(loadStatus, 10000);
