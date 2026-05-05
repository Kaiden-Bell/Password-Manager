const API_BASE = '/api';

let isLocked = true;
let currentEntries = [];
let vaultIdCache = 1;
let pendingDeleteVaultId = null;

const authView = document.getElementById('auth-view');
const vaultView = document.getElementById('vault-view');
const unlockSection = document.getElementById('unlock-section');
const initSection = document.getElementById('init-section');
const authError = document.getElementById('auth-error');
const hwStatus = document.getElementById('hardware-status');

async function init() {
    await checkStatus();
    setupEventListeners();
    setInterval(checkStatus, 2000);
}

let vaultMeta = {};

async function loadVaultsList(username = '') {
    const select = document.getElementById('unlock-vault-id');

    if (!username) {
        select.innerHTML = '<option value="" disabled selected>Enter username to search vaults</option>';
        select.disabled = true;
        vaultMeta = {};
        updateHardwareState(null);
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/vaults?username=${encodeURIComponent(username)}`);
        const data = await res.json();

        vaultMeta = {};
        if (data.vaults && data.vaults.length > 0) {
            select.innerHTML = '<option value="" disabled selected>Select a Vault</option>';
            select.disabled = false;
            data.vaults.forEach(v => {
                vaultMeta[v.vault_id] = v;
                const opt = document.createElement('option');
                opt.value = v.vault_id;
                opt.textContent = v.vault_name;
                select.appendChild(opt);
            });
            if (data.vaults.length === 1) {
                select.value = data.vaults[0].vault_id;
                vaultIdCache = data.vaults[0].vault_id;
                updateHardwareState(data.vaults[0].vault_id);
            } else {
                updateHardwareState(null);
            }
        } else {
            select.innerHTML = '<option value="" disabled selected>No vaults found</option>';
            select.disabled = true;
            updateHardwareState(null);
        }
    } catch (err) {
        console.error('Failed to load vaults list', err);
    }
}

function updateHardwareState(vaultId) {
    const meta = vaultMeta[vaultId];
    const hwWaiting = document.getElementById('hw-waiting');
    const hwReady = document.getElementById('hw-ready');
    const passphraseGroup = document.getElementById('unlock-passphrase-group');
    const passphraseInput = document.getElementById('unlock-passphrase');
    const unlockBtn = document.getElementById('unlock-btn');

    if (meta && meta.hardware_gate_required) {
        hwWaiting.classList.remove('hidden');
        hwReady.classList.add('hidden');
        passphraseGroup.classList.add('hidden');
        passphraseInput.required = false;
        unlockBtn.classList.add('hidden');
        setHardwareTarget(vaultId);
    } else {
        hwWaiting.classList.add('hidden');
        hwReady.classList.add('hidden');
        passphraseGroup.classList.remove('hidden');
        passphraseInput.required = true;
        unlockBtn.classList.remove('hidden');
        setHardwareTarget(null);
    }
}

async function setHardwareTarget(vaultId) {
    try {
        const query = vaultId != null ? `?vault_id=${vaultId}` : '';
        await fetch(`${API_BASE}/hardware/target${query}`, { method: 'PUT' });
    } catch (err) {
        console.error('Failed to set hardware target', err);
    }
}

function showPassphraseReady() {
    document.getElementById('hw-waiting').classList.add('hidden');
    document.getElementById('hw-ready').classList.remove('hidden');
    document.getElementById('unlock-passphrase-group').classList.remove('hidden');
    document.getElementById('unlock-passphrase').required = true;
    document.getElementById('unlock-btn').classList.remove('hidden');
}

async function checkStatus() {
    try {
        const query = vaultIdCache ? `?vault_id=${vaultIdCache}` : '';
        const res = await fetch(`${API_BASE}/status${query}`);
        const data = await res.json();

        if (data.is_locked !== isLocked) {
            isLocked = data.is_locked;
            if (isLocked) {
                showAuthView();
            } else {
                vaultIdCache = data.vault_id || vaultIdCache;
                showVaultView();
            }
        }

        if (data.hardware_gate_required) {
            hwStatus.classList.add('active');
            hwStatus.title = "Hardware Keypad Required";
        } else {
            hwStatus.classList.remove('active');
            hwStatus.title = "Hardware Keypad Optional";
        }

        if (data.passphrase_window_active && isLocked) {
            showPassphraseReady();
        }
        if (isLocked && vaultIdCache && vaultMeta[vaultIdCache] && vaultMeta[vaultIdCache].hardware_gate_required) {
            const authActive = !authView.classList.contains('hidden');
            const unlockActive = !unlockSection.classList.contains('hidden');
            if (authActive && unlockActive && data.hardware_target_id !== vaultIdCache) {
                setHardwareTarget(vaultIdCache);
            }
        }

    } catch (err) {
        console.error("Failed to fetch status", err);
    }
}

function showAuthView() {
    vaultView.classList.add('hidden');
    authView.classList.remove('hidden');
    document.getElementById('unlock-passphrase').value = '';
    const usernameInput = document.getElementById('unlock-username');
    if (usernameInput) loadVaultsList(usernameInput.value.trim());
}

function showVaultView() {
    authView.classList.add('hidden');
    vaultView.classList.remove('hidden');
    loadEntries();
}

function showError(msg) {
    authError.textContent = msg;
    setTimeout(() => authError.textContent = '', 4000);
}

function setupEventListeners() {
    document.getElementById('show-init').addEventListener('click', (e) => {
        e.preventDefault();
        unlockSection.classList.add('hidden');
        initSection.classList.remove('hidden');
        authError.textContent = '';
    });

    document.getElementById('show-unlock').addEventListener('click', (e) => {
        e.preventDefault();
        initSection.classList.add('hidden');
        unlockSection.classList.remove('hidden');
        authError.textContent = '';
    });

    document.getElementById('init-hw-req').addEventListener('change', (e) => {
        const pinGroup = document.getElementById('pin-input-group');
        const pinInput = document.getElementById('init-pin');
        if (e.target.checked) {
            pinGroup.classList.remove('hidden');
            pinInput.required = true;
        } else {
            pinGroup.classList.add('hidden');
            pinInput.required = false;
            pinInput.value = '';
        }
    });

    let searchTimeout;
    document.getElementById('unlock-username').addEventListener('input', (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            loadVaultsList(e.target.value.trim());
        }, 400);
    });

    document.getElementById('unlock-vault-id').addEventListener('change', (e) => {
        vaultIdCache = parseInt(e.target.value);
        updateHardwareState(vaultIdCache);
    });

    document.getElementById('delete-vault-btn').addEventListener('click', () => {
        if (!vaultIdCache) return;

        pendingDeleteVaultId = vaultIdCache;
        const meta = vaultMeta[vaultIdCache];
        document.getElementById('delete-vault-name').textContent = meta ? meta.vault_name : `Vault #${vaultIdCache}`;
        document.getElementById('delete-vault-modal').classList.remove('hidden');
    });

    document.getElementById('cancel-delete-btn').addEventListener('click', () => {
        pendingDeleteVaultId = null;
        document.getElementById('delete-vault-modal').classList.add('hidden');
    });

    document.getElementById('confirm-delete-btn').addEventListener('click', async () => {
        if (!pendingDeleteVaultId) return;
        const btn = document.getElementById('confirm-delete-btn');
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Deleting…';

        try {
            const res = await fetch(`${API_BASE}/vaults/${pendingDeleteVaultId}`, { method: 'DELETE' });
            const text = await res.text();
            let data;
            try { data = JSON.parse(text); } catch { throw new Error(text || 'Server error'); }
            if (!res.ok) throw new Error(data.detail || 'Delete failed');

            isLocked = true;
            vaultIdCache = 1;
            showAuthView();
            authError.style.color = '#10b981';
            authError.textContent = 'Vault deleted successfully.';
            setTimeout(() => { authError.textContent = ''; authError.style.color = ''; }, 4000);
        } catch (err) {
            alert(err.message);
        } finally {
            pendingDeleteVaultId = null;
            document.getElementById('delete-vault-modal').classList.add('hidden');
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-trash"></i> Delete Forever';
        }
    });

    document.getElementById('unlock-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const passphrase = document.getElementById('unlock-passphrase').value;
        const vault_id = parseInt(document.getElementById('unlock-vault-id').value);

        if (!vault_id) { showError('Please select a vault.'); return; }

        vaultIdCache = vault_id;
        const meta = vaultMeta[vault_id];
        const isHardware = meta && meta.hardware_gate_required;
        const endpoint = isHardware ? '/unlock/passphrase' : '/unlock/software';

        try {
            const res = await fetch(`${API_BASE}${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ vault_id, passphrase })
            });
            const text = await res.text();
            let data;
            try { data = JSON.parse(text); } catch { throw new Error(text || 'Server error'); }

            if (res.status === 403 && isHardware) {
                showError(data.detail || 'Too many incorrect attempts. Re-enter PIN on keypad.');
                updateHardwareState(vault_id);
                document.getElementById('unlock-passphrase').value = '';
                return;
            }

            if (!res.ok) throw new Error(data.detail || 'Unlock failed.');

            await checkStatus();
        } catch (err) {
            showError(err.message);
        }
    });

    document.getElementById('init-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const hwRequired = document.getElementById('init-hw-req').checked;
        const passphrase = document.getElementById('init-passphrase').value;
        const verifyPassphrase = document.getElementById('init-verify-passphrase').value;

        if (passphrase !== verifyPassphrase) {
            showError('Passwords do not match.');
            return;
        }

        const payload = {
            username: document.getElementById('init-username').value,
            display_name: document.getElementById('init-username').value, // Use username as display_name for now
            vault_name: document.getElementById('init-vault').value,
            passphrase: passphrase,
            keypad_pin: document.getElementById('init-pin').value || null,
            hardware_gate_required: hwRequired,
            software_only_enabled: !hwRequired
        };

        try {
            const res = await fetch(`${API_BASE}/init`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const text = await res.text();
            let data;

            try { data = JSON.parse(text); } catch { throw new Error(text || 'Server error'); }
            if (!res.ok) throw new Error(data.detail || 'Initialization failed');

            const vaultIdMatch = data.message.match(/Vault (\d+)/);
            if (vaultIdMatch) vaultIdCache = parseInt(vaultIdMatch[1]);

            if (hwRequired) {
                showError('');
                initSection.classList.add('hidden');
                unlockSection.classList.remove('hidden');

                const uInput = document.getElementById('unlock-username');
                uInput.value = payload.username;
                await loadVaultsList(payload.username);

                document.getElementById('unlock-vault-id').value = vaultIdCache;
                updateHardwareState(vaultIdCache);
                authError.textContent = '';
                authError.style.color = '#10b981';
                authError.textContent = 'Vault created! Enter your PIN on the keypad to unlock.';
                setTimeout(() => { authError.textContent = ''; authError.style.color = ''; }, 5000);
            } else {
                const unlockRes = await fetch(`${API_BASE}/unlock/software`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ vault_id: vaultIdCache, passphrase: payload.passphrase })
                });
                const unlockText = await unlockRes.text();
                let unlockData;
                try { unlockData = JSON.parse(unlockText); } catch { throw new Error(unlockText || 'Unlock failed after init'); }
                if (!unlockRes.ok) throw new Error(unlockData.detail || 'Auto-unlock failed after vault creation');
                await checkStatus();
            }
        } catch (err) {
            showError(err.message);
        }
    });

    document.getElementById('lock-btn').addEventListener('click', async () => {
        await fetch(`${API_BASE}/lock`, { method: 'POST' });
        await setHardwareTarget(null);
        await checkStatus();
    });

    const searchInput = document.getElementById('search-input');
    const searchFilter = document.getElementById('search-filter');

    const handleSearch = () => {
        const q = searchInput.value.toLowerCase();
        const filter = searchFilter.value;
        renderEntries(currentEntries.filter(entry => {
            if (filter === 'all') {
                return entry.site.toLowerCase().includes(q) || entry.username.toLowerCase().includes(q);
            } else if (filter === 'site') {
                return entry.site.toLowerCase().includes(q);
            } else if (filter === 'username') {
                return entry.username.toLowerCase().includes(q);
            }
            return true;
        }));
    };

    searchInput.addEventListener('input', handleSearch);
    searchFilter.addEventListener('change', handleSearch);


    document.getElementById('add-entry-btn').addEventListener('click', () => {
        document.getElementById('entry-form').reset();
        document.getElementById('entry-id').value = '';
        document.getElementById('modal-title').textContent = 'Add Entry';
        document.getElementById('entry-modal').classList.remove('hidden');
    });

    document.getElementById('close-modal-btn').addEventListener('click', () => {
        document.getElementById('entry-modal').classList.add('hidden');
    });


    document.getElementById('entry-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = document.getElementById('entry-id').value;
        const payload = {
            site: document.getElementById('entry-site').value,
            username: document.getElementById('entry-username').value,
            password: document.getElementById('entry-password').value
        };

        try {
            let url = `${API_BASE}/entries`;
            let method = 'POST';
            if (id) {
                url += `/${id}`;
                method = 'PUT';
            }

            const res = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!res.ok) throw new Error('Failed to save entry');

            document.getElementById('entry-modal').classList.add('hidden');
            loadEntries();
        } catch (err) {
            alert(err.message);
        }
    });

    document.getElementById('generate-btn').addEventListener('click', () => {
        document.getElementById('generator-modal').classList.remove('hidden');
    });

    document.getElementById('close-gen-btn').addEventListener('click', () => {
        document.getElementById('generator-modal').classList.add('hidden');
    });

    document.getElementById('gen-length').addEventListener('input', (e) => {
        document.getElementById('length-val').textContent = e.target.value;
    });

    document.getElementById('do-generate-btn').addEventListener('click', async () => {
        const payload = {
            length: parseInt(document.getElementById('gen-length').value),
            use_upper: document.getElementById('gen-upper').checked,
            use_lower: document.getElementById('gen-lower').checked,
            use_digits: document.getElementById('gen-digits').checked,
            use_symbols: document.getElementById('gen-symbols').checked
        };

        try {
            const res = await fetch(`${API_BASE}/password/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            document.getElementById('gen-result').value = data.password;
        } catch (err) {
            console.error('Generation failed', err);
        }
    });

    document.getElementById('copy-gen-btn').addEventListener('click', () => {
        const val = document.getElementById('gen-result').value;
        if (val) {
            navigator.clipboard.writeText(val);
            const icon = document.querySelector('#copy-gen-btn i');
            icon.classList.replace('fa-copy', 'fa-check');
            setTimeout(() => icon.classList.replace('fa-check', 'fa-copy'), 1500);
        }
    });

    const hwInfoBtn = document.getElementById('hw-info-btn');
    if (hwInfoBtn) {
        hwInfoBtn.addEventListener('click', () => {
            document.getElementById('hw-info-modal').classList.remove('hidden');
        });
    }

    const closeHwInfoBtn = document.getElementById('close-hw-info-btn');
    if (closeHwInfoBtn) {
        closeHwInfoBtn.addEventListener('click', () => {
            document.getElementById('hw-info-modal').classList.add('hidden');
        });
    }

    document.querySelectorAll('.toggle-pwd').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            const icon = btn.querySelector('i');
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.replace('fa-eye', 'fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.replace('fa-eye-slash', 'fa-eye');
            }
        });
    });

    // Password Strength Meter Logic
    const initPassInput = document.getElementById('init-passphrase');
    const strengthMeter = document.getElementById('password-strength-meter');
    const strengthBar = strengthMeter.querySelector('.strength-bar');
    const strengthLabel = strengthMeter.querySelector('.strength-label');

    const entryPassInput = document.getElementById('entry-password');
    const entryStrengthMeter = document.getElementById('entry-password-strength-meter');
    const entryStrengthBar = entryStrengthMeter.querySelector('.strength-bar');
    const entryStrengthLabel = entryStrengthMeter.querySelector('.strength-label');

    let strengthTimeout;

    const checkStrength = async (password, bar, label, meter) => {
        if (!password) {
            meter.classList.add('hidden');
            return;
        }
        meter.classList.remove('hidden');

        clearTimeout(strengthTimeout);
        strengthTimeout = setTimeout(async () => {
            try {
                const res = await fetch(`${API_BASE}/password/check`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                const data = await res.json();
                bar.className = `strength-bar score-${data.score}`;
                label.className = `strength-label score-${data.score}`;
                label.textContent = data.label;
            } catch (err) {
                console.error('Strength check failed', err);
            }
        }, 300);
    };

    initPassInput.addEventListener('input', () => checkStrength(initPassInput.value, strengthBar, strengthLabel, strengthMeter));
    entryPassInput.addEventListener('input', () => checkStrength(entryPassInput.value, entryStrengthBar, entryStrengthLabel, entryStrengthMeter));
}

async function loadEntries() {
    try {
        const res = await fetch(`${API_BASE}/entries`);
        if (!res.ok) throw new Error('Failed to load entries');
        const data = await res.json();
        currentEntries = data.entries || [];
        renderEntries(currentEntries);
    } catch (err) {
        console.error(err);
    }
}

function renderEntries(entries) {
    const grid = document.getElementById('entries-grid');
    grid.innerHTML = '';

    if (entries.length === 0) {
        grid.innerHTML = '<p style="color: var(--text-muted); grid-column: 1/-1; text-align: center; padding: 3rem;">No credentials found. Add one to get started.</p>';
        return;
    }

    entries.forEach(entry => {
        const card = document.createElement('div');
        card.className = 'entry-card';
        card.innerHTML = `
            <div class="entry-header">
                <div class="entry-site">${escapeHtml(entry.site)}</div>
                <div class="entry-actions">
                    <button class="edit-btn" title="Edit"><i class="fa-solid fa-pen"></i></button>
                    <button class="delete-btn" title="Delete"><i class="fa-solid fa-trash"></i></button>
                </div>
            </div>
            <div class="entry-field">
                <label>Username</label>
                <div class="entry-value">
                    <span class="truncate">${escapeHtml(entry.username)}</span>
                    <button class="icon-btn copy-user" title="Copy"><i class="fa-regular fa-copy"></i></button>
                </div>
            </div>
            <div class="entry-field">
                <label>Password</label>
                <div class="entry-value">
                    <span class="truncate">••••••••</span>
                    <div>
                        <button class="icon-btn copy-pwd" title="Copy"><i class="fa-regular fa-copy"></i></button>
                    </div>
                </div>
            </div>
        `;

        card.querySelector('.edit-btn').addEventListener('click', () => editEntry(entry));
        card.querySelector('.delete-btn').addEventListener('click', () => deleteEntry(entry.entry_id));

        card.querySelector('.copy-user').addEventListener('click', function () {
            navigator.clipboard.writeText(entry.username);
            const icon = this.querySelector('i');
            icon.classList.replace('fa-copy', 'fa-check');
            setTimeout(() => icon.classList.replace('fa-check', 'fa-copy'), 1500);
        });

        card.querySelector('.copy-pwd').addEventListener('click', function () {
            navigator.clipboard.writeText(entry.password);
            const icon = this.querySelector('i');
            icon.classList.replace('fa-copy', 'fa-check');
            setTimeout(() => icon.classList.replace('fa-check', 'fa-copy'), 1500);
        });

        grid.appendChild(card);
    });
}

function editEntry(entry) {
    document.getElementById('entry-id').value = entry.entry_id;
    document.getElementById('entry-site').value = entry.site;
    document.getElementById('entry-username').value = entry.username;
    document.getElementById('entry-password').value = entry.password;
    document.getElementById('modal-title').textContent = 'Edit Entry';
    document.getElementById('entry-modal').classList.remove('hidden');
}

async function deleteEntry(id) {
    if (!confirm('Are you sure you want to delete this credential?')) return;
    try {
        const res = await fetch(`${API_BASE}/entries/${id}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('Delete failed');
        loadEntries();
    } catch (err) {
        alert(err.message);
    }
}

function escapeHtml(unsafe) {
    return (unsafe || '').toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

init();
