/**
 * app.js — The Vault frontend logic.
 *
 * Vanilla JavaScript with fetch-based API calls.
 * Handles initialization, unlock/lock, CRUD entries,
 * password generation, and strength checking.
 */

const API_BASE = "/api";

// ═══════════════════════════════════════════════════════════════════════════
// DOM References
// ═══════════════════════════════════════════════════════════════════════════

const $ = (id) => document.getElementById(id);

const els = {
    // Status
    statusIndicator: $("status-indicator"),

    // Sections
    initSection: $("init-section"),
    unlockSection: $("unlock-section"),
    dashboardSection: $("dashboard-section"),

    // Init form
    initForm: $("init-form"),
    initMessage: $("init-message"),

    // Unlock form
    unlockForm: $("unlock-form"),
    unlockSoftwareMode: $("unlock-software-mode"),
    unlockMessage: $("unlock-message"),
    gateStatusText: $("gate-status-text"),
    windowStatusText: $("window-status-text"),

    // Dashboard
    lockBtn: $("lock-btn"),
    searchInput: $("search-input"),
    searchBtn: $("search-btn"),
    entriesTbody: $("entries-tbody"),
    noEntriesMsg: $("no-entries-msg"),
    addEntryForm: $("add-entry-form"),
    dashboardMessage: $("dashboard-message"),

    // Password tools
    generatePasswordBtn: $("generate-password-btn"),
    generatedPasswordOutput: $("generated-password-output"),
    strengthCheckInput: $("strength-check-input"),
    checkStrengthBtn: $("check-strength-btn"),
    strengthResult: $("strength-result"),
};


// ═══════════════════════════════════════════════════════════════════════════
// API Helpers
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Make a fetch request to the backend API.
 * @param {string} endpoint - API path (e.g., "/init")
 * @param {object} options  - fetch options (method, body, etc.)
 * @returns {Promise<object>} Parsed JSON response.
 */
async function apiCall(endpoint, options = {}) {
    // TODO: Implement fetch call to API_BASE + endpoint.
    // - Set Content-Type to application/json for POST/PUT.
    // - Parse and return JSON response.
    // - Handle HTTP errors and return { success: false, message: "..." }.
    console.warn(`apiCall(${endpoint}) not yet implemented`);
    return { success: false, message: "Not implemented" };
}


// ═══════════════════════════════════════════════════════════════════════════
// Message Display
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Show a success or error message in a message element.
 * @param {HTMLElement} el      - The message element.
 * @param {string}      text    - Message text.
 * @param {boolean}     success - True for success, false for error.
 */
function showMessage(el, text, success = true) {
    // TODO:
    // 1. Set el.textContent = text.
    // 2. Remove both "success" and "error" classes.
    // 3. Add the appropriate class.
    // 4. Set el.style.display = "block".
    console.log(`[${success ? "OK" : "ERR"}] ${text}`);
}


// ═══════════════════════════════════════════════════════════════════════════
// Section Visibility
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Show only the specified section, hide the others.
 * @param {"init"|"unlock"|"dashboard"} section
 */
function showSection(section) {
    // TODO:
    // 1. Hide all three sections (add "hidden" class).
    // 2. Show the specified section (remove "hidden" class).
    // 3. Update status indicator text and class.
    console.log(`showSection(${section})`);
}


// ═══════════════════════════════════════════════════════════════════════════
// Initialization
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Handle vault initialization form submission.
 */
async function handleInit(event) {
    event.preventDefault();

    // TODO:
    // 1. Read form values from init inputs.
    // 2. POST to /api/init with InitRequest body.
    // 3. On success, show unlock section.
    // 4. On error, show error message.
    showMessage(els.initMessage, "initialize_vault not yet implemented", false);
}


// ═══════════════════════════════════════════════════════════════════════════
// Unlock
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Handle vault unlock form submission.
 */
async function handleUnlock(event) {
    event.preventDefault();

    // TODO:
    // 1. Read vault_id and passphrase from unlock inputs.
    // 2. Check if software-only mode is selected.
    // 3. POST to /api/unlock/software or /api/unlock/passphrase.
    // 4. On success, show dashboard section and load entries.
    // 5. On error, show error message.
    showMessage(els.unlockMessage, "unlock not yet implemented", false);
}


// ═══════════════════════════════════════════════════════════════════════════
// Lock
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Lock the vault and return to unlock section.
 */
async function handleLock() {
    // TODO:
    // 1. POST to /api/lock.
    // 2. Clear dashboard entries.
    // 3. Show unlock section.
    console.log("handleLock() not yet implemented");
}


// ═══════════════════════════════════════════════════════════════════════════
// Entries
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Load and render all credential entries.
 */
async function loadEntries() {
    // TODO:
    // 1. GET /api/entries.
    // 2. Render entries in the table.
    // 3. If no entries, show the no-entries message.
    console.log("loadEntries() not yet implemented");
}

/**
 * Render a list of entry objects into the entries table.
 * Passwords are masked by default with a reveal toggle.
 * @param {Array} entries
 */
function renderEntries(entries) {
    // TODO:
    // 1. Clear entries tbody.
    // 2. For each entry, create a table row with:
    //    - Site, Username, masked Password (with reveal button),
    //      Last Rotated, Actions (edit, delete).
    // 3. Attach event listeners for reveal, edit, delete.
    console.log("renderEntries() not yet implemented");
}

/**
 * Handle add credential form submission.
 */
async function handleAddEntry(event) {
    event.preventDefault();

    // TODO:
    // 1. Read site, username, password from add form.
    // 2. POST to /api/entries with AddEntryRequest body.
    // 3. On success, reload entries and clear form.
    // 4. On error, show error message.
    console.log("handleAddEntry() not yet implemented");
}

/**
 * Handle credential deletion.
 * @param {number} entryId
 */
async function handleDeleteEntry(entryId) {
    // TODO:
    // 1. Confirm deletion with user.
    // 2. DELETE /api/entries/{entryId}.
    // 3. On success, reload entries.
    console.log(`handleDeleteEntry(${entryId}) not yet implemented`);
}

/**
 * Search credentials by query.
 */
async function handleSearch() {
    // TODO:
    // 1. Read query from search input.
    // 2. GET /api/entries/search?q={query}.
    // 3. Render matching entries.
    console.log("handleSearch() not yet implemented");
}


// ═══════════════════════════════════════════════════════════════════════════
// Password Tools
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate a random password via the API.
 */
async function handleGeneratePassword() {
    // TODO:
    // 1. POST to /api/password/generate.
    // 2. Display result in generated-password-output.
    console.log("handleGeneratePassword() not yet implemented");
}

/**
 * Check password strength via the API.
 */
async function handleCheckStrength() {
    // TODO:
    // 1. Read password from strength-check-input.
    // 2. POST to /api/password/check.
    // 3. Display score/label in strength-result.
    console.log("handleCheckStrength() not yet implemented");
}


// ═══════════════════════════════════════════════════════════════════════════
// Status Polling
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Poll the /api/status endpoint to update UI state.
 */
async function pollStatus() {
    // TODO:
    // 1. GET /api/status.
    // 2. Update status indicator.
    // 3. Update hardware gate and passphrase window info.
    // 4. If session expired, switch to unlock section.
    console.log("pollStatus() not yet implemented");
}


// ═══════════════════════════════════════════════════════════════════════════
// Event Listeners
// ═══════════════════════════════════════════════════════════════════════════

document.addEventListener("DOMContentLoaded", () => {
    // Form submissions
    els.initForm?.addEventListener("submit", handleInit);
    els.unlockForm?.addEventListener("submit", handleUnlock);
    els.addEntryForm?.addEventListener("submit", handleAddEntry);

    // Buttons
    els.lockBtn?.addEventListener("click", handleLock);
    els.searchBtn?.addEventListener("click", handleSearch);
    els.generatePasswordBtn?.addEventListener("click", handleGeneratePassword);
    els.checkStrengthBtn?.addEventListener("click", handleCheckStrength);

    // Enter key on search
    els.searchInput?.addEventListener("keyup", (e) => {
        if (e.key === "Enter") handleSearch();
    });

    // Initial status check
    pollStatus();

    // Poll status every 10 seconds
    // setInterval(pollStatus, 10000);
});
