const API_BASE = "/api";

// Disable right-click and developer shortcuts
document.addEventListener('contextmenu', function(e) {
  e.preventDefault();
});

document.addEventListener('keydown', function(e) {
  // F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C
  if (e.key === 'F12' ||
      (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) ||
      // Ctrl+U (View Source), Ctrl+S (Save), Ctrl+Shift+S (Save As)
      (e.ctrlKey && (e.key === 'u' || e.key === 'U' || e.key === 's' || e.key === 'S')) ||
      // Ctrl+P (Print), Ctrl+Shift+P (Print Settings)
      (e.ctrlKey && (e.key === 'p' || e.key === 'P')) ||
      // Ctrl+Shift+K (Browser Console), Ctrl+Shift+E (Network)
      (e.ctrlKey && e.shiftKey && (e.key === 'K' || e.key === 'E')) ||
      // Ctrl+Shift+M (Responsive Design Mode)
      (e.ctrlKey && e.shiftKey && e.key === 'M') ||
      // Ctrl+Shift+D (Debugger)
      (e.ctrlKey && e.shiftKey && e.key === 'D') ||
      // Ctrl+Shift+F (Search in files)
      (e.ctrlKey && e.shiftKey && e.key === 'F') ||
      // Ctrl+Shift+O (Source)
      (e.ctrlKey && e.shiftKey && e.key === 'O')) {
    e.preventDefault();
  }
});

// Disable text selection
document.addEventListener('selectstart', function(e) {
  e.preventDefault();
});

// Disable copy
document.addEventListener('copy', function(e) {
  e.preventDefault();
});

// Disable cut
document.addEventListener('cut', function(e) {
  e.preventDefault();
});

// Disable paste
document.addEventListener('paste', function(e) {
  e.preventDefault();
});

// Add CSS to disable text selection via stylesheet
const style = document.createElement('style');
style.textContent = `
  * {
    -webkit-user-select: none !important;
    -moz-user-select: none !important;
    -ms-user-select: none !important;
    user-select: none !important;
  }
`;
document.head.appendChild(style);

// Hacker Loader
const hackerLoader = document.getElementById("hackerLoader");
const statusPercent = document.querySelector(".status-percent");
const statusText = document.querySelector(".status-text");
const loadingDots = document.querySelector(".loading-dots");

if (hackerLoader && statusPercent && statusText) {
  let progress = 0;
  const interval = setInterval(() => {
    progress += Math.floor(Math.random() * 3) + 1;
    if (progress >= 100) {
      progress = 100;
      clearInterval(interval);
      if (loadingDots) {
        loadingDots.style.display = "none";
      }
      statusText.innerHTML = "Connected Successfully";
      statusText.style.color = "#4ae2bc";
      // Hide loader after showing confirmation for 2 seconds
      setTimeout(() => {
        hackerLoader.classList.add("is-hidden");
      }, 2000);
    }
    statusPercent.textContent = progress + "%";
  }, 80);

  // Fallback: hide loader after 6.5 seconds regardless
  setTimeout(() => {
    if (!hackerLoader.classList.contains("is-hidden")) {
      hackerLoader.classList.add("is-hidden");
      clearInterval(interval);
    }
  }, 6500);
}

const attackToggle = document.getElementById("attackToggle");
const attackStatusText = document.getElementById("attackStatusText");
const runBtn = document.getElementById("runTransactionBtn");
const amountInput = document.getElementById("amount");
const transactionStepsDiv = document.getElementById("transactionSteps");
const riskAnalysisDiv = document.getElementById("riskAnalysis");
const threeLiesDiv = document.getElementById("threeLies");
const cryptoInfoDiv = document.getElementById("cryptoInfo");
const logListDiv = document.getElementById("logList");
const trustFlowDiv = document.getElementById("trustFlow");
const attackerNode = document.getElementById("attackerNode");
const middleLink = document.getElementById("middleLink");
const scenarioBanner = document.getElementById("scenarioBanner");
const telemetryGrid = document.getElementById("telemetryGrid");
const traceBoard = document.getElementById("traceBoard");
const attackerConsole = document.getElementById("attackerConsole");
const comparisonPanel = document.getElementById("comparisonPanel");
const demoSummary = document.getElementById("demoSummary");
const exportReportBtn = document.getElementById("exportReportBtn");
const metricsStrip = document.getElementById("metricsStrip");
const loginOverlay = document.getElementById("loginOverlay");
const loginForm = document.getElementById("loginForm");
const loginEmail = document.getElementById("loginEmail");
const loginPassword = document.getElementById("loginPassword");
const loginCode = document.getElementById("loginCode");
const loginCodeGroup = document.getElementById("loginCodeGroup");
const loginCodeSlots = Array.from(document.querySelectorAll(".code-slot"));
const loginSubmitBtn = document.getElementById("loginSubmitBtn");
const loginResetBtn = document.getElementById("loginResetBtn");
const loginCodeCountdown = document.getElementById("loginCodeCountdown");
const loginHint = document.getElementById("loginHint");
const loginError = document.getElementById("loginError");
const logoutModal = document.getElementById("logoutModal");
const cancelLogoutBtn = document.getElementById("cancelLogoutBtn");
const confirmLogoutBtn = document.getElementById("confirmLogoutBtn");
const idleWarningModal = document.getElementById("idleWarningModal");
const idleCountdownLabel = document.getElementById("idleCountdownLabel");
const idleWarningMessage = document.getElementById("idleWarningMessage");
const idleLogoutNowBtn = document.getElementById("idleLogoutNowBtn");
const staySignedInBtn = document.getElementById("staySignedInBtn");
const logoutBtn = document.getElementById("logoutBtn");
const authUserLabel = document.getElementById("authUserLabel");
const sessionExpiryLabel = document.getElementById("sessionExpiryLabel");
const sessionStatusChip = document.getElementById("sessionStatusChip");
const auditBoard = document.getElementById("auditBoard");
const passwordForm = document.getElementById("passwordForm");
const currentPassword = document.getElementById("currentPassword");
const newPassword = document.getElementById("newPassword");
const confirmPassword = document.getElementById("confirmPassword");
const passwordMessage = document.getElementById("passwordMessage");
const passwordToggleButtons = Array.from(document.querySelectorAll("[data-toggle-password]"));
const prevAuditPageBtn = document.getElementById("prevAuditPageBtn");
const nextAuditPageBtn = document.getElementById("nextAuditPageBtn");
const auditPageLabel = document.getElementById("auditPageLabel");
const prevPageBtn = document.getElementById("prevPageBtn");
const nextPageBtn = document.getElementById("nextPageBtn");
const pageLabel = document.getElementById("pageLabel");

let mitmActive = false;
let currentRun = null;
let baselineRun = null;
let attackRun = null;
let authToken = localStorage.getItem("emv_admin_token") || "";
let authUser = null;
let loginChallengeId = "";
let currentPage = 1;
let totalRuns = 0;
let currentAuditPage = 1;
let totalAuditRuns = 0;
let sessionClockTimer = null;
let inactivityWarningTimer = null;
let inactivityLogoutTimer = null;
let idleCountdownTimer = null;
let lastActivityAt = 0;
let idleDeadlineAt = 0;
let idleWarningOpen = false;
let loginCodeExpiresAt = 0;
let loginCodeCountdownTimer = null;
const PAGE_SIZE = 4;
const AUDIT_PAGE_SIZE = 4;
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const IDLE_WARNING_MS = 60 * 1000;

function authHeaders(extra = {}) {
  return authToken ? { ...extra, Authorization: `Bearer ${authToken}` } : extra;
}

function setAuthState(authenticated) {
  loginOverlay.classList.toggle("is-hidden", authenticated);
  logoutBtn.classList.toggle("is-hidden", !authenticated);
  sessionStatusChip.textContent = authenticated ? "Authenticated" : "Locked";
  sessionStatusChip.className = `status-chip ${authenticated ? "status-ok" : ""}`;
  if (!authenticated) {
    clearSessionTimers();
    setIdleWarningState(false);
    currentPage = 1;
    currentAuditPage = 1;
    authUserLabel.textContent = "Not signed in";
    sessionExpiryLabel.textContent = "Session inactive";
    resetLoginFlow();
  }
}

function resetLoginFlow() {
  window.clearInterval(loginCodeCountdownTimer);
  loginCodeCountdownTimer = null;
  loginCodeExpiresAt = 0;
  loginChallengeId = "";
  loginCode.value = "";
  setCodeSlots("");
  loginCodeGroup.classList.add("is-hidden");
  loginResetBtn.classList.add("is-hidden");
  loginCodeCountdown.classList.add("is-hidden");
  loginCode.required = false;
  loginEmail.disabled = false;
  loginPassword.disabled = false;
  loginSubmitBtn.textContent = "Send Verification Code";
  loginHint.textContent = "Step 1: enter your email and password to request an SMS code.";
}

function startLoginCodeCountdown(expiresAt) {
  window.clearInterval(loginCodeCountdownTimer);
  loginCodeExpiresAt = expiresAt ? new Date(expiresAt).getTime() : 0;

  if (!loginCodeExpiresAt) {
    loginCodeCountdown.classList.add("is-hidden");
    return;
  }

  const formatCountdown = (totalSeconds) => {
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
  };

  const renderCountdown = () => {
    const remainingSeconds = Math.max(0, Math.ceil((loginCodeExpiresAt - Date.now()) / 1000));
    loginCodeCountdown.textContent = `Verification code expires in ${formatCountdown(remainingSeconds)}.`;
    loginCodeCountdown.classList.remove("is-hidden");

    if (remainingSeconds <= 0) {
      window.clearInterval(loginCodeCountdownTimer);
      loginCodeCountdownTimer = null;
      loginChallengeId = "";
      loginCode.value = "";
      setCodeSlots("");
      loginCodeCountdown.textContent = "Verification code expired. Request a new code.";
      loginError.textContent = "Verification code expired. Request a new code.";
    }
  };

  renderCountdown();
  loginCodeCountdownTimer = window.setInterval(renderCountdown, 1000);
}

async function requestVerificationCode() {
  loginError.textContent = "";
  const payload = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: loginEmail.value,
      password: loginPassword.value,
    }),
  }).then(async (response) => {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.detail || "Invalid credentials");
    }
    return body;
  });

  loginChallengeId = payload.challenge_id;
  loginCode.value = "";
  setCodeSlots("");
  loginCodeGroup.classList.remove("is-hidden");
  loginResetBtn.classList.remove("is-hidden");
  loginCodeCountdown.classList.remove("is-hidden");
  loginCode.required = true;
  loginEmail.disabled = true;
  loginPassword.disabled = true;
  loginSubmitBtn.textContent = "Verify And Sign In";
  loginHint.textContent = payload.delivery?.channel === "sms"
    ? `Step 2: enter the code sent to ${payload.delivery.destination}.`
    : "Step 2: enter the code shown in the local server console debug output.";
  startLoginCodeCountdown(payload.expires_at);
  loginCodeSlots[0]?.focus();
}

function syncCodeValue() {
  loginCode.value = loginCodeSlots.map((slot) => slot.value).join("");
  const isInvalid = loginCode.value.length > 0 && loginCode.value.length < loginCodeSlots.length;
  loginCodeSlots.forEach((slot) => {
    slot.classList.toggle("code-slot-filled", slot.value !== "");
    slot.classList.toggle("code-slot-invalid", isInvalid);
  });
}

function setCodeSlots(code) {
  const digits = String(code || "").replace(/\D/g, "").slice(0, loginCodeSlots.length).split("");
  loginCodeSlots.forEach((slot, index) => {
    slot.value = digits[index] || "";
    slot.classList.remove("code-slot-invalid");
    slot.classList.toggle("code-slot-filled", slot.value !== "");
  });
  syncCodeValue();
}

function setLogoutModalState(open) {
  logoutModal.classList.toggle("is-hidden", !open);
  logoutModal.setAttribute("aria-hidden", open ? "false" : "true");
}

function setIdleWarningState(open) {
  idleWarningOpen = open;
  idleWarningModal.classList.toggle("is-hidden", !open);
  idleWarningModal.setAttribute("aria-hidden", open ? "false" : "true");
}

function formatExactDateTime(value) {
  if (!value) return "Unknown";
  const date = new Date(value);
  const day = String(date.getDate()).padStart(2, "0");
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const year = date.getFullYear();
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const seconds = String(date.getSeconds()).padStart(2, "0");
  return `${day}/${month}/${year}, ${hours}:${minutes}:${seconds}`;
}

function clearSessionTimers() {
  window.clearInterval(sessionClockTimer);
  window.clearTimeout(inactivityWarningTimer);
  window.clearTimeout(inactivityLogoutTimer);
  window.clearInterval(idleCountdownTimer);
  sessionClockTimer = null;
  inactivityWarningTimer = null;
  inactivityLogoutTimer = null;
  idleCountdownTimer = null;
}

function renderSessionStatus() {
  if (!authUser?.expires_at) {
    sessionExpiryLabel.textContent = "Session inactive";
    return;
  }

  const expiryMs = new Date(authUser.expires_at).getTime();
  const now = Date.now();
  const idleRemainingMs = Math.max(0, IDLE_TIMEOUT_MS - (now - lastActivityAt));
  const idleRemainingSeconds = Math.ceil(idleRemainingMs / 1000);
  sessionExpiryLabel.textContent = `Session expires ${formatExactDateTime(authUser.expires_at)}. If inactive for five minutes, the session will automatically log out. Idle timeout in ${idleRemainingSeconds}s.`;

  if (expiryMs <= now) {
    forceLogout("Session expired");
  }
}

function openIdleWarning() {
  idleDeadlineAt = Date.now() + IDLE_WARNING_MS;
  setIdleWarningState(true);
  idleWarningMessage.textContent = "No activity has been detected. The dashboard will lock automatically after five minutes of inactivity.";
  window.clearInterval(idleCountdownTimer);
  idleCountdownTimer = window.setInterval(() => {
    const remainingSeconds = Math.max(0, Math.ceil((idleDeadlineAt - Date.now()) / 1000));
    idleCountdownLabel.textContent = String(remainingSeconds);
  }, 250);
  idleCountdownLabel.textContent = "60";
}

function scheduleInactivityTimers() {
  clearSessionTimers();
  renderSessionStatus();
  sessionClockTimer = window.setInterval(renderSessionStatus, 1000);
  inactivityWarningTimer = window.setTimeout(openIdleWarning, IDLE_TIMEOUT_MS - IDLE_WARNING_MS);
  inactivityLogoutTimer = window.setTimeout(() => forceLogout("Logged out after five minutes of inactivity"), IDLE_TIMEOUT_MS);
}

function markActivity() {
  if (!authToken || idleWarningOpen) {
    return;
  }
  lastActivityAt = Date.now();
  scheduleInactivityTimers();
}

async function forceLogout(reason = "Logged out") {
  clearSessionTimers();
  setIdleWarningState(false);
  setLogoutModalState(false);
  try {
    if (authToken) {
      await fetch(`${API_BASE}/auth/logout`, {
        method: "POST",
        headers: authHeaders(),
      });
    }
  } catch (_error) {
    // Best effort logout. The UI still needs to lock immediately.
  } finally {
    authToken = "";
    authUser = null;
    localStorage.removeItem("emv_admin_token");
    setAuthState(false);
    loginError.textContent = reason;
    loginPassword.focus();
  }
}

function updatePagination(total = totalRuns, entriesCount = 0) {
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (currentPage > totalPages) {
    currentPage = totalPages;
  }

  const hasEntries = total > 0 || entriesCount > 0;
  pageLabel.textContent = hasEntries ? `Page ${currentPage} of ${totalPages} · 4 items per page` : "Page 1 of 1 · 4 items per page";
  prevPageBtn.disabled = currentPage <= 1;
  nextPageBtn.disabled = currentPage >= totalPages || !hasEntries;
}

function updateAuditPagination(total = totalAuditRuns, entriesCount = 0) {
  const totalPages = Math.max(1, Math.ceil(total / AUDIT_PAGE_SIZE));
  if (currentAuditPage > totalPages) {
    currentAuditPage = totalPages;
  }

  const hasEntries = total > 0 || entriesCount > 0;
  auditPageLabel.textContent = hasEntries
    ? `Page ${currentAuditPage} of ${totalPages} · 4 items per page`
    : "Page 1 of 1 · 4 items per page";
  prevAuditPageBtn.disabled = currentAuditPage <= 1;
  nextAuditPageBtn.disabled = currentAuditPage >= totalPages || !hasEntries;
}

function formatDateTime(value) {
  if (!value) return "Unknown";
  return new Date(value).toLocaleString();
}

function updateAuthBanner() {
  if (!authUser) {
    authUserLabel.textContent = "Not signed in";
    sessionExpiryLabel.textContent = "Session inactive";
    return;
  }

  authUserLabel.textContent = `${authUser.email} (${authUser.role})`;
  renderSessionStatus();
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload),
  });
  const body = await response.json().catch(() => ({}));
  if (response.status === 401) {
    authToken = "";
    authUser = null;
    localStorage.removeItem("emv_admin_token");
    setAuthState(false);
    throw new Error(body.detail || "Authentication required");
  }
  if (!response.ok) {
    throw new Error(body.detail || `Request failed: ${response.status}`);
  }
  return body;
}

async function getJson(url) {
  const response = await fetch(url, { headers: authHeaders() });
  const body = await response.json().catch(() => ({}));
  if (response.status === 401) {
    authToken = "";
    authUser = null;
    localStorage.removeItem("emv_admin_token");
    setAuthState(false);
    throw new Error(body.detail || "Authentication required");
  }
  if (!response.ok) {
    throw new Error(body.detail || `Request failed: ${response.status}`);
  }
  return body;
}

function setAttackState(active) {
  mitmActive = active;
  attackToggle.checked = active;
  attackStatusText.textContent = active ? "ACTIVE" : "INACTIVE";
  attackStatusText.className = active ? "status-active" : "status-inactive";
  trustFlowDiv.className = `trust-flow ${active ? "trust-flow-attack" : "trust-flow-safe"}`;
  attackerNode.className = `flow-node attacker-node ${active ? "attacker-active" : "attacker-idle"}`;
  middleLink.className = `flow-link ${active ? "flow-link-attack" : ""}`;
  scenarioBanner.className = `scenario-banner ${active ? "attack-banner" : "safe-banner"}`;
  scenarioBanner.textContent = active
    ? "MITM mode armed in the simulator: the attacker sits between card and terminal and alters unsigned verification fields."
    : "Normal flow: the terminal trusts the card and sees verified CVM data.";
  attackerNode.querySelector("span:last-child").textContent = active ? "Intercepting path" : "Inactive";
}

function displayTelemetry(transactionData, riskAnalysis, attackActive) {
  const tiles = [
    ["CVM", transactionData?.cvm || "Unknown"],
    ["Device Claim", transactionData?.device_verified ? "Verified" : "Not verified"],
    ["Actual Verification", transactionData?.actual_verification ? "Performed" : "Not performed"],
    ["Trust Outcome", riskAnalysis ? `${riskAnalysis.risk_level} / ${attackActive ? "Compromised" : "Observed"}` : "Waiting"],
  ];

  telemetryGrid.innerHTML = tiles
    .map(([label, value]) => `
      <article class="telemetry-tile ${attackActive && label !== "CVM" ? "telemetry-hot" : ""}">
        <span class="tile-label">${label}</span>
        <strong>${value}</strong>
      </article>
    `)
    .join("");
}

function displayMetrics(metrics) {
  const latest = metrics.latest_run
    ? `${metrics.latest_run.transaction_type} / ${metrics.latest_run.risk_level}`
    : "No runs yet";

  metricsStrip.innerHTML = `
    <article class="metric-card">
      <span class="tile-label">Database</span>
      <strong>${metrics.database.engine.toUpperCase()}</strong>
      <p>${latest}</p>
    </article>
    <article class="metric-card">
      <span class="tile-label">Total Runs</span>
      <strong>${metrics.total_runs}</strong>
      <p>Stored in SQL</p>
    </article>
    <article class="metric-card">
      <span class="tile-label">Attack Detections</span>
      <strong>${metrics.detections}</strong>
      <p>Flagged by risk engine</p>
    </article>
    <article class="metric-card">
      <span class="tile-label">Average Risk</span>
      <strong>${metrics.average_risk}</strong>
      <p>Across all runs</p>
    </article>
    <article class="metric-card">
      <span class="tile-label">Active Sessions</span>
      <strong>${metrics.active_sessions}</strong>
      <p>Current admin tokens</p>
    </article>
    <article class="metric-card">
      <span class="tile-label">Audit Events</span>
      <strong>${metrics.audit_events}</strong>
      <p>Recorded backend actions</p>
    </article>
  `;
}

function displayAuditLogs(entries) {
  if (!entries.length) {
    auditBoard.innerHTML = `<div class="empty">No audit events available.</div>`;
    updateAuditPagination(totalAuditRuns, 0);
    return;
  }

  auditBoard.innerHTML = entries
    .map((entry) => `
      <article class="trace-entry ${entry.status === "failed" ? "trace-danger" : ""}">
        <div class="trace-index">${entry.id}</div>
        <div class="trace-body">
          <div class="trace-meta">${entry.action} · ${entry.status}</div>
          <strong>${entry.email || "system"}</strong>
          <div class="trace-detail">${entry.detail}</div>
          <div class="trace-detail">${formatDateTime(entry.created_at)}</div>
        </div>
      </article>
    `)
    .join("");

  updateAuditPagination(totalAuditRuns, entries.length);
}

function buildTraceEntries(data) {
  const amount = Number(data.transaction_data?.amount || 0).toLocaleString();
  const shared = [
    {
      actor: "Terminal",
      code: "00A40400",
      title: "Application selection",
      detail: "Terminal selects payment application on the card path.",
    },
    {
      actor: "Terminal",
      code: "80A80000",
      title: "Get processing options",
      detail: "Terminal requests processing profile and CVM-related behavior.",
    },
  ];

  if (data.attack_active) {
    shared.push(
      {
        actor: "Attacker",
        code: "MOD-CVM",
        title: "Unsigned fields altered",
        detail: "CVM changed to NO_VERIFICATION while device claim remains trusted.",
        danger: true,
      },
      {
        actor: "Terminal",
        code: "VERIFY",
        title: "Terminal accepts modified claims",
        detail: "Terminal reads verification context that no longer reflects reality.",
      },
    );
  } else {
    shared.push({
      actor: "Card",
      code: "CVM-OK",
      title: "PIN verification result",
      detail: "Card path reports successful verified cardholder method.",
    });
  }

  shared.push({
    actor: "Bank",
    code: "AUTH",
    title: `Authorization for ${amount}`,
    detail: data.risk_analysis.is_attack_detected
      ? "Issuer-side controls would need anomaly detection to stop this pattern."
      : "Authorization proceeds because the verification story appears consistent.",
    danger: data.risk_analysis.is_attack_detected,
  });

  return shared;
}

function displayTrace(data) {
  const entries = buildTraceEntries(data);
  traceBoard.innerHTML = entries
    .map((entry, index) => `
      <article class="trace-entry ${entry.danger ? "trace-danger" : ""}">
        <div class="trace-index">${index + 1}</div>
        <div class="trace-body">
          <div class="trace-meta">${entry.actor} · ${entry.code}</div>
          <strong>${entry.title}</strong>
          <div class="trace-detail">${entry.detail}</div>
        </div>
      </article>
    `)
    .join("");
}

function displayAttackerConsole(data) {
  if (!data.attack_active || !data.attack_log) {
    attackerConsole.innerHTML = `<div class="empty">MITM console is idle. Run the attack mode to show field tampering.</div>`;
    return;
  }

  attackerConsole.innerHTML = data.attack_log.modifications
    .map((item, index) => `
      <article class="console-entry">
        <div class="trace-meta">Event ${index + 1} · ${item.field}</div>
        <strong>${item.original !== undefined ? `${item.original} -> ${item.modified}` : "Injected modified response"}</strong>
        <div class="trace-detail">${item.timestamp}</div>
      </article>
    `)
    .join("");
}

function renderComparisonCard(title, run, emptyText) {
  if (!run) {
    return `
      <article class="comparison-card">
        <span class="tile-label">${title}</span>
        <strong>Waiting</strong>
        <p>${emptyText}</p>
      </article>
    `;
  }

  return `
    <article class="comparison-card ${run.attack_active ? "comparison-attack" : "comparison-safe"}">
      <span class="tile-label">${title}</span>
      <strong>${run.risk_analysis.risk_level} · ${run.risk_analysis.risk_score}%</strong>
      <p>CVM: ${run.transaction_data.cvm}</p>
      <p>Actual verification: ${run.transaction_data.actual_verification ? "Performed" : "Not performed"}</p>
      <p>Recommendation: ${run.risk_analysis.recommendation}</p>
    </article>
  `;
}

function displayComparison() {
  comparisonPanel.innerHTML = [
    renderComparisonCard("Normal Flow", baselineRun, "Run a normal transaction to capture the baseline."),
    renderComparisonCard("Attack Flow", attackRun, "Run an MITM transaction to show the compromised path."),
  ].join("");
}

function displayDemoSummary(data) {
  const items = [
    ["Threat Model", data.attack_active ? "Attacker now sits inline between card and terminal." : "Trusted path is direct between card and terminal."],
    ["Verification Story", `CVM=${data.transaction_data.cvm} and actual verification=${data.transaction_data.actual_verification ? "performed" : "not performed"}.`],
    ["Issuer Outcome", `${data.risk_analysis.risk_level} risk with recommendation: ${data.risk_analysis.recommendation}`],
    ["Research Insight", data.attack_active ? "Unsigned verification context is the weak link in this demonstration." : "Baseline shows what the system expects when claims and reality match."],
  ];

  demoSummary.innerHTML = items
    .map(([label, text]) => `
      <article class="summary-card">
        <span class="tile-label">${label}</span>
        <p>${text}</p>
      </article>
    `)
    .join("");
}

function displaySteps(steps) {
  transactionStepsDiv.innerHTML = steps
    .map((step) => {
      const isCritical = step.status.includes("FRAUD");
      const isAttack = isCritical || step.status.includes("MITM") || step.status.includes("BYPASSED");
      const stepClass = isCritical ? "critical" : isAttack ? "attack" : "";
      return `
        <article class="step ${stepClass}">
          <div class="step-status">${step.status} · ${step.step}</div>
          <div class="step-detail">${step.detail}</div>
          ${step.attack_lie ? `<div class="step-lie">${step.attack_lie}</div>` : ""}
        </article>
      `;
    })
    .join("");
}

function displayRisk(risk) {
  const riskClass =
    risk.risk_level === "CRITICAL" ? "risk-critical" :
    risk.risk_level === "HIGH" ? "risk-high" :
    "risk-low";

  const riskItems = risk.risks.length
    ? risk.risks.map((item) => `<div class="risk-item">${item.message}</div>`).join("")
    : `<div class="risk-item">No abnormal indicators found.</div>`;

  riskAnalysisDiv.innerHTML = `
    <div class="risk-score ${riskClass}">${risk.risk_score}% · ${risk.risk_level}</div>
    <div class="risk-item"><strong>Recommendation:</strong> ${risk.recommendation}</div>
    ${riskItems}
    ${risk.is_attack_detected ? '<div class="risk-item attack-banner">Attack detected: MITM pattern identified</div>' : ""}
  `;
}

function displayLogs(entries) {
  if (!entries.length) {
    logListDiv.innerHTML = `<div class="empty">No transactions logged yet.</div>`;
    updatePagination(totalRuns, 0);
    return;
  }

  logListDiv.innerHTML = entries
    .map((entry) => `
      <article class="log-entry">
        <div class="log-row">
          <strong>${entry.transaction_type || "UNKNOWN"}</strong>
          <span>${entry.risk_analysis?.risk_level || "UNKNOWN"} · ${entry.risk_analysis?.risk_score ?? 0}%</span>
        </div>
        <div class="log-row muted">
          <span>Amount: ${Number(entry.transaction_data?.amount || 0).toLocaleString()}</span>
          <span>Attack active: ${entry.attack_active ? "Yes" : "No"}</span>
        </div>
        <div class="log-row muted">
          <span>CVM: ${entry.transaction_data?.cvm || "Unknown"}</span>
          <span>Actual verification: ${entry.transaction_data?.actual_verification ? "Performed" : "Not performed"}</span>
        </div>
      </article>
    `)
    .join("");

  updatePagination(totalRuns, entries.length);
}

function displayThreeLies(payload) {
  threeLiesDiv.innerHTML = payload.lies
    .map((lie) => `
      <article class="lie">
        <div class="lie-title">${lie.name}: ${lie.claim}</div>
        <div class="lie-copy">${lie.reality}</div>
        <div class="lie-mitigation">Mitigation: ${lie.mitigation}</div>
      </article>
    `)
    .join("");
}

function displayCryptoInfo(vulnerability, demo) {
  cryptoInfoDiv.innerHTML = `
    <p><strong>Signed fields:</strong> ${vulnerability.signed_fields.join(", ")}</p>
    <p><strong>Unsigned fields:</strong> ${vulnerability.unsigned_fields.join(", ")}</p>
    <p><strong>Vulnerability:</strong> ${vulnerability.vulnerability}</p>
    <p><strong>Attack path:</strong> ${vulnerability.attack}</p>
    <hr />
    <p><strong>Original signature valid:</strong> ${demo.original_signature_valid}</p>
    <p><strong>Modified signature valid:</strong> ${demo.modified_signature_valid}</p>
    <p><strong>Explanation:</strong> ${demo.explanation}</p>
  `;
}

async function runTransaction() {
  const amount = Number.parseInt(amountInput.value, 10) || 10000;
  transactionStepsDiv.innerHTML = `<div class="step empty">Processing transaction...</div>`;
  riskAnalysisDiv.innerHTML = `<div class="empty">Analyzing risk...</div>`;
  displayTelemetry(null, null, mitmActive);

  const endpoint = mitmActive ? `${API_BASE}/transaction/attack` : `${API_BASE}/transaction/normal`;
  const data = await postJson(endpoint, { amount, attack_enabled: mitmActive });
  currentRun = data;
  if (data.attack_active) {
    attackRun = data;
  } else {
    baselineRun = data;
  }
  currentPage = 1;

  displaySteps(data.steps);
  displayRisk(data.risk_analysis);
  displayTelemetry(data.transaction_data, data.risk_analysis, data.attack_active);
  displayTrace(data);
  displayAttackerConsole(data);
  displayComparison();
  displayDemoSummary(data);
  await loadLogs();
}

async function loadLogs() {
  const offset = (currentPage - 1) * PAGE_SIZE;
  const auditOffset = (currentAuditPage - 1) * AUDIT_PAGE_SIZE;
  const [entries, metrics, audit, txMeta, auditMeta] = await Promise.all([
    getJson(`${API_BASE}/transactions?limit=${PAGE_SIZE}&offset=${offset}`),
    getJson(`${API_BASE}/metrics`),
    getJson(`${API_BASE}/audit?limit=${AUDIT_PAGE_SIZE}&offset=${auditOffset}`),
    getJson(`${API_BASE}/transactions/meta`),
    getJson(`${API_BASE}/audit/meta`),
  ]);
  totalRuns = txMeta.total;
  totalAuditRuns = auditMeta.total;
  displayLogs(entries);
  displayMetrics(metrics);
  displayAuditLogs(audit);
}

async function initialize() {
  if (!authToken) {
    setAuthState(false);
    return;
  }

  const offset = (currentPage - 1) * PAGE_SIZE;
  const auditOffset = (currentAuditPage - 1) * AUDIT_PAGE_SIZE;
  const [me, status, lies, vulnerability, demo, logs, metrics, audit, txMeta, auditMeta] = await Promise.all([
    getJson(`${API_BASE}/auth/me`),
    getJson(`${API_BASE}/mitm/status`),
    getJson(`${API_BASE}/the-three-lies`),
    getJson(`${API_BASE}/crypto/vulnerability`),
    getJson(`${API_BASE}/crypto/demo`),
    getJson(`${API_BASE}/transactions?limit=${PAGE_SIZE}&offset=${offset}`),
    getJson(`${API_BASE}/metrics`),
    getJson(`${API_BASE}/audit?limit=${AUDIT_PAGE_SIZE}&offset=${auditOffset}`),
    getJson(`${API_BASE}/transactions/meta`),
    getJson(`${API_BASE}/audit/meta`),
  ]);

  authUser = me;
  totalRuns = txMeta.total;
  totalAuditRuns = auditMeta.total;
  lastActivityAt = Date.now();
  setAttackState(Boolean(status.attack_active));
  updateAuthBanner();
  displayThreeLies(lies);
  displayCryptoInfo(vulnerability, demo);
  displayLogs(logs);
  displayMetrics(metrics);
  displayAuditLogs(audit);
  displayTelemetry(null, null, Boolean(status.attack_active));
  displayComparison();
  setAuthState(true);
  scheduleInactivityTimers();
}

function exportCurrentRun() {
  if (!currentRun) {
    return;
  }

  const blob = new Blob([JSON.stringify(currentRun, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  link.href = url;
  link.download = `emv-mitm-report-${timestamp}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

attackToggle.addEventListener("change", async (event) => {
  const enabled = event.target.checked;
  await postJson(`${API_BASE}/mitm/control`, { enabled });
  setAttackState(enabled);
});

runBtn.addEventListener("click", () => {
  runTransaction().catch((error) => {
    transactionStepsDiv.innerHTML = `<div class="step empty">Failed to run transaction: ${error.message}</div>`;
    riskAnalysisDiv.innerHTML = `<div class="empty">Request failed.</div>`;
  });
});

exportReportBtn.addEventListener("click", exportCurrentRun);

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginError.textContent = "";
  try {
    if (!loginChallengeId) {
      await requestVerificationCode();
      return;
    }

    syncCodeValue();
    if (loginCode.value.length !== loginCodeSlots.length) {
      loginError.textContent = "Enter the full 6-digit verification code.";
      loginCodeSlots.find((slot) => !slot.value)?.focus();
      return;
    }

    const payload = await fetch(`${API_BASE}/auth/verify-2fa`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challenge_id: loginChallengeId,
        code: loginCode.value.trim(),
      }),
    }).then(async (response) => {
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.detail || "Invalid verification code");
      }
      return body;
    });

    authToken = payload.token;
    currentPage = 1;
    currentAuditPage = 1;
    localStorage.setItem("emv_admin_token", authToken);
    window.clearInterval(loginCodeCountdownTimer);
    loginCodeCountdownTimer = null;
    await initialize();
  } catch (error) {
    loginError.textContent = error.message;
  }
});

loginResetBtn.addEventListener("click", async () => {
  loginError.textContent = "";
  try {
    await requestVerificationCode();
    loginHint.textContent += " A new code has been sent.";
  } catch (error) {
    loginError.textContent = error.message;
  }
});

loginCodeSlots.forEach((slot, index) => {
  slot.addEventListener("input", (event) => {
    const digits = event.target.value.replace(/\D/g, "");
    if (!digits) {
      event.target.value = "";
      syncCodeValue();
      return;
    }

    if (digits.length > 1) {
      setCodeSlots(loginCodeSlots.map((item) => item.value).join("").slice(0, index) + digits);
      const nextIndex = Math.min(index + digits.length, loginCodeSlots.length - 1);
      loginCodeSlots[nextIndex]?.focus();
      return;
    }

    event.target.value = digits;
    syncCodeValue();
    loginCodeSlots[index + 1]?.focus();
  });

  slot.addEventListener("keydown", (event) => {
    if (event.key === "Backspace" && !slot.value && index > 0) {
      loginCodeSlots[index - 1].focus();
      loginCodeSlots[index - 1].value = "";
      syncCodeValue();
    }

    if (event.key === "ArrowLeft" && index > 0) {
      event.preventDefault();
      loginCodeSlots[index - 1].focus();
    }

    if (event.key === "ArrowRight" && index < loginCodeSlots.length - 1) {
      event.preventDefault();
      loginCodeSlots[index + 1].focus();
    }
  });

  slot.addEventListener("focus", () => {
    slot.select();
  });

  slot.addEventListener("paste", (event) => {
    event.preventDefault();
    const pasted = event.clipboardData?.getData("text") || "";
    setCodeSlots(pasted);
    const nextEmpty = loginCodeSlots.find((item) => !item.value);
    (nextEmpty || loginCodeSlots[loginCodeSlots.length - 1])?.focus();
  });
});

logoutBtn.addEventListener("click", async () => {
  setLogoutModalState(true);
});

cancelLogoutBtn.addEventListener("click", () => {
  setLogoutModalState(false);
});

confirmLogoutBtn.addEventListener("click", async () => {
  await forceLogout("Logged out");
});

logoutModal.addEventListener("click", (event) => {
  if (event.target === logoutModal) {
    setLogoutModalState(false);
  }
});

staySignedInBtn.addEventListener("click", () => {
  setIdleWarningState(false);
  lastActivityAt = Date.now();
  scheduleInactivityTimers();
});

idleLogoutNowBtn.addEventListener("click", async () => {
  await forceLogout("Logged out");
});

["mousedown", "keydown", "mousemove", "scroll", "touchstart", "click"].forEach((eventName) => {
  document.addEventListener(eventName, markActivity, { passive: true });
});

passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  passwordMessage.textContent = "";
  passwordMessage.classList.remove("status-success");
  if (newPassword.value !== confirmPassword.value) {
    passwordMessage.textContent = "New password confirmation does not match.";
    return;
  }
  try {
    await postJson(`${API_BASE}/auth/change-password`, {
      current_password: currentPassword.value,
      new_password: newPassword.value,
    });
    passwordMessage.textContent = "Password updated successfully. Redirecting to sign in again.";
    passwordMessage.classList.add("status-success");
    currentPassword.value = "";
    newPassword.value = "";
    confirmPassword.value = "";
    window.setTimeout(() => {
      forceLogout("Password updated. Sign in again with your new password.");
    }, 1200);
  } catch (error) {
    passwordMessage.classList.remove("status-success");
    passwordMessage.textContent = error.message;
  }
});

passwordToggleButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const targetId = button.dataset.togglePassword;
    const input = document.getElementById(targetId);
    if (!input) return;
    const isPassword = input.type === "password";
    input.type = isPassword ? "text" : "password";
    button.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
    const icon = button.querySelector(".input-toggle-icon");
    if (icon) {
      icon.textContent = isPassword ? "🙈" : "👁";
    }
  });
});

prevPageBtn.addEventListener("click", async () => {
  if (currentPage <= 1) return;
  currentPage -= 1;
  await loadLogs();
});

nextPageBtn.addEventListener("click", async () => {
  const totalPages = Math.max(1, Math.ceil(totalRuns / PAGE_SIZE));
  if (currentPage >= totalPages) return;
  currentPage += 1;
  await loadLogs();
});

prevAuditPageBtn.addEventListener("click", async () => {
  if (currentAuditPage <= 1) return;
  currentAuditPage -= 1;
  await loadLogs();
});

nextAuditPageBtn.addEventListener("click", async () => {
  const totalPages = Math.max(1, Math.ceil(totalAuditRuns / AUDIT_PAGE_SIZE));
  if (currentAuditPage >= totalPages) return;
  currentAuditPage += 1;
  await loadLogs();
});

initialize().catch((error) => {
  transactionStepsDiv.innerHTML = `<div class="step empty">Failed to load simulator data: ${error.message}</div>`;
});
