/**
 * SentinelAI Desktop v1.4.0 - Main JavaScript
 * Handles UI interactions and communication with Tauri backend
 * Features: Hybrid ML detection, AI analysis, autostart, settings
 */

// Check if running in Tauri
const isTauri = window.__TAURI__ !== undefined;

// Tauri invoke helper - works with both Tauri 1.x and 2.x
async function invoke(cmd, args = {}) {
    if (!isTauri) return null;
    try {
        // Tauri 2.x
        if (window.__TAURI__.core && window.__TAURI__.core.invoke) {
            return await window.__TAURI__.core.invoke(cmd, args);
        }
        // Tauri 1.x fallback
        if (window.__TAURI__.invoke) {
            return await window.__TAURI__.invoke(cmd, args);
        }
        // Try tauri module
        if (window.__TAURI__.tauri && window.__TAURI__.tauri.invoke) {
            return await window.__TAURI__.tauri.invoke(cmd, args);
        }
        console.error('No invoke method found');
        return null;
    } catch (e) {
        console.error(`Invoke ${cmd} failed:`, e);
        throw e;
    }
}

// Dashboard URL - will be fetched from backend for SaaS
// Use external IP for distributed deployment
let DASHBOARD_URL = 'http://148.170.66.162:8015';

// State
let agentStatus = {
    running: false,
    threats_blocked: 0,
    active_threats: 0,
    processes_monitored: 0,
    connections: 0,
    events: []
};

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    console.log('SentinelAI Desktop initializing...');
    console.log('Tauri available:', isTauri);
    console.log('Tauri object:', window.__TAURI__);
    
    // Get dashboard URL from backend (for SaaS deployment)
    if (isTauri) {
        try {
            const url = await invoke('get_dashboard_url');
            if (url) DASHBOARD_URL = url;
            console.log('Dashboard URL:', DASHBOARD_URL);
        } catch (e) {
            console.log('Using default dashboard URL:', e);
        }
    }
    
    setupNavigation();
    setupTitlebar();
    setupButtons();
    setupAgentControls();
    
    // Auto-start agent after short delay
    if (isTauri) {
        setTimeout(autoStartAgent, 1000);
    }
    
    // Start polling for updates
    setInterval(updateStatus, 5000);
    setInterval(checkAgentStatus, 5000);
    updateStatus();
    checkAgentStatus();
});

/**
 * Auto-start the embedded agent
 */
async function autoStartAgent() {
    console.log('Auto-starting agent...');
    try {
        const result = await invoke('start_agent', { dashboard_url: null });
        console.log('Agent auto-start result:', result);
        if (result) {
            updateAgentIndicator(true);
            showToast('Agent started successfully');
        }
    } catch (error) {
        console.error('Failed to auto-start agent:', error);
        showToast('Failed to start agent: ' + error, 'error');
    }
}

/**
 * Start agent manually
 */
async function startAgentManual() {
    console.log('Starting agent manually...');
    const btn = document.getElementById('start-agent-btn');
    if (btn) {
        btn.innerHTML = '<i class="bi bi-hourglass-split me-2"></i>Starting...';
        btn.disabled = true;
    }
    
    try {
        const result = await invoke('start_agent', { dashboard_url: null });
        console.log('Start result:', result);
        showToast(result || 'Agent started');
        updateAgentIndicator(true);
        if (btn) {
            btn.innerHTML = '<i class="bi bi-stop-fill me-2"></i>Stop Agent';
            btn.style.background = '#dc3545';
            btn.disabled = false;
            btn.onclick = stopAgentManual;
        }
    } catch (error) {
        console.error('Start failed:', error);
        showToast('Start failed: ' + error, 'error');
        if (btn) {
            btn.innerHTML = '<i class="bi bi-play-fill me-2"></i>Start Agent';
            btn.disabled = false;
        }
    }
}

/**
 * Stop agent manually
 */
async function stopAgentManual() {
    console.log('Stopping agent...');
    try {
        const result = await invoke('stop_agent');
        showToast(result || 'Agent stopped');
        updateAgentIndicator(false);
        const btn = document.getElementById('start-agent-btn');
        if (btn) {
            btn.innerHTML = '<i class="bi bi-play-fill me-2"></i>Start Agent';
            btn.style.background = '#00d26a';
            btn.onclick = () => startAgentManual();
        }
    } catch (error) {
        showToast('Stop failed: ' + error, 'error');
    }
}

// Expose to window for onclick
window.startAgentManual = startAgentManual;
window.stopAgentManual = stopAgentManual;

/**
 * Setup agent control buttons
 */
function setupAgentControls() {
    // Start agent button
    document.getElementById('start-agent-btn')?.addEventListener('click', startAgentManual);
    
    // Stop agent button (if exists separately)
    document.getElementById('stop-agent-btn')?.addEventListener('click', stopAgentManual);
}

/**
 * Check if embedded agent is running
 */
async function checkAgentStatus() {
    if (!isTauri) return;
    
    try {
        const running = await invoke('is_agent_running');
        console.log('Agent running:', running);
        updateAgentIndicator(running);
        
        // Update button state based on agent status
        const btn = document.getElementById('start-agent-btn');
        if (btn) {
            if (running) {
                btn.innerHTML = '<i class="bi bi-stop-fill me-2"></i>Stop Agent';
                btn.style.background = '#dc3545';
                btn.onclick = stopAgentManual;
            } else {
                btn.innerHTML = '<i class="bi bi-play-fill me-2"></i>Start Agent';
                btn.style.background = '#00d26a';
                btn.onclick = startAgentManual;
            }
        }
    } catch (error) {
        console.debug('Agent status check failed:', error);
    }
}

/**
 * Update agent indicator in UI
 */
function updateAgentIndicator(running) {
    const icon = document.getElementById('protection-icon');
    const title = document.getElementById('protection-title');
    const subtitle = document.getElementById('protection-subtitle');
    
    if (running) {
        if (icon) {
            icon.className = 'protection-icon protected';
            icon.innerHTML = '<i class="bi bi-shield-fill-check"></i>';
        }
        if (title) title.textContent = 'Protected';
        if (subtitle) subtitle.textContent = 'Agent is running and monitoring';
    } else {
        if (icon) {
            icon.className = 'protection-icon warning';
            icon.innerHTML = '<i class="bi bi-shield-exclamation"></i>';
        }
        if (title) title.textContent = 'Not Connected';
        if (subtitle) subtitle.textContent = 'Agent not running - click to start';
    }
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    console.log(`[${type}] ${message}`);
    // Create toast element
    let toast = document.getElementById('toast-notification');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast-notification';
        toast.style.cssText = `
            position: fixed;
            bottom: 80px;
            right: 20px;
            padding: 12px 20px;
            background: ${type === 'error' ? '#dc3545' : '#0f3460'};
            color: white;
            border-radius: 8px;
            z-index: 9999;
            transition: opacity 0.3s;
        `;
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.opacity = '1';
    setTimeout(() => { toast.style.opacity = '0'; }, 3000);
}

/**
 * Add entry to activity log
 */
function addLogEntry(level, message) {
    const logBox = document.getElementById('activity-log');
    if (!logBox) return;
    
    const time = new Date().toLocaleTimeString();
    const levelClass = level.toLowerCase();
    
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `<span class="log-time">${time}</span> <span class="log-${levelClass}">[${level}]</span> ${message}`;
    
    logBox.insertBefore(entry, logBox.firstChild);
    
    // Keep only last 50 entries
    while (logBox.children.length > 50) {
        logBox.removeChild(logBox.lastChild);
    }
}

/**
 * Setup navigation
 */
function setupNavigation() {
    const pages = {
        'dashboard': { name: 'Dashboard', hasPage: true },
        'threats': { name: 'Threats', hasPage: false, openDashboard: true },
        'monitors': { name: 'Monitors', hasPage: true },
        'firewall': { name: 'Firewall', hasPage: false, openDashboard: true },
        'settings': { name: 'Settings', hasPage: true }
    };
    
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
        item.addEventListener('click', () => {
            const page = item.dataset.page;
            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            
            const pageConfig = pages[page];
            
            // Handle page switching
            if (page === 'dashboard') {
                showPage('dashboard');
            } else if (page === 'monitors') {
                showPage('logs');
                loadAuditLogs();
            } else if (page === 'settings') {
                showPage('settings');
                loadSettings();
            } else if (pageConfig?.openDashboard) {
                openDashboard();
                showToast(`Opening ${pageConfig.name} in dashboard...`);
            } else {
                showToast(`${pageConfig?.name || page} - Coming soon!`);
            }
        });
    });
    
    // Dashboard link (external link icon at bottom)
    document.getElementById('dashboard-link')?.addEventListener('click', openDashboard);
    
    // Refresh logs button
    document.getElementById('refresh-logs-btn')?.addEventListener('click', loadAuditLogs);
    
    // Log filters
    document.getElementById('log-filter-severity')?.addEventListener('change', loadAuditLogs);
    document.getElementById('log-filter-source')?.addEventListener('change', loadAuditLogs);
}

/**
 * Show a specific page
 */
function showPage(pageName) {
    // Hide all pages
    document.querySelectorAll('.page-content').forEach(p => p.style.display = 'none');
    
    // Show dashboard content by default
    const logsPage = document.getElementById('logs-page');
    const settingsPage = document.getElementById('settings-page');
    
    if (pageName === 'logs' && logsPage) {
        // Hide dashboard elements, show logs
        document.querySelectorAll('.content > *:not(.page-content)').forEach(el => {
            el.style.display = 'none';
        });
        logsPage.style.display = 'block';
    } else if (pageName === 'settings' && settingsPage) {
        // Hide dashboard elements, show settings
        document.querySelectorAll('.content > *:not(.page-content)').forEach(el => {
            el.style.display = 'none';
        });
        settingsPage.style.display = 'block';
    } else {
        // Show dashboard elements, hide other pages
        document.querySelectorAll('.content > *:not(.page-content)').forEach(el => {
            el.style.display = '';
        });
    }
}

/**
 * Load settings from Tauri backend
 */
async function loadSettings() {
    if (!isTauri) return;
    
    try {
        // Check autostart status
        const autostartEnabled = await invoke('is_autostart_enabled');
        document.getElementById('autostart-toggle').checked = autostartEnabled;
        
        // Load dashboard URL
        const dashboardUrl = await invoke('get_dashboard_url');
        document.getElementById('dashboard-url').value = dashboardUrl || DASHBOARD_URL;
    } catch (error) {
        console.debug('Failed to load settings:', error);
    }
    
    // Setup save button
    document.getElementById('save-settings-btn')?.addEventListener('click', saveSettings);
    
    // Setup autostart toggle
    document.getElementById('autostart-toggle')?.addEventListener('change', async (e) => {
        try {
            const result = await invoke('set_autostart', { enabled: e.target.checked });
            showToast(result);
        } catch (error) {
            showToast('Failed to update autostart: ' + error, 'error');
            e.target.checked = !e.target.checked; // Revert
        }
    });
}

/**
 * Save settings
 */
async function saveSettings() {
    const dashboardUrl = document.getElementById('dashboard-url')?.value;
    if (dashboardUrl) {
        DASHBOARD_URL = dashboardUrl;
        localStorage.setItem('dashboardUrl', dashboardUrl);
    }
    
    showToast('Settings saved');
}

/**
 * Open GitHub repository
 */
function openGitHub() {
    const url = 'https://github.com/VibrationRobotics/SentinelAI';
    if (isTauri && window.__TAURI__?.shell?.open) {
        window.__TAURI__.shell.open(url);
    } else {
        window.open(url, '_blank');
    }
}
window.openGitHub = openGitHub;

/**
 * Load audit logs from API
 */
async function loadAuditLogs() {
    const logsList = document.getElementById('logs-list');
    if (!logsList) return;
    
    const severity = document.getElementById('log-filter-severity')?.value || '';
    const source = document.getElementById('log-filter-source')?.value || '';
    
    try {
        let url = `${DASHBOARD_URL}/api/v1/audit?limit=100`;
        if (severity) url += `&severity=${severity}`;
        if (source) url += `&source=${source}`;
        
        const response = await fetch(url);
        if (!response.ok) throw new Error('Failed to fetch logs');
        
        const data = await response.json();
        const logs = data.logs || [];
        
        if (logs.length === 0) {
            logsList.innerHTML = `
                <div class="text-center text-muted py-4">
                    <i class="bi bi-journal-text" style="font-size: 48px; opacity: 0.3;"></i>
                    <p class="mt-2">No logs found</p>
                </div>
            `;
            return;
        }
        
        logsList.innerHTML = logs.map(log => `
            <div class="event-item" style="border-left: 3px solid ${getSeverityColor(log.severity)};">
                <div class="event-icon ${log.severity?.toLowerCase() || 'info'}" style="background: ${getSeverityColor(log.severity)}20;">
                    <i class="bi bi-${getLogIcon(log.action)}"></i>
                </div>
                <div class="event-details" style="flex: 1;">
                    <div class="event-title">${escapeHtml(log.description)}</div>
                    <div class="event-time">
                        <span class="badge" style="background: ${getSeverityColor(log.severity)}; font-size: 10px;">${log.severity}</span>
                        <span class="ms-2">${log.source}</span>
                        ${log.hostname ? `<span class="ms-2">@ ${log.hostname}</span>` : ''}
                        <span class="ms-2">${formatLogTime(log.timestamp)}</span>
                    </div>
                </div>
            </div>
        `).join('');
        
    } catch (error) {
        console.error('Failed to load logs:', error);
        logsList.innerHTML = `
            <div class="text-center text-muted py-4">
                <i class="bi bi-exclamation-triangle" style="font-size: 48px; opacity: 0.3; color: var(--warning);"></i>
                <p class="mt-2">Failed to load logs: ${error.message}</p>
            </div>
        `;
    }
}

function getSeverityColor(severity) {
    const colors = {
        'INFO': '#17a2b8',
        'WARNING': '#ffc107',
        'ERROR': '#dc3545',
        'CRITICAL': '#dc3545'
    };
    return colors[severity] || '#6c757d';
}

function getLogIcon(action) {
    const icons = {
        'agent_registered': 'pc-display',
        'agent_heartbeat': 'heart-pulse',
        'threat_detected': 'shield-exclamation',
        'ip_blocked': 'slash-circle',
        'login': 'box-arrow-in-right',
        'logout': 'box-arrow-right',
        'scan_started': 'search',
        'scan_completed': 'check-circle'
    };
    return icons[action] || 'journal-text';
}

function formatLogTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Open dashboard in browser
 */
function openDashboard() {
    if (isTauri && window.__TAURI__?.shell?.open) {
        window.__TAURI__.shell.open(DASHBOARD_URL);
    } else {
        window.open(DASHBOARD_URL, '_blank');
    }
}

/**
 * Setup titlebar buttons - use Tauri commands for reliability
 */
function setupTitlebar() {
    // Minimize button
    document.getElementById('minimize-btn')?.addEventListener('click', async () => {
        console.log('Minimize clicked');
        try {
            await invoke('minimize_window');
        } catch (e) {
            console.error('Minimize failed:', e);
            showToast('Minimize failed', 'error');
        }
    });
    
    // Maximize button
    document.getElementById('maximize-btn')?.addEventListener('click', async () => {
        console.log('Maximize clicked');
        try {
            await invoke('toggle_maximize');
        } catch (e) {
            console.error('Maximize failed:', e);
        }
    });
    
    // Close button
    document.getElementById('close-btn')?.addEventListener('click', async () => {
        console.log('Close clicked');
        try {
            await invoke('close_window');
        } catch (e) {
            console.error('Close failed:', e);
            // Fallback - try process exit
            try {
                if (window.__TAURI__?.process?.exit) {
                    await window.__TAURI__.process.exit(0);
                }
            } catch (e2) {
                console.error('Exit also failed:', e2);
            }
        }
    });
}

/**
 * Setup buttons
 */
function setupButtons() {
    // Quick Scan button
    document.getElementById('scan-btn')?.addEventListener('click', () => {
        startQuickScan();
    });
    
    // View All events button
    document.querySelectorAll('.btn-sentinel').forEach(btn => {
        if (btn.textContent.includes('View All')) {
            btn.addEventListener('click', () => {
                openDashboard();
                showToast('Opening dashboard...');
            });
        }
    });
    
    // Tray hint - clicking it minimizes
    document.querySelector('.tray-hint')?.addEventListener('click', async () => {
        if (isTauri) {
            try {
                const { getCurrentWindow } = window.__TAURI__.window;
                const win = getCurrentWindow ? getCurrentWindow() : window.__TAURI__.window.appWindow;
                if (win) await win.minimize();
            } catch (e) {}
        }
    });
}

/**
 * Update status from agent
 */
async function updateStatus() {
    try {
        // Try to get status from local agent API
        const response = await fetch(`${DASHBOARD_URL}/api/v1/windows/agent/list`);
        if (response.ok) {
            const data = await response.json();
            
            // Update UI with agent data
            if (data.agents && data.agents.length > 0) {
                const agent = data.agents[0];
                updateProtectionStatus(true, agent);
            } else {
                updateProtectionStatus(false);
            }
        }
        
        // Get threat stats
        const threatResponse = await fetch(`${DASHBOARD_URL}/api/v1/threats`);
        if (threatResponse.ok) {
            const threats = await threatResponse.json();
            const activeThreats = threats.filter(t => !t.resolved).length;
            document.getElementById('active-threats').textContent = activeThreats;
            document.getElementById('threats-blocked').textContent = threats.filter(t => t.resolved).length;
        }
        
    } catch (error) {
        console.debug('Could not connect to dashboard:', error);
        updateProtectionStatus(false);
    }
}

/**
 * Update protection status UI
 */
function updateProtectionStatus(connected, agent = null) {
    const icon = document.getElementById('protection-icon');
    const title = document.getElementById('protection-title');
    const subtitle = document.getElementById('protection-subtitle');
    
    if (connected && agent) {
        icon.className = 'protection-icon protected';
        icon.innerHTML = '<i class="bi bi-shield-fill-check"></i>';
        title.textContent = 'Protected';
        subtitle.textContent = `Agent connected: ${agent.hostname} (${agent.platform_version || agent.platform})`;
        
        // Update stats
        document.getElementById('processes-monitored').textContent = 
            agent.capabilities?.length || 0;
    } else {
        icon.className = 'protection-icon warning';
        icon.innerHTML = '<i class="bi bi-shield-exclamation"></i>';
        title.textContent = 'Not Connected';
        subtitle.textContent = 'Dashboard or agent not running';
    }
}

/**
 * Start quick scan
 */
async function startQuickScan() {
    const btn = document.getElementById('scan-btn');
    btn.innerHTML = '<i class="bi bi-hourglass-split me-2"></i>Scanning...';
    btn.disabled = true;
    
    try {
        // Trigger scan via API
        const response = await fetch(`${DASHBOARD_URL}/api/v1/monitoring/processes/scan`, {
            method: 'POST'
        });
        
        if (response.ok) {
            showNotification('Scan complete', 'success');
        } else {
            showNotification('Scan failed', 'error');
        }
    } catch (error) {
        showNotification('Could not connect to agent', 'error');
    }
    
    btn.innerHTML = '<i class="bi bi-search me-2"></i>Quick Scan';
    btn.disabled = false;
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    if (isTauri) {
        // Use Tauri notification
        window.__TAURI__.notification.sendNotification({
            title: 'SentinelAI',
            body: message
        });
    } else {
        // Browser notification
        if (Notification.permission === 'granted') {
            new Notification('SentinelAI', { body: message });
        } else {
            console.log(`[${type}] ${message}`);
        }
    }
}

/**
 * Add event to list
 */
function addEvent(event) {
    const list = document.getElementById('events-list');
    const severityClass = event.severity === 'HIGH' ? 'high' : 
                         event.severity === 'MEDIUM' ? 'medium' : 'low';
    
    const html = `
        <div class="event-item">
            <div class="event-icon ${severityClass}">
                <i class="bi bi-${getEventIcon(event.type)}"></i>
            </div>
            <div class="event-details">
                <div class="event-title">${event.description}</div>
                <div class="event-time">${formatTime(event.timestamp)}</div>
            </div>
        </div>
    `;
    
    list.insertAdjacentHTML('afterbegin', html);
    
    // Keep only last 10 events
    while (list.children.length > 10) {
        list.removeChild(list.lastChild);
    }
}

/**
 * Get icon for event type
 */
function getEventIcon(type) {
    const icons = {
        'usb_connected': 'usb-drive',
        'new_scheduled_task': 'calendar-check',
        'registry_new_entry': 'file-earmark-code',
        'new_startup_item': 'power',
        'suspicious_process': 'exclamation-octagon',
        'network_threat': 'wifi-off',
        'default': 'shield-exclamation'
    };
    return icons[type] || icons.default;
}

/**
 * Format timestamp
 */
function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = (now - date) / 1000;
    
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`;
    return date.toLocaleDateString();
}
