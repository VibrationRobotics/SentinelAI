/**
 * SentinelAI Monitoring Dashboard JavaScript
 * Handles all monitoring services UI updates and controls
 */

const MonitoringDashboard = {
    // API base URL
    apiBase: '/api/v1',
    
    // Update interval (ms)
    updateInterval: 5000,
    
    // Interval IDs
    intervals: {},

    /**
     * Initialize the monitoring dashboard
     */
    init: function() {
        console.log('Initializing Monitoring Dashboard...');
        
        // Bind button events
        this.bindEvents();
        
        // Initial data load
        this.refreshAll();
        
        // Start auto-refresh
        this.startAutoRefresh();
        
        // Auto-start process monitor (works in Docker)
        this.autoStartServices();
    },
    
    /**
     * Auto-start monitoring services
     */
    autoStartServices: async function() {
        // Start process monitor automatically
        try {
            const response = await fetch(`${this.apiBase}/monitoring/processes/start`, { method: 'POST' });
            if (response.ok) {
                console.log('Process monitor auto-started');
            }
        } catch (e) {
            console.debug('Could not auto-start process monitor');
        }
        
        // Start log collector
        try {
            const response = await fetch(`${this.apiBase}/logs/start`, { method: 'POST' });
            if (response.ok) {
                console.log('Log collector auto-started');
            }
        } catch (e) {
            console.debug('Could not auto-start log collector');
        }
    },

    /**
     * Bind click events to buttons
     */
    bindEvents: function() {
        // Auto-Response toggle
        const autoResponseBtn = document.getElementById('toggle-auto-response');
        if (autoResponseBtn) {
            autoResponseBtn.addEventListener('click', () => this.toggleAutoResponse());
        }

        // Network Monitor toggle
        const networkBtn = document.getElementById('toggle-network-monitor');
        if (networkBtn) {
            networkBtn.addEventListener('click', () => this.toggleService('network'));
        }

        // File Scanner toggle
        const fileBtn = document.getElementById('toggle-file-scanner');
        if (fileBtn) {
            fileBtn.addEventListener('click', () => this.toggleService('files'));
        }

        // Process Monitor toggle
        const processBtn = document.getElementById('toggle-process-monitor');
        if (processBtn) {
            processBtn.addEventListener('click', () => this.toggleService('processes'));
        }

        // Log Collector toggle
        const logBtn = document.getElementById('toggle-log-collector');
        if (logBtn) {
            logBtn.addEventListener('click', () => this.toggleService('logs'));
        }

        // Refresh security events
        const refreshEventsBtn = document.getElementById('refresh-security-events');
        if (refreshEventsBtn) {
            refreshEventsBtn.addEventListener('click', () => this.refreshSecurityEvents());
        }

        // Refresh agents
        const refreshAgentsBtn = document.getElementById('refresh-agents');
        if (refreshAgentsBtn) {
            refreshAgentsBtn.addEventListener('click', () => this.refreshAgents());
        }
    },

    /**
     * Start auto-refresh intervals
     */
    startAutoRefresh: function() {
        this.intervals.main = setInterval(() => this.refreshAll(), this.updateInterval);
    },

    /**
     * Refresh all monitoring data
     */
    refreshAll: function() {
        this.refreshAutoResponse();
        this.refreshMonitoringStatus();
        this.refreshSystemInfo();
        this.refreshSecurityEvents();
        this.refreshAgents();
    },

    /**
     * Refresh auto-response status
     */
    refreshAutoResponse: async function() {
        try {
            const response = await fetch(`${this.apiBase}/auto-response/config`);
            if (response.ok) {
                const config = await response.json();
                this.updateAutoResponseUI(config);
            }

            const statsResponse = await fetch(`${this.apiBase}/auto-response/stats`);
            if (statsResponse.ok) {
                const stats = await statsResponse.json();
                this.updateAutoResponseStats(stats);
            }
        } catch (error) {
            console.error('Error refreshing auto-response:', error);
        }
    },

    /**
     * Update auto-response UI elements
     */
    updateAutoResponseUI: function(config) {
        const statusEl = document.getElementById('auto-response-status');
        const modeEl = document.getElementById('auto-mode-badge');
        const thresholdEl = document.getElementById('auto-threshold');
        const whitelistEl = document.getElementById('whitelist-count');

        if (statusEl) {
            statusEl.textContent = config.enabled ? 'ACTIVE' : 'DISABLED';
            statusEl.className = `badge bg-light ${config.enabled ? 'text-success' : 'text-danger'} me-2`;
        }

        if (modeEl) {
            modeEl.textContent = config.enabled ? 'ENABLED' : 'DISABLED';
            modeEl.className = `badge ${config.enabled ? 'bg-success' : 'bg-danger'} fs-6`;
        }

        if (thresholdEl) {
            thresholdEl.textContent = config.severity_threshold || 'HIGH';
        }

        if (whitelistEl && config.whitelist_ips) {
            whitelistEl.textContent = config.whitelist_ips.length;
        }
    },

    /**
     * Update auto-response statistics
     */
    updateAutoResponseStats: function(stats) {
        const blockedEl = document.getElementById('auto-blocked-count');
        const actionsEl = document.getElementById('auto-actions-hour');

        if (blockedEl) {
            blockedEl.textContent = stats.blocked_ips || 0;
        }

        if (actionsEl) {
            actionsEl.textContent = stats.actions_last_hour || 0;
        }
    },

    /**
     * Toggle auto-response on/off
     */
    toggleAutoResponse: async function() {
        try {
            const response = await fetch(`${this.apiBase}/auto-response/toggle`, {
                method: 'POST'
            });
            if (response.ok) {
                const result = await response.json();
                this.refreshAutoResponse();
                this.showNotification(`Auto-response ${result.enabled ? 'enabled' : 'disabled'}`, 'success');
            }
        } catch (error) {
            console.error('Error toggling auto-response:', error);
            this.showNotification('Failed to toggle auto-response', 'error');
        }
    },

    /**
     * Refresh monitoring services status
     */
    refreshMonitoringStatus: async function() {
        try {
            const response = await fetch(`${this.apiBase}/monitoring/status`);
            if (response.ok) {
                const status = await response.json();
                this.updateNetworkMonitorUI(status.network_monitor);
                this.updateFileScannerUI(status.file_scanner);
                this.updateProcessMonitorUI(status.process_monitor);
            }
        } catch (error) {
            console.error('Error refreshing monitoring status:', error);
        }

        // Also refresh log collector
        try {
            const logResponse = await fetch(`${this.apiBase}/logs/stats`);
            if (logResponse.ok) {
                const logStats = await logResponse.json();
                this.updateLogCollectorUI(logStats);
            }
        } catch (error) {
            console.error('Error refreshing log collector:', error);
        }
    },

    /**
     * Update Network Monitor UI
     */
    updateNetworkMonitorUI: function(stats) {
        const statusEl = document.getElementById('network-monitor-status');
        const packetsEl = document.getElementById('network-packets');
        const portScansEl = document.getElementById('network-port-scans');
        const bruteForceEl = document.getElementById('network-brute-force');
        const toggleBtn = document.getElementById('toggle-network-monitor');

        if (statusEl) {
            statusEl.textContent = stats.running ? 'Running' : 'Stopped';
            statusEl.className = `badge ${stats.running ? 'bg-success' : 'bg-secondary'}`;
        }

        if (packetsEl) packetsEl.textContent = stats.packets_captured || 0;
        if (portScansEl) portScansEl.textContent = stats.port_scans || 0;
        if (bruteForceEl) bruteForceEl.textContent = stats.brute_force_attempts || 0;

        if (toggleBtn) {
            const icon = toggleBtn.querySelector('i');
            if (icon) {
                icon.className = stats.running ? 'bi bi-stop-fill' : 'bi bi-play-fill';
            }
        }
    },

    /**
     * Update File Scanner UI
     */
    updateFileScannerUI: function(stats) {
        const statusEl = document.getElementById('file-scanner-status');
        const scannedEl = document.getElementById('files-scanned');
        const threatsEl = document.getElementById('files-threats');
        const quarantinedEl = document.getElementById('files-quarantined');
        const toggleBtn = document.getElementById('toggle-file-scanner');

        if (statusEl) {
            statusEl.textContent = stats.running ? 'Running' : 'Stopped';
            statusEl.className = `badge ${stats.running ? 'bg-success' : 'bg-secondary'}`;
        }

        if (scannedEl) scannedEl.textContent = stats.files_scanned || 0;
        if (threatsEl) threatsEl.textContent = stats.threats_detected || 0;
        if (quarantinedEl) quarantinedEl.textContent = stats.files_quarantined || 0;

        if (toggleBtn) {
            const icon = toggleBtn.querySelector('i');
            if (icon) {
                icon.className = stats.running ? 'bi bi-stop-fill' : 'bi bi-play-fill';
            }
        }
    },

    /**
     * Update Process Monitor UI
     */
    updateProcessMonitorUI: function(stats) {
        const statusEl = document.getElementById('process-monitor-status');
        const monitoredEl = document.getElementById('processes-monitored');
        const suspiciousEl = document.getElementById('processes-suspicious');
        const eventsEl = document.getElementById('processes-events');
        const toggleBtn = document.getElementById('toggle-process-monitor');

        if (statusEl) {
            statusEl.textContent = stats.running ? 'Running' : 'Stopped';
            statusEl.className = `badge ${stats.running ? 'bg-success' : 'bg-secondary'}`;
        }

        if (monitoredEl) monitoredEl.textContent = stats.processes_monitored || 0;
        if (suspiciousEl) suspiciousEl.textContent = stats.suspicious_detected || 0;
        if (eventsEl) eventsEl.textContent = stats.events_generated || 0;

        if (toggleBtn) {
            const icon = toggleBtn.querySelector('i');
            if (icon) {
                icon.className = stats.running ? 'bi bi-stop-fill' : 'bi bi-play-fill';
            }
        }
    },

    /**
     * Update Log Collector UI
     */
    updateLogCollectorUI: function(stats) {
        const statusEl = document.getElementById('log-collector-status');
        const collectedEl = document.getElementById('logs-collected');
        const threatsEl = document.getElementById('logs-threats');
        const highEl = document.getElementById('logs-high');
        const mediumEl = document.getElementById('logs-medium');
        const lowEl = document.getElementById('logs-low');
        const toggleBtn = document.getElementById('toggle-log-collector');

        if (statusEl) {
            statusEl.textContent = stats.running ? 'Running' : 'Stopped';
            statusEl.className = `badge ${stats.running ? 'bg-success' : 'bg-secondary'}`;
        }

        if (collectedEl) collectedEl.textContent = stats.entries_collected || 0;
        if (threatsEl) threatsEl.textContent = stats.threats_detected || 0;

        if (stats.by_severity) {
            if (highEl) highEl.textContent = stats.by_severity.HIGH || 0;
            if (mediumEl) mediumEl.textContent = stats.by_severity.MEDIUM || 0;
            if (lowEl) lowEl.textContent = stats.by_severity.LOW || 0;
        }

        if (toggleBtn) {
            const icon = toggleBtn.querySelector('i');
            if (icon) {
                icon.className = stats.running ? 'bi bi-stop-fill' : 'bi bi-play-fill';
            }
        }
    },

    /**
     * Toggle a monitoring service
     */
    toggleService: async function(service) {
        const endpoints = {
            'network': '/monitoring/network',
            'files': '/monitoring/files',
            'processes': '/monitoring/processes',
            'logs': '/logs'
        };

        const endpoint = endpoints[service];
        if (!endpoint) return;

        try {
            // Get current status
            const statusResponse = await fetch(`${this.apiBase}${endpoint}/stats`);
            const stats = await statusResponse.json();
            const isRunning = stats.running;

            // Toggle
            const action = isRunning ? 'stop' : 'start';
            const response = await fetch(`${this.apiBase}${endpoint}/${action}`, {
                method: 'POST'
            });

            if (response.ok) {
                this.refreshMonitoringStatus();
                this.showNotification(`${service} monitor ${action}ed`, 'success');
            }
        } catch (error) {
            console.error(`Error toggling ${service}:`, error);
            this.showNotification(`Failed to toggle ${service}`, 'error');
        }
    },

    /**
     * Refresh system information
     */
    refreshSystemInfo: async function() {
        try {
            const response = await fetch(`${this.apiBase}/windows/system/info`);
            if (response.ok) {
                const info = await response.json();
                this.updateSystemInfoUI(info);
            }
        } catch (error) {
            console.error('Error refreshing system info:', error);
        }
    },

    /**
     * Update System Info UI
     */
    updateSystemInfoUI: function(info) {
        const platformEl = document.getElementById('sys-platform');
        const hostnameEl = document.getElementById('sys-hostname');
        const cpuEl = document.getElementById('sys-cpu');
        const memoryEl = document.getElementById('sys-memory');
        const diskEl = document.getElementById('sys-disk');
        const firewallEl = document.getElementById('sys-firewall');

        if (platformEl) platformEl.textContent = info.platform || '-';
        if (hostnameEl) hostnameEl.textContent = (info.hostname || '-').substring(0, 12);
        if (cpuEl) cpuEl.textContent = info.cpu_count || '-';
        
        if (memoryEl && info.memory_total_gb) {
            memoryEl.textContent = `${info.memory_available_gb}/${info.memory_total_gb} GB`;
        }
        
        if (diskEl && info.disk_total_gb) {
            diskEl.textContent = `${info.disk_total_gb} GB`;
        }

        if (firewallEl) {
            firewallEl.textContent = info.platform === 'Windows' ? 'Windows' : 'iptables';
            firewallEl.className = 'badge bg-success';
        }
    },

    /**
     * Refresh connected agents list
     */
    refreshAgents: async function() {
        try {
            const response = await fetch(`${this.apiBase}/windows/agent/list`);
            if (response.ok) {
                const data = await response.json();
                this.updateAgentsTable(data.agents || {});
            }
        } catch (error) {
            console.error('Error refreshing agents:', error);
        }
    },

    /**
     * Update agents table UI
     */
    updateAgentsTable: function(agents) {
        const tbody = document.getElementById('agents-table');
        if (!tbody) return;

        const agentList = Object.values(agents);
        
        if (agentList.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">No agents connected</td></tr>';
            return;
        }

        tbody.innerHTML = agentList.map(agent => {
            const statusClass = agent.status === 'online' ? 'bg-success' : 'bg-secondary';
            const lastSeen = new Date(agent.last_seen).toLocaleString();
            const capabilities = (agent.capabilities || []).map(c => 
                `<span class="badge bg-info me-1">${c}</span>`
            ).join('');
            
            // Admin status badge
            const adminBadge = agent.is_admin 
                ? '<span class="badge bg-warning text-dark ms-1" title="Running as Administrator"><i class="bi bi-shield-check"></i> Admin</span>'
                : '<span class="badge bg-secondary ms-1" title="Not running as Administrator">User</span>';

            return `
                <tr>
                    <td><strong>${agent.hostname}</strong>${adminBadge}</td>
                    <td><small>${agent.platform_version || agent.platform || 'Unknown'}</small></td>
                    <td><span class="badge ${statusClass}">${agent.status}</span></td>
                    <td>${capabilities}</td>
                    <td><small>${lastSeen}</small></td>
                </tr>
            `;
        }).join('');
    },

    /**
     * Refresh security events table
     */
    refreshSecurityEvents: async function() {
        const events = [];

        // Get events from PostgreSQL database (primary source)
        try {
            const dbResponse = await fetch(`${this.apiBase}/windows/events?limit=50`);
            if (dbResponse.ok) {
                const data = await dbResponse.json();
                if (data.events) {
                    data.events.forEach(e => {
                        const aiAnalysis = e.details?.ai_analysis;
                        events.push({
                            time: e.timestamp,
                            source: e.hostname || 'Agent',
                            type: e.event_type,
                            severity: e.severity,
                            description: e.description,
                            ai_analyzed: aiAnalysis?.analyzed || false,
                            ai_classification: aiAnalysis?.ai_classification,
                            ai_confidence: aiAnalysis?.ai_confidence,
                            ai_explanation: aiAnalysis?.ai_explanation,
                            is_false_positive: aiAnalysis?.is_false_positive,
                            mitre_techniques: aiAnalysis?.mitre_techniques || [],
                            details: e.details
                        });
                    });
                }
            }
        } catch (error) {
            console.debug('Database events not available:', error);
        }

        try {
            // Get network events
            const networkResponse = await fetch(`${this.apiBase}/monitoring/network/events?limit=10`);
            if (networkResponse.ok) {
                const data = await networkResponse.json();
                if (data.events) {
                    data.events.forEach(e => {
                        events.push({
                            time: e.timestamp,
                            source: 'Network',
                            type: e.event_type,
                            severity: e.severity,
                            description: e.description
                        });
                    });
                }
            }
        } catch (error) {
            console.debug('Network events not available');
        }

        try {
            // Get process events
            const processResponse = await fetch(`${this.apiBase}/monitoring/processes/events?limit=10`);
            if (processResponse.ok) {
                const data = await processResponse.json();
                if (data.events) {
                    data.events.forEach(e => {
                        events.push({
                            time: e.timestamp,
                            source: 'Process',
                            type: e.event_type,
                            severity: e.severity,
                            description: e.description
                        });
                    });
                }
            }
        } catch (error) {
            console.debug('Process events not available');
        }

        try {
            // Get log threats
            const logResponse = await fetch(`${this.apiBase}/logs/entries?limit=10&threats_only=true`);
            if (logResponse.ok) {
                const data = await logResponse.json();
                if (data.entries) {
                    data.entries.forEach(e => {
                        events.push({
                            time: e.timestamp,
                            source: 'Logs',
                            type: e.threats ? e.threats.join(', ') : 'threat',
                            severity: e.severity,
                            description: e.message
                        });
                    });
                }
            }
        } catch (error) {
            console.debug('Log entries not available');
        }

        try {
            // Get auto-response history
            const autoResponse = await fetch(`${this.apiBase}/auto-response/history?limit=10`);
            if (autoResponse.ok) {
                const data = await autoResponse.json();
                if (data.actions) {
                    data.actions.forEach(a => {
                        events.push({
                            time: a.timestamp,
                            source: 'Auto-Response',
                            type: a.action,
                            severity: 'HIGH',
                            description: `Blocked IP: ${a.ip}`
                        });
                    });
                }
            }
        } catch (error) {
            console.debug('Auto-response history not available');
        }

        // Sort by time descending and deduplicate
        events.sort((a, b) => new Date(b.time) - new Date(a.time));
        
        // Remove duplicates based on time + description
        const seen = new Set();
        const uniqueEvents = events.filter(e => {
            const key = `${e.time}-${e.description}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });

        // Update table
        this.updateSecurityEventsTable(uniqueEvents.slice(0, 30));
    },

    /**
     * Update security events table
     */
    updateSecurityEventsTable: function(events) {
        const tbody = document.getElementById('security-events-table');
        if (!tbody) return;

        if (events.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">No security events detected</td></tr>';
            return;
        }

        tbody.innerHTML = events.map(event => {
            const time = new Date(event.time).toLocaleTimeString();
            const severityClass = {
                'CRITICAL': 'bg-danger',
                'HIGH': 'bg-danger',
                'MEDIUM': 'bg-warning',
                'LOW': 'bg-info',
                'NORMAL': 'bg-success'
            }[event.severity] || 'bg-secondary';

            // AI Analysis badge
            let aiBadge = '';
            if (event.ai_analyzed) {
                const aiConfidence = event.ai_confidence ? Math.round(event.ai_confidence * 100) : 0;
                const aiClass = event.is_false_positive ? 'bg-success' : 'bg-primary';
                const aiIcon = event.is_false_positive ? 'check-circle' : 'robot';
                const aiTitle = event.ai_explanation || event.ai_classification || 'AI Analyzed';
                aiBadge = `<span class="badge ${aiClass} ms-1" title="${aiTitle}"><i class="bi bi-${aiIcon}"></i> AI ${aiConfidence}%</span>`;
                
                // Show MITRE techniques if available
                if (event.mitre_techniques && event.mitre_techniques.length > 0) {
                    aiBadge += event.mitre_techniques.map(t => 
                        `<span class="badge bg-dark ms-1" title="MITRE ATT&CK">${t}</span>`
                    ).join('');
                }
            }

            // False positive indicator
            const fpBadge = event.is_false_positive 
                ? '<span class="badge bg-success ms-1" title="AI determined this is safe"><i class="bi bi-shield-check"></i> Safe</span>' 
                : '';

            return `
                <tr>
                    <td><small>${time}</small></td>
                    <td><small>${event.source}</small></td>
                    <td><small>${event.type}</small></td>
                    <td>
                        <span class="badge ${severityClass}">${event.severity}</span>
                        ${aiBadge}${fpBadge}
                    </td>
                    <td><small>${(event.description || '').substring(0, 60)}</small></td>
                </tr>
            `;
        }).join('');
    },

    /**
     * Show notification toast
     */
    showNotification: function(message, type = 'info') {
        // Create toast element
        const toast = document.createElement('div');
        toast.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show position-fixed`;
        toast.style.cssText = 'top: 80px; right: 20px; z-index: 9999; min-width: 250px;';
        toast.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.body.appendChild(toast);

        // Auto-remove after 3 seconds
        setTimeout(() => {
            toast.remove();
        }, 3000);
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    MonitoringDashboard.init();
});

/**
 * Page Navigation System
 * Handles switching between Dashboard, Threats, and Agents views
 */
function showPage(pageName) {
    // Update navbar active state
    document.querySelectorAll('.navbar-nav .nav-link').forEach(link => {
        link.classList.remove('active');
        if (link.dataset.page === pageName) {
            link.classList.add('active');
        }
    });
    
    // Define page sections
    const dashboardSections = [
        'dashboard-main', 'threat-list-container', 'threatChart', 
        'map', 'originsChart', 'timeline-container'
    ];
    
    // Get all main content sections
    const allSections = document.querySelectorAll('.dashboard-container > .row');
    
    switch(pageName) {
        case 'dashboard':
            // Show all sections
            allSections.forEach(section => {
                section.style.display = '';
            });
            break;
            
        case 'threats':
            // Show only threat-related sections
            allSections.forEach(section => {
                const hasThreatContent = section.querySelector('#threat-list') || 
                                        section.querySelector('#threatChart') ||
                                        section.id === 'dashboard-main';
                section.style.display = hasThreatContent ? '' : 'none';
            });
            // Scroll to threats
            const threatList = document.getElementById('threat-list');
            if (threatList) {
                threatList.scrollIntoView({ behavior: 'smooth' });
            }
            break;
            
        case 'agents':
            // Show only agent/monitoring sections
            allSections.forEach(section => {
                const hasAgentContent = section.querySelector('#agents-table') || 
                                       section.querySelector('.monitoring-card') ||
                                       section.querySelector('#security-events-table');
                section.style.display = hasAgentContent ? '' : 'none';
            });
            // Scroll to agents section
            const agentsSection = document.getElementById('agents-table');
            if (agentsSection) {
                agentsSection.scrollIntoView({ behavior: 'smooth' });
            }
            break;
    }
}

/**
 * Settings Management
 */
function loadSettings() {
    // Load settings from API
    fetch('/api/v1/auto-response/settings')
        .then(response => response.json())
        .then(settings => {
            document.getElementById('settings-auto-response-toggle').checked = settings.enabled;
            document.getElementById('settings-severity-threshold').value = settings.threshold || 'HIGH';
            document.getElementById('settings-cooldown').value = settings.cooldown || 300;
            if (settings.whitelist) {
                document.getElementById('settings-whitelist').value = settings.whitelist.join('\n');
            }
        })
        .catch(err => console.debug('Could not load settings:', err));
}

function saveSettings() {
    const settings = {
        enabled: document.getElementById('settings-auto-response-toggle').checked,
        threshold: document.getElementById('settings-severity-threshold').value,
        cooldown: parseInt(document.getElementById('settings-cooldown').value),
        whitelist: document.getElementById('settings-whitelist').value.split('\n').filter(ip => ip.trim())
    };
    
    fetch('/api/v1/auto-response/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
    })
    .then(response => {
        if (response.ok) {
            MonitoringDashboard.showNotification('Settings saved successfully', 'success');
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('settingsModal'));
            if (modal) modal.hide();
        } else {
            MonitoringDashboard.showNotification('Failed to save settings', 'error');
        }
    })
    .catch(err => {
        console.error('Error saving settings:', err);
        MonitoringDashboard.showNotification('Error saving settings', 'error');
    });
}

// Bind settings events
document.addEventListener('DOMContentLoaded', function() {
    // Load settings when modal opens
    const settingsModal = document.getElementById('settingsModal');
    if (settingsModal) {
        settingsModal.addEventListener('show.bs.modal', loadSettings);
    }
    
    // Save settings button
    const saveBtn = document.getElementById('saveSettingsButton');
    if (saveBtn) {
        saveBtn.addEventListener('click', saveSettings);
    }
});
