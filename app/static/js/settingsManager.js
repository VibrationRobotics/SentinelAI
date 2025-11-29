/**
 * SentinelAI Settings Manager
 * Connects all settings UI to real backend APIs
 */

class SettingsManager {
    constructor() {
        this.apiKeys = [];
        this.subscription = null;
    }

    async init() {
        await this.loadDashboardStats();
        await this.loadSettings();
        await this.loadAPIKeys();
        await this.loadSubscription();
        this.setupEventListeners();
    }

    getAuthHeaders() {
        const token = localStorage.getItem('sentinel_auth_token');
        return token ? { 'Authorization': `Bearer ${token}` } : {};
    }

    // ============== Dashboard Stats ==============
    
    async loadDashboardStats() {
        try {
            const response = await fetch('/api/v1/settings/dashboard-stats', {
                headers: this.getAuthHeaders()
            });
            
            if (response.ok) {
                const stats = await response.json();
                this.updateNavbar(stats);
            }
        } catch (error) {
            console.debug('Failed to load dashboard stats:', error);
        }
    }

    updateNavbar(stats) {
        // Update alert count
        const alertCount = document.getElementById('alert-count');
        if (alertCount) {
            alertCount.textContent = stats.alerts_count || 0;
            alertCount.parentElement.classList.toggle('bg-danger', stats.alerts_count > 0);
            alertCount.parentElement.classList.toggle('bg-secondary', stats.alerts_count === 0);
        }

        // Update user dropdown
        const userDropdown = document.querySelector('.dropdown-toggle');
        if (userDropdown && stats.user_name) {
            userDropdown.innerHTML = `<i class="bi bi-person-circle me-1"></i>${stats.user_name}`;
        }
    }

    // ============== Settings ==============

    async loadSettings() {
        try {
            const response = await fetch('/api/v1/settings/', {
                headers: this.getAuthHeaders()
            });
            
            if (response.ok) {
                const settings = await response.json();
                this.populateSettingsForm(settings);
            }
        } catch (error) {
            console.debug('Failed to load settings:', error);
        }
    }

    populateSettingsForm(settings) {
        // Auto-response settings
        const autoResponseToggle = document.getElementById('settings-auto-response-toggle');
        if (autoResponseToggle) autoResponseToggle.checked = settings.auto_response_enabled;

        const severityThreshold = document.getElementById('settings-severity-threshold');
        if (severityThreshold) severityThreshold.value = settings.severity_threshold;

        const cooldown = document.getElementById('settings-cooldown');
        if (cooldown) cooldown.value = settings.cooldown_seconds;

        const whitelist = document.getElementById('settings-whitelist');
        if (whitelist) whitelist.value = settings.ip_whitelist;

        // AI settings
        const aiEnabled = document.getElementById('settings-ai-enabled');
        if (aiEnabled) aiEnabled.checked = settings.ai_analysis_enabled;

        // Monitoring settings
        const processMonitor = document.getElementById('settings-process-monitor');
        if (processMonitor) processMonitor.checked = settings.process_monitor_enabled;

        const networkMonitor = document.getElementById('settings-network-monitor');
        if (networkMonitor) networkMonitor.checked = settings.network_monitor_enabled;

        const logCollector = document.getElementById('settings-log-collector');
        if (logCollector) logCollector.checked = settings.log_collector_enabled;

        const fileScanner = document.getElementById('settings-file-scanner');
        if (fileScanner) fileScanner.checked = settings.file_scanner_enabled;

        // Notification settings
        const browserNotifications = document.getElementById('settings-browser-notifications');
        if (browserNotifications) browserNotifications.checked = settings.browser_notifications;

        const soundAlerts = document.getElementById('settings-sound-alerts');
        if (soundAlerts) soundAlerts.checked = settings.sound_alerts;
    }

    async saveSettings() {
        const settings = {
            auto_response_enabled: document.getElementById('settings-auto-response-toggle')?.checked || false,
            severity_threshold: document.getElementById('settings-severity-threshold')?.value || 'HIGH',
            cooldown_seconds: parseInt(document.getElementById('settings-cooldown')?.value) || 300,
            ip_whitelist: document.getElementById('settings-whitelist')?.value || '',
            ai_analysis_enabled: document.getElementById('settings-ai-enabled')?.checked || false,
            process_monitor_enabled: document.getElementById('settings-process-monitor')?.checked || false,
            network_monitor_enabled: document.getElementById('settings-network-monitor')?.checked || false,
            log_collector_enabled: document.getElementById('settings-log-collector')?.checked || false,
            file_scanner_enabled: document.getElementById('settings-file-scanner')?.checked || false,
            browser_notifications: document.getElementById('settings-browser-notifications')?.checked || false,
            sound_alerts: document.getElementById('settings-sound-alerts')?.checked || false
        };

        try {
            const response = await fetch('/api/v1/settings/', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    ...this.getAuthHeaders()
                },
                body: JSON.stringify(settings)
            });

            if (response.ok) {
                this.showNotification('Settings saved successfully', 'success');
            } else {
                throw new Error('Failed to save settings');
            }
        } catch (error) {
            console.error('Save settings error:', error);
            this.showNotification('Failed to save settings', 'error');
        }
    }

    // ============== API Keys ==============

    async loadAPIKeys() {
        try {
            const response = await fetch('/api/v1/settings/api-keys', {
                headers: this.getAuthHeaders()
            });
            
            if (response.ok) {
                this.apiKeys = await response.json();
                this.renderAPIKeys();
            }
        } catch (error) {
            console.debug('Failed to load API keys:', error);
        }
    }

    renderAPIKeys() {
        const container = document.getElementById('api-keys-list');
        if (!container) return;

        if (this.apiKeys.length === 0) {
            container.innerHTML = `
                <div class="text-muted text-center py-3">
                    <i class="bi bi-key fs-3 d-block mb-2"></i>
                    No API keys yet. Create one to authenticate your agents.
                </div>
            `;
            return;
        }

        container.innerHTML = this.apiKeys.map(key => `
            <div class="d-flex justify-content-between align-items-center p-2 border-bottom">
                <div>
                    <strong>${key.name}</strong>
                    <br>
                    <small class="text-muted">
                        <code>${key.key_prefix}...</code> • 
                        Created ${new Date(key.created_at).toLocaleDateString()}
                        ${key.expires_at ? ` • Expires ${new Date(key.expires_at).toLocaleDateString()}` : ''}
                    </small>
                </div>
                <div>
                    ${key.is_active 
                        ? `<button class="btn btn-sm btn-outline-danger" onclick="settingsManager.revokeAPIKey(${key.id})">
                            <i class="bi bi-trash"></i> Revoke
                           </button>`
                        : '<span class="badge bg-secondary">Revoked</span>'
                    }
                </div>
            </div>
        `).join('');
    }

    async createAPIKey() {
        const name = document.getElementById('new-api-key-name')?.value;
        if (!name) {
            this.showNotification('Please enter a name for the API key', 'error');
            return;
        }

        try {
            const response = await fetch('/api/v1/settings/api-keys', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...this.getAuthHeaders()
                },
                body: JSON.stringify({ name })
            });

            if (response.ok) {
                const result = await response.json();
                
                // Show the key to the user (only shown once!)
                this.showAPIKeyModal(result);
                
                // Clear input and reload list
                document.getElementById('new-api-key-name').value = '';
                await this.loadAPIKeys();
            } else {
                throw new Error('Failed to create API key');
            }
        } catch (error) {
            console.error('Create API key error:', error);
            this.showNotification('Failed to create API key', 'error');
        }
    }

    showAPIKeyModal(keyData) {
        // Create modal to show the new API key
        const modalHtml = `
            <div class="modal fade" id="newApiKeyModal" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content bg-dark text-light">
                        <div class="modal-header border-secondary">
                            <h5 class="modal-title"><i class="bi bi-key text-success me-2"></i>API Key Created</h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="alert alert-warning">
                                <i class="bi bi-exclamation-triangle me-2"></i>
                                <strong>Save this key now!</strong> It will not be shown again.
                            </div>
                            <div class="mb-3">
                                <label class="form-label">API Key</label>
                                <div class="input-group">
                                    <input type="text" class="form-control bg-secondary text-light font-monospace" 
                                           value="${keyData.api_key}" id="new-api-key-value" readonly>
                                    <button class="btn btn-outline-light" onclick="settingsManager.copyAPIKey()">
                                        <i class="bi bi-clipboard"></i>
                                    </button>
                                </div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Usage in Agent</label>
                                <pre class="bg-secondary p-2 rounded text-light"><code>SENTINEL_API_KEY=${keyData.api_key}</code></pre>
                            </div>
                        </div>
                        <div class="modal-footer border-secondary">
                            <button type="button" class="btn btn-primary" data-bs-dismiss="modal">I've Saved It</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Remove existing modal if any
        document.getElementById('newApiKeyModal')?.remove();
        
        // Add and show modal
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        const modal = new bootstrap.Modal(document.getElementById('newApiKeyModal'));
        modal.show();
    }

    copyAPIKey() {
        const input = document.getElementById('new-api-key-value');
        if (input) {
            navigator.clipboard.writeText(input.value);
            this.showNotification('API key copied to clipboard', 'success');
        }
    }

    async revokeAPIKey(keyId) {
        if (!confirm('Are you sure you want to revoke this API key? This cannot be undone.')) {
            return;
        }

        try {
            const response = await fetch(`/api/v1/settings/api-keys/${keyId}`, {
                method: 'DELETE',
                headers: this.getAuthHeaders()
            });

            if (response.ok) {
                this.showNotification('API key revoked', 'success');
                await this.loadAPIKeys();
            } else {
                throw new Error('Failed to revoke API key');
            }
        } catch (error) {
            console.error('Revoke API key error:', error);
            this.showNotification('Failed to revoke API key', 'error');
        }
    }

    // ============== Subscription ==============

    async loadSubscription() {
        try {
            const response = await fetch('/api/v1/settings/subscription', {
                headers: this.getAuthHeaders()
            });
            
            if (response.ok) {
                this.subscription = await response.json();
                this.renderSubscription();
            }
        } catch (error) {
            console.debug('Failed to load subscription:', error);
        }
    }

    renderSubscription() {
        const container = document.getElementById('subscription-info');
        if (!container || !this.subscription) return;

        const tierColors = {
            free: 'secondary',
            pro: 'primary',
            enterprise: 'success'
        };

        const tierIcons = {
            free: 'bi-person',
            pro: 'bi-star',
            enterprise: 'bi-building'
        };

        container.innerHTML = `
            <div class="d-flex align-items-center mb-3">
                <span class="badge bg-${tierColors[this.subscription.tier]} fs-6 me-2">
                    <i class="bi ${tierIcons[this.subscription.tier]} me-1"></i>
                    ${this.subscription.tier.toUpperCase()}
                </span>
                <span class="text-muted">Current Plan</span>
            </div>
            <ul class="list-unstyled">
                <li><i class="bi bi-check-circle text-success me-2"></i>Max ${this.subscription.max_agents} agents</li>
                <li><i class="bi bi-check-circle text-success me-2"></i>${this.subscription.max_events_per_day.toLocaleString()} events/day</li>
                <li><i class="bi ${this.subscription.ai_analysis_enabled ? 'bi-check-circle text-success' : 'bi-x-circle text-danger'} me-2"></i>
                    AI Analysis ${this.subscription.ai_analysis_enabled ? 'Enabled' : 'Disabled'}</li>
            </ul>
            ${this.subscription.tier === 'free' ? `
                <button class="btn btn-primary btn-sm mt-2" onclick="settingsManager.showUpgradeModal()">
                    <i class="bi bi-arrow-up-circle me-1"></i>Upgrade Plan
                </button>
            ` : ''}
        `;
    }

    showUpgradeModal() {
        this.showNotification('Contact sales@sentinel.ai for enterprise pricing', 'info');
    }

    // ============== Event Listeners ==============

    setupEventListeners() {
        // Save settings button
        document.getElementById('saveSettingsButton')?.addEventListener('click', () => {
            this.saveSettings();
        });

        // Create API key button
        document.getElementById('create-api-key-btn')?.addEventListener('click', () => {
            this.createAPIKey();
        });

        // Refresh stats periodically
        setInterval(() => this.loadDashboardStats(), 30000);
    }

    // ============== Utilities ==============

    showNotification(message, type = 'info') {
        // Use existing notification system if available
        if (typeof showNotification === 'function') {
            showNotification(message, type);
        } else {
            console.log(`[${type}] ${message}`);
        }
    }
}

// Global instance
const settingsManager = new SettingsManager();

// Initialize when DOM is ready and user is authenticated
document.addEventListener('DOMContentLoaded', () => {
    // Wait for auth to complete
    setTimeout(() => {
        if (localStorage.getItem('sentinel_auth_token')) {
            settingsManager.init();
        }
    }, 1000);
});

// Re-init when user logs in
window.addEventListener('storage', (e) => {
    if (e.key === 'sentinel_auth_token' && e.newValue) {
        settingsManager.init();
    }
});
