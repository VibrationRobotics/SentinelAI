/**
 * SentinelAI Authentication Module
 * Handles login, registration, and protected routes
 */

const AUTH_TOKEN_KEY = 'sentinel_auth_token';
const AUTH_USER_KEY = 'sentinel_auth_user';

class AuthManager {
    constructor() {
        this.token = localStorage.getItem(AUTH_TOKEN_KEY);
        this.user = JSON.parse(localStorage.getItem(AUTH_USER_KEY) || 'null');
        this.loginModal = null;
        this.isInitialized = false;
    }

    init() {
        if (this.isInitialized) return;
        this.isInitialized = true;

        // Initialize Bootstrap modal
        const modalEl = document.getElementById('loginModal');
        if (modalEl) {
            this.loginModal = new bootstrap.Modal(modalEl);
        }

        // Setup event listeners
        this.setupEventListeners();

        // Check authentication on page load
        this.checkAuth();
    }

    setupEventListeners() {
        // Login button
        document.getElementById('login-btn')?.addEventListener('click', () => this.login());
        
        // Register button
        document.getElementById('register-btn')?.addEventListener('click', () => this.register());
        
        // Toggle between login and register forms
        document.getElementById('show-register-btn')?.addEventListener('click', () => {
            document.getElementById('login-form').classList.add('d-none');
            document.getElementById('register-form').classList.remove('d-none');
            this.clearErrors();
        });
        
        document.getElementById('show-login-btn')?.addEventListener('click', () => {
            document.getElementById('register-form').classList.add('d-none');
            document.getElementById('login-form').classList.remove('d-none');
            this.clearErrors();
        });

        // Enter key handlers
        document.getElementById('login-password')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.login();
        });
        
        document.getElementById('register-password')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.register();
        });

        // Logout handler
        document.getElementById('logout-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.logout();
        });
        
        // Admin panel handlers
        document.getElementById('adminModal')?.addEventListener('show.bs.modal', () => {
            if (this.isAdmin()) {
                this.loadAdminData();
            }
        });
    }
    
    async loadAdminData() {
        // Load users list
        try {
            const response = await fetch('/api/v1/settings/admin/users', {
                headers: this.getAuthHeader()
            });
            if (response.ok) {
                const users = await response.json();
                this.renderAdminUsers(users);
            }
        } catch (e) {
            console.debug('Failed to load admin users');
        }
        
        // Load agents list
        try {
            const response = await fetch('/api/v1/windows/agent/list', {
                headers: this.getAuthHeader()
            });
            if (response.ok) {
                const data = await response.json();
                this.renderAdminAgents(data.agents || []);
            }
        } catch (e) {
            console.debug('Failed to load agents');
        }
        
        // Load audit log
        try {
            const response = await fetch('/api/v1/audit?limit=50', {
                headers: this.getAuthHeader()
            });
            if (response.ok) {
                const logs = await response.json();
                this.renderAdminAudit(logs);
            }
        } catch (e) {
            console.debug('Failed to load audit logs');
        }
    }
    
    renderAdminUsers(users) {
        const container = document.getElementById('admin-users-list');
        if (!container) return;
        
        // Store users for later reference
        this.adminUsers = users;
        
        container.innerHTML = users.map(u => `
            <tr data-user-id="${u.id}">
                <td>${u.full_name}</td>
                <td>${u.email}</td>
                <td>
                    <select class="form-select form-select-sm" style="width:auto" onchange="authManager.updateUserRole(${u.id}, this.value)">
                        <option value="user" ${u.role === 'user' ? 'selected' : ''}>User</option>
                        <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option>
                        <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>Viewer</option>
                    </select>
                </td>
                <td>
                    <select class="form-select form-select-sm" style="width:auto" onchange="authManager.updateUserTier(${u.id}, this.value)">
                        <option value="free" ${(u.tier || 'free') === 'free' ? 'selected' : ''}>Free</option>
                        <option value="pro" ${u.tier === 'pro' ? 'selected' : ''}>Pro</option>
                        <option value="enterprise" ${u.tier === 'enterprise' ? 'selected' : ''}>Enterprise</option>
                    </select>
                </td>
                <td>
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" ${u.is_active ? 'checked' : ''} 
                               onchange="authManager.updateUserStatus(${u.id}, this.checked)">
                    </div>
                </td>
                <td>
                    <button class="btn btn-sm btn-outline-info" onclick="authManager.viewUserDetails(${u.id})" title="View Details">
                        <i class="bi bi-eye"></i>
                    </button>
                </td>
            </tr>
        `).join('') || '<tr><td colspan="6" class="text-center">No users found</td></tr>';
    }
    
    async updateUserRole(userId, role) {
        try {
            const response = await fetch(`/api/v1/settings/admin/users/${userId}/role?role=${role}`, {
                method: 'PUT',
                headers: this.getAuthHeader()
            });
            if (response.ok) {
                this.showToast(`User role updated to ${role}`, 'success');
            } else {
                const err = await response.json();
                this.showToast(err.detail || 'Failed to update role', 'danger');
            }
        } catch (e) {
            this.showToast('Error updating role', 'danger');
        }
    }
    
    async updateUserTier(userId, tier) {
        try {
            const response = await fetch(`/api/v1/settings/admin/users/${userId}/tier?tier=${tier}`, {
                method: 'PUT',
                headers: this.getAuthHeader()
            });
            if (response.ok) {
                this.showToast(`User upgraded to ${tier.toUpperCase()} tier`, 'success');
            } else {
                const err = await response.json();
                this.showToast(err.detail || 'Failed to update tier', 'danger');
            }
        } catch (e) {
            this.showToast('Error updating tier', 'danger');
        }
    }
    
    async updateUserStatus(userId, isActive) {
        try {
            const response = await fetch(`/api/v1/settings/admin/users/${userId}/status?is_active=${isActive}`, {
                method: 'PUT',
                headers: this.getAuthHeader()
            });
            if (response.ok) {
                this.showToast(`User ${isActive ? 'enabled' : 'disabled'}`, 'success');
            } else {
                const err = await response.json();
                this.showToast(err.detail || 'Failed to update status', 'danger');
            }
        } catch (e) {
            this.showToast('Error updating status', 'danger');
        }
    }
    
    async viewUserDetails(userId) {
        try {
            const response = await fetch(`/api/v1/settings/admin/users/${userId}`, {
                headers: this.getAuthHeader()
            });
            if (response.ok) {
                const user = await response.json();
                alert(`User Details:\n\nName: ${user.full_name}\nEmail: ${user.email}\nRole: ${user.role}\nTier: ${user.subscription.tier}\nMax Agents: ${user.subscription.max_agents}\nMax Events/Day: ${user.subscription.max_events_per_day}\nAPI Keys: ${user.api_keys_count}\nCreated: ${user.created_at}`);
            }
        } catch (e) {
            console.error('Error fetching user details', e);
        }
    }
    
    showToast(message, type = 'info') {
        // Simple toast notification
        const toast = document.createElement('div');
        toast.className = `alert alert-${type} position-fixed bottom-0 end-0 m-3`;
        toast.style.zIndex = '9999';
        toast.innerHTML = message;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    }
    
    renderAdminAgents(agents) {
        const container = document.getElementById('admin-agents-list');
        if (!container) return;
        
        container.innerHTML = agents.map(a => `
            <tr>
                <td>${a.hostname}</td>
                <td>${a.platform}</td>
                <td>${a.agent_version}</td>
                <td><span class="badge bg-${a.status === 'online' ? 'success' : 'secondary'}">${a.status}</span></td>
                <td>${new Date(a.last_seen).toLocaleString()}</td>
            </tr>
        `).join('') || '<tr><td colspan="5" class="text-center">No agents connected</td></tr>';
    }
    
    renderAdminAudit(logs) {
        const container = document.getElementById('admin-audit-list');
        if (!container) return;
        
        container.innerHTML = logs.map(l => `
            <div class="border-bottom py-2">
                <small class="text-muted">${new Date(l.timestamp).toLocaleString()}</small>
                <span class="badge bg-${l.severity === 'HIGH' ? 'danger' : l.severity === 'WARNING' ? 'warning' : 'info'} ms-2">${l.severity}</span>
                <br>
                <strong>${l.action}</strong>: ${l.description}
            </div>
        `).join('') || '<p class="text-muted">No audit logs found</p>';
    }

    async checkAuth() {
        if (!this.token) {
            this.showLoginModal();
            return false;
        }

        try {
            const response = await fetch('/api/v1/auth/me', {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (response.ok) {
                this.user = await response.json();
                localStorage.setItem(AUTH_USER_KEY, JSON.stringify(this.user));
                this.updateUI();
                return true;
            } else {
                this.clearAuth();
                this.showLoginModal();
                return false;
            }
        } catch (error) {
            console.error('Auth check failed:', error);
            // Don't show login modal on network errors - might be temporary
            return false;
        }
    }

    async login() {
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;

        if (!email || !password) {
            this.showError('login-error', 'Please enter email and password');
            return;
        }

        try {
            const formData = new URLSearchParams();
            formData.append('username', email);
            formData.append('password', password);

            const response = await fetch('/api/v1/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: formData
            });

            if (response.ok) {
                const data = await response.json();
                this.token = data.access_token;
                localStorage.setItem(AUTH_TOKEN_KEY, this.token);
                
                // Get user info
                await this.checkAuth();
                
                // Hide modal
                this.loginModal?.hide();
                
                // Refresh dashboard
                if (typeof loadDashboardData === 'function') {
                    loadDashboardData();
                }
            } else {
                const error = await response.json();
                this.showError('login-error', error.detail || 'Login failed');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showError('login-error', 'Connection error. Please try again.');
        }
    }

    async register() {
        const name = document.getElementById('register-name').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;

        if (!name || !email || !password) {
            this.showError('register-error', 'Please fill in all fields');
            return;
        }

        if (password.length < 8) {
            this.showError('register-error', 'Password must be at least 8 characters');
            return;
        }

        try {
            const response = await fetch('/api/v1/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    full_name: name,
                    email: email,
                    password: password
                })
            });

            if (response.ok) {
                this.showSuccess('register-success', 'Account created! Please login.');
                
                // Switch to login form after delay
                setTimeout(() => {
                    document.getElementById('register-form').classList.add('d-none');
                    document.getElementById('login-form').classList.remove('d-none');
                    document.getElementById('login-email').value = email;
                    this.clearErrors();
                }, 1500);
            } else {
                const error = await response.json();
                this.showError('register-error', error.detail || 'Registration failed');
            }
        } catch (error) {
            console.error('Registration error:', error);
            this.showError('register-error', 'Connection error. Please try again.');
        }
    }

    logout() {
        this.clearAuth();
        this.showLoginModal();
    }

    clearAuth() {
        this.token = null;
        this.user = null;
        localStorage.removeItem(AUTH_TOKEN_KEY);
        localStorage.removeItem(AUTH_USER_KEY);
    }

    showLoginModal() {
        if (this.loginModal) {
            this.loginModal.show();
        }
    }

    updateUI() {
        if (!this.user) return;
        
        // Update username in navbar
        const userName = document.getElementById('user-name');
        if (userName) {
            userName.textContent = this.user.full_name || this.user.email || 'User';
        }
        
        // Update role badge
        const roleBadge = document.getElementById('user-role-badge');
        if (roleBadge) {
            const role = this.user.role || 'user';
            roleBadge.textContent = role;
            roleBadge.className = 'badge ms-1';
            if (role === 'admin') {
                roleBadge.classList.add('bg-danger');
            } else if (role === 'viewer') {
                roleBadge.classList.add('bg-secondary');
            } else {
                roleBadge.classList.add('bg-primary');
            }
        }
        
        // Show/hide admin menu
        const adminSection = document.getElementById('admin-menu-section');
        if (adminSection) {
            if (this.user.role === 'admin') {
                adminSection.classList.remove('d-none');
            } else {
                adminSection.classList.add('d-none');
            }
        }
        
        // Update profile modal
        this.updateProfileModal();
        
        // Apply role-based restrictions
        this.applyRoleRestrictions();
    }
    
    updateProfileModal() {
        if (!this.user) return;
        
        const profileName = document.getElementById('profile-name');
        const profileEmail = document.getElementById('profile-email');
        const profileRole = document.getElementById('profile-role');
        const profileCreated = document.getElementById('profile-created');
        
        if (profileName) profileName.value = this.user.full_name || '';
        if (profileEmail) profileEmail.value = this.user.email || '';
        if (profileRole) profileRole.value = (this.user.role || 'user').toUpperCase();
        if (profileCreated) {
            const date = this.user.created_at ? new Date(this.user.created_at).toLocaleDateString() : 'Unknown';
            profileCreated.value = date;
        }
    }
    
    applyRoleRestrictions() {
        const role = this.user?.role || 'user';
        
        // Viewers can't modify settings
        if (role === 'viewer') {
            document.getElementById('saveSettingsButton')?.setAttribute('disabled', 'true');
            document.getElementById('create-api-key-btn')?.setAttribute('disabled', 'true');
        }
        
        // Only admins can see certain sections
        const adminOnlyElements = document.querySelectorAll('[data-admin-only]');
        adminOnlyElements.forEach(el => {
            if (role !== 'admin') {
                el.classList.add('d-none');
            }
        });
    }
    
    isAdmin() {
        return this.user?.role === 'admin';
    }

    showError(elementId, message) {
        const el = document.getElementById(elementId);
        if (el) {
            el.textContent = message;
            el.classList.remove('d-none');
        }
    }

    showSuccess(elementId, message) {
        const el = document.getElementById(elementId);
        if (el) {
            el.textContent = message;
            el.classList.remove('d-none');
        }
    }

    clearErrors() {
        ['login-error', 'register-error', 'register-success'].forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.classList.add('d-none');
                el.textContent = '';
            }
        });
    }

    // Get auth header for API calls
    getAuthHeader() {
        return this.token ? { 'Authorization': `Bearer ${this.token}` } : {};
    }

    isAuthenticated() {
        return !!this.token;
    }
}

// Global instance
const authManager = new AuthManager();

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    authManager.init();
});

// Export for use in other modules
window.authManager = authManager;
