/**
 * main.js
 * Main entry point for the SentinelAI dashboard
 */

// Global variables for the dashboard
let map;
let mapMarkers = [];
let currentThreats = [];
let threatMap;
let autoUpdateInterval;
let mapInitialized = false; // Add flag to track map initialization
let autoUpdateEnabled = false; // Define autoUpdateEnabled variable with default value

/**
 * Initialize the application
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log('SentinelAI Dashboard initialized');
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Setup navigation
    setupNavigation();
    
    // Load the default page (dashboard)
    loadPage('dashboard');
    
    // Initialize Azure AI services
    initializeAzureAI();
    
    // Start the data refresh cycle
    startDataRefreshCycle();
});

/**
 * Setup navigation event handlers
 */
function setupNavigation() {
    // Get all nav links
    const navLinks = document.querySelectorAll('.nav-link[data-page]');
    
    // Add click event to each nav link
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Get the page to load
            const pageName = this.getAttribute('data-page');
            if (pageName) {
                loadPage(pageName);
                
                // Update active state in navbar
                document.querySelectorAll('.nav-link').forEach(navLink => {
                    navLink.classList.remove('active');
                });
                this.classList.add('active');
            }
        });
    });
    
    // Setup user dropdown handlers if present
    const userDropdown = document.getElementById('userDropdown');
    if (userDropdown) {
        const userMenuItems = userDropdown.querySelectorAll('.dropdown-item[data-action]');
        userMenuItems.forEach(item => {
            item.addEventListener('click', function(e) {
                e.preventDefault();
                const action = this.getAttribute('data-action');
                handleUserAction(action);
            });
        });
    }
}

/**
 * Load a specific page content
 * @param {string} pageName - Name of the page to load
 */
function loadPage(pageName) {
    console.log('Loading page:', pageName);
    
    // Use the showPage function from monitoring.js if available
    if (typeof showPage === 'function') {
        showPage(pageName);
        return;
    }
    
    // Fallback: Show the appropriate content and hide others
    const contentSections = document.querySelectorAll('.content-section');
    contentSections.forEach(section => {
        if (section.id === `${pageName}-content`) {
            section.classList.remove('d-none');
        } else {
            section.classList.add('d-none');
        }
    });
    
    // Specific page initialization
    switch (pageName) {
        case 'dashboard':
            initializeDashboard();
            break;
        case 'threats':
            // Scroll to threats section
            const threatList = document.getElementById('threat-list');
            if (threatList) threatList.scrollIntoView({ behavior: 'smooth' });
            fetchThreats();
            break;
        case 'agents':
            // Scroll to agents section
            const agentsTable = document.getElementById('agents-table');
            if (agentsTable) agentsTable.scrollIntoView({ behavior: 'smooth' });
            break;
        default:
            // For dashboard, just refresh
            initializeDashboard();
    }
    
    // Update page title
    document.title = `SentinelAI - ${pageName.charAt(0).toUpperCase() + pageName.slice(1)}`;
}

/**
 * Initialize the dashboard page
 */
function initializeDashboard() {
    console.log('Initializing dashboard');
    
    // Initialize charts via dashboardManager
    if (typeof DashboardManager !== 'undefined' && typeof DashboardManager.initCharts === 'function') {
        DashboardManager.initCharts();
    }
    
    // Load recent threats - use fetchThreats which is defined later
    if (typeof fetchThreats === 'function') {
        fetchThreats();
    }
    
    // Load AI stats
    if (typeof refreshAIData === 'function') {
        refreshAIData();
    }
}

/**
 * Initialize the threats page
 */
function initializeThreatsPage() {
    console.log('Initializing threats page');
    
    // Load threats data
    loadThreatsData();
    
    // Initialize threats filters
    initializeThreatsFilters();
}

/**
 * Initialize the AI services page
 */
function initializeAIServicesPage() {
    console.log('Initializing AI services page');
    
    // Load AI services data
    loadAIServicesData();
}

/**
 * Initialize the devices page
 */
function initializeDevicesPage() {
    console.log('Initializing devices page');
    
    // Load devices data
    loadDevicesData();
}

/**
 * Initialize the users page
 */
function initializeUsersPage() {
    console.log('Initializing users page');
    
    // Load users data
    loadUsersData();
}

/**
 * Initialize the settings page
 */
function initializeSettingsPage() {
    console.log('Initializing settings page');
    
    // Load current settings
    loadSettings();
}

/**
 * Initialize the reports page
 */
function initializeReportsPage() {
    console.log('Initializing reports page');
    
    // Load reports data
    loadReportsData();
}

/**
 * Start the data refresh cycle for real-time updates
 */
function startDataRefreshCycle() {
    console.log('Starting data refresh cycle');
    
    // Refresh dashboard data every 60 seconds
    setInterval(function() {
        const dashboardContent = document.getElementById('dashboard-content');
        if (dashboardContent && !dashboardContent.classList.contains('d-none')) {
            if (typeof refreshDashboardData === 'function') {
                refreshDashboardData();
            }
        } else {
            // If no specific content div, just refresh threats
            if (typeof fetchThreats === 'function') {
                fetchThreats();
            }
        }
    }, 60000);
    
    // Refresh threats data every 30 seconds
    setInterval(function() {
        const threatsContent = document.getElementById('threats-content');
        if (threatsContent && !threatsContent.classList.contains('d-none')) {
            if (typeof loadThreatsData === 'function') {
                loadThreatsData();
            }
        }
    }, 30000);
    
    // Refresh AI stats every 120 seconds
    setInterval(function() {
        if (typeof refreshAIData === 'function') {
            refreshAIData();
        }
    }, 120000);
}

/**
 * Initialize Azure AI services
 */
function initializeAzureAI() {
    console.log('Initializing Azure AI services');
    
    // Refresh AI data initially
    refreshAIData();
    
    // Check AI service status
    checkAIServiceStatus();
}

/**
 * Check the status of AI services
 */
function checkAIServiceStatus() {
    fetch('/api/v1/ai/status')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('AI service status:', data);
            
            // Update service status indicators if they exist
            const statusElement = document.getElementById('ai-service-status');
            if (statusElement) {
                if (data.operational) {
                    statusElement.innerHTML = '<span class="badge bg-success">Operational</span>';
                } else {
                    statusElement.innerHTML = '<span class="badge bg-danger">Service Issue</span>';
                }
            }
        })
        .catch(error => {
            console.error('Error checking AI service status:', error);
            showNotification('Error checking AI service status', 'warning');
        });
}

/**
 * Handle user actions from dropdown
 * @param {string} action - Action to perform
 */
function handleUserAction(action) {
    console.log('Handling user action:', action);
    
    switch (action) {
        case 'profile':
            loadPage('profile');
            break;
        case 'settings':
            loadPage('settings');
            break;
        case 'logout':
            window.location.href = '/logout';
            break;
        default:
            console.warn('Unknown user action:', action);
    }
}

/**
 * Initialize the dashboard
 */
function initDashboard() {
    console.log('Initializing dashboard components');
    
    try {
        // Make DashboardManager available globally
        window.DashboardManager = {
            populateDashboard: populateDashboard,
            updateThreatActivityChart: window.updateThreatActivityChart,
            updateThreatOriginsChart: window.updateThreatOriginsChart,
            updateStats: window.updateStats,
            updateAIMetrics: window.updateAIMetrics
        };
        
        // Check for Azure AI module
        if (typeof window.AzureAI === 'undefined') {
            // Create a dummy Azure AI module to prevent errors
            window.AzureAI = {
                updateMetrics: function(threats) {
                    console.log('Using fallback AzureAI module implementation');
                    // Update AI metrics elements if they exist
                    const analyzedCount = document.getElementById('ai-analyzed-count');
                    const anomaliesCount = document.getElementById('ai-anomalies');
                    
                    if (analyzedCount) {
                        analyzedCount.innerText = threats.filter(t => t.ai_analyzed).length;
                    }
                    
                    if (anomaliesCount) {
                        anomaliesCount.innerText = threats.filter(t => t.ai_anomaly_score > 0.7).length;
                    }
                }
            };
            console.warn('AzureAI module not available - AI features will be limited');
        }
        
        // Check if map is initialized before proceeding
        if (!mapInitialized) {
            console.error('Map not initialized - cannot initialize dashboard');
            return;
        }
        
        // Initialize all charts
        console.log('Initializing charts...');
        if (window.DashboardManager.initCharts) {
            window.DashboardManager.initCharts();
        } else {
            // If not available in DashboardManager, initialize them directly
            if (typeof initThreatActivityChart === 'function') {
                initThreatActivityChart();
            }
            
            if (typeof initThreatOriginsChart === 'function') {
                initThreatOriginsChart();
            }
        }
        
        // Fetch initial data
        fetchThreats();
        
        // Success notification
        showNotification('Dashboard initialized successfully', 'info');
    } catch (error) {
        console.error('Error initializing dashboard:', error);
        showNotification('Error initializing dashboard: ' + error.message, 'danger');
    }
}

/**
 * Initialize the map for threat visualization
 */
function initMap() {
    console.log('Initializing map');
    
    // Get map container element
    const mapElement = document.getElementById('map');
    if (!mapElement) {
        console.error('Map element not found - cannot initialize map');
        return;
    }
    
    try {
        // Create the map centered on world view
        map = L.map('map', {
            center: [30, 0],
            zoom: 2,
            minZoom: 2,
            maxZoom: 10
        });
        
        // Add OpenStreetMap tile layer
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        }).addTo(map);
        
        // Set the initialization flag
        mapInitialized = true;
        
        console.log('Map initialized successfully');
    } catch (error) {
        console.error('Error initializing map:', error);
    }
}

/**
 * Set up event listeners for the dashboard
 */
function setupEventListeners() {
    console.log('Setting up event listeners');
    
    // Refresh button
    const refreshButtons = document.querySelectorAll('.refresh-threats');
    refreshButtons.forEach(button => {
        button.addEventListener('click', function() {
            showNotification('Refreshing threat data...', 'info');
            fetchThreats();
        });
    });
    
    // Auto-update toggle
    const autoUpdateButton = document.getElementById('toggle-auto-threats');
    if (autoUpdateButton) {
        autoUpdateButton.addEventListener('click', toggleAutoUpdate);
    }
    
    // Time range buttons
    const timeButtons = document.querySelectorAll('[id^="time-range-"]');
    timeButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Remove active class from all buttons
            timeButtons.forEach(btn => btn.classList.remove('active', 'btn-secondary'));
            timeButtons.forEach(btn => btn.classList.add('btn-outline-secondary'));
            
            // Add active class to clicked button
            this.classList.remove('btn-outline-secondary');
            this.classList.add('active', 'btn-secondary');
            
            // Get time range from button id
            const timeRange = this.id.replace('time-range-', '');
            filterThreatsByTimeRange(timeRange);
        });
    });
    
    // Azure AI refresh button
    const refreshAIDataButton = document.querySelector('[id="refresh-ai-data"]');
    if (refreshAIDataButton) {
        refreshAIDataButton.addEventListener('click', function() {
            if (window.AzureAI && typeof window.AzureAI.refreshData === 'function') {
                window.AzureAI.refreshData();
                showNotification('Refreshing AI analysis...', 'info');
            }
        });
    }
    
    console.log('Event listeners set up successfully');
}

/**
 * Toggle automatic threat updates
 */
function toggleAutoUpdate() {
    const button = document.getElementById('toggle-auto-threats');
    const statusSpan = document.getElementById('auto-threats-status');
    
    if (!button || !statusSpan) {
        console.error('Auto update elements not found');
        return;
    }
    
    if (autoUpdateInterval) {
        // Turn off auto updates
        clearInterval(autoUpdateInterval);
        autoUpdateInterval = null;
        statusSpan.textContent = 'Auto Threats: Off';
        button.classList.remove('btn-success');
        button.classList.add('btn-outline-secondary');
        showNotification('Auto updates disabled', 'info');
    } else {
        // Turn on auto updates (every 30 seconds)
        statusSpan.textContent = 'Auto Threats: On';
        button.classList.remove('btn-outline-secondary');
        button.classList.add('btn-success');
        showNotification('Auto updates enabled (30s)', 'info');
        
        // Immediate update
        fetchThreats();
        
        // Set interval for future updates
        autoUpdateInterval = setInterval(fetchThreats, 30000);
    }
}

/**
 * Fetch threat data from the API
 */
function fetchThreats() {
    console.log('Fetching threat data from API');
    
    // Simulate loading state
    document.querySelectorAll('.stat-value').forEach(el => {
        el.classList.add('loading');
    });
    
    // Using the correct API endpoint
    fetch('/api/proxy/threats/recent')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Received threat data:', data.length, 'threats');
            currentThreats = data;
            
            // Remove loading state
            document.querySelectorAll('.stat-value').forEach(el => {
                el.classList.remove('loading');
            });
            
            // Update dashboard with threat data
            updateDashboardWithThreats(data);
            
            // Display appropriate notification
            if (data.length === 0) {
                showNotification('No threats found in database', 'info');
            } else {
                showNotification(`Loaded ${data.length} threats from database`, 'success');
            }
        })
        .catch(error => {
            console.error('Error fetching threats:', error);
            
            // Remove loading state
            document.querySelectorAll('.stat-value').forEach(el => {
                el.classList.remove('loading');
            });
            
            // Show error notification
            showNotification('Error connecting to API: ' + error.message, 'danger');
        });
}

/**
 * Update the dashboard with new threat data
 * @param {Array} threats - Array of threat objects
 */
function updateDashboardWithThreats(threats) {
    console.log('Updating dashboard with threats');
    
    try {
        // Check if Dashboard Manager is available
        if (!window.DashboardManager || typeof window.DashboardManager.populateDashboard !== 'function') {
            console.error('DashboardManager not available - cannot update dashboard');
            return;
        }
        
        // Call the Dashboard Manager to populate all components
        window.DashboardManager.populateDashboard(threats);
        
        // Update the threat list UI
        updateThreatsList(threats);
        
        // Set auto-refresh if needed
        if (autoUpdateEnabled && !autoUpdateInterval) {
            startAutoRefresh();
        }
    } catch (error) {
        console.error('Error updating dashboard:', error);
        showNotification('Error updating dashboard: ' + error.message, 'danger');
    }
}

/**
 * Update the threat list UI with threat data
 * @param {Array} threats - Array of threat objects
 */
function updateThreatsList(threats) {
    const threatListContainer = document.getElementById('threat-list');
    if (!threatListContainer) {
        console.error('Threat list container not found');
        return;
    }
    
    console.log('Updating threats list with', threats.length, 'threats');
    
    // Clear existing content
    threatListContainer.innerHTML = '';
    
    // If no threats, show a message
    if (threats.length === 0) {
        threatListContainer.innerHTML = '<div class="alert alert-info">No threats detected</div>';
        return;
    }
    
    // Sort threats by analysis_time (newest first) - more reliable than timestamp
    const sortedThreats = [...threats].sort((a, b) => {
        const timeA = new Date(b.analysis_time || b.timestamp || 0);
        const timeB = new Date(a.analysis_time || a.timestamp || 0);
        return timeA - timeB;
    });
    
    // Create a table for threats
    const table = document.createElement('table');
    table.className = 'table table-hover table-striped';
    
    // Create table header
    const thead = document.createElement('thead');
    thead.innerHTML = `
        <tr>
            <th>Type</th>
            <th>Severity</th>
            <th>Source</th>
            <th>Time</th>
            <th>Actions</th>
        </tr>
    `;
    table.appendChild(thead);
    
    // Create table body
    const tbody = document.createElement('tbody');
    
    // Add each threat to the table
    sortedThreats.forEach(threat => {
        const tr = document.createElement('tr');
        
        // Normalize severity to uppercase for comparison
        const severity = (threat.severity || 'NORMAL').toUpperCase();
        
        // Set row class based on severity
        if (severity === 'HIGH') {
            tr.className = 'table-danger';
        } else if (severity === 'MEDIUM') {
            tr.className = 'table-warning';
        }
        
        // Format the date using analysis_time (more reliable)
        const timeStr = threat.analysis_time || threat.timestamp;
        let formattedDate = 'Unknown';
        if (timeStr) {
            const date = new Date(timeStr);
            if (!isNaN(date.getTime())) {
                formattedDate = date.toLocaleString();
            }
        }
        
        // Get threat type from behavior field (API uses behavior, not type)
        const threatType = threat.behavior || threat.type || 'Unknown';
        
        // Get source from source_ip field (API uses source_ip, not source)
        const source = threat.source_ip || threat.source || 'Unknown';
        
        // Determine badge color based on severity
        let badgeClass = 'info';
        if (severity === 'HIGH') badgeClass = 'danger';
        else if (severity === 'MEDIUM') badgeClass = 'warning';
        else if (severity === 'LOW') badgeClass = 'primary';
        else if (severity === 'NORMAL') badgeClass = 'secondary';
        
        // Create the row content
        tr.innerHTML = `
            <td>${threatType}</td>
            <td><span class="badge bg-${badgeClass}">${severity}</span></td>
            <td>${source}</td>
            <td>${formattedDate}</td>
            <td>
                <button class="btn btn-sm btn-outline-secondary" data-threat-id="${threat.id}" onclick="showThreatDetails('${threat.id}')">
                    <i class="bi bi-eye"></i>
                </button>
            </td>
        `;
        
        tbody.appendChild(tr);
    });
    
    table.appendChild(tbody);
    threatListContainer.appendChild(table);
}

/**
 * Show threat details in the modal
 * @param {string} threatId - ID of the threat to show details for
 */
function showThreatDetails(threatId) {
    console.log('Showing details for threat ID:', threatId);
    
    // Find the threat in the current threats array
    const threat = currentThreats.find(t => t.id === threatId);
    if (!threat) {
        console.error('Threat not found with ID:', threatId);
        showNotification('Threat details not found', 'danger');
        return;
    }
    
    // Set modal title and details
    const modal = document.getElementById('threatDetailsModal');
    const modalTitle = document.getElementById('threatDetailsModalLabel');
    
    if (!modal || !modalTitle) {
        console.error('Modal elements not found');
        return;
    }
    
    // Set modal title with severity badge
    let severityClass = 'bg-info';
    if (threat.severity === 'HIGH') {
        severityClass = 'bg-danger';
    } else if (threat.severity === 'MEDIUM') {
        severityClass = 'bg-warning';
    } else if (threat.severity === 'LOW') {
        severityClass = 'bg-info';
    }
    
    modalTitle.innerHTML = `
        Threat Details 
        <span class="badge ${severityClass} ms-2">${threat.severity}</span>
        <span class="badge bg-secondary ms-2">${threat.protocol || 'Unknown'}</span>
    `;
    
    // Populate details
    const detailsContainer = document.getElementById('threatDetailsContent');
    if (detailsContainer) {
        // Format timestamps for readability - prefer analysis_time over timestamp
        const timeValue = threat.analysis_time || threat.timestamp || threat.detection_time;
        const timestamp = timeValue ? new Date(timeValue).toLocaleString() : 'Unknown';
        const detectedTime = timestamp;
        
        // Build the details HTML
        let detailsHtml = `
            <div class="row mb-3">
                <div class="col-md-6">
                    <div class="mb-2"><strong>Source IP:</strong> ${threat.source_ip}</div>
                    <div class="mb-2"><strong>Destination IP:</strong> ${threat.destination_ip || 'N/A'}</div>
                    <div class="mb-2"><strong>Protocol:</strong> ${threat.protocol || 'Unknown'}</div>
                    <div class="mb-2"><strong>Detected:</strong> ${detectedTime}</div>
                </div>
                <div class="col-md-6">
                    <div class="mb-2"><strong>Severity:</strong> <span class="badge bg-${threat.severity === 'high' ? 'danger' : (threat.severity === 'medium' ? 'warning' : 'info')}">${threat.severity || 'low'}</span></div>
                    <div class="mb-2"><strong>Status:</strong> <span class="badge bg-${threat.resolved ? 'success' : 'warning'}">${threat.resolved ? 'Resolved' : 'Active'}</span></div>
                    <div class="mb-2"><strong>Confidence:</strong> ${Math.round(threat.confidence * 100)}%</div>
                    <div class="mb-2"><strong>Time:</strong> ${timestamp}</div>
                </div>
            </div>
        `;
        
        // Add AI analysis if available
        if (threat.ai_analyzed) {
            detailsHtml += `
                <div class="row mb-3">
                    <div class="col-12">
                        <div class="card border-primary">
                            <div class="card-header bg-primary text-white">
                                <i class="bi bi-robot"></i> AI Analysis
                            </div>
                            <div class="card-body">
                                <div class="mb-2"><strong>Classification:</strong> ${threat.classification || 'Unknown'}</div>
                                <div class="mb-2"><strong>AI Confidence:</strong> ${Math.round(threat.ai_confidence * 100)}%</div>
                                ${threat.ai_summary ? `<div class="mb-2"><strong>Summary:</strong> ${threat.ai_summary}</div>` : ''}
                                ${threat.ai_anomaly_score ? `<div class="mb-2"><strong>Anomaly Score:</strong> ${Math.round(threat.ai_anomaly_score * 100)}%</div>` : ''}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        // Add AI Actions section - always show for re-analysis
        detailsHtml += `
            <div class="row mb-3">
                <div class="col-12">
                    <div class="card border-info">
                        <div class="card-header bg-info text-white">
                            <i class="bi bi-cpu"></i> AI Actions
                        </div>
                        <div class="card-body">
                            <div class="d-flex flex-wrap gap-2 mb-3">
                                <button class="btn btn-primary" onclick="reanalyzeWithAI('${threat.id}')" id="reanalyze-btn-${threat.id}">
                                    <i class="bi bi-arrow-repeat"></i> Re-analyze with AI
                                </button>
                                <button class="btn btn-success" onclick="addToWhitelist('${threat.id}', '${threat.source_ip}')">
                                    <i class="bi bi-check-circle"></i> Mark as Safe / Whitelist
                                </button>
                                <button class="btn btn-outline-secondary" onclick="markAsFalsePositive('${threat.id}')">
                                    <i class="bi bi-x-circle"></i> False Positive
                                </button>
                            </div>
                            <div id="ai-analysis-result-${threat.id}" class="d-none">
                                <hr>
                                <h6><i class="bi bi-lightbulb"></i> New AI Analysis:</h6>
                                <div id="ai-analysis-content-${threat.id}"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Add payload data if available
        if (threat.payload) {
            detailsHtml += `
                <div class="row mb-3">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                Payload Data
                            </div>
                            <div class="card-body">
                                <pre class="mb-0"><code>${threat.payload}</code></pre>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        // Add recommendation if available
        if (threat.recommendation) {
            detailsHtml += `
                <div class="row mb-3">
                    <div class="col-12">
                        <div class="card border-info">
                            <div class="card-header bg-info text-white">
                                <i class="bi bi-lightbulb"></i> Recommendation
                            </div>
                            <div class="card-body">
                                ${threat.recommendation}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        // Add location info if available
        if (threat.location || threat.latitude) {
            detailsHtml += `
                <div class="row mb-3">
                    <div class="col-12">
                        <div class="card border-secondary">
                            <div class="card-header bg-secondary text-white">
                                <i class="bi bi-geo-alt"></i> Threat Origin
                            </div>
                            <div class="card-body">
                                <div class="mb-2"><strong>Location:</strong> ${threat.location?.city || 'Unknown'}, ${threat.location?.country || threat.location?.country_name || 'Unknown'}</div>
                                <div class="mb-2"><strong>Coordinates:</strong> ${threat.latitude?.toFixed(4) || 'N/A'}, ${threat.longitude?.toFixed(4) || 'N/A'}</div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        // Add remediation steps if available
        if (threat.remediation_steps && threat.remediation_steps.length > 0) {
            let stepsHtml = '';
            threat.remediation_steps.forEach((step, index) => {
                const isApplied = threat.applied_fixes?.some(f => f.action === step.action);
                const btnClass = isApplied ? 'btn-success disabled' : (step.automated ? 'btn-warning' : 'btn-outline-secondary');
                const btnText = isApplied ? '<i class="bi bi-check-circle"></i> Applied' : (step.automated ? '<i class="bi bi-play-circle"></i> Apply Fix' : '<i class="bi bi-hand-index"></i> Manual');
                
                stepsHtml += `
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                        <div>
                            <strong>${step.action?.replace(/_/g, ' ').toUpperCase()}</strong>
                            <br><small class="text-muted">${step.description || ''}</small>
                            ${step.command ? `<br><code class="small">${step.command}</code>` : ''}
                        </div>
                        <button class="btn btn-sm ${btnClass}" 
                                onclick="applyFix('${threat.id}', ${index})"
                                ${isApplied || !step.automated ? 'disabled' : ''}>
                            ${btnText}
                        </button>
                    </div>
                `;
            });
            
            detailsHtml += `
                <div class="row mb-3">
                    <div class="col-12">
                        <div class="card border-warning">
                            <div class="card-header bg-warning text-dark">
                                <i class="bi bi-tools"></i> Remediation Steps
                            </div>
                            <div class="card-body p-0">
                                <div class="list-group list-group-flush">
                                    ${stepsHtml}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        // Add description if available (from AI analysis)
        if (threat.description) {
            detailsHtml += `
                <div class="row mb-3">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <i class="bi bi-file-text"></i> Analysis Details
                            </div>
                            <div class="card-body">
                                ${threat.description}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        detailsContainer.innerHTML = detailsHtml;
        
        // Update button states based on threat resolved status
        const resolveButton = document.getElementById('resolve-threat-btn');
        const blockButton = document.getElementById('block-threat-btn');
        
        if (resolveButton) {
            if (threat.resolved) {
                resolveButton.classList.add('disabled');
                resolveButton.textContent = 'Resolved';
            } else {
                resolveButton.classList.remove('disabled');
                resolveButton.textContent = 'Resolve';
                
                // Set up the click event for resolve button
                resolveButton.onclick = function() {
                    resolveThreat(threatId);
                };
            }
        }
        
        if (blockButton) {
            if (threat.blocked) {
                blockButton.classList.add('disabled');
                blockButton.textContent = 'Blocked';
            } else {
                blockButton.classList.remove('disabled');
                blockButton.textContent = 'Block Source';
                
                // Set up the click event for block button
                blockButton.onclick = function() {
                    blockThreat(threatId);
                };
            }
        }
    }
    
    // Show the modal
    const modalElement = bootstrap.Modal.getInstance(modal) || new bootstrap.Modal(modal);
    modalElement.show();
}

/**
 * Apply a fix for a threat
 * @param {string} threatId - ID of the threat
 * @param {number} fixIndex - Index of the fix to apply
 */
function applyFix(threatId, fixIndex) {
    console.log(`Applying fix ${fixIndex} for threat ${threatId}`);
    
    // Show confirmation dialog
    const threat = currentThreats.find(t => t.id === threatId);
    if (!threat) {
        showNotification('Threat not found', 'danger');
        return;
    }
    
    const fix = threat.remediation_steps?.[fixIndex];
    if (!fix) {
        showNotification('Fix not found', 'danger');
        return;
    }
    
    const confirmMsg = `Are you sure you want to apply this fix?\n\nAction: ${fix.action?.replace(/_/g, ' ').toUpperCase()}\nDescription: ${fix.description}\n${fix.command ? `Command: ${fix.command}` : ''}`;
    
    if (!confirm(confirmMsg)) {
        return;
    }
    
    showNotification('Applying fix...', 'info');
    
    // Call the API to apply the fix
    fetch(`/api/v1/threats/${threatId}/apply-fix?fix_index=${fixIndex}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Fix applied:', data);
        
        // Update the threat in the current threats array
        const threatIndex = currentThreats.findIndex(t => t.id === threatId);
        if (threatIndex !== -1) {
            if (!currentThreats[threatIndex].applied_fixes) {
                currentThreats[threatIndex].applied_fixes = [];
            }
            currentThreats[threatIndex].applied_fixes.push(data.fix);
            currentThreats[threatIndex].status = data.threat_status;
        }
        
        showNotification(`Fix applied successfully: ${fix.action}`, 'success');
        
        // Refresh the modal to show updated state
        showThreatDetails(threatId);
        
        // Refresh the threats list
        fetchThreats();
    })
    .catch(error => {
        console.error('Error applying fix:', error);
        showNotification('Error applying fix: ' + error.message, 'danger');
    });
}

/**
 * Resolve a threat
 * @param {string} threatId - ID of the threat to resolve
 */
function resolveThreat(threatId) {
    console.log('Resolving threat:', threatId);
    showNotification('Processing request...', 'info');
    
    // Call the API to resolve the threat
    fetch(`/api/v1/threats/${threatId}/resolve`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${window.authManager?.token}`
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Threat resolved:', data);
        
        // Update the threat in the current threats array
        const threatIndex = currentThreats.findIndex(t => t.id === threatId);
        if (threatIndex !== -1) {
            currentThreats[threatIndex].resolved = true;
            
            // Update the UI
            updateThreatsList(currentThreats);
            
            // Update the modal buttons
            const resolveButton = document.getElementById('resolve-threat-btn');
            if (resolveButton) {
                resolveButton.classList.add('disabled');
                resolveButton.textContent = 'Resolved';
            }
        }
        
        showNotification('Threat successfully resolved', 'success');
    })
    .catch(error => {
        console.error('Error resolving threat:', error);
        showNotification('Error resolving threat: ' + error.message, 'danger');
    });
}

/**
 * Block a threat's source IP
 * @param {string} threatId - ID of the threat to block
 */
function blockThreat(threatId) {
    console.log('Blocking threat source:', threatId);
    showNotification('Processing block request...', 'info');
    
    // Call the API to block the threat source
    fetch(`/api/v1/threats/${threatId}/block`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${window.authManager?.token}`
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Threat source blocked:', data);
        
        // Update the threat in the current threats array
        const threatIndex = currentThreats.findIndex(t => t.id === threatId);
        if (threatIndex !== -1) {
            currentThreats[threatIndex].blocked = true;
            
            // Update the UI
            updateThreatsList(currentThreats);
            
            // Update the modal buttons
            const blockButton = document.getElementById('block-threat-btn');
            if (blockButton) {
                blockButton.classList.add('disabled');
                blockButton.textContent = 'Blocked';
            }
        }
        
        showNotification('Source IP successfully blocked', 'success');
    })
    .catch(error => {
        console.error('Error blocking threat source:', error);
        showNotification('Error blocking source: ' + error.message, 'danger');
    });
}

/**
 * Re-analyze a threat with AI
 * @param {string} threatId - ID of the threat to re-analyze
 */
function reanalyzeWithAI(threatId) {
    console.log('Re-analyzing threat with AI:', threatId);
    
    // Find the threat data
    const threat = currentThreats.find(t => t.id === threatId);
    if (!threat) {
        showNotification('Threat not found', 'danger');
        return;
    }
    
    // Update button to show loading
    const btn = document.getElementById(`reanalyze-btn-${threatId}`);
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Analyzing...';
    }
    
    showNotification('Sending to AI for analysis...', 'info');
    
    // Call the re-analyze API
    fetch('/api/v1/ai/reanalyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            source_ip: threat.source_ip,
            destination_ip: threat.destination_ip,
            protocol: threat.protocol,
            threat_type: threat.type || threat.threat_type,
            description: threat.description,
            payload: threat.payload,
            severity: threat.severity,
            additional_data: threat.additional_data || {}
        })
    })
    .then(response => response.json())
    .then(data => {
        console.log('AI Re-analysis result:', data);
        
        // Show the result
        const resultDiv = document.getElementById(`ai-analysis-result-${threatId}`);
        const contentDiv = document.getElementById(`ai-analysis-content-${threatId}`);
        
        if (resultDiv && contentDiv) {
            resultDiv.classList.remove('d-none');
            
            const analysis = data.analysis || data;
            const isFalsePositive = analysis.is_false_positive || analysis.severity === 'NORMAL';
            const severityClass = analysis.severity === 'HIGH' ? 'danger' : 
                                 analysis.severity === 'MEDIUM' ? 'warning' : 
                                 analysis.severity === 'NORMAL' ? 'success' : 'info';
            
            contentDiv.innerHTML = `
                <div class="alert alert-${severityClass}">
                    <strong>Severity:</strong> ${analysis.severity || 'Unknown'}
                    ${isFalsePositive ? '<span class="badge bg-success ms-2">FALSE POSITIVE</span>' : ''}
                </div>
                <p><strong>Type:</strong> ${analysis.threat_type || 'Unknown'}</p>
                <p><strong>Description:</strong> ${analysis.description || 'No description'}</p>
                ${analysis.why_safe_or_dangerous ? `<p><strong>Analysis:</strong> ${analysis.why_safe_or_dangerous}</p>` : ''}
                <p><strong>Risk Score:</strong> ${analysis.risk_score || 0}/100</p>
                <p><strong>Recommendation:</strong> ${analysis.recommendation || 'Manual review'}</p>
                ${isFalsePositive ? `
                    <div class="mt-3">
                        <button class="btn btn-success btn-sm" onclick="addToWhitelist('${threatId}', '${threat.source_ip}')">
                            <i class="bi bi-check-circle"></i> Add to Whitelist
                        </button>
                        <button class="btn btn-outline-secondary btn-sm" onclick="markAsFalsePositive('${threatId}')">
                            <i class="bi bi-x-circle"></i> Dismiss as False Positive
                        </button>
                    </div>
                ` : ''}
            `;
        }
        
        // Reset button
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Re-analyze with AI';
        }
        
        showNotification('AI analysis complete!', 'success');
    })
    .catch(error => {
        console.error('Error re-analyzing threat:', error);
        showNotification('Error: ' + error.message, 'danger');
        
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Re-analyze with AI';
        }
    });
}

/**
 * Add an event/IP to whitelist
 * @param {string} threatId - ID of the threat
 * @param {string} sourceIp - Source IP to whitelist
 */
function addToWhitelist(threatId, sourceIp) {
    console.log('Adding to whitelist:', threatId, sourceIp);
    
    const threat = currentThreats.find(t => t.id === threatId);
    const reason = prompt('Reason for whitelisting (optional):', 'Verified as safe system activity');
    
    if (reason === null) return; // User cancelled
    
    fetch('/api/v1/ai/whitelist/event', {
        method: 'POST',
        headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${window.authManager?.token}`
        },
        body: JSON.stringify({
            event_type: threat?.type || 'unknown',
            event_id: threatId,
            source: sourceIp,
            reason: reason
        })
    })
    .then(response => response.json())
    .then(data => {
        console.log('Whitelist result:', data);
        showNotification('Added to whitelist successfully!', 'success');
        
        // Also add IP to auto-response whitelist
        fetch('/api/v1/auto-response/whitelist', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${window.authManager?.token}`
            },
            body: JSON.stringify({ ip: sourceIp, action: 'add' })
        });
        
        // Mark threat as resolved
        resolveThreat(threatId);
    })
    .catch(error => {
        console.error('Error adding to whitelist:', error);
        showNotification('Error: ' + error.message, 'danger');
    });
}

/**
 * Mark a threat as false positive
 * @param {string} threatId - ID of the threat
 */
function markAsFalsePositive(threatId) {
    console.log('Marking as false positive:', threatId);
    
    if (!confirm('Mark this threat as a false positive? It will be resolved and logged.')) {
        return;
    }
    
    // Resolve the threat
    resolveThreat(threatId);
    
    showNotification('Marked as false positive', 'success');
}

/**
 * Update map markers based on threat data
 * @param {Array} threats - Array of threat objects
 */
function updateMapMarkers(threats) {
    console.log('Updating map markers');
    
    // Check if map is initialized
    if (!map || !mapInitialized) {
        console.error('Map not initialized - cannot update markers');
        // Try again after a delay in case map is still initializing
        setTimeout(() => {
            if (map && mapInitialized) {
                console.log('Map now initialized, updating markers');
                updateMapMarkers(threats);
            }
        }, 1000);
        return;
    }
    
    // Clear existing markers
    clearMapMarkers();
    
    // Create markers for each threat with valid coordinates
    let validMarkers = 0;
    threats.forEach(threat => {
        if (threat.latitude && threat.longitude) {
            addMapMarker(threat.latitude, threat.longitude, threat.severity, threat.type);
            validMarkers++;
        }
    });
    
    console.log(`Added ${validMarkers} map markers`);
}

/**
 * Clear all markers from the map
 */
function clearMapMarkers() {
    if (!map || !mapInitialized) {
        console.error('Map not initialized - cannot clear markers');
        return;
    }
    
    // Remove all current markers
    mapMarkers.forEach(marker => {
        if (map.hasLayer(marker)) {
            map.removeLayer(marker);
        }
    });
    
    // Reset markers array
    mapMarkers = [];
    console.log('Map markers cleared');
}

/**
 * Add a marker to the map
 * @param {number} lat - Latitude
 * @param {number} lng - Longitude
 * @param {string} severity - Threat severity for marker color
 * @param {string} title - Marker title/popup
 */
function addMapMarker(lat, lng, severity, title) {
    if (!map || !mapInitialized) {
        console.error('Map not initialized - cannot add marker');
        return;
    }
    
    try {
        // Create marker color based on severity
        const color = severity === 'high' ? 'red' : 
                     (severity === 'medium' ? 'orange' : 'blue');
        
        // Create marker and add to map
        const marker = L.circleMarker([lat, lng], {
            radius: 8,
            fillColor: color,
            color: '#fff',
            weight: 1,
            opacity: 1,
            fillOpacity: 0.8
        }).addTo(map);
        
        // Add popup with threat information
        marker.bindPopup(`<b>${title}</b><br>Severity: ${severity}<br>Location: ${lat.toFixed(4)}, ${lng.toFixed(4)}`);
        
        // Add to markers array
        mapMarkers.push(marker);
    } catch (error) {
        console.error('Error adding map marker:', error);
    }
}

/**
 * Filter threats by time range and update dashboard
 * @param {string} timeRange - Time range to filter ('today', 'week', 'month')
 */
function filterThreatsByTimeRange(timeRange) {
    if (!currentThreats || currentThreats.length === 0) {
        console.warn('No threats to filter');
        return;
    }
    
    console.log('Filtering threats by time range:', timeRange);
    
    const now = new Date();
    const filteredThreats = currentThreats.filter(threat => {
        const threatTime = new Date(threat.timestamp);
        
        switch (timeRange) {
            case 'today':
                // Same day
                return threatTime.toDateString() === now.toDateString();
            case 'week':
                // Last 7 days
                const oneWeekAgo = new Date(now);
                oneWeekAgo.setDate(now.getDate() - 7);
                return threatTime >= oneWeekAgo;
            case 'month':
                // Last 30 days
                const oneMonthAgo = new Date(now);
                oneMonthAgo.setDate(now.getDate() - 30);
                return threatTime >= oneMonthAgo;
            default:
                return true;
        }
    });
    
    // Update dashboard with filtered threats
    updateDashboardWithThreats(filteredThreats);
    
    // Show notification
    showNotification(`Showing threats from: ${timeRange}`, 'info');
}

/**
 * Show a notification to the user
 * @param {string} message - Notification message
 * @param {string} type - Notification type ('success', 'info', 'warning', 'danger')
 */
function showNotification(message, type = 'info') {
    // Use the utility module if available
    if (window.Utilities && typeof window.Utilities.showNotification === 'function') {
        window.Utilities.showNotification(message, type);
        return;
    }
    
    // Fallback notification implementation
    console.log(`Notification (${type}): ${message}`);
    
    // Create toast element
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    toast.setAttribute('id', toastId);
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    // Find or create toast container
    let toastContainer = document.querySelector('.toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    // Add toast to container
    toastContainer.appendChild(toast);
    
    // Initialize and show the toast
    const bsToast = new bootstrap.Toast(toast, { autohide: true, delay: 5000 });
    bsToast.show();
    
    // Remove from DOM after hiding
    toast.addEventListener('hidden.bs.toast', function () {
        toast.remove();
    });
}

// DOM loaded event listener
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM fully loaded - initializing dashboard');
    
    // Initialize the map first
    initMap();
    
    // Initialize the dashboard with a delay to ensure map is ready
    setTimeout(() => {
        initDashboard();
        
        // Initial data fetch after dashboard is initialized
        fetchThreats();
    }, 800); // Increase delay to ensure map is fully initialized
    
    // Set up event listeners
    setupEventListeners();
});

// Make map functions available to other modules
window.clearMapMarkers = clearMapMarkers;
window.addMapMarker = addMapMarker;

// Initialize on window load for additional resources
window.addEventListener('load', function() {
    console.log('All resources loaded');
});

// Expose functions for global use
window.refreshThreats = fetchThreats;
window.filterThreatsByTimeRange = filterThreatsByTimeRange;

/**
 * Load AI services data
 */
function loadAIServicesData() {
    console.log('Loading AI services data');
    showNotification('Loading AI services data...', 'info', 2000);
    
    // Fetch AI services data from API
    fetch('/api/v1/ai/services')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('AI services data:', data);
            displayAIServicesData(data);
        })
        .catch(error => {
            console.error('Error loading AI services data:', error);
            showNotification('Error loading AI services data', 'danger');
        });
}

/**
 * Display AI services data in the UI
 * @param {Array} services - Array of AI services data
 */
function displayAIServicesData(services) {
    const container = document.getElementById('ai-services-container');
    if (!container) {
        console.error('AI services container not found');
        return;
    }
    
    // Clear existing content
    container.innerHTML = '';
    
    if (!services || services.length === 0) {
        container.innerHTML = '<div class="alert alert-info">No AI services available</div>';
        return;
    }
    
    // Create cards for each service
    services.forEach(service => {
        const statusClass = service.status === 'active' ? 'success' : 
                           (service.status === 'warning' ? 'warning' : 
                           (service.status === 'error' ? 'danger' : 'secondary'));
        
        const serviceCard = document.createElement('div');
        serviceCard.className = 'col-md-6 col-lg-4 mb-4';
        serviceCard.innerHTML = `
            <div class="card h-100 ${service.status === 'error' ? 'border-danger' : ''}">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">${service.name}</h5>
                    <span class="badge bg-${statusClass}">${service.status}</span>
                </div>
                <div class="card-body">
                    <p class="card-text">${service.description}</p>
                    <div class="mb-3">
                        <small class="text-muted">Service Type: ${service.type}</small>
                    </div>
                    <div class="mb-3">
                        <strong>Performance:</strong>
                        <div class="progress mt-1">
                            <div class="progress-bar bg-${statusClass}" role="progressbar" 
                                style="width: ${service.performance * 100}%" 
                                aria-valuenow="${service.performance * 100}" 
                                aria-valuemin="0" aria-valuemax="100">
                                ${Math.round(service.performance * 100)}%
                            </div>
                        </div>
                    </div>
                    ${service.last_used ? `<div class="mb-2">
                        <small class="text-muted">Last Used: ${new Date(service.last_used).toLocaleString()}</small>
                    </div>` : ''}
                    ${service.usage_count !== undefined ? `<div class="mb-2">
                        <small class="text-muted">Usage Count: ${service.usage_count}</small>
                    </div>` : ''}
                </div>
                <div class="card-footer d-flex justify-content-between">
                    <button class="btn btn-sm btn-primary ai-service-test" data-service-id="${service.id}">
                        <i class="bi bi-play-fill"></i> Test Service
                    </button>
                    <button class="btn btn-sm btn-outline-secondary ai-service-config" data-service-id="${service.id}">
                        <i class="bi bi-gear-fill"></i> Configure
                    </button>
                </div>
            </div>
        `;
        
        container.appendChild(serviceCard);
    });
    
    // Add event listeners to buttons
    document.querySelectorAll('.ai-service-test').forEach(button => {
        button.addEventListener('click', function() {
            const serviceId = this.getAttribute('data-service-id');
            testAIService(serviceId);
        });
    });
    
    document.querySelectorAll('.ai-service-config').forEach(button => {
        button.addEventListener('click', function() {
            const serviceId = this.getAttribute('data-service-id');
            configureAIService(serviceId);
        });
    });
}

/**
 * Test an AI service
 * @param {string} serviceId - ID of the service to test
 */
function testAIService(serviceId) {
    console.log('Testing AI service:', serviceId);
    showNotification('Testing AI service...', 'info');
    
    fetch(`/api/v1/ai/services/${serviceId}/test`, {
        method: 'POST'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Test result:', data);
        
        if (data.success) {
            showNotification(`Service test successful: ${data.message}`, 'success');
        } else {
            showNotification(`Service test failed: ${data.message}`, 'warning');
        }
    })
    .catch(error => {
        console.error('Error testing AI service:', error);
        showNotification(`Error testing service: ${error.message}`, 'danger');
    });
}

/**
 * Open configuration modal for an AI service
 * @param {string} serviceId - ID of the service to configure
 */
function configureAIService(serviceId) {
    console.log('Configuring AI service:', serviceId);
    
    // Fetch service configuration
    fetch(`/api/v1/ai/services/${serviceId}/config`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Service configuration:', data);
            
            // Get the modal
            const modal = document.getElementById('aiServiceConfigModal');
            const modalTitle = document.getElementById('aiServiceConfigModalLabel');
            const modalBody = document.getElementById('ai-service-config-body');
            const saveButton = document.getElementById('save-ai-service-config');
            
            if (!modal || !modalTitle || !modalBody || !saveButton) {
                console.error('Modal elements not found');
                return;
            }
            
            // Set modal title
            modalTitle.textContent = `Configure ${data.name}`;
            
            // Generate form fields based on configuration options
            let formHtml = '';
            
            Object.entries(data.config).forEach(([key, value]) => {
                let inputType = 'text';
                let inputValue = value;
                
                // Determine input type based on value
                if (typeof value === 'boolean') {
                    inputType = 'checkbox';
                } else if (typeof value === 'number') {
                    inputType = 'number';
                }
                
                // Format key for display
                const displayKey = key.replace(/_/g, ' ')
                    .replace(/\b\w/g, l => l.toUpperCase());
                
                if (inputType === 'checkbox') {
                    formHtml += `
                        <div class="form-check mb-3">
                            <input type="checkbox" class="form-check-input" id="config-${key}" 
                                name="${key}" ${value ? 'checked' : ''}>
                            <label class="form-check-label" for="config-${key}">${displayKey}</label>
                        </div>
                    `;
                } else {
                    formHtml += `
                        <div class="mb-3">
                            <label for="config-${key}" class="form-label">${displayKey}</label>
                            <input type="${inputType}" class="form-control" id="config-${key}" 
                                name="${key}" value="${inputValue}">
                        </div>
                    `;
                }
            });
            
            // Add a hidden input for the service ID
            formHtml += `<input type="hidden" id="config-service-id" value="${serviceId}">`;
            
            // Set the form HTML
            modalBody.innerHTML = formHtml;
            
            // Set up save button handler
            saveButton.onclick = function() {
                saveAIServiceConfig(serviceId);
            };
            
            // Show the modal
            const bsModal = new bootstrap.Modal(modal);
            bsModal.show();
        })
        .catch(error => {
            console.error('Error loading service configuration:', error);
            showNotification('Error loading service configuration', 'danger');
        });
}

/**
 * Save AI service configuration
 * @param {string} serviceId - ID of the service to save configuration for
 */
function saveAIServiceConfig(serviceId) {
    console.log('Saving configuration for service:', serviceId);
    
    // Get all form fields
    const form = document.getElementById('ai-service-config-body');
    const inputs = form.querySelectorAll('input');
    
    // Build configuration object
    const config = {};
    
    inputs.forEach(input => {
        const name = input.getAttribute('name');
        if (name && name !== 'service-id') {
            if (input.type === 'checkbox') {
                config[name] = input.checked;
            } else if (input.type === 'number') {
                config[name] = parseFloat(input.value);
            } else {
                config[name] = input.value;
            }
        }
    });
    
    // Send configuration to API
    fetch(`/api/v1/ai/services/${serviceId}/config`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ config })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Configuration saved:', data);
        
        // Close the modal
        const modal = document.getElementById('aiServiceConfigModal');
        const bsModal = bootstrap.Modal.getInstance(modal);
        if (bsModal) {
            bsModal.hide();
        }
        
        // Show success notification
        showNotification('Service configuration saved successfully', 'success');
        
        // Reload services data to reflect changes
        loadAIServicesData();
    })
    .catch(error => {
        console.error('Error saving service configuration:', error);
        showNotification(`Error saving configuration: ${error.message}`, 'danger');
    });
}
