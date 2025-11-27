/**
 * dashboardManager.js
 * Handles dashboard visualization and updates for the SentinelAI dashboard
 */

// Chart objects for global reference
let threatActivityChart;
let threatOriginsChart;
let cpuChart;
let memoryChart;
let networkChart;
let anomalyChart;

// Track charts for consistent updates
const charts = {
    activityChart: null,
    originsChart: null
};

/**
 * Initialize all charts and visualizations
 */
function initCharts() {
    console.log('Initializing all dashboard charts');
    
    try {
        // Initialize the threat activity chart
        initThreatActivityChart();
        
        // Initialize the threat origins chart
        initThreatOriginsChart();
        
        // Initialize any other charts
        initSystemResourceCharts();
        
        console.log('All charts initialized successfully');
        return true;
    } catch (error) {
        console.error('Error initializing charts:', error);
        return false;
    }
}

/**
 * Initialize the threat activity chart
 * @returns {boolean} - Whether the chart was successfully initialized
 */
function initThreatActivityChart() {
    console.log('Initializing threat activity chart...');
    
    try {
        // Check if Chart is defined
        if (typeof Chart === 'undefined') {
            console.error('Chart.js not loaded - cannot initialize threat activity chart');
            return false;
        }
        
        // Get the chart canvas
        const chartCanvas = document.getElementById('threatChart');
        if (!chartCanvas) {
            console.error('Threat activity chart canvas not found (ID: threatChart)');
            return false;
        }
        
        // Destroy existing chart if it exists
        if (charts.activityChart) {
            charts.activityChart.destroy();
        }
        
        // Initial data - will be updated with real data
        const initialData = {
            labels: ['00:00', '01:00', '02:00', '03:00', '04:00', '05:00'],
            datasets: [{
                label: 'Threats',
                data: [0, 0, 0, 0, 0, 0],
                borderColor: 'rgba(255, 99, 132, 1)',
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        };
        
        // Create the chart
        charts.activityChart = new Chart(chartCanvas, {
            type: 'line',
            data: initialData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                }
            }
        });
        
        console.log('Threat activity chart initialized');
        return true;
    } catch (error) {
        console.error('Error initializing threat activity chart:', error);
        return false;
    }
}

/**
 * Initialize the threat origins chart
 * @returns {boolean} - Whether the chart was successfully initialized
 */
function initThreatOriginsChart() {
    console.log('Initializing threat origins chart');
    
    try {
        // Check if Chart is defined
        if (typeof Chart === 'undefined') {
            console.error('Chart.js not loaded - cannot initialize threat origins chart');
            return false;
        }
        
        // Get the chart canvas element
        const chartCanvas = document.getElementById('originsChart');
        if (!chartCanvas) {
            console.error('Origins chart canvas not found');
            return false;
        }
        
        // Check if chart already exists and destroy it
        if (charts.originsChart) {
            charts.originsChart.destroy();
        }
        
        // Create the chart with default data
        charts.originsChart = new Chart(chartCanvas, {
            type: 'pie',
            data: {
                labels: ['Unknown'],
                datasets: [{
                    data: [1],
                    backgroundColor: ['#6c757d'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                legend: {
                    position: 'right',
                    labels: {
                        padding: 20,
                        boxWidth: 12
                    }
                },
                tooltips: {
                    callbacks: {
                        label: function(tooltipItem, data) {
                            const dataset = data.datasets[tooltipItem.datasetIndex];
                            const total = dataset.data.reduce((acc, current) => acc + current, 0);
                            const currentValue = dataset.data[tooltipItem.index];
                            const percentage = Math.round((currentValue / total) * 100);
                            return `${data.labels[tooltipItem.index]}: ${percentage}%`;
                        }
                    }
                }
            }
        });
        
        console.log('Origins chart initialized successfully');
        return true;
    } catch (error) {
        console.error('Error initializing threat origins chart:', error);
        return false;
    }
}

/**
 * Populate dashboard with data
 * @param {Array} threatData - Array of threat objects
 */
function populateDashboard(threatData) {
    console.log('Populating dashboard with', threatData.length, 'threats');
    
    try {
        // Update all dashboard components with the new data
        updateThreatActivityChart(threatData);
        updateThreatOriginsChart(threatData);
        updateStats(threatData);
        updateAIMetrics(threatData);
        updateMap(threatData);
        updateTimeline(threatData);
        
        console.log('Dashboard updated successfully');
    } catch (error) {
        console.error('Error populating dashboard:', error);
    }
}

/**
 * Update the activity timeline with threat data
 * @param {Array} threatData - Array of threat objects
 */
function updateTimeline(threatData) {
    console.log('Updating activity timeline');
    
    const timeline = document.getElementById('timeline');
    if (!timeline) {
        console.warn('Timeline element not found');
        return;
    }
    
    // Clear existing content
    timeline.innerHTML = '';
    
    if (threatData.length === 0) {
        timeline.innerHTML = '<p class="text-muted text-center">No recent activity</p>';
        return;
    }
    
    // Sort by analysis_time (newest first) and take top 10
    const sortedThreats = [...threatData].sort((a, b) => {
        const timeA = new Date(a.analysis_time || a.timestamp || 0);
        const timeB = new Date(b.analysis_time || b.timestamp || 0);
        return timeB - timeA;
    }).slice(0, 10);
    
    // Create timeline items
    sortedThreats.forEach(threat => {
        const severity = (threat.severity || 'NORMAL').toUpperCase();
        let severityClass = 'secondary';
        let severityIcon = 'bi-info-circle';
        
        if (severity === 'HIGH') {
            severityClass = 'danger';
            severityIcon = 'bi-exclamation-triangle-fill';
        } else if (severity === 'MEDIUM') {
            severityClass = 'warning';
            severityIcon = 'bi-exclamation-circle';
        } else if (severity === 'LOW') {
            severityClass = 'info';
            severityIcon = 'bi-info-circle';
        }
        
        // Format time
        const timeStr = threat.analysis_time || threat.timestamp;
        let formattedTime = 'Unknown time';
        if (timeStr) {
            const date = new Date(timeStr);
            if (!isNaN(date.getTime())) {
                formattedTime = date.toLocaleTimeString();
            }
        }
        
        const threatType = threat.behavior || threat.type || 'Unknown threat';
        const source = threat.source_ip || threat.source || 'Unknown';
        
        const item = document.createElement('div');
        item.className = 'timeline-item d-flex align-items-start mb-3';
        item.innerHTML = `
            <div class="timeline-marker me-3">
                <i class="bi ${severityIcon} text-${severityClass} fs-5"></i>
            </div>
            <div class="timeline-content flex-grow-1">
                <div class="d-flex justify-content-between align-items-center">
                    <strong class="text-${severityClass}">${severity}</strong>
                    <small class="text-muted">${formattedTime}</small>
                </div>
                <p class="mb-1 small">${threatType}</p>
                <small class="text-muted">Source: ${source}</small>
            </div>
        `;
        
        timeline.appendChild(item);
    });
    
    console.log('Timeline updated with', sortedThreats.length, 'items');
}

/**
 * Update the threat activity chart with new data
 * @param {Array} threatData - Array of threat objects
 */
function updateThreatActivityChart(threatData) {
    try {
        if (!charts.activityChart) {
            console.error('Threat activity chart not initialized');
            // Try to initialize the chart if it doesn't exist
            initThreatActivityChart();
            // Return early to avoid errors, we'll update on next data refresh
            return;
        }
        
        // Count threats by hour using analysis_time (more reliable than timestamp)
        const hourCounts = Array(24).fill(0);
        
        threatData.forEach(threat => {
            // Use analysis_time as primary, fallback to timestamp
            const timeStr = threat.analysis_time || threat.timestamp;
            if (timeStr) {
                const date = new Date(timeStr);
                if (!isNaN(date.getTime())) {
                    const hour = date.getHours();
                    hourCounts[hour]++;
                }
            }
        });
        
        // Update chart data for Chart.js 2.x
        charts.activityChart.data.datasets[0].data = hourCounts;
        charts.activityChart.update();
        
        console.log('Threat activity chart updated');
    } catch (error) {
        console.error('Error updating threat activity chart:', error);
    }
}

/**
 * Update the threat origins chart
 * @param {Array} threatData - Array of threat objects
 */
function updateThreatOriginsChart(threatData) {
    console.log('Updating threat origins chart');
    
    try {
        // Check if chart exists or initialize it
        if (!charts.originsChart && !initThreatOriginsChart()) {
            console.error('Cannot update threat origins chart - initialization failed');
            return;
        }
        
        // Aggregate threat sources by source_ip
        const sourceCount = {};
        
        // Count threats by source_ip (API field name)
        threatData.forEach(threat => {
            const source = threat.source_ip || threat.source || 'Unknown';
            sourceCount[source] = (sourceCount[source] || 0) + 1;
        });
        
        // Convert to arrays for the chart
        const sources = Object.keys(sourceCount);
        const counts = Object.values(sourceCount);
        
        // Generate colors based on the number of sources
        const colors = [];
        sources.forEach((_, index) => {
            // Create a color based on index
            const hue = (index * 137) % 360; // Golden ratio to spread colors
            colors.push(`hsl(${hue}, 70%, 60%)`);
        });
        
        // Update chart data
        charts.originsChart.data.labels = sources;
        charts.originsChart.data.datasets[0].data = counts;
        charts.originsChart.data.datasets[0].backgroundColor = colors;
        
        // Update the chart
        charts.originsChart.update();
        
        console.log('Origins chart updated with', sources.length, 'sources');
    } catch (error) {
        console.error('Error updating threat origins chart:', error);
    }
}

/**
 * Initialize system resource charts (CPU, Memory, Network)
 */
function initSystemResourceCharts() {
    // Implementation for system resource charts
    console.log('System resource charts initialized');
}

/**
 * Update system resource charts with new data
 */
function updateSystemResourceCharts() {
    // Implementation for updating system resource charts
    console.log('System resource charts updated');
}

/**
 * Update dashboard stats based on threat data
 * @param {Array} threatData - Array of threat objects
 */
function updateStats(threatData) {
    try {
        // Count threats by severity (API returns uppercase: HIGH, MEDIUM, LOW, NORMAL)
        let highCount = 0;
        let mediumCount = 0;
        let lowCount = 0;
        let total = threatData.length;
        
        // Calculate response time
        let totalResponseTime = 0;
        let responseTimeCount = 0;
        
        threatData.forEach(threat => {
            const severity = (threat.severity || '').toUpperCase();
            if (severity === 'HIGH') highCount++;
            else if (severity === 'MEDIUM') mediumCount++;
            else if (severity === 'LOW') lowCount++;
            // NORMAL severity is not counted in high/medium/low
            
            // If threat has response time data
            if (threat.responseTime) {
                totalResponseTime += threat.responseTime;
                responseTimeCount++;
            }
        });
        
        // Update the UI with the stats
        updateElementText('high-count', highCount);
        updateElementText('medium-count', mediumCount);
        // Using total-count instead of low-count since that's what exists in the HTML
        updateElementText('total-count', total);
        
        // Calculate and update average response time
        const avgResponseTime = responseTimeCount > 0 ? Math.round(totalResponseTime / responseTimeCount) : 0;
        // Using response-time instead of avg-response since that's what exists in the HTML
        updateElementText('response-time', avgResponseTime + 's');
        
        // Update alert count
        const alertCount = threatData.filter(threat => 
            threat.severity === 'high' || (threat.isAnomaly && threat.aiConfidence > 0.8)
        ).length;
        updateElementText('alert-count', alertCount);
        
        console.log('Dashboard stats updated');
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}

/**
 * Update AI metrics based on threat data
 * @param {Array} threatData - Array of threat objects
 */
function updateAIMetrics(threatData) {
    console.log('Updating AI metrics');
    
    try {
        // All threats are analyzed by our AI classifier
        const analyzedCount = threatData.length;
        
        // Count high severity threats as "anomalies" 
        const anomalyCount = threatData.filter(threat => {
            const severity = (threat.severity || '').toUpperCase();
            return severity === 'HIGH';
        }).length;
        
        // Count threats with MITRE techniques identified as "similar threats"
        const similarThreatsCount = threatData.filter(threat => 
            threat.techniques && threat.techniques.length > 0
        ).length;
        
        // Count medium+ severity as "metrics alerts"
        const metricsAlertsCount = threatData.filter(threat => {
            const severity = (threat.severity || '').toUpperCase();
            return severity === 'HIGH' || severity === 'MEDIUM';
        }).length;
        
        // Calculate average confidence
        let totalConfidence = 0;
        threatData.forEach(threat => {
            totalConfidence += threat.confidence || 0.5;
        });
        const avgConfidence = threatData.length > 0 ? Math.round((totalConfidence / threatData.length) * 100) : 0;
        
        // Update UI elements with the counts (top stats bar)
        updateElementText('ai-analyzed-count', analyzedCount);
        updateElementText('ai-anomalies', anomalyCount);
        updateElementText('ai-similar-threats', similarThreatsCount);
        updateElementText('ai-metrics-alerts', metricsAlertsCount);
        updateElementText('ai-confidence', avgConfidence + '%');
        
        // Update AI Performance section (bottom panel)
        updateElementText('ai-perf-analyzed', analyzedCount);
        updateElementText('ai-perf-anomalies', anomalyCount);
        updateElementText('ai-perf-similar', similarThreatsCount);
        updateElementText('ai-perf-alerts', metricsAlertsCount);
        updateElementText('ai-perf-confidence', avgConfidence + '%');
        
        console.log('AI metrics updated:', {
            analyzed: analyzedCount,
            anomalies: anomalyCount,
            similar: similarThreatsCount,
            alerts: metricsAlertsCount,
            confidence: avgConfidence
        });
    } catch (error) {
        console.error('Error updating AI metrics:', error);
    }
}

/**
 * Update the map with threat locations
 * @param {Array} threatData - Array of threat objects
 */
function updateMap(threatData) {
    console.log('Updating map with threat locations');
    
    // Check if window.updateMapMarkers exists (it might be defined in main.js)
    if (typeof window.updateMapMarkers !== 'function') {
        console.error('updateMapMarkers function not found');
        return;
    }
    
    try {
        // Get threats with valid coordinates
        const validThreats = threatData.filter(threat => 
            threat.latitude && threat.longitude &&
            !isNaN(threat.latitude) && !isNaN(threat.longitude)
        );
        
        if (validThreats.length === 0) {
            console.warn('No threats with valid coordinates found');
        }
        
        // Call the map update function from main.js
        window.updateMapMarkers(validThreats);
    } catch (error) {
        console.error('Error updating map:', error);
    }
}

/**
 * Helper function to safely update element text content
 * @param {string} elementId - ID of the element to update
 * @param {*} value - New text value
 */
function updateElementText(elementId, value) {
    try {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = value;
        } else {
            console.warn(`Element with ID "${elementId}" not found for updating text to "${value}"`);
        }
    } catch (error) {
        console.error(`Error updating element text for "${elementId}"`, error);
    }
}

/**
 * Add a new event to the timeline
 * @param {Object} threat - Threat object to add to timeline
 */
function addTimelineEvent(threat) {
    const timeline = document.getElementById('timeline');
    if (!timeline) {
        console.error('Timeline element not found');
        return;
    }
    
    const timelineItem = document.createElement('div');
    timelineItem.className = 'timeline-item';
    
    const severityClass = threat.severity === 'high' ? 'danger' : 
                          threat.severity === 'medium' ? 'warning' : 'info';
    
    const formattedTime = formatDateTime(threat.timestamp);
    
    timelineItem.innerHTML = `
        <div class="timeline-marker bg-${severityClass}"></div>
        <div class="timeline-content">
            <h6 class="mb-1">${threat.type || 'Unknown Threat'}</h6>
            <p class="mb-0 small text-muted">${formattedTime}</p>
            <p class="mb-0 small">${threat.source} → ${threat.target}</p>
        </div>
    `;
    
    timeline.appendChild(timelineItem);
}

/**
 * Format a date/time string
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted date/time
 */
function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Export functions for other modules
window.DashboardManager = {
    initCharts,
    initThreatActivityChart,
    initOriginsChart: initThreatOriginsChart,
    populateDashboard,
    updateStats,
    updateAIMetrics
};
