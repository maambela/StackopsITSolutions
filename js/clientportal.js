/* Client Portal JavaScript */

// ════════════════════════════════════════════════════════════════════════════════
// DASHBOARD LOADING SYSTEM - SIMPLIFIED & RELIABLE
// ════════════════════════════════════════════════════════════════════════════════
// Rebuilt according to strict rules: No animations, no delays, instant rendering

let currentProject = null;
let charts = {};
let currentProjectIndex = 0;
let selectedProjectId = null;
let previewLockedByClick = false;
const SUNBIRD_PHONE_PROJECT_DISPLAY_ORDER = [2, 3, 5, 10, 9];

// Sunbird-only card IDs that should be hidden from non-Sunbird clients
const SUNBIRD_ONLY_CARD_IDS = [2, 3, 4, 5, 7, 8, 9, 10]; // Identity Protection, Devices, Security & Events, Email Security, Backup & Recovery, Applications, Credential Security, Network Security

// Cards to hide from Sunbird clients
const HIDDEN_FROM_SUNBIRD_IDS = []; // All Sunbird cards are visible to them

// Cards to hide from the main project cards UI (keep functionality in code)
const HIDDEN_PROJECT_CARD_IDS = [4, 7, 8, 6]; // Security & Events, Backup and Recovery, Applications, Cloud data services

// SEDFA/Duo user-specific card IDs (Cisco Duo Licenses, Cloud data services, Infrastructure Monitoring)
const SEDFA_CARD_IDS = [1, 6, 11];
const NON_SUNBIRD_BLUR_PROJECT_IDS = [6, 11];
const NON_SUNBIRD_BLUR_PANEL_IDS = ['billing-card', 'governance-card'];

// ════════════════════════════════════════════════════════════════════════════════
// DASHBOARD CONFIGURATION - UNIVERSAL TEMPLATE FOR ALL DASHBOARDS
// ════════════════════════════════════════════════════════════════════════════════

const dashboardConfigs = {
    "Identity Protection": {
        title: "Identity Protection Dashboard",
        subtitle: "User Management & Access Control",
        stats: [
            { id: "stat-users", label: "Total Users", icon: "fas fa-users", value: "0" },
            { id: "stat-active", label: "Active (24h)", icon: "fas fa-user-check", value: "0" },
            { id: "stat-admin", label: "Admin Roles", icon: "fas fa-crown", value: "0" },
            { id: "stat-score", label: "Security Score", icon: "fas fa-shield-alt", value: "0" }
        ],
        charts: [
            { id: "riskChart", title: "Risk Assessment Overview", type: "line" },
            { id: "securityChart", title: "Security Status", type: "doughnut" },
            { id: "healthChart", title: "System Health", type: "radar" },
            { id: "threatChart", title: "Threat Detection Timeline", type: "bar" }
        ],
        sections: [
            { name: "Security Events", content: "" },
            { name: "User Access", content: "" },
            { name: "Risk Alerts", content: "" }
        ]
    },
    "Device Protection": {
        title: "Device Protection Dashboard",
        subtitle: "Device Management & Compliance",
        stats: [
            { id: "stat-devices", label: "Total Devices", icon: "fas fa-desktop", value: "0" },
            { id: "stat-noncompliant", label: "Non-Compliant", icon: "fas fa-times-circle", value: "0" },
            { id: "stat-encrypted", label: "Not Encrypted", icon: "fas fa-lock-open", value: "0" },
            { id: "stat-stale", label: "Stale (7+ days)", icon: "fas fa-clock", value: "0" }
        ],
        charts: [
            { id: "riskChart", title: "Risk Assessment Overview", type: "line" },
            { id: "securityChart", title: "Compliance Status", type: "doughnut" },
            { id: "healthChart", title: "Device Health", type: "radar" },
            { id: "threatChart", title: "Threat Timeline", type: "bar" }
        ],
        sections: [
            { name: "Device Inventory", content: "" },
            { name: "Compliance Status", content: "" },
            { name: "Security Patches", content: "" }
        ]
    },
    "Security": {
        title: "Security Dashboard",
        subtitle: "Real-Time Security Intelligence & Threat Response",
        stats: [
            { id: "stat-incidents", label: "Active Incidents", icon: "fas fa-exclamation-triangle", value: "0" },
            { id: "stat-alerts", label: "High Alerts", icon: "fas fa-bell", value: "0" },
            { id: "stat-threats", label: "Threats Detected", icon: "fas fa-virus", value: "0" },
            { id: "stat-response", label: "Response Time", icon: "fas fa-clock", value: "N/A" }
        ],
        charts: [
            { id: "riskChart", title: "Risk Assessment Overview", type: "line" },
            { id: "securityChart", title: "Security Posture", type: "doughnut" },
            { id: "healthChart", title: "Threat Analysis", type: "radar" },
            { id: "threatChart", title: "Incident Timeline", type: "bar" }
        ],
        sections: [
            { name: "Active Threats", content: "" },
            { name: "Security Alerts", content: "" },
            { name: "Incident Response", content: "" }
        ]
    },
    "Compliance": {
        title: "Compliance Dashboard",
        subtitle: "Compliance Controls & Recovery Operations",
        stats: [
            { id: "stat-compliant", label: "Compliant Systems", icon: "fas fa-check-circle", value: "0" },
            { id: "stat-violations", label: "Policy Violations", icon: "fas fa-exclamation-circle", value: "0" },
            { id: "stat-storage", label: "Total Storage", icon: "fas fa-database", value: "0 TB" },
            { id: "stat-coverage", label: "Services Covered", icon: "fas fa-shield-alt", value: "0" }
        ],
        charts: [
            { id: "riskChart", title: "Compliance Trend", type: "line" },
            { id: "securityChart", title: "Compliance Status", type: "doughnut" },
            { id: "healthChart", title: "Policy Adherence", type: "radar" },
            { id: "threatChart", title: "Violation Timeline", type: "bar" }
        ],
        sections: [
            { name: "Compliance Status", content: "" },
            { name: "Policy Violations", content: "" },
            { name: "Remediation Actions", content: "" }
        ]
    },
    "Service Desk": {
        title: "Service Desk Dashboard",
        subtitle: "Support Tickets & Service Operations",
        stats: [
            { id: "stat-open", label: "Open Tickets", icon: "fas fa-ticket-alt", value: "0" },
            { id: "stat-resolved", label: "Resolved (24h)", icon: "fas fa-check-circle", value: "0" },
            { id: "stat-avgtime", label: "Avg Resolution", icon: "fas fa-hourglass-end", value: "0 hrs" },
            { id: "stat-satisfaction", label: "Satisfaction", icon: "fas fa-smile", value: "0%" }
        ],
        charts: [
            { id: "riskChart", title: "Ticket Volume Trend", type: "line" },
            { id: "securityChart", title: "Ticket Status Distribution", type: "doughnut" },
            { id: "healthChart", title: "Resolution Performance", type: "radar" },
            { id: "threatChart", title: "Priority Timeline", type: "bar" }
        ],
        sections: [
            { name: "Open Tickets", content: "" },
            { name: "In Progress", content: "" },
            { name: "Recently Resolved", content: "" }
        ]
    }
};

// ════════════════════════════════════════════════════════════════════════════════
// NEW DASHBOARD SYSTEM - RULE 2: ONE SIMPLE DASHBOARD LOADER
// ════════════════════════════════════════════════════════════════════════════════

let originalDashboardViewHTML = null;

function captureDashboardViewHTML() {
    const dashboardView = document.getElementById('dashboard-view');
    if (dashboardView && originalDashboardViewHTML === null) {
        originalDashboardViewHTML = dashboardView.innerHTML;
    }
}

function restoreDashboardViewHTML() {
    const dashboardView = document.getElementById('dashboard-view');
    if (
        dashboardView &&
        originalDashboardViewHTML !== null &&
        (
            dashboardView.querySelector('#sunbird-identity-dashboard') ||
            dashboardView.querySelector('#sunbird-devices-dashboard') ||
            dashboardView.querySelector('#sunbird-email-dashboard') ||
            dashboardView.querySelector('#sunbird-security-dashboard') ||
            dashboardView.querySelector('#sunbird-backup-dashboard') ||
            dashboardView.querySelector('#sunbird-applications-dashboard') ||
            dashboardView.querySelector('#sunbird-network-security-dashboard') ||
            dashboardView.querySelector('#sunbird-reports-dashboard')
        )
    ) {
        dashboardView.innerHTML = originalDashboardViewHTML;
    }
}

/**
 * RULE 17: ONE EVENT LISTENER ONLY
 * Main function to open any dashboard
 * Usage: onclick="openDashboard(project)"
 */
function openDashboard(project) {
    console.log('[Dashboard] Opening dashboard for project:', project);
    
    // RULE 1: Validate project
    if (!project) {
        console.error('[Dashboard] No project provided');
        return;
    }

    if (Number(project.id) === 2 || project.isIdentityCard === true) {
        openIdentityDashboard();
        return;
    }

    if (Number(project.id) === 3 || project.isDevicesCard === true) {
        openSunbirdDevicesDashboard();
        return;
    }

    if (Number(project.id) === 5 || project.isEmailSecurityCard === true) {
        openSunbirdEmailSecurityDashboard();
        return;
    }

    if ((Number(project.id) === 4 || project.isSecurityCard === true) && isSunbirdUser()) {
        openSunbirdSecurityDashboard();
        return;
    }

    if ((Number(project.id) === 7 || project.isBackupRecoveryCard === true) && isSunbirdUser()) {
        openSunbirdBackupDashboard();
        return;
    }

    if ((Number(project.id) === 8 || project.isApplicationsCard === true) && isSunbirdUser()) {
        openSunbirdApplicationsDashboard();
        return;
    }

    if ((Number(project.id) === 10 || project.isNetworkSecurityCard === true) && isSunbirdUser()) {
        openSunbirdNetworkSecurityDashboard();
        return;
    }

    restoreDashboardViewHTML();
    document.getElementById('dashboard-view')?.classList.remove('sunbird-identity-active');
    document.getElementById('dashboard-view')?.classList.remove('sunbird-device-active');
    document.getElementById('dashboard-view')?.classList.remove('sunbird-email-active');
    document.getElementById('dashboard-view')?.classList.remove('sunbird-security-active');
    document.getElementById('dashboard-view')?.classList.remove('sunbird-backup-active');
    document.getElementById('dashboard-view')?.classList.remove('sunbird-applications-active');
    document.getElementById('dashboard-view')?.classList.remove('sunbird-network-security-active');
    
    // Get dashboard type with fallback
    const dashboardType = project.dashboardType || "Security"; // RULE 18: Fallback config
    console.log('[Dashboard] Dashboard type:', dashboardType);
    
    // Get configuration
    const config = dashboardConfigs[dashboardType];
    if (!config) {
        console.error('[Dashboard] Configuration missing for:', dashboardType);
        // Use Security as fallback
        const fallbackConfig = dashboardConfigs["Security"];
        renderDashboard(fallbackConfig, project);
        return;
    }
    
    // RULE 2: Hide projects view
    const projectsView = document.getElementById('projects-view');
    if (projectsView) projectsView.style.display = 'none';
    
    // RULE 2: Show dashboard view
    const dashboardView = document.getElementById('dashboard-view');
    if (dashboardView) dashboardView.style.display = 'block';
    
    // RULE 2: Render dashboard
    renderDashboard(config, project);
}

/**
 * RULE 5: Render dashboard HTML with universal template
 * Process: No animations, set innerHTML, then initialize charts
 */
function renderDashboard(config, project) {
    console.log('[Dashboard] Rendering:', config.title);
    
    const dashboardView = document.getElementById('dashboard-view');
    if (!dashboardView) {
        console.error('[Dashboard] Dashboard view element not found');
        return;
    }
    
    // RULE 10: Clear dashboard content
    const dashboardContent = dashboardView.querySelector('.charts-section') || dashboardView.querySelector('.monitoring-section');
    
    // Update title
    const titleElement = document.getElementById('project-name');
    if (titleElement) titleElement.textContent = config.title;
    
    // RULE 2: Initialize charts immediately
    initializeDashboardCharts(config);
    
    console.log('[Dashboard] Dashboard rendered successfully');
}

/**
 * RULE 6: Initialize charts
 * Process: Destroy old charts, create new charts
 */
function initializeDashboardCharts(config) {
    console.log('[Dashboard] Initializing charts for:', config.title);
    
    // RULE 7: Destroy old chart instances
    if (window.dashboardCharts) {
        Object.values(window.dashboardCharts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
    }
    window.dashboardCharts = {};
    
    // RULE 6: Create new charts
    config.charts.forEach(chartConfig => {
        const canvas = document.getElementById(chartConfig.id);
        if (!canvas) {
            console.warn('[Dashboard] Canvas not found:', chartConfig.id);
            return;
        }
        
        try {
            const ctx = canvas.getContext('2d');
            window.dashboardCharts[chartConfig.id] = createChart(ctx, chartConfig);
            console.log('[Dashboard] Chart created:', chartConfig.id);
        } catch (error) {
            console.error('[Dashboard] Error creating chart:', chartConfig.id, error);
        }
    });
}

/**
 * Helper function to create chart based on type
 */
function createChart(ctx, chartConfig) {
    switch(chartConfig.type) {
        case 'line':
            return new Chart(ctx, {
                type: 'line',
                data: {
                    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                    datasets: [
                        {
                            label: 'Critical',
                            data: [2, 3, 2, 4, 2, 1, 2],
                            borderColor: '#ff3f5f',
                            backgroundColor: 'rgba(255, 63, 95, 0.08)',
                            borderWidth: 3,
                            tension: 0.45,
                            cubicInterpolationMode: 'monotone',
                            fill: false,
                            pointRadius: 3,
                            pointHoverRadius: 5,
                            pointBackgroundColor: '#ff3f5f',
                            pointBorderColor: '#ff3f5f',
                            pointBorderWidth: 1
                        },
                        {
                            label: 'High',
                            data: [5, 6, 4, 7, 5, 3, 3],
                            borderColor: '#ffd000',
                            backgroundColor: 'rgba(255, 208, 0, 0.08)',
                            borderWidth: 3,
                            tension: 0.45,
                            cubicInterpolationMode: 'monotone',
                            fill: false,
                            pointRadius: 3,
                            pointHoverRadius: 5,
                            pointBackgroundColor: '#ffd000',
                            pointBorderColor: '#ffd000',
                            pointBorderWidth: 1
                        },
                        {
                            label: 'Medium',
                            data: [8, 9, 7, 10, 8, 6, 5],
                            borderColor: '#ff9f1c',
                            backgroundColor: 'rgba(255, 159, 28, 0.08)',
                            borderWidth: 3,
                            tension: 0.45,
                            cubicInterpolationMode: 'monotone',
                            fill: false,
                            pointRadius: 3,
                            pointHoverRadius: 5,
                            pointBackgroundColor: '#ff9f1c',
                            pointBorderColor: '#ff9f1c',
                            pointBorderWidth: 1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        mode: 'index',
                        intersect: false
                    },
                    elements: {
                        line: {
                            capBezierPoints: true
                        }
                    },
                    plugins: {
                        legend: {
                            position: 'top',
                            align: 'center',
                            labels: {
                                color: 'rgba(255, 255, 255, 0.78)',
                                boxWidth: 12,
                                boxHeight: 12,
                                padding: 18,
                                usePointStyle: true,
                                pointStyle: 'rect',
                                generateLabels(chart) {
                                    return Chart.defaults.plugins.legend.labels.generateLabels(chart).map(label => ({
                                        ...label,
                                        fillStyle: 'rgba(255, 255, 255, 0.08)',
                                        strokeStyle: label.strokeStyle || label.fillStyle,
                                        lineWidth: 2
                                    }));
                                }
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(2, 6, 23, 0.92)',
                            borderColor: 'rgba(148, 163, 184, 0.25)',
                            borderWidth: 1,
                            titleColor: '#f8fafc',
                            bodyColor: '#e2e8f0',
                            displayColors: true,
                            padding: 12,
                            callbacks: {
                                label(context) {
                                    return `${context.dataset.label}: ${context.parsed.y} findings`;
                                }
                            }
                        }
                    },
                    scales: {
                        y: {
                            min: 0,
                            suggestedMax: 10,
                            grid: {
                                color: 'rgba(255, 255, 255, 0.08)',
                                drawBorder: false
                            },
                            ticks: {
                                color: 'rgba(255, 255, 255, 0.72)',
                                stepSize: 1,
                                callback(value) {
                                    return value === 0 ? '' : value;
                                }
                            }
                        },
                        x: {
                            grid: {
                                display: false,
                                drawBorder: false
                            },
                            ticks: {
                                color: 'rgba(255, 255, 255, 0.72)'
                            }
                        }
                    }
                }
            });
        case 'doughnut':
            return new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Secure', 'Vulnerable'],
                    datasets: [{
                        data: [70, 30],
                        backgroundColor: [
                            'rgba(40, 167, 69, 0.8)',
                            'rgba(220, 53, 69, 0.8)'
                        ],
                        borderColor: ['#28a745', '#dc3545'],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#bdbdbd',
                                padding: 15
                            }
                        }
                    }
                }
            });
        case 'radar':
            return new Chart(ctx, {
                type: 'radar',
                data: {
                    labels: ['Performance', 'Availability', 'Security', 'Compliance', 'Backup'],
                    datasets: [{
                        label: 'Health Score',
                        data: [92, 88, 85, 90, 88],
                        borderColor: '#006eff',
                        backgroundColor: 'rgba(0, 110, 255, 0.2)',
                        pointBackgroundColor: '#006eff',
                        pointBorderColor: '#fff',
                        pointHoverBackgroundColor: '#fff',
                        pointHoverBorderColor: '#006eff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#bdbdbd'
                            }
                        }
                    },
                    scales: {
                        r: {
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            },
                            ticks: {
                                color: '#bdbdbd',
                                backdropColor: 'transparent'
                            }
                        }
                    }
                }
            });
        case 'bar':
        default:
            return new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                    datasets: [
                        {
                            label: 'Critical',
                            data: [2, 3, 1, 5, 2, 1, 3],
                            backgroundColor: 'rgba(220, 53, 69, 0.8)',
                            borderColor: '#dc3545',
                            borderWidth: 1
                        },
                        {
                            label: 'High',
                            data: [5, 7, 3, 8, 4, 2, 6],
                            backgroundColor: 'rgba(255, 193, 7, 0.8)',
                            borderColor: '#ffc107',
                            borderWidth: 1
                        },
                        {
                            label: 'Medium',
                            data: [3, 4, 2, 6, 4, 3, 5],
                            backgroundColor: 'rgba(255, 152, 0, 0.8)',
                            borderColor: '#ff9800',
                            borderWidth: 1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#bdbdbd',
                                padding: 15
                            }
                        }
                    },
                    scales: {
                        y: {
                            grid: {
                                color: 'rgba(255, 255, 255, 0.05)',
                                drawBorder: false
                            },
                            ticks: {
                                color: '#bdbdbd'
                            }
                        },
                        x: {
                            grid: {
                                display: false,
                                drawBorder: false
                            },
                            ticks: {
                                color: '#bdbdbd'
                            }
                        }
                    }
                }
            });
    }
}

/**
 * RULE 9 & 10: Simplified goBackToProjects
 * No animations, just display changes
 */
function goBackToProjects() {
    console.log('[Dashboard] Returning to projects');
    
    const projectsView = document.getElementById('projects-view');
    const dashboardView = document.getElementById('dashboard-view');
    
    if (projectsView) projectsView.style.display = 'block';
    if (dashboardView) {
        dashboardView.style.display = 'none';
        dashboardView.classList.remove('sunbird-identity-active');
        dashboardView.classList.remove('sunbird-device-active');
        dashboardView.classList.remove('sunbird-email-active');
        dashboardView.classList.remove('sunbird-security-active');
        dashboardView.classList.remove('sunbird-backup-active');
        dashboardView.classList.remove('sunbird-applications-active');
        dashboardView.classList.remove('sunbird-reports-active');
    }
    
    // Destroy charts
    if (window.dashboardCharts) {
        Object.values(window.dashboardCharts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
        window.dashboardCharts = {};
    }
    
    currentProject = null;
}

// Check if current user is a Sunbird client
function isSunbirdUser() {
    // StackOps demo tenant (user 36 / company 5) mirrors the Sunbird dashboard
    // design but is fed entirely by local mock data (js/clientportal-stackops-mock.js).
    // This clause only widens the "true" set — real Sunbird/Sedfa detection below is unchanged.
    if (typeof isStackOpsMockUser === 'function' && isStackOpsMockUser()) return true;
    try {
        const rawUser = localStorage.getItem('user');
        if (!rawUser) return false;
        const user = JSON.parse(rawUser);
        return String(user?.access || '').toLowerCase() === 'sunbird' || Boolean(user?.hasSunbirdAccess);
    } catch (error) {
        return false;
    }
}

async function refreshUserAccessFromServer() {
    const token = localStorage.getItem('authToken');
    if (!token || isAuthTokenExpired(token)) return null;
    try {
        const response = await fetch('/api/auth/session', {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        if (!response.ok) return null;
        const data = await response.json();
        if (data?.user) {
            localStorage.setItem('user', JSON.stringify(data.user));
        }
        if (data?.accessToken) {
            localStorage.setItem('authToken', data.accessToken);
        }
        updateSunbirdLogoVisibility();
        return data?.user || null;
    } catch (error) {
        console.warn('[Auth Session] Unable to refresh access context:', error.message);
        return null;
    }
}

function isSunbirdIdentityClient() {
    try {
        const rawUser = localStorage.getItem('user');
        const user = rawUser ? JSON.parse(rawUser) : {};
        const email = String(user?.email || sessionStorage.getItem('userEmail') || '').toLowerCase();
        const client = String(user?.access || user?.client || '').toLowerCase();
        return client === 'sunbird' || Boolean(user?.hasSunbirdAccess) || email.includes('@sunbird.eu') || email.includes('@stackopsit.co.za');
    } catch (error) {
        const email = String(sessionStorage.getItem('userEmail') || '').toLowerCase();
        return email.includes('@sunbird.eu') || email.includes('@stackopsit.co.za');
    }
}

// Check if current user is sedfa client (has Cisco Duo access)
// Access type is set by backend from user_duo_accounts table
function isSedfaUser() {
    try {
        const rawUser = localStorage.getItem('user');
        if (!rawUser) return false;
        const user = JSON.parse(rawUser);
        // Check if user has duo access (set by backend via user_duo_accounts table)
        const access = String(user?.access || '').toLowerCase();
        return access === 'duo' || access === 'sedfa';
    } catch (error) {
        return false;
    }
}

// Update Sunbird logo visibility based on user type
function updateSunbirdLogoVisibility() {
    const isSunbird = isSunbirdUser();
    document.body?.classList.toggle('sunbird-client-portal', isSunbird);
    syncNonSunbirdBlurGatedPanels();

    const isStackOpsMock = typeof isStackOpsMockUser === 'function' && isStackOpsMockUser();

    const logoImg = document.querySelector('.sunbird-logo-img');
    if (logoImg) {
        if (isStackOpsMock) {
            // StackOps demo tenant: use the StackOps logo (same asset as the Home page header)
            if (!logoImg.dataset.stackopsLogoApplied) {
                logoImg.src = 'Images/Logos/RemovedStackOps.png';
                logoImg.alt = 'StackOps';
                logoImg.dataset.stackopsLogoApplied = 'true';
            }
            logoImg.style.display = 'block';
        } else if (isSunbird) {
            logoImg.style.display = 'block';
        } else {
            logoImg.style.display = 'none';
        }
    }
}

// Check if session is still valid
function decodeAuthTokenPayload(token) {
    try {
        const payload = String(token || '').split('.')[1];
        if (!payload) return null;
        const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
        const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '=');
        return JSON.parse(atob(padded));
    } catch (error) {
        return null;
    }
}

function isAuthTokenExpired(token, skewMs = 30000) {
    const payload = decodeAuthTokenPayload(token);
    if (!payload?.exp) return !token;
    return (payload.exp * 1000) <= (Date.now() + skewMs);
}

function clearClientPortalAuthState() {
    ['userEmail', 'userFirstName', 'userLastName', 'isLoggedIn', 'loginTime'].forEach(key => {
        sessionStorage.removeItem(key);
    });
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
}

function isSessionValid() {
    const isLoggedIn = sessionStorage.getItem('isLoggedIn');
    const userEmail = sessionStorage.getItem('userEmail');
    const token = localStorage.getItem('authToken');

    if (isLoggedIn !== 'true' || !userEmail || !token) return false;
    if (isAuthTokenExpired(token)) {
        clearClientPortalAuthState();
        return false;
    }

    return true;
}

// Get filtered projects based on user access level
function getFilteredProjects() {
    if (isSunbirdUser()) {
        // Sunbird users see ONLY Sunbird-specific projects (excluding hidden ones)
        return mockProjects.filter(project =>
            SUNBIRD_ONLY_CARD_IDS.includes(project.id) &&
            !HIDDEN_PROJECT_CARD_IDS.includes(project.id)
        );
    }
    
    if (isSedfaUser()) {
        // Sedfa users see Cisco Duo Licenses, Cloud data services, and Infrastructure Monitoring
        return mockProjects.filter(project =>
            SEDFA_CARD_IDS.includes(project.id)
        );
    }
    
    // All other clients see all projects EXCEPT Sunbird-only, Cisco Duo, and hidden projects
    return mockProjects.filter(project =>
        !SUNBIRD_ONLY_CARD_IDS.includes(project.id) && 
        project.id !== 1 &&
        !HIDDEN_PROJECT_CARD_IDS.includes(project.id)
    );
}

function getPhoneFilteredProjects() {
    const projects = getFilteredProjects();
    if (!isSunbirdUser()) return projects;

    return projects.slice().sort((a, b) => {
        const aOrder = SUNBIRD_PHONE_PROJECT_DISPLAY_ORDER.indexOf(Number(a.id));
        const bOrder = SUNBIRD_PHONE_PROJECT_DISPLAY_ORDER.indexOf(Number(b.id));
        return (aOrder === -1 ? 99 : aOrder) - (bOrder === -1 ? 99 : bOrder);
    });
}
const mockProjects = [
    {
        id: 9,
        name: "Credential Security", 
        type: "Password & Credential Management",
        status: "inactive",
        risks: { critical: 1, high: 1, medium: 1 },
        securityScore: 85,
        uptime: 98.5,
        lastUpdate: "2 days ago",
        icon: "fas fa-key",
        cardMetrics: [
            { label: "Weak Passwords", value: ": 12", icon: "fas fa-exclamation-triangle" },
            { label: "Reused Passwords", value: ": 8", icon: "fas fa-sync-alt" }
        ],
        cardFooter: "High-risk credentials detected"
    },
    {
        id: 1,
        name: "Cisco Duo Licenses",
        type: "Enterprise  Identity Protection Management",
        status: "Syncing...", // Changed from Active
        risks: { critical: 0, high: 0, medium: 0 },
        securityScore: 100,
        uptime: 100,
        lastUpdate: "Checking database...",
        icon: "fas fa-shield-check",
        image: "Images/cisco-duo.png",
        cardMetrics: [
            { label: "Total Licences", value: ": ...", icon: "fas fa-id-card" },
            { label: "Active Usage", value: ": ...", icon: "fas fa-user-check" },
            { label: "Remaining Licences", value: ": ...", icon: "fas fa-user-plus" }
        ],
        cardFooter: "Verifying...",
        noDashboard: true
    },
    {
        id: 2,
        name: " Identity Protection",
        type: "User Management & Access Control",
        status: "active",
        risks: { critical: 0, high: 0, medium: 0 },
        securityScore: 0,
        uptime: 100,
        lastUpdate: "Loading...",
        icon: "fas fa-shield-alt",
        cardMetrics: [
            { label: "Total Users", value: ": 0", icon: "fas fa-users" },
            { label: "Active (24h)", value: ": 0", icon: "fas fa-user-check" },
            { label: "Admin Roles", value: ": 0", icon: "fas fa-crown" },
            { label: "Security Score", value: ": 0", icon: "fas fa-shield-alt" }
        ],
        cardFooter: "Live data",
        hasTabs: false,
        microsoftGraphEnabled: true,
        isIdentityCard: true,
        dashboardType: "Identity Protection"
    },
    {
        id: 3,
        name: "Device Protection",
        type: "Device Management & Compliance",
        status: "active",
        risks: { critical: 0, high: 0, medium: 0 },
        securityScore: 0,
        uptime: 100,
        lastUpdate: "Loading...",
        icon: "fas fa-laptop",
        cardMetrics: [
            { label: "Total Devices", value: ": 0", icon: "fas fa-desktop" },
            { label: "Non-Compliant", value: ": 0", icon: "fas fa-times-circle" },
            { label: "Not Encrypted", value: ": 0", icon: "fas fa-lock-open" },
            { label: "Stale (7+ days)", value: ": 0", icon: "fas fa-clock" }
        ],
        cardFooter: "Live device status",
        hasTabs: false,
        microsoftGraphEnabled: true,
        isDevicesCard: true,
        dashboardType: "Device Protection"
    },
    {
        id: 4,
        name: "Security & Events",
        type: "Real-Time SOC Threat Intelligence & Response",
        status: "active",
        risks: { critical: 0, high: 0, medium: 0 },
        securityScore: 0,
        uptime: 100,
        lastUpdate: "Loading...",
        icon: "fas fa-bell-slash",
        cardMetrics: [
            { label: "Active Incidents", value: ": ...", icon: "fas fa-exclamation-triangle" },
            { label: "High Alerts", value: ": ...", icon: "fas fa-bell" }
        ],
        cardFooter: "Fetching from Microsoft Graph Security...",
        hasTabs: false,
        microsoftGraphEnabled: true,
        isSecurityCard: true,
        dashboardType: "Security"
    },
    {
        id: 5,
        name: "Email Security",
        type: "Email Threat Detection & Management",
        status: "active",
        risks: { critical: 0, high: 0, medium: 0 },
        securityScore: 0,
        uptime: 100,
        lastUpdate: "Loading...",
        icon: "fas fa-envelope-open-text",
        cardMetrics: [
            { label: "Active Threats", value: ": 0", icon: "fas fa-exclamation-triangle" },
            { label: "High Severity", value: ": 0", icon: "fas fa-circle-exclamation" },
            { label: "Users Targeted", value: ": 0", icon: "fas fa-user-shield" },
            { label: "Open Incidents", value: ": 0", icon: "fas fa-bug" }
        ],
        cardFooter: "Monitoring threats",
        hasTabs: false,
        microsoftGraphEnabled: true,
        isEmailSecurityCard: true,
        dashboardType: "Security"
    },
    {
        id: 6,
        name: "Cloud data services",
        type: "Optomized cloud storage & Database health",
        status: "inactive",
        risks: { critical: 0, high: 0, medium: 0 },
        securityScore: 0,
        uptime: 0,
        lastUpdate: "Inactive",
        icon: "fas fa-database",
        cardMetrics: [
            { label: "Storage Used", value: ": 0", icon: "fas fa-cloud" },
            { label: "Data Redundancy", value: ": 0", icon: "fas fa-copy" }
        ],
        cardFooter: "Cloud Cost: R0/month",
        noDashboard: true
    },
    {
        id: 7,
        name: "Backup and Recovery",
        type: "Data Protection & Disaster Recovery",
        status: "active",
        risks: { critical: 0, high: 0, medium: 0 },
        securityScore: 0,
        uptime: 100,
        lastUpdate: "Loading...",
        icon: "fas fa-shield-alt",
        cardMetrics: [
            { label: "Total Storage", value: ": ...", icon: "fas fa-database" },
            { label: "Services Covered", value: ": 3", icon: "fas fa-cloud" }
        ],
        cardFooter: "Fetching from Microsoft Graph...",
        hasTabs: false,
        microsoftGraphEnabled: true,
        isBackupRecoveryCard: true,
        dashboardType: "Compliance"
    },
    {
        id: 8,
        name: "Applications",
        type: "Application Access & Risk Management",
        status: "active",
        risks: { critical: 0, high: 0, medium: 0 },
        securityScore: 0,
        uptime: 100,
        lastUpdate: "Loading...",
        icon: "fas fa-cubes",
        cardMetrics: [
            { label: "Total Apps", value: ": 0", icon: "fas fa-cubes" },
            { label: "External Apps", value: ": 0", icon: "fas fa-globe" },
            { label: "High Risk Apps", value: ": 0", icon: "fas fa-exclamation-circle" },
            { label: "High Access Apps", value: ": 0", icon: "fas fa-users" }
        ],
        cardFooter: "Access monitoring active",
        hasTabs: false,
        microsoftGraphEnabled: true,
        isApplicationsCard: true,
        dashboardType: "Device Protection"
    },
    {
        id: 11,
        name: "Infrastructure Monitoring",
        type: "Server Health & Performance Monitoring",
        status: "inactive",
        risks: { critical: 0, high: 0, medium: 0 },
        securityScore: 0,
        uptime: 0,
        lastUpdate: "Inactive",
        icon: "fas fa-server",
        cardMetrics: [
            { label: "Servers Online", value: ": 0", icon: "fas fa-server" },
            { label: "CPU Avg Load", value: ": 0", icon: "fas fa-microchip" },
            { label: "Memory Usage", value: ": 0", icon: "fas fa-memory" },
            { label: "Disk Space", value: ": 0", icon: "fas fa-hdd" }
        ],
        cardFooter: "Infrastructure inactive",
        noDashboard: true
    },
    {
        id: 10,
        name: "Network Security",
        type: "Cloudflare One / Zero Trust", 
        status: "loading",
        risks: { critical: 0, high: 0, medium: 0 },
        securityScore: 0,
        uptime: 97.2,
        lastUpdate: "Loading...",
        icon: "fas fa-network-wired",
        cardMetrics: [
            { label: "Protected Apps", value: ": ...", icon: "fas fa-lock" },
            { label: "Devices", value: ": ...", icon: "fas fa-laptop" },
            { label: "Gateway Rules", value: ": ...", icon: "fas fa-filter" },
            { label: "Identity", value: ": ...", icon: "fas fa-id-card" }
        ],
        cardFooter: "Fetching Cloudflare Zero Trust...",
        isNetworkSecurityCard: true,
        dashboardType: "Security"
    }
];

/* INITIALIZATION */
let microsoftUsersData = [];
let microsoftRolesData = [];
let userRolesMap = {}; // Maps userId to array of role names
let applicationsData = []; // Applications from Microsoft Graph
const SUNBIRD_APPLICATIONS_CACHE_KEY = 'sunbirdApplicationsDashboardSnapshot';
const SUNBIRD_GOVERNANCE_CACHE_KEY = 'sunbirdGovernanceSnapshot_v1';
const SUNBIRD_COMPLIANCE_CACHE_KEY = 'sunbirdComplianceSnapshot_v1';
const SUNBIRD_OPERATIONS_CACHE_KEY = 'sunbirdOperationsSnapshot_v1';
const SUNBIRD_CARD_CACHE_TTL_MS = 5 * 60 * 1000;
let sunbirdApplicationsPayload = null;
let sunbirdApplicationsTableState = { search: '', type: 'all', risk: 'all', sort: 'risk' };
let lockedSunbirdApplicationsInsightEvidenceKey = null;
let servicePrincipalsData = []; // Service Principals for app mapping
let groupsData = []; // Groups for access mapping
let sunbirdBillingMenuSelection = 'security';
let cachedSunbirdBillingHtml = '';
let cachedSunbirdSecurityData = null;
let cachedSunbirdBackupData = null;
let cachedSunbirdReportsData = null;
let sunbirdReportsRange = '30d';
let sunbirdReportsRequestId = 0;
const sunbirdReportDomainEvidenceMap = new Map();
let sunbirdReportDomainFilter = 'all';
const sunbirdReportsRequests = new Map();
const SUNBIRD_NETWORK_SECURITY_CACHE_KEY = 'sunbirdNetworkSecuritySnapshot_v1';
const BILLING_CACHE_KEY = 'billingInvoiceCache_v1';
const BILLING_CACHE_TTL_MS = 5 * 60 * 1000;
let billingAuthRetryCount = 0;
let identityRiskFocus = 'all';
let pendingIdentityRiskFocus = 'all';
let identityFetchRequestId = 0;
let sunbirdIdentityDashboardRequestPromise = null;
let sunbirdIdentityDashboardNotice = '';
let retryCount = 0; // Retry counter for Identity Access API failures
let latestDevicesCardData = null;
let latestEmailCardData = null;
let latestNetworkSecurityData = null;
let isNetworkSecurityLocked = false;
let isCredentialSecurityLocked = false;
let projectGridHasRendered = false;

function toBooleanMfa(value) {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') return value > 0;
    if (typeof value === 'string') {
        const normalized = value.trim().toLowerCase();
        return normalized === 'true' || normalized === 'yes' || normalized === 'enabled' || normalized === '1';
    }
    return false;
}

function isSummaryProjectCard(project) {
    return !!(project && (project.isIdentityCard || project.isDevicesCard || project.isEmailSecurityCard || project.isApplicationsCard));
}

function getSummaryCardStatusMeta(project) {
    if (!project || !isSummaryProjectCard(project)) {
        return { status: 'active', text: 'Live data', dotClass: 'ok' };
    }

    const normalizedStatus = String(project.status || '').toLowerCase();
    if (normalizedStatus.includes('error')) {
        return { status: 'error', text: 'Data unavailable', dotClass: 'error' };
    }

    if (normalizedStatus.includes('loading') || normalizedStatus.includes('syncing')) {
        return { status: 'loading', text: 'Live data', dotClass: 'partial' };
    }

    return { status: 'active', text: '', dotClass: 'ok' };
}

function toMetricValue(value, fallback = 0) {
    const raw = String(value ?? '').replace(':', '').trim();
    if (!raw || raw === '...') return String(fallback);
    return raw;
}

function normalizeSummaryMetrics(project) {
    if (!project || !isSummaryProjectCard(project)) return Array.isArray(project?.cardMetrics) ? project.cardMetrics : [];

    const defaultMetricsByCard = {
        2: [
            { label: "Total Users", value: ": 0", icon: "fas fa-users" },
            { label: "Active (24h)", value: ": 0", icon: "fas fa-user-check" },
            { label: "Admin Roles", value: ": 0", icon: "fas fa-crown" },
            { label: "Security Score", value: ": 0", icon: "fas fa-shield-alt" }
        ],
        3: [
            { label: "Total Devices", value: ": 0", icon: "fas fa-desktop" },
            { label: "Non-Compliant", value: ": 0", icon: "fas fa-times-circle" },
            { label: "Not Encrypted", value: ": 0", icon: "fas fa-lock-open" },
            { label: "Stale (7+ days)", value: ": 0", icon: "fas fa-clock" }
        ],
        5: [
            { label: "Active Threats", value: ": 0", icon: "fas fa-exclamation-triangle" },
            { label: "High Severity", value: ": 0", icon: "fas fa-circle-exclamation" },
            { label: "Users Targeted", value: ": 0", icon: "fas fa-user-shield" },
            { label: "Open Incidents", value: ": 0", icon: "fas fa-bug" }
        ],
        8: [
            { label: "Total Apps", value: ": 0", icon: "fas fa-cubes" },
            { label: "External Apps", value: ": 0", icon: "fas fa-globe" },
            { label: "High Risk Apps", value: ": 0", icon: "fas fa-exclamation-circle" },
            { label: "High Access Apps", value: ": 0", icon: "fas fa-users" }
        ]
    };

    const defaults = defaultMetricsByCard[project.id] || [];
    const incoming = Array.isArray(project.cardMetrics) ? project.cardMetrics.slice(0, 4) : [];
    return defaults.map((metric, index) => ({ ...metric, ...(incoming[index] || {}) })).slice(0, 4);
}

document.addEventListener('DOMContentLoaded', function() {
    setupEventListeners();
    initializePortalMobileDashboard();
    setupSessionManagement();
    initializeProjectsList();
    initializeBillingCard();
    initializeGovernanceCard();
    initializeSupportCard();
    initializeSunbirdLeftMenu();
    updateCopyrightYear();
});

function getSunbirdBillingActiveView() {
    const billingCard = document.getElementById('billing-card');
    return billingCard?.dataset?.sunbirdView || sunbirdBillingMenuSelection;
}

function isSunbirdBillingViewActive(view) {
    return getSunbirdBillingActiveView() === view;
}

async function bootstrapDashboardDataAfterLogin() {
    await refreshUserAccessFromServer();
    // Rebuild visible cards for the authenticated user immediately.
    syncPortalMobileUserName();
    initializeProjectsList();
    initializeGovernanceCard();
    initializeSupportCard();

    // Sunbird structure should be visible before slower API calls finish.
    if (isSunbirdUser()) {
        initializeSunbirdLeftMenu();
        if (typeof window.switchBillingMenu === 'function') {
            window.switchBillingMenu(sunbirdBillingMenuSelection || 'security');
        }
    }

    // Fire all key dashboard data fetches in parallel.
    Promise.allSettled([
        fetchDuoStats(),
        fetchApplicationsData(),
        fetchDevicesCardData(),
        fetchEmailCardData(),
        fetchBackupCardData(),
        initializeBillingCard()
    ]).then(() => {
        refreshPortalMobileDashboard();
        // Retry identity fetch once if Sunbird data is still empty.
        if (isSunbirdUser() && microsoftUsersData.length === 0) {
            setTimeout(() => {
                fetchIdentityAccessData();
            }, 900);
        }
    });
}

// Setup project tabs event listeners
function setupProjectsTabs() {
    // Removed - no longer using tabs
}

// Switch project tab
function switchProjectTab(tabId) {
    // Removed - no longer using tabs
}

// ============================================
//  Identity Protection / MICROSOFT GRAPH APIs
// ============================================
// Handles user management, role assignments, and identity data
// from Microsoft Graph, including user lists and access control

// Fetch Microsoft users and populate Identity Protection cards
async function fetchMicrosoftUsersForCard() {
    try {
        const authToken = localStorage.getItem('authToken');
        if (!authToken) {
            console.error('[Microsoft Users] No auth token found');
            return;
        }

        if (!isSunbirdUser()) {
            console.log('[Microsoft Users] Non-Sunbird user. Skipping fetch.');
            return;
        }
        
        const response = await fetch('/api/db/identity-details', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            console.error('[Microsoft Users] Error:', data.message);
            showNotification('Failed to load Microsoft Users data', false);
            return;
        }
        
        // Pass the entire data object to the population function
        populateIdentityCards(data);
        
    } catch (error) {
        console.error('[Microsoft Users] Exception:', error);
        showNotification('Failed to load Microsoft Users data', false);
    }
}

// Populate Identity Protection cards
function populateIdentityCards(apiData) {
    const container = document.getElementById('identity-cards-container');
    if (!container) return;

    container.innerHTML = '';
    
    // 1. Prioritize aggregate stats sent from the database/backend
    // 2. Fallback to calculating from the users array if aggregates aren't provided
    const users = apiData.users || [];
    const stats = {
        total: apiData.totalUsers ?? users.length,
        external: apiData.externalCount ?? users.filter(u => u.isExternal).length,
        missing: apiData.missingDataCount ?? users.filter(u => !u.jobTitle || !u.mobilePhone).length
    };
    
    const internalUsers = stats.total - stats.external;

    const card = document.createElement('div');
    card.className = 'identity-card';
    card.innerHTML = `
        <div class="identity-card-header">
            <i class="fas fa-shield-alt"></i>
            <div>
                <div class="identity-card-title">Identity Protection</div>
                <div class="identity-card-type">User Management & Access Control</div>
            </div>
        </div>
        
        <p class="identity-card-description">
            Monitor and manage user identities, access permissions, and authentication across your organization.
        </p>
        
        <div class="identity-card-status">
            <span class="status-badge">
                <span class="status-badge-dot"></span>
                Active
            </span>
        </div>
        
        <div class="identity-card-stats">
            <div class="identity-stat">
                <span class="identity-stat-value">${stats.total}</span>
                <span class="identity-stat-label">Total Users</span>
            </div>
            <div class="identity-stat">
                <span class="identity-stat-value">${stats.external}</span>
                <span class="identity-stat-label">External</span>
            </div>
            <div class="identity-stat">
                <span class="identity-stat-value">${internalUsers}</span>
                <span class="identity-stat-label">Internal</span>
            </div>
            <div class="identity-stat">
                <span class="identity-stat-value">${stats.missing}</span>
                <span class="identity-stat-label">Missing Data</span>
            </div>
        </div>
        
        <button class="identity-card-button" onclick="openIdentityDashboard()">
            View Full Dashboard & Analytics →
        </button>
    `;
    
    container.appendChild(card);
}

// ============================================
// APPLICATIONS - FETCH DATA & CARD DISPLAY
// ============================================

// Fetch Applications data from API
async function fetchApplicationsData() {
    try {
        const authToken = localStorage.getItem('authToken');
        if (!authToken) {
            console.error('[Applications] No auth token found');
            return;
        }

        // Only fetch Applications for Sunbird users
        if (!isSunbirdUser()) {
            console.log('[Applications] Non-Sunbird user. Skipping fetch.');
            return;
        }
        
        console.log('[Applications] Fetching applications data...');

        const payloadResponse = await fetch('/api/db/applications', {
            method: 'GET',
            cache: 'no-store',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });

        if (payloadResponse.ok) {
            const payloadData = await payloadResponse.json();
            if (payloadData.success) {
                sunbirdApplicationsPayload = normalizeSunbirdApplicationsData(payloadData);
                applicationsData = sunbirdApplicationsPayload.applications;
                saveSunbirdApplicationsSnapshot(sunbirdApplicationsPayload);
                populateApplicationsCard(sunbirdApplicationsPayload.summary);
                return;
            }
        }

        const response = await fetch('/api/db/application-metrics', {
            method: 'GET',
            cache: 'no-store',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Failed to load application metrics');
        const metrics = data.metrics || {};
        applicationsData = applicationsData || [];
        console.log('[Applications] Loaded DB application metrics');
        populateApplicationsCard({
            totalApplications: metrics.TotalApps || metrics.totalApps || 0,
            externalApplications: metrics.ExternalApps || metrics.externalApps || 0,
            highRiskApps: metrics.HighRiskApps || metrics.highRiskApps || 0,
            highAccessApps: metrics.HighAccessApps || metrics.highAccessApps || 0
        });
        
    } catch (error) {
        console.error('[Applications] Exception:', error);
        showNotification('Failed to load Applications data', false);
    }
}

// Populate Applications card in projects view
function populateApplicationsCard(apiData) {
    const container = document.getElementById('applications-cards-container');
    
    // If container doesn't exist, create it dynamically in the grid
    // This is handled by the project card system, so we update the project card metrics
    const appProject = mockProjects.find(p => p.isApplicationsCard);
    if (!appProject) return;
    
    // Update project card metrics
    const totalApps = apiData.totalApplications || 0;
    const externalApps = apiData.externalApplications || 0;
    const highRiskApps = apiData.highRiskApps ?? calculateHighRiskApplications(applicationsData);
    const highAccessApps = apiData.highAccessApps ?? applicationsData.filter(app => (app.userCount || 0) >= 20).length;

    appProject.status = 'active';
    appProject.cardMetrics = [
        { label: "Total Apps", value: `: ${totalApps}`, icon: "fas fa-cubes" },
        { label: "External Apps", value: `: ${externalApps}`, icon: "fas fa-globe" },
        { label: "High Risk Apps", value: `: ${highRiskApps}`, icon: "fas fa-exclamation-circle" },
        { label: "High Access Apps", value: `: ${highAccessApps}`, icon: "fas fa-users" }
    ];
    appProject.cardFooter = highRiskApps > 0 ? `${highRiskApps} high risk apps` : 'No high risk apps detected';
    appProject.lastUpdate = new Date().toLocaleTimeString();
    saveProjectCardToCache(appProject);
    
    // Re-render project cards
    displayCurrentProject();
}

// Show detailed app access (users/groups) modal/card
async function showAppAccessDetail(spId, appName) {
    console.log(`[App Access] Showing details for ${appName} (${spId})`);
    
    const authToken = localStorage.getItem('authToken');
    if (!authToken) {
        showNotification('Please login again to view app details', false);
        return;
    }
    
    try {
        // Show loading state
        const accessContainer = document.getElementById('apps-access-content');
        if (accessContainer) {
            accessContainer.innerHTML = isSunbirdUser()
                ? renderSunbirdPremiumLoader('Loading app access details')
                : `
                    <div style="text-align: center; padding: 40px; color: #94a3b8;">
                        <i class="fas fa-spinner fa-spin" style="font-size: 24px; margin-bottom: 12px;"></i>
                        <div>Loading app access details...</div>
                    </div>
                `;
        }
        
        const response = await fetch(`/api/app-access/${spId}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Failed to fetch app access data');
        }
        
        renderAppAccessDetail(spId, appName, data);
        
    } catch (error) {
        console.error('[App Access] Error:', error);
        const accessContainer = document.getElementById('apps-access-content');
        if (accessContainer) {
            accessContainer.innerHTML = `
                <div style="text-align: center; padding: 40px; color: #f87171;">
                    <i class="fas fa-exclamation-triangle" style="font-size: 24px; margin-bottom: 12px;"></i>
                    <div>Failed to load app details</div>
                    <small>${error.message}</small>
                </div>
            `;
        }
        showNotification('Failed to load app details', false);
    }
}

// Render app access detail view
function renderAppAccessDetail(spId, appName, data) {
    const accessContainer = document.getElementById('apps-access-content');
    if (!accessContainer) return;
    
    const { users, groups, hasDirect, message } = data;
    const app = applicationsData.find(a => a.id === spId);
    const isExternal = app ? app.isExternal : false;
    
    let groupsHtml = '';
    if (groups && groups.length > 0) {
        groupsHtml = groups.slice(0, 8).map(group => `<span class="group-tag">${group}</span>`).join(' ');
        if (groups.length > 8) {
            groupsHtml += ` <span class="group-tag more-groups">+${groups.length - 8} more</span>`;
        }
    } else {
        groupsHtml = '<span class="group-tag no-groups">No groups assigned</span>';
    }
    
    let usersHtml = `<span class="user-count-badge">${users || 0} users</span>`;
    
    const accessHtml = `
        <div class="access-grid">
            <div class="access-card">
                <h4>${appName}</h4>
                <p class="access-stat">
                    ${usersHtml}
                    <span>assigned users</span>
                </p>
                <small>${isExternal ? 'External app' : 'Internal app'}</small>
            </div>
            
            <div class="access-card">
                <h4>Assigned Groups</h4>
                <div class="groups-display">
                    ${groupsHtml}
                </div>
                ${groups && groups.length > 0 ? '' : '<small>No group assignments</small>'}
            </div>
            
            ${hasDirect ? 
                `<div class="access-card success">
                    <h4>✅ Direct Assignments</h4>
                    <p class="access-stat app-users">${users || 0} <span>users with direct access</span></p>
                    <small>Active assignments confirmed</small>
                </div>` :
                `<div class="access-card warning">
                    <h4>⚠️ ${message || 'No Direct Assignments Detected'}</h4>
                    <p class="access-stat">0 <span>direct user assignments</span></p>
                    <small>App exists but no users/groups assigned</small>
                </div>`
            }
            
            <div class="access-card full-width">
                <h4>Quick Actions</h4>
                <div class="access-actions">
                    <button class="btn-action" onclick="copyAppDetails('${spId}', '${appName}')">
                        <i class="fas fa-copy"></i> Copy Details
                    </button>
                    <button class="btn-action external" onclick="openMicrosoftApp('${spId}')">
                        <i class="fas fa-external-link-alt"></i> Azure Portal
                    </button>
                </div>
            </div>
        </div>
    `;
    
    accessContainer.innerHTML = accessHtml;
}

// Copy app details to clipboard
function copyAppDetails(spId, appName) {
    const app = applicationsData.find(a => a.id === spId);
    const details = `App: ${appName} (${spId})
Users: ${app?.userCount || 0}
External: ${app?.isExternal ? 'Yes' : 'No'}
Permissions: ${(app?.scopeCount || 0) + (app?.roleCount || 0)}`;
    
    navigator.clipboard.writeText(details).then(() => {
        showNotification('App details copied to clipboard', true);
    }).catch(() => {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = details;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        showNotification('App details copied', true);
    });
}

// Open app in Microsoft Azure Portal
function openMicrosoftApp(spId) {
    const url = `https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/ServicePrincipals/servicePrincipalId/${spId}/overview`;
    window.open(url, '_blank');
}

// Populate Applications table exactly as requested: App | Users | Type | Risk
function populateApplicationsTable() {
    const tableBody = document.getElementById('apps-table-body');
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    // Sort apps: High risk first, then by user count
    const sortedApps = [...applicationsData].sort((a, b) => {
         const riskA = calculateAppRisk(a).level;
         const riskB = calculateAppRisk(b).level;
         if (riskA === 'high' && riskB !== 'high') return -1;
         if (riskB === 'high' && riskA !== 'high') return 1;
         return b.userCount - a.userCount;
    });

    sortedApps.forEach((app) => {
        const risk = calculateAppRisk(app);
        
        // Emoji Logic
        let riskIcon = '✅';
        if (risk.level === 'high') riskIcon = '🔴';
        else if (risk.level === 'medium') riskIcon = '⚠️';
        
        const row = document.createElement('tr');
        row.className = 'app-row';
        row.innerHTML = `
            <td class="app-name">
                <strong>${app.name}</strong><br>
                <small style="color: #64748b;">${app.assignedGroups && app.assignedGroups.length ? 'Groups: ' + app.assignedGroups.join(', ') : 'No assigned groups'}</small>
            </td>
            <td class="app-users"><strong>${app.userCount || 0}</strong></td>
            <td class="app-type"><span class="user-type-badge ${app.isExternal ? 'external' : 'internal'}">${app.type}</span></td>
            <td class="app-risk">
                <span title="Risk Info">${riskIcon} <small style="color: #94a3b8; margin-left: 5px;">${risk.reasons[0]}</small></span>
            </td>
        `;
        
        tableBody.appendChild(row);
    });
    
    // Calculate and update the 4 Top Cards
    const totalApps = applicationsData.length;
    const externalApps = applicationsData.filter(a => a.isExternal).length;
    const highRiskApps = applicationsData.filter(a => calculateAppRisk(a).level === 'high').length;
    
    // Fix the "0 Avg Users" bug by only averaging apps that ACTUALLY have users
    const appsWithUsers = applicationsData.filter(a => a.userCount > 0);
    const totalUsers = appsWithUsers.reduce((sum, a) => sum + a.userCount, 0);
    const avgUsers = appsWithUsers.length > 0 ? Math.round(totalUsers / appsWithUsers.length) : 0;
    
    document.getElementById('totalAppsValue').textContent = totalApps;
    document.getElementById('externalAppsValue').textContent = externalApps;
    document.getElementById('highRiskAppsValue').textContent = highRiskApps;
    document.getElementById('avgUsersValue').textContent = avgUsers;
    
    // Update bottom insights dynamically
    updateApplicationsAccessOverview(totalUsers, externalApps);
    updateApplicationsInsights(totalApps, externalApps, highRiskApps);
}

async function fetchDevicesCardData() {
    const project = mockProjects.find(p => p.id === 3);
    if (!project) return;

    try {
        const token = localStorage.getItem('authToken');
        if (!token) return;

        if (!hasRealProjectMetrics(project)) {
            project.status = 'loading';
            displayCurrentProject();
        }

        const response = await fetch('/api/db/device-metrics', {
            method: 'GET',
            cache: 'no-store',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.message || 'Failed to fetch device metrics');
        }

        latestDevicesCardData = data;
        try {
            const detailResponse = await fetch('/api/microsoft-devices', {
                method: 'GET',
                cache: 'no-store',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            const detailData = await detailResponse.json();
            if (detailResponse.ok && detailData.success) {
                latestDevicesCardData = normalizeSunbirdDevicesData(detailData);
                sunbirdDevicesDashboardData = latestDevicesCardData;
                saveSunbirdDevicesSnapshot(latestDevicesCardData);
            }
        } catch (detailError) {
            console.warn('[Devices Card] Detailed device data unavailable, using cached metrics:', detailError.message);
        }

        const normalized = normalizeSunbirdDevicesData(latestDevicesCardData);
        const total = normalized.summary.totalDevices || 0;
        const nonCompliant = normalized.summary.nonCompliantDevices || 0;
        const notEncrypted = Math.max(0, total - (normalized.summary.encryptedDevices || 0));
        const stale7days = normalized.activityBreakdown?.stale7days ?? normalized.summary.staleDevices ?? 0;

        project.status = 'active';
        project.cardMetrics = [
            { label: "Total Devices", value: `: ${total}`, icon: "fas fa-desktop" },
            { label: "Non-Compliant", value: `: ${nonCompliant}`, icon: "fas fa-times-circle" },
            { label: "Not Encrypted", value: `: ${notEncrypted}`, icon: "fas fa-lock-open" },
            { label: "Stale (7+ days)", value: `: ${stale7days}`, icon: "fas fa-clock" }
        ];
        project.cardFooter = nonCompliant > 0 ? `${nonCompliant} non-compliant devices` : 'All devices compliant';
        project.lastUpdate = new Date().toLocaleTimeString();
        saveProjectCardToCache(project);
        displayCurrentProject();
    } catch (error) {
        console.error('[Devices Card] Error:', error);
        project.status = 'error';
        project.cardFooter = 'Data unavailable';
        displayCurrentProject();
    }
}

async function fetchEmailCardData() {
    const project = mockProjects.find(p => p.id === 5);
    if (!project) return;

    try {
        const token = localStorage.getItem('authToken');
        if (!token) return;

        if (!hasRealProjectMetrics(project)) {
            project.status = 'loading';
            displayCurrentProject();
        }

        const response = await fetch('/api/db/email-metrics', {
            method: 'GET',
            cache: 'no-store',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.message || 'Failed to fetch email metrics');
        }

        latestEmailCardData = normalizeSunbirdEmailData(data);

        try {
            const detailResponse = await fetch('/api/db/email-security', {
                method: 'GET',
                cache: 'no-store',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            const detailData = await detailResponse.json();
            if (detailResponse.ok && detailData.success) {
                latestEmailCardData = normalizeSunbirdEmailData({
                    ...detailData,
                    metrics: data.metrics || detailData.metrics
                });
                sunbirdEmailDashboardData = latestEmailCardData;
                saveSunbirdEmailSnapshot(latestEmailCardData);
            }
        } catch (detailError) {
            console.warn('[Email Card] Detailed cached email data unavailable, using cached metrics:', detailError.message);
        }

        const summary = latestEmailCardData.summary || {};
        const mailSummary = summary.mailActivity || latestEmailCardData.mailActivity?.summary || {};
        project.status = 'active';
        project.cardMetrics = [
            { label: "Active Threats", value: `: ${summary.activeThreats || 0}`, icon: "fas fa-exclamation-triangle" },
            { label: "High Severity", value: `: ${summary.highSeverityAlerts || 0}`, icon: "fas fa-circle-exclamation" },
            { label: "Users Targeted", value: `: ${summary.affectedUsersCount || 0}`, icon: "fas fa-user-shield" },
            { label: "Open Incidents", value: `: ${summary.activeIncidents || 0}`, icon: "fas fa-bug" }
        ];
        const activeThreats = summary.activeThreats || 0;
        project.cardFooter = activeThreats > 0
            ? `${activeThreats} active threats detected`
            : mailSummary.activeMailboxes
                ? `${mailSummary.activeMailboxes} active mailboxes | ${mailSummary.totalMailActivity || 0} mail events`
                : 'No active threats';
        project.lastUpdate = new Date().toLocaleTimeString();
        saveProjectCardToCache(project);
        displayCurrentProject();

        if (document.getElementById('project-preview-section')?.classList.contains('visible') && currentProject?.id === project.id) {
            showProjectPreview(project);
        }
    } catch (error) {
        console.error('[Email Card] Error:', error);
        project.status = 'error';
        project.cardFooter = 'Data unavailable';
        displayCurrentProject();
    }
}

// Calculate simple risk logic exactly as requested
function calculateAppRisk(app) {
    let riskLevel = 'safe'; 
    let riskReasons = [];
    
    const totalPermissions = (app.scopeCount || 0) + (app.roleCount || 0);
    const userCount = app.userCount || 0;
    
    // High Risk Rules
    if (userCount > 50) {
        riskLevel = 'high';
        riskReasons.push('App has high user access');
    }
    if (totalPermissions > 10) {
        riskLevel = 'high';
        riskReasons.push('Excessive permissions detected');
    }
    if (app.isExternal || app.type === 'External') {
        riskLevel = 'high';
        riskReasons.push('External app connected');
    }
    
    // Fallback if no rules hit
    if (riskReasons.length === 0) {
        riskLevel = 'safe';
        riskReasons.push('Safe / Internal');
    }
    
    return { level: riskLevel, reasons: riskReasons };
}

// Calculate number of high-risk applications
function calculateHighRiskApplications(apps) {
    if (!apps) return 0;
    return apps.filter(app => calculateAppRisk(app).level === 'high').length;
}

// Open Applications full dashboard
function openApplicationsDashboard() {
    console.log('[Applications Dashboard] Opening full dashboard...');
    
    const dashboardView = document.getElementById('dashboard-view');
    if (!dashboardView) return;

    // Show dashboard view immediately (no animations)
    const projectsView = document.getElementById('projects-view');
    if (projectsView) projectsView.style.display = 'none';
    dashboardView.style.display = 'block';
    
    // Hide generic dashboard parts
    const statsGrid = dashboardView.querySelector('.stats-grid');
    const chartsSection = dashboardView.querySelector('.charts-section');
    const dashboardTabs = dashboardView.querySelector('.dashboard-tabs');
    
    if (statsGrid) statsGrid.style.display = 'none';
    if (chartsSection) chartsSection.style.display = 'none';
    if (dashboardTabs) dashboardTabs.style.display = 'none';

    // Update dashboard title
    const projectName = document.getElementById('project-name');
    const projectStatus = document.getElementById('project-status');
    if (projectName) projectName.textContent = 'Applications - Access & Risk Management';
    if (projectStatus) projectStatus.textContent = 'Active';
    
    // Hide site header initially
    const siteHeader = document.querySelector('.site-headers');
    if (siteHeader) {
        siteHeader.classList.add('header-hidden');
        siteHeader.classList.remove('header-visible');
    }

    // Add scroll listener for header
    const handleDashboardScroll = () => {
        if (window.scrollY > 100) {
            siteHeader?.classList.add('header-visible');
            siteHeader?.classList.remove('header-hidden');
        } else {
            siteHeader?.classList.add('header-hidden');
            siteHeader?.classList.remove('header-visible');
        }
    };
    
    window.removeApplicationsDashboardScroll = () => {
        window.removeEventListener('scroll', handleDashboardScroll);
        delete window.removeApplicationsDashboardScroll;
    };
    
    window.addEventListener('scroll', handleDashboardScroll);

    // Update back button
    const backBtn = document.getElementById('btn-back');
    if (backBtn) {
        backBtn.onclick = function() {
            goBackToProjects();
            
            // Restore generic parts
            if (statsGrid) statsGrid.style.display = 'grid';
            if (chartsSection) chartsSection.style.display = 'grid';
        };
    }
    
    // Initialize dashboard if data is ready
    if (applicationsData.length > 0) {
        console.log('[Applications Dashboard] Data already loaded, initializing immediately');
        initializeApplicationsDashboard();
    } else {
        // Fetch data first
        console.log('[Applications Dashboard] Waiting for data to load...');
        let waitTime = 0;
        const maxWait = 5000;
        const checkInterval = setInterval(() => {
            waitTime += 100;
            if (applicationsData.length > 0) {
                console.log('[Applications Dashboard] Data loaded successfully');
                clearInterval(checkInterval);
                initializeApplicationsDashboard();
            } else if (waitTime >= maxWait) {
                console.warn('[Applications Dashboard] Data load timeout');
                clearInterval(checkInterval);
                initializeApplicationsDashboard();
            }
        }, 100);
    }
}

// Initialize Applications dashboard
async function initializeApplicationsDashboard() {
    console.log('[Applications Dashboard] Initializing...');
    console.log(`[Applications Dashboard] Applications data: ${applicationsData.length}`);
    
    const dashboardView = document.getElementById('dashboard-view');
    if (dashboardView) {
        dashboardView.innerHTML = generateApplicationsDashboardHTML();
    }
    
    // Populate dashboard content
    setTimeout(() => {
        console.log('[Applications Dashboard] Populating content...');
        populateApplicationsTable();
        initializeApplicationsCharts();
    }, 100);
}

// Generate Applications dashboard HTML
function generateApplicationsDashboardHTML() {
    return `
        <div class="applications-dashboard">
            <!-- Dashboard Header with Back Button and Title -->
            <div class="dashboard-header">
                <div class="dashboard-header-left">
                    <button class="btn-back-dashboard" id="btn-back-identity" onclick="goBackToProjects()">
                        <i class="fas fa-arrow-left"></i> Back
                    </button>
                    <h2 class="dashboard-heading">Applications - Access & Risk Management</h2>
                </div>
            </div>

            <!-- Top Stats Cards -->
            <div class="apps-stats-cards">
                <div class="apps-stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-cubes"></i>
                    </div>
                    <div class="stat-content">
                        <span class="stat-value" id="totalAppsValue">0</span>
                        <span class="stat-label">Total Applications</span>
                    </div>
                </div>
                
                <div class="apps-stat-card external">
                    <div class="stat-icon">
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                    <div class="stat-content">
                        <span class="stat-value" id="externalAppsValue">0</span>
                        <span class="stat-label">External Applications</span>
                    </div>
                </div>
                
                <div class="apps-stat-card risk">
                    <div class="stat-icon">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="stat-content">
                        <span class="stat-value" id="highRiskAppsValue">0</span>
                        <span class="stat-label">High Risk Applications</span>
                    </div>
                </div>
                
                <div class="apps-stat-card users">
                    <div class="stat-icon">
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="stat-content">
                        <span class="stat-value" id="avgUsersValue">0</span>
                        <span class="stat-label">Avg Users per App</span>
                    </div>
                </div>
            </div>

            <!-- Chart Section -->
            <div class="apps-chart-section">
                <div class="apps-chart-container">
                    <h3><i class="fas fa-chart-bar"></i> App Distribution</h3>
                    <canvas id="appDistributionChart"></canvas>
                </div>
                
                <div class="apps-chart-container">
                    <h3><i class="fas fa-chart-pie"></i> Top 5 Apps by Users</h3>
                    <canvas id="topAppsChart"></canvas>
                </div>
            </div>

            <!-- Applications Table -->
            <div class="apps-table-container">
                <h3><i class="fas fa-list"></i> Applications List</h3>
                <table class="apps-table">
                    <thead>
                        <tr>
                            <th>Application</th>
                            <th>Type</th>
                            <th>Users</th>
                            <th>Permissions</th>
                            <th>Risk Level</th>
                        </tr>
                    </thead>
                    <tbody id="apps-table-body">
                    </tbody>
                </table>
            </div>

            <!-- Access & Assignments Section -->
            <div class="apps-access-section">
                <h3><i class="fas fa-key"></i> Access Overview</h3>
                <div id="apps-access-content"></div>
            </div>

            <!-- Risk Insights Section -->
            <div class="apps-insights-section">
                <h3><i class="fas fa-lightbulb"></i> Risk Insights</h3>
                <div id="apps-insights-content"></div>
            </div>
        </div>
    `;
}


// Update Applications access overview
function updateApplicationsAccessOverview(totalUsers, externalApps) {
    const accessContainer = document.getElementById('apps-access-content');
    if (!accessContainer) return;
    
    const appsWithUsers = applicationsData.filter(a => a.userCount > 0);
    const appsWithoutUsers = applicationsData.filter(a => a.userCount === 0);
    
    let accessHTML = '<div class="access-grid">';
    
    accessHTML += `
        <div class="access-card">
            <h4>User Assignments</h4>
            <p class="access-stat">${totalUsers} <span>total users assigned</span></p>
            <small>${appsWithUsers.length} apps have users assigned</small>
        </div>
        
        <div class="access-card">
            <h4>Apps Without Access</h4>
            <p class="access-stat">${appsWithoutUsers.length} <span>apps have no assigned users</span></p>
            <small>Consider removing or archiving unused apps</small>
        </div>
        
        <div class="access-card">
            <h4>Risk Summary</h4>
            <p class="access-stat">${externalApps} <span>external apps</span></p>
            <small>Require additional security review</small>
        </div>
    `;
    
    // Show top apps by user count
    const topApps = applicationsData
        .filter(a => a.userCount > 0)
        .sort((a, b) => b.userCount - a.userCount)
        .slice(0, 3);
    
    if (topApps.length > 0) {
        accessHTML += `
            <div class="access-card full-width">
                <h4>Top 3 Apps by User Count</h4>
                <div class="top-apps-list">
        `;
        
        topApps.forEach(app => {
            const risk = calculateAppRisk(app);
            const riskColor = risk.level === 'high' ? 'danger' : risk.level === 'medium' ? 'warning' : 'success';
            accessHTML += `
                <div class="top-app-item">
                    <div class="app-info">
                        <span class="app-name">${app.name}</span>
                        <span class="app-type">${app.isExternal ? 'External' : 'Internal'}</span>
                    </div>
                    <div class="user-badge ${riskColor}">${app.userCount} users</div>
                </div>
            `;
        });
        
        accessHTML += `
                </div>
            </div>
        `;
    }
    
    accessHTML += '</div>';
    accessContainer.innerHTML = accessHTML;
}


// Update Applications insights
function updateApplicationsInsights(totalApps, externalApps, highRiskApps) {
    const insightsContainer = document.getElementById('apps-insights-content');
    if (!insightsContainer) return;
    
    let insightsHTML = '<div class="insights-list">';
    
    if (externalApps > 0) {
        insightsHTML += `
            <div class="insight-item warning">
                <i class="fas fa-exclamation-circle"></i>
                <span><strong>${externalApps} external app(s)</strong> connected - review access regularly</span>
            </div>
        `;
    }
    
    if (highRiskApps > 0) {
        insightsHTML += `
            <div class="insight-item danger">
                <i class="fas fa-exclamation-triangle"></i>
                <span><strong>${highRiskApps} high-risk app(s)</strong> detected - requires attention</span>
            </div>
        `;
    }
    
    const internalApps = totalApps - externalApps;
    if (internalApps > 0) {
        insightsHTML += `
            <div class="insight-item success">
                <i class="fas fa-check-circle"></i>
                <span><strong>${internalApps} internal app(s)</strong> - managed by Microsoft</span>
            </div>
        `;
    }
    
    insightsHTML += '</div>';
    insightsContainer.innerHTML = insightsHTML;
}

// Initialize Applications charts
function initializeApplicationsCharts() {
    console.log('[Applications Charts] Initializing charts...');
    
    if (typeof Chart === 'undefined') {
        console.warn('[Applications Charts] Chart.js not loaded yet');
        setTimeout(initializeApplicationsCharts, 100);
        return;
    }
    
    setTimeout(() => {
        renderAppDistributionChart();
        renderTopAppsChart();
    }, 50);
}

// Render App Distribution Chart
function renderAppDistributionChart() {
    const canvasElement = document.getElementById('appDistributionChart');
    if (!canvasElement) return;
    
    const internalCount = applicationsData.filter(a => !a.isExternal).length;
    const externalCount = applicationsData.filter(a => a.isExternal).length;
    
    canvasElement.width = canvasElement.parentElement.clientWidth;
    canvasElement.height = 300;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.appDistributionChartInstance && typeof window.appDistributionChartInstance.destroy === 'function') {
        window.appDistributionChartInstance.destroy();
    }
    
    window.appDistributionChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Internal', 'External'],
            datasets: [{
                label: 'Application Count',
                data: [internalCount, externalCount],
                backgroundColor: [
                    'rgba(34, 197, 94, 0.7)',
                    'rgba(248, 113, 113, 0.7)'
                ],
                borderColor: [
                    'rgba(34, 197, 94, 1)',
                    'rgba(248, 113, 113, 1)'
                ],
                borderWidth: 2,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            indexAxis: 'y',
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: { color: '#999' },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' }
                },
                y: {
                    ticks: { color: '#999', font: { size: 12 } },
                    grid: { display: false }
                }
            }
        }
    });
}

// Render Top Apps by Users Chart
function renderTopAppsChart() {
    const canvasElement = document.getElementById('topAppsChart');
    if (!canvasElement) return;
    
    const topApps = applicationsData
        .sort((a, b) => b.userCount - a.userCount)
        .slice(0, 5);
    
    if (topApps.length === 0) return;
    
    const labels = topApps.map(a => a.name.substring(0, 15));
    const data = topApps.map(a => a.userCount || 0);
    
    canvasElement.width = canvasElement.parentElement.clientWidth;
    canvasElement.height = 300;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.topAppsChartInstance && typeof window.topAppsChartInstance.destroy === 'function') {
        window.topAppsChartInstance.destroy();
    }
    
    const colors = [
        'rgba(0, 110, 255, 0.8)',
        'rgba(249, 115, 22, 0.8)',
        'rgba(34, 197, 94, 0.8)',
        'rgba(248, 113, 113, 0.8)',
        'rgba(168, 85, 247, 0.8)'
    ];
    
    window.topAppsChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'User Count',
                data: data,
                backgroundColor: colors.slice(0, labels.length),
                borderColor: colors.slice(0, labels.length).map(c => c.replace('0.8', '1')),
                borderWidth: 2,
                borderRadius: 6
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: { color: '#999' },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' }
                },
                y: {
                    ticks: { color: '#999', font: { size: 11 } },
                    grid: { display: false }
                }
            }
        }
    });
}

// Open Identity full dashboard
function openIdentityDashboard() {
    console.log('[Identity Dashboard] Opening full dashboard...');

    if (isSunbirdIdentityClient()) {
        openSunbirdIdentityDashboard();
        return;
    }
    
    const dashboardView = document.getElementById('dashboard-view');
    if (!dashboardView) return;

    // Show dashboard view immediately (no animations)
    const projectsView = document.getElementById('projects-view');
    if (projectsView) projectsView.style.display = 'none';
    dashboardView.style.display = 'block';
    
    // Hide generic dashboard parts to prioritize Identity content
    const statsGrid = dashboardView.querySelector('.stats-grid');
    const chartsSection = dashboardView.querySelector('.charts-section');
    const dashboardTabs = dashboardView.querySelector('.dashboard-tabs');
    
    if (statsGrid) statsGrid.style.display = 'none';
    if (chartsSection) chartsSection.style.display = 'none';
    if (dashboardTabs) dashboardTabs.style.display = 'none';

    // Update dashboard title
    const projectName = document.getElementById('project-name');
    const projectStatus = document.getElementById('project-status');
    if (projectName) projectName.textContent = ' Identity Protection - Full Dashboard';
    if (projectStatus) projectStatus.textContent = 'Active';
    
    // Hide site header initially for full dashboard view
    const siteHeader = document.querySelector('.site-headers');
    if (siteHeader) {
        siteHeader.classList.add('header-hidden');
        siteHeader.classList.remove('header-visible');
    }

    // Add scroll listener to show/hide header
    const handleDashboardScroll = () => {
        if (window.scrollY > 100) {
            siteHeader?.classList.add('header-visible');
            siteHeader?.classList.remove('header-hidden');
        } else {
            siteHeader?.classList.add('header-hidden');
            siteHeader?.classList.remove('header-visible');
        }
    };
    
    // Make it removable
    window.removeDashboardScroll = () => {
        window.removeEventListener('scroll', handleDashboardScroll);
        delete window.removeDashboardScroll;
    };
    
    window.addEventListener('scroll', handleDashboardScroll);

    // Update back button to go back to projects
    const backBtn = document.getElementById('btn-back');
    if (backBtn) {
        backBtn.onclick = function() {
            goBackToProjects();
            
            // Restore generic parts for other projects
            if (statsGrid) statsGrid.style.display = 'grid';
            if (chartsSection) chartsSection.style.display = 'grid';
        };
    }
    
    // Render an identity-specific loading view immediately to avoid showing generic dashboard content.
    dashboardView.innerHTML = generateIdentityDashboardHTML();
    showIdentityTableLoadingSkeleton();

    // Trigger fresh fetch whenever user opens Identity dashboard.
    fetchIdentityAccessData();

    // WAIT for data to load before initializing dashboard
    if (microsoftUsersData.length > 0) {
        console.log('[Identity Dashboard] Data already loaded, initializing immediately');
        initializeIdentityDashboard();
    } else {
        // Otherwise wait for data to load with timeout
        console.log('[Identity Dashboard] Waiting for data to load...');
        let waitTime = 0;
        const maxWait = 12000; // Max 12 seconds for slower Graph calls
        const checkInterval = setInterval(() => {
            waitTime += 100;
            if (microsoftUsersData.length > 0) {
                console.log('[Identity Dashboard] Data loaded successfully');
                clearInterval(checkInterval);
                initializeIdentityDashboard();
            } else if (waitTime >= maxWait) {
                console.warn('[Identity Dashboard] Data load timeout, initializing with available data');
                clearInterval(checkInterval);
                initializeIdentityDashboard();
            }
        }, 100);
    }
}

const SUNBIRD_IDENTITY_CACHE_KEY = 'sunbirdIdentityDashboardSnapshot';
let sunbirdIdentityTableState = {
    search: '',
    risk: 'all',
    mfa: 'all',
    type: 'all',
    sort: 'risk'
};
let lockedSunbirdInsightEvidenceKey = null;

function escapeIdentityText(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[char]));
}

function getIdentityRoleNames(user) {
    return (user?.roles || [])
        .map(role => typeof role === 'string' ? role : (role?.name || role?.roleName || ''))
        .filter(Boolean);
}

function isIdentityPrivileged(user) {
    return getIdentityRoleNames(user).some(role => /(admin|global|privileged|security|directory|exchange|sharepoint|compliance)/i.test(role));
}

function getIdentityLastSignInTime(user) {
    const raw = user?.lastSignIn?.dateTime || user?.signInActivity?.lastSignInDateTime || null;
    const time = raw ? new Date(raw).getTime() : 0;
    return Number.isFinite(time) ? time : 0;
}

function normalizeSunbirdIdentityUser(user = {}) {
    const rawSignIn = user.lastSignIn || {};
    const signInActivity = user.signInActivity || {};
    const dateTime = rawSignIn.dateTime || signInActivity.lastSignInDateTime || user.lastSignInDateTime || null;
    const lastSignInTime = dateTime ? new Date(dateTime).getTime() : 0;
    const daysSince = Number.isFinite(Number(rawSignIn.daysSince))
        ? Number(rawSignIn.daysSince)
        : lastSignInTime
            ? Math.floor((Date.now() - lastSignInTime) / (24 * 60 * 60 * 1000))
            : 999;
    return {
        ...user,
        signInActivity: {
            ...signInActivity,
            lastSignInDateTime: dateTime || signInActivity.lastSignInDateTime || null
        },
        lastSignIn: {
            ...rawSignIn,
            dateTime,
            location: rawSignIn.location || user.location || signInActivity.location || 'Unknown',
            device: rawSignIn.device || user.device || signInActivity.device || 'Unknown Device',
            status: rawSignIn.status || signInActivity.status || user.signInStatus || 'Success',
            daysSince
        }
    };
}

function getIdentityDaysSinceSignIn(user) {
    if (Number.isFinite(Number(user?.lastSignIn?.daysSince))) return Number(user.lastSignIn.daysSince);
    const time = getIdentityLastSignInTime(user);
    if (!time) return 999;
    return Math.floor((Date.now() - time) / (24 * 60 * 60 * 1000));
}

function formatIdentityDate(user) {
    const time = getIdentityLastSignInTime(user);
    if (!time) return 'Never';
    const date = new Date(time);
    const dateStr = date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    const timeStr = date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    return `${dateStr} ${timeStr}`;
}

function getIdentityRiskRank(user) {
    const risk = String(user?.riskLevel || 'SAFE').toUpperCase();
    if (risk === 'HIGH') return 3;
    if (risk === 'MEDIUM') return 2;
    return 1;
}

function getSunbirdIdentityUsers(data = sunbirdDashboardData) {
    if (Array.isArray(data?.users) && data.users.length > 0) return data.users;
    return Array.isArray(microsoftUsersData) ? microsoftUsersData : [];
}

function buildSunbirdIdentityModel(data = sunbirdDashboardData) {
    const users = getSunbirdIdentityUsers(data);
    const totalUsers = users.length;
    const privilegedUsers = users.filter(isIdentityPrivileged);
    const mfaEnabledUsers = users.filter(user => toBooleanMfa(user.mfaEnabled));
    const mfaMissingUsers = users.filter(user => !toBooleanMfa(user.mfaEnabled));
    const highRiskUsers = users.filter(user => String(user.riskLevel || '').toUpperCase() === 'HIGH');
    const mediumRiskUsers = users.filter(user => String(user.riskLevel || '').toUpperCase() === 'MEDIUM');
    const safeUsers = Math.max(0, totalUsers - highRiskUsers.length - mediumRiskUsers.length);
    const externalUsers = users.filter(user => user.isExternal);
    const inactiveUsers = users.filter(user => getIdentityDaysSinceSignIn(user) > 30);
    const unknownDeviceUsers = users.filter(user => /unknown|no sign-in|n\/a/i.test(String(user?.lastSignIn?.device || 'Unknown')));
    const adminsWithoutMfa = privilegedUsers.filter(user => !toBooleanMfa(user.mfaEnabled));
    const failedSignInUsers = users.filter(user => getSunbirdSignInIssueReasons(user).length > 0);
    const multiplePrivilegedRoles = users.filter(user => getIdentityRoleNames(user).filter(role => /(admin|global|privileged|security|directory)/i.test(role)).length > 1);

    return {
        users,
        metrics: {
            totalUsers,
            mfaEnabled: mfaEnabledUsers.length,
            mfaMissing: mfaMissingUsers.length,
            mfaCoverage: totalUsers ? Math.round((mfaEnabledUsers.length / totalUsers) * 100) : 0,
            privilegedUsers: privilegedUsers.length,
            highRiskUsers: highRiskUsers.length,
            mediumRiskUsers: mediumRiskUsers.length,
            safeUsers,
            externalUsers: externalUsers.length,
            inactiveUsers: inactiveUsers.length,
            failedSignIns: failedSignInUsers.length,
            unknownDevices: unknownDeviceUsers.length,
            adminsWithoutMfa: adminsWithoutMfa.length,
            multiplePrivilegedRoles: multiplePrivilegedRoles.length
        },
        evidence: {
            allUsers: users,
            mfaEnabledUsers,
            mfaMissingUsers,
            privilegedUsers,
            highRiskUsers,
            adminsWithoutMfa,
            usersWithoutMfa: mfaMissingUsers,
            inactiveUsers,
            failedSignInUsers,
            externalUsers,
            unknownDeviceUsers,
            multiplePrivilegedRoles
        }
    };
}

function getSunbirdSignInIssueReasons(user) {
    const reasons = [];
    const status = String(user?.lastSignIn?.status || '').toLowerCase();
    const location = String(user?.lastSignIn?.location || '').toLowerCase();
    const device = String(user?.lastSignIn?.device || '').toLowerCase();
    const risk = String(user?.riskLevel || '').toUpperCase();
    const daysSince = getIdentityDaysSinceSignIn(user);

    if (status.includes('fail')) reasons.push('Failed sign-in');
    if (risk === 'HIGH') reasons.push('High-risk user');
    if (location.includes('unknown') || location === 'no sign-in') reasons.push('Unknown location');
    if (device.includes('unknown') || device === 'no sign-in') reasons.push('Unknown device');
    if (daysSince > 30) reasons.push('Inactive sign-in');

    return reasons;
}

function openSunbirdIdentityDashboard() {
    const dashboardView = document.getElementById('dashboard-view');
    const projectsView = document.getElementById('projects-view');
    if (!dashboardView) return;

    if (projectsView) projectsView.style.display = 'none';
    dashboardView.style.display = 'block';
    dashboardView.style.visibility = 'visible';
    dashboardView.style.opacity = '1';
    dashboardView.classList.remove('sunbird-device-active');
    dashboardView.classList.remove('sunbird-email-active');
    dashboardView.classList.remove('sunbird-security-active');
    dashboardView.classList.remove('sunbird-backup-active');
    dashboardView.classList.remove('sunbird-applications-active');
    dashboardView.classList.add('sunbird-identity-active');

    const projectName = document.getElementById('project-name');
    const projectStatus = document.getElementById('project-status');
    if (projectName) projectName.textContent = 'Identity Protection';
    if (projectStatus) projectStatus.textContent = 'Active';

    captureDashboardViewHTML();
    dashboardView.innerHTML = renderSunbirdIdentityShell();
    setupSunbirdIdentityDashboard();

    const cached = readSunbirdIdentitySnapshot();
    if (cached && isFreshSunbirdIdentitySnapshot(cached)) {
        sunbirdDashboardData = normalizeSunbirdDashboardData(cached);
        microsoftUsersData = getSunbirdIdentityUsers(sunbirdDashboardData);
        microsoftRolesData = Array.isArray(sunbirdDashboardData.roleAssignments) ? sunbirdDashboardData.roleAssignments : microsoftRolesData;
        buildUserRolesMap();
        renderSunbirdIdentityDashboard();
    } else if (getSunbirdIdentityUsers().length > 0) {
        renderSunbirdIdentityDashboard();
    } else {
        const signinsEl = document.getElementById('sunbird-id-signins');
        if (signinsEl) signinsEl.innerHTML = renderSunbirdPremiumLoader('Refreshing live sign-ins');
    }

    loadSunbirdIdentityDashboardData();
}

function renderSunbirdIdentityShell() {
    return `
        <section class="sunbird-identity-dashboard" id="sunbird-identity-dashboard">
            <div class="sunbird-id-header">
                <button id="sunbird-id-back" class="sunbird-id-back-btn" type="button">
                    <span class="sunbird-id-back-icon" aria-hidden="true">&larr;</span>
                    <span>Back</span>
                </button>
                <div>
                    <h2>Identity Protection</h2>
                    <p>Identity and access evidence for Sunbird users.</p>
                </div>
                <div class="sunbird-id-microsoft-badge" aria-label="Microsoft Solutions">
                    <span class="sunbird-id-ms-logo" aria-hidden="true">
                        <i></i><i></i><i></i><i></i>
                    </span>
                    <span>Microsoft Solutions</span>
                </div>
            </div>

            <div class="sunbird-id-metrics" id="sunbird-id-metrics"></div>
            <div class="sunbird-id-insights" id="sunbird-id-insights"></div>
            <div class="sunbird-id-charts" id="sunbird-id-charts"></div>
            <div class="sunbird-id-signins" id="sunbird-id-signins"></div>

            <section class="sunbird-id-table-section">
                <div class="sunbird-id-table-toolbar">
                    <input id="sunbird-id-search" class="sunbird-id-search" type="search" placeholder="Search name, email, role, risk, location, device">
                    <select id="sunbird-id-risk-filter" class="sunbird-id-select">
                        <option value="all">All risks</option>
                        <option value="safe">Safe</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                    </select>
                    <select id="sunbird-id-mfa-filter" class="sunbird-id-select">
                        <option value="all">All MFA</option>
                        <option value="yes">MFA yes</option>
                        <option value="no">MFA no</option>
                    </select>
                    <select id="sunbird-id-type-filter" class="sunbird-id-select">
                        <option value="all">All types</option>
                        <option value="internal">Internal</option>
                        <option value="external">External</option>
                    </select>
                    <select id="sunbird-id-sort" class="sunbird-id-select">
                        <option value="risk">Sort risk</option>
                        <option value="lastSignIn">Sort last sign-in</option>
                    </select>
                    <button id="sunbird-id-clear" class="sunbird-id-clear-btn" type="button">Clear</button>
                </div>

                <div class="sunbird-id-table-wrap">
                    <table class="sunbird-id-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Job Title</th>
                                <th>Roles</th>
                                <th>Type</th>
                                <th>MFA</th>
                                <th>Auth Methods</th>
                                <th>Risk</th>
                                <th>Status</th>
                                <th>Last Sign-In</th>
                                <th>Location</th>
                                <th>Device</th>
                                <th>Phone</th>
                            </tr>
                        </thead>
                        <tbody id="sunbird-id-users-body"></tbody>
                    </table>
                </div>
            </section>
        </section>
        <div id="sunbird-id-evidence-modal" class="sunbird-id-modal" aria-hidden="true"></div>
    `;
}

function readSunbirdIdentitySnapshot() {
    try {
        const parsed = JSON.parse(localStorage.getItem(SUNBIRD_IDENTITY_CACHE_KEY) || 'null');
        return parsed?.users ? parsed : null;
    } catch (error) {
        return null;
    }
}

function shouldBlurGateForNonSunbird() {
    return !isSunbirdUser();
}

function enableNonSunbirdBlurGate(card) {
    if (!card || card.dataset.blurGateReady === 'true') return;

    card.dataset.blurGateReady = 'true';
    if (!card.hasAttribute('tabindex')) card.setAttribute('tabindex', '0');

    card.addEventListener('click', event => {
        if (isSunbirdUser()) return;
        if (event.target.closest('button, a, input, select, textarea, [role="button"]')) return;
        card.classList.toggle('blur-gate-revealed');
    });

    card.addEventListener('keydown', event => {
        if (isSunbirdUser()) return;
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        card.classList.toggle('blur-gate-revealed');
    });
}

function setNonSunbirdBlurGate(card, enabled) {
    if (!card) return;
    card.classList.toggle('non-sunbird-blur-gated', enabled);
    if (!enabled) card.classList.remove('blur-gate-revealed');
    if (enabled) enableNonSunbirdBlurGate(card);
}

function syncNonSunbirdBlurGatedPanels() {
    const enabled = shouldBlurGateForNonSunbird();
    NON_SUNBIRD_BLUR_PANEL_IDS.forEach(id => {
        setNonSunbirdBlurGate(document.getElementById(id), enabled);
    });
}

function isFreshSunbirdIdentitySnapshot(snapshot, maxAgeMs = 60000) {
    const savedAt = snapshot?.savedAt ? new Date(snapshot.savedAt).getTime() : 0;
    return savedAt && Number.isFinite(savedAt) && Date.now() - savedAt <= maxAgeMs;
}

function saveSunbirdIdentitySnapshot(data) {
    if (!data?.users?.length) return;
    localStorage.setItem(SUNBIRD_IDENTITY_CACHE_KEY, JSON.stringify({
        ...data,
        savedAt: new Date().toISOString()
    }));
}

async function fetchFreshSunbirdIdentityDashboardData() {
    if (sunbirdIdentityDashboardRequestPromise) {
        console.log('[Sunbird Identity Dashboard] Reusing dashboard request already in progress');
        return sunbirdIdentityDashboardRequestPromise;
    }

    const request = requestFreshSunbirdIdentityDashboardData();
    sunbirdIdentityDashboardRequestPromise = request;
    try {
        return await request;
    } finally {
        if (sunbirdIdentityDashboardRequestPromise === request) {
            sunbirdIdentityDashboardRequestPromise = null;
        }
    }
}

async function requestFreshSunbirdIdentityDashboardData() {
    const token = localStorage.getItem('authToken');
    if (!token) throw new Error('Authentication required');

    const endpoint = '/api/sunbird/identity-dashboard';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25000);
    try {
        const response = await fetch(endpoint, {
            method: 'GET',
            cache: 'no-store',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            },
            signal: controller.signal
        });

        const responseBody = await response.text();
        let result;
        try {
            result = responseBody ? JSON.parse(responseBody) : {};
        } catch (_) {
            throw new Error(response.ok
                ? 'Identity Protection returned an invalid response.'
                : `Identity Protection is temporarily unavailable (${response.status}).`);
        }

        if (response.ok && result.success) {
            console.log('[Sunbird Identity Dashboard] Data loaded from production endpoint');
            return { ...result, liveSource: endpoint };
        }
        if (response.status === 403) {
            const error = new Error('Access denied: This feature is only available for Sunbird clients');
            error.statusCode = 403;
            throw error;
        }
        if (response.status === 401) {
            const error = new Error('Identity Protection authentication expired');
            error.statusCode = 401;
            throw error;
        }
        throw new Error(result.message || `Identity Dashboard endpoint failed (${response.status})`);
    } catch (error) {
        // Keep the dashboard usable when a live Microsoft Graph refresh is slow.
        // The cache-only query is intentionally prevented from triggering Graph again.
        if (error?.statusCode !== 401 && error?.statusCode !== 403) {
            const cacheController = new AbortController();
            const cacheTimeout = setTimeout(() => cacheController.abort(), 8000);
            try {
                const cachedResponse = await fetch('/api/sunbird/identity-dashboard-cached?cacheOnly=1', {
                    method: 'GET',
                    cache: 'no-store',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json',
                        'Cache-Control': 'no-cache, no-store, must-revalidate'
                    },
                    signal: cacheController.signal
                });
                const cachedData = await cachedResponse.json().catch(() => ({}));
                if (cachedResponse.ok && cachedData.success && Array.isArray(cachedData.users) && cachedData.users.length) {
                    console.warn('[Sunbird Identity Dashboard] Live refresh unavailable; showing the latest stored evidence.');
                    return { ...cachedData, liveSource: '/api/sunbird/identity-dashboard-cached', cachedFallback: true };
                }
            } catch (cacheError) {
                console.warn('[Sunbird Identity Dashboard] Cached fallback failed:', cacheError.message);
            } finally {
                clearTimeout(cacheTimeout);
            }
        }
        const message = error.name === 'AbortError'
            ? 'Live identity refresh took too long.'
            : error.message;
        console.error('[Sunbird Identity Dashboard] Fetch error:', message);
        throw new Error(message);
    } finally {
        clearTimeout(timeout);
    }
}

async function loadSunbirdIdentityDashboardData() {
    try {
        const data = await fetchFreshSunbirdIdentityDashboardData();

        sunbirdIdentityDashboardNotice = '';
        sunbirdDashboardData = normalizeSunbirdDashboardData(data);
        microsoftUsersData = getSunbirdIdentityUsers(sunbirdDashboardData);
        microsoftRolesData = Array.isArray(sunbirdDashboardData.roleAssignments) ? sunbirdDashboardData.roleAssignments : microsoftRolesData;
        buildUserRolesMap();
        saveSunbirdIdentitySnapshot(sunbirdDashboardData);
        updateIdentityProjectCardFromDashboard(sunbirdDashboardData);
        renderSunbirdIdentityDashboard(false);
    } catch (error) {
        console.error('[Sunbird Identity Dashboard] Failed to load:', error.message);
        const snapshot = readSunbirdIdentitySnapshot();
        if (snapshot?.users?.length) {
            sunbirdIdentityDashboardNotice = `Live refresh is delayed. Showing saved identity evidence from ${formatSunbirdReportDate(snapshot.savedAt, true)}.`;
            sunbirdDashboardData = normalizeSunbirdDashboardData(snapshot);
            microsoftUsersData = getSunbirdIdentityUsers(sunbirdDashboardData);
            microsoftRolesData = Array.isArray(sunbirdDashboardData.roleAssignments) ? sunbirdDashboardData.roleAssignments : microsoftRolesData;
            buildUserRolesMap();
            renderSunbirdIdentityDashboard();
            return;
        }

        const signinsEl = document.getElementById('sunbird-id-signins');
        if (signinsEl) {
            signinsEl.innerHTML = `
                <article class="sunbird-id-signin-card sunbird-id-refresh-state">
                    <h3>Live sign-ins are temporarily unavailable</h3>
                    <p>${escapeIdentityText(error.message || 'The identity service did not return data.')}</p>
                    <button type="button" class="sunbird-id-evidence-btn" onclick="window.openSunbirdIdentityDashboard()">Retry live refresh</button>
                </article>
            `;
        }
        const body = document.getElementById('sunbird-id-users-body');
        if (body) {
            body.innerHTML = '<tr><td colspan="13" class="sunbird-id-empty">Live identity evidence is temporarily unavailable. Retry the refresh shortly.</td></tr>';
        }
    }
}

function setupSunbirdIdentityDashboard() {
    document.getElementById('sunbird-id-back')?.addEventListener('click', goBackToProjects);
    document.getElementById('sunbird-id-search')?.addEventListener('input', event => {
        sunbirdIdentityTableState.search = event.target.value;
        renderSunbirdIdentityTable();
    });
    document.getElementById('sunbird-id-risk-filter')?.addEventListener('change', event => {
        sunbirdIdentityTableState.risk = event.target.value;
        renderSunbirdIdentityTable();
    });
    document.getElementById('sunbird-id-mfa-filter')?.addEventListener('change', event => {
        sunbirdIdentityTableState.mfa = event.target.value;
        renderSunbirdIdentityTable();
    });
    document.getElementById('sunbird-id-type-filter')?.addEventListener('change', event => {
        sunbirdIdentityTableState.type = event.target.value;
        renderSunbirdIdentityTable();
    });
    document.getElementById('sunbird-id-sort')?.addEventListener('change', event => {
        sunbirdIdentityTableState.sort = event.target.value;
        renderSunbirdIdentityTable();
    });
    document.getElementById('sunbird-id-clear')?.addEventListener('click', () => {
        sunbirdIdentityTableState = { search: '', risk: 'all', mfa: 'all', type: 'all', sort: 'risk' };
        ['sunbird-id-search', 'sunbird-id-risk-filter', 'sunbird-id-mfa-filter', 'sunbird-id-type-filter', 'sunbird-id-sort'].forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.value = id === 'sunbird-id-sort' ? 'risk' : 'all';
            if (id === 'sunbird-id-search') el.value = '';
        });
        renderSunbirdIdentityTable();
    });
}

function renderSunbirdIdentityDashboard() {
    const model = buildSunbirdIdentityModel();
    renderSunbirdIdentityMetrics(model);
    renderSunbirdIdentityInsights(model);
    renderSunbirdIdentityCharts(model);
    renderSunbirdIdentitySignIns(model);
    renderSunbirdIdentityTable(model);
}

function renderSunbirdIdentityMetrics(model) {
    const metricsEl = document.getElementById('sunbird-id-metrics');
    if (!metricsEl) return;
    const metrics = [
        { key: 'total-users', label: 'Total Users', value: model.metrics.totalUsers, tone: 'neutral', evidence: 'allUsers' },
        { key: 'mfa-coverage', label: 'MFA Coverage', value: `${model.metrics.mfaCoverage}%`, tone: model.metrics.mfaCoverage >= 90 ? 'good' : model.metrics.mfaCoverage >= 70 ? 'warn' : 'bad', evidence: 'mfaMissingUsers' },
        { key: 'privileged-users', label: 'Privileged Users', value: model.metrics.privilegedUsers, tone: model.metrics.privilegedUsers > 5 ? 'warn' : 'neutral', evidence: 'privilegedUsers' },
        { key: 'high-risk-users', label: 'High Risk Users', value: model.metrics.highRiskUsers, tone: model.metrics.highRiskUsers > 0 ? 'bad' : 'good', evidence: 'highRiskUsers' }
    ];

    metricsEl.innerHTML = metrics.map(metric => `
        <article class="sunbird-id-metric-card tone-${metric.tone}">
            <div class="sunbird-id-metric-value">${escapeIdentityText(metric.value)}</div>
            <div class="sunbird-id-metric-label">${escapeIdentityText(metric.label)}</div>
            <button type="button" onclick="openSunbirdIdentityEvidence('${metric.evidence}', '${metric.key}')" class="sunbird-id-evidence-btn">View Evidence</button>
        </article>
    `).join('');
}

function renderSunbirdIdentityInsights(model) {
    const insightsEl = document.getElementById('sunbird-id-insights');
    if (!insightsEl) return;
    const insights = [
        { title: 'Admins without MFA', value: model.metrics.adminsWithoutMfa, evidence: 'adminsWithoutMfa', filter: { mfa: 'no' }, tone: 'bad' },
        { title: 'Users without MFA', value: model.metrics.mfaMissing, evidence: 'usersWithoutMfa', filter: { mfa: 'no' }, tone: 'warn' },
        { title: 'Inactive users', value: model.metrics.inactiveUsers, evidence: 'inactiveUsers', sort: 'lastSignIn', tone: 'warn' },
        { title: 'Sign-in issues', value: model.metrics.failedSignIns, evidence: 'failedSignInUsers', tone: 'bad' },
        { title: 'External users', value: model.metrics.externalUsers, evidence: 'externalUsers', filter: { type: 'external' }, tone: 'neutral' },
        { title: 'Unknown devices', value: model.metrics.unknownDevices, evidence: 'unknownDeviceUsers', tone: 'warn' },
        { title: 'Multiple privileged roles', value: model.metrics.multiplePrivilegedRoles, evidence: 'multiplePrivilegedRoles', tone: 'bad' }
    ];

    insightsEl.innerHTML = insights.map((item, index) => `
        <article class="sunbird-id-insight tone-${item.tone}" role="button" tabindex="0" data-evidence-key="${item.evidence}" onclick="toggleSunbirdInsightEvidenceLock('${item.evidence}')" onkeydown="handleSunbirdInsightEvidenceKey(event, '${item.evidence}')">
            <span>${escapeIdentityText(item.title)}</span>
            <strong>${item.value}</strong>
            ${renderSunbirdInsightEvidencePreview(item, model, index)}
        </article>
    `).join('');
}

function renderSunbirdInsightEvidencePreview(item, model, index) {
    const users = model.evidence[item.evidence] || [];
    const previewUsers = users.slice(0, 4);
    const summary = item.evidence === 'failedSignInUsers'
        ? 'Issue reason is shown for each matched sign-in.'
        : `${users.length} user${users.length === 1 ? '' : 's'} matched this evidence.`;

    return `
        <div class="sunbird-id-insight-evidence" onclick="event.stopPropagation()">
            <p>${escapeIdentityText(summary)}</p>
            <div class="sunbird-id-insight-evidence-list">
                ${previewUsers.length ? previewUsers.map(user => `
                    <div>
                        <strong>${escapeIdentityText(user.displayName || 'Unknown')}</strong>
                        <span>${escapeIdentityText(user.mail || user.userPrincipalName || 'N/A')}</span>
                        ${item.evidence === 'failedSignInUsers' ? `<small>${getSunbirdSignInIssueReasons(user).map(escapeIdentityText).join(', ') || 'Sign-in issue'}</small>` : ''}
                    </div>
                `).join('') : '<em>No evidence found.</em>'}
            </div>
            ${users.length > previewUsers.length ? `<small>${users.length - previewUsers.length} more in full evidence</small>` : ''}
            <button type="button" onclick="openSunbirdIdentityEvidence('${item.evidence}', 'insight-${index}')">Open Evidence</button>
        </div>
    `;
}

function toggleSunbirdInsightEvidenceLock(evidenceKey) {
    const tile = document.querySelector(`.sunbird-id-insight[data-evidence-key="${evidenceKey}"]`);
    if (!tile) return;
    const shouldLock = lockedSunbirdInsightEvidenceKey !== evidenceKey;
    document.querySelectorAll('.sunbird-id-insight.locked').forEach(item => item.classList.remove('locked'));
    lockedSunbirdInsightEvidenceKey = shouldLock ? evidenceKey : null;
    if (shouldLock) tile.classList.add('locked');
}

function handleSunbirdInsightEvidenceKey(event, evidenceKey) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    toggleSunbirdInsightEvidenceLock(evidenceKey);
}

function renderSunbirdIdentityCharts(model) {
    const chartsEl = document.getElementById('sunbird-id-charts');
    if (!chartsEl) return;
    chartsEl.innerHTML = `
        ${renderSunbirdPieChart('Risk distribution', [
            { label: 'Safe', value: model.metrics.safeUsers, tone: 'good' },
            { label: 'Medium', value: model.metrics.mediumRiskUsers, tone: 'warn' },
            { label: 'High', value: model.metrics.highRiskUsers, tone: 'bad' }
        ], model.metrics.totalUsers, 'sunbird-id-compact-pie-card')}
        ${renderSunbirdHealthGraph(model)}
    `;
    animateSunbirdIdentityCharts();
}

function animateSunbirdIdentityCharts() {
    const cards = document.querySelectorAll('.sunbird-id-chart-card');
    if (!cards.length) return;

    if (window.sunbirdIdentityChartObserver) {
        window.sunbirdIdentityChartObserver.disconnect();
    }

    if (!('IntersectionObserver' in window)) {
        cards.forEach(card => card.classList.add('is-visible'));
        return;
    }

    window.sunbirdIdentityChartObserver = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            entry.target.classList.toggle('is-visible', entry.isIntersecting);
        });
    }, { threshold: 0.35 });

    cards.forEach(card => window.sunbirdIdentityChartObserver.observe(card));
}

function getSunbirdToneColor(tone, alpha = 1) {
    const colors = {
        good: [52, 211, 153],
        warn: [255, 159, 28],
        bad: [239, 68, 68],
        neutral: [56, 189, 248]
    };
    const color = colors[tone] || [255, 255, 255];
    if (alpha < 1) return `rgba(${color[0]}, ${color[1]}, ${color[2]}, ${alpha})`;
    return {
        good: '#34d399',
        warn: '#ff9f1c',
        bad: '#ef4444',
        neutral: '#38bdf8'
    }[tone] || '#ffffff';
}

function renderSunbirdPieChart(title, items, total, extraClass = '') {
    const safeTotal = Math.max(1, total || items.reduce((sum, item) => sum + item.value, 0));
    let cursor = 0;
    const segments = items.map(item => {
        const start = cursor;
        const end = cursor + ((item.value / safeTotal) * 100);
        cursor = end;
        return `${getSunbirdToneColor(item.tone, 0.82)} ${start}% ${end}%`;
    }).join(', ');

    return `
        <article class="sunbird-id-chart-card sunbird-id-pie-card ${extraClass}">
            <h3>${escapeIdentityText(title)}</h3>
            <div class="sunbird-id-pie" style="background: conic-gradient(${segments || 'rgba(255,255,255,0.16) 0 100%'})">
            </div>
            <div class="sunbird-id-legend">
                ${items.map(item => `
                    <span><i style="background:${getSunbirdToneColor(item.tone, 0.78)}"></i>${escapeIdentityText(item.label)} ${item.value}</span>
                `).join('')}
            </div>
        </article>
    `;
}

function renderSunbirdHealthGraph(model) {
    const mfa = model.metrics.mfaCoverage;
    const privilegedMfa = model.metrics.privilegedUsers
        ? Math.round(((model.metrics.privilegedUsers - model.metrics.adminsWithoutMfa) / model.metrics.privilegedUsers) * 100)
        : 100;
    const activity = model.metrics.totalUsers ? Math.round(((model.metrics.totalUsers - model.metrics.inactiveUsers) / model.metrics.totalUsers) * 100) : 0;
    return `
        <article class="sunbird-id-chart-card sunbird-id-health-card sunbird-id-compact-health-card">
            <h3>Identity posture</h3>
            ${[
                { label: 'MFA', value: mfa, tone: mfa >= 80 ? 'good' : 'warn' },
                { label: 'Privileged MFA', value: privilegedMfa, tone: privilegedMfa >= 100 ? 'good' : 'bad' },
                { label: 'Active in 30 days', value: activity, tone: activity >= 70 ? 'good' : 'warn' }
            ].map(item => `
                <div class="sunbird-id-health-row">
                    <span>${item.label}</span>
                    <div class="sunbird-id-health-track"><div class="sunbird-id-health-fill tone-${item.tone}" style="width:${item.value}%"></div></div>
                    <strong>${item.value}%</strong>
                </div>
            `).join('')}
        </article>
    `;
}

function renderSunbirdBarChart(title, items, total) {
    const max = Math.max(1, total, ...items.map(item => item.value));
    return `
        <article class="sunbird-id-chart-card">
            <h3>${escapeIdentityText(title)}</h3>
            <div class="sunbird-id-bars">
                ${items.map(item => `
                    <div class="sunbird-id-bar-row">
                        <span>${escapeIdentityText(item.label)}</span>
                        <div class="sunbird-id-bar-track"><div class="sunbird-id-bar-fill tone-${item.tone}" style="width:${Math.round((item.value / max) * 100)}%"></div></div>
                        <strong>${item.value}</strong>
                    </div>
                `).join('')}
            </div>
        </article>
    `;
}

function renderSunbirdSignInTrend(users) {
    const buckets = { '0-1d': 0, '2-7d': 0, '8-30d': 0, '30d+': 0 };
    users.forEach(user => {
        const days = getIdentityDaysSinceSignIn(user);
        if (days <= 1) buckets['0-1d']++;
        else if (days <= 7) buckets['2-7d']++;
        else if (days <= 30) buckets['8-30d']++;
        else buckets['30d+']++;
    });
    return renderSunbirdBarChart('Sign-in activity', Object.entries(buckets).map(([label, value]) => ({
        label,
        value,
        tone: label === '30d+' ? 'warn' : 'neutral'
    })), users.length);
}

function renderSunbirdIdentitySignIns(model) {
    const signinsEl = document.getElementById('sunbird-id-signins');
    if (!signinsEl) return;
    const latest = [...model.users]
        .sort((a, b) => getIdentityLastSignInTime(b) - getIdentityLastSignInTime(a))
        .slice(0, 50);
    const failed = [...model.evidence.failedSignInUsers]
        .sort((a, b) => getIdentityLastSignInTime(b) - getIdentityLastSignInTime(a))
        .slice(0, 50);

    signinsEl.innerHTML = `
        ${sunbirdIdentityDashboardNotice ? `<p class="sunbird-id-stale-notice">${escapeIdentityText(sunbirdIdentityDashboardNotice)}</p>` : ''}
        ${renderSunbirdSignInList('Latest sign-ins', latest, false)}
        ${renderSunbirdSignInList('Sign-in issues', failed, true)}
    `;
}

function renderSunbirdSignInList(title, users, showIssues = false) {
    return `
        <article class="sunbird-id-signin-card">
            <h3>${escapeIdentityText(title)}</h3>
            <div class="sunbird-id-signin-list">
                ${users.length ? users.map(user => `
                    <div class="sunbird-id-signin-item">
                        <div>
                            <strong>${escapeIdentityText(user.displayName || 'Unknown')}</strong>
                            <span>${escapeIdentityText(user.mail || user.userPrincipalName || 'N/A')}</span>
                            ${showIssues ? `<div class="sunbird-id-issue-tags">${getSunbirdSignInIssueReasons(user).map(reason => `<em>${escapeIdentityText(reason)}</em>`).join('')}</div>` : ''}
                        </div>
                        <div>
                            <small>${escapeIdentityText(formatIdentityDate(user))}</small>
                            <small>${escapeIdentityText(user?.lastSignIn?.location || 'Unknown')}</small>
                        </div>
                    </div>
                `).join('') : '<div class="sunbird-id-empty compact">No matching sign-ins.</div>'}
            </div>
        </article>
    `;
}

function getFilteredSunbirdIdentityUsers(model = buildSunbirdIdentityModel()) {
    const search = sunbirdIdentityTableState.search.trim().toLowerCase();
    const riskFilter = sunbirdIdentityTableState.risk;
    const mfaFilter = sunbirdIdentityTableState.mfa;
    const typeFilter = sunbirdIdentityTableState.type;

    return model.users.filter(user => {
        const risk = String(user.riskLevel || 'SAFE').toLowerCase();
        const roles = getIdentityRoleNames(user).join(' ');
        const haystack = [
            user.displayName,
            user.mail,
            user.userPrincipalName,
            user.jobTitle,
            roles,
            risk,
            user?.lastSignIn?.location,
            user?.lastSignIn?.device
        ].join(' ').toLowerCase();

        if (search && !haystack.includes(search)) return false;
        if (riskFilter !== 'all' && risk !== riskFilter) return false;
        if (mfaFilter !== 'all' && (toBooleanMfa(user.mfaEnabled) ? 'yes' : 'no') !== mfaFilter) return false;
        if (typeFilter !== 'all' && (user.isExternal ? 'external' : 'internal') !== typeFilter) return false;
        return true;
    }).sort((a, b) => {
        if (sunbirdIdentityTableState.sort === 'lastSignIn') return getIdentityLastSignInTime(b) - getIdentityLastSignInTime(a);
        return getIdentityRiskRank(b) - getIdentityRiskRank(a);
    });
}

function renderSunbirdIdentityTable(model = buildSunbirdIdentityModel()) {
    const body = document.getElementById('sunbird-id-users-body');
    if (!body) return;
    const users = getFilteredSunbirdIdentityUsers(model);

    if (users.length === 0) {
        body.innerHTML = '<tr><td colspan="13" class="sunbird-id-empty">No users match the current filters.</td></tr>';
        return;
    }

    body.innerHTML = users.map(user => {
        const roles = getIdentityRoleNames(user);
        const risk = String(user.riskLevel || 'SAFE').toLowerCase();
        return `
            <tr>
                <td data-label="Name">${escapeIdentityText(user.displayName || 'Unknown')}</td>
                <td data-label="Email">${escapeIdentityText(user.mail || user.userPrincipalName || 'N/A')}</td>
                <td data-label="Job Title">${escapeIdentityText(user.jobTitle || 'No Title')}</td>
                <td data-label="Roles"><div class="sunbird-id-role-list">${roles.length ? roles.map(role => `<span>${escapeIdentityText(role)}</span>`).join('') : '<em>Standard</em>'}</div></td>
                <td data-label="Type"><span class="sunbird-id-pill">${user.isExternal ? 'External' : 'Internal'}</span></td>
                <td data-label="MFA"><span class="sunbird-id-pill ${toBooleanMfa(user.mfaEnabled) ? 'ok' : 'bad'}">${toBooleanMfa(user.mfaEnabled) ? 'Yes' : 'No'}</span></td>
                <td data-label="Auth Methods">${escapeIdentityText(user.authMethodCount ?? 0)}</td>
                <td data-label="Risk"><span class="sunbird-id-risk ${risk}">${escapeIdentityText(risk)}</span></td>
                <td data-label="Status">${user.accountEnabled === false ? 'Disabled' : 'Active'}</td>
                <td data-label="Last Sign-In">${escapeIdentityText(formatIdentityDate(user))}</td>
                <td data-label="Location">${escapeIdentityText(user?.lastSignIn?.location || 'Unknown')}</td>
                <td data-label="Device">${escapeIdentityText(user?.lastSignIn?.device || 'Unknown')}</td>
                <td data-label="Phone">${escapeIdentityText(user.mobilePhone || 'N/A')}</td>
            </tr>
        `;
    }).join('');
}

function applySunbirdIdentityTableFilter(filter = {}) {
    sunbirdIdentityTableState = { ...sunbirdIdentityTableState, ...filter };
    const setValue = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.value = value;
    };
    setValue('sunbird-id-risk-filter', sunbirdIdentityTableState.risk);
    setValue('sunbird-id-mfa-filter', sunbirdIdentityTableState.mfa);
    setValue('sunbird-id-type-filter', sunbirdIdentityTableState.type);
    setValue('sunbird-id-sort', sunbirdIdentityTableState.sort);
    renderSunbirdIdentityTable();
    document.querySelector('.sunbird-id-table-section')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function openSunbirdIdentityEvidence(evidenceKey) {
    const model = buildSunbirdIdentityModel();
    const users = model.evidence[evidenceKey] || [];
    const modal = document.getElementById('sunbird-id-evidence-modal');
    if (!modal) return;

    const titleMap = {
        allUsers: 'Total Users',
        mfaMissingUsers: 'MFA Coverage Evidence',
        privilegedUsers: 'Privileged Users',
        highRiskUsers: 'High Risk Users',
        adminsWithoutMfa: 'Admins Without MFA',
        usersWithoutMfa: 'Users Without MFA',
        inactiveUsers: 'Inactive Users',
        failedSignInUsers: 'Sign-in Issues',
        externalUsers: 'External Users',
        unknownDeviceUsers: 'Unknown Devices',
        multiplePrivilegedRoles: 'Multiple Privileged Roles'
    };

    const filterMap = {
        mfaMissingUsers: { mfa: 'no' },
        usersWithoutMfa: { mfa: 'no' },
        adminsWithoutMfa: { mfa: 'no' },
        highRiskUsers: { risk: 'high' },
        externalUsers: { type: 'external' },
        inactiveUsers: { sort: 'lastSignIn' }
    };

    modal.innerHTML = `
        <div class="sunbird-id-modal-backdrop" onclick="closeSunbirdIdentityEvidence()"></div>
        <div class="sunbird-id-modal-panel" role="dialog" aria-modal="true">
            <div class="sunbird-id-modal-header">
                <div>
                    <h3>${escapeIdentityText(titleMap[evidenceKey] || 'Evidence')}</h3>
                    <p>${users.length} user${users.length === 1 ? '' : 's'} matched this evidence set.</p>
                </div>
                <button type="button" onclick="closeSunbirdIdentityEvidence()" class="sunbird-id-modal-close">&times;</button>
            </div>
            <div class="sunbird-id-evidence-summary">
                ${evidenceKey === 'mfaMissingUsers' || evidenceKey === 'usersWithoutMfa' ? `
                    <span>Total users: ${model.metrics.totalUsers}</span>
                    <span>MFA enabled: ${model.metrics.mfaEnabled}</span>
                    <span>MFA missing: ${model.metrics.mfaMissing}</span>
                ` : `
                    <span>Total users: ${model.metrics.totalUsers}</span>
                    <span>Evidence count: ${users.length}</span>
                `}
            </div>
            <div class="sunbird-id-evidence-list">
                ${users.length ? users.slice(0, 80).map(user => `
                    <div class="sunbird-id-evidence-user">
                        <strong>${escapeIdentityText(user.displayName || 'Unknown')}</strong>
                        <span>${escapeIdentityText(user.mail || user.userPrincipalName || 'N/A')}</span>
                        <small>${escapeIdentityText(getIdentityRoleNames(user).join(', ') || user.riskLevel || 'SAFE')}</small>
                    </div>
                `).join('') : '<div class="sunbird-id-empty">No evidence found for this item.</div>'}
            </div>
            <div class="sunbird-id-modal-actions">
                <button type="button" class="sunbird-id-evidence-btn" onclick='applySunbirdIdentityTableFilter(${JSON.stringify(filterMap[evidenceKey] || {})}); closeSunbirdIdentityEvidence();'>View in Table</button>
            </div>
        </div>
    `;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
}

function closeSunbirdIdentityEvidence() {
    const modal = document.getElementById('sunbird-id-evidence-modal');
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
}

window.openSunbirdIdentityEvidence = openSunbirdIdentityEvidence;
window.closeSunbirdIdentityEvidence = closeSunbirdIdentityEvidence;
window.applySunbirdIdentityTableFilter = applySunbirdIdentityTableFilter;
window.toggleSunbirdInsightEvidenceLock = toggleSunbirdInsightEvidenceLock;
window.handleSunbirdInsightEvidenceKey = handleSunbirdInsightEvidenceKey;

const SUNBIRD_DEVICES_CACHE_KEY = 'sunbirdDevicesDashboardSnapshot';
let sunbirdDevicesDashboardData = null;
let sunbirdDevicesTableState = {
    search: '',
    risk: 'all',
    compliance: 'all',
    encryption: 'all',
    sort: 'risk'
};
let lockedSunbirdDeviceInsightEvidenceKey = null;

function openSunbirdDevicesDashboard() {
    const dashboardView = document.getElementById('dashboard-view');
    const projectsView = document.getElementById('projects-view');
    if (!dashboardView) return;

    if (projectsView) projectsView.style.display = 'none';
    dashboardView.style.display = 'block';
    dashboardView.style.visibility = 'visible';
    dashboardView.style.opacity = '1';
    dashboardView.classList.remove('sunbird-identity-active');
    dashboardView.classList.remove('sunbird-email-active');
    dashboardView.classList.remove('sunbird-security-active');
    dashboardView.classList.remove('sunbird-backup-active');
    dashboardView.classList.remove('sunbird-applications-active');
    dashboardView.classList.add('sunbird-device-active');

    captureDashboardViewHTML();
    dashboardView.innerHTML = renderSunbirdDevicesShell();
    setupSunbirdDevicesDashboard();

    const cached = readSunbirdDevicesSnapshot();
    if (cached) {
        sunbirdDevicesDashboardData = normalizeSunbirdDevicesData(cached);
        renderSunbirdDevicesDashboard();
    } else if (latestDevicesCardData) {
        sunbirdDevicesDashboardData = normalizeSunbirdDevicesData(latestDevicesCardData);
        renderSunbirdDevicesDashboard();
    } else {
        sunbirdDevicesDashboardData = normalizeSunbirdDevicesData({ success: true, devices: [] });
        renderSunbirdDevicesDashboard();
    }

    loadSunbirdDevicesDashboardData();
}

function renderSunbirdDevicesShell() {
    return `
        <section class="sunbird-identity-dashboard sunbird-devices-dashboard" id="sunbird-devices-dashboard">
            <div class="sunbird-id-header">
                <button id="sunbird-devices-back" class="sunbird-id-back-btn" type="button">
                    <span class="sunbird-id-back-icon" aria-hidden="true">&larr;</span>
                    <span>Back</span>
                </button>
                <div>
                    <h2>Device Protection</h2>
                    <p>Devices, compliance, encryption, activity, and security evidence.</p>
                </div>
                <div class="sunbird-id-microsoft-badge sunbird-security-provider-badge" aria-label="Microsoft security evidence">
                    <span class="sunbird-id-ms-logo" aria-hidden="true"><i></i><i></i><i></i><i></i></span>
                    <span>Microsoft</span>
                </div>
            </div>

            <div class="sunbird-id-metrics" id="sunbird-devices-metrics"></div>
            <div class="sunbird-id-insights" id="sunbird-devices-insights"></div>
            <div class="sunbird-id-charts" id="sunbird-devices-charts"></div>
            <div class="sunbird-id-signins" id="sunbird-devices-panels"></div>

            <section class="sunbird-id-table-section">
                <div class="sunbird-id-table-toolbar sunbird-devices-table-toolbar">
                    <input id="sunbird-devices-search" class="sunbird-id-search" type="search" placeholder="Search device, user, OS, compliance, serial, management">
                    <select id="sunbird-devices-risk-filter" class="sunbird-id-select">
                        <option value="all">All risks</option>
                        <option value="safe">Safe</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                    </select>
                    <select id="sunbird-devices-compliance-filter" class="sunbird-id-select">
                        <option value="all">All compliance</option>
                        <option value="compliant">Compliant</option>
                        <option value="noncompliant">Non-compliant</option>
                        <option value="unknown">Unknown</option>
                    </select>
                    <select id="sunbird-devices-encryption-filter" class="sunbird-id-select">
                        <option value="all">All encryption</option>
                        <option value="yes">Encrypted</option>
                        <option value="no">Not encrypted</option>
                    </select>
                    <select id="sunbird-devices-sort" class="sunbird-id-select">
                        <option value="risk">Sort risk</option>
                        <option value="lastSync">Sort last sync</option>
                        <option value="name">Sort name</option>
                    </select>
                    <button id="sunbird-devices-clear" class="sunbird-id-clear-btn" type="button">Clear</button>
                </div>

                <div class="sunbird-id-table-wrap">
                    <table class="sunbird-id-table sunbird-devices-table">
                        <thead>
                            <tr>
                                <th>Device</th>
                                <th>User</th>
                                <th>OS</th>
                                <th>Version</th>
                                <th>Compliance</th>
                                <th>Encryption</th>
                                <th>Management</th>
                                <th>Last Sync</th>
                                <th>Registration</th>
                                <th>Enrollment</th>
                                <th>Serial</th>
                                <th>Risk</th>
                                <th>Issues</th>
                            </tr>
                        </thead>
                        <tbody id="sunbird-devices-body"></tbody>
                    </table>
                </div>
            </section>
        </section>
        <div id="sunbird-device-evidence-modal" class="sunbird-id-modal" aria-hidden="true"></div>
    `;
}

function setupSunbirdDevicesDashboard() {
    document.getElementById('sunbird-devices-back')?.addEventListener('click', goBackToProjects);
    document.getElementById('sunbird-devices-search')?.addEventListener('input', event => {
        sunbirdDevicesTableState.search = event.target.value;
        renderSunbirdDevicesTable();
    });
    document.getElementById('sunbird-devices-risk-filter')?.addEventListener('change', event => {
        sunbirdDevicesTableState.risk = event.target.value;
        renderSunbirdDevicesTable();
    });
    document.getElementById('sunbird-devices-compliance-filter')?.addEventListener('change', event => {
        sunbirdDevicesTableState.compliance = event.target.value;
        renderSunbirdDevicesTable();
    });
    document.getElementById('sunbird-devices-encryption-filter')?.addEventListener('change', event => {
        sunbirdDevicesTableState.encryption = event.target.value;
        renderSunbirdDevicesTable();
    });
    document.getElementById('sunbird-devices-sort')?.addEventListener('change', event => {
        sunbirdDevicesTableState.sort = event.target.value;
        renderSunbirdDevicesTable();
    });
    document.getElementById('sunbird-devices-clear')?.addEventListener('click', () => {
        sunbirdDevicesTableState = { search: '', risk: 'all', compliance: 'all', encryption: 'all', sort: 'risk' };
        ['sunbird-devices-search', 'sunbird-devices-risk-filter', 'sunbird-devices-compliance-filter', 'sunbird-devices-encryption-filter', 'sunbird-devices-sort'].forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.value = id === 'sunbird-devices-sort' ? 'risk' : 'all';
            if (id === 'sunbird-devices-search') el.value = '';
        });
        renderSunbirdDevicesTable();
    });
}

function readSunbirdDevicesSnapshot() {
    try {
        const parsed = JSON.parse(localStorage.getItem(SUNBIRD_DEVICES_CACHE_KEY) || 'null');
        return parsed?.summary || parsed?.devices ? parsed : null;
    } catch (error) {
        return null;
    }
}

function saveSunbirdDevicesSnapshot(data) {
    if (!data?.summary && !data?.devices) return;
    localStorage.setItem(SUNBIRD_DEVICES_CACHE_KEY, JSON.stringify({
        ...data,
        savedAt: new Date().toISOString()
    }));
}

function getSunbirdMetricNumber(metrics, keys, fallback = 0) {
    for (const key of keys) {
        const value = metrics?.[key];
        if (value !== undefined && value !== null && value !== '') return Number(value) || 0;
    }
    return fallback;
}

function normalizeSunbirdDevicesData(data = {}) {
    const devices = Array.isArray(data.devices) ? data.devices : [];
    const hasDeviceEvidence = devices.length > 0;
    const metrics = data.metrics || {};
    const summary = data.summary || {};
    const totalDevices = hasDeviceEvidence ? devices.length : summary.totalDevices ?? getSunbirdMetricNumber(metrics, ['TotalDevices', 'totalDevices'], 0);
    const nonCompliantDevices = hasDeviceEvidence
        ? devices.filter(d => normalizeSunbirdDeviceCompliance(d) === 'noncompliant').length
        : summary.nonCompliantDevices ?? summary.nonCompliant ?? getSunbirdMetricNumber(metrics, ['NonCompliant', 'nonCompliant'], 0);
    const notEncryptedDevices = hasDeviceEvidence
        ? devices.filter(d => !d.isEncrypted).length
        : summary.notEncryptedDevices ?? getSunbirdMetricNumber(metrics, ['NotEncrypted', 'notEncrypted'], 0);
    const staleDeviceEvidenceCount = devices.filter(d => getSunbirdDeviceDaysSinceSync(d) > 7 && getSunbirdDeviceDaysSinceSync(d) <= 30).length;
    const deadDeviceEvidenceCount = devices.filter(d => getSunbirdDeviceDaysSinceSync(d) > 30).length;
    const staleDevices = hasDeviceEvidence
        ? staleDeviceEvidenceCount
        : summary.staleDevices ?? getSunbirdMetricNumber(metrics, ['StaleDevices', 'staleDevices'], 0);
    const compliantDevices = hasDeviceEvidence
        ? devices.filter(d => normalizeSunbirdDeviceCompliance(d) === 'compliant').length
        : summary.compliantDevices ?? Math.max(0, totalDevices - nonCompliantDevices);
    const encryptedDevices = hasDeviceEvidence
        ? devices.filter(d => d.isEncrypted).length
        : summary.encryptedDevices ?? Math.max(0, totalDevices - notEncryptedDevices);
    const activityBreakdown = { ...(data.activityBreakdown || summary.activityBreakdown || {
        active24h: devices.filter(d => getSunbirdDeviceDaysSinceSync(d) <= 1).length,
        stale7days: staleDeviceEvidenceCount,
        dead30days: deadDeviceEvidenceCount
    }) };
    if (hasDeviceEvidence) {
        activityBreakdown.active24h = devices.filter(d => getSunbirdDeviceDaysSinceSync(d) <= 1).length;
        activityBreakdown.stale7days = staleDeviceEvidenceCount;
        activityBreakdown.dead30days = deadDeviceEvidenceCount;
    }

    return {
        ...data,
        devices,
        alerts: Array.isArray(data.alerts) ? data.alerts : [],
        policies: Array.isArray(data.policies) ? data.policies : [],
        compliance: data.compliance || {
            compliant: compliantDevices,
            nonCompliant: nonCompliantDevices,
            unknown: devices.filter(d => normalizeSunbirdDeviceCompliance(d) === 'unknown').length
        },
        osDistribution: data.osDistribution || buildSunbirdDeviceOsDistribution(devices),
        managementStatus: data.managementStatus || buildSunbirdDeviceManagementStatus(devices),
        activityBreakdown,
        summary: {
            ...summary,
            totalDevices,
            nonCompliantDevices,
            notEncryptedDevices,
            compliantDevices,
            encryptedDevices,
            staleDevices,
            highRiskDevices: hasDeviceEvidence ? devices.filter(d => getSunbirdDeviceRiskLevel(d) === 'high').length : summary.highRiskDevices ?? 0,
            compliancePercentage: summary.compliancePercentage ?? (totalDevices ? Math.round((compliantDevices / totalDevices) * 100) : 0),
            encryptionPercentage: summary.encryptionPercentage ?? (totalDevices ? Math.round((encryptedDevices / totalDevices) * 100) : 0),
            deviceSecurityScore: summary.deviceSecurityScore ?? calculateSunbirdDeviceSecurityScore(totalDevices, compliantDevices, encryptedDevices, activityBreakdown.active24h)
        }
    };
}

async function loadSunbirdDevicesDashboardData() {
    const token = localStorage.getItem('authToken');
    if (!token) return;

    try {
        const metricsResponse = await fetch('/api/db/device-metrics', {
            method: 'GET',
            cache: 'no-store',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        const metricsData = await metricsResponse.json();
        if (metricsResponse.ok && metricsData.success) {
            sunbirdDevicesDashboardData = normalizeSunbirdDevicesData({ ...(sunbirdDevicesDashboardData || {}), metrics: metricsData.metrics });
            latestDevicesCardData = metricsData;
            renderSunbirdDevicesDashboard();
        }
    } catch (error) {
        console.warn('[Device Dashboard] Cached metrics unavailable:', error.message);
    }

    try {
        const detailResponse = await fetch('/api/microsoft-devices', {
            method: 'GET',
            cache: 'no-store',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        const detailData = await detailResponse.json();
        if (!detailResponse.ok || !detailData.success) throw new Error(detailData.message || 'Device details unavailable');
        sunbirdDevicesDashboardData = normalizeSunbirdDevicesData(detailData);
        saveSunbirdDevicesSnapshot(sunbirdDevicesDashboardData);
        renderSunbirdDevicesDashboard();
    } catch (error) {
        console.warn('[Device Dashboard] Detailed evidence unavailable:', error.message);
    }
}

function buildSunbirdDevicesModel(data = sunbirdDevicesDashboardData) {
    const normalized = normalizeSunbirdDevicesData(data || {});
    const devices = normalized.devices;
    const nonCompliantDevices = devices.filter(d => normalizeSunbirdDeviceCompliance(d) === 'noncompliant');
    const notEncryptedDevices = devices.filter(d => !d.isEncrypted);
    const staleDevices = devices.filter(d => getSunbirdDeviceDaysSinceSync(d) > 7 && getSunbirdDeviceDaysSinceSync(d) <= 30);
    const deadDevices = devices.filter(d => getSunbirdDeviceDaysSinceSync(d) > 30);
    const highRiskDevices = devices.filter(d => getSunbirdDeviceRiskLevel(d) === 'high');
    const mediumRiskDevices = devices.filter(d => getSunbirdDeviceRiskLevel(d) === 'medium');
    const safeDevices = devices.filter(d => getSunbirdDeviceRiskLevel(d) === 'safe');
    const unmanagedDevices = devices.filter(d => !String(d.managementAgent || '').trim() || /unknown|none/i.test(String(d.managementAgent || '')));
    const aadRegisteredDevices = devices.filter(d => d.azureADRegistered);

    return {
        ...normalized,
        evidence: {
            allDevices: devices,
            compliantDevices: devices.filter(d => normalizeSunbirdDeviceCompliance(d) === 'compliant'),
            nonCompliantDevices,
            notEncryptedDevices,
            staleDevices,
            stale7daysDevices: staleDevices,
            deadDevices,
            highRiskDevices,
            mediumRiskDevices,
            safeDevices,
            active24hDevices: devices.filter(d => getSunbirdDeviceDaysSinceSync(d) <= 1),
            unmanagedDevices,
            aadRegisteredDevices,
            securityAlerts: normalized.alerts,
            policies: normalized.policies
        }
    };
}

function renderSunbirdDevicesDashboard() {
    const model = buildSunbirdDevicesModel();
    renderSunbirdDevicesMetrics(model);
    renderSunbirdDevicesInsights(model);
    renderSunbirdDevicesCharts(model);
    renderSunbirdDevicesPanels(model);
    renderSunbirdDevicesTable(model);
}

function renderSunbirdDevicesMetrics(model) {
    const el = document.getElementById('sunbird-devices-metrics');
    if (!el) return;
    const summary = model.summary;
    const metrics = [
        { key: 'total-devices', label: 'Total Devices', value: summary.totalDevices, tone: 'neutral', evidence: 'allDevices' },
        { key: 'compliant-devices', label: 'Compliant', value: `${summary.compliancePercentage}%`, tone: summary.compliancePercentage >= 85 ? 'good' : summary.compliancePercentage >= 65 ? 'warn' : 'bad', evidence: 'nonCompliantDevices' },
        { key: 'encrypted-devices', label: 'Encrypted', value: `${summary.encryptionPercentage}%`, tone: summary.encryptionPercentage >= 90 ? 'good' : summary.encryptionPercentage >= 70 ? 'warn' : 'bad', evidence: 'notEncryptedDevices' },
        { key: 'active-devices', label: 'Active (24h)', value: model.activityBreakdown.active24h || 0, tone: 'neutral', evidence: 'active24hDevices' }
    ];

    el.innerHTML = metrics.map(metric => `
        <article class="sunbird-id-metric-card tone-${metric.tone}">
            <div class="sunbird-id-metric-value">${escapeIdentityText(metric.value)}</div>
            <div class="sunbird-id-metric-label">${escapeIdentityText(metric.label)}</div>
            <button type="button" onclick="openSunbirdDeviceEvidence('${metric.evidence}')" class="sunbird-id-evidence-btn">View Evidence</button>
        </article>
    `).join('');
}

function renderSunbirdDevicesInsights(model) {
    const el = document.getElementById('sunbird-devices-insights');
    if (!el) return;
    const insights = [
        { title: 'High risk devices', value: model.evidence.highRiskDevices.length || model.summary.highRiskDevices || 0, evidence: 'highRiskDevices', tone: 'bad', filter: { risk: 'high' } },
        { title: 'Non-compliant', value: model.evidence.nonCompliantDevices.length || Math.max(0, model.summary.totalDevices - model.summary.compliantDevices), evidence: 'nonCompliantDevices', tone: 'bad', filter: { compliance: 'noncompliant' } },
        { title: 'Not encrypted', value: model.evidence.notEncryptedDevices.length || Math.max(0, model.summary.totalDevices - model.summary.encryptedDevices), evidence: 'notEncryptedDevices', tone: 'warn', filter: { encryption: 'no' } },
        { title: 'Stale devices', value: model.evidence.staleDevices.length || model.summary.staleDevices || 0, evidence: 'staleDevices', tone: 'warn', sort: 'lastSync' },
        { title: 'Dead 30+ days', value: model.evidence.deadDevices.length || model.activityBreakdown.dead30days || 0, evidence: 'deadDevices', tone: 'bad', sort: 'lastSync' },
        { title: 'Unmanaged', value: model.evidence.unmanagedDevices.length, evidence: 'unmanagedDevices', tone: 'warn' },
        { title: 'Security alerts', value: model.alerts.length, evidence: 'securityAlerts', tone: model.alerts.length ? 'bad' : 'good' }
    ];

    el.innerHTML = insights.map((item, index) => `
        <article class="sunbird-id-insight tone-${item.tone}" role="button" tabindex="0" data-device-evidence-key="${item.evidence}" onclick="toggleSunbirdDeviceInsightEvidenceLock('${item.evidence}')" onkeydown="handleSunbirdDeviceInsightEvidenceKey(event, '${item.evidence}')">
            <span>${escapeIdentityText(item.title)}</span>
            <strong>${escapeIdentityText(item.value)}</strong>
            ${renderSunbirdDeviceInsightEvidencePreview(item, model, index)}
        </article>
    `).join('');
}

function renderSunbirdDeviceInsightEvidencePreview(item, model, index) {
    const rows = getSunbirdDeviceEvidenceRows(item.evidence, model);
    const previewRows = rows.slice(0, 4);
    return `
        <div class="sunbird-id-insight-evidence" onclick="event.stopPropagation()">
            <p>${rows.length} evidence item${rows.length === 1 ? '' : 's'} matched this signal.</p>
            <div class="sunbird-id-insight-evidence-list">
                ${previewRows.length ? previewRows.map(row => `
                    <div>
                        <strong>${escapeIdentityText(row.title)}</strong>
                        <span>${escapeIdentityText(row.subtitle)}</span>
                        <small>${escapeIdentityText(row.meta)}</small>
                    </div>
                `).join('') : '<em>No evidence found.</em>'}
            </div>
            ${rows.length > previewRows.length ? `<small>${rows.length - previewRows.length} more in full evidence</small>` : ''}
            <button type="button" onclick="openSunbirdDeviceEvidence('${item.evidence}', 'insight-${index}')">Open Evidence</button>
        </div>
    `;
}

function renderSunbirdDevicesCharts(model) {
    const el = document.getElementById('sunbird-devices-charts');
    if (!el) return;
    const total = model.summary.totalDevices || model.devices.length || 0;
    const osItems = Object.entries(model.osDistribution || {}).slice(0, 5).map(([label, value], index) => ({
        label,
        value,
        tone: index === 0 ? 'neutral' : index === 1 ? 'good' : index === 2 ? 'warn' : 'bad'
    }));

    el.innerHTML = `
        ${renderSunbirdPieChart('Compliance breakdown', [
            { label: 'Compliant', value: model.compliance.compliant || 0, tone: 'good' },
            { label: 'Non-compliant', value: model.compliance.nonCompliant || 0, tone: 'bad' },
            { label: 'Unknown', value: model.compliance.unknown || 0, tone: 'warn' }
        ], total)}
        ${renderSunbirdPieChart('Encryption coverage', [
            { label: 'Encrypted', value: model.summary.encryptedDevices || 0, tone: 'good' },
            { label: 'Missing', value: Math.max(0, total - (model.summary.encryptedDevices || 0)), tone: 'bad' }
        ], total)}
        ${renderSunbirdPieChart('Management status', [
            { label: 'Managed', value: model.managementStatus.managed || 0, tone: 'good' },
            { label: 'Unmanaged', value: model.managementStatus.unmanaged || 0, tone: 'bad' },
            { label: 'AAD registered', value: model.managementStatus.aadRegistered || 0, tone: 'neutral' }
        ], total)}
        ${renderSunbirdDeviceBars('OS distribution', osItems, Math.max(1, ...osItems.map(item => item.value), total))}
    `;
    animateSunbirdIdentityCharts();
}

function renderSunbirdDeviceBars(title, items, total, emptyText = 'No OS data available.') {
    return `
        <article class="sunbird-id-chart-card">
            <h3>${escapeIdentityText(title)}</h3>
            <div class="sunbird-id-bars">
                ${items.length ? items.map(item => `
                    <div class="sunbird-id-bar-row sunbird-device-bar-row">
                        <span>${escapeIdentityText(item.label)}</span>
                        <div class="sunbird-id-bar-track"><div class="sunbird-id-bar-fill tone-${item.tone}" style="width:${Math.max(4, Math.round((item.value / Math.max(1, total)) * 100))}%"></div></div>
                        <strong>${escapeIdentityText(item.value)}</strong>
                    </div>
                `).join('') : `<div class="sunbird-id-empty compact">${escapeIdentityText(emptyText)}</div>`}
            </div>
        </article>
    `;
}

function renderSunbirdDevicesPanels(model) {
    const el = document.getElementById('sunbird-devices-panels');
    if (!el) return;
    el.innerHTML = `
        ${renderSunbirdDeviceListPanel('High risk devices', getSunbirdDeviceEvidenceRows('highRiskDevices', model).slice(0, 10))}
        ${renderSunbirdDeviceAlertPanel('Security alerts feed', model.alerts.slice(0, 10))}
        ${renderSunbirdDeviceActivityPanel(model)}
        ${renderSunbirdDevicePolicyPanel(model)}
    `;
}

function renderSunbirdDeviceListPanel(title, rows) {
    return `
        <article class="sunbird-id-signin-card">
            <h3>${escapeIdentityText(title)}</h3>
            <div class="sunbird-id-signin-list">
                ${rows.length ? rows.map(row => `
                    <div class="sunbird-id-signin-item">
                        <div>
                            <strong>${escapeIdentityText(row.title)}</strong>
                            <span>${escapeIdentityText(row.subtitle)}</span>
                            <div class="sunbird-id-issue-tags"><em>${escapeIdentityText(row.meta)}</em></div>
                        </div>
                    </div>
                `).join('') : '<div class="sunbird-id-empty compact">No matching device evidence.</div>'}
            </div>
        </article>
    `;
}

function renderSunbirdDeviceAlertPanel(title, alerts) {
    return `
        <article class="sunbird-id-signin-card">
            <h3>${escapeIdentityText(title)}</h3>
            <div class="sunbird-id-signin-list">
                ${alerts.length ? alerts.map(alert => `
                    <div class="sunbird-id-signin-item">
                        <div>
                            <strong>${escapeIdentityText(alert.title || 'Security alert')}</strong>
                            <span>${escapeIdentityText(alert.vendorInformation || alert.status || 'Microsoft security')}</span>
                            <div class="sunbird-id-issue-tags"><em>${escapeIdentityText(alert.severity || 'medium')}</em></div>
                        </div>
                        <div>
                            <small>${escapeIdentityText(formatSunbirdDeviceDate(alert.createdDateTime || alert.eventDateTime))}</small>
                        </div>
                    </div>
                `).join('') : '<div class="sunbird-id-empty compact">No active security alerts.</div>'}
            </div>
        </article>
    `;
}

function renderSunbirdDeviceActivityPanel(model) {
    const activity = model.activityBreakdown || {};
    const rows = [
        { title: 'Active (24h)', value: model.evidence.active24hDevices.length || activity.active24h || 0, tone: 'good', evidence: 'active24hDevices' },
        { title: 'Stale (7+ days)', value: model.evidence.stale7daysDevices.length || activity.stale7days || 0, tone: 'warn', evidence: 'stale7daysDevices' },
        { title: 'Dead (30+ days)', value: model.evidence.deadDevices.length || activity.dead30days || 0, tone: 'bad', evidence: 'deadDevices' },
        { title: 'Security score', value: `${model.summary.deviceSecurityScore || 0}%`, tone: model.summary.deviceSecurityScore >= 80 ? 'good' : model.summary.deviceSecurityScore >= 60 ? 'warn' : 'bad', evidence: 'allDevices' }
    ];
    return `
        <article class="sunbird-id-signin-card">
            <h3>Device activity timeline</h3>
            <div class="sunbird-device-mini-grid">
                ${rows.map(row => `
                    <article class="sunbird-device-mini-stat tone-${row.tone}" role="button" tabindex="0" onclick="openSunbirdDeviceEvidence('${row.evidence}')" onkeydown="if(event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openSunbirdDeviceEvidence('${row.evidence}'); }">
                        <span>${escapeIdentityText(row.title)}</span>
                        <strong>${escapeIdentityText(row.value)}</strong>
                        ${renderSunbirdDeviceMiniStatEvidence(row, model)}
                    </article>
                `).join('')}
            </div>
        </article>
    `;
}

function renderSunbirdDeviceMiniStatEvidence(row, model) {
    const rows = getSunbirdDeviceEvidenceRows(row.evidence, model);
    const previewRows = rows.slice(0, 3);
    return `
        <div class="sunbird-device-mini-evidence" onclick="event.stopPropagation()">
            <p>${rows.length} evidence item${rows.length === 1 ? '' : 's'} matched this timeline signal.</p>
            <div class="sunbird-id-insight-evidence-list">
                ${previewRows.length ? previewRows.map(item => `
                    <div>
                        <strong>${escapeIdentityText(item.title)}</strong>
                        <span>${escapeIdentityText(item.subtitle)}</span>
                        <small>${escapeIdentityText(item.meta)}</small>
                    </div>
                `).join('') : '<em>No evidence found.</em>'}
            </div>
            ${rows.length > previewRows.length ? `<small>${rows.length - previewRows.length} more in full evidence</small>` : ''}
            <small>Click tile to open full evidence.</small>
        </div>
    `;
}

function renderSunbirdDevicePolicyPanel(model) {
    const policies = model.policies || [];
    const coverage = model.summary.totalDevices ? model.summary.compliancePercentage : 0;
    return `
        <article class="sunbird-id-signin-card">
            <h3>Policy coverage</h3>
            <div class="sunbird-device-policy-summary">
                <div>
                    <span>Coverage</span>
                    <strong>${coverage}%</strong>
                </div>
                <div>
                    <span>Policies</span>
                    <strong>${policies.length}</strong>
                </div>
            </div>
            <div class="sunbird-id-signin-list sunbird-device-policy-list">
                ${policies.length ? policies.slice(0, 6).map(policy => `
                    <div class="sunbird-id-signin-item">
                        <div>
                            <strong>${escapeIdentityText(policy.displayName || policy.name || policy.id || 'Compliance policy')}</strong>
                            <span>${escapeIdentityText(policy.description || policy.platforms || 'Policy evidence')}</span>
                        </div>
                    </div>
                `).join('') : '<div class="sunbird-id-empty compact">No policy evidence available.</div>'}
            </div>
            <button type="button" class="sunbird-id-evidence-btn sunbird-device-policy-btn" onclick="openSunbirdDeviceEvidence('policies')">View Evidence</button>
        </article>
    `;
}

function renderSunbirdDevicesTable(model = buildSunbirdDevicesModel()) {
    const body = document.getElementById('sunbird-devices-body');
    if (!body) return;
    const devices = getFilteredSunbirdDevices(model);
    if (!devices.length) {
        body.innerHTML = '<tr><td colspan="13" class="sunbird-id-empty">No devices match the current filters.</td></tr>';
        return;
    }

    body.innerHTML = devices.map(device => {
        const risk = getSunbirdDeviceRiskLevel(device);
        const issues = getSunbirdDeviceIssueReasons(device);
        return `
            <tr>
                <td data-label="Device">${escapeIdentityText(device.deviceName || 'Unknown')}</td>
                <td data-label="User">${escapeIdentityText(device.userPrincipalName || 'N/A')}</td>
                <td data-label="OS">${escapeIdentityText(device.operatingSystem || 'Unknown')}</td>
                <td data-label="Version">${escapeIdentityText(device.osVersion || 'N/A')}</td>
                <td data-label="Compliance"><span class="sunbird-id-pill ${normalizeSunbirdDeviceCompliance(device) === 'compliant' ? 'ok' : 'bad'}">${escapeIdentityText(normalizeSunbirdDeviceCompliance(device))}</span></td>
                <td data-label="Encryption"><span class="sunbird-id-pill ${device.isEncrypted ? 'ok' : 'bad'}">${device.isEncrypted ? 'Encrypted' : 'Not encrypted'}</span></td>
                <td data-label="Management">${escapeIdentityText(device.managementAgent || 'Unknown')}</td>
                <td data-label="Last Sync">${escapeIdentityText(formatSunbirdDeviceDate(device.lastSyncDateTime))}</td>
                <td data-label="Registration"><span class="sunbird-id-pill ${device.azureADRegistered ? 'ok' : ''}">${device.azureADRegistered ? 'AAD registered' : 'Not registered'}</span></td>
                <td data-label="Enrollment">${escapeIdentityText(device.deviceEnrollmentType || 'Unknown')}</td>
                <td data-label="Serial">${escapeIdentityText(device.serialNumber || 'N/A')}</td>
                <td data-label="Risk"><span class="sunbird-id-risk ${risk}">${escapeIdentityText(risk)}</span></td>
                <td data-label="Issues"><div class="sunbird-id-role-list">${issues.length ? issues.map(issue => `<span>${escapeIdentityText(issue)}</span>`).join('') : '<em>None</em>'}</div></td>
            </tr>
        `;
    }).join('');
}

function getFilteredSunbirdDevices(model = buildSunbirdDevicesModel()) {
    const search = sunbirdDevicesTableState.search.trim().toLowerCase();
    return model.devices.filter(device => {
        const risk = getSunbirdDeviceRiskLevel(device);
        const compliance = normalizeSunbirdDeviceCompliance(device);
        const haystack = [
            device.deviceName,
            device.userPrincipalName,
            device.operatingSystem,
            device.osVersion,
            compliance,
            device.managementAgent,
            device.serialNumber,
            device.deviceEnrollmentType,
            getSunbirdDeviceIssueReasons(device).join(' ')
        ].join(' ').toLowerCase();

        if (search && !haystack.includes(search)) return false;
        if (sunbirdDevicesTableState.risk !== 'all' && risk !== sunbirdDevicesTableState.risk) return false;
        if (sunbirdDevicesTableState.compliance !== 'all' && compliance !== sunbirdDevicesTableState.compliance) return false;
        if (sunbirdDevicesTableState.encryption !== 'all' && (device.isEncrypted ? 'yes' : 'no') !== sunbirdDevicesTableState.encryption) return false;
        return true;
    }).sort((a, b) => {
        if (sunbirdDevicesTableState.sort === 'lastSync') return getSunbirdDeviceLastSyncTime(b) - getSunbirdDeviceLastSyncTime(a);
        if (sunbirdDevicesTableState.sort === 'name') return String(a.deviceName || '').localeCompare(String(b.deviceName || ''));
        return getSunbirdDeviceRiskRank(b) - getSunbirdDeviceRiskRank(a);
    });
}

function applySunbirdDeviceTableFilter(filter = {}) {
    sunbirdDevicesTableState = { ...sunbirdDevicesTableState, ...filter };
    const setValue = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.value = value;
    };
    setValue('sunbird-devices-risk-filter', sunbirdDevicesTableState.risk);
    setValue('sunbird-devices-compliance-filter', sunbirdDevicesTableState.compliance);
    setValue('sunbird-devices-encryption-filter', sunbirdDevicesTableState.encryption);
    setValue('sunbird-devices-sort', sunbirdDevicesTableState.sort);
    renderSunbirdDevicesTable();
    document.querySelector('.sunbird-devices-dashboard .sunbird-id-table-section')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function openSunbirdDeviceEvidence(evidenceKey) {
    const model = buildSunbirdDevicesModel();
    const rows = getSunbirdDeviceEvidenceRows(evidenceKey, model);
    const modal = document.getElementById('sunbird-device-evidence-modal');
    if (!modal) return;
    const titleMap = {
        allDevices: 'Total Devices',
        compliantDevices: 'Compliant Devices',
        nonCompliantDevices: 'Non-compliant Devices',
        notEncryptedDevices: 'Devices Without Encryption',
        staleDevices: 'Stale Devices',
        stale7daysDevices: 'Stale 7+ Day Devices',
        deadDevices: 'Dead 30+ Day Devices',
        highRiskDevices: 'High Risk Devices',
        active24hDevices: 'Active Devices',
        unmanagedDevices: 'Unmanaged Devices',
        aadRegisteredDevices: 'Azure AD Registered Devices',
        securityAlerts: 'Security Alerts',
        policies: 'Compliance Policies'
    };
    const filterMap = {
        nonCompliantDevices: { compliance: 'noncompliant' },
        notEncryptedDevices: { encryption: 'no' },
        highRiskDevices: { risk: 'high' },
        staleDevices: { sort: 'lastSync' },
        stale7daysDevices: { sort: 'lastSync' },
        deadDevices: { sort: 'lastSync' }
    };

    modal.innerHTML = `
        <div class="sunbird-id-modal-backdrop" onclick="closeSunbirdDeviceEvidence()"></div>
        <div class="sunbird-id-modal-panel" role="dialog" aria-modal="true">
            <div class="sunbird-id-modal-header">
                <div>
                    <h3>${escapeIdentityText(titleMap[evidenceKey] || 'Device Evidence')}</h3>
                    <p>${rows.length} evidence item${rows.length === 1 ? '' : 's'} matched this set.</p>
                </div>
                <button type="button" onclick="closeSunbirdDeviceEvidence()" class="sunbird-id-modal-close">&times;</button>
            </div>
            <div class="sunbird-id-evidence-summary">
                <span>Total devices: ${model.summary.totalDevices || 0}</span>
                <span>Evidence count: ${rows.length}</span>
                <span>Security score: ${model.summary.deviceSecurityScore || 0}</span>
            </div>
            <div class="sunbird-id-evidence-list">
                ${rows.length ? rows.slice(0, 100).map(row => `
                    <div class="sunbird-id-evidence-user">
                        <strong>${escapeIdentityText(row.title)}</strong>
                        <span>${escapeIdentityText(row.subtitle)}</span>
                        <small>${escapeIdentityText(row.meta)}</small>
                    </div>
                `).join('') : '<div class="sunbird-id-empty">No evidence found for this item.</div>'}
            </div>
            <div class="sunbird-id-modal-actions">
                <button type="button" class="sunbird-id-evidence-btn" onclick='applySunbirdDeviceTableFilter(${JSON.stringify(filterMap[evidenceKey] || {})}); closeSunbirdDeviceEvidence();'>View in Table</button>
            </div>
        </div>
    `;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
}

function closeSunbirdDeviceEvidence() {
    const modal = document.getElementById('sunbird-device-evidence-modal');
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
}

function getSunbirdDeviceEvidenceRows(evidenceKey, model = buildSunbirdDevicesModel()) {
    if (evidenceKey === 'securityAlerts') {
        return (model.alerts || []).map(alert => ({
            title: alert.title || 'Security alert',
            subtitle: alert.vendorInformation || alert.status || 'Microsoft security',
            meta: `${alert.severity || 'medium'} | ${formatSunbirdDeviceDate(alert.createdDateTime || alert.eventDateTime)}`
        }));
    }
    if (evidenceKey === 'policies') {
        return (model.policies || []).map(policy => ({
            title: policy.displayName || policy.name || policy.id || 'Compliance policy',
            subtitle: policy.description || 'Device compliance policy',
            meta: policy.platforms || policy.createdDateTime || 'Policy evidence'
        }));
    }
    return (model.evidence?.[evidenceKey] || []).map(device => ({
        title: device.deviceName || 'Unknown device',
        subtitle: device.userPrincipalName || device.operatingSystem || 'N/A',
        meta: getSunbirdDeviceIssueReasons(device).join(', ') || `${normalizeSunbirdDeviceCompliance(device)} | ${device.isEncrypted ? 'Encrypted' : 'Not encrypted'}`
    }));
}

function toggleSunbirdDeviceInsightEvidenceLock(evidenceKey) {
    const tile = document.querySelector(`.sunbird-id-insight[data-device-evidence-key="${evidenceKey}"]`);
    if (!tile) return;
    const shouldLock = lockedSunbirdDeviceInsightEvidenceKey !== evidenceKey;
    document.querySelectorAll('.sunbird-id-insight.locked').forEach(item => item.classList.remove('locked'));
    lockedSunbirdDeviceInsightEvidenceKey = shouldLock ? evidenceKey : null;
    if (shouldLock) tile.classList.add('locked');
}

function handleSunbirdDeviceInsightEvidenceKey(event, evidenceKey) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    toggleSunbirdDeviceInsightEvidenceLock(evidenceKey);
}

function buildSunbirdDeviceOsDistribution(devices) {
    return devices.reduce((acc, device) => {
        const os = device.operatingSystem || 'Unknown';
        acc[os] = (acc[os] || 0) + 1;
        return acc;
    }, {});
}

function buildSunbirdDeviceManagementStatus(devices) {
    return {
        managed: devices.filter(d => String(d.managementAgent || '').trim() && !/unknown|none/i.test(String(d.managementAgent || ''))).length,
        unmanaged: devices.filter(d => !String(d.managementAgent || '').trim() || /unknown|none/i.test(String(d.managementAgent || ''))).length,
        aadRegistered: devices.filter(d => d.azureADRegistered).length
    };
}

function calculateSunbirdDeviceSecurityScore(total, compliant, encrypted, active24h) {
    if (!total) return 0;
    const compliance = compliant / total;
    const encryption = encrypted / total;
    const activity = active24h / total;
    return Math.round(((compliance + encryption + activity) / 3) * 100);
}

function normalizeSunbirdDeviceCompliance(device) {
    const value = String(device?.complianceState || 'unknown').toLowerCase().replace(/[_\s-]/g, '');
    if (value === 'noncompliant') return 'noncompliant';
    if (value === 'compliant') return 'compliant';
    return 'unknown';
}

function getSunbirdDeviceLastSyncTime(device) {
    const raw = device?.lastSyncDateTime;
    const time = raw ? new Date(raw).getTime() : 0;
    return Number.isFinite(time) ? time : 0;
}

function getSunbirdDeviceDaysSinceSync(device) {
    const time = getSunbirdDeviceLastSyncTime(device);
    if (!time) return 999;
    return Math.floor((Date.now() - time) / (24 * 60 * 60 * 1000));
}

function formatSunbirdDeviceDate(value) {
    if (!value) return 'Never';
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return 'Never';
    return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function getSunbirdDeviceIssueReasons(device) {
    const reasons = [];
    const compliance = normalizeSunbirdDeviceCompliance(device);
    const days = getSunbirdDeviceDaysSinceSync(device);
    if (compliance !== 'compliant') reasons.push(compliance === 'unknown' ? 'Unknown compliance' : 'Non-compliant');
    if (!device.isEncrypted) reasons.push('Not encrypted');
    if (days > 30) reasons.push('Dead 30+ days');
    else if (days > 7) reasons.push('Stale 7+ days');
    if (!String(device.managementAgent || '').trim() || /unknown|none/i.test(String(device.managementAgent || ''))) reasons.push('Unmanaged');
    if (device.hasPendingActions) reasons.push('Pending actions');
    return reasons;
}

function getSunbirdDeviceRiskLevel(device) {
    const reasons = getSunbirdDeviceIssueReasons(device);
    if ((!device.isEncrypted && normalizeSunbirdDeviceCompliance(device) !== 'compliant') || reasons.includes('Dead 30+ days')) return 'high';
    if (reasons.length > 0) return 'medium';
    return 'safe';
}

function getSunbirdDeviceRiskRank(device) {
    const risk = getSunbirdDeviceRiskLevel(device);
    if (risk === 'high') return 3;
    if (risk === 'medium') return 2;
    return 1;
}

window.openSunbirdDeviceEvidence = openSunbirdDeviceEvidence;
window.closeSunbirdDeviceEvidence = closeSunbirdDeviceEvidence;
window.applySunbirdDeviceTableFilter = applySunbirdDeviceTableFilter;
window.toggleSunbirdDeviceInsightEvidenceLock = toggleSunbirdDeviceInsightEvidenceLock;
window.handleSunbirdDeviceInsightEvidenceKey = handleSunbirdDeviceInsightEvidenceKey;

const SUNBIRD_EMAIL_CACHE_KEY = 'sunbirdEmailSecurityDashboardSnapshot';
let sunbirdEmailDashboardData = null;
let sunbirdEmailTableState = {
    search: '',
    severity: 'all',
    threat: 'all',
    status: 'all',
    sort: 'newest'
};
let lockedSunbirdEmailInsightEvidenceKey = null;

function openSunbirdEmailSecurityDashboard() {
    const dashboardView = document.getElementById('dashboard-view');
    const projectsView = document.getElementById('projects-view');
    if (!dashboardView) return;

    if (projectsView) projectsView.style.display = 'none';
    dashboardView.style.display = 'block';
    dashboardView.style.visibility = 'visible';
    dashboardView.style.opacity = '1';
    dashboardView.classList.remove('sunbird-identity-active');
    dashboardView.classList.remove('sunbird-device-active');
    dashboardView.classList.remove('sunbird-security-active');
    dashboardView.classList.remove('sunbird-backup-active');
    dashboardView.classList.remove('sunbird-applications-active');
    dashboardView.classList.add('sunbird-email-active');

    captureDashboardViewHTML();
    dashboardView.innerHTML = renderSunbirdEmailShell();
    setupSunbirdEmailDashboard();

    const cached = readSunbirdEmailSnapshot();
    if (cached) {
        sunbirdEmailDashboardData = normalizeSunbirdEmailData(cached);
    } else if (latestEmailCardData) {
        sunbirdEmailDashboardData = normalizeSunbirdEmailData(latestEmailCardData);
    } else {
        sunbirdEmailDashboardData = normalizeSunbirdEmailData({ success: true, alerts: [], incidents: [] });
    }
    renderSunbirdEmailDashboard();
    loadSunbirdEmailDashboardData();
}

function renderSunbirdEmailShell() {
    return `
        <section class="sunbird-identity-dashboard sunbird-email-dashboard" id="sunbird-email-dashboard">
            <div class="sunbird-id-header">
                <button id="sunbird-email-back" class="sunbird-id-back-btn" type="button">
                    <span class="sunbird-id-back-icon" aria-hidden="true">&larr;</span>
                    <span>Back</span>
                </button>
                <div>
                    <h2>Email Security</h2>
                    <p>Email threat intelligence, incidents, affected users, and evidence.</p>
                </div>
                <div class="sunbird-id-microsoft-badge" aria-label="Microsoft Solutions">
                    <span class="sunbird-id-ms-logo" aria-hidden="true"><i></i><i></i><i></i><i></i></span>
                    <span>Microsoft Solutions</span>
                </div>
            </div>

            <div class="sunbird-id-metrics" id="sunbird-email-metrics"></div>
            <div class="sunbird-id-insights" id="sunbird-email-insights"></div>
            <div class="sunbird-id-charts" id="sunbird-email-charts"></div>
            <div class="sunbird-id-signins" id="sunbird-email-panels"></div>

            <section class="sunbird-id-table-section">
                <div class="sunbird-id-table-toolbar sunbird-email-table-toolbar">
                    <input id="sunbird-email-search" class="sunbird-id-search" type="search" placeholder="Search sender, user, title, threat, severity, status">
                    <select id="sunbird-email-severity-filter" class="sunbird-id-select">
                        <option value="all">All severity</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                    <select id="sunbird-email-threat-filter" class="sunbird-id-select">
                        <option value="all">All threats</option>
                        <option value="mailflow">Mail flow</option>
                        <option value="phishing">Phishing</option>
                        <option value="malware">Malware</option>
                        <option value="spam">Spam</option>
                        <option value="bec">BEC</option>
                        <option value="spoofing">Spoofing</option>
                        <option value="other">Other</option>
                    </select>
                    <select id="sunbird-email-status-filter" class="sunbird-id-select">
                        <option value="all">All status</option>
                        <option value="newalert">New</option>
                        <option value="inprogress">In progress</option>
                        <option value="resolved">Resolved</option>
                        <option value="dismissed">Dismissed</option>
                    </select>
                    <select id="sunbird-email-sort" class="sunbird-id-select">
                        <option value="newest">Sort newest</option>
                        <option value="severity">Sort severity</option>
                        <option value="threat">Sort threat</option>
                    </select>
                    <button id="sunbird-email-clear" class="sunbird-id-clear-btn" type="button">Clear</button>
                </div>

                <div class="sunbird-id-table-wrap">
                    <table class="sunbird-id-table sunbird-email-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Threat</th>
                                <th>Severity</th>
                                <th>Status</th>
                                <th>Sender</th>
                                <th>Targeted User</th>
                                <th>Subject / Alert</th>
                                <th>Action</th>
                                <th>Category</th>
                                <th>Evidence</th>
                            </tr>
                        </thead>
                        <tbody id="sunbird-email-body"></tbody>
                    </table>
                </div>
            </section>
        </section>
        <div id="sunbird-email-evidence-modal" class="sunbird-id-modal" aria-hidden="true"></div>
    `;
}

function setupSunbirdEmailDashboard() {
    document.getElementById('sunbird-email-back')?.addEventListener('click', goBackToProjects);
    document.getElementById('sunbird-email-search')?.addEventListener('input', event => {
        sunbirdEmailTableState.search = event.target.value;
        renderSunbirdEmailTable();
    });
    document.getElementById('sunbird-email-severity-filter')?.addEventListener('change', event => {
        sunbirdEmailTableState.severity = event.target.value;
        renderSunbirdEmailTable();
    });
    document.getElementById('sunbird-email-threat-filter')?.addEventListener('change', event => {
        sunbirdEmailTableState.threat = event.target.value;
        renderSunbirdEmailTable();
    });
    document.getElementById('sunbird-email-status-filter')?.addEventListener('change', event => {
        sunbirdEmailTableState.status = event.target.value;
        renderSunbirdEmailTable();
    });
    document.getElementById('sunbird-email-sort')?.addEventListener('change', event => {
        sunbirdEmailTableState.sort = event.target.value;
        renderSunbirdEmailTable();
    });
    document.getElementById('sunbird-email-clear')?.addEventListener('click', () => {
        sunbirdEmailTableState = { search: '', severity: 'all', threat: 'all', status: 'all', sort: 'newest' };
        ['sunbird-email-search', 'sunbird-email-severity-filter', 'sunbird-email-threat-filter', 'sunbird-email-status-filter', 'sunbird-email-sort'].forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.value = id === 'sunbird-email-sort' ? 'newest' : 'all';
            if (id === 'sunbird-email-search') el.value = '';
        });
        renderSunbirdEmailTable();
    });
}

function readSunbirdEmailSnapshot() {
    try {
        const parsed = JSON.parse(localStorage.getItem(SUNBIRD_EMAIL_CACHE_KEY) || 'null');
        return parsed?.summary || parsed?.alerts ? parsed : null;
    } catch (error) {
        return null;
    }
}

function saveSunbirdEmailSnapshot(data) {
    if (!data?.summary && !data?.alerts) return;
    localStorage.setItem(SUNBIRD_EMAIL_CACHE_KEY, JSON.stringify({
        ...data,
        savedAt: new Date().toISOString()
    }));
}

async function loadSunbirdEmailDashboardData() {
    const token = localStorage.getItem('authToken');
    if (!token) return;

    try {
        const metricsResponse = await fetch('/api/db/email-metrics', {
            method: 'GET',
            cache: 'no-store',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        const metricsData = await metricsResponse.json();
        if (metricsResponse.ok && metricsData.success) {
            sunbirdEmailDashboardData = normalizeSunbirdEmailData({ ...(sunbirdEmailDashboardData || {}), metrics: metricsData.metrics });
            latestEmailCardData = metricsData;
            renderSunbirdEmailDashboard();
        }
    } catch (error) {
        console.warn('[Email Dashboard] Cached metrics unavailable:', error.message);
    }

    try {
        const cachedResponse = await fetch('/api/db/email-security', {
            method: 'GET',
            cache: 'no-store',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        const cachedData = await cachedResponse.json();
        if (!cachedResponse.ok || !cachedData.success) throw new Error(cachedData.message || 'Cached email security unavailable');
        sunbirdEmailDashboardData = normalizeSunbirdEmailData(cachedData);
        saveSunbirdEmailSnapshot(sunbirdEmailDashboardData);
        renderSunbirdEmailDashboard();
    } catch (cachedError) {
        try {
            const liveResponse = await fetch('/api/email-security', {
                method: 'GET',
                cache: 'no-store',
                headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
            });
            const liveData = await liveResponse.json();
            if (!liveResponse.ok || !liveData.success) throw new Error(liveData.message || 'Email security unavailable');
            sunbirdEmailDashboardData = normalizeSunbirdEmailData(liveData);
            saveSunbirdEmailSnapshot(sunbirdEmailDashboardData);
            renderSunbirdEmailDashboard();
        } catch (liveError) {
            console.warn('[Email Dashboard] Detailed evidence unavailable:', liveError.message);
        }
    }
}

function normalizeSunbirdEmailData(data = {}) {
    const payload = data.payload && typeof data.payload === 'object' ? data.payload : data;
    const metrics = payload.metrics || data.metrics || {};
    const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
    const incidents = Array.isArray(payload.incidents) ? payload.incidents : [];
    const affectedUsers = payload.affectedUsers || {};
    const mailActivity = payload.mailActivity || { users: [], summary: {} };
    const summary = payload.summary || {};
    const activeThreats = summary.activeThreats ?? getSunbirdMetricNumber(metrics, ['ActiveThreats', 'activeThreats'], alerts.filter(a => ['newalert', 'inprogress'].includes(String(a.status || '').toLowerCase())).length);
    const highSeverityAlerts = summary.highSeverityAlerts ?? getSunbirdMetricNumber(metrics, ['HighSeverity', 'highSeverity'], alerts.filter(a => ['critical', 'high'].includes(String(a.severity || '').toLowerCase())).length);
    const affectedUsersCount = summary.affectedUsersCount ?? getSunbirdMetricNumber(metrics, ['UsersTargeted', 'usersTargeted'], Array.isArray(affectedUsers.all) ? affectedUsers.all.length : 0);
    const activeIncidents = summary.activeIncidents ?? getSunbirdMetricNumber(metrics, ['OpenIncidents', 'openIncidents'], incidents.filter(i => ['active', 'inprogress'].includes(String(i.status || '').toLowerCase())).length);
    const threats = payload.threats || buildSunbirdEmailThreatBreakdown(alerts);

    return {
        ...payload,
        alerts,
        incidents,
        threats,
        affectedUsers,
        mailActivity: {
            ...mailActivity,
            users: Array.isArray(mailActivity.users) ? mailActivity.users : [],
            summary: mailActivity.summary || summary.mailActivity || {}
        },
        insights: Array.isArray(payload.insights) ? payload.insights : [],
        summary: {
            ...summary,
            activeThreats,
            highSeverityAlerts,
            affectedUsersCount,
            activeIncidents,
            mailActivity: summary.mailActivity || mailActivity.summary || {},
            threatResolutionRate: summary.threatResolutionRate ?? calculateSunbirdEmailResolutionRate(alerts),
            securityScore: summary.securityScore ?? calculateSunbirdEmailSecurityScore(alerts)
        }
    };
}

function buildSunbirdEmailModel(data = sunbirdEmailDashboardData) {
    const normalized = normalizeSunbirdEmailData(data || {});
    const alerts = normalized.alerts.map(alert => ({
        ...alert,
        threatType: getSunbirdEmailThreatType(alert)
    }));
    const highSeverityAlerts = alerts.filter(alert => ['critical', 'high'].includes(String(alert.severity || '').toLowerCase()));
    const phishingAlerts = alerts.filter(alert => alert.threatType === 'phishing');
    const malwareAlerts = alerts.filter(alert => alert.threatType === 'malware');
    const spamAlerts = alerts.filter(alert => alert.threatType === 'spam');
    const becAlerts = alerts.filter(alert => alert.threatType === 'bec');
    const quarantinedAlerts = alerts.filter(alert => /quarantine|blocked|prevented|remediated/i.test(getSunbirdEmailAction(alert)));
    const affectedUserRows = getSunbirdEmailAffectedUserRows(normalized, alerts);
    const recommendations = buildSunbirdEmailRecommendations(normalized, { highSeverityAlerts, phishingAlerts, malwareAlerts, affectedUserRows, quarantinedAlerts });
    const mailActivityUsers = Array.isArray(normalized.mailActivity?.users) ? normalized.mailActivity.users : [];
    const tableRows = [
        ...alerts.map(alert => ({ ...alert, rowType: 'threat' })),
        ...mailActivityUsers.map(user => ({
            rowType: 'mailActivity',
            id: `mail-${user.userPrincipalName}`,
            title: 'Exchange mailbox activity',
            severity: 'low',
            status: user.lastActivityDate ? 'active' : 'inactive',
            created: user.lastActivityDate || user.reportRefreshDate,
            category: 'Exchange Activity Report',
            sender: user.userPrincipalName,
            recipient: user.userPrincipalName,
            action: `${user.sendCount || 0} sent | ${user.receiveCount || 0} received | ${user.readCount || 0} read`,
            description: `Last activity: ${user.lastActivityDate || 'No recent activity'}`,
            userStates: [{ accountName: user.userPrincipalName }]
        }))
    ];

    return {
        ...normalized,
        alerts,
        tableRows,
        recommendations,
        evidence: {
            allAlerts: alerts,
            highSeverityAlerts,
            phishingAlerts,
            malwareAlerts,
            spamAlerts,
            becAlerts,
            quarantinedAlerts,
            affectedUsers: affectedUserRows,
            mailActivityUsers,
            activeIncidents: normalized.incidents.filter(i => ['active', 'inprogress'].includes(String(i.status || '').toLowerCase())),
            incidents: normalized.incidents,
            recommendations
        }
    };
}

function renderSunbirdEmailDashboard() {
    const model = buildSunbirdEmailModel();
    renderSunbirdEmailMetrics(model);
    renderSunbirdEmailInsights(model);
    renderSunbirdEmailCharts(model);
    renderSunbirdEmailPanels(model);
    renderSunbirdEmailTable(model);
}

function renderSunbirdEmailMetrics(model) {
    const el = document.getElementById('sunbird-email-metrics');
    if (!el) return;
    const metrics = [
        { key: 'active-threats', label: 'Active Threats', value: model.summary.activeThreats, tone: model.summary.activeThreats ? 'bad' : 'good', evidence: 'allAlerts' },
        { key: 'high-severity', label: 'High Severity', value: model.summary.highSeverityAlerts, tone: model.summary.highSeverityAlerts ? 'bad' : 'good', evidence: 'highSeverityAlerts' },
        { key: 'users-targeted', label: 'Users Targeted', value: model.summary.affectedUsersCount, tone: model.summary.affectedUsersCount > 5 ? 'warn' : 'neutral', evidence: 'affectedUsers' },
        { key: 'security-score', label: 'Email Security Score', value: `${model.summary.securityScore || 0}%`, tone: model.summary.securityScore >= 80 ? 'good' : model.summary.securityScore >= 60 ? 'warn' : 'bad', evidence: 'recommendations' }
    ];
    el.innerHTML = metrics.map(metric => `
        <article class="sunbird-id-metric-card tone-${metric.tone}">
            <div class="sunbird-id-metric-value">${escapeIdentityText(metric.value)}</div>
            <div class="sunbird-id-metric-label">${escapeIdentityText(metric.label)}</div>
            <button type="button" onclick="openSunbirdEmailEvidence('${metric.evidence}')" class="sunbird-id-evidence-btn">View Evidence</button>
        </article>
    `).join('');
}

function renderSunbirdEmailInsights(model) {
    const el = document.getElementById('sunbird-email-insights');
    if (!el) return;
    const insights = [
        { title: 'Phishing', value: model.evidence.phishingAlerts.length, evidence: 'phishingAlerts', tone: model.evidence.phishingAlerts.length ? 'bad' : 'good', filter: { threat: 'phishing' } },
        { title: 'Malware', value: model.evidence.malwareAlerts.length, evidence: 'malwareAlerts', tone: model.evidence.malwareAlerts.length ? 'bad' : 'good', filter: { threat: 'malware' } },
        { title: 'Spam', value: model.evidence.spamAlerts.length, evidence: 'spamAlerts', tone: model.evidence.spamAlerts.length ? 'warn' : 'neutral', filter: { threat: 'spam' } },
        { title: 'BEC attempts', value: model.evidence.becAlerts.length, evidence: 'becAlerts', tone: model.evidence.becAlerts.length ? 'bad' : 'neutral', filter: { threat: 'bec' } },
        { title: 'Active mailboxes', value: model.summary.mailActivity?.activeMailboxes || model.evidence.mailActivityUsers.length, evidence: 'mailActivityUsers', tone: 'neutral', filter: { threat: 'mailflow' } },
        { title: 'Mail events', value: model.summary.mailActivity?.totalMailActivity || 0, evidence: 'mailActivityUsers', tone: 'neutral', filter: { threat: 'mailflow' } },
        { title: 'Open incidents', value: model.evidence.activeIncidents.length, evidence: 'activeIncidents', tone: model.evidence.activeIncidents.length ? 'bad' : 'good' },
        { title: 'Recommendations', value: model.recommendations.length, evidence: 'recommendations', tone: model.recommendations.some(r => r.priority === 'critical') ? 'bad' : 'warn' }
    ];
    el.innerHTML = insights.map((item, index) => `
        <article class="sunbird-id-insight tone-${item.tone}" role="button" tabindex="0" data-email-evidence-key="${item.evidence}" onclick="toggleSunbirdEmailInsightEvidenceLock('${item.evidence}')" onkeydown="handleSunbirdEmailInsightEvidenceKey(event, '${item.evidence}')">
            <span>${escapeIdentityText(item.title)}</span>
            <strong>${escapeIdentityText(item.value)}</strong>
            ${renderSunbirdEmailInsightEvidencePreview(item, model, index)}
        </article>
    `).join('');
}

function renderSunbirdEmailInsightEvidencePreview(item, model, index) {
    const rows = getSunbirdEmailEvidenceRows(item.evidence, model);
    const previewRows = rows.slice(0, 4);
    return `
        <div class="sunbird-id-insight-evidence" onclick="event.stopPropagation()">
            <p>${rows.length} evidence item${rows.length === 1 ? '' : 's'} matched this email signal.</p>
            <div class="sunbird-id-insight-evidence-list">
                ${previewRows.length ? previewRows.map(row => `
                    <div>
                        <strong>${escapeIdentityText(row.title)}</strong>
                        <span>${escapeIdentityText(row.subtitle)}</span>
                        <small>${escapeIdentityText(row.meta)}</small>
                    </div>
                `).join('') : '<em>No evidence found.</em>'}
            </div>
            ${rows.length > previewRows.length ? `<small>${rows.length - previewRows.length} more in full evidence</small>` : ''}
            <button type="button" onclick="openSunbirdEmailEvidence('${item.evidence}', 'insight-${index}')">Open Evidence</button>
        </div>
    `;
}

function renderSunbirdEmailCharts(model) {
    const el = document.getElementById('sunbird-email-charts');
    if (!el) return;
    const total = Math.max(1, model.alerts.length);
    const threats = model.threats.byType || {};
    const severity = model.threats.bySeverity || {};
    el.innerHTML = `
        ${renderSunbirdPieChart('Threat type distribution', [
            { label: 'Phishing', value: threats.Phishing || model.evidence.phishingAlerts.length, tone: 'bad' },
            { label: 'Malware', value: threats.Malware || model.evidence.malwareAlerts.length, tone: 'warn' },
            { label: 'Spam', value: threats.Spam || model.evidence.spamAlerts.length, tone: 'neutral' },
            { label: 'Other', value: threats.Other || 0, tone: 'good' }
        ], total)}
        ${renderSunbirdPieChart('Severity distribution', [
            { label: 'High', value: severity.high || 0, tone: 'bad' },
            { label: 'Medium', value: severity.medium || 0, tone: 'warn' },
            { label: 'Low', value: severity.low || 0, tone: 'good' }
        ], total)}
        ${renderSunbirdDeviceBars('Most targeted users', getSunbirdEmailTargetedUserChartItems(model), Math.max(1, ...getSunbirdEmailTargetedUserChartItems(model).map(item => item.value)))}
        ${renderSunbirdDeviceBars('Mail flow activity', [
            { label: 'Sent', value: model.summary.mailActivity?.sendCount || 0, tone: 'neutral' },
            { label: 'Received', value: model.summary.mailActivity?.receiveCount || 0, tone: 'good' },
            { label: 'Read', value: model.summary.mailActivity?.readCount || 0, tone: 'warn' }
        ], Math.max(1, model.summary.mailActivity?.sendCount || 0, model.summary.mailActivity?.receiveCount || 0, model.summary.mailActivity?.readCount || 0))}
        ${renderSunbirdEmailHealthGraph(model)}
    `;
    animateSunbirdIdentityCharts();
}

function renderSunbirdEmailRiskTrendChart(model) {
    const trend = buildSunbirdEmailRiskTrend(model.alerts);
    const width = 720;
    const height = 190;
    const padding = { top: 18, right: 18, bottom: 30, left: 34 };
    const maxValue = Math.max(1, ...trend.days.flatMap(day => [day.critical, day.high, day.medium]));
    const point = (value, index) => {
        const x = padding.left + (index * ((width - padding.left - padding.right) / Math.max(1, trend.days.length - 1)));
        const y = height - padding.bottom - ((value / maxValue) * (height - padding.top - padding.bottom));
        return `${x},${y}`;
    };
    const polyline = key => trend.days.map((day, index) => point(day[key], index)).join(' ');
    const circles = (key, className) => trend.days.map((day, index) => {
        const [x, y] = point(day[key], index).split(',');
        return `<circle class="${className}" cx="${x}" cy="${y}" r="3"></circle>`;
    }).join('');
    const yTicks = Array.from({ length: Math.min(6, maxValue + 1) }, (_, index) => Math.round((maxValue / Math.max(1, Math.min(5, maxValue))) * index));

    return `
        <article class="sunbird-id-chart-card sunbird-email-risk-trend-card">
            <h3><i class="fas fa-chart-line"></i> Risk Assessment Overview</h3>
            <div class="sunbird-email-risk-legend">
                <span class="critical">Critical</span>
                <span class="high">High</span>
                <span class="medium">Medium</span>
            </div>
            <svg class="sunbird-email-risk-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="Email risk trend over the last seven days">
                ${yTicks.map(tick => {
                    const y = height - padding.bottom - ((tick / maxValue) * (height - padding.top - padding.bottom));
                    return `<g><line x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}"></line><text x="12" y="${y + 4}">${tick}</text></g>`;
                }).join('')}
                <polyline class="critical" points="${polyline('critical')}"></polyline>
                <polyline class="high" points="${polyline('high')}"></polyline>
                <polyline class="medium" points="${polyline('medium')}"></polyline>
                ${circles('critical', 'critical')}
                ${circles('high', 'high')}
                ${circles('medium', 'medium')}
                ${trend.days.map((day, index) => {
                    const x = padding.left + (index * ((width - padding.left - padding.right) / Math.max(1, trend.days.length - 1)));
                    return `<text class="x-label" x="${x}" y="${height - 8}">${escapeIdentityText(day.label)}</text>`;
                }).join('')}
            </svg>
        </article>
    `;
}

function renderSunbirdEmailHealthGraph(model) {
    const resolved = model.summary.threatResolutionRate || 0;
    const score = model.summary.securityScore || 0;
    const exposure = model.alerts.length ? Math.max(0, 100 - Math.min(100, model.evidence.highSeverityAlerts.length * 12)) : 100;
    return `
        <article class="sunbird-id-chart-card sunbird-id-health-card">
            <h3>Email posture</h3>
            ${[
                { label: 'Score', value: score, tone: score >= 80 ? 'good' : 'warn' },
                { label: 'Resolution', value: resolved, tone: resolved >= 75 ? 'good' : 'warn' },
                { label: 'Exposure', value: exposure, tone: exposure >= 80 ? 'good' : 'warn' }
            ].map(item => `
                <div class="sunbird-id-health-row">
                    <span>${item.label}</span>
                    <div class="sunbird-id-health-track"><div class="sunbird-id-health-fill tone-${item.tone}" style="width:${item.value}%"></div></div>
                    <strong>${item.value}%</strong>
                </div>
            `).join('')}
        </article>
    `;
}

function renderSunbirdEmailPanels(model) {
    const el = document.getElementById('sunbird-email-panels');
    if (!el) return;
    el.innerHTML = `
        ${renderSunbirdEmailFeedPanel('Threat intelligence feed', getSunbirdEmailEvidenceRows('allAlerts', model).slice(0, 10))}
        ${renderSunbirdEmailFeedPanel('Mail flow analytics', getSunbirdEmailEvidenceRows('mailActivityUsers', model).slice(0, 10))}
        ${renderSunbirdEmailVipPanel(model)}
        ${renderSunbirdEmailFeedPanel('Security recommendations', getSunbirdEmailEvidenceRows('recommendations', model).slice(0, 10))}
    `;
}

function renderSunbirdEmailVipPanel(model) {
    const users = model.evidence.affectedUsers.length
        ? model.evidence.affectedUsers.slice(0, 10)
        : model.evidence.mailActivityUsers
            .slice()
            .sort((a, b) => ((b.sendCount || 0) + (b.receiveCount || 0) + (b.readCount || 0)) - ((a.sendCount || 0) + (a.receiveCount || 0) + (a.readCount || 0)))
            .slice(0, 10)
            .map(user => ({
                user: user.userPrincipalName,
                threatCount: (user.sendCount || 0) + (user.receiveCount || 0) + (user.readCount || 0),
                isMailActivity: true
            }));
    return `
        <article class="sunbird-id-signin-card">
            <h3>VIP / user risk monitoring</h3>
            <div class="sunbird-id-signin-list">
                ${users.length ? users.map(user => {
                    const alerts = getSunbirdEmailAlertsForUser(model, user.user);
                    return `
                        <div class="sunbird-id-signin-item sunbird-email-vip-item">
                            <div>
                                <strong>${escapeIdentityText(user.user)}</strong>
                                <span>${user.isMailActivity ? `${user.threatCount} mail activity event${user.threatCount === 1 ? '' : 's'}` : `${user.threatCount} email threat${user.threatCount === 1 ? '' : 's'}`}</span>
                                <div class="sunbird-email-vip-evidence-list">
                                    ${alerts.length ? alerts.slice(0, 3).map(alert => `
                                        <small>${escapeIdentityText(formatSunbirdDateTime(alert.created || alert.createdDateTime))} - ${escapeIdentityText(alert.title || getSunbirdEmailThreatLabel(alert))}</small>
                                    `).join('') : '<small>Exchange email activity report evidence</small>'}
                                </div>
                                <button type="button" class="sunbird-email-vip-evidence-btn" onclick='openSunbirdEmailUserEvidence(${JSON.stringify(user.user)})'>Targeted mailbox evidence</button>
                            </div>
                        </div>
                    `;
                }).join('') : '<div class="sunbird-id-empty compact">No targeted mailbox evidence.</div>'}
            </div>
        </article>
    `;
}

function renderSunbirdEmailFeedPanel(title, rows) {
    return `
        <article class="sunbird-id-signin-card">
            <h3>${escapeIdentityText(title)}</h3>
            <div class="sunbird-id-signin-list">
                ${rows.length ? rows.map(row => `
                    <div class="sunbird-id-signin-item">
                        <div>
                            <strong>${escapeIdentityText(row.title)}</strong>
                            <span>${escapeIdentityText(row.subtitle)}</span>
                            <div class="sunbird-id-issue-tags"><em>${escapeIdentityText(row.meta)}</em></div>
                        </div>
                    </div>
                `).join('') : '<div class="sunbird-id-empty compact">No matching email evidence.</div>'}
            </div>
        </article>
    `;
}

function renderSunbirdEmailTable(model = buildSunbirdEmailModel()) {
    const body = document.getElementById('sunbird-email-body');
    if (!body) return;
    const rows = getFilteredSunbirdEmailRows(model);
    if (!rows.length) {
        body.innerHTML = '<tr><td colspan="10" class="sunbird-id-empty">No email evidence matches the current filters.</td></tr>';
        return;
    }
    body.innerHTML = rows.map(alert => {
        const severity = String(alert.severity || 'low').toLowerCase();
        const threat = getSunbirdEmailThreatType(alert);
        return `
            <tr>
                <td data-label="Time">${escapeIdentityText(formatSunbirdDeviceDate(alert.created || alert.createdDateTime))}</td>
                <td data-label="Threat"><span class="sunbird-id-role-list"><span>${escapeIdentityText(threat)}</span></span></td>
                <td data-label="Severity"><span class="sunbird-id-risk ${severity === 'critical' || severity === 'high' ? 'high' : severity === 'medium' ? 'medium' : 'safe'}">${escapeIdentityText(severity)}</span></td>
                <td data-label="Status"><span class="sunbird-id-pill">${escapeIdentityText(alert.status || 'newAlert')}</span></td>
                <td data-label="Sender">${escapeIdentityText(getSunbirdEmailSender(alert))}</td>
                <td data-label="Targeted User">${escapeIdentityText(getSunbirdEmailTargetUser(alert))}</td>
                <td data-label="Subject / Alert">${escapeIdentityText(alert.title || 'Email alert')}</td>
                <td data-label="Action">${escapeIdentityText(alert.action || getSunbirdEmailAction(alert))}</td>
                <td data-label="Category">${escapeIdentityText(alert.category || 'Email Threat')}</td>
                <td data-label="Evidence">${escapeIdentityText((alert.description || '').slice(0, 90) || 'Security alert evidence')}</td>
            </tr>
        `;
    }).join('');
}

function getFilteredSunbirdEmailRows(model = buildSunbirdEmailModel()) {
    const search = sunbirdEmailTableState.search.trim().toLowerCase();
    return model.tableRows.filter(alert => {
        const severity = String(alert.severity || 'low').toLowerCase();
        const threat = getSunbirdEmailThreatType(alert);
        const status = String(alert.status || '').toLowerCase();
        const haystack = [
            alert.title,
            alert.description,
            alert.category,
            severity,
            threat,
            status,
            getSunbirdEmailSender(alert),
            getSunbirdEmailTargetUser(alert),
            getSunbirdEmailAction(alert)
        ].join(' ').toLowerCase();
        if (search && !haystack.includes(search)) return false;
        if (sunbirdEmailTableState.severity !== 'all' && severity !== sunbirdEmailTableState.severity) return false;
        if (sunbirdEmailTableState.threat !== 'all' && threat !== sunbirdEmailTableState.threat) return false;
        if (sunbirdEmailTableState.status !== 'all' && status !== sunbirdEmailTableState.status) return false;
        return true;
    }).sort((a, b) => {
        if (sunbirdEmailTableState.sort === 'severity') return getSunbirdEmailSeverityRank(b) - getSunbirdEmailSeverityRank(a);
        if (sunbirdEmailTableState.sort === 'threat') return getSunbirdEmailThreatType(a).localeCompare(getSunbirdEmailThreatType(b));
        return getSunbirdEmailTime(b) - getSunbirdEmailTime(a);
    });
}

function applySunbirdEmailTableFilter(filter = {}) {
    sunbirdEmailTableState = { ...sunbirdEmailTableState, ...filter };
    const setValue = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.value = value;
    };
    setValue('sunbird-email-severity-filter', sunbirdEmailTableState.severity);
    setValue('sunbird-email-threat-filter', sunbirdEmailTableState.threat);
    setValue('sunbird-email-status-filter', sunbirdEmailTableState.status);
    setValue('sunbird-email-sort', sunbirdEmailTableState.sort);
    renderSunbirdEmailTable();
    document.querySelector('.sunbird-email-dashboard .sunbird-id-table-section')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function openSunbirdEmailEvidence(evidenceKey) {
    const model = buildSunbirdEmailModel();
    const rows = getSunbirdEmailEvidenceRows(evidenceKey, model);
    const modal = document.getElementById('sunbird-email-evidence-modal');
    if (!modal) return;
    const titleMap = {
        allAlerts: 'Threat Mail Evidence',
        highSeverityAlerts: 'High Severity Email Threats',
        phishingAlerts: 'Phishing Detections',
        malwareAlerts: 'Malware Email Detections',
        spamAlerts: 'Spam Detections',
        becAlerts: 'Business Email Compromise Attempts',
        quarantinedAlerts: 'Quarantined / Blocked Emails',
        affectedUsers: 'Users Targeted',
        activeIncidents: 'Open Email Incidents',
        incidents: 'Incident Drilldown',
        mailActivityUsers: 'Exchange Mail Activity',
        recommendations: 'Security Recommendations'
    };
    const filterMap = {
        highSeverityAlerts: { severity: 'high' },
        phishingAlerts: { threat: 'phishing' },
        malwareAlerts: { threat: 'malware' },
        spamAlerts: { threat: 'spam' },
        becAlerts: { threat: 'bec' }
    };
    modal.innerHTML = `
        <div class="sunbird-id-modal-backdrop" onclick="closeSunbirdEmailEvidence()"></div>
        <div class="sunbird-id-modal-panel" role="dialog" aria-modal="true">
            <div class="sunbird-id-modal-header">
                <div>
                    <h3>${escapeIdentityText(titleMap[evidenceKey] || 'Email Evidence')}</h3>
                    <p>${rows.length} evidence item${rows.length === 1 ? '' : 's'} matched this set.</p>
                </div>
                <button type="button" onclick="closeSunbirdEmailEvidence()" class="sunbird-id-modal-close">&times;</button>
            </div>
            <div class="sunbird-id-evidence-summary">
                <span>Active threats: ${model.summary.activeThreats || 0}</span>
                <span>High severity: ${model.summary.highSeverityAlerts || 0}</span>
                <span>Users targeted: ${model.summary.affectedUsersCount || 0}</span>
            </div>
            <div class="sunbird-id-evidence-list">
                ${rows.length ? rows.slice(0, 100).map(row => `
                    <div class="sunbird-id-evidence-user">
                        <strong>${escapeIdentityText(row.title)}</strong>
                        <span>${escapeIdentityText(row.subtitle)}</span>
                        <small>${escapeIdentityText(row.meta)}</small>
                    </div>
                `).join('') : '<div class="sunbird-id-empty">No evidence found for this item.</div>'}
            </div>
            <div class="sunbird-id-modal-actions">
                <button type="button" class="sunbird-id-evidence-btn" onclick='applySunbirdEmailTableFilter(${JSON.stringify(filterMap[evidenceKey] || {})}); closeSunbirdEmailEvidence();'>View in Table</button>
            </div>
        </div>
    `;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
}

function openSunbirdEmailUserEvidence(userName) {
    const model = buildSunbirdEmailModel();
    const alerts = getSunbirdEmailAlertsForUser(model, userName);
    const mailUser = model.evidence.mailActivityUsers.find(user => String(user.userPrincipalName || '').toLowerCase() === String(userName || '').toLowerCase());
    const modal = document.getElementById('sunbird-email-evidence-modal');
    if (!modal) return;

    modal.innerHTML = `
        <div class="sunbird-id-modal-backdrop" onclick="closeSunbirdEmailEvidence()"></div>
        <div class="sunbird-id-modal-panel" role="dialog" aria-modal="true">
            <div class="sunbird-id-modal-header">
                <div>
                    <h3>${escapeIdentityText(userName)} mailbox evidence</h3>
                    <p>${alerts.length || (mailUser ? 1 : 0)} evidence item${(alerts.length || (mailUser ? 1 : 0)) === 1 ? '' : 's'} matched this user.</p>
                </div>
                <button type="button" onclick="closeSunbirdEmailEvidence()" class="sunbird-id-modal-close">&times;</button>
            </div>
            <div class="sunbird-id-evidence-summary">
                <span>User: ${escapeIdentityText(userName)}</span>
                <span>Threat count: ${alerts.length}</span>
                ${mailUser ? `<span>Mail activity: ${(mailUser.sendCount || 0) + (mailUser.receiveCount || 0) + (mailUser.readCount || 0)}</span>` : ''}
            </div>
            <div class="sunbird-id-evidence-list">
                ${alerts.length ? alerts.map(alert => `
                    <div class="sunbird-id-evidence-user">
                        <strong>${escapeIdentityText(alert.title || 'Email alert')}</strong>
                        <span>${escapeIdentityText(formatSunbirdDateTime(alert.created || alert.createdDateTime))}</span>
                        <small>${escapeIdentityText(`${getSunbirdEmailThreatType(alert)} | ${alert.severity || 'low'} | ${getSunbirdEmailAction(alert)}`)}</small>
                    </div>
                `).join('') : mailUser ? `
                    <div class="sunbird-id-evidence-user">
                        <strong>${escapeIdentityText(mailUser.displayName || mailUser.userPrincipalName)}</strong>
                        <span>${escapeIdentityText(mailUser.userPrincipalName)}</span>
                        <small>${escapeIdentityText(`${mailUser.sendCount || 0} sent | ${mailUser.receiveCount || 0} received | ${mailUser.readCount || 0} read | Last activity: ${mailUser.lastActivityDate || 'N/A'}`)}</small>
                    </div>
                ` : '<div class="sunbird-id-empty">No evidence found for this mailbox.</div>'}
            </div>
            <div class="sunbird-id-modal-actions">
                <button type="button" class="sunbird-id-evidence-btn" onclick="closeSunbirdEmailEvidence()">Close</button>
            </div>
        </div>
    `;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
}

function closeSunbirdEmailEvidence() {
    const modal = document.getElementById('sunbird-email-evidence-modal');
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
}

function getSunbirdEmailEvidenceRows(evidenceKey, model = buildSunbirdEmailModel()) {
    if (evidenceKey === 'affectedUsers') {
        return model.evidence.affectedUsers.map(user => ({
            title: user.user,
            subtitle: `${user.threatCount} email threat${user.threatCount === 1 ? '' : 's'}`,
            meta: 'Targeted mailbox evidence'
        }));
    }
    if (evidenceKey === 'mailActivityUsers') {
        return model.evidence.mailActivityUsers.map(user => ({
            title: user.displayName || user.userPrincipalName,
            subtitle: user.userPrincipalName,
            meta: `${user.sendCount || 0} sent | ${user.receiveCount || 0} received | ${user.readCount || 0} read | Last activity: ${user.lastActivityDate || 'N/A'}`
        }));
    }
    if (evidenceKey === 'incidents' || evidenceKey === 'activeIncidents') {
        return (model.evidence[evidenceKey] || []).map(incident => ({
            title: incident.displayName || 'Email incident',
            subtitle: incident.description || incident.assignedTo || 'Incident evidence',
            meta: `${incident.severity || 'medium'} | ${incident.status || 'active'}`
        }));
    }
    if (evidenceKey === 'recommendations') {
        return model.recommendations.map(item => ({
            title: item.title,
            subtitle: item.detail,
            meta: item.priority
        }));
    }
    return (model.evidence[evidenceKey] || []).map(alert => ({
        title: alert.title || 'Email alert',
        subtitle: `${getSunbirdEmailTargetUser(alert)} | ${getSunbirdEmailSender(alert)}`,
        meta: `${getSunbirdEmailThreatType(alert)} | ${alert.severity || 'low'} | ${getSunbirdEmailAction(alert)}`
    }));
}

function toggleSunbirdEmailInsightEvidenceLock(evidenceKey) {
    const tile = document.querySelector(`.sunbird-id-insight[data-email-evidence-key="${evidenceKey}"]`);
    if (!tile) return;
    const shouldLock = lockedSunbirdEmailInsightEvidenceKey !== evidenceKey;
    document.querySelectorAll('.sunbird-id-insight.locked').forEach(item => item.classList.remove('locked'));
    lockedSunbirdEmailInsightEvidenceKey = shouldLock ? evidenceKey : null;
    if (shouldLock) tile.classList.add('locked');
}

function handleSunbirdEmailInsightEvidenceKey(event, evidenceKey) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    toggleSunbirdEmailInsightEvidenceLock(evidenceKey);
}

function buildSunbirdEmailThreatBreakdown(alerts) {
    const byType = {};
    const bySeverity = { high: 0, medium: 0, low: 0 };
    alerts.forEach(alert => {
        const label = getSunbirdEmailThreatLabel(alert);
        byType[label] = (byType[label] || 0) + 1;
        const severity = String(alert.severity || 'low').toLowerCase();
        if (severity === 'critical' || severity === 'high') bySeverity.high++;
        else if (severity === 'medium') bySeverity.medium++;
        else bySeverity.low++;
    });
    return { byType, bySeverity };
}

function calculateSunbirdEmailResolutionRate(alerts) {
    if (!alerts.length) return 100;
    const resolved = alerts.filter(alert => /resolved|dismissed|closed/i.test(String(alert.status || ''))).length;
    return Math.round((resolved / alerts.length) * 100);
}

function calculateSunbirdEmailSecurityScore(alerts) {
    let score = 100;
    alerts.slice(0, 30).forEach(alert => {
        const severity = String(alert.severity || 'low').toLowerCase();
        score -= severity === 'critical' ? 18 : severity === 'high' ? 12 : severity === 'medium' ? 5 : 2;
    });
    return Math.max(0, Math.min(100, score));
}

function getSunbirdEmailThreatType(alert) {
    if (alert.rowType === 'mailActivity') return 'mailflow';
    const text = `${alert.title || ''} ${alert.description || ''} ${alert.category || ''}`.toLowerCase();
    if (/business email|bec|impersonation|spoof/.test(text)) return text.includes('spoof') ? 'spoofing' : 'bec';
    if (text.includes('phish')) return 'phishing';
    if (text.includes('malware') || text.includes('attachment') || text.includes('ransomware')) return 'malware';
    if (text.includes('spam')) return 'spam';
    return 'other';
}

function getSunbirdEmailThreatLabel(alert) {
    const type = getSunbirdEmailThreatType(alert);
    return {
        phishing: 'Phishing',
        malware: 'Malware',
        spam: 'Spam',
        bec: 'BEC',
        spoofing: 'Spoofing',
        mailflow: 'Mail Flow',
        other: 'Other'
    }[type] || 'Other';
}

function getSunbirdEmailSender(alert) {
    return alert.sender || alert.from || alert.sourceAddress || alert.vendorInformation || 'Unknown sender';
}

function getSunbirdEmailTargetUser(alert) {
    const users = Array.isArray(alert.userStates) ? alert.userStates : [];
    return users[0]?.accountName || alert.recipient || alert.userPrincipalName || 'Unknown user';
}

function getSunbirdEmailAction(alert) {
    const status = String(alert.status || '').toLowerCase();
    if (/resolved|dismissed|closed/.test(status)) return 'Resolved';
    if (/quarantine|blocked|prevented/.test(`${alert.title || ''} ${alert.description || ''}`.toLowerCase())) return 'Blocked / Quarantined';
    if (/inprogress/.test(status)) return 'Investigation active';
    return 'Needs review';
}

function getSunbirdEmailTime(alert) {
    const raw = alert.created || alert.createdDateTime || alert.eventDateTime;
    const time = raw ? new Date(raw).getTime() : 0;
    return Number.isFinite(time) ? time : 0;
}

function getSunbirdEmailSeverityRank(alert) {
    const severity = String(alert.severity || 'low').toLowerCase();
    if (severity === 'critical') return 4;
    if (severity === 'high') return 3;
    if (severity === 'medium') return 2;
    return 1;
}

function getSunbirdEmailAffectedUserRows(data, alerts) {
    const counts = {};
    alerts.forEach(alert => {
        const user = getSunbirdEmailTargetUser(alert);
        counts[user] = (counts[user] || 0) + 1;
    });
    if (Array.isArray(data.affectedUsers?.mostTargeted)) {
        data.affectedUsers.mostTargeted.forEach(user => {
            const name = user.user || user.accountName || 'Unknown user';
            counts[name] = Math.max(counts[name] || 0, user.threatCount || user.count || 0);
        });
    }
    return Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .map(([user, threatCount]) => ({ user, threatCount }));
}

function getSunbirdEmailTargetedUserChartItems(model) {
    if (!model.evidence.affectedUsers.length) {
        return model.evidence.mailActivityUsers
            .slice()
            .sort((a, b) => ((b.sendCount || 0) + (b.receiveCount || 0) + (b.readCount || 0)) - ((a.sendCount || 0) + (a.receiveCount || 0) + (a.readCount || 0)))
            .slice(0, 5)
            .map((user, index) => ({
                label: (user.displayName || user.userPrincipalName || 'Mailbox').split('@')[0],
                value: (user.sendCount || 0) + (user.receiveCount || 0) + (user.readCount || 0),
                tone: index === 0 ? 'warn' : 'neutral'
            }));
    }
    return model.evidence.affectedUsers.slice(0, 5).map((user, index) => ({
        label: user.user.split('@')[0] || user.user,
        value: user.threatCount,
        tone: index === 0 ? 'bad' : index === 1 ? 'warn' : 'neutral'
    }));
}

function buildSunbirdEmailRecommendations(model, evidence) {
    const recs = [];
    if (evidence.highSeverityAlerts.length) {
        recs.push({ priority: 'critical', title: 'Review high severity email threats', detail: `${evidence.highSeverityAlerts.length} high severity alert(s) need investigation.` });
    }
    if (evidence.phishingAlerts.length) {
        recs.push({ priority: 'high', title: 'Strengthen phishing protection', detail: 'Review Safe Links, anti-phishing policy, and targeted user training.' });
    }
    if (evidence.malwareAlerts.length) {
        recs.push({ priority: 'high', title: 'Validate Safe Attachments coverage', detail: `${evidence.malwareAlerts.length} malware-related email alert(s) detected.` });
    }
    if (evidence.affectedUserRows.length > 5) {
        recs.push({ priority: 'medium', title: 'Prioritize targeted mailbox review', detail: `${evidence.affectedUserRows.length} users are represented in threat evidence.` });
    }
    const mailSummary = model.summary?.mailActivity || model.mailActivity?.summary || {};
    if ((mailSummary.activeMailboxes || 0) > 0) {
        recs.push({ priority: 'low', title: 'Review mailbox activity baseline', detail: `${mailSummary.activeMailboxes} active mailbox(es), ${mailSummary.totalMailActivity || 0} mail activity event(s) in the latest Exchange report.` });
    }
    if (!recs.length) {
        recs.push({ priority: 'low', title: 'Maintain monitoring baseline', detail: 'No urgent email-security recommendations from current evidence.' });
    }
    return recs;
}

function buildSunbirdEmailRiskTrend(alerts) {
    const now = new Date();
    const days = Array.from({ length: 7 }, (_, offset) => {
        const date = new Date(now);
        date.setDate(now.getDate() - (6 - offset));
        date.setHours(0, 0, 0, 0);
        return {
            date,
            label: date.toLocaleDateString(undefined, { weekday: 'short' }),
            critical: 0,
            high: 0,
            medium: 0
        };
    });
    alerts.forEach(alert => {
        const time = getSunbirdEmailTime(alert);
        if (!time) return;
        const date = new Date(time);
        date.setHours(0, 0, 0, 0);
        const bucket = days.find(day => day.date.getTime() === date.getTime());
        if (!bucket) return;
        const severity = String(alert.severity || 'low').toLowerCase();
        if (severity === 'critical') bucket.critical += 1;
        else if (severity === 'high') bucket.high += 1;
        else if (severity === 'medium') bucket.medium += 1;
    });
    return { days };
}

function getSunbirdEmailAlertsForUser(model, userName) {
    const target = String(userName || '').toLowerCase();
    return model.alerts
        .filter(alert => String(getSunbirdEmailTargetUser(alert)).toLowerCase() === target)
        .sort((a, b) => getSunbirdEmailTime(b) - getSunbirdEmailTime(a));
}

function formatSunbirdDateTime(value) {
    if (!value) return 'Unknown time';
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return 'Unknown time';
    return date.toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

window.openSunbirdEmailEvidence = openSunbirdEmailEvidence;
window.openSunbirdEmailUserEvidence = openSunbirdEmailUserEvidence;
window.closeSunbirdEmailEvidence = closeSunbirdEmailEvidence;
window.applySunbirdEmailTableFilter = applySunbirdEmailTableFilter;
window.toggleSunbirdEmailInsightEvidenceLock = toggleSunbirdEmailInsightEvidenceLock;
window.handleSunbirdEmailInsightEvidenceKey = handleSunbirdEmailInsightEvidenceKey;

const SUNBIRD_SECURITY_CACHE_KEY = 'sunbirdSecurityEventsDashboardSnapshot';
let sunbirdSecurityDashboardData = null;
let sunbirdSecurityTableState = { search: '', severity: 'all', status: 'all', source: 'all', sort: 'newest' };
let lockedSunbirdSecurityInsightEvidenceKey = null;
let sunbirdSecurityTrendWindow = '7d';

function openSunbirdSecurityDashboard() {
    const dashboardView = document.getElementById('dashboard-view');
    const projectsView = document.getElementById('projects-view');
    if (!dashboardView) return;

    if (projectsView) projectsView.style.display = 'none';
    dashboardView.style.display = 'block';
    dashboardView.style.visibility = 'visible';
    dashboardView.style.opacity = '1';
    dashboardView.classList.remove('sunbird-identity-active');
    dashboardView.classList.remove('sunbird-device-active');
    dashboardView.classList.remove('sunbird-email-active');
    dashboardView.classList.remove('sunbird-backup-active');
    dashboardView.classList.remove('sunbird-applications-active');
    dashboardView.classList.add('sunbird-security-active');

    captureDashboardViewHTML();
    dashboardView.innerHTML = renderSunbirdSecurityShell();
    setupSunbirdSecurityDashboard();

    const cached = readSunbirdSecuritySnapshot();
    sunbirdSecurityDashboardData = normalizeSunbirdSecurityData(cached || { success: true });
    renderSunbirdSecurityDashboard();
    loadSunbirdSecurityDashboardData();
}

function renderSunbirdSecurityShell() {
    return `
        <section class="sunbird-identity-dashboard sunbird-security-dashboard" id="sunbird-security-dashboard">
            <div class="sunbird-id-header">
                <button id="sunbird-security-back" class="sunbird-id-back-btn" type="button">
                    <span class="sunbird-id-back-icon" aria-hidden="true">&larr;</span>
                    <span>Back</span>
                </button>
                <div>
                    <h2>Security Alerts</h2>
                    <p>SOC threat intelligence, incidents, attack chain, and evidence.</p>
                </div>
                <div class="sunbird-id-microsoft-badge" aria-label="Microsoft Solutions">
                    <span class="sunbird-id-ms-logo" aria-hidden="true"><i></i><i></i><i></i><i></i></span>
                    <span>Microsoft Solutions</span>
                </div>
            </div>

            <div class="sunbird-id-metrics" id="sunbird-security-metrics"></div>
            <div class="sunbird-id-insights" id="sunbird-security-insights"></div>
            <div class="sunbird-id-charts" id="sunbird-security-charts"></div>
            <div class="sunbird-id-signins" id="sunbird-security-panels"></div>

            <section class="sunbird-id-table-section">
                <div class="sunbird-id-table-toolbar sunbird-security-table-toolbar">
                    <input id="sunbird-security-search" class="sunbird-id-search" type="search" placeholder="Search incident, alert, user, source, MITRE, region">
                    <select id="sunbird-security-severity-filter" class="sunbird-id-select">
                        <option value="all">All severity</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                    <select id="sunbird-security-status-filter" class="sunbird-id-select">
                        <option value="all">All status</option>
                        <option value="active">Active</option>
                        <option value="newalert">New</option>
                        <option value="inprogress">In progress</option>
                        <option value="resolved">Resolved</option>
                    </select>
                    <select id="sunbird-security-source-filter" class="sunbird-id-select">
                        <option value="all">All sources</option>
                        <option value="cloudflare">Cloudflare One</option>
                        <option value="alert">Alerts</option>
                        <option value="incident">Incidents</option>
                        <option value="signin">Sign-ins</option>
                        <option value="indicator">Indicators</option>
                    </select>
                    <select id="sunbird-security-sort" class="sunbird-id-select">
                        <option value="newest">Sort newest</option>
                        <option value="severity">Sort severity</option>
                        <option value="status">Sort status</option>
                    </select>
                    <button id="sunbird-security-clear" class="sunbird-id-clear-btn" type="button">Clear</button>
                </div>
                <div class="sunbird-id-table-wrap">
                    <table class="sunbird-id-table sunbird-security-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Severity</th>
                                <th>Type</th>
                                <th>Incident / Alert</th>
                                <th>Status</th>
                                <th>User / Asset</th>
                                <th>Source</th>
                                <th>Category</th>
                                <th>MITRE</th>
                                <th>Evidence</th>
                            </tr>
                        </thead>
                        <tbody id="sunbird-security-body"></tbody>
                    </table>
                </div>
            </section>

            <div class="sunbird-security-whatsapp-test">
                <button id="sunbird-security-whatsapp-test-btn" class="sunbird-security-whatsapp-btn" type="button">
                    <i class="fab fa-whatsapp" aria-hidden="true"></i>
                    <span>Send security alert test</span>
                </button>
                <p id="sunbird-security-whatsapp-test-status" aria-live="polite"></p>
            </div>
        </section>
        <div id="sunbird-security-evidence-modal" class="sunbird-id-modal" aria-hidden="true"></div>
    `;
}

function setupSunbirdSecurityDashboard() {
    document.getElementById('sunbird-security-back')?.addEventListener('click', goBackToProjects);
    document.getElementById('sunbird-security-whatsapp-test-btn')?.addEventListener('click', sendLatestSunbirdSecurityAlertToWhatsApp);
    document.getElementById('sunbird-security-search')?.addEventListener('input', event => {
        sunbirdSecurityTableState.search = event.target.value;
        renderSunbirdSecurityTable();
    });
    document.getElementById('sunbird-security-severity-filter')?.addEventListener('change', event => {
        sunbirdSecurityTableState.severity = event.target.value;
        renderSunbirdSecurityTable();
    });
    document.getElementById('sunbird-security-status-filter')?.addEventListener('change', event => {
        sunbirdSecurityTableState.status = event.target.value;
        renderSunbirdSecurityTable();
    });
    document.getElementById('sunbird-security-source-filter')?.addEventListener('change', event => {
        sunbirdSecurityTableState.source = event.target.value;
        renderSunbirdSecurityTable();
    });
    document.getElementById('sunbird-security-sort')?.addEventListener('change', event => {
        sunbirdSecurityTableState.sort = event.target.value;
        renderSunbirdSecurityTable();
    });
    document.getElementById('sunbird-security-clear')?.addEventListener('click', () => {
        sunbirdSecurityTableState = { search: '', severity: 'all', status: 'all', source: 'all', sort: 'newest' };
        ['sunbird-security-search', 'sunbird-security-severity-filter', 'sunbird-security-status-filter', 'sunbird-security-source-filter', 'sunbird-security-sort'].forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.value = id === 'sunbird-security-sort' ? 'newest' : id === 'sunbird-security-search' ? '' : 'all';
        });
        renderSunbirdSecurityTable();
    });
}

async function sendLatestSunbirdSecurityAlertToWhatsApp() {
    const button = document.getElementById('sunbird-security-whatsapp-test-btn');
    const status = document.getElementById('sunbird-security-whatsapp-test-status');
    const token = localStorage.getItem('authToken');

    if (!token) {
        if (status) {
            status.textContent = 'Please sign in again before sending a test alert.';
            status.className = 'error';
        }
        return;
    }

    if (button) {
        button.disabled = true;
        button.classList.add('is-loading');
    }
    if (status) {
        status.textContent = 'Sending security alert test...';
        status.className = '';
    }

    try {
        const response = await fetch('/api/whatsapp/test-hello', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.success) {
            throw new Error(data.message || data.error || `Request failed with status ${response.status}`);
        }

        if (status) {
            status.textContent = `Meta accepted security_alert: ${data.messageId || 'No message ID returned'}`;
            status.className = 'success';
        }
    } catch (error) {
        if (status) {
            status.textContent = `WhatsApp test failed: ${error.message}`;
            status.className = 'error';
        }
    } finally {
        if (button) {
            button.disabled = false;
            button.classList.remove('is-loading');
        }
    }
}

function readSunbirdSecuritySnapshot() {
    try {
        const parsed = JSON.parse(localStorage.getItem(SUNBIRD_SECURITY_CACHE_KEY) || 'null');
        return parsed?.summary || parsed?.alerts ? parsed : null;
    } catch (error) {
        return null;
    }
}

function saveSunbirdSecuritySnapshot(data) {
    if (!data?.summary && !data?.alerts) return;
    localStorage.setItem(SUNBIRD_SECURITY_CACHE_KEY, JSON.stringify({ ...data, savedAt: new Date().toISOString() }));
}

async function loadSunbirdSecurityDashboardData() {
    const token = localStorage.getItem('authToken');
    if (!token) return;
    try {
        const cachedResponse = await fetch('/api/db/security-events', {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        const cachedData = await cachedResponse.json();
        if (!cachedResponse.ok || !cachedData.success) throw new Error(cachedData.message || 'Cached security events unavailable');
        sunbirdSecurityDashboardData = normalizeSunbirdSecurityData(augmentSunbirdSecurityDataWithCloudflare(cachedData));
        saveSunbirdSecuritySnapshot(sunbirdSecurityDashboardData);
        renderSunbirdSecurityDashboard();
    } catch (cachedError) {
        try {
            const liveResponse = await fetch('/api/security-events', {
                method: 'GET',
                headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
            });
            const liveData = await liveResponse.json();
            if (!liveResponse.ok || !liveData.success) throw new Error(liveData.message || 'Security events unavailable');
            sunbirdSecurityDashboardData = normalizeSunbirdSecurityData(augmentSunbirdSecurityDataWithCloudflare(liveData));
            saveSunbirdSecuritySnapshot(sunbirdSecurityDashboardData);
            renderSunbirdSecurityDashboard();
        } catch (liveError) {
            console.warn('[Security Dashboard] Detailed SOC evidence unavailable:', liveError.message);
        }
    }
}

function normalizeSunbirdSecurityData(data = {}) {
    const augmentedData = augmentSunbirdSecurityDataWithCloudflare(data);
    const payload = augmentedData.payload && typeof augmentedData.payload === 'object' ? augmentedData.payload : augmentedData;
    const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
    const incidents = Array.isArray(payload.incidents) ? payload.incidents : [];
    const threats = Array.isArray(payload.threats) ? payload.threats : [];
    const suspiciousSignIns = Array.isArray(payload.signIns?.suspicious) ? payload.signIns.suspicious : [];
    const usersUnderAttack = Array.isArray(payload.signIns?.usersUnderAttack) ? payload.signIns.usersUnderAttack : [];
    const summary = payload.summary || {};
    const highSeverityAlerts = summary.highSeverityAlerts ?? alerts.filter(a => ['critical', 'high'].includes(String(a.severity || '').toLowerCase())).length;
    const activeIncidents = summary.activeIncidents ?? incidents.filter(i => ['active', 'inprogress', 'newalert'].includes(String(i.status || '').toLowerCase())).length;
    const totalAlerts = summary.totalAlerts ?? alerts.length;
    const securityScore = summary.securityScore ?? calculateSunbirdSecurityScore({ alerts, incidents, threats, suspiciousSignIns });
    return {
        ...payload,
        alerts,
        incidents,
        threats,
        signIns: { ...(payload.signIns || {}), suspicious: suspiciousSignIns, usersUnderAttack },
        activityFeed: Array.isArray(payload.activityFeed) ? payload.activityFeed : [],
        mitre: Array.isArray(payload.mitre) ? payload.mitre : buildSunbirdSecurityMitre(alerts, incidents, suspiciousSignIns, threats),
        topTargetedUsers: Array.isArray(payload.topTargetedUsers) ? payload.topTargetedUsers : buildSunbirdSecurityTargetedUsers(alerts, suspiciousSignIns),
        sourceDistribution: Array.isArray(payload.sourceDistribution) ? payload.sourceDistribution : countSunbirdSecurityBy(alerts, a => a.source || a.vendor || 'Microsoft Security'),
        categoryDistribution: Array.isArray(payload.categoryDistribution) ? payload.categoryDistribution : countSunbirdSecurityBy(alerts, a => a.category || 'Other'),
        regionDistribution: Array.isArray(payload.regionDistribution) ? payload.regionDistribution : countSunbirdSecurityBy(suspiciousSignIns, s => s.country || s.location || 'Unknown'),
        attackTimeline: Array.isArray(payload.attackTimeline) ? payload.attackTimeline : buildSunbirdSecurityTimeline(alerts, incidents, suspiciousSignIns, threats),
        aiSummary: payload.aiSummary || 'Security posture is currently based on cached Microsoft security evidence.',
        recommendations: Array.isArray(payload.recommendations) ? payload.recommendations : buildSunbirdSecurityRecommendations({ highSeverityAlerts, activeIncidents, usersUnderAttack, threats }),
        summary: {
            ...summary,
            activeIncidents,
            highSeverityAlerts,
            totalAlerts,
            threatIndicators: summary.threatIndicators ?? threats.length,
            usersUnderAttack: summary.usersUnderAttack ?? usersUnderAttack.length,
            securityScore
        }
    };
}

function buildSunbirdSecurityModel(data = sunbirdSecurityDashboardData) {
    const normalized = normalizeSunbirdSecurityData(data || {});
    const allEvents = getSunbirdSecurityEvents(normalized);
    const recommendations = normalized.recommendations.length ? normalized.recommendations : buildSunbirdSecurityRecommendations(normalized.summary);
    return {
        ...normalized,
        allEvents,
        recommendations,
        evidence: {
            allAlerts: normalized.alerts,
            activeIncidents: normalized.incidents.filter(i => ['active', 'inprogress', 'newalert'].includes(String(i.status || '').toLowerCase())),
            highSeverityAlerts: normalized.alerts.filter(a => ['critical', 'high'].includes(String(a.severity || '').toLowerCase())),
            cloudflareAlerts: normalized.alerts.filter(a => a.cloudflareOneSignal || /cloudflare/i.test(String(a.source || a.vendor || ''))),
            cloudflareIncidents: normalized.incidents.filter(i => i.cloudflareOneSignal || /cloudflare/i.test(String(i.source || ''))),
            threatIndicators: normalized.threats,
            suspiciousSignIns: normalized.signIns.suspicious,
            usersUnderAttack: normalized.signIns.usersUnderAttack,
            mitre: normalized.mitre,
            topTargetedUsers: normalized.topTargetedUsers,
            sourceDistribution: normalized.sourceDistribution,
            regionDistribution: normalized.regionDistribution,
            attackTimeline: normalized.attackTimeline,
            recommendations
        }
    };
}

function renderSunbirdSecurityDashboard() {
    const model = buildSunbirdSecurityModel();
    renderSunbirdSecurityMetrics(model);
    renderSunbirdSecurityInsights(model);
    renderSunbirdSecurityCharts(model);
    renderSunbirdSecurityPanels(model);
    renderSunbirdSecurityTable(model);
}

function renderSunbirdSecurityMetrics(model) {
    const el = document.getElementById('sunbird-security-metrics');
    if (!el) return;
    const metrics = [
        { label: 'Active Incidents', value: model.summary.activeIncidents, tone: model.summary.activeIncidents ? 'bad' : 'good', evidence: 'activeIncidents' },
        { label: 'High Severity', value: model.summary.highSeverityAlerts, tone: model.summary.highSeverityAlerts ? 'bad' : 'good', evidence: 'highSeverityAlerts' },
        { label: 'Total Alerts', value: model.summary.totalAlerts, tone: model.summary.totalAlerts ? 'warn' : 'good', evidence: 'allAlerts' },
        { label: 'Security Score', value: `${model.summary.securityScore || 0}%`, tone: model.summary.securityScore >= 80 ? 'good' : model.summary.securityScore >= 60 ? 'warn' : 'bad', evidence: 'recommendations' }
    ];
    el.innerHTML = metrics.map(metric => `
        <article class="sunbird-id-metric-card tone-${metric.tone}">
            <div class="sunbird-id-metric-value">${escapeIdentityText(metric.value)}</div>
            <div class="sunbird-id-metric-label">${escapeIdentityText(metric.label)}</div>
            <button type="button" onclick="openSunbirdSecurityEvidence('${metric.evidence}')" class="sunbird-id-evidence-btn">View Evidence</button>
        </article>
    `).join('');
}

function renderSunbirdSecurityInsights(model) {
    const el = document.getElementById('sunbird-security-insights');
    if (!el) return;
    const insights = [
        { title: 'Users under attack', value: model.evidence.usersUnderAttack.length, evidence: 'usersUnderAttack', tone: model.evidence.usersUnderAttack.length ? 'bad' : 'good' },
        { title: 'Threat indicators', value: model.summary.threatIndicators, evidence: 'threatIndicators', tone: model.summary.threatIndicators ? 'warn' : 'neutral' },
        { title: 'Suspicious sign-ins', value: model.evidence.suspiciousSignIns.length, evidence: 'suspiciousSignIns', tone: model.evidence.suspiciousSignIns.length ? 'bad' : 'good' },
        { title: 'Cloudflare One', value: model.evidence.cloudflareAlerts.length + model.evidence.cloudflareIncidents.length, evidence: 'cloudflareAlerts', tone: model.evidence.cloudflareIncidents.length ? 'bad' : model.evidence.cloudflareAlerts.length ? 'warn' : 'good' },
        { title: 'MITRE techniques', value: model.evidence.mitre.length, evidence: 'mitre', tone: model.evidence.mitre.length ? 'warn' : 'neutral' },
        { title: 'Attack regions', value: model.evidence.regionDistribution.length, evidence: 'regionDistribution', tone: model.evidence.regionDistribution.length ? 'warn' : 'neutral' },
        { title: 'Open incidents', value: model.evidence.activeIncidents.length, evidence: 'activeIncidents', tone: model.evidence.activeIncidents.length ? 'bad' : 'good' },
        { title: 'Recommendations', value: model.recommendations.length, evidence: 'recommendations', tone: model.recommendations.some(r => r.priority === 'critical') ? 'bad' : 'warn' }
    ];
    el.innerHTML = insights.map((item, index) => `
        <article class="sunbird-id-insight tone-${item.tone}" role="button" tabindex="0" data-security-evidence-key="${item.evidence}" onclick="toggleSunbirdSecurityInsightEvidenceLock('${item.evidence}')" onkeydown="handleSunbirdSecurityInsightEvidenceKey(event, '${item.evidence}')">
            <span>${escapeIdentityText(item.title)}</span>
            <strong>${escapeIdentityText(item.value)}</strong>
            ${renderSunbirdSecurityInsightEvidencePreview(item, model, index)}
        </article>
    `).join('');
}

function renderSunbirdSecurityInsightEvidencePreview(item, model, index) {
    const rows = getSunbirdSecurityEvidenceRows(item.evidence, model);
    return `
        <div class="sunbird-id-insight-evidence" onclick="event.stopPropagation()">
            <p>${rows.length} evidence item${rows.length === 1 ? '' : 's'} matched this SOC signal.</p>
            <div class="sunbird-id-insight-evidence-list">
                ${rows.slice(0, 4).map(row => `
                    <div>
                        <strong>${escapeIdentityText(row.title)}</strong>
                        <span>${escapeIdentityText(row.subtitle)}</span>
                        <small>${escapeIdentityText(row.meta)}</small>
                    </div>
                `).join('') || '<em>No evidence found.</em>'}
            </div>
            ${rows.length > 4 ? `<small>${rows.length - 4} more in full evidence</small>` : ''}
            <button type="button" onclick="openSunbirdSecurityEvidence('${item.evidence}', 'insight-${index}')">Open Evidence</button>
        </div>
    `;
}

function renderSunbirdSecurityCharts(model) {
    const el = document.getElementById('sunbird-security-charts');
    if (!el) return;
    const severityCounts = countSunbirdSecurityBy(model.alerts, a => String(a.severity || 'low').toLowerCase());
    const statusCounts = countSunbirdSecurityBy(model.incidents, i => String(i.status || 'active').toLowerCase());
    const severityValue = label => severityCounts.find(i => i.label === label)?.value || 0;
    const statusValue = label => statusCounts.find(i => i.label === label)?.value || 0;
    el.innerHTML = `
        ${renderSunbirdSecurityRiskTrendChart(model)}
        ${renderSunbirdPieChart('Alert severity', [
            { label: 'Critical', value: severityValue('critical'), tone: 'bad' },
            { label: 'High', value: severityValue('high'), tone: 'warn' },
            { label: 'Medium', value: severityValue('medium'), tone: 'neutral' },
            { label: 'Low', value: severityValue('low'), tone: 'good' }
        ], Math.max(1, model.alerts.length))}
        ${renderSunbirdPieChart('Incident status', [
            { label: 'Active', value: statusValue('active') + statusValue('inprogress') + statusValue('newalert'), tone: 'bad' },
            { label: 'Resolved', value: statusValue('resolved'), tone: 'good' },
            { label: 'Other', value: Math.max(0, model.incidents.length - statusValue('resolved') - statusValue('active') - statusValue('inprogress') - statusValue('newalert')), tone: 'neutral' }
        ], Math.max(1, model.incidents.length))}
        ${renderSunbirdSecurityRadar(model)}
        ${renderSunbirdDeviceBars('Top targeted users', model.topTargetedUsers.slice(0, 5).map((u, index) => ({ label: (u.user || 'Unknown').split('@')[0], value: u.total || u.failedAttempts || 0, tone: index === 0 ? 'bad' : index === 1 ? 'warn' : 'neutral' })), Math.max(1, ...model.topTargetedUsers.map(u => u.total || u.failedAttempts || 0)))}
        ${renderSunbirdDeviceBars('MITRE ATT&CK Mapping', model.mitre.slice(0, 5).map(item => ({ label: item.technique || item.tactic, value: item.count || 0, tone: ['critical', 'high'].includes(String(item.severity || '').toLowerCase()) ? 'bad' : 'warn' })), Math.max(1, ...model.mitre.map(item => item.count || 0)))}
        ${renderSunbirdDeviceBars('Threat source regions', model.regionDistribution.filter(item => item.value > 0 && !/^unknown$/i.test(String(item.label || ''))).slice(0, 5).map((item, index) => ({ label: item.label, value: item.value, tone: index === 0 ? 'warn' : 'neutral' })), Math.max(1, ...model.regionDistribution.map(item => item.value)), 'No region evidence returned.')}
    `;
    renderSunbirdSecurityRiskTrendCanvas(model);
    animateSunbirdIdentityCharts();
}

function renderSunbirdSecurityRiskTrendChart(model) {
    return `
        <article class="sunbird-id-chart-card sunbird-email-risk-trend-card sunbird-security-risk-trend-card">
            <div class="sunbird-security-chart-heading">
                <h3><i class="fas fa-chart-line"></i> Risk Assessment Overview</h3>
                <div class="sunbird-security-risk-window">
                    ${['24h', '7d', '30d'].map(windowKey => `<button type="button" class="${sunbirdSecurityTrendWindow === windowKey ? 'active' : ''}" onclick="setSunbirdSecurityTrendWindow('${windowKey}')">${windowKey}</button>`).join('')}
                </div>
            </div>
            <div class="sunbird-email-risk-legend">
                <span class="critical">Critical</span>
                <span class="high">High</span>
                <span class="medium">Medium</span>
            </div>
            <div class="sunbird-security-risk-chart-shell">
                <canvas id="sunbirdSecurityRiskTrendChart" aria-label="SOC risk trend" role="img"></canvas>
            </div>
        </article>
    `;
}

function renderSunbirdSecurityRiskTrendCanvas(model) {
    const canvas = document.getElementById('sunbirdSecurityRiskTrendChart');
    if (!canvas || typeof Chart === 'undefined') return;

    if (window.sunbirdSecurityRiskTrendChartInstance) {
        window.sunbirdSecurityRiskTrendChartInstance.destroy();
    }

    const trend = buildSunbirdSecurityRiskTrend(model.allEvents, sunbirdSecurityTrendWindow);
    const maxValue = Math.max(10, ...trend.days.flatMap(day => [day.critical, day.high, day.medium]));
    const makeDataset = (label, key, color) => ({
        label,
        data: trend.days.map(day => day[key]),
        borderColor: color,
        backgroundColor: 'transparent',
        borderWidth: 3,
        tension: 0.45,
        cubicInterpolationMode: 'monotone',
        fill: false,
        pointRadius: 3,
        pointHoverRadius: 5,
        pointBackgroundColor: color,
        pointBorderColor: color,
        pointBorderWidth: 1
    });

    window.sunbirdSecurityRiskTrendChartInstance = new Chart(canvas.getContext('2d'), {
        type: 'line',
        data: {
            labels: trend.days.map(day => day.label),
            datasets: [
                makeDataset('Critical', 'critical', '#ff3f5f'),
                makeDataset('High', 'high', '#ffd000'),
                makeDataset('Medium', 'medium', '#ff9f1c')
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(2, 6, 23, 0.94)',
                    borderColor: 'rgba(148, 163, 184, 0.28)',
                    borderWidth: 1,
                    titleColor: '#f8fafc',
                    bodyColor: '#e2e8f0',
                    displayColors: true,
                    padding: 12,
                    callbacks: {
                        label(context) {
                            return `${context.dataset.label}: ${context.parsed.y}`;
                        }
                    }
                }
            },
            onClick(event, elements) {
                const point = elements?.[0];
                if (!point) return;
                const dataset = this.data.datasets[point.datasetIndex];
                const day = trend.days[point.index];
                if (!dataset || !day) return;
                openSunbirdSecurityTrendEvidence(day.key, String(dataset.label || '').toLowerCase());
            },
            scales: {
                y: {
                    min: 0,
                    suggestedMax: maxValue,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.08)',
                        drawBorder: false
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.72)',
                        stepSize: 1,
                        callback(value) {
                            return value === 0 ? '' : value;
                        }
                    }
                },
                x: {
                    grid: {
                        display: false,
                        drawBorder: false
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.72)'
                    }
                }
            }
        }
    });
}

function renderSunbirdSecurityRadar(model) {
    const axes = [
        { label: 'Identity Risk', value: Math.max(20, 100 - model.signIns.suspicious.length * 4) },
        { label: 'Device Risk', value: Math.max(35, 100 - model.alerts.filter(a => /device|endpoint/i.test(`${a.title || ''} ${a.category || ''}`)).length * 8) },
        { label: 'Email Risk', value: Math.max(35, 100 - model.alerts.filter(a => /email|phish|mail/i.test(`${a.title || ''} ${a.category || ''}`)).length * 8) },
        { label: 'App Risk', value: Math.max(40, 100 - model.alerts.filter(a => /app|cloud/i.test(`${a.title || ''} ${a.category || ''}`)).length * 8) },
        { label: 'Incident Response', value: Math.max(20, 100 - model.summary.activeIncidents * 12) },
        { label: 'Compliance', value: model.summary.securityScore || 0 }
    ];
    const center = 86;
    const radius = 62;
    const points = axes.map((axis, index) => {
        const angle = (-90 + (360 / axes.length) * index) * Math.PI / 180;
        const scaled = radius * (axis.value / 100);
        return `${center + Math.cos(angle) * scaled},${center + Math.sin(angle) * scaled}`;
    }).join(' ');
    return `
        <article class="sunbird-id-chart-card sunbird-security-radar-card">
            <h3><i class="fas fa-heart-pulse"></i> SOC Health Radar</h3>
            <svg class="sunbird-security-radar" viewBox="0 0 172 172" role="img" aria-label="SOC health radar">
                <polygon class="grid" points="${axes.map((_, index) => {
                    const angle = (-90 + (360 / axes.length) * index) * Math.PI / 180;
                    return `${center + Math.cos(angle) * radius},${center + Math.sin(angle) * radius}`;
                }).join(' ')}"></polygon>
                <polygon class="value" points="${points}"></polygon>
                ${axes.map((axis, index) => {
                    const angle = (-90 + (360 / axes.length) * index) * Math.PI / 180;
                    const x = center + Math.cos(angle) * (radius + 18);
                    const y = center + Math.sin(angle) * (radius + 18);
                    return `<text x="${x}" y="${y}">${escapeIdentityText(axis.label.split(' ')[0])}</text>`;
                }).join('')}
            </svg>
        </article>
    `;
}

function renderSunbirdSecurityPanels(model) {
    const el = document.getElementById('sunbird-security-panels');
    if (!el) return;
    el.innerHTML = `
        ${renderSunbirdSecurityFeedPanel('Real-time threat feed', getSunbirdSecurityEvidenceRows('attackTimeline', model).slice(0, 10))}
        ${renderSunbirdSecurityFeedPanel('Attack timeline', getSunbirdSecurityEvidenceRows('attackTimeline', model).slice(0, 10))}
        ${renderSunbirdSecurityFeedPanel('MITRE ATT&CK mapping', getSunbirdSecurityEvidenceRows('mitre', model).slice(0, 10))}
        ${renderSunbirdSecuritySummaryPanel(model)}
    `;
}

function renderSunbirdSecurityFeedPanel(title, rows) {
    return `
        <article class="sunbird-id-signin-card">
            <h3>${escapeIdentityText(title)}</h3>
            <div class="sunbird-id-signin-list">
                ${rows.length ? rows.map(row => `
                    <div class="sunbird-id-signin-item">
                        <div>
                            <strong>${escapeIdentityText(row.title)}</strong>
                            <span>${escapeIdentityText(row.subtitle)}</span>
                            <div class="sunbird-id-issue-tags"><em>${escapeIdentityText(row.meta)}</em></div>
                        </div>
                    </div>
                `).join('') : '<div class="sunbird-id-empty compact">No matching SOC evidence.</div>'}
            </div>
        </article>
    `;
}

function renderSunbirdSecuritySummaryPanel(model) {
    return `
        <article class="sunbird-id-signin-card sunbird-security-ai-card">
            <h3>AI security summary</h3>
            <p>${escapeIdentityText(model.aiSummary)}</p>
            <div class="sunbird-id-signin-list">
                ${model.recommendations.slice(0, 6).map(item => `
                    <div class="sunbird-id-signin-item">
                        <div>
                            <strong>${escapeIdentityText(item.title)}</strong>
                            <span>${escapeIdentityText(item.detail)}</span>
                            <div class="sunbird-id-issue-tags"><em>${escapeIdentityText(item.priority || 'medium')}</em></div>
                        </div>
                    </div>
                `).join('')}
            </div>
        </article>
    `;
}

function renderSunbirdSecurityTable(model = buildSunbirdSecurityModel()) {
    const body = document.getElementById('sunbird-security-body');
    if (!body) return;
    const events = getFilteredSunbirdSecurityEvents(model);
    if (!events.length) {
        body.innerHTML = '<tr><td colspan="10" class="sunbird-id-empty">No SOC evidence matches the current filters.</td></tr>';
        return;
    }
    body.innerHTML = events.map(event => {
        const severity = String(event.severity || 'low').toLowerCase();
        const mitre = getSunbirdSecurityMitre(event);
        return `
            <tr>
                <td data-label="Time">${escapeIdentityText(formatSunbirdDeviceDate(event.timestamp))}</td>
                <td data-label="Severity"><span class="sunbird-id-risk ${severity === 'critical' || severity === 'high' ? 'high' : severity === 'medium' ? 'medium' : 'safe'}">${escapeIdentityText(severity)}</span></td>
                <td data-label="Type"><span class="sunbird-id-role-list"><span>${escapeIdentityText(event.recordType || 'event')}</span></span></td>
                <td data-label="Incident / Alert">${escapeIdentityText(event.title || event.displayName || event.name || event.message || 'Security event')}</td>
                <td data-label="Status"><span class="sunbird-id-pill">${escapeIdentityText(event.status || event.riskLevel || 'observed')}</span></td>
                <td data-label="User / Asset">${escapeIdentityText(event.user || event.assignedTo || event.indicator || 'Unknown')}</td>
                <td data-label="Source">${escapeIdentityText(event.source || event.vendor || event.type || 'Microsoft Security')}</td>
                <td data-label="Category">${escapeIdentityText(event.category || event.location || event.action || 'SOC signal')}</td>
                <td data-label="MITRE">${escapeIdentityText(`${mitre.tactic} / ${mitre.technique}`)}</td>
                <td data-label="Evidence"><button type="button" class="sunbird-id-evidence-btn" onclick='openSunbirdSecurityEventEvidence(${JSON.stringify(event.uid)})'>Open</button></td>
            </tr>
        `;
    }).join('');
}

function getFilteredSunbirdSecurityEvents(model = buildSunbirdSecurityModel()) {
    const search = sunbirdSecurityTableState.search.trim().toLowerCase();
    return model.allEvents.filter(event => {
        const severity = String(event.severity || 'low').toLowerCase();
        const status = String(event.status || event.riskLevel || '').toLowerCase();
        const type = String(event.recordType || '').toLowerCase();
        const mitre = getSunbirdSecurityMitre(event);
        const haystack = [
            event.title, event.displayName, event.name, event.message, event.description,
            event.user, event.assignedTo, event.indicator, event.source, event.vendor,
            event.category, event.location, event.ipAddress, mitre.tactic, mitre.technique,
            severity, status, type
        ].join(' ').toLowerCase();
        if (search && !haystack.includes(search)) return false;
        if (sunbirdSecurityTableState.severity !== 'all' && severity !== sunbirdSecurityTableState.severity) return false;
        if (sunbirdSecurityTableState.status !== 'all' && status !== sunbirdSecurityTableState.status) return false;
        if (sunbirdSecurityTableState.source === 'cloudflare' && !/cloudflare/i.test([event.source, event.vendor, event.recordType, event.type].filter(Boolean).join(' '))) return false;
        if (sunbirdSecurityTableState.source !== 'all' && sunbirdSecurityTableState.source !== 'cloudflare' && type !== sunbirdSecurityTableState.source) return false;
        return true;
    }).sort((a, b) => {
        if (sunbirdSecurityTableState.sort === 'severity') return getSunbirdSecuritySeverityRank(b.severity) - getSunbirdSecuritySeverityRank(a.severity);
        if (sunbirdSecurityTableState.sort === 'status') return String(a.status || '').localeCompare(String(b.status || ''));
        return getSunbirdSecurityTime(b) - getSunbirdSecurityTime(a);
    });
}

function applySunbirdSecurityTableFilter(filter = {}) {
    sunbirdSecurityTableState = { ...sunbirdSecurityTableState, ...filter };
    const setValue = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.value = value;
    };
    setValue('sunbird-security-severity-filter', sunbirdSecurityTableState.severity);
    setValue('sunbird-security-status-filter', sunbirdSecurityTableState.status);
    setValue('sunbird-security-source-filter', sunbirdSecurityTableState.source);
    setValue('sunbird-security-sort', sunbirdSecurityTableState.sort);
    renderSunbirdSecurityTable();
    document.querySelector('.sunbird-security-dashboard .sunbird-id-table-section')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function openSunbirdSecurityEvidence(evidenceKey) {
    const model = buildSunbirdSecurityModel();
    const rows = getSunbirdSecurityEvidenceRows(evidenceKey, model);
    const modal = document.getElementById('sunbird-security-evidence-modal');
    if (!modal) return;
    const titleMap = {
        allAlerts: 'Security Alert Evidence',
        activeIncidents: 'Active Incidents',
        highSeverityAlerts: 'High Severity Alerts',
        cloudflareAlerts: 'Cloudflare One Evidence',
        threatIndicators: 'Threat Indicators',
        suspiciousSignIns: 'Suspicious Sign-ins',
        usersUnderAttack: 'Users Under Attack',
        mitre: 'MITRE ATT&CK Evidence',
        topTargetedUsers: 'Top Targeted Users',
        regionDistribution: 'Threat Source Regions',
        attackTimeline: 'Attack Timeline',
        recommendations: 'Security Recommendations',
        sourceDistribution: 'Alert Sources'
    };
    const filterMap = {
        highSeverityAlerts: { severity: 'high', source: 'alert' },
        activeIncidents: { source: 'incident' },
        cloudflareAlerts: { source: 'cloudflare' },
        suspiciousSignIns: { source: 'signin' },
        threatIndicators: { source: 'indicator' }
    };
    modal.innerHTML = `
        <div class="sunbird-id-modal-backdrop" onclick="closeSunbirdSecurityEvidence()"></div>
        <div class="sunbird-id-modal-panel" role="dialog" aria-modal="true">
            <div class="sunbird-id-modal-header">
                <div>
                    <h3>${escapeIdentityText(titleMap[evidenceKey] || 'SOC Evidence')}</h3>
                    <p>${rows.length} evidence item${rows.length === 1 ? '' : 's'} matched this set.</p>
                </div>
                <button type="button" onclick="closeSunbirdSecurityEvidence()" class="sunbird-id-modal-close">&times;</button>
            </div>
            <div class="sunbird-id-evidence-summary">
                <span>Alerts: ${model.summary.totalAlerts || 0}</span>
                <span>Incidents: ${model.summary.activeIncidents || 0}</span>
                <span>Score: ${model.summary.securityScore || 0}%</span>
            </div>
            <div class="sunbird-id-evidence-list">
                ${rows.length ? rows.slice(0, 120).map(row => `
                    <div class="sunbird-id-evidence-user">
                        <strong>${escapeIdentityText(row.title)}</strong>
                        <span>${escapeIdentityText(row.subtitle)}</span>
                        <small>${escapeIdentityText(row.meta)}</small>
                    </div>
                `).join('') : '<div class="sunbird-id-empty">No evidence found for this item.</div>'}
            </div>
            <div class="sunbird-id-modal-actions">
                <button type="button" class="sunbird-id-evidence-btn" onclick='applySunbirdSecurityTableFilter(${JSON.stringify(filterMap[evidenceKey] || {})}); closeSunbirdSecurityEvidence();'>View in Table</button>
            </div>
        </div>
    `;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
}

function openSunbirdSecurityTrendEvidence(dayKey, severity) {
    const model = buildSunbirdSecurityModel();
    const rows = model.allEvents
        .filter(event => getSunbirdSecurityDayKey(event.timestamp) === dayKey && String(event.severity || 'low').toLowerCase() === severity)
        .map(event => ({
            title: event.title || event.displayName || event.name || 'Security event',
            subtitle: event.user || event.source || event.location || 'Microsoft Security',
            meta: `${formatSunbirdDateTime(event.timestamp)} | ${severity}`
        }));
    openSunbirdSecurityRowsModal(`${severity} alerts on ${dayKey}`, rows);
}

function openSunbirdSecurityEventEvidence(uid) {
    const model = buildSunbirdSecurityModel();
    const event = model.allEvents.find(item => item.uid === uid);
    if (!event) return;
    const mitre = getSunbirdSecurityMitre(event);
    openSunbirdSecurityRowsModal(event.title || event.displayName || event.name || 'Security evidence', [{
        title: event.description || event.message || event.name || 'SOC evidence',
        subtitle: `${event.user || event.source || event.location || 'Microsoft Security'} | ${event.status || event.riskLevel || 'observed'}`,
        meta: `${formatSunbirdDateTime(event.timestamp)} | ${event.severity || 'low'} | ${mitre.tactic} / ${mitre.technique}`
    }]);
}

function openSunbirdSecurityRowsModal(title, rows) {
    const modal = document.getElementById('sunbird-security-evidence-modal');
    if (!modal) return;
    modal.innerHTML = `
        <div class="sunbird-id-modal-backdrop" onclick="closeSunbirdSecurityEvidence()"></div>
        <div class="sunbird-id-modal-panel" role="dialog" aria-modal="true">
            <div class="sunbird-id-modal-header">
                <div><h3>${escapeIdentityText(title)}</h3><p>${rows.length} evidence item${rows.length === 1 ? '' : 's'}.</p></div>
                <button type="button" onclick="closeSunbirdSecurityEvidence()" class="sunbird-id-modal-close">&times;</button>
            </div>
            <div class="sunbird-id-evidence-list">
                ${rows.map(row => `<div class="sunbird-id-evidence-user"><strong>${escapeIdentityText(row.title)}</strong><span>${escapeIdentityText(row.subtitle)}</span><small>${escapeIdentityText(row.meta)}</small></div>`).join('') || '<div class="sunbird-id-empty">No evidence found.</div>'}
            </div>
            <div class="sunbird-id-modal-actions"><button type="button" class="sunbird-id-evidence-btn" onclick="closeSunbirdSecurityEvidence()">Close</button></div>
        </div>
    `;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
}

function closeSunbirdSecurityEvidence() {
    const modal = document.getElementById('sunbird-security-evidence-modal');
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
}

function getSunbirdSecurityEvidenceRows(evidenceKey, model = buildSunbirdSecurityModel()) {
    if (evidenceKey === 'activeIncidents') return model.evidence.activeIncidents.map(i => ({ title: i.displayName || 'Incident', subtitle: i.description || i.assignedTo || 'Incident evidence', meta: `${formatSunbirdDateTime(i.created)} | ${i.severity || 'medium'} | ${i.status || 'active'}` }));
    if (evidenceKey === 'allAlerts' || evidenceKey === 'highSeverityAlerts') return model.evidence[evidenceKey].map(a => ({ title: a.title || 'Security alert', subtitle: a.description || a.user || a.source || 'Alert evidence', meta: `${formatSunbirdDateTime(a.created)} | ${a.severity || 'low'} | ${a.category || a.source || 'Microsoft Security'}` }));
    if (evidenceKey === 'cloudflareAlerts') return [...model.evidence.cloudflareIncidents, ...model.evidence.cloudflareAlerts].map(item => ({ title: item.title || item.displayName || 'Cloudflare One signal', subtitle: item.description || item.category || 'Cloudflare evidence', meta: `${formatSunbirdDateTime(item.created)} | ${item.severity || 'medium'} | ${item.status || 'active'}` }));
    if (evidenceKey === 'threatIndicators') return model.threats.map(t => ({ title: t.indicator || 'Threat indicator', subtitle: t.description || t.type || 'Indicator evidence', meta: `${formatSunbirdDateTime(t.created)} | ${t.severity || 'medium'} | ${t.action || 'Block'}` }));
    if (evidenceKey === 'suspiciousSignIns') return model.signIns.suspicious.map(s => ({ title: s.user || 'Suspicious sign-in', subtitle: `${s.ipAddress || 'Unknown IP'} | ${s.location || 'Unknown location'}`, meta: `${formatSunbirdDateTime(s.timestamp)} | ${s.status || 'Failed'} | ${s.failureReason || s.riskLevel || 'Risk signal'}` }));
    if (evidenceKey === 'usersUnderAttack') return model.signIns.usersUnderAttack.map(u => ({ title: u.user || 'Unknown user', subtitle: `${u.failedAttempts || u.total || 0} failed or suspicious attempt(s)`, meta: 'Repeated risky activity' }));
    if (evidenceKey === 'mitre') return model.mitre.map(m => ({ title: `${m.tactic || 'Tactic'} / ${m.technique || 'Technique'}`, subtitle: `${m.count || 0} mapped event(s)`, meta: `${m.severity || 'medium'} severity peak` }));
    if (evidenceKey === 'topTargetedUsers') return model.topTargetedUsers.map(u => ({ title: u.user || 'Unknown user', subtitle: `${u.total || u.failedAttempts || 0} security signal(s)`, meta: `${u.alerts || 0} alert(s), ${u.signIns || 0} sign-in signal(s)` }));
    if (evidenceKey === 'regionDistribution' || evidenceKey === 'sourceDistribution') return model.evidence[evidenceKey].map(item => ({ title: item.label || 'Unknown', subtitle: `${item.value || 0} event(s)`, meta: evidenceKey === 'regionDistribution' ? 'Threat source region' : 'Alert source' }));
    if (evidenceKey === 'attackTimeline') return model.attackTimeline.map(item => ({ title: item.title || 'Security event', subtitle: item.subtitle || item.type || 'SOC event', meta: `${formatSunbirdDateTime(item.timestamp)} | ${item.severity || 'medium'}${item.mitre ? ` | ${item.mitre.tactic}/${item.mitre.technique}` : ''}` }));
    if (evidenceKey === 'recommendations') return model.recommendations.map(item => ({ title: item.title, subtitle: item.detail, meta: item.priority || 'medium' }));
    return [];
}

function toggleSunbirdSecurityInsightEvidenceLock(evidenceKey) {
    const tile = document.querySelector(`.sunbird-id-insight[data-security-evidence-key="${evidenceKey}"]`);
    if (!tile) return;
    const shouldLock = lockedSunbirdSecurityInsightEvidenceKey !== evidenceKey;
    document.querySelectorAll('.sunbird-id-insight.locked').forEach(item => item.classList.remove('locked'));
    lockedSunbirdSecurityInsightEvidenceKey = shouldLock ? evidenceKey : null;
    if (shouldLock) tile.classList.add('locked');
}

function handleSunbirdSecurityInsightEvidenceKey(event, evidenceKey) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    toggleSunbirdSecurityInsightEvidenceLock(evidenceKey);
}

function setSunbirdSecurityTrendWindow(value) {
    sunbirdSecurityTrendWindow = value;
    renderSunbirdSecurityCharts(buildSunbirdSecurityModel());
}

function getSunbirdSecurityEvents(data) {
    return [
        ...(data.alerts || []).map((item, index) => ({ ...item, uid: `alert-${item.id || index}`, recordType: 'alert', timestamp: item.created || item.eventTime || item.createdDateTime, name: item.title })),
        ...(data.incidents || []).map((item, index) => ({ ...item, uid: `incident-${item.id || index}`, recordType: 'incident', timestamp: item.created || item.updated || item.createdDateTime, name: item.displayName, source: item.source || 'Microsoft Incident' })),
        ...(data.signIns?.suspicious || []).map((item, index) => ({ ...item, uid: `signin-${item.id || index}`, recordType: 'signin', timestamp: item.timestamp || item.createdDateTime, title: item.failureReason || 'Suspicious sign-in', severity: item.status === 'Failed' ? 'medium' : 'low', source: 'Microsoft Entra ID', category: item.location })),
        ...(data.threats || []).map((item, index) => ({ ...item, uid: `indicator-${item.id || index}`, recordType: 'indicator', timestamp: item.created || item.createdDateTime, title: item.indicator, source: item.type || 'Threat indicator', status: item.action || 'Observed' }))
    ];
}

function getSunbirdSecurityTime(item) {
    const raw = item?.timestamp || item?.created || item?.updated || item?.eventTime || item?.createdDateTime;
    const time = raw ? new Date(raw).getTime() : 0;
    return Number.isFinite(time) ? time : 0;
}

function getSunbirdSecuritySeverityRank(value) {
    const severity = String(value || 'low').toLowerCase();
    if (severity === 'critical') return 4;
    if (severity === 'high') return 3;
    if (severity === 'medium') return 2;
    return 1;
}

function getSunbirdSecurityMitre(item = {}) {
    const text = [item.title, item.displayName, item.name, item.description, item.category, item.source, item.message].filter(Boolean).join(' ').toLowerCase();
    if (/phish|spoof|email|mail|bec/.test(text)) return { tactic: 'Initial Access', technique: 'Phishing' };
    if (/credential|password|signin|sign-in|login|mfa|account|impossible travel/.test(text)) return { tactic: 'Credential Access', technique: 'Valid Accounts' };
    if (/malware|ransom|payload|execution|script|virus/.test(text)) return { tactic: 'Execution', technique: 'Malware' };
    if (/persist|startup|autorun|scheduled task/.test(text)) return { tactic: 'Persistence', technique: 'Account Persistence' };
    return { tactic: 'Defense Evasion', technique: 'Suspicious Activity' };
}

function countSunbirdSecurityBy(rows, getter) {
    const counts = {};
    rows.forEach(row => {
        const label = getter(row) || 'Unknown';
        counts[label] = (counts[label] || 0) + 1;
    });
    return Object.entries(counts).map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value);
}

function buildSunbirdSecurityMitre(alerts, incidents, signIns, threats) {
    const map = {};
    getSunbirdSecurityEvents({ alerts, incidents, threats, signIns: { suspicious: signIns } }).forEach(event => {
        const mitre = getSunbirdSecurityMitre(event);
        const key = `${mitre.tactic}/${mitre.technique}`;
        map[key] = map[key] || { ...mitre, count: 0, severity: 'low' };
        map[key].count += 1;
        if (getSunbirdSecuritySeverityRank(event.severity) > getSunbirdSecuritySeverityRank(map[key].severity)) map[key].severity = event.severity || 'medium';
    });
    return Object.values(map).sort((a, b) => b.count - a.count);
}

function buildSunbirdSecurityTargetedUsers(alerts, signIns) {
    const counts = {};
    alerts.forEach(alert => {
        const user = alert.user || 'Unknown user';
        counts[user] = counts[user] || { user, total: 0, alerts: 0, signIns: 0 };
        counts[user].total += 1;
        counts[user].alerts += 1;
    });
    signIns.forEach(signIn => {
        const user = signIn.user || 'Unknown user';
        counts[user] = counts[user] || { user, total: 0, alerts: 0, signIns: 0 };
        counts[user].total += 1;
        counts[user].signIns += 1;
    });
    return Object.values(counts).sort((a, b) => b.total - a.total).slice(0, 15);
}

function buildSunbirdSecurityTimeline(alerts, incidents, signIns, threats) {
    return getSunbirdSecurityEvents({ alerts, incidents, threats, signIns: { suspicious: signIns } })
        .sort((a, b) => getSunbirdSecurityTime(b) - getSunbirdSecurityTime(a))
        .slice(0, 50)
        .map(event => ({
            type: event.recordType,
            title: event.title || event.displayName || event.name || 'Security event',
            subtitle: event.user || event.source || event.location || 'Microsoft Security',
            timestamp: event.timestamp,
            severity: event.severity || 'medium',
            mitre: getSunbirdSecurityMitre(event)
        }));
}

function buildSunbirdSecurityRecommendations(input = {}) {
    const summary = input.summary || input;
    const recs = [];
    if (summary.highSeverityAlerts) recs.push({ priority: 'critical', title: 'Review critical and high alerts', detail: `${summary.highSeverityAlerts} alert(s) need SOC triage.` });
    if (summary.activeIncidents) recs.push({ priority: 'high', title: 'Triage active incidents', detail: `${summary.activeIncidents} active incident(s) are still open.` });
    if (Array.isArray(input.usersUnderAttack) && input.usersUnderAttack.length) recs.push({ priority: 'high', title: 'Investigate users under attack', detail: `${input.usersUnderAttack.length} user(s) show repeated suspicious activity.` });
    if (Array.isArray(input.threats) && input.threats.length) recs.push({ priority: 'medium', title: 'Validate threat indicators', detail: `${input.threats.length} threat indicator(s) should be reviewed.` });
    if (!recs.length) recs.push({ priority: 'low', title: 'Maintain SOC monitoring', detail: 'No urgent recommendations in the cached security evidence.' });
    return recs;
}

function calculateSunbirdSecurityScore({ alerts = [], incidents = [], threats = [], suspiciousSignIns = [] }) {
    let score = 100;
    alerts.slice(0, 30).forEach(alert => {
        const severity = String(alert.severity || 'low').toLowerCase();
        score -= severity === 'critical' ? 18 : severity === 'high' ? 12 : severity === 'medium' ? 5 : 2;
    });
    score -= incidents.filter(i => ['active', 'inprogress'].includes(String(i.status || '').toLowerCase())).length * 8;
    score -= threats.length * 2;
    score -= suspiciousSignIns.length;
    return Math.max(0, Math.min(100, score));
}

function buildSunbirdSecurityRiskTrend(events, windowKey = '7d') {
    const now = new Date();
    const count = windowKey === '24h' ? 7 : windowKey === '30d' ? 10 : 7;
    const days = Array.from({ length: count }, (_, offset) => {
        const date = new Date(now);
        if (windowKey === '24h') date.setHours(now.getHours() - (count - 1 - offset), 0, 0, 0);
        else date.setDate(now.getDate() - ((count - 1 - offset) * (windowKey === '30d' ? 3 : 1)));
        if (windowKey !== '24h') date.setHours(0, 0, 0, 0);
        return {
            date,
            key: getSunbirdSecurityDayKey(date),
            label: windowKey === '24h' ? date.toLocaleTimeString(undefined, { hour: '2-digit' }) : date.toLocaleDateString(undefined, { weekday: 'short' }),
            critical: 0,
            high: 0,
            medium: 0
        };
    });
    events.forEach(event => {
        const eventDate = new Date(event.timestamp || event.created || event.updated || event.eventTime || 0);
        if (!Number.isFinite(eventDate.getTime())) return;
        const bucket = days.find(day => getSunbirdSecurityDayKey(eventDate) === day.key);
        if (!bucket) return;
        const severity = String(event.severity || 'low').toLowerCase();
        if (severity === 'critical') bucket.critical += 1;
        else if (severity === 'high') bucket.high += 1;
        else if (severity === 'medium') bucket.medium += 1;
    });
    return { days };
}

function getSunbirdSecurityDayKey(value) {
    const date = value instanceof Date ? value : new Date(value);
    if (!Number.isFinite(date.getTime())) return 'unknown';
    return `${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()}`;
}

window.openSunbirdSecurityDashboard = openSunbirdSecurityDashboard;
window.openSunbirdSecurityEvidence = openSunbirdSecurityEvidence;
window.openSunbirdSecurityEventEvidence = openSunbirdSecurityEventEvidence;
window.openSunbirdSecurityTrendEvidence = openSunbirdSecurityTrendEvidence;
window.closeSunbirdSecurityEvidence = closeSunbirdSecurityEvidence;
window.applySunbirdSecurityTableFilter = applySunbirdSecurityTableFilter;
window.toggleSunbirdSecurityInsightEvidenceLock = toggleSunbirdSecurityInsightEvidenceLock;
window.handleSunbirdSecurityInsightEvidenceKey = handleSunbirdSecurityInsightEvidenceKey;
window.setSunbirdSecurityTrendWindow = setSunbirdSecurityTrendWindow;

const SUNBIRD_BACKUP_CACHE_KEY = 'sunbirdBackupRecoveryDashboardSnapshot';
let sunbirdBackupTableState = { search: '', service: 'all', activity: 'all', sort: 'storage' };
let lockedSunbirdBackupInsightEvidenceKey = null;

function openSunbirdBackupDashboard() {
    const dashboardView = document.getElementById('dashboard-view');
    const projectsView = document.getElementById('projects-view');
    if (!dashboardView) return;

    if (projectsView) projectsView.style.display = 'none';
    dashboardView.style.display = 'block';
    dashboardView.style.visibility = 'visible';
    dashboardView.style.opacity = '1';
    dashboardView.classList.remove('sunbird-identity-active');
    dashboardView.classList.remove('sunbird-device-active');
    dashboardView.classList.remove('sunbird-email-active');
    dashboardView.classList.remove('sunbird-security-active');
    dashboardView.classList.add('sunbird-backup-active');

    captureDashboardViewHTML();
    dashboardView.innerHTML = renderSunbirdBackupShell();
    setupSunbirdBackupDashboard();

    const cached = readSunbirdBackupSnapshot();
    cachedSunbirdBackupData = normalizeSunbirdBackupData(cached || cachedSunbirdBackupData || { success: true });
    renderSunbirdBackupDashboard();
    loadSunbirdBackupDashboardData();
}

function renderSunbirdBackupShell() {
    return `
        <section class="sunbird-identity-dashboard sunbird-backup-dashboard" id="sunbird-backup-dashboard">
            <div class="sunbird-id-header">
                <button id="sunbird-backup-back" class="sunbird-id-back-btn" type="button">
                    <span class="sunbird-id-back-icon" aria-hidden="true">&larr;</span>
                    <span>Back</span>
                </button>
                <div>
                    <h2>Backup & Recovery</h2>
                    <p>Microsoft 365 storage, activity, coverage, and recovery evidence.</p>
                </div>
                <div class="sunbird-id-microsoft-badge" aria-label="Microsoft Solutions">
                    <span class="sunbird-id-ms-logo" aria-hidden="true"><i></i><i></i><i></i><i></i></span>
                    <span>Microsoft Solutions</span>
                </div>
            </div>

            <div class="sunbird-id-metrics" id="sunbird-backup-metrics"></div>
            <div class="sunbird-id-insights" id="sunbird-backup-insights"></div>
            <div class="sunbird-id-charts" id="sunbird-backup-charts"></div>
            <div class="sunbird-id-signins" id="sunbird-backup-panels"></div>

            <section class="sunbird-id-table-section">
                <div class="sunbird-id-table-toolbar sunbird-backup-table-toolbar">
                    <input id="sunbird-backup-search" class="sunbird-id-search" type="search" placeholder="Search user, site, service, activity, storage">
                    <select id="sunbird-backup-service-filter" class="sunbird-id-select">
                        <option value="all">All services</option>
                        <option value="OneDrive">OneDrive</option>
                        <option value="SharePoint">SharePoint</option>
                        <option value="Exchange">Exchange</option>
                    </select>
                    <select id="sunbird-backup-activity-filter" class="sunbird-id-select">
                        <option value="all">All activity</option>
                        <option value="active">Active</option>
                        <option value="inactive">Inactive</option>
                    </select>
                    <select id="sunbird-backup-sort" class="sunbird-id-select">
                        <option value="storage">Sort storage</option>
                        <option value="activity">Sort last activity</option>
                        <option value="service">Sort service</option>
                    </select>
                    <button id="sunbird-backup-clear" class="sunbird-id-clear-btn" type="button">Clear</button>
                    <button id="sunbird-backup-export" class="sunbird-id-clear-btn" type="button">Export CSV</button>
                </div>
                <div class="sunbird-id-table-wrap">
                    <table class="sunbird-id-table sunbird-backup-table">
                        <thead>
                            <tr>
                                <th>Service</th>
                                <th>Name</th>
                                <th>Principal / URL</th>
                                <th>Storage</th>
                                <th>Files / Items</th>
                                <th>Last Activity</th>
                                <th>Activity Age</th>
                                <th>Risk</th>
                                <th>Evidence</th>
                            </tr>
                        </thead>
                        <tbody id="sunbird-backup-body"></tbody>
                    </table>
                </div>
            </section>
        </section>
        <div id="sunbird-backup-evidence-modal" class="sunbird-id-modal" aria-hidden="true"></div>
    `;
}

function setupSunbirdBackupDashboard() {
    document.getElementById('sunbird-backup-back')?.addEventListener('click', goBackToProjects);
    document.getElementById('sunbird-backup-search')?.addEventListener('input', event => {
        sunbirdBackupTableState.search = event.target.value;
        renderSunbirdBackupTable();
    });
    document.getElementById('sunbird-backup-service-filter')?.addEventListener('change', event => {
        sunbirdBackupTableState.service = event.target.value;
        renderSunbirdBackupTable();
    });
    document.getElementById('sunbird-backup-activity-filter')?.addEventListener('change', event => {
        sunbirdBackupTableState.activity = event.target.value;
        renderSunbirdBackupTable();
    });
    document.getElementById('sunbird-backup-sort')?.addEventListener('change', event => {
        sunbirdBackupTableState.sort = event.target.value;
        renderSunbirdBackupTable();
    });
    document.getElementById('sunbird-backup-clear')?.addEventListener('click', () => {
        sunbirdBackupTableState = { search: '', service: 'all', activity: 'all', sort: 'storage' };
        ['sunbird-backup-search', 'sunbird-backup-service-filter', 'sunbird-backup-activity-filter', 'sunbird-backup-sort'].forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.value = id === 'sunbird-backup-sort' ? 'storage' : id === 'sunbird-backup-search' ? '' : 'all';
        });
        renderSunbirdBackupTable();
    });
    document.getElementById('sunbird-backup-export')?.addEventListener('click', exportSunbirdBackupCsv);
}

function readSunbirdBackupSnapshot() {
    try {
        const parsed = JSON.parse(localStorage.getItem(SUNBIRD_BACKUP_CACHE_KEY) || 'null');
        return parsed?.summary || parsed?.storage ? parsed : null;
    } catch (error) {
        return null;
    }
}

function saveSunbirdBackupSnapshot(data) {
    if (!data?.summary && !data?.storage) return;
    localStorage.setItem(SUNBIRD_BACKUP_CACHE_KEY, JSON.stringify({ ...data, savedAt: new Date().toISOString() }));
}

async function loadSunbirdBackupDashboardData() {
    try {
        const data = await fetchSunbirdBackupRecoveryData();
        cachedSunbirdBackupData = normalizeSunbirdBackupData(data);
        saveSunbirdBackupSnapshot(cachedSunbirdBackupData);
        updateBackupProjectCardFromData(cachedSunbirdBackupData);
        renderSunbirdBackupDashboard();
    } catch (error) {
        console.warn('[Backup Dashboard] Cached/live data unavailable:', error.message);
    }
}

function normalizeSunbirdBackupData(data = {}) {
    const payload = data.payload && typeof data.payload === 'object' ? data.payload : data;
    const summary = payload.summary || {};
    const storage = payload.storage || {};
    const byService = storage.byService || {};
    const users = Array.isArray(storage.users) ? storage.users : [];
    const sites = Array.isArray(storage.sites) ? storage.sites : [];
    const inactiveUsers = Array.isArray(storage.inactiveUsers) ? storage.inactiveUsers : [];
    const inactiveUsersCount = inactiveUsers.length
        ? new Set(inactiveUsers.map(user => String(user.user || '').toLowerCase()).filter(Boolean)).size
        : (summary.inactiveUsersCount ?? users.filter(user => !user.lastActivity || getSunbirdBackupActivityAge(user.lastActivity) > 30).length);
    const totalStorageGB = summary.totalStorageGB ?? Number(((byService.onedrive || 0) + (byService.sharepoint || 0) + (byService.exchange || 0)).toFixed(1));
    return {
        ...payload,
        summary: {
            ...summary,
            totalStorageGB,
            oneDriveStorageGB: summary.oneDriveStorageGB ?? byService.onedrive ?? 0,
            sharePointStorageGB: summary.sharePointStorageGB ?? byService.sharepoint ?? 0,
            exchangeStorageGB: summary.exchangeStorageGB ?? byService.exchange ?? 0,
            activeUsersCount: summary.activeUsersCount ?? users.filter(user => user.lastActivity).length,
            inactiveUsersCount,
            servicesCovered: summary.servicesCovered ?? 3,
            backupConfigured: Boolean(summary.backupConfigured)
        },
        storage: {
            ...storage,
            byService: {
                onedrive: byService.onedrive ?? summary.oneDriveStorageGB ?? 0,
                sharepoint: byService.sharepoint ?? summary.sharePointStorageGB ?? 0,
                exchange: byService.exchange ?? summary.exchangeStorageGB ?? 0
            },
            users,
            sites,
            inactiveUsers,
            inactiveUserStorageGB: storage.inactiveUserStorageGB ?? 0
        },
        insights: Array.isArray(payload.insights) ? payload.insights : []
    };
}

function buildSunbirdBackupModel(data = cachedSunbirdBackupData) {
    const normalized = normalizeSunbirdBackupData(data || {});
    const rows = buildSunbirdBackupRows(normalized);
    const userRows = rows.filter(row => row.service !== 'SharePoint');
    const inactiveRows = userRows.filter(row => row.activityAge > 30 || !row.lastActivity);
    const highStorageRows = rows.filter(row => row.storageGB >= 20);
    const staleRows = rows.filter(row => row.activityAge > 90 || !row.lastActivity);
    const serviceRows = [
        { service: 'OneDrive', storageGB: normalized.summary.oneDriveStorageGB || 0 },
        { service: 'SharePoint', storageGB: normalized.summary.sharePointStorageGB || 0 },
        { service: 'Exchange', storageGB: normalized.summary.exchangeStorageGB || 0 }
    ];
    const backupCoverageScore = Math.round(((normalized.summary.servicesCovered || 0) / 3) * 100);
    const dataExposureRiskScore = Math.min(100, Math.round((inactiveRows.length * 3) + (highStorageRows.length * 5) + (normalized.storage.inactiveUserStorageGB || 0) / 10));
    const recommendations = buildSunbirdBackupRecommendations(normalized, { inactiveRows, highStorageRows, staleRows, backupCoverageScore, dataExposureRiskScore });
    return {
        ...normalized,
        rows,
        serviceRows,
        recommendations,
        scores: { backupCoverageScore, dataExposureRiskScore },
        evidence: {
            allRows: rows,
            serviceRows,
            inactiveRows,
            highStorageRows,
            staleRows,
            topUsers: userRows.sort((a, b) => b.storageGB - a.storageGB).slice(0, 20),
            topSites: rows.filter(row => row.service === 'SharePoint').sort((a, b) => b.storageGB - a.storageGB).slice(0, 10),
            lastActivityBuckets: buildSunbirdBackupActivityBuckets(userRows),
            insights: normalized.insights,
            recommendations
        }
    };
}

function renderSunbirdBackupDashboard() {
    const model = buildSunbirdBackupModel();
    renderSunbirdBackupMetrics(model);
    renderSunbirdBackupInsights(model);
    renderSunbirdBackupCharts(model);
    renderSunbirdBackupPanels(model);
    renderSunbirdBackupTable(model);
}

function renderSunbirdBackupMetrics(model) {
    const el = document.getElementById('sunbird-backup-metrics');
    if (!el) return;
    const metrics = [
        { label: 'Total Storage', value: `${model.summary.totalStorageGB || 0} GB`, tone: model.summary.totalStorageGB > 1000 ? 'warn' : 'neutral', evidence: 'serviceRows' },
        { label: 'Active Users', value: model.summary.activeUsersCount || 0, tone: 'good', evidence: 'topUsers' },
        { label: 'Inactive Users', value: model.summary.inactiveUsersCount || 0, tone: model.summary.inactiveUsersCount ? 'warn' : 'good', evidence: 'inactiveRows' },
        { label: 'Coverage Score', value: `${model.scores.backupCoverageScore}%`, tone: model.scores.backupCoverageScore >= 100 ? 'good' : 'warn', evidence: 'recommendations' }
    ];
    el.innerHTML = metrics.map(metric => `
        <article class="sunbird-id-metric-card tone-${metric.tone}">
            <div class="sunbird-id-metric-value">${escapeIdentityText(metric.value)}</div>
            <div class="sunbird-id-metric-label">${escapeIdentityText(metric.label)}</div>
            <button type="button" onclick="openSunbirdBackupEvidence('${metric.evidence}')" class="sunbird-id-evidence-btn">View Evidence</button>
        </article>
    `).join('');
}

function renderSunbirdBackupInsights(model) {
    const el = document.getElementById('sunbird-backup-insights');
    if (!el) return;
    const insights = [
        { title: 'Growth risk', value: `${model.summary.totalStorageGB || 0} GB`, evidence: 'serviceRows', tone: model.summary.totalStorageGB > 1000 ? 'bad' : 'warn' },
        { title: 'Inactive data holders', value: model.evidence.inactiveRows.length, evidence: 'inactiveRows', tone: model.evidence.inactiveRows.length ? 'bad' : 'good' },
        { title: 'Top storage users', value: model.evidence.topUsers.length, evidence: 'topUsers', tone: 'neutral' },
        { title: 'Top SharePoint sites', value: model.evidence.topSites.length, evidence: 'topSites', tone: 'neutral' },
        { title: 'Stale activity', value: model.evidence.staleRows.length, evidence: 'staleRows', tone: model.evidence.staleRows.length ? 'warn' : 'good' },
        { title: 'Exposure risk score', value: `${model.scores.dataExposureRiskScore}%`, evidence: 'inactiveRows', tone: model.scores.dataExposureRiskScore > 50 ? 'bad' : 'warn' },
        { title: 'Recommendations', value: model.recommendations.length, evidence: 'recommendations', tone: 'warn' }
    ];
    el.innerHTML = insights.map((item, index) => `
        <article class="sunbird-id-insight tone-${item.tone}" role="button" tabindex="0" data-backup-evidence-key="${item.evidence}" onclick="toggleSunbirdBackupInsightEvidenceLock('${item.evidence}')" onkeydown="handleSunbirdBackupInsightEvidenceKey(event, '${item.evidence}')">
            <span>${escapeIdentityText(item.title)}</span>
            <strong>${escapeIdentityText(item.value)}</strong>
            ${renderSunbirdBackupInsightEvidencePreview(item, model, index)}
        </article>
    `).join('');
}

function renderSunbirdBackupInsightEvidencePreview(item, model, index) {
    const rows = getSunbirdBackupEvidenceRows(item.evidence, model);
    return `
        <div class="sunbird-id-insight-evidence" onclick="event.stopPropagation()">
            <p>${rows.length} evidence item${rows.length === 1 ? '' : 's'} matched this backup signal.</p>
            <div class="sunbird-id-insight-evidence-list">
                ${rows.slice(0, 4).map(row => `
                    <div>
                        <strong>${escapeIdentityText(row.title)}</strong>
                        <span>${escapeIdentityText(row.subtitle)}</span>
                        <small>${escapeIdentityText(row.meta)}</small>
                    </div>
                `).join('') || '<em>No evidence found.</em>'}
            </div>
            ${rows.length > 4 ? `<small>${rows.length - 4} more in full evidence</small>` : ''}
            <button type="button" onclick="openSunbirdBackupEvidence('${item.evidence}', 'insight-${index}')">Open Evidence</button>
        </div>
    `;
}

function renderSunbirdBackupCharts(model) {
    const el = document.getElementById('sunbird-backup-charts');
    if (!el) return;
    const buckets = model.evidence.lastActivityBuckets;
    el.innerHTML = `
        ${renderSunbirdPieChart('Storage distribution', [
            { label: 'OneDrive', value: model.summary.oneDriveStorageGB || 0, tone: 'neutral' },
            { label: 'SharePoint', value: model.summary.sharePointStorageGB || 0, tone: 'warn' },
            { label: 'Exchange', value: model.summary.exchangeStorageGB || 0, tone: 'good' }
        ], Math.max(1, model.summary.totalStorageGB || 0))}
        ${renderSunbirdBackupActivityRadarCard()}
        ${renderSunbirdDeviceBars('Service comparison', model.serviceRows.map((row, index) => ({
            label: row.service,
            value: row.storageGB,
            tone: index === 0 ? 'neutral' : index === 1 ? 'warn' : 'good'
        })), Math.max(1, ...model.serviceRows.map(row => row.storageGB)))}
        ${renderSunbirdBackupHealthGraph(model)}
    `;
    renderSunbirdBackupActivityFreshnessRadar(model);
    animateSunbirdIdentityCharts();
}

function renderSunbirdBackupActivityRadarCard() {
    return `
        <article class="sunbird-id-chart-card sunbird-backup-activity-radar-card">
            <h3>User Activity Freshness</h3>
            <div class="sunbird-backup-chart-canvas">
                <canvas id="sunbirdBackupActivityRadar"></canvas>
            </div>
        </article>
    `;
}

function renderSunbirdBackupActivityFreshnessRadar(model) {
    const canvas = document.getElementById('sunbirdBackupActivityRadar');
    if (!canvas) return;
    if (typeof Chart === 'undefined') {
        setTimeout(() => renderSunbirdBackupActivityFreshnessRadar(model), 100);
        return;
    }

    const buckets = model.evidence.lastActivityBuckets || { recent: 0, warm: 0, stale: 0, cold: 0 };
    const maxBucket = Math.max(1, buckets.recent, buckets.warm, buckets.stale, buckets.cold);
    const toScore = value => Math.round((value / maxBucket) * 100);
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    if (window.sunbirdBackupActivityRadarInstance && typeof window.sunbirdBackupActivityRadarInstance.destroy === 'function') {
        window.sunbirdBackupActivityRadarInstance.destroy();
    }

    window.sunbirdBackupActivityRadarInstance = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: ['0-7d Active', '8-30d Warm', '31-90d Stale', '90d+ Cold'],
            datasets: [{
                label: 'Activity Buckets',
                data: [toScore(buckets.recent), toScore(buckets.warm), toScore(buckets.stale), toScore(buckets.cold)],
                borderColor: '#006eff',
                backgroundColor: 'rgba(0, 110, 255, 0.2)',
                pointBackgroundColor: '#006eff',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: '#006eff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: '#bdbdbd'
                    }
                },
                tooltip: {
                    callbacks: {
                        label: context => {
                            const rawCounts = [buckets.recent, buckets.warm, buckets.stale, buckets.cold];
                            return `${context.dataset.label}: ${rawCounts[context.dataIndex] || 0} record(s)`;
                        }
                    }
                }
            },
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#bdbdbd',
                        backdropColor: 'transparent'
                    },
                    pointLabels: {
                        color: '#bdbdbd'
                    }
                }
            }
        }
    });
}

function renderSunbirdBackupHealthGraph(model) {
    const coverage = model.scores.backupCoverageScore;
    const active = model.summary.activeUsersCount || 0;
    const inactive = model.summary.inactiveUsersCount || 0;
    const activity = active + inactive ? Math.round((active / (active + inactive)) * 100) : 100;
    const exposureRisk = model.scores.dataExposureRiskScore;
    return `
        <article class="sunbird-id-chart-card sunbird-id-health-card">
            <h3>Recovery posture</h3>
            ${[
                { label: 'Coverage', value: coverage, tone: coverage >= 100 ? 'good' : 'warn' },
                { label: 'Activity', value: activity, tone: activity >= 75 ? 'good' : 'warn' },
                { label: 'Exposure risk', value: exposureRisk, tone: exposureRisk <= 30 ? 'good' : exposureRisk <= 60 ? 'warn' : 'bad' }
            ].map(item => `
                <div class="sunbird-id-health-row">
                    <span>${item.label}</span>
                    <div class="sunbird-id-health-track"><div class="sunbird-id-health-fill tone-${item.tone}" style="width:${item.value}%"></div></div>
                    <strong>${item.value}%</strong>
                </div>
            `).join('')}
        </article>
    `;
}

function renderSunbirdBackupPanels(model) {
    const el = document.getElementById('sunbird-backup-panels');
    if (!el) return;
    el.innerHTML = `
        ${renderSunbirdBackupFeedPanel('Top 20 users by storage', getSunbirdBackupEvidenceRows('topUsers', model).slice(0, 10))}
        ${renderSunbirdBackupFeedPanel('Top 10 SharePoint sites', getSunbirdBackupEvidenceRows('topSites', model).slice(0, 10))}
        ${renderSunbirdBackupFeedPanel('Storage insights', getSunbirdBackupEvidenceRows('insights', model).slice(0, 10))}
        ${renderSunbirdBackupFeedPanel('Actionable recommendations', getSunbirdBackupEvidenceRows('recommendations', model).slice(0, 10))}
    `;
}

function renderSunbirdBackupFeedPanel(title, rows) {
    return `
        <article class="sunbird-id-signin-card">
            <h3>${escapeIdentityText(title)}</h3>
            <div class="sunbird-id-signin-list">
                ${rows.length ? rows.map(row => `
                    <div class="sunbird-id-signin-item">
                        <div>
                            <strong>${escapeIdentityText(row.title)}</strong>
                            <span>${escapeIdentityText(row.subtitle)}</span>
                            <div class="sunbird-id-issue-tags"><em>${escapeIdentityText(row.meta)}</em></div>
                        </div>
                    </div>
                `).join('') : '<div class="sunbird-id-empty compact">No matching backup evidence.</div>'}
            </div>
        </article>
    `;
}

function renderSunbirdBackupTable(model = buildSunbirdBackupModel()) {
    const body = document.getElementById('sunbird-backup-body');
    if (!body) return;
    const rows = getFilteredSunbirdBackupRows(model);
    if (!rows.length) {
        body.innerHTML = '<tr><td colspan="9" class="sunbird-id-empty">No backup evidence matches the current filters.</td></tr>';
        return;
    }
    body.innerHTML = rows.map(row => `
        <tr>
            <td data-label="Service"><span class="sunbird-id-role-list"><span>${escapeIdentityText(row.service)}</span></span></td>
            <td data-label="Name">${escapeIdentityText(row.name)}</td>
            <td data-label="Principal / URL">${escapeIdentityText(row.principal)}</td>
            <td data-label="Storage">${escapeIdentityText(`${row.storageGB} GB`)}</td>
            <td data-label="Files / Items">${escapeIdentityText(row.itemCount)}</td>
            <td data-label="Last Activity">${escapeIdentityText(row.lastActivity || 'N/A')}</td>
            <td data-label="Activity Age">${escapeIdentityText(row.activityAge >= 999 ? 'Unknown' : `${row.activityAge} days`)}</td>
            <td data-label="Risk"><span class="sunbird-id-risk ${row.risk === 'high' ? 'high' : row.risk === 'medium' ? 'medium' : 'safe'}">${escapeIdentityText(row.risk)}</span></td>
            <td data-label="Evidence"><button type="button" class="sunbird-id-evidence-btn" onclick='openSunbirdBackupRowEvidence(${JSON.stringify(row.id)})'>Open</button></td>
        </tr>
    `).join('');
}

function getFilteredSunbirdBackupRows(model = buildSunbirdBackupModel()) {
    const search = sunbirdBackupTableState.search.trim().toLowerCase();
    return model.rows.filter(row => {
        const haystack = [row.service, row.name, row.principal, row.lastActivity, row.risk, row.itemCount].join(' ').toLowerCase();
        if (search && !haystack.includes(search)) return false;
        if (sunbirdBackupTableState.service !== 'all' && row.service !== sunbirdBackupTableState.service) return false;
        if (sunbirdBackupTableState.activity !== 'all') {
            const activeState = row.activityAge <= 30 ? 'active' : 'inactive';
            if (activeState !== sunbirdBackupTableState.activity) return false;
        }
        return true;
    }).sort((a, b) => {
        if (sunbirdBackupTableState.sort === 'activity') return a.activityAge - b.activityAge;
        if (sunbirdBackupTableState.sort === 'service') return a.service.localeCompare(b.service);
        return b.storageGB - a.storageGB;
    });
}

function buildSunbirdBackupRows(data) {
    const rows = [];
    mergeSunbirdBackupUserRecords(data.storage.users || [], data.storage.inactiveUsers || []).forEach((user, index) => {
        const service = user.items !== undefined ? 'Exchange' : 'OneDrive';
        const bytes = Number(user.storage || 0);
        const storageGB = Number((bytes / (1024 ** 3)).toFixed(2));
        const lastActivity = user.lastActivity || '';
        rows.push({
            id: `${service}-${index}-${user.user}`,
            service,
            name: user.displayName || user.user || 'Unknown user',
            principal: user.user || 'N/A',
            storageGB,
            itemCount: service === 'Exchange' ? `${user.items || 0} items` : `${user.files || 0} files`,
            lastActivity,
            activityAge: getSunbirdBackupActivityAge(lastActivity),
            risk: getSunbirdBackupRowRisk(storageGB, lastActivity),
            raw: user
        });
    });
    (data.storage.sites || []).forEach((site, index) => {
        const bytes = Number(site.storage || 0);
        const storageGB = Number((bytes / (1024 ** 3)).toFixed(2));
        const lastActivity = site.lastActivity || '';
        rows.push({
            id: `SharePoint-${index}-${site.url || site.owner}`,
            service: 'SharePoint',
            name: site.owner || 'SharePoint site',
            principal: site.url || 'N/A',
            storageGB,
            itemCount: `${site.files || 0} files`,
            lastActivity,
            activityAge: getSunbirdBackupActivityAge(lastActivity),
            risk: getSunbirdBackupRowRisk(storageGB, lastActivity),
            raw: site
        });
    });
    return rows;
}

function mergeSunbirdBackupUserRecords(users, inactiveUsers) {
    const records = new Map();
    [...users, ...inactiveUsers].forEach(user => {
        const key = `${user.items !== undefined ? 'Exchange' : 'OneDrive'}:${String(user.user || user.displayName || '').toLowerCase()}`;
        if (!key.endsWith(':')) records.set(key, user);
        else records.set(`${key}${records.size}`, user);
    });
    return Array.from(records.values());
}

function getSunbirdBackupActivityAge(value) {
    if (!value) return 999;
    const time = new Date(value).getTime();
    if (!Number.isFinite(time)) return 999;
    return Math.max(0, Math.floor((Date.now() - time) / (24 * 60 * 60 * 1000)));
}

function getSunbirdBackupRowRisk(storageGB, lastActivity) {
    const age = getSunbirdBackupActivityAge(lastActivity);
    if (age > 90 || storageGB >= 50) return 'high';
    if (age > 30 || storageGB >= 20) return 'medium';
    return 'safe';
}

function buildSunbirdBackupActivityBuckets(rows) {
    const userActivity = new Map();
    rows.forEach(row => {
        const key = String(row.principal || row.name || '').toLowerCase();
        if (!key) return;
        userActivity.set(key, Math.min(userActivity.get(key) ?? 999, row.activityAge));
    });
    return Array.from(userActivity.values()).reduce((acc, activityAge) => {
        if (activityAge <= 7) acc.recent += 1;
        else if (activityAge <= 30) acc.warm += 1;
        else if (activityAge <= 90) acc.stale += 1;
        else acc.cold += 1;
        return acc;
    }, { recent: 0, warm: 0, stale: 0, cold: 0 });
}

function buildSunbirdBackupRecommendations(model, evidence) {
    const recs = [];
    if (!model.summary.backupConfigured) {
        recs.push({ priority: 'critical', title: 'Validate external backup coverage', detail: 'Microsoft-native retention is visible, but external backup status is not confirmed by current Graph report data.' });
    }
    if (evidence.inactiveRows.length) {
        recs.push({ priority: 'high', title: 'Review inactive users holding data', detail: `${evidence.inactiveRows.length} inactive or stale owner(s) still hold recoverable data.` });
    }
    if (evidence.highStorageRows.length) {
        recs.push({ priority: 'medium', title: 'Monitor large storage holders', detail: `${evidence.highStorageRows.length} user/site record(s) exceed storage risk thresholds.` });
    }
    if (evidence.backupCoverageScore < 100) {
        recs.push({ priority: 'medium', title: 'Improve service coverage', detail: `${model.summary.servicesCovered || 0} of 3 Microsoft 365 service areas are currently represented.` });
    }
    if (!recs.length) {
        recs.push({ priority: 'low', title: 'Maintain backup evidence baseline', detail: 'Storage, activity, and service coverage are currently stable in cached Graph report data.' });
    }
    return recs;
}

function getSunbirdBackupEvidenceRows(evidenceKey, model = buildSunbirdBackupModel()) {
    if (evidenceKey === 'serviceRows') {
        return model.serviceRows.map(row => ({ title: row.service, subtitle: `${row.storageGB || 0} GB`, meta: 'Microsoft Graph storage report' }));
    }
    if (evidenceKey === 'insights') {
        return (model.insights || []).map(item => ({ title: item.message || item.type || 'Insight', subtitle: item.detail || 'Backup insight', meta: item.type || 'info' }));
    }
    if (evidenceKey === 'recommendations') {
        return model.recommendations.map(item => ({ title: item.title, subtitle: item.detail, meta: item.priority || 'medium' }));
    }
    if (evidenceKey === 'lastActivityBuckets') {
        const buckets = model.evidence.lastActivityBuckets;
        return Object.entries(buckets).map(([label, value]) => ({ title: label, subtitle: `${value} record(s)`, meta: 'Last activity age bucket' }));
    }
    const rows = model.evidence[evidenceKey] || model.rows || [];
    return rows.map(row => ({
        title: row.name || row.service || 'Backup evidence',
        subtitle: row.principal || `${row.storageGB || 0} GB`,
        meta: `${row.service || ''} | ${row.storageGB || 0} GB | ${row.lastActivity || 'No activity'}`
    }));
}

function openSunbirdBackupEvidence(evidenceKey) {
    const model = buildSunbirdBackupModel();
    const rows = getSunbirdBackupEvidenceRows(evidenceKey, model);
    const modal = document.getElementById('sunbird-backup-evidence-modal');
    if (!modal) return;
    const titleMap = {
        serviceRows: 'Storage by Service Evidence',
        inactiveRows: 'Inactive Users Holding Data',
        highStorageRows: 'Storage Growth Risk',
        staleRows: 'Last Activity Risk',
        topUsers: 'Top Users by Storage',
        topSites: 'Top SharePoint Sites by Storage',
        insights: 'Storage Insights',
        recommendations: 'Actionable Recommendations'
    };
    modal.innerHTML = `
        <div class="sunbird-id-modal-backdrop" onclick="closeSunbirdBackupEvidence()"></div>
        <div class="sunbird-id-modal-panel" role="dialog" aria-modal="true">
            <div class="sunbird-id-modal-header">
                <div>
                    <h3>${escapeIdentityText(titleMap[evidenceKey] || 'Backup Evidence')}</h3>
                    <p>${rows.length} evidence item${rows.length === 1 ? '' : 's'} matched this set.</p>
                </div>
                <button type="button" onclick="closeSunbirdBackupEvidence()" class="sunbird-id-modal-close">&times;</button>
            </div>
            <div class="sunbird-id-evidence-summary">
                <span>Total storage: ${model.summary.totalStorageGB || 0} GB</span>
                <span>Active users: ${model.summary.activeUsersCount || 0}</span>
                <span>Coverage: ${model.scores.backupCoverageScore}%</span>
            </div>
            <div class="sunbird-id-evidence-list">
                ${rows.length ? rows.slice(0, 120).map(row => `
                    <div class="sunbird-id-evidence-user">
                        <strong>${escapeIdentityText(row.title)}</strong>
                        <span>${escapeIdentityText(row.subtitle)}</span>
                        <small>${escapeIdentityText(row.meta)}</small>
                    </div>
                `).join('') : '<div class="sunbird-id-empty">No evidence found for this item.</div>'}
            </div>
            <div class="sunbird-id-modal-actions">
                <button type="button" class="sunbird-id-evidence-btn" onclick="closeSunbirdBackupEvidence()">Close</button>
            </div>
        </div>
    `;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
}

function openSunbirdBackupRowEvidence(rowId) {
    const model = buildSunbirdBackupModel();
    const row = model.rows.find(item => item.id === rowId);
    if (!row) return;
    openSunbirdBackupRowsModal(row.name, [{
        title: row.name,
        subtitle: row.principal,
        meta: `${row.service} | ${row.storageGB} GB | ${row.itemCount} | Last activity: ${row.lastActivity || 'N/A'} | Risk: ${row.risk}`
    }]);
}

function openSunbirdBackupRowsModal(title, rows) {
    const modal = document.getElementById('sunbird-backup-evidence-modal');
    if (!modal) return;
    modal.innerHTML = `
        <div class="sunbird-id-modal-backdrop" onclick="closeSunbirdBackupEvidence()"></div>
        <div class="sunbird-id-modal-panel" role="dialog" aria-modal="true">
            <div class="sunbird-id-modal-header">
                <div><h3>${escapeIdentityText(title)}</h3><p>${rows.length} evidence item${rows.length === 1 ? '' : 's'}.</p></div>
                <button type="button" onclick="closeSunbirdBackupEvidence()" class="sunbird-id-modal-close">&times;</button>
            </div>
            <div class="sunbird-id-evidence-list">
                ${rows.map(row => `<div class="sunbird-id-evidence-user"><strong>${escapeIdentityText(row.title)}</strong><span>${escapeIdentityText(row.subtitle)}</span><small>${escapeIdentityText(row.meta)}</small></div>`).join('')}
            </div>
            <div class="sunbird-id-modal-actions"><button type="button" class="sunbird-id-evidence-btn" onclick="closeSunbirdBackupEvidence()">Close</button></div>
        </div>
    `;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
}

function closeSunbirdBackupEvidence() {
    const modal = document.getElementById('sunbird-backup-evidence-modal');
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
}

function toggleSunbirdBackupInsightEvidenceLock(evidenceKey) {
    const tile = document.querySelector(`.sunbird-id-insight[data-backup-evidence-key="${evidenceKey}"]`);
    if (!tile) return;
    const shouldLock = lockedSunbirdBackupInsightEvidenceKey !== evidenceKey;
    document.querySelectorAll('.sunbird-id-insight.locked').forEach(item => item.classList.remove('locked'));
    lockedSunbirdBackupInsightEvidenceKey = shouldLock ? evidenceKey : null;
    if (shouldLock) tile.classList.add('locked');
}

function handleSunbirdBackupInsightEvidenceKey(event, evidenceKey) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    toggleSunbirdBackupInsightEvidenceLock(evidenceKey);
}

function exportSunbirdBackupCsv() {
    const rows = getFilteredSunbirdBackupRows(buildSunbirdBackupModel());
    const header = ['Service', 'Name', 'Principal', 'StorageGB', 'Items', 'LastActivity', 'ActivityAge', 'Risk'];
    const csv = [
        header.join(','),
        ...rows.map(row => [row.service, row.name, row.principal, row.storageGB, row.itemCount, row.lastActivity, row.activityAge, row.risk]
            .map(value => `"${String(value ?? '').replace(/"/g, '""')}"`).join(','))
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `backup-recovery-evidence-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
}

function updateBackupProjectCardFromData(data) {
    const project = mockProjects.find(p => p.isBackupRecoveryCard);
    if (!project) return;
    const model = buildSunbirdBackupModel(data);
    project.status = 'active';
    project.cardMetrics = [
        { label: 'Total Storage', value: `: ${model.summary.totalStorageGB || 0} GB`, icon: 'fas fa-database' },
        { label: 'Active Users', value: `: ${model.summary.activeUsersCount || 0}`, icon: 'fas fa-users' },
        { label: 'Inactive Users', value: `: ${model.summary.inactiveUsersCount || 0}`, icon: 'fas fa-user-clock' },
        { label: 'Coverage Score', value: `: ${model.scores.backupCoverageScore}%`, icon: 'fas fa-cloud' }
    ];
    project.cardFooter = `${model.summary.servicesCovered || 0}/3 services covered | ${model.summary.totalStorageGB || 0} GB`;
    project.risks = {
        critical: model.recommendations.filter(item => item.priority === 'critical').length,
        high: model.recommendations.filter(item => item.priority === 'high').length,
        medium: model.recommendations.filter(item => item.priority === 'medium').length
    };
    project.lastUpdate = new Date().toLocaleTimeString();
    saveProjectCardToCache(project);
    if (currentProject?.id === project.id) displayCurrentProject();
}

window.openSunbirdBackupDashboard = openSunbirdBackupDashboard;
window.openSunbirdBackupEvidence = openSunbirdBackupEvidence;
window.openSunbirdBackupRowEvidence = openSunbirdBackupRowEvidence;
window.closeSunbirdBackupEvidence = closeSunbirdBackupEvidence;
window.toggleSunbirdBackupInsightEvidenceLock = toggleSunbirdBackupInsightEvidenceLock;
window.handleSunbirdBackupInsightEvidenceKey = handleSunbirdBackupInsightEvidenceKey;

function normalizeSunbirdApplicationsData(data = {}) {
    const payload = data.payload && typeof data.payload === 'object' ? data.payload : data;
    const apps = (Array.isArray(payload.applications) ? payload.applications : []).map(app => {
        const assignedGroups = Array.isArray(app.assignedGroups)
            ? app.assignedGroups.filter(Boolean)
            : String(app.assignedGroups || '').split(',').map(group => group.trim()).filter(Boolean);
        const scopeCount = Number(app.scopeCount || app.scopes || 0);
        const roleCount = Number(app.roleCount || app.roles || 0);
        const userCount = Number(app.userCount || app.users || app.assignmentCount || 0);
        const explicitType = String(app.type || '').toLowerCase();
        const publisherName = String(app.publisherName || '').toLowerCase();
        const isExternal = explicitType
            ? explicitType === 'external'
            : Boolean(app.isExternal || (publisherName && !publisherName.includes('microsoft')));
        return {
            ...app,
            id: app.id || app.spId || app.appId || app.servicePrincipalId || '',
            name: app.name || app.displayName || 'Unknown App',
            displayName: app.displayName || app.name || 'Unknown App',
            type: isExternal ? 'External' : 'Microsoft',
            isExternal,
            assignedGroups,
            scopeCount,
            roleCount,
            userCount,
            publisherName: app.publisherName || 'Unknown'
        };
    });
    const summary = payload.summary || {};
    const externalApplications = summary.externalApplications ?? payload.externalApplications ?? apps.filter(app => app.isExternal || app.type === 'External').length;
    const highRiskApps = summary.highRiskApps ?? payload.highRiskApps ?? apps.filter(app => calculateAppRisk(app).level === 'high').length;
    const highAccessApps = summary.highAccessApps ?? payload.highAccessApps ?? apps.filter(app => (app.userCount || 0) >= 20 || (app.assignedGroups || []).length >= 3).length;
    return {
        ...payload,
        applications: apps,
        summary: {
            ...summary,
            totalApplications: summary.totalApplications ?? payload.totalApplications ?? apps.length,
            externalApplications,
            highRiskApps,
            highAccessApps,
            userCount: summary.userCount ?? payload.userCount ?? 0,
            groupCount: summary.groupCount ?? payload.groupCount ?? 0
        }
    };
}

function readSunbirdApplicationsSnapshot() {
    try {
        const parsed = JSON.parse(localStorage.getItem(SUNBIRD_APPLICATIONS_CACHE_KEY) || 'null');
        return parsed?.applications ? parsed : null;
    } catch (error) {
        return null;
    }
}

function saveSunbirdApplicationsSnapshot(data) {
    if (!data?.applications) return;
    localStorage.setItem(SUNBIRD_APPLICATIONS_CACHE_KEY, JSON.stringify({ ...data, savedAt: new Date().toISOString() }));
}

function buildSunbirdApplicationsModel(data = sunbirdApplicationsPayload || readSunbirdApplicationsSnapshot() || { applications: applicationsData }) {
    const normalized = normalizeSunbirdApplicationsData(data || {});
    const apps = normalized.applications.map(app => ({ ...app, risk: calculateAppRisk(app) }));
    const externalApps = apps.filter(app => app.isExternal || app.type === 'External');
    const highRiskApps = apps.filter(app => app.risk.level === 'high');
    const highAccessApps = apps.filter(app => (app.userCount || 0) >= 20 || (app.assignedGroups || []).length >= 3);
    const excessivePermissionApps = apps.filter(app => ((app.scopeCount || 0) + (app.roleCount || 0)) > 10);
    const groupAssignedApps = apps.filter(app => (app.assignedGroups || []).length > 0);
    const governanceScore = calculateSunbirdApplicationsGovernanceScore(apps);
    return {
        ...normalized,
        applications: apps,
        governanceScore,
        evidence: {
            allApps: apps,
            externalApps,
            highRiskApps,
            highAccessApps,
            excessivePermissionApps,
            groupAssignedApps,
            permissionBuckets: buildSunbirdApplicationsPermissionBuckets(apps),
            recommendations: buildSunbirdApplicationsRecommendations(apps, governanceScore)
        },
        summary: {
            ...normalized.summary,
            totalApplications: apps.length,
            externalApplications: externalApps.length,
            highRiskApps: highRiskApps.length,
            highAccessApps: highAccessApps.length,
            excessivePermissionApps: excessivePermissionApps.length,
            groupAssignedApps: groupAssignedApps.length
        }
    };
}

function openSunbirdApplicationsDashboard() {
    const dashboardView = document.getElementById('dashboard-view');
    const projectsView = document.getElementById('projects-view');
    if (!dashboardView) return;
    if (projectsView) projectsView.style.display = 'none';
    dashboardView.style.display = 'block';
    dashboardView.style.visibility = 'visible';
    dashboardView.style.opacity = '1';
    dashboardView.classList.remove('sunbird-identity-active');
    dashboardView.classList.remove('sunbird-device-active');
    dashboardView.classList.remove('sunbird-email-active');
    dashboardView.classList.remove('sunbird-security-active');
    dashboardView.classList.remove('sunbird-backup-active');
    dashboardView.classList.add('sunbird-applications-active');

    captureDashboardViewHTML();
    dashboardView.innerHTML = renderSunbirdApplicationsShell();
    setupSunbirdApplicationsDashboard();

    const cached = readSunbirdApplicationsSnapshot();
    if (cached) {
        sunbirdApplicationsPayload = normalizeSunbirdApplicationsData(cached);
        applicationsData = sunbirdApplicationsPayload.applications;
    }
    renderSunbirdApplicationsDashboard();
    loadSunbirdApplicationsDashboardData();
}

function renderSunbirdApplicationsShell() {
    return `
        <section class="sunbird-identity-dashboard sunbird-applications-dashboard" id="sunbird-applications-dashboard">
            <div class="sunbird-id-header">
                <button id="sunbird-applications-back" class="sunbird-id-back-btn" type="button"><span class="sunbird-id-back-icon" aria-hidden="true">&larr;</span><span>Back</span></button>
                <div><h2>Applications & Access</h2><p>Enterprise app inventory, access, permissions, and risk evidence.</p></div>
                <div class="sunbird-id-microsoft-badge" aria-label="Microsoft Solutions"><span class="sunbird-id-ms-logo" aria-hidden="true"><i></i><i></i><i></i><i></i></span><span>Microsoft Solutions</span></div>
            </div>
            <div class="sunbird-id-metrics" id="sunbird-applications-metrics"></div>
            <div class="sunbird-id-insights" id="sunbird-applications-insights"></div>
            <div class="sunbird-id-charts" id="sunbird-applications-charts"></div>
            <div class="sunbird-id-signins" id="sunbird-applications-panels"></div>
            <section class="sunbird-id-table-section">
                <div class="sunbird-id-table-toolbar">
                    <input id="sunbird-applications-search" class="sunbird-id-search" type="search" placeholder="Search app, type, group, risk reason">
                    <select id="sunbird-applications-type-filter" class="sunbird-id-select"><option value="all">All types</option><option value="Microsoft">Microsoft</option><option value="External">External</option></select>
                    <select id="sunbird-applications-risk-filter" class="sunbird-id-select"><option value="all">All risk</option><option value="high">High</option><option value="safe">Safe</option></select>
                    <select id="sunbird-applications-sort" class="sunbird-id-select"><option value="risk">Sort risk</option><option value="users">Sort users</option><option value="permissions">Sort permissions</option><option value="created">Sort created</option></select>
                    <button id="sunbird-applications-clear" class="sunbird-id-clear-btn" type="button">Clear</button>
                </div>
                <div class="sunbird-id-table-wrap">
                    <table class="sunbird-id-table sunbird-applications-table">
                        <thead><tr><th>App</th><th>Type</th><th>Users</th><th>Groups</th><th>Scopes</th><th>Roles</th><th>Created</th><th>Risk</th><th>Evidence</th></tr></thead>
                        <tbody id="sunbird-applications-body"></tbody>
                    </table>
                </div>
            </section>
        </section>
        <div id="sunbird-applications-evidence-modal" class="sunbird-id-modal" aria-hidden="true"></div>
    `;
}

function setupSunbirdApplicationsDashboard() {
    document.getElementById('sunbird-applications-back')?.addEventListener('click', goBackToProjects);
    document.getElementById('sunbird-applications-search')?.addEventListener('input', e => { sunbirdApplicationsTableState.search = e.target.value; renderSunbirdApplicationsTable(); });
    document.getElementById('sunbird-applications-type-filter')?.addEventListener('change', e => { sunbirdApplicationsTableState.type = e.target.value; renderSunbirdApplicationsTable(); });
    document.getElementById('sunbird-applications-risk-filter')?.addEventListener('change', e => { sunbirdApplicationsTableState.risk = e.target.value; renderSunbirdApplicationsTable(); });
    document.getElementById('sunbird-applications-sort')?.addEventListener('change', e => { sunbirdApplicationsTableState.sort = e.target.value; renderSunbirdApplicationsTable(); });
    document.getElementById('sunbird-applications-clear')?.addEventListener('click', () => {
        sunbirdApplicationsTableState = { search: '', type: 'all', risk: 'all', sort: 'risk' };
        ['sunbird-applications-search', 'sunbird-applications-type-filter', 'sunbird-applications-risk-filter', 'sunbird-applications-sort'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = id === 'sunbird-applications-sort' ? 'risk' : id === 'sunbird-applications-search' ? '' : 'all';
        });
        renderSunbirdApplicationsTable();
    });
}

async function loadSunbirdApplicationsDashboardData() {
    await fetchApplicationsData();
    renderSunbirdApplicationsDashboard();
}

function renderSunbirdApplicationsDashboard() {
    const model = buildSunbirdApplicationsModel();
    renderSunbirdApplicationsMetrics(model);
    renderSunbirdApplicationsInsights(model);
    renderSunbirdApplicationsCharts(model);
    renderSunbirdApplicationsPanels(model);
    renderSunbirdApplicationsTable(model);
}

function renderSunbirdApplicationsMetrics(model) {
    const el = document.getElementById('sunbird-applications-metrics');
    if (!el) return;
    const metrics = [
        { label: 'Total Apps', value: model.summary.totalApplications, tone: 'neutral', evidence: 'allApps' },
        { label: 'External Apps', value: model.summary.externalApplications, tone: model.summary.externalApplications ? 'warn' : 'good', evidence: 'externalApps' },
        { label: 'High Risk Apps', value: model.summary.highRiskApps, tone: model.summary.highRiskApps ? 'bad' : 'good', evidence: 'highRiskApps' },
        { label: 'Governance Score', value: `${model.governanceScore}%`, tone: model.governanceScore >= 80 ? 'good' : model.governanceScore >= 60 ? 'warn' : 'bad', evidence: 'recommendations' }
    ];
    el.innerHTML = metrics.map(metric => `<article class="sunbird-id-metric-card tone-${metric.tone}"><div class="sunbird-id-metric-value">${escapeIdentityText(metric.value)}</div><div class="sunbird-id-metric-label">${escapeIdentityText(metric.label)}</div><button type="button" onclick="openSunbirdApplicationsEvidence('${metric.evidence}')" class="sunbird-id-evidence-btn">View Evidence</button></article>`).join('');
}

function renderSunbirdApplicationsInsights(model) {
    const el = document.getElementById('sunbird-applications-insights');
    if (!el) return;
    const insights = [
        { title: 'External apps', value: model.evidence.externalApps.length, evidence: 'externalApps', tone: model.evidence.externalApps.length ? 'bad' : 'good' },
        { title: 'High access apps', value: model.evidence.highAccessApps.length, evidence: 'highAccessApps', tone: model.evidence.highAccessApps.length ? 'warn' : 'good' },
        { title: 'Excessive permissions', value: model.evidence.excessivePermissionApps.length, evidence: 'excessivePermissionApps', tone: model.evidence.excessivePermissionApps.length ? 'bad' : 'good' },
        { title: 'Group-assigned apps', value: model.evidence.groupAssignedApps.length, evidence: 'groupAssignedApps', tone: 'neutral' },
        { title: 'Users in tenant', value: model.summary.userCount || 0, evidence: 'allApps', tone: 'neutral' },
        { title: 'Groups in tenant', value: model.summary.groupCount || 0, evidence: 'groupAssignedApps', tone: 'neutral' },
        { title: 'Recommendations', value: model.evidence.recommendations.length, evidence: 'recommendations', tone: 'warn' }
    ];
    el.innerHTML = insights.map((item, index) => `
        <article class="sunbird-id-insight tone-${item.tone}" role="button" tabindex="0" data-applications-evidence-key="${item.evidence}" onclick="toggleSunbirdApplicationsInsightEvidenceLock('${item.evidence}')" onkeydown="handleSunbirdApplicationsInsightEvidenceKey(event, '${item.evidence}')">
            <span>${escapeIdentityText(item.title)}</span><strong>${escapeIdentityText(item.value)}</strong>${renderSunbirdApplicationsInsightEvidencePreview(item, model, index)}
        </article>`).join('');
}

function renderSunbirdApplicationsInsightEvidencePreview(item, model, index) {
    const rows = getSunbirdApplicationsEvidenceRows(item.evidence, model);
    return `<div class="sunbird-id-insight-evidence" onclick="event.stopPropagation()"><p>${rows.length} evidence item${rows.length === 1 ? '' : 's'} matched this app signal.</p><div class="sunbird-id-insight-evidence-list">${rows.slice(0, 4).map(row => `<div><strong>${escapeIdentityText(row.title)}</strong><span>${escapeIdentityText(row.subtitle)}</span><small>${escapeIdentityText(row.meta)}</small></div>`).join('') || '<em>No evidence found.</em>'}</div>${rows.length > 4 ? `<small>${rows.length - 4} more in full evidence</small>` : ''}<button type="button" onclick="openSunbirdApplicationsEvidence('${item.evidence}', 'insight-${index}')">Open Evidence</button></div>`;
}

function renderSunbirdApplicationsCharts(model) {
    const el = document.getElementById('sunbird-applications-charts');
    if (!el) return;
    const buckets = model.evidence.permissionBuckets;
    el.innerHTML = `
        ${renderSunbirdPieChart('Internal vs external apps', [
            { label: 'Microsoft', value: Math.max(0, model.summary.totalApplications - model.summary.externalApplications), tone: 'good' },
            { label: 'External', value: model.summary.externalApplications, tone: 'warn' }
        ], Math.max(1, model.summary.totalApplications))}
        ${renderSunbirdDeviceBars('Permission risk buckets', [
            { label: '0-3', value: buckets.low, tone: 'good' },
            { label: '4-10', value: buckets.medium, tone: 'warn' },
            { label: '10+', value: buckets.high, tone: 'bad' }
        ], Math.max(1, buckets.low, buckets.medium, buckets.high))}
        ${renderSunbirdDeviceBars('High access apps', model.applications.slice().sort((a,b)=>(b.userCount||0)-(a.userCount||0)).slice(0,5).map((app,index)=>({ label: app.name || app.displayName, value: app.userCount || 0, tone: index === 0 ? 'bad' : 'neutral' })), Math.max(1, ...model.applications.map(app => app.userCount || 0)))}
        ${renderSunbirdApplicationsHealthGraph(model)}
    `;
    animateSunbirdIdentityCharts();
}

function renderSunbirdApplicationsHealthGraph(model) {
    const externalRatio = model.summary.totalApplications ? Math.round(100 - ((model.summary.externalApplications / model.summary.totalApplications) * 100)) : 100;
    const permissionScore = model.summary.totalApplications ? Math.round(100 - ((model.evidence.excessivePermissionApps.length / model.summary.totalApplications) * 100)) : 100;
    return `<article class="sunbird-id-chart-card sunbird-id-health-card"><h3>App governance</h3>${[
        { label: 'Score', value: model.governanceScore, tone: model.governanceScore >= 80 ? 'good' : 'warn' },
        { label: 'Internal ratio', value: externalRatio, tone: externalRatio >= 70 ? 'good' : 'warn' },
        { label: 'Permission hygiene', value: permissionScore, tone: permissionScore >= 80 ? 'good' : 'warn' }
    ].map(item => `<div class="sunbird-id-health-row"><span>${item.label}</span><div class="sunbird-id-health-track"><div class="sunbird-id-health-fill tone-${item.tone}" style="width:${item.value}%"></div></div><strong>${item.value}%</strong></div>`).join('')}</article>`;
}

function renderSunbirdApplicationsPanels(model) {
    const el = document.getElementById('sunbird-applications-panels');
    if (!el) return;
    el.innerHTML = `
        ${renderSunbirdApplicationsFeedPanel('External apps risk panel', getSunbirdApplicationsEvidenceRows('externalApps', model).slice(0, 10))}
        ${renderSunbirdApplicationsFeedPanel('High access apps', getSunbirdApplicationsEvidenceRows('highAccessApps', model).slice(0, 10))}
        ${renderSunbirdApplicationsFeedPanel('Permission risk evidence', getSunbirdApplicationsEvidenceRows('excessivePermissionApps', model).slice(0, 10))}
        ${renderSunbirdApplicationsFeedPanel('Security recommendations', getSunbirdApplicationsEvidenceRows('recommendations', model).slice(0, 10))}
    `;
}

function renderSunbirdApplicationsFeedPanel(title, rows) {
    return `<article class="sunbird-id-signin-card"><h3>${escapeIdentityText(title)}</h3><div class="sunbird-id-signin-list">${rows.length ? rows.map(row => `<div class="sunbird-id-signin-item"><div><strong>${escapeIdentityText(row.title)}</strong><span>${escapeIdentityText(row.subtitle)}</span><div class="sunbird-id-issue-tags"><em>${escapeIdentityText(row.meta)}</em></div></div></div>`).join('') : '<div class="sunbird-id-empty compact">No matching application evidence.</div>'}</div></article>`;
}

function renderSunbirdApplicationsTable(model = buildSunbirdApplicationsModel()) {
    const body = document.getElementById('sunbird-applications-body');
    if (!body) return;
    const apps = getFilteredSunbirdApplications(model);
    if (!apps.length) {
        body.innerHTML = '<tr><td colspan="9" class="sunbird-id-empty">No applications match the current filters.</td></tr>';
        return;
    }
    body.innerHTML = apps.map(app => {
        const permissions = (app.scopeCount || 0) + (app.roleCount || 0);
        return `<tr><td data-label="App">${escapeIdentityText(app.name || app.displayName || 'Unknown App')}</td><td data-label="Type"><span class="sunbird-id-pill">${escapeIdentityText(app.type || 'Unknown')}</span></td><td data-label="Users">${app.userCount || 0}</td><td data-label="Groups">${(app.assignedGroups || []).length}</td><td data-label="Scopes">${app.scopeCount || 0}</td><td data-label="Roles">${app.roleCount || 0}</td><td data-label="Created">${escapeIdentityText(formatSunbirdDeviceDate(app.createdDateTime))}</td><td data-label="Risk"><span class="sunbird-id-risk ${app.risk.level === 'high' ? 'high' : 'safe'}">${escapeIdentityText(app.risk.level)}</span></td><td data-label="Evidence"><button type="button" class="sunbird-id-evidence-btn" onclick='openSunbirdApplicationAppEvidence(${JSON.stringify(app.id)})'>Open</button></td></tr>`;
    }).join('');
}

function getFilteredSunbirdApplications(model = buildSunbirdApplicationsModel()) {
    const search = sunbirdApplicationsTableState.search.trim().toLowerCase();
    return model.applications.filter(app => {
        const permissions = (app.scopeCount || 0) + (app.roleCount || 0);
        const haystack = [app.name, app.displayName, app.type, app.publisherName, app.risk.reasons.join(' '), (app.assignedGroups || []).join(' '), permissions].join(' ').toLowerCase();
        if (search && !haystack.includes(search)) return false;
        if (sunbirdApplicationsTableState.type !== 'all' && app.type !== sunbirdApplicationsTableState.type) return false;
        if (sunbirdApplicationsTableState.risk !== 'all' && app.risk.level !== sunbirdApplicationsTableState.risk) return false;
        return true;
    }).sort((a, b) => {
        if (sunbirdApplicationsTableState.sort === 'users') return (b.userCount || 0) - (a.userCount || 0);
        if (sunbirdApplicationsTableState.sort === 'permissions') return ((b.scopeCount || 0) + (b.roleCount || 0)) - ((a.scopeCount || 0) + (a.roleCount || 0));
        if (sunbirdApplicationsTableState.sort === 'created') return new Date(b.createdDateTime || 0) - new Date(a.createdDateTime || 0);
        return (a.risk.level === 'high' ? -1 : 1) - (b.risk.level === 'high' ? -1 : 1);
    });
}

function getSunbirdApplicationsEvidenceRows(evidenceKey, model = buildSunbirdApplicationsModel()) {
    if (evidenceKey === 'permissionBuckets') {
        const b = model.evidence.permissionBuckets;
        return [{ title: '0-3 permissions', subtitle: `${b.low} app(s)`, meta: 'Low' }, { title: '4-10 permissions', subtitle: `${b.medium} app(s)`, meta: 'Medium' }, { title: '10+ permissions', subtitle: `${b.high} app(s)`, meta: 'High' }];
    }
    if (evidenceKey === 'recommendations') return model.evidence.recommendations.map(item => ({ title: item.title, subtitle: item.detail, meta: item.priority }));
    return (model.evidence[evidenceKey] || model.applications || []).map(app => ({ title: app.name || app.displayName || 'Application', subtitle: `${app.type || 'Unknown'} | ${app.userCount || 0} users | ${(app.assignedGroups || []).length} groups`, meta: `${(app.scopeCount || 0) + (app.roleCount || 0)} permissions | ${app.risk?.reasons?.join(', ') || 'Evidence'}` }));
}

function openSunbirdApplicationsEvidence(evidenceKey) {
    const model = buildSunbirdApplicationsModel();
    const rows = getSunbirdApplicationsEvidenceRows(evidenceKey, model);
    const modal = ensureSunbirdApplicationsEvidenceModal();
    if (!modal) return;
    modal.innerHTML = `<div class="sunbird-id-modal-backdrop" onclick="closeSunbirdApplicationsEvidence()"></div><div class="sunbird-id-modal-panel" role="dialog" aria-modal="true"><div class="sunbird-id-modal-header"><div><h3>${escapeIdentityText(evidenceKey)}</h3><p>${rows.length} evidence item${rows.length === 1 ? '' : 's'} matched this set.</p></div><button type="button" onclick="closeSunbirdApplicationsEvidence()" class="sunbird-id-modal-close">&times;</button></div><div class="sunbird-id-evidence-summary"><span>Total apps: ${model.summary.totalApplications}</span><span>External: ${model.summary.externalApplications}</span><span>Score: ${model.governanceScore}%</span></div><div class="sunbird-id-evidence-list">${rows.map(row => `<div class="sunbird-id-evidence-user"><strong>${escapeIdentityText(row.title)}</strong><span>${escapeIdentityText(row.subtitle)}</span><small>${escapeIdentityText(row.meta)}</small></div>`).join('') || '<div class="sunbird-id-empty">No evidence found.</div>'}</div><div class="sunbird-id-modal-actions"><button type="button" class="sunbird-id-evidence-btn" onclick="closeSunbirdApplicationsEvidence()">Close</button></div></div>`;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
}

async function openSunbirdApplicationAppEvidence(appId) {
    const model = buildSunbirdApplicationsModel();
    const app = model.applications.find(item => item.id === appId);
    if (!app) return;
    let detail = null;
    try {
        const token = localStorage.getItem('authToken');
        const response = await fetch(`/api/app-access/${appId}`, { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } });
        if (response.ok) detail = await response.json();
    } catch (_) {}
    const directUsers = Number(detail?.users ?? app.userCount ?? 0);
    const groups = Array.isArray(detail?.groups) ? detail.groups : (app.assignedGroups || []);
    const totalAssignments = Number(detail?.totalAssignments ?? app.userCount ?? 0);
    const rows = [{
        title: app.name || app.displayName || 'Application',
        subtitle: `${app.type} | ${directUsers} direct users | ${groups.length} groups | ${totalAssignments} total assignments`,
        meta: `${(app.scopeCount || 0) + (app.roleCount || 0)} permissions | ${groups.length ? `Groups: ${groups.join(', ')}` : app.risk.reasons.join(', ')}`
    }];
    openSunbirdApplicationsRowsModal(app.name || 'Application evidence', rows);
}

function openSunbirdApplicationsRowsModal(title, rows) {
    const modal = ensureSunbirdApplicationsEvidenceModal();
    if (!modal) return;
    modal.innerHTML = `<div class="sunbird-id-modal-backdrop" onclick="closeSunbirdApplicationsEvidence()"></div><div class="sunbird-id-modal-panel" role="dialog" aria-modal="true"><div class="sunbird-id-modal-header"><div><h3>${escapeIdentityText(title)}</h3><p>${rows.length} evidence item${rows.length === 1 ? '' : 's'}.</p></div><button type="button" onclick="closeSunbirdApplicationsEvidence()" class="sunbird-id-modal-close">&times;</button></div><div class="sunbird-id-evidence-list">${rows.map(row => `<div class="sunbird-id-evidence-user"><strong>${escapeIdentityText(row.title)}</strong><span>${escapeIdentityText(row.subtitle)}</span><small>${escapeIdentityText(row.meta)}</small></div>`).join('')}</div><div class="sunbird-id-modal-actions"><button type="button" class="sunbird-id-evidence-btn" onclick="closeSunbirdApplicationsEvidence()">Close</button></div></div>`;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
}

function closeSunbirdApplicationsEvidence() {
    const modal = document.getElementById('sunbird-applications-evidence-modal');
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
}

function ensureSunbirdApplicationsEvidenceModal() {
    let modal = document.getElementById('sunbird-applications-evidence-modal');
    if (modal) return modal;
    modal = document.createElement('div');
    modal.id = 'sunbird-applications-evidence-modal';
    modal.className = 'sunbird-id-modal';
    modal.setAttribute('aria-hidden', 'true');
    document.body.appendChild(modal);
    return modal;
}

function toggleSunbirdApplicationsInsightEvidenceLock(evidenceKey) {
    const tile = document.querySelector(`.sunbird-id-insight[data-applications-evidence-key="${evidenceKey}"]`);
    if (!tile) return;
    const shouldLock = lockedSunbirdApplicationsInsightEvidenceKey !== evidenceKey;
    document.querySelectorAll('.sunbird-id-insight.locked').forEach(item => item.classList.remove('locked'));
    lockedSunbirdApplicationsInsightEvidenceKey = shouldLock ? evidenceKey : null;
    if (shouldLock) tile.classList.add('locked');
}

function handleSunbirdApplicationsInsightEvidenceKey(event, evidenceKey) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    toggleSunbirdApplicationsInsightEvidenceLock(evidenceKey);
}

function buildSunbirdApplicationsPermissionBuckets(apps) {
    return apps.reduce((acc, app) => {
        const permissions = (app.scopeCount || 0) + (app.roleCount || 0);
        if (permissions > 10) acc.high += 1;
        else if (permissions >= 4) acc.medium += 1;
        else acc.low += 1;
        return acc;
    }, { low: 0, medium: 0, high: 0 });
}

function calculateSunbirdApplicationsGovernanceScore(apps) {
    if (!apps.length) return 100;
    const externalRatio = apps.filter(app => app.isExternal || app.type === 'External').length / apps.length;
    const highAccessRatio = apps.filter(app => (app.userCount || 0) > 50).length / apps.length;
    const permissionRatio = apps.filter(app => ((app.scopeCount || 0) + (app.roleCount || 0)) > 10).length / apps.length;
    const groupRatio = apps.filter(app => (app.assignedGroups || []).length > 0).length / apps.length;
    return Math.max(0, Math.round(100 - ((externalRatio * 35) + (highAccessRatio * 25) + (permissionRatio * 25) + (groupRatio * 10))));
}

function buildSunbirdApplicationsRecommendations(apps, score) {
    const recs = [];
    const external = apps.filter(app => app.isExternal || app.type === 'External').length;
    const excessive = apps.filter(app => ((app.scopeCount || 0) + (app.roleCount || 0)) > 10).length;
    const highAccess = apps.filter(app => (app.userCount || 0) > 50).length;
    if (external) recs.push({ priority: 'high', title: 'Review external enterprise apps', detail: `${external} external app(s) are connected.` });
    if (excessive) recs.push({ priority: 'high', title: 'Review excessive permissions', detail: `${excessive} app(s) have more than 10 permissions.` });
    if (highAccess) recs.push({ priority: 'medium', title: 'Validate high access apps', detail: `${highAccess} app(s) have broad user access.` });
    if (!recs.length) recs.push({ priority: 'low', title: 'Maintain application governance', detail: `Governance score is ${score}%.` });
    return recs;
}

window.openSunbirdApplicationsDashboard = openSunbirdApplicationsDashboard;
window.openSunbirdApplicationsEvidence = openSunbirdApplicationsEvidence;
window.openSunbirdApplicationAppEvidence = openSunbirdApplicationAppEvidence;
window.closeSunbirdApplicationsEvidence = closeSunbirdApplicationsEvidence;
window.toggleSunbirdApplicationsInsightEvidenceLock = toggleSunbirdApplicationsInsightEvidenceLock;
window.handleSunbirdApplicationsInsightEvidenceKey = handleSunbirdApplicationsInsightEvidenceKey;

// Initialize  Identity Protection dashboard
function initializeIdentityDashboard() {
    console.log('[Identity Dashboard] Initializing dashboard...');
    console.log(`[Identity Dashboard] Users data available: ${microsoftUsersData.length}`);
    console.log(`[Identity Dashboard] Sunbird dashboard: ${isSunbirdDashboard}`);
    console.log('[Identity Dashboard] First user sample:', microsoftUsersData[0]);
    
    if (microsoftUsersData.length === 0) {
        console.warn('[Identity Dashboard] No user data available yet, retrying...');
        setTimeout(() => {
            if (microsoftUsersData.length > 0) {
                initializeIdentityDashboard();
            } else {
                fetchIdentityAccessData();
            }
        }, 700);
        return;
    }
    
    // Update dashboard content with Identity-specific layout
    const dashboardView = document.getElementById('dashboard-view');
    if (dashboardView) {
        dashboardView.innerHTML = generateIdentityDashboardHTML();
        // CRITICAL: Show the dashboard view!
        dashboardView.style.display = 'grid';
        dashboardView.style.visibility = 'visible';
        dashboardView.style.opacity = '1';
    }
    
    // Show loading skeleton immediately
    showIdentityTableLoadingSkeleton();
    
    // Use requestAnimationFrame to ensure DOM has rendered before populating
    requestAnimationFrame(() => {
        console.log('[Identity Dashboard] Initializing table, search, and insights');
        populateIdentityTable();
        setupIdentitySearch();
        initializeIdentityInsights();
    });
}

// Show loading skeleton while table data loads
function showIdentityTableLoadingSkeleton() {
    console.log('[Identity Skeleton] Creating skeleton rows...');
    const tableBody = document.getElementById('users-table-body');
    
    if (!tableBody) {
        console.warn('[Identity Skeleton] ⚠️ Table body not yet available, will retry');
        // Retry once more after a brief delay
        setTimeout(() => {
            const tb = document.getElementById('users-table-body');
            if (tb) {
                console.log('[Identity Skeleton] ✅ Table body found on retry');
                showIdentityTableLoadingSkeleton();
            } else {
                console.error('[Identity Skeleton] ❌ Table body still not found after retry');
            }
        }, 50);
        return;
    }
    
    console.log('[Identity Skeleton] ✅ Table body found, adding skeleton rows');
    tableBody.innerHTML = '';
    
    // Create 8 skeleton rows
    for (let i = 0; i < 8; i++) {
        const row = document.createElement('tr');
        row.className = 'skeleton-row';
        row.innerHTML = `
            <td><div class="skeleton-block"></div></td>
            <td><div class="skeleton-block"></div></td>
            <td><div class="skeleton-block"></div></td>
            <td><div class="skeleton-block"></div></td>
            <td><div class="skeleton-block"></div></td>
            <td><div class="skeleton-block"></div></td>
            <td><div class="skeleton-block"></div></td>
            <td><div class="skeleton-block"></div></td>
            <td><div class="skeleton-block"></div></td>
            <td><div class="skeleton-block"></div></td>
            <td><div class="skeleton-block"></div></td>
            <td><div class="skeleton-block"></div></td>
            <td><div class="skeleton-block"></div></td>
        `;
        tableBody.appendChild(row);
    }
    console.log('[Identity Skeleton] ✅ Skeleton rows added');
}

function setupIdentitySearch() {
    const searchInput = document.getElementById('user-search-input');
    const filterCheckboxes = document.querySelectorAll('.filter-checkbox input[type="checkbox"]');
    const clearFiltersBtn = document.getElementById('btn-clear-filters');
    const backBtn = document.getElementById('btn-back-identity');
    const tableContainer = document.querySelector('.identity-users-table-container');
    
    // Add horizontal scroll indicator when table can be scrolled
    if (tableContainer) {
        const updateScrollIndicator = () => {
            const isScrollable = tableContainer.scrollWidth > tableContainer.clientWidth;
            const isAtEnd = tableContainer.scrollLeft + tableContainer.clientWidth >= tableContainer.scrollWidth - 10;
            
            if (isScrollable && !isAtEnd) {
                tableContainer.classList.add('has-scroll');
            } else {
                tableContainer.classList.remove('has-scroll');
            }
        };

        // Check on load
        setTimeout(updateScrollIndicator, 300);
        
        // Update on scroll
        tableContainer.addEventListener('scroll', updateScrollIndicator);
        
        // Update as content changes or window resizes
        window.addEventListener('resize', updateScrollIndicator);
    }
    
    const isUserPrivileged = (user) => {
        const roleNames = (user.roles || []).map(role => typeof role === 'string' ? role : (role?.name || '')).join(' ').toLowerCase();
        return /(admin|global|privileged|security)/.test(roleNames);
    };

    const isUserActive24h = (user) => {
        const dt = user?.lastSignIn?.dateTime ? new Date(user.lastSignIn.dateTime) : null;
        if (!dt || Number.isNaN(dt.getTime())) return false;
        return (Date.now() - dt.getTime()) <= (24 * 60 * 60 * 1000);
    };

    const matchesRiskFocus = (user) => {
        if (identityRiskFocus === 'all') return true;
        if (identityRiskFocus === 'high-risk-users') return String(user.riskLevel || '').toUpperCase() === 'HIGH';
        if (identityRiskFocus === 'privileged-without-mfa') return isUserPrivileged(user) && !user.mfaEnabled;
        if (identityRiskFocus === 'active-users-24h') return isUserActive24h(user);
        return true;
    };

    // Function to apply all filters and search
    const applyFilters = () => {
        const searchTerm = searchInput?.value.toLowerCase() || '';
        const selectedFilters = Array.from(filterCheckboxes)
            .filter(cb => cb.checked)
            .map(cb => cb.dataset.filter);
        
        const rows = document.querySelectorAll('#users-table-body tr');
        
        rows.forEach((row, rowIndex) => {
            const name = row.cells[0]?.textContent.toLowerCase() || '';
            const email = row.cells[1]?.textContent.toLowerCase() || '';
            
            // Get the actual user data
            const user = microsoftUsersData[rowIndex];
            if (!user) return;
            
            // Search filter
            const matchesSearch = !searchTerm || name.includes(searchTerm) || email.includes(searchTerm);
            
            // Type filters
            let matchesTypeFilter = true;
            
            if (selectedFilters.length > 0) {
                const isInternal = !user.isExternal;
                const isExternal = user.isExternal;
                const hasRoles = (userRolesMap[user.id] && userRolesMap[user.id].length > 0) ||
                                (isSunbirdDashboard && user.roles && user.roles.length > 0);
                const hasMissingJobTitle = !user.jobTitle || user.jobTitle === 'No Title' || user.jobTitle.trim() === '';
                const hasMissingPhone = !user.mobilePhone || user.mobilePhone === 'N/A' || (typeof user.mobilePhone === 'string' && user.mobilePhone.trim() === '');
                const hasMissingData = hasMissingJobTitle || hasMissingPhone;
                
                matchesTypeFilter = 
                    (selectedFilters.includes('internal') && isInternal) ||
                    (selectedFilters.includes('external') && isExternal) ||
                    (selectedFilters.includes('admins') && hasRoles) ||
                    (selectedFilters.includes('missing-data') && hasMissingData);
            }
            
            const matchesRisk = matchesRiskFocus(user);
            row.style.display = (matchesSearch && matchesTypeFilter && matchesRisk) ? '' : 'none';
        });
    };
    
    // Add event listeners
    if (searchInput) {
        searchInput.addEventListener('input', applyFilters);
    }
    
    filterCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', applyFilters);
    });
    
    if (clearFiltersBtn) {
        clearFiltersBtn.addEventListener('click', () => {
            filterCheckboxes.forEach(cb => cb.checked = false);
            if (searchInput) searchInput.value = '';
            identityRiskFocus = 'all';
            document.querySelectorAll('.sunbird-summary-card.risk-filter-active').forEach(card => {
                card.classList.remove('risk-filter-active');
            });
            applyFilters();
        });
    }
    
    // Back button functionality
    if (backBtn) {
        backBtn.addEventListener('click', () => {
            goBackToProjects();
        });
    }

    // Expose for summary risk quick filters
    window.applyIdentityRiskFilters = applyFilters;

    if (pendingIdentityRiskFocus !== 'all') {
        identityRiskFocus = pendingIdentityRiskFocus;
        const targetCard = document.querySelector(`.sunbird-summary-card[data-risk-filter="${pendingIdentityRiskFocus}"]`);
        if (targetCard) {
            document.querySelectorAll('.sunbird-summary-card[data-risk-filter]').forEach(c => c.classList.remove('risk-filter-active'));
            targetCard.classList.add('risk-filter-active');
        }
        pendingIdentityRiskFocus = 'all';
        applyFilters();
    }
}

function initializeIdentityInsights() {
    console.log('[Identity Insights] Initializing insights and charts...');
    
    if (microsoftUsersData.length === 0) {
        console.warn('[Identity Insights] No user data available');
        return;
    }
    
    // Calculate data for insights
    const missingJobTitles = microsoftUsersData.filter(u => !u.jobTitle || u.jobTitle === 'No Title' || u.jobTitle.trim() === '').length;
    const missingPhones = microsoftUsersData.filter(u => !u.mobilePhone || u.mobilePhone === 'N/A' || (typeof u.mobilePhone === 'string' && u.mobilePhone.trim() === '')).length;
    const completeProfiles = microsoftUsersData.filter(u => (u.jobTitle && u.jobTitle !== 'No Title' && u.jobTitle.trim() !== '') && (u.mobilePhone && u.mobilePhone !== 'N/A' && typeof u.mobilePhone === 'string' && u.mobilePhone.trim() !== '')).length;
    
    // Update missing data display with null checks
    const missingJobTitlesEl = document.getElementById('missingJobTitles');
    const missingPhonesEl = document.getElementById('missingPhones');
    const completeProfilesEl = document.getElementById('completeProfiles');
    if (missingJobTitlesEl) missingJobTitlesEl.textContent = missingJobTitles;
    if (missingPhonesEl) missingPhonesEl.textContent = missingPhones;
    if (completeProfilesEl) completeProfilesEl.textContent = completeProfiles;
    
    // Calculate and update health score
    const healthScore = Math.round((completeProfiles / microsoftUsersData.length) * 100);
    const healthScoreValueEl = document.getElementById('healthScoreValue');
    const healthScoreProgressEl = document.getElementById('healthScoreProgress');
    if (healthScoreValueEl) healthScoreValueEl.textContent = healthScore;
    if (healthScoreProgressEl) healthScoreProgressEl.style.width = healthScore + '%';
    
    // Update risk panel
    const hasBreakGlass = microsoftUsersData.some(u => u.mail?.toLowerCase().includes('break glass'));
    const riskCriticalDiv = document.getElementById('riskCritical');
    if (hasBreakGlass && riskCriticalDiv) {
        riskCriticalDiv.style.display = 'flex';
    }
    
    const riskMediumText = document.getElementById('riskMediumText');
    if (riskMediumText) riskMediumText.textContent = missingPhones;
    if (riskMediumText) {
        riskMediumText.textContent = `Medium Risk: ${missingJobTitles} users without job titles, ${missingPhones} users without phone`;
    }
    
    // Initialize charts
    initializeIdentityCharts();
    
    // Initialize Sunbird-specific analytics if available
    renderSunbirdAnalytics();
}

function initializeIdentityCharts() {
    console.log('[Identity Charts] Initializing all charts...');
    
    // Ensure Chart.js is loaded
    if (typeof Chart === 'undefined') {
        console.warn('[Identity Charts] Chart.js not loaded yet, retrying in 100ms...');
        setTimeout(initializeIdentityCharts, 100);
        return;
    }
    
    // Give DOM time to settle
    setTimeout(() => {
        // Job Title Distribution
        const jobTitleDistribution = {};
        microsoftUsersData.forEach(u => {
            const title = (u.jobTitle && u.jobTitle !== 'No Title') ? u.jobTitle : 'Missing';
            jobTitleDistribution[title] = (jobTitleDistribution[title] || 0) + 1;
        });
        
        // Get top 8 job titles
        const sortedTitles = Object.entries(jobTitleDistribution).sort((a, b) => b[1] - a[1]).slice(0, 8);
        const jobTitleLabels = sortedTitles.map(t => t[0].substring(0, 15));
        const jobTitleData = sortedTitles.map(t => t[1]);
        
        renderJobTitleChart(jobTitleLabels, jobTitleData);
        
        // Contact Completeness
        const hasPhone = microsoftUsersData.filter(u => u.mobilePhone && u.mobilePhone !== 'N/A' && typeof u.mobilePhone === 'string' && u.mobilePhone.trim() !== '').length;
        const noPhone = microsoftUsersData.length - hasPhone;
        renderContactChart(hasPhone, noPhone);
        
        // User Type Distribution
        const internalCount = microsoftUsersData.filter(u => !u.isExternal).length;
        const externalCount = microsoftUsersData.filter(u => u.isExternal).length;
        renderUserTypeChart(internalCount, externalCount);
        
        // Active Status
        const activeCount = microsoftUsersData.length;
        const inactiveCount = 0;
        renderActiveStatusChart(activeCount, inactiveCount);
        
        // Role Distribution  
        renderSunbirdRoleDistributionChart();
        
        // Admin users list
        populateAdminUsersList();
        
        // Risk indicator
        populateRiskIndicator();
        
        // Security insights
        populateSecurityInsights();
    }, 50);
}

function renderJobTitleChart(labels, data) {
    const canvasElement = document.getElementById('jobTitleChart');
    if (!canvasElement) return;
    
    // Set canvas dimensions
    canvasElement.width = canvasElement.parentElement.clientWidth;
    canvasElement.height = 250;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.jobTitleChartInstance && typeof window.jobTitleChartInstance.destroy === 'function') {
        window.jobTitleChartInstance.destroy();
    }
    
    window.jobTitleChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Count',
                data: data,
                backgroundColor: 'rgba(0, 110, 255, 0.6)',
                borderColor: 'rgba(0, 110, 255, 1)',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            indexAxis: 'y',
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: { color: '#999' },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' }
                },
                y: {
                    ticks: { color: '#999', font: { size: 11 } },
                    grid: { display: false }
                }
            }
        }
    });
}

function renderContactChart(hasPhone, noPhone) {
    const canvasElement = document.getElementById('contactChart');
    if (!canvasElement) return;
    
    // Set canvas dimensions
    canvasElement.width = canvasElement.parentElement.clientWidth;
    canvasElement.height = 250;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.contactChartInstance && typeof window.contactChartInstance.destroy === 'function') {
        window.contactChartInstance.destroy();
    }
    
    window.contactChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Has Phone', 'Missing Phone'],
            datasets: [{
                data: [hasPhone, noPhone],
                backgroundColor: [
                    'rgba(34, 197, 94, 0.7)',
                    'rgba(220, 53, 69, 0.7)'
                ],
                borderColor: [
                    'rgba(34, 197, 94, 1)',
                    'rgba(220, 53, 69, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: { color: '#999', font: { size: 11 } }
                }
            }
        }
    });
}

function renderUserTypeChart(internal, external) {
    const canvasElement = document.getElementById('userTypeChart');
    if (!canvasElement) return;
    
    // Set canvas dimensions
    canvasElement.width = canvasElement.parentElement.clientWidth;
    canvasElement.height = 250;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.userTypeChartInstance && typeof window.userTypeChartInstance.destroy === 'function') {
        window.userTypeChartInstance.destroy();
    }
    
    window.userTypeChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Internal', 'External'],
            datasets: [{
                data: [internal, external],
                backgroundColor: [
                    'rgba(34, 197, 94, 0.7)',
                    'rgba(249, 115, 22, 0.7)'
                ],
                borderColor: [
                    'rgba(34, 197, 94, 1)',
                    'rgba(249, 115, 22, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: { color: '#999', font: { size: 11 } }
                }
            }
        }
    });
}

function renderActiveStatusChart(active, inactive) {
    const canvasElement = document.getElementById('activeStatusChart');
    if (!canvasElement) return;
    
    // Set canvas dimensions
    canvasElement.width = canvasElement.parentElement.clientWidth;
    canvasElement.height = 250;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.activeStatusChartInstance && typeof window.activeStatusChartInstance.destroy === 'function') {
        window.activeStatusChartInstance.destroy();
    }
    
    window.activeStatusChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Active', 'Inactive'],
            datasets: [{
                data: [active, inactive],
                backgroundColor: [
                    'rgba(34, 197, 94, 0.7)',
                    'rgba(107, 114, 128, 0.7)'
                ],
                borderColor: [
                    'rgba(34, 197, 94, 1)',
                    'rgba(107, 114, 128, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: { color: '#999', font: { size: 11 } }
                }
            }
        }
    });
}

// Render Role Distribution Chart
function renderRoleDistributionChart() {
    const canvasElement = document.getElementById('roleDistributionChart');
    if (!canvasElement) return;
    
    // Count roles distribution
    const roleDistribution = {};
    microsoftRolesData.forEach(assignment => {
        const roleName = assignment.roleName || 'Unknown';
        roleDistribution[roleName] = (roleDistribution[roleName] || 0) + 1;
    });
    
    const labels = Object.keys(roleDistribution).slice(0, 10); // Top 10 roles
    const data = labels.map(role => roleDistribution[role]);
    
    // Set canvas dimensions
    canvasElement.width = canvasElement.parentElement.clientWidth;
    canvasElement.height = 250;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.roleDistributionChartInstance && typeof window.roleDistributionChartInstance.destroy === 'function') {
        window.roleDistributionChartInstance.destroy();
    }
    
    const colors = [
        'rgba(0, 110, 255, 0.8)',
        'rgba(249, 115, 22, 0.8)',
        'rgba(34, 197, 94, 0.8)',
        'rgba(248, 113, 113, 0.8)',
        'rgba(132, 204, 22, 0.8)',
        'rgba(168, 85, 247, 0.8)',
        'rgba(14, 165, 233, 0.8)',
        'rgba(236, 72, 153, 0.8)',
        'rgba(251, 146, 60, 0.8)',
        'rgba(59, 130, 246, 0.8)'
    ];
    
    window.roleDistributionChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Number of Assignments',
                data: data,
                backgroundColor: colors.slice(0, labels.length),
                borderColor: colors.slice(0, labels.length).map(c => c.replace('0.8', '1')),
                borderWidth: 1,
                borderRadius: 4,
                barThickness: 20
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        color: '#999',
                        font: { size: 11 }
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    }
                },
                y: {
                    ticks: {
                        color: '#999',
                        font: { size: 11 }
                    },
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

// Populate Admin Users List
function populateAdminUsersList() {
    const adminListContainer = document.getElementById('admin-users-list');
    if (!adminListContainer) return;
    
    const usersWithRoles = Object.entries(userRolesMap)
        .map(([userId, roles]) => {
            const user = microsoftUsersData.find(u => u.id === userId);
            if (!user) return null;
            return {
                ...user,
                roles: roles,
                isGlobalAdmin: roles.some(role => role.toLowerCase().includes('global admin') || role.toLowerCase().includes('company administrator')),
                isSecurityAdmin: roles.some(role => role.toLowerCase().includes('security admin')),
                isPrivileged: roles.some(role => 
                    role.toLowerCase().includes('admin') || 
                    role.toLowerCase().includes('owner') || 
                    role.toLowerCase().includes('manager')
                )
            };
        })
        .filter(user => user && user.isPrivileged)
        .sort((a, b) => (b.isGlobalAdmin ? 1 : 0) - (a.isGlobalAdmin ? 1 : 0));
    
    if (usersWithRoles.length === 0) {
        adminListContainer.innerHTML = '<p style="text-align: center; color: #999; padding: 20px;">No admin users found</p>';
        return;
    }
    
    let html = '<div class="admin-stats">';
    
    const globalAdmins = usersWithRoles.filter(u => u.isGlobalAdmin).length;
    const securityAdmins = usersWithRoles.filter(u => u.isSecurityAdmin).length;
    const privilegedUsers = usersWithRoles.length;
    
    html += `
        <div class="admin-stat-item">
            <span class="stat-label">👑 Global Admins:</span>
            <span class="stat-value">${globalAdmins}</span>
        </div>
        <div class="admin-stat-item">
            <span class="stat-label">🔐 Security Admins:</span>
            <span class="stat-value">${securityAdmins}</span>
        </div>
        <div class="admin-stat-item">
            <span class="stat-label">⭐ Privileged Users:</span>
            <span class="stat-value">${privilegedUsers}</span>
        </div>
    </div>
    
    <div class="admin-users-table">
        <div class="admin-user-header">
            <span>User</span>
            <span>Roles</span>
        </div>
    `;
    
    usersWithRoles.slice(0, 10).forEach(user => {
        const rolesList = user.roles.map(role => {
            let badgeClass = 'role-badge-normal';
            if (role.toLowerCase().includes('global admin') || role.toLowerCase().includes('company administrator')) {
                badgeClass = 'role-badge-critical';
            } else if (role.toLowerCase().includes('security admin')) {
                badgeClass = 'role-badge-warning';
            }
            return `<span class="${badgeClass}">${role}</span>`;
        }).join('');
        
        html += `
            <div class="admin-user-item">
                <span class="user-name">${user.displayName || 'Unknown User'}</span>
                <span class="user-roles">${rolesList}</span>
            </div>
        `;
    });
    
    html += '</div>';
    
    if (usersWithRoles.length > 10) {
        html += `<p style="text-align: center; color: #999; font-size: 0.85em; margin-top: 10px;">+${usersWithRoles.length - 10} more admin users</p>`;
    }
    
    adminListContainer.innerHTML = html;
}

// ============================================
// SECURITY & RISK ASSESSMENT API
// ============================================
// Analyzes security risks including admin privileges,
// break glass accounts, and multi-role users

// Populate Risk Indicator
function populateRiskIndicator() {
    const riskContainer = document.getElementById('risk-summary');
    if (!riskContainer) return;
    
    const usersWithRoles = Object.keys(userRolesMap).length;
    const totalAdmins = Object.entries(userRolesMap)
        .filter(([_, roles]) => roles.some(role => role.toLowerCase().includes('admin')))
        .length;
    
    // Find break glass account
    const breakGlassUser = microsoftUsersData.find(u => 
        u.mail?.toLowerCase().includes('break glass') || 
        u.displayName?.toLowerCase().includes('break glass')
    );
    const hasBreakGlass = !!breakGlassUser;
    
    let riskLevel = 'LOW';
    let riskColor = '#22c55e'; // green
    let riskEmoji = '✅';
    
    if (hasBreakGlass) {
        riskLevel = 'CRITICAL';
        riskColor = '#dc2626'; // red
        riskEmoji = '🔥';
    } else if (totalAdmins > 5) {
        riskLevel = 'HIGH';
        riskColor = '#dc2626'; // red
        riskEmoji = '🔴';
    } else if (totalAdmins > 3) {
        riskLevel = 'MEDIUM';
        riskColor = '#f59e0b'; // orange
        riskEmoji = '🟡';
    }
    
    let html = `
        <div class="risk-indicator" style="border-left: 4px solid ${riskColor}; padding-left: 15px;">
            <!-- RISK LEVEL STATS (TOP) -->
            <div class="risk-level-display">
                <span class="risk-emoji">${riskEmoji}</span>
                <div class="risk-info">
                    <span class="risk-level" style="color: ${riskColor};">${riskLevel}</span>
                    <span class="risk-description">Risk Level</span>
                </div>
            </div>
            
            <!-- RISK STATS - Labels Left, Values Right -->
            <div class="risk-details" style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.1);">
                <div class="risk-detail-item" style="display: flex; width: 100%; font-size: 0.9rem;">
                    <span style="flex: 0 0 auto;">Total Admin Users:</span>
                    <span class="detail-value" style="flex: 1; text-align: right;">${totalAdmins}</span>
                </div>
    `;
    
    if (hasBreakGlass) {
        html += `
                <div class="risk-detail-item" style="display: flex; width: 100%; color: #dc2626; margin-top: 10px; font-size: 0.9rem;">
                    <span style="flex: 0 0 auto;">⚠️ Master Admin (Break Glass):</span>
                    <span class="detail-value" style="flex: 1; text-align: right; color: #0066ff;">${(breakGlassUser.displayName || breakGlassUser.mail || 'Unknown').substring(0, 50)}</span>
                </div>
        `;
    }
    
    if (totalAdmins > 5) {
        html += `
                <div class="risk-detail-item" style="display: flex; width: 100%; color: #dc2626; margin-top: 10px; font-size: 0.9rem;">
                    <span style="flex: 0 0 auto;">⚠️ Excessive Admin Privileges:</span>
                    <span class="detail-value" style="flex: 1; text-align: right;">${totalAdmins} users</span>
                </div>
        `;
    }
    
    html += `
            </div>
    `;
    
    // BELOW: Recommended Actions section (stacked vertically)
    if (hasBreakGlass || totalAdmins > 5) {
        html += `
            <div class="risk-todo-section" style="margin-top: 20px; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 6px; border-left: 3px solid ${riskColor};">
                <h4 style="margin: 0 0 12px 0; font-size: 0.95rem; color: #e0e0e0; font-weight: 200;">📋 Recommended Actions:</h4>
                <ul style="margin: 0; padding-left: 20px; list-style: disc; display: flex; flex-direction: column; gap: 8px;">
        `;
        
        if (hasBreakGlass) {
            html += `
                    <li style="color: #d1d5db; font-size: 0.8rem;">
                        <strong>Secure Break Glass Account:</strong> Limit access, enable MFA, audit recent activities
                    </li>
                    <li style="color: #d1d5db; font-size: 0.8rem;">
                        <strong>Review Permissions:</strong> Ensure Break Glass is only used for emergencies
                    </li>
            `;
        }
        
        if (totalAdmins > 5) {
            html += `
                    <li style="color: #d1d5db; font-size: 0.8rem;">
                        <strong>Audit Admin Roles:</strong> Remove unnecessary admin privileges from users
                    </li>
                    <li style="color: #d1d5db; font-size: 0.8rem;">
                        <strong>Implement Principle of Least Privilege:</strong> Assign specific admin roles instead of global admin
                    </li>
                    <li style="color: #d1d5db; font-size: 0.8rem;">
                        <strong>Target Goal:</strong> Reduce admin count to 3-5 key administrators
                    </li>
            `;
        }
        
        html += `
                </ul>
            </div>
        `;
    }
    
    html += `
        </div>
    `;
    
    riskContainer.innerHTML = html;
}

// ============================================
// SECURITY INSIGHTS API
// ============================================
// Provides detailed security insights for multi-role users,
// admins without phone numbers, and privilege analysis

// Populate Security Insights
function populateSecurityInsights() {
    const insightsContainer = document.getElementById('security-insights-list');
    if (!insightsContainer) return;
    
    const insights = [];
    
    // Find users with multiple roles
    const multiRoleUsers = Object.entries(userRolesMap)
        .filter(([_, roles]) => roles.length > 2)
        .map(([userId, roles]) => {
            const user = microsoftUsersData.find(u => u.id === userId);
            return { user: user?.displayName || user?.mail || 'Unknown', roleCount: roles.length, roles };
        });
    
    if (multiRoleUsers.length > 0) {
        const usersList = multiRoleUsers
            .sort((a, b) => b.roleCount - a.roleCount)
            .map(u => `${u.user} (${u.roleCount} roles)`)
            .join(', ');
        
        insights.push({
            icon: '⚠️',
            title: 'Users with Multiple Admin Roles',
            description: `${multiRoleUsers.length} user(s) have multiple roles:<br><strong>${usersList}</strong>`,
            severity: 'warning'
        });
    }
    
    // Find external users (highest security concern)
    const externalAdmins = Object.entries(userRolesMap)
        .map(([userId, roles]) => {
            const user = microsoftUsersData.find(u => u.id === userId);
            return { user, roles };
        })
        .filter(({ user }) => user && user.isExternal);
    
    if (externalAdmins.length > 0) {
        insights.push({
            icon: '🔴',
            title: 'External Users with Roles',
            description: `${externalAdmins.length} external user(s) have administrative roles assigned.`,
            severity: 'critical'
        });
    }
    
    // Check for users with incomplete profiles
    const adminsWithoutPhoneList = Object.entries(userRolesMap)
        .map(([userId, _]) => {
            const user = microsoftUsersData.find(u => u.id === userId);
            return user;
        })
        .filter(user => user && (!user.mobilePhone || user.mobilePhone === 'N/A'));
    
    if (adminsWithoutPhoneList.length > 0) {
        const phonelessList = adminsWithoutPhoneList
            .map(u => u.displayName || u.mail || 'Unknown')
            .slice(0, 10)
            .join(', ');
        const moreText = adminsWithoutPhoneList.length > 10 ? `<br>... and ${adminsWithoutPhoneList.length - 10} more` : '';
        
        insights.push({
            icon: '📱',
            title: 'Admins Without Phone',
            description: `${adminsWithoutPhoneList.length} admin(s) don't have phone numbers on file:<br><strong>${phonelessList}</strong>${moreText}`,
            severity: 'medium'
        });
    }
    
    // High admin ratio
    const totalAdmins = Object.keys(userRolesMap).length;
    const adminRatio = (totalAdmins / microsoftUsersData.length * 100).toFixed(1);
    
    if (adminRatio > 20) {
        insights.push({
            icon: '📊',
            title: 'High Admin Ratio',
            description: `${adminRatio}% of users have administrative roles (recommended: <10%).`,
            severity: 'medium'
        });
    }
    
    if (insights.length === 0) {
        insightsContainer.innerHTML = '<p style="text-align: center; color: #22c55e; padding: 20px;">✅ No security concerns detected</p>';
        return;
    }
    
    let html = '<div class="insights-list">';
    
    insights.forEach(insight => {
        const severityClass = `insight-${insight.severity}`;
        html += `
            <div class="insight-item ${severityClass}">
                <span class="insight-icon">${insight.icon}</span>
                <div class="insight-content">
                    <div class="insight-title">${insight.title}</div>
                    <div class="insight-description">${insight.description}</div>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    insightsContainer.innerHTML = html;
}

/* ============================================================== */
/* SUNBIRD ANALYTICS RENDERING FUNCTIONS                          */
/* ============================================================== */

// Render Sunbird Summary Cards (Security Score, Risk, Activity)
function renderSunbirdSummaryCards() {
    const summaryCardsDiv = document.getElementById('sunbird-summary-cards');
    if (!summaryCardsDiv || !sunbirdDashboardData || !sunbirdDashboardData.summary) return;

    const securityScore = Math.round(sunbirdDashboardData.summary.securityScore || 0);
    const identityRiskScore = Math.round(sunbirdDashboardData.summary.identityRiskScore || 0);
    const activeUsers = sunbirdDashboardData.summary.activeUsers24h || 0;
    const activeUsersPercentage = sunbirdDashboardData.summary.activeUsersPercentage || 0;
    const highRiskUsers = sunbirdDashboardData.summary.highRiskUsers || 0;
    const privilegedWithoutMFA = sunbirdDashboardData.summary.privilegedUsersWithoutMFA || 0;

    // Update summary card values with improved context
    document.getElementById('sunbird-security-score').textContent = securityScore;
    document.getElementById('sunbird-active-users').innerHTML = `<span style="font-size: 1.3rem;">${activeUsers}</span><span style="font-size: 0.75rem; opacity: 0.7; display: block;">${activeUsersPercentage}%</span>`;
    document.getElementById('sunbird-high-risk').textContent = highRiskUsers;
    document.getElementById('sunbird-privileged-without-mfa').textContent = privilegedWithoutMFA;
    document.getElementById('sunbird-identity-risk-score').textContent = identityRiskScore;

    // Update identity hygiene if the element exists
    const hygieneElement = document.getElementById('sunbird-identity-hygiene');
    if (hygieneElement) {
        const hygieneScore = sunbirdDashboardData.summary.identityHygieneScore || 0;
        hygieneElement.textContent = hygieneScore;
    }

    summaryCardsDiv.style.display = 'grid';
    setupSunbirdRiskQuickFilters();
}

function setupSunbirdRiskQuickFilters() {
    const cards = document.querySelectorAll('.sunbird-summary-card[data-risk-filter]');
    cards.forEach(card => {
        card.onclick = () => {
            const filterKey = card.dataset.riskFilter || 'all';

            if (identityRiskFocus === filterKey) {
                identityRiskFocus = 'all';
                card.classList.remove('risk-filter-active');
            } else {
                identityRiskFocus = filterKey;
                document.querySelectorAll('.sunbird-summary-card[data-risk-filter]').forEach(c => c.classList.remove('risk-filter-active'));
                card.classList.add('risk-filter-active');
            }

            if (typeof window.applyIdentityRiskFilters === 'function') {
                window.applyIdentityRiskFilters();
            }
        };
    });
}

function collectSunbirdRiskItems() {
    const rawItems = [];

    const pushItem = (tab, risk, severity, insight) => {
        rawItems.push({ tab, risk, severity, insight });
    };

    if (sunbirdDashboardData?.summary) {
        const summary = sunbirdDashboardData.summary;
        pushItem('Identity Protection', 'Privileged Without MFA', 'high', `${summary.privilegedUsersWithoutMFA || 0} privileged accounts without MFA.`);
        pushItem('Identity Protection', 'High Risk Users', 'high', `${summary.highRiskUsers || 0} users classified as HIGH risk.`);
        pushItem('Identity Protection', 'Active Users (24h)', 'medium', `${summary.activeUsers24h || 0} users active in the last 24 hours.`);
    }

    if (cachedSunbirdSecurityData?.summary) {
        const sec = cachedSunbirdSecurityData.summary;
        pushItem('Security Alerts', 'High Severity Alerts', 'high', `${sec.highSeverityAlerts || 0} high severity alerts currently open.`);
        pushItem('Security Alerts', 'Active Incidents', 'high', `${sec.activeIncidents || 0} active incidents require investigation.`);
    }

    if (cachedSunbirdBackupData?.summary) {
        const backup = cachedSunbirdBackupData.summary;
        pushItem('Backup & Recovery', 'Storage Growth Risk', 'medium', `${backup.totalStorageGB || 0} GB protected storage to monitor for growth.`);
        pushItem('Backup & Recovery', 'Coverage Risk', 'medium', `${backup.activeUsersCount || 0} active users currently included in coverage.`);
    }

    // Include all project-card level risk footers so we don't miss existing risk hints.
    mockProjects.forEach(project => {
        const footer = project.cardFooter || '';
        if (/risk|risks|threat|alert/i.test(footer)) {
            const severity = /high|critical/i.test(footer) ? 'high' : /medium/i.test(footer) ? 'medium' : 'low';
            pushItem(project.name, 'Card Risk Summary', severity, footer);
        }
    });

    const normalizeTab = (tab) => {
        if (tab === 'Identity Protection') return 'Identity Protection';
        if (tab === 'Security Alerts') return 'Security Alerts';
        if (tab === 'Backup & Recovery') return 'Backup & Recovery';
        return 'Applications/Others';
    };

    const dedupMap = new Map();
    rawItems.forEach(item => {
        const tab = normalizeTab(item.tab);
        const key = `${tab}|${item.risk}`.toLowerCase();
        const existing = dedupMap.get(key);

        if (!existing) {
            dedupMap.set(key, {
                tab,
                risk: item.risk,
                severity: item.severity,
                insights: [item.insight]
            });
            return;
        }

        // Keep highest severity across duplicates.
        const rank = { high: 3, medium: 2, low: 1 };
        if ((rank[item.severity] || 0) > (rank[existing.severity] || 0)) {
            existing.severity = item.severity;
        }

        if (!existing.insights.includes(item.insight)) {
            existing.insights.push(item.insight);
        }
    });

    const tabOrder = {
        'Identity Protection': 1,
        'Security Alerts': 2,
        'Backup & Recovery': 3,
        'Applications/Others': 4
    };
    const severityRank = { high: 1, medium: 2, low: 3 };

    return Array.from(dedupMap.values())
        .map(item => ({
            tab: item.tab,
            risk: item.risk,
            severity: item.severity,
            insight: item.insights.join(' ')
        }))
        .sort((a, b) =>
            (tabOrder[a.tab] || 99) - (tabOrder[b.tab] || 99) ||
            (severityRank[a.severity] || 99) - (severityRank[b.severity] || 99) ||
            a.risk.localeCompare(b.risk)
        );
}

window.viewRiskFromRegister = function(encodedTab, encodedRisk) {
    const tab = decodeURIComponent(encodedTab || '');
    const risk = decodeURIComponent(encodedRisk || '');

    if (tab === 'Identity Protection') {
        const identityProject = mockProjects.find(p => p.id === 2 || p.isIdentityCard);
        if (identityProject) {
            if (/privileged without mfa/i.test(risk)) {
                pendingIdentityRiskFocus = 'privileged-without-mfa';
            } else if (/high risk users/i.test(risk)) {
                pendingIdentityRiskFocus = 'high-risk-users';
            } else if (/active users/i.test(risk)) {
                pendingIdentityRiskFocus = 'active-users-24h';
            } else {
                pendingIdentityRiskFocus = 'all';
            }
            openDashboard(identityProject);
        }
        return;
    }

    if (tab === 'Security Alerts') {
        const secProject = mockProjects.find(p => p.isSecurityCard);
        if (secProject) openDashboard(secProject);
        return;
    }

    if (tab === 'Backup & Recovery') {
        const backupProject = mockProjects.find(p => p.isBackupRecoveryCard);
        if (backupProject) openDashboard(backupProject);
        return;
    }

    // Applications / other project card summaries
    const appProject = mockProjects.find(p => p.isApplicationsCard) || mockProjects.find(p => p.name === 'Applications');
    if (appProject) {
        openDashboard(appProject);
    }
};

async function renderSunbirdRisksView(forceRefresh = false) {
    const billingCard = document.getElementById('billing-card');
    if (!billingCard) return;
    if (!isSunbirdBillingViewActive('risks')) return;

    try {
        billingCard.innerHTML = renderSunbirdPremiumLoader('Loading risk register');

        // Pull latest risk sources where available.
        if (forceRefresh || !cachedSunbirdSecurityData) {
            try { cachedSunbirdSecurityData = await fetchSunbirdSecurityEventsData(); } catch (_) {}
        }
        if (forceRefresh || !cachedSunbirdBackupData) {
            try { cachedSunbirdBackupData = await fetchSunbirdBackupRecoveryData(); } catch (_) {}
        }
        if (!sunbirdDashboardData) {
            try { await fetchIdentityAccessData(); } catch (_) {}
        }

        const riskItems = collectSunbirdRiskItems();
        const rowsHtml = riskItems.length
            ? riskItems.map(item => `
                <tr>
                    <td>${item.tab}</td>
                    <td>${item.risk}</td>
                    <td><span class="sunbird-risk-pill ${item.severity}">${item.severity.toUpperCase()}</span></td>
                    <td>${item.insight}</td>
                    <td>
                        <button class="sunbird-risk-view-btn" onclick="window.viewRiskFromRegister('${encodeURIComponent(item.tab)}','${encodeURIComponent(item.risk)}')">
                            View
                        </button>
                    </td>
                </tr>
            `).join('')
            : '<tr><td colspan="5" class="sunbird-empty-row">No risks available</td></tr>';

        if (!isSunbirdBillingViewActive('risks')) return;
        billingCard.innerHTML = `
            <div class="sunbird-panel-view">
                <div class="billing-card-header">
                    <i class="fas fa-triangle-exclamation"></i>
                    <h3>Risks Register</h3>
                </div>
                <div class="sunbird-section-title">All Risks by Tab</div>
                <div class="sunbird-risk-list-wrap">
                    <table class="sunbird-incidents-table sunbird-risk-table">
                        <thead>
                            <tr>
                                <th>Tab</th>
                                <th>Risk</th>
                                <th>Severity</th>
                                <th>Insight</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>${rowsHtml}</tbody>
                    </table>
                </div>
            </div>
        `;
    } finally {
        ensureSunbirdBillingCardDimensions();
        syncSunbirdLeftMenuHeight();
    }
}

// Render System Health Radar Chart
function renderSystemHealthRadar() {
    const canvasElement = document.getElementById('systemHealthRadar');
    if (!canvasElement || !sunbirdDashboardData || !sunbirdDashboardData.systemHealth) return;

    const health = sunbirdDashboardData.systemHealth || {};
    
    // Set canvas dimensions
    canvasElement.width = 400;
    canvasElement.height = 300;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.systemHealthRadarInstance && typeof window.systemHealthRadarInstance.destroy === 'function') {
        window.systemHealthRadarInstance.destroy();
    }

    window.systemHealthRadarInstance = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: ['Performance', 'Availability', 'Security', 'Compliance', 'Backup'],
            datasets: [{
                label: 'System Health',
                data: [
                    health.performance || 0,
                    health.availability || 0,
                    health.security || 0,
                    health.compliance || 0,
                    health.backup || 0
                ],
                borderColor: 'rgba(0, 110, 255, 0.8)',
                backgroundColor: 'rgba(0, 110, 255, 0.2)',
                borderWidth: 2,
                fill: true,
                pointRadius: 4,
                pointBackgroundColor: 'rgba(0, 110, 255, 0.9)',
                pointBorderColor: '#fff',
                pointBorderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#999', font: { size: 11, weight: 200 } },
                    display: true
                }
            },
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        color: '#666',
                        font: { size: 10, weight: 200 }
                    },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' }
                }
            }
        }
    });
}

// Render Risk Distribution Pie Chart
function renderRiskDistributionPie() {
    const canvasElement = document.getElementById('riskDistributionPie');
    if (!canvasElement || !sunbirdDashboardData) return;

    const riskDist = sunbirdDashboardData.riskDistribution || {};
    const highRisk = riskDist.HIGH || 0;
    const mediumRisk = riskDist.MEDIUM || 0;
    const safeRisk = riskDist.SAFE || 0;

    // Set canvas dimensions
    canvasElement.width = 300;
    canvasElement.height = 250;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.riskDistributionPieInstance && typeof window.riskDistributionPieInstance.destroy === 'function') {
        window.riskDistributionPieInstance.destroy();
    }

    window.riskDistributionPieInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['🔴 High Risk', '🟡 Medium Risk', '🟢 Safe'],
            datasets: [{
                data: [highRisk, mediumRisk, safeRisk],
                backgroundColor: [
                    'rgba(220, 53, 69, 0.7)',
                    'rgba(249, 115, 22, 0.7)',
                    'rgba(34, 197, 94, 0.7)'
                ],
                borderColor: [
                    'rgba(220, 53, 69, 1)',
                    'rgba(249, 115, 22, 1)',
                    'rgba(34, 197, 94, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#999', font: { size: 11, weight: 200 } },
                    position: 'bottom'
                }
            }
        }
    });
}

// 🆕 Render Authentication Strength Chart
function renderAuthenticationStrengthChart() {
    const canvasElement = document.getElementById('authenticationStrengthChart');
    if (!canvasElement || !sunbirdDashboardData || !sunbirdDashboardData.authenticationStrength) return;

    const authStrength = sunbirdDashboardData.authenticationStrength || { passwordOnly: 0, basicMFA: 0, strongMFA: 0 };
    canvasElement.width = 300;
    canvasElement.height = 250;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.authStrengthInstance && typeof window.authStrengthInstance.destroy === 'function') {
        window.authStrengthInstance.destroy();
    }

    window.authStrengthInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['❌ Password Only', '⚠️ Basic MFA', '✅ Strong MFA'],
            datasets: [{
                data: [authStrength.passwordOnly, authStrength.basicMFA, authStrength.strongMFA],
                backgroundColor: [
                    'rgba(220, 53, 69, 0.7)',
                    'rgba(249, 115, 22, 0.7)',
                    'rgba(34, 197, 94, 0.7)'
                ],
                borderColor: [
                    'rgba(220, 53, 69, 1)',
                    'rgba(249, 115, 22, 1)',
                    'rgba(34, 197, 94, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: '#999', font: { size: 11, weight: 200 } }, position: 'bottom' }
            }
        }
    });
}

// 🆕 Render Device Trust Analysis Chart
function renderDeviceTrustChart() {
    const canvasElement = document.getElementById('deviceTrustChart');
    if (!canvasElement || !sunbirdDashboardData || !sunbirdDashboardData.deviceTrustAnalysis) return;

    const deviceTrust = sunbirdDashboardData.deviceTrustAnalysis || { managed: 0, unmanaged: 0, unknown: 0 };
    canvasElement.width = 300;
    canvasElement.height = 250;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.deviceTrustInstance && typeof window.deviceTrustInstance.destroy === 'function') {
        window.deviceTrustInstance.destroy();
    }

    window.deviceTrustInstance = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['✅ Managed', '⚠️ Unmanaged', '❓ Unknown'],
            datasets: [{
                data: [deviceTrust.managed, deviceTrust.unmanaged, deviceTrust.unknown],
                backgroundColor: [
                    'rgba(34, 197, 94, 0.7)',
                    'rgba(249, 115, 22, 0.7)',
                    'rgba(107, 114, 128, 0.7)'
                ],
                borderColor: [
                    'rgba(34, 197, 94, 1)',
                    'rgba(249, 115, 22, 1)',
                    'rgba(107, 114, 128, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: '#999', font: { size: 11, weight: 200 } }, position: 'bottom' }
            }
        }
    });
}

// 🆕 Render Sunbird Role Distribution Chart
function renderSunbirdRoleDistributionChart() {
    const canvasElement = document.getElementById('roleDistributionChart');
    if (!canvasElement || !sunbirdDashboardData || !sunbirdDashboardData.topRoles) return;

    const roles = sunbirdDashboardData.topRoles || [];
    const labels = roles.map(r => r.role.substring(0, 20)).slice(0, 8);
    const data = roles.map(r => r.count).slice(0, 8);

    canvasElement.width = 400;
    canvasElement.height = 250;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.roleDistributionInstance && typeof window.roleDistributionInstance.destroy === 'function') {
        window.roleDistributionInstance.destroy();
    }

    const colors = [
        'rgba(59, 130, 246, 0.7)',
        'rgba(34, 197, 94, 0.7)',
        'rgba(249, 115, 22, 0.7)',
        'rgba(139, 92, 246, 0.7)',
        'rgba(236, 72, 153, 0.7)',
        'rgba(14, 165, 233, 0.7)',
        'rgba(168, 85, 247, 0.7)',
        'rgba(59, 130, 246, 0.5)'
    ];

    window.roleDistributionInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Users',
                data: data,
                backgroundColor: colors.slice(0, labels.length),
                borderColor: colors.slice(0, labels.length).map(c => c.replace('0.7', '1')),
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: { ticks: { color: '#999' } },
                y: { ticks: { color: '#999', font: { size: 10 } } }
            }
        }
    });
}

// 🆕 Render Inactive Users Breakdown (Stacked Bar)
function renderInactiveBreakdownChart() {
    const canvasElement = document.getElementById('inactiveBreakdownChart');
    if (!canvasElement || !sunbirdDashboardData || !sunbirdDashboardData.inactiveBreakdown) return;

    const inactive = sunbirdDashboardData.inactiveBreakdown || { '0-7days': 0, '7-30days': 0, '30-90days': 0, '90+days': 0 };
    
    canvasElement.width = 500;
    canvasElement.height = 150;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.inactiveBreakdownInstance && typeof window.inactiveBreakdownInstance.destroy === 'function') {
        window.inactiveBreakdownInstance.destroy();
    }

    window.inactiveBreakdownInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Inactive Users'],
            datasets: [
                {
                    label: '0–7 days',
                    data: [inactive['0-7days']],
                    backgroundColor: 'rgba(34, 197, 94, 0.7)',
                    borderColor: 'rgba(34, 197, 94, 1)',
                    borderWidth: 1
                },
                {
                    label: '7–30 days',
                    data: [inactive['7-30days']],
                    backgroundColor: 'rgba(59, 130, 246, 0.7)',
                    borderColor: 'rgba(59, 130, 246, 1)',
                    borderWidth: 1
                },
                {
                    label: '30–90 days',
                    data: [inactive['30-90days']],
                    backgroundColor: 'rgba(249, 115, 22, 0.7)',
                    borderColor: 'rgba(249, 115, 22, 1)',
                    borderWidth: 1
                },
                {
                    label: '90+ days',
                    data: [inactive['90+days']],
                    backgroundColor: 'rgba(220, 53, 69, 0.7)',
                    borderColor: 'rgba(220, 53, 69, 1)',
                    borderWidth: 1
                }
            ]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { stacked: true, ticks: { color: '#999' } },
                y: { stacked: true, ticks: { color: '#999' } }
            },
            plugins: {
                legend: { labels: { color: '#999', font: { size: 10, weight: 200 } }, position: 'bottom' }
            }
        }
    });
}

// 🆕 Render Identity Hygiene Score Breakdown
function renderIdentityHygieneBreakdown() {
    const hygieneDiv = document.getElementById('identity-hygiene-breakdown');
    if (!hygieneDiv || !sunbirdDashboardData || !sunbirdDashboardData.hygieneLevels) return;

    const hygiene = sunbirdDashboardData.hygieneLevels || { profileCompleteness: 0, authCompleteness: 0, activityCompleteness: 0 };
    
    hygieneDiv.innerHTML = `
        <div style="display: grid; gap: 12px;">
            <div>
                <div style="display: flex; justify-content: space-between; font-size: 0.9rem; margin-bottom: 4px;">
                    <span>👤 Profile Completeness</span>
                    <strong>${hygiene.profileCompleteness}%</strong>
                </div>
                <div style="width: 100%; height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden;">
                    <div style="width: ${hygiene.profileCompleteness}%; height: 100%; background: linear-gradient(90deg, #3b82f6, #0ea5e9); transition: width 0.3s ease;"></div>
                </div>
            </div>
            <div>
                <div style="display: flex; justify-content: space-between; font-size: 0.9rem; margin-bottom: 4px;">
                    <span>🔐 Auth Completeness</span>
                    <strong>${hygiene.authCompleteness}%</strong>
                </div>
                <div style="width: 100%; height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden;">
                    <div style="width: ${hygiene.authCompleteness}%; height: 100%; background: linear-gradient(90deg, #22c55e, #84cc16); transition: width 0.3s ease;"></div>
                </div>
            </div>
            <div>
                <div style="display: flex; justify-content: space-between; font-size: 0.9rem; margin-bottom: 4px;">
                    <span>📊 Activity Completeness</span>
                    <strong>${hygiene.activityCompleteness}%</strong>
                </div>
                <div style="width: 100%; height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden;">
                    <div style="width: ${hygiene.activityCompleteness}%; height: 100%; background: linear-gradient(90deg, #f97316, #ef4444); transition: width 0.3s ease;"></div>
                </div>
            </div>
        </div>
    `;
}

// Render Sign-In Insights (Top Locations, Device Breakdown, Timeline)
function renderSignInInsights() {
    const insightsRowDiv = document.getElementById('sunbird-insights-row');
    if (!insightsRowDiv || !sunbirdDashboardData || !sunbirdDashboardData.signInPatterns) return;

    // Render Top Locations Table
    const topLocationsBody = document.getElementById('top-locations-body');
    if (topLocationsBody && sunbirdDashboardData.signInPatterns) {
        const locations = sunbirdDashboardData.signInPatterns.topLocations || [];
        topLocationsBody.innerHTML = '';
        
        locations.slice(0, 5).forEach(location => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${location.location || 'Unknown'}</td>
                <td><strong>${location.count || 0}</strong></td>
            `;
            topLocationsBody.appendChild(row);
        });

        if (locations.length === 0) {
            topLocationsBody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: #999;">No location data available</td></tr>';
        }
    }

    // Render Device Breakdown Chart
    renderDeviceBreakdownChart();

    // Render Sign-In Timeline
    renderSignInTimeline();

    // Show all analytics rows
    insightsRowDiv.style.display = 'grid';
    const analyticsRow2 = document.getElementById('sunbird-analytics-row-2');
    const analyticsRow3 = document.getElementById('sunbird-analytics-row-3');
    if (analyticsRow2) analyticsRow2.style.display = 'grid';
    if (analyticsRow3) analyticsRow3.style.display = 'grid';
}

// Render Device Breakdown Chart
function renderDeviceBreakdownChart() {
    const canvasElement = document.getElementById('deviceBreakdownChart');
    if (!canvasElement || !sunbirdDashboardData || !sunbirdDashboardData.signInPatterns) return;

    const deviceData = sunbirdDashboardData.signInPatterns?.deviceBreakdown || {};
    const labels = Object.keys(deviceData);
    const data = Object.values(deviceData);

    // Set canvas dimensions
    canvasElement.width = 250;
    canvasElement.height = 200;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    if (window.deviceBreakdownInstance && typeof window.deviceBreakdownInstance.destroy === 'function') {
        window.deviceBreakdownInstance.destroy();
    }

    const colors = [
        'rgba(59, 130, 246, 0.7)',
        'rgba(34, 197, 94, 0.7)',
        'rgba(249, 115, 22, 0.7)',
        'rgba(139, 92, 246, 0.7)',
        'rgba(236, 72, 153, 0.7)'
    ];

    window.deviceBreakdownInstance = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors.slice(0, labels.length),
                borderColor: colors.slice(0, labels.length).map(c => c.replace('0.7', '1')),
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#999', font: { size: 10, weight: 200 } },
                    position: 'bottom'
                }
            }
        }
    });
}

// Render Sign-In Timeline
function renderSignInTimeline() {
    const timelineContainer = document.getElementById('timeline-container');
    if (!timelineContainer || !sunbirdDashboardData) return;

    timelineContainer.innerHTML = '';

    const signIns = sunbirdDashboardData.users
        ?.filter(u => u.lastSignIn && u.lastSignIn.dateTime)
        .map(u => ({
            user: u.displayName,
            date: new Date(u.lastSignIn.dateTime),
            location: u.lastSignIn.location,
            app: u.lastSignIn.appDisplayName,
            clientAppUsed: u.lastSignIn.clientAppUsed
        }))
        .sort((a, b) => b.date - a.date)
        .slice(0, 10) || [];

    if (signIns.length === 0) {
        timelineContainer.innerHTML = '<p style="text-align: center; color: #999; font-size: 0.85rem;">No recent sign-ins</p>';
        return;
    }

    signIns.forEach(signin => {
        const timeAgo = getTimeAgoString(signin.date);
        const appName = signin.app || signin.clientAppUsed || 'Microsoft Portal';
        const timelineItem = document.createElement('div');
        timelineItem.className = 'timeline-item';
        timelineItem.innerHTML = `
            <div class="timeline-icon">📋</div>
            <div class="timeline-info">
                <div class="timeline-user">${signin.user}</div>
                <div class="timeline-action">Signed in via ${appName}</div>
                <div class="timeline-time">${signin.location || 'Unknown location'} • ${timeAgo}</div>
            </div>
        `;
        timelineContainer.appendChild(timelineItem);
    });
}

// Helper function: Convert timestamp to "X time ago" format
function getTimeAgoString(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    
    let interval = seconds / 31536000;
    if (interval > 1) return Math.floor(interval) + ' years ago';
    
    interval = seconds / 2592000;
    if (interval > 1) return Math.floor(interval) + ' months ago';
    
    interval = seconds / 86400;
    if (interval > 1) return Math.floor(interval) + ' days ago';
    
    interval = seconds / 3600;
    if (interval > 1) return Math.floor(interval) + ' hours ago';
    
    interval = seconds / 60;
    if (interval > 1) return Math.floor(interval) + ' minutes ago';
    
    return 'Just now';
}

// Master function to render all Sunbird analytics
function renderSunbirdAnalytics() {
    if (!isSunbirdDashboard || !sunbirdDashboardData) {
        console.log('[Sunbird Analytics] Not Sunbird dashboard, skipping analytics');
        return;
    }

    console.log('[Sunbird Analytics] Rendering all components...');
    
    try {
        renderSunbirdSummaryCards();
        renderSystemHealthRadar();
        renderRiskDistributionPie();
        renderAuthenticationStrengthChart();
        renderDeviceTrustChart();
        renderSunbirdRoleDistributionChart();
        renderInactiveBreakdownChart();
        renderIdentityHygieneBreakdown();
        renderSignInInsights();
        
        console.log('[Sunbird Analytics] All components rendered successfully');
    } catch (error) {
        console.error('[Sunbird Analytics] Error rendering components:', error);
    }
}

function setupEventListeners() {
    const loginForm = document.getElementById('login-form');
    const logoutBtn = document.getElementById('btn-logout');
    const backBtn = document.getElementById('btn-back');
    const backBtnsGeneric = document.querySelectorAll('[id="btn-back"]');
    const passwordToggle = document.getElementById('password-toggle');
    const navPrev = document.getElementById('nav-prev');
    const navNext = document.getElementById('nav-next');
    const sidePeekPrev = document.getElementById('side-peek-prev');
    const sidePeekNext = document.getElementById('side-peek-next');
    const mobileMenuToggle = document.getElementById('mobile-menu-toggle');
    const mobileNavClose = document.getElementById('mobile-nav-close');
    const mobileNav = document.getElementById('mobile-nav');
    const btnLogoutMobile = document.getElementById('btn-logout-mobile');
    const verifyMfaBtn = document.getElementById('verify-mfa-btn');
    const resendCodeLink = document.getElementById('resend-code-link');
    const backToLoginLink = document.getElementById('back-to-login');
    const emailSignInTrigger = document.getElementById('email-signin-trigger');
    const backToMicrosoftSignIn = document.getElementById('back-to-microsoft-signin');

    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    if (emailSignInTrigger) {
        emailSignInTrigger.addEventListener('click', showEmailSignIn);
    }

    if (backToMicrosoftSignIn) {
        backToMicrosoftSignIn.addEventListener('click', showMicrosoftSignIn);
    }

    if (verifyMfaBtn) {
        verifyMfaBtn.addEventListener('click', handleMfaVerification);
    }

    // Handle resend code (same as signin.html)
    if (resendCodeLink) {
        resendCodeLink.addEventListener('click', async function(e) {
            e.preventDefault();
            try {
                const response = await fetch('/api/auth/send-mfa', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email: currentEmail })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showNotification('New MFA code sent to your email', true);
                } else {
                    showNotification(data.message || 'Failed to resend code. Please try again.', false);
                }
            } catch (error) {
                console.error('Error:', error);
                showNotification('An error occurred. Please try again.', false);
            }
        });
    }

    // Add Enter key support for MFA code input
    const mfaCodeInput = document.getElementById('mfa-code');
    if (mfaCodeInput) {
        mfaCodeInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                handleMfaVerification();
            }
        });
        
        // Only allow numbers
        mfaCodeInput.addEventListener('input', function(e) {
            e.target.value = e.target.value.replace(/[^0-9]/g, '');
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }

    if (backBtnsGeneric.length) {
        backBtnsGeneric.forEach(btn => btn.addEventListener('click', goBackToProjects));
    } else if (backBtn) {
        backBtn.addEventListener('click', goBackToProjects);
    }

    // Back buttons for full dashboards (non-generic views)

    if (passwordToggle) {
        passwordToggle.addEventListener('click', togglePasswordVisibility);
    }

    if (navPrev) {
        navPrev.addEventListener('click', goToPreviousProject);
    }

    if (navNext) {
        navNext.addEventListener('click', goToNextProject);
    }

    // Mobile menu toggle
    if (mobileMenuToggle) {
        mobileMenuToggle.addEventListener('click', toggleMobileMenu);
    }

    if (mobileNavClose) {
        mobileNavClose.addEventListener('click', closeMobileMenu);
    }

    // Close mobile menu when clicking outside
    if (mobileNav) {
        document.addEventListener('click', (e) => {
            if (mobileNav.classList.contains('active') && 
                !mobileNav.contains(e.target) && 
                !mobileMenuToggle.contains(e.target)) {
                closeMobileMenu();
            }
        });
    }

    // Mobile logout button
    if (btnLogoutMobile) {
        btnLogoutMobile.addEventListener('click', () => {
            closeMobileMenu();
            handleLogout();
        });
    }

    // Sync user name in mobile nav
    if (document.getElementById('user-name-mobile')) {
        const userName = document.getElementById('user-name');
        const userNameMobile = document.getElementById('user-name-mobile');
        if (userName && userNameMobile) {
            userNameMobile.textContent = userName.textContent;
        }
    }
}

function toggleMobileMenu() {
    const mobileMenuToggle = document.getElementById('mobile-menu-toggle');
    const mobileNav = document.getElementById('mobile-nav');
    const overlay = document.querySelector('.mobile-nav-overlay') || createMobileOverlay();

    if (mobileNav && mobileMenuToggle) {
        mobileNav.classList.toggle('active');
        mobileMenuToggle.classList.toggle('active');
        overlay.classList.toggle('active');
        document.body.style.overflow = mobileNav.classList.contains('active') ? 'hidden' : '';
    }
}

function closeMobileMenu() {
    const mobileMenuToggle = document.getElementById('mobile-menu-toggle');
    const mobileNav = document.getElementById('mobile-nav');
    const overlay = document.querySelector('.mobile-nav-overlay');

    if (mobileNav && mobileMenuToggle) {
        mobileNav.classList.remove('active');
        mobileMenuToggle.classList.remove('active');
        if (overlay) {
            overlay.classList.remove('active');
        }
        document.body.style.overflow = '';
    }
}

function createMobileOverlay() {
    const overlay = document.createElement('div');
    overlay.className = 'mobile-nav-overlay';
    overlay.addEventListener('click', closeMobileMenu);
    document.body.appendChild(overlay);
    return overlay;
}

function togglePasswordVisibility() {
    const passwordInput = document.getElementById('login-password');
    const toggle = document.getElementById('password-toggle');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggle.classList.remove('fa-eye');
        toggle.classList.add('fa-eye-slash');
        toggle.setAttribute('aria-label', 'Hide password');
        toggle.setAttribute('aria-pressed', 'true');
    } else {
        passwordInput.type = 'password';
        toggle.classList.remove('fa-eye-slash');
        toggle.classList.add('fa-eye');
        toggle.setAttribute('aria-label', 'Show password');
        toggle.setAttribute('aria-pressed', 'false');
    }
}

// ============================================
// AUTHENTICATION APIs
// ============================================
// Handles user login, MFA verification, password management,
// and session management for secure access

/* AUTHENTICATION */
let currentEmail = '';

function showEmailSignIn() {
    const choiceCard = document.getElementById('login-choice-card');
    const emailSignIn = document.getElementById('email-signin');
    const loginForm = document.getElementById('login-form');
    const mfaSection = document.getElementById('mfa-section');
    const emailInput = document.getElementById('login-email');

    if (!choiceCard || !emailSignIn) return;

    choiceCard.hidden = true;
    emailSignIn.hidden = false;
    emailSignIn.setAttribute('aria-hidden', 'false');
    if (loginForm) loginForm.style.display = 'block';
    if (mfaSection) mfaSection.style.display = 'none';

    window.setTimeout(() => emailInput?.focus(), 0);
}

function showMicrosoftSignIn() {
    const choiceCard = document.getElementById('login-choice-card');
    const emailSignIn = document.getElementById('email-signin');
    const loginForm = document.getElementById('login-form');
    const mfaSection = document.getElementById('mfa-section');
    const mfaCodeInput = document.getElementById('mfa-code');
    const mfaError = document.getElementById('mfa-error');
    const emailError = document.getElementById('login-email-error');
    const passwordError = document.getElementById('login-password-error');
    const microsoftButton = document.getElementById('microsoft-signin-btn');

    if (!choiceCard || !emailSignIn) return;

    if (loginForm) {
        loginForm.reset();
        loginForm.style.display = 'block';
    }
    if (mfaSection) mfaSection.style.display = 'none';
    if (mfaCodeInput) mfaCodeInput.value = '';
    [mfaError, emailError, passwordError].forEach((element) => {
        if (element) element.style.display = 'none';
    });
    currentEmail = '';
    emailSignIn.hidden = true;
    emailSignIn.setAttribute('aria-hidden', 'true');
    choiceCard.hidden = false;
    microsoftButton?.focus();
}
// Show notification (same as signin.html)
function showNotification(message, isSuccess = true) {
    const notification = document.getElementById('notification');
    if (!notification) return;
    
    notification.textContent = message;
    notification.className = 'notification ' + (isSuccess ? 'success' : 'error');
    notification.classList.add('show');
    
    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}

function showPdfLoadingOverlay(message = 'Generating PDF...') {
    let overlay = document.getElementById('pdf-loading-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'pdf-loading-overlay';
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            backdrop-filter: blur(4px);
        `;
        
        const loaderContent = document.createElement('div');
        loaderContent.style.cssText = `
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
        `;
        
        loaderContent.innerHTML = `
            <div class="sunbird-stack-loader-shell" style="position: relative; width: 100px; height: 100px;">
                <div class="sunbird-stack-loader-ring" style="position: absolute; inset: 0; border: 3px solid rgba(249, 115, 22, 0.2); border-top-color: #f97316; border-radius: 50%; animation: spin 1s linear infinite;"></div>
                <img src="Images/Logos/StackCTRLLoading.png" alt="" style="width: 70%; height: 70%; object-fit: contain; position: absolute; inset: 0; margin: auto;">
            </div>
            <p style="color: #ffffff; font-size: 0.95rem; margin: 0; text-align: center;">${message}</p>
        `;
        
        overlay.appendChild(loaderContent);
        document.body.appendChild(overlay);
    } else {
        overlay.style.display = 'flex';
        const messageEl = overlay.querySelector('p');
        if (messageEl) messageEl.textContent = message;
    }
}

function hidePdfLoadingOverlay() {
    const overlay = document.getElementById('pdf-loading-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const emailError = document.getElementById('login-email-error');
    const passwordError = document.getElementById('login-password-error');
    const loginForm = document.getElementById('login-form');
    const mfaSection = document.getElementById('mfa-section');
    const submitBtn = document.getElementById('login-submit-btn');
    const mfaError = document.getElementById('mfa-error');
    
    // Reset error messages
    emailError.style.display = 'none';
    passwordError.style.display = 'none';
    if (mfaError) mfaError.style.display = 'none';
    
    // Basic validation
    let isValid = true;
    if (!validateEmail(email)) {
        emailError.style.display = 'block';
        isValid = false;
    }
    
    if (password.length < 8) {
        passwordError.style.display = 'block';
        isValid = false;
    }
    
    if (!isValid) return;
    
    currentEmail = email;
    
    // Disable submit button
    submitBtn.disabled = true;
    const originalText = submitBtn.querySelector('span').textContent;
    submitBtn.querySelector('span').textContent = 'Signing in...';
    
    // Call signin API (same as signin.html)
    fetch('/api/auth/signin', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('MFA code sent to your email', true);
            mfaSection.style.display = 'block';
            loginForm.style.display = 'none';
        } else {
            // Display error message in email field for invalid credentials
            const errorMessage = data.message || 'Invalid email or password. Please check your credentials and try again.';
            emailError.textContent = errorMessage;
            emailError.style.display = 'block';
            passwordError.textContent = errorMessage;
            passwordError.style.display = 'block';
            showNotification(errorMessage, false);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        const errorMessage = 'An error occurred. Please try again.';
        emailError.textContent = errorMessage;
        emailError.style.display = 'block';
        showNotification(errorMessage, false);
    })
    .finally(() => {
        submitBtn.disabled = false;
        submitBtn.querySelector('span').textContent = originalText;
    });
}

function handleMfaVerification() {
    const mfaCodeInput = document.getElementById('mfa-code');
    const mfaError = document.getElementById('mfa-error');
    const verifyBtn = document.getElementById('verify-mfa-btn');
    const loginForm = document.getElementById('login-form');
    const mfaSection = document.getElementById('mfa-section');
    const code = mfaCodeInput.value.trim();
    
    mfaError.style.display = 'none';
    
    if (code.length !== 6 || !/^\d+$/.test(code)) {
        mfaError.textContent = 'Please enter a valid 6-digit code.';
        mfaError.style.display = 'block';
        return;
    }
    
    verifyBtn.disabled = true;
    const originalText = verifyBtn.textContent;
    verifyBtn.textContent = 'Verifying...';
    
    // Call verify-mfa API (same as signin.html)
    fetch('/api/auth/verify-mfa', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email: currentEmail, code })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            if (data.accessToken) {
                localStorage.setItem('authToken', data.accessToken);
            }
            if (data.user) {
                localStorage.setItem('user', JSON.stringify(data.user));
            }
            
            // Store user session
            sessionStorage.setItem('userEmail', currentEmail);
            sessionStorage.setItem('isLoggedIn', 'true');
            sessionStorage.setItem('loginTime', new Date().getTime());
            
            // Update UI with user's full name
            let displayName = 'Client';
            if (data.user && data.user.firstName && data.user.lastName) {
                displayName = `${data.user.firstName} ${data.user.lastName}`;
                sessionStorage.setItem('userFirstName', data.user.firstName);
                sessionStorage.setItem('userLastName', data.user.lastName);
            } else if (data.user && data.user.firstName) {
                displayName = data.user.firstName;
                sessionStorage.setItem('userFirstName', data.user.firstName);
            }
            
            document.getElementById('user-name').textContent = displayName;
            const userNameMobile = document.getElementById('user-name-mobile');
            if (userNameMobile) {
                userNameMobile.textContent = displayName;
            }
            
            // Update Sunbird logo visibility
            updateSunbirdLogoVisibility();
            
            showNotification('Authentication successful! Redirecting...', true);
            
            // Handle cross-portal redirection (Admin vs Client)
            if (data.redirect && !data.redirect.includes('ClientPortal.html')) {
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 1500);
                return;
            }
            
            // Switch to dashboard (for normal client login on this page)
            setTimeout(() => {
                document.getElementById('login-section').classList.remove('active');
                document.getElementById('dashboard-section').classList.add('active');

                // Reset forms
                if (loginForm) loginForm.reset();
                mfaCodeInput.value = '';
                if (loginForm) loginForm.style.display = 'block';
                if (mfaSection) mfaSection.style.display = 'none';
                
                // Reload dashboard data now that token/session are set.
                bootstrapDashboardDataAfterLogin();
                
                // Initialize chatbot after login
                if (typeof window.initChatbot === 'function') {
                    window.initChatbot();
                }
            }, 1500);
        } else {
            mfaError.textContent = data.message || 'Invalid code. Please try again.';
            mfaError.style.display = 'block';
        }
    })
    .catch(error => {
        console.error('Error:', error);
        mfaError.textContent = 'An error occurred. Please try again.';
        mfaError.style.display = 'block';
    })
    .finally(() => {
        verifyBtn.disabled = false;
        verifyBtn.textContent = originalText;
    });
}

function handleLogout() {
    if (!confirm('Are you sure you want to logout?')) {
        return;
    }

    clearClientPortalAuthState();

    // Reset UI (for safety if we stay on the page)
    const dashboardSection = document.getElementById('dashboard-section');
    const loginSection = document.getElementById('login-section');
    if (dashboardSection && loginSection) {
        dashboardSection.classList.remove('active');
        loginSection.classList.add('active');
        goBackToProjects();
    }

    // Hide chatbot
    const chatWidget = document.getElementById('chatbot-widget');
    if (chatWidget) {
        chatWidget.style.display = 'none';
    }

    // Redirect to the public client dashboard promo page so protected views aren't visible
    window.location.href = 'ClientDashboardHome.html';
}

function setupSessionManagement() {
    if (!isSessionValid()) {
        updateSunbirdLogoVisibility();
        return;
    }

    const userEmail = sessionStorage.getItem('userEmail');
    const userFirstName = sessionStorage.getItem('userFirstName');
    const userLastName = sessionStorage.getItem('userLastName');
    
    if (userEmail) {
        document.getElementById('login-section').classList.remove('active');
        document.getElementById('dashboard-section').classList.add('active');
        
        // Display user's full name if available, otherwise fallback to email prefix
        let displayName = 'Client';
        if (userFirstName && userLastName) {
            displayName = `${userFirstName} ${userLastName}`;
        } else if (userFirstName) {
            displayName = userFirstName;
        } else {
            displayName = userEmail.split('@')[0];
        }
        
        document.getElementById('user-name').textContent = displayName;
        const userNameMobile = document.getElementById('user-name-mobile');
        if (userNameMobile) {
            userNameMobile.textContent = displayName;
        }
        
        // Update Sunbird logo visibility
        updateSunbirdLogoVisibility();
        
        // Load billing card if user is logged in
        bootstrapDashboardDataAfterLogin();
        
        // Initialize chatbot if user is logged in
        if (typeof window.initChatbot === 'function') {
            window.initChatbot();
        }
    }
}

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function showError(message) {
    showNotification(message, false);
}


// ============================================
// SUNBIRD IDENTITY DASHBOARD API
// ============================================
// Integrates with Sunbird for enhanced identity analytics,
// user enrichment, and advanced security insights

// Fetch  Identity Protection data and update card preview
// Global variables for Sunbird dashboard
let isSunbirdDashboard = false;
let sunbirdDashboardData = null;

// ════════════════════════════════════════════════════════════════════════════════
// IDENTITY ACCESS DATA - Smooth Updates from Cached Database
// ════════════════════════════════════════════════════════════════════════════════

let identityDashboardUpdateInterval = null;
let lastIdentityMetrics = null;
const PROJECT_CARD_CACHE_KEY = 'stackopsProjectCardSnapshot';

function hasRealProjectMetrics(project) {
    return Array.isArray(project?.cardMetrics) && project.cardMetrics.some(metric => {
        const value = Number(String(metric.value ?? '').replace(':', '').replace('%', '').trim());
        return Number.isFinite(value) && value > 0;
    });
}

function readProjectCardCache() {
    try {
        return JSON.parse(localStorage.getItem(PROJECT_CARD_CACHE_KEY) || '{}');
    } catch (error) {
        return {};
    }
}

function saveProjectCardToCache(project) {
    if (!project || !hasRealProjectMetrics(project)) return;
    const snapshot = readProjectCardCache();
    snapshot[project.id] = {
        status: project.status,
        securityScore: project.securityScore,
        risks: project.risks,
        cardMetrics: project.cardMetrics,
        cardFooter: project.cardFooter,
        lastUpdate: project.lastUpdate,
        savedAt: Date.now()
    };
    localStorage.setItem(PROJECT_CARD_CACHE_KEY, JSON.stringify(snapshot));
}

function applyCachedProjectCards() {
    const snapshot = readProjectCardCache();
    mockProjects.forEach(project => {
        const cached = snapshot[project.id];
        if (!cached || !Array.isArray(cached.cardMetrics)) return;
        if (hasRealProjectMetrics(project)) return;

        project.status = cached.status || 'active';
        project.securityScore = cached.securityScore ?? project.securityScore;
        project.risks = cached.risks || project.risks;
        project.cardMetrics = cached.cardMetrics;
        project.cardFooter = cached.cardFooter || project.cardFooter;
        project.lastUpdate = cached.lastUpdate || project.lastUpdate;
    });
}

// Normalize API response to ensure all required analytics data exists
function normalizeSunbirdDashboardData(data) {
    if (!data) return {};
    
    const users = Array.isArray(data.users) ? data.users.map(normalizeSunbirdIdentityUser) : [];
    
    // Calculate analytics from users array if not provided by API
    const calculateRiskDistribution = () => {
        if (data.riskDistribution && (data.riskDistribution.HIGH || data.riskDistribution.MEDIUM || data.riskDistribution.SAFE)) {
            return data.riskDistribution;
        }
        const distribution = { HIGH: 0, MEDIUM: 0, SAFE: 0 };
        users.forEach(user => {
            const risk = user.riskLevel || 'SAFE';
            if (distribution.hasOwnProperty(risk)) {
                distribution[risk]++;
            }
        });
        return distribution;
    };
    
    const calculateAuthenticationStrength = () => {
        if (data.authenticationStrength && (data.authenticationStrength.passwordOnly || data.authenticationStrength.basicMFA || data.authenticationStrength.strongMFA)) {
            return data.authenticationStrength;
        }
        const auth = { passwordOnly: 0, basicMFA: 0, strongMFA: 0 };
        users.forEach(user => {
            if (!user.mfaEnabled) {
                auth.passwordOnly++;
            } else if (user.authMethodCount && user.authMethodCount >= 2) {
                auth.strongMFA++;
            } else {
                auth.basicMFA++;
            }
        });
        return auth;
    };

    const calculateInactiveBreakdown = () => {
        if (data.inactiveBreakdown && (data.inactiveBreakdown['0-7days'] || data.inactiveBreakdown['7-30days'] || data.inactiveBreakdown['30-90days'] || data.inactiveBreakdown['90+days'])) {
            return data.inactiveBreakdown;
        }
        const inactive = { '0-7days': 0, '7-30days': 0, '30-90days': 0, '90+days': 0 };
        users.forEach(user => {
            const daysSince = user.lastSignIn?.daysSince ?? 999;
            if (daysSince <= 7) inactive['0-7days']++;
            else if (daysSince <= 30) inactive['7-30days']++;
            else if (daysSince <= 90) inactive['30-90days']++;
            else inactive['90+days']++;
        });
        return inactive;
    };
    
    const calculateSummary = () => {
        const existing = data.summary || {};
        const riskDist = calculateRiskDistribution();
        const authStrength = calculateAuthenticationStrength();
        
        return {
            securityScore: existing.securityScore || 75,
            identityRiskScore: existing.identityRiskScore || (riskDist.HIGH > 0 ? 50 : 30),
            activeUsers24h: existing.activeUsers24h || users.length,
            activeUsersPercentage: existing.activeUsersPercentage || 100,
            highRiskUsers: existing.highRiskUsers || riskDist.HIGH,
            privilegedUsersWithoutMFA: existing.privilegedUsersWithoutMFA || 0,
            identityHygieneScore: existing.identityHygieneScore || 65,
            ...existing
        };
    };
    
    return {
        ...data,
        users: users,
        summary: calculateSummary(),
        riskDistribution: calculateRiskDistribution(),
        systemHealth: {
            performance: data.systemHealth?.performance || 80,
            availability: data.systemHealth?.availability || 95,
            security: data.systemHealth?.security || 70,
            compliance: data.systemHealth?.compliance || 85,
            backup: data.systemHealth?.backup || 90,
            ...data.systemHealth
        },
        authenticationStrength: calculateAuthenticationStrength(),
        deviceTrustAnalysis: {
            managed: data.deviceTrustAnalysis?.managed || 0,
            unmanaged: data.deviceTrustAnalysis?.unmanaged || 0,
            unknown: data.deviceTrustAnalysis?.unknown || 0,
            ...data.deviceTrustAnalysis
        },
        topRoles: data.topRoles || [],
        inactiveBreakdown: calculateInactiveBreakdown(),
        hygieneLevels: {
            profileCompleteness: data.hygieneLevels?.profileCompleteness || 0,
            authCompleteness: data.hygieneLevels?.authCompleteness || 0,
            activityCompleteness: data.hygieneLevels?.activityCompleteness || 0,
            ...data.hygieneLevels
        },
        signInPatterns: {
            topLocations: data.signInPatterns?.topLocations || [],
            deviceBreakdown: data.signInPatterns?.deviceBreakdown || {},
            ...data.signInPatterns
        },
        metrics: data.metrics || {}
    };
}

function updateIdentityProjectCardFromDashboard(data) {
    const project = mockProjects.find(p => p.id === 2);
    if (!project || !data) return;

    const metrics = data.metrics || {};
    const summary = data.summary || {};
    const totalUsers = summary.totalUsers ?? metrics.totalUsers ?? 0;
    const activeUsers = summary.activeUsers24h ?? metrics.activeUsers24h ?? 0;
    const adminRoles = summary.adminUsers ?? metrics.adminUsers ?? 0;
    const securityScore = summary.securityScore ?? metrics.securityScore ?? 0;

    project.status = 'active';
    project.securityScore = securityScore;
    project.risks = {
        critical: summary.highRiskUsers ?? metrics.highRiskUsers ?? 0,
        high: summary.privilegedUsersWithoutMFA ?? metrics.privilegedUsersWithoutMFA ?? 0,
        medium: summary.mediumRiskUsers ?? metrics.mediumRiskUsers ?? 0
    };
    project.cardMetrics = [
        { label: "Total Users", value: `: ${totalUsers}`, icon: "fas fa-users" },
        { label: "Active (24h)", value: `: ${activeUsers}`, icon: "fas fa-user-check" },
        { label: "Admin Roles", value: `: ${adminRoles}`, icon: "fas fa-crown" },
        { label: "Security Score", value: `: ${securityScore}`, icon: "fas fa-shield-alt" }
    ];
    project.cardFooter = `Users: ${totalUsers} | Active: ${activeUsers}`;
    project.lastUpdate = new Date().toLocaleTimeString();
    saveProjectCardToCache(project);
}

async function fetchIdentityAccessData() {
    const requestId = ++identityFetchRequestId;
    const isStaleRequest = () => requestId !== identityFetchRequestId;
    
    // Declare these outside try block so they're accessible in catch
    let isFirstLoad;
    let identityProjectForState;
    
    try {
        identityProjectForState = mockProjects.find(p => p.id === 2);
        isFirstLoad = !sunbirdDashboardData;
        
        if (isFirstLoad && identityProjectForState && !hasRealProjectMetrics(identityProjectForState)) {
            identityProjectForState.status = 'loading';
            displayCurrentProject();
        }

        const token = localStorage.getItem('authToken');
        const isLoggedIn = sessionStorage.getItem('isLoggedIn') === 'true';
        
        if (!token || !isLoggedIn) {
            console.log('[Identity Access] User not logged in. Skipping fetch.');
            return;
        }

        if (!isSunbirdUser()) {
            console.log('[Identity Access] Non-Sunbird user. Skipping fetch.');
            return;
        }

        console.log('[Identity Access] Fetching fresh dashboard data for live sign-ins...');
        const sunbirdData = await fetchFreshSunbirdIdentityDashboardData();
        
        if (isStaleRequest()) return;
        
        if (sunbirdData.success) {
            console.log(`[Identity Access] Dashboard loaded successfully from ${sunbirdData.liveSource || 'identity endpoint'}`);
            isSunbirdDashboard = true;
            // Normalize the API response to ensure all required data structures exist
            sunbirdDashboardData = normalizeSunbirdDashboardData(sunbirdData);
            updateIdentityProjectCardFromDashboard(sunbirdDashboardData);
            
            // Enrich users - handle empty array gracefully
            const usersFromApi = sunbirdDashboardData.users || [];
            console.log(`[Identity Access] Processing ${usersFromApi.length} users from API`);
            
            microsoftUsersData = usersFromApi.map(user => ({
                id: user.id,
                displayName: user.displayName,
                mail: user.mail,
                userPrincipalName: user.userPrincipalName,
                jobTitle: user.jobTitle,
                mobilePhone: user.mobilePhone,
                roles: user.roles || [],
                mfaEnabled: toBooleanMfa(user.mfaEnabled),
                authMethodCount: user.authMethodCount || 0,
                riskLevel: user.riskLevel || 'SAFE',
                isExternal: user.isExternal,
                accountEnabled: user.accountEnabled !== false,
                ...normalizeSunbirdIdentityUser(user)
            }));
            microsoftRolesData = Array.isArray(sunbirdDashboardData.roleAssignments) ? sunbirdDashboardData.roleAssignments : [];
            buildUserRolesMap();
            
            console.log(`[Identity Access] Enriched to ${microsoftUsersData.length} users`);
            
            // FIRST LOAD: Render everything normally
            if (isFirstLoad) {
                console.log('[Identity Access] FIRST LOAD - Rendering full dashboard');
                if (document.getElementById('sunbird-identity-dashboard')) {
                    saveSunbirdIdentitySnapshot(sunbirdDashboardData);
                    renderSunbirdIdentityDashboard();
                }
                
                displayCurrentProject();
                
                // Store initial metrics for comparison
                lastIdentityMetrics = JSON.parse(JSON.stringify(sunbirdData.metrics || {}));
                
                // Start polling for updates every 1 minute
                startIdentityDashboardUpdates();
                
            } else {
                // SUBSEQUENT UPDATES: Only update values smoothly
                console.log('[Identity Access] UPDATE - Smoothly updating values only');
                updateIdentityDashboardValuesSmootly();
            }
        } else {
            console.warn('[Identity Access] API response not successful:', sunbirdData);
            throw new Error(sunbirdData.message || 'API did not return success status');
        }
        
    } catch (error) {
        console.error('[Identity Access] Error:', error);
        console.error('[Identity Access] Error stack:', error.stack);
        
        if (!identityProjectForState) {
            identityProjectForState = mockProjects.find(p => p.id === 2);
        }
        
        if (identityProjectForState) {
            identityProjectForState.status = 'error';
            displayCurrentProject();
        }
        
        // Only retry if this is the first load and we haven't tried too many times
        if (isFirstLoad && retryCount < 3) {
            retryCount++;
            console.log(`[Identity Access] Retrying in 2 seconds (attempt ${retryCount}/3)...`);
            setTimeout(() => {
                fetchIdentityAccessData();
            }, 2000);
        } else if (isFirstLoad && retryCount >= 3) {
            console.error('[Identity Access] Max retries reached, giving up');
            retryCount = 0;
        }
    }
}

// Start polling for updates every 1 minute
function startIdentityDashboardUpdates() {
    if (identityDashboardUpdateInterval) return;
    
    console.log('[Identity Dashboard] Starting smooth updates every 1 minute...');
    
    identityDashboardUpdateInterval = setInterval(() => {
        fetchUpdatedIdentityData();
    }, 60000); // Every 1 minute
}

// Stop polling
function stopIdentityDashboardUpdates() {
    if (identityDashboardUpdateInterval) {
        clearInterval(identityDashboardUpdateInterval);
        identityDashboardUpdateInterval = null;
        console.log('[Identity Dashboard] Stopped polling updates');
    }
}

// Fetch updated data silently
async function fetchUpdatedIdentityData() {
    if (!isSunbirdUser()) {
        stopIdentityDashboardUpdates();
        return;
    }
    try {
        const data = await fetchFreshSunbirdIdentityDashboardData();
        sunbirdDashboardData = normalizeSunbirdDashboardData(data);
        microsoftUsersData = (sunbirdDashboardData.users || []).map(normalizeSunbirdIdentityUser);
        microsoftRolesData = Array.isArray(sunbirdDashboardData.roleAssignments) ? sunbirdDashboardData.roleAssignments : microsoftRolesData;
        buildUserRolesMap();
        updateIdentityProjectCardFromDashboard(sunbirdDashboardData);
        saveSunbirdIdentitySnapshot(sunbirdDashboardData);
        
        // Smoothly update UI values
        updateIdentityDashboardValuesSmootly();
        renderSunbirdIdentitySignIns(buildSunbirdIdentityModel());
        displayCurrentProject();
    } catch (error) {
        if ([401, 403].includes(Number(error.statusCode))) {
            stopIdentityDashboardUpdates();
            console.warn(`[Identity Dashboard] Background updates stopped: ${error.message}`);
            return;
        }
        console.warn('[Identity Dashboard] Background update warning:', error.message);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// Smooth Value Updates - NO FLASHING
// Only text content changes, DOM structure stays intact
// ════════════════════════════════════════════════════════════════════════════════

function updateIdentityDashboardValuesSmootly() {
    try {
        const metrics = sunbirdDashboardData?.metrics || {};
        const riskBreakdown = sunbirdDashboardData?.riskBreakdown || {};
        const inactivity = riskBreakdown.inactivity || {};
        const deviceTrust = riskBreakdown.deviceTrust || {};
        const authenticationStrength = riskBreakdown.authenticationStrength || {};
        
        const updates = [
            // Main stats
            { selector: '[data-stat="totalUsers"]', value: metrics.totalUsers || 0 },
            { selector: '[data-stat="adminUsers"]', value: metrics.adminUsers || 0 },
            { selector: '[data-stat="mfaEnabledUsers"]', value: metrics.mfaEnabledUsers || 0 },
            { selector: '[data-stat="mfaPercentage"]', value: (metrics.mfaPercentage || 0) + '%' },
            { selector: '[data-stat="highRiskUsers"]', value: metrics.highRiskUsers || 0 },
            { selector: '[data-stat="mediumRiskUsers"]', value: metrics.mediumRiskUsers || 0 },
            { selector: '[data-stat="activeUsers24h"]', value: metrics.activeUsers24h || 0 },
            { selector: '[data-stat="completeProfiles"]', value: metrics.usersWithCompleteProfile || 0 },
            { selector: '[data-stat="identityRiskScore"]', value: metrics.identityRiskScore || 0 },
            { selector: '[data-stat="privilegedWithoutMFA"]', value: metrics.privilegedUsersWithoutMFA || 0 },
            
            // Inactivity breakdown
            { selector: '[data-inactivity="0-7"]', value: inactivity['0-7days'] || 0 },
            { selector: '[data-inactivity="7-30"]', value: inactivity['7-30days'] || 0 },
            { selector: '[data-inactivity="30-90"]', value: inactivity['30-90days'] || 0 },
            { selector: '[data-inactivity="90+"]', value: inactivity['90+days'] || 0 },
            
            // Device trust
            { selector: '[data-device="managed"]', value: deviceTrust.managed || 0 },
            { selector: '[data-device="unmanaged"]', value: deviceTrust.unmanaged || 0 },
            { selector: '[data-device="unknown"]', value: deviceTrust.unknown || 0 },
            
            // Auth strength
            { selector: '[data-auth="passwordOnly"]', value: authenticationStrength.passwordOnly || 0 },
            { selector: '[data-auth="basicMFA"]', value: authenticationStrength.basicMFA || 0 },
            { selector: '[data-auth="strongMFA"]', value: authenticationStrength.strongMFA || 0 }
        ];
        
        // Update all values smoothly (just text, no re-rendering)
        updates.forEach(({ selector, value }) => {
            const element = document.querySelector(selector);
            if (element && element.textContent !== String(value)) {
                // Subtle fade effect on change
                element.textContent = value;
                element.style.opacity = '0.7';
                setTimeout(() => { 
                    if (element) element.style.opacity = '1'; 
                }, 200);
            }
        });
        
        // Update tables only if data changed significantly
        if (hasMetricsChanged()) {
            console.log('[Identity Dashboard] Metrics changed - updating table');
            populateIdentityTable();
        }
        
        console.log('[Identity Dashboard] ✅ Values updated smoothly - no flashing');
        
    } catch (error) {
        console.error('[Identity Dashboard] Error updating values:', error);
    }
}

// Check if metrics have significantly changed
function hasMetricsChanged() {
    if (!lastIdentityMetrics) return true;
    
    const current = sunbirdDashboardData.metrics;
    const threshold = 0.02; // 2% change threshold
    
    const checks = [
        Math.abs((current.totalUsers - lastIdentityMetrics.totalUsers) / lastIdentityMetrics.totalUsers) > threshold,
        Math.abs((current.highRiskUsers - lastIdentityMetrics.highRiskUsers) / (lastIdentityMetrics.highRiskUsers || 1)) > threshold,
        Math.abs((current.mfaPercentage - lastIdentityMetrics.mfaPercentage)) > 2,
        current.identityRiskScore !== lastIdentityMetrics.identityRiskScore
    ];
    
    if (checks.some(c => c)) {
        lastIdentityMetrics = JSON.parse(JSON.stringify(current));
        return true;
    }
    
    return false;
}

// Build a map of users to their assigned roles
function buildUserRolesMap() {
    userRolesMap = {};
    
    if (!microsoftRolesData || microsoftRolesData.length === 0) {
        return;
    }
    
    microsoftRolesData.forEach(assignment => {
        const principalId = assignment.principalId;
        const roleName = assignment.roleName || 'Unknown Role';
        
        if (!userRolesMap[principalId]) {
            userRolesMap[principalId] = [];
        }
        
        if (!userRolesMap[principalId].includes(roleName)) {
            userRolesMap[principalId].push(roleName);
        }
    });
    
    console.log(`[User Roles Map] Built map for ${Object.keys(userRolesMap).length} users`);
}

// ============================================
// CISCO DUO INTEGRATION API
// ============================================
// Fetches Duo license information and usage statistics
// for multi-factor authentication tracking

// Updated: fetchDuoStats - Now with better error handling, loading states, and retries
async function fetchDuoStats(retryCount = 0) {
    const token = localStorage.getItem('authToken');
    const isLoggedIn = sessionStorage.getItem('isLoggedIn') === 'true';
    
    // Only fetch if user is logged in and has a token
    if (!token || !isLoggedIn) {
        console.log('[Duo Sync] User not logged in. Skipping fetch.');
        return;
    }

    const duoProject = mockProjects.find(p => p.name === "Cisco Duo Licenses");
    if (!duoProject) {
        console.error('[Duo Sync] Duo project not found in mockProjects.');
        return;
    }

    // Set loading state
    duoProject.status = "Loading...";
    duoProject.cardMetrics = [
        { label: "Total Licences", value: ": Loading...", icon: "fas fa-id-card" },
        { label: "Active Usage", value: ": Loading...", icon: "fas fa-user-check" },
        { label: "Remaining Licences", value: ": Loading...", icon: "fas fa-user-plus" }
    ];
    duoProject.cardFooter = "Fetching data...";
    displayCurrentProject(); // Re-render to show loading

    try {
        console.log('[Duo Sync] Fetching data from /api/duo-stats...');
        const response = await fetch('/api/duo-stats', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error(`API responded with status ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('[Duo Sync] Received data:', data);

        // Validate data structure
        if (!data || typeof data.used_licenses !== 'number' || typeof data.total_licenses !== 'number') {
            throw new Error('Invalid data structure from API.');
        }

        // Update the project with real data
        if (data.total_licenses === 0) {
            console.log('[Duo Sync] No licenses found. Removing Duo project from list.');
            const index = mockProjects.findIndex(p => p.id === duoProject.id);
            if (index > -1) {
                mockProjects.splice(index, 1);
                initializeProjectsList(); // Re-initialize to update counter and display
                displayCurrentProject(); // Refresh the display
                return;
            }
        }

        duoProject.status = "Active";
        duoProject.cardMetrics = [
            { label: "Total Licences", value: `: ${data.total_licenses}`, icon: "fas fa-id-card" },
            { label: "Active Usage", value: `: ${data.used_licenses}`, icon: "fas fa-user-check" },
            { label: "Remaining Licences", value: `: ${data.remaining_licenses}`, icon: "fas fa-user-plus" }
        ];
        duoProject.cardFooter = `Tier: ${data.edition || 'Unknown'}`;
        duoProject.lastUpdate = `Synced: ${data.last_sync || 'Unknown'}`;

        // Re-render the UI with updated data
        displayCurrentProject();
        console.log('[Duo Sync] UI updated with real data.');

    } catch (error) {
        console.error('[Duo Sync] Error fetching Duo stats:', error.message);

        // If error is 404 or unauthorized, assume no licenses and remove from list
        if (error.message.includes('404') || error.message.includes('401')) {
            console.log('[Duo Sync] No access to Duo. Removing from project list.');
            const index = mockProjects.findIndex(p => p.id === duoProject.id);
            if (index > -1) {
                mockProjects.splice(index, 1);
                initializeProjectsList();
                displayCurrentProject();
                return;
            }
        }

        // Fallback: Set error state
        duoProject.status = "Error";
        duoProject.cardMetrics = [
            { label: "Total Licences", value: ": Error", icon: "fas fa-id-card" },
            { label: "Active Usage", value: ": Error", icon: "fas fa-user-check" },
            { label: "Remaining Licences", value: ": Error", icon: "fas fa-user-plus" }
        ];
        duoProject.cardFooter = "Error loading Duo stats. Please try again later.";
        displayCurrentProject();

        // Optional: Retry up to 2 times with exponential backoff
        if (retryCount < 2) {
            const delay = Math.pow(2, retryCount) * 1000; // 1s, 2s, 4s
            console.log(`[Duo Sync] Retrying in ${delay}ms... (attempt ${retryCount + 1})`);
            setTimeout(() => fetchDuoStats(retryCount + 1), delay);
        }
    }
}

/*  Identity Protection DASHBOARD */
function generateIdentityDashboardHTML() {
    // Calculate stats
    const totalUsers = microsoftUsersData.length;
    const internalUsers = microsoftUsersData.filter(u => !u.isExternal).length;
    const externalUsers = microsoftUsersData.filter(u => u.isExternal).length;
    const activeUsers = totalUsers; // All users are active
    
    return `
        <div class="identity-dashboard" id="identity-monitoring-section">
            <!-- Dashboard Header with Back Button and Title -->
            <div class="identity-dashboard-header">
                <div class="identity-header-left">
                    <div class="btn-back-wrapper glow-wrap">
                        <div class="glowing-border-layer"></div>
                        <button id="btn-back-identity" class="btn-back">
                            <i class="fas fa-arrow-left"></i> Back
                        </button>
                    </div>
                    <h2 class="identity-dashboard-title"> Identity Protection - Dashboard</h2>
                </div>
            </div>

            <!-- Overview Stats (Key Metrics) -->
            <div class="identity-stats-cards">
                <div class="identity-stat-card">
                    <div class="stat-card-icon" style="background: rgba(255, 255, 255, 0.2); color: #ffffff;">
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="stat-card-content">
                        <div class="stat-card-label">Total Users</div>
                        <div class="stat-card-value">${totalUsers}</div>
                    </div>
                </div>

                <div class="identity-stat-card">
                    <div class="stat-card-icon" style="background: rgba(0, 230, 118, 0.2); color: #00e676;">
                        <i class="fas fa-user-tie"></i>
                    </div>
                    <div class="stat-card-content">
                        <div class="stat-card-label">Internal Users</div>
                        <div class="stat-card-value">${internalUsers}</div>
                    </div>
                </div>

                <div class="identity-stat-card">
                    <div class="stat-card-icon" style="background: rgba(255, 152, 0, 0.2); color: #ff9800;">
                        <i class="fas fa-user-secret"></i>
                    </div>
                    <div class="stat-card-content">
                        <div class="stat-card-label">External Users</div>
                        <div class="stat-card-value">${externalUsers}</div>
                    </div>
                </div>

                <div class="identity-stat-card">
                    <div class="stat-card-icon" style="background: rgba(0, 230, 118, 0.2); color: #00e676;">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div class="stat-card-content">
                        <div class="stat-card-label">Active Users</div>
                        <div class="stat-card-value">${activeUsers}</div>
                    </div>
                </div>
            </div>

            <!-- Search Bar and Filters -->
            <div class="identity-controls-section">
                <input type="text" id="user-search-input" class="identity-search-bar" placeholder="Search by name or email...">
                
                <div class="identity-filters">
                    <label class="filter-checkbox">
                        <input type="checkbox" id="filter-internal" data-filter="internal">
                        <span>Internal Users</span>
                    </label>
                    <label class="filter-checkbox">
                        <input type="checkbox" id="filter-external" data-filter="external">
                        <span>External Users</span>
                    </label>
                    <label class="filter-checkbox">
                        <input type="checkbox" id="filter-admins" data-filter="admins">
                        <span>👑 Admins</span>
                    </label>
                    <label class="filter-checkbox">
                        <input type="checkbox" id="filter-missing-data" data-filter="missing-data">
                        <span>Missing Data</span>
                    </label>
                    <button id="btn-clear-filters" class="btn-clear-filters">Clear Filters</button>
                </div>
            </div>

            <!-- Users Table (Full Width) -->
            <div class="identity-users-table-container">
                <table class="identity-users-table" id="users-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Job Title</th>
                            <th>Roles</th>
                            <th>Type</th>
                            <th>MFA</th>
                            <th>Auth Methods</th>
                            <th>Risk</th>
                            <th>Status</th>
                            <th>Last Sign-In</th>
                            <th>Location</th>
                            <th>Device</th>
                            <th>Phone</th>
                        </tr>
                    </thead>
                    <tbody id="users-table-body">
                        <!-- Users will be populated here -->
                    </tbody>
                </table>
            </div>

            <!-- Charts & Insights Section Below Table -->
            <div class="identity-insights-section">
                <!-- Sunbird-Specific Analytics Components (Only visible for Sunbird) -->
                <!-- Row 0: Summary Cards (Security, Risk, Activity) -->
                <div class="sunbird-summary-cards-row" id="sunbird-summary-cards" style="display: none;">
                    <div class="sunbird-summary-card" data-risk-filter="active-users-24h">
                        <div class="summary-card-icon" style="background: rgba(255, 255, 255, 0.2); color: #ffffff;">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div class="summary-card-content">
                            <div class="summary-card-label">Security Score</div>
                            <div class="summary-card-value" id="sunbird-security-score">0</div>
                            <div class="summary-card-subtext">/100</div>
                        </div>
                    </div>

                    <div class="sunbird-summary-card" data-risk-filter="high-risk-users">
                        <div class="summary-card-icon" style="background: rgba(0, 230, 118, 0.2); color: #00e676;">
                            <i class="fas fa-user-check"></i>
                        </div>
                        <div class="summary-card-content">
                            <div class="summary-card-label">Active Users (24h)</div>
                            <div class="summary-card-value" id="sunbird-active-users">0</div>
                        </div>
                    </div>

                    <div class="sunbird-summary-card" data-risk-filter="privileged-without-mfa">
                        <div class="summary-card-icon" style="background: rgba(255, 77, 77, 0.2); color: #ff4d4d;">
                            <i class="fas fa-exclamation-circle"></i>
                        </div>
                        <div class="summary-card-content">
                            <div class="summary-card-label">High Risk Users</div>
                            <div class="summary-card-value" id="sunbird-high-risk">0</div>
                        </div>
                    </div>

                    <div class="sunbird-summary-card">
                        <div class="summary-card-icon" style="background: rgba(255, 152, 0, 0.2); color: #ff9800;">
                            <i class="fas fa-user-clock"></i>
                        </div>
                        <div class="summary-card-content">
                            <div class="summary-card-label">Inactive (30+ days)</div>
                            <div class="summary-card-value" id="sunbird-inactive-users">0</div>
                        </div>
                    </div>

                    <div class="sunbird-summary-card">
                        <div class="summary-card-icon" style="background: rgba(255, 77, 77, 0.2); color: #ff4d4d;">
                            <i class="fas fa-lock"></i>
                        </div>
                        <div class="summary-card-content">
                            <div class="summary-card-label">🚨 Privileged Without MFA</div>
                            <div class="summary-card-value" id="sunbird-privileged-without-mfa">0</div>
                        </div>
                    </div>

                    <div class="sunbird-summary-card">
                        <div class="summary-card-icon" style="background: rgba(255, 152, 0, 0.2); color: #ff9800;">
                            <i class="fas fa-fire"></i>
                        </div>
                        <div class="summary-card-content">
                            <div class="summary-card-label">Identity Risk Score</div>
                            <div class="summary-card-value" id="sunbird-identity-risk-score">0</div>
                            <div class="summary-card-subtext">/100</div>
                        </div>
                    </div>
                </div>

                <!-- Row 1: System Health Radar & Risk Distribution Pie -->
                <div class="sunbird-analytics-row-1" id="sunbird-analytics-row-1" style="display: none;">
                    <div class="sunbird-analytics-card sunbird-analytics-card-wide">
                        <h4 class="chart-card-title">System Health Radar</h4>
                        <div class="chart-wrapper">
                            <canvas id="systemHealthRadar" width="400" height="300"></canvas>
                        </div>
                    </div>

                    <div class="sunbird-analytics-card">
                        <h4 class="chart-card-title">Risk Distribution</h4>
                        <div class="chart-wrapper">
                            <canvas id="riskDistributionPie" width="300" height="250"></canvas>
                        </div>
                    </div>
                </div>

                <!-- Row 2: Security & Identity Analytics -->
                <div class="sunbird-analytics-row-2" id="sunbird-analytics-row-2" style="display: none;">
                    <div class="sunbird-analytics-card">
                        <h4 class="chart-card-title">🔐 Authentication Strength</h4>
                        <div class="chart-wrapper">
                            <canvas id="authenticationStrengthChart" width="300" height="250"></canvas>
                        </div>
                    </div>

                    <div class="sunbird-analytics-card">
                        <h4 class="chart-card-title">📱 Device Trust Analysis</h4>
                        <div class="chart-wrapper">
                            <canvas id="deviceTrustChart" width="300" height="250"></canvas>
                        </div>
                    </div>

                    <div class="sunbird-analytics-card">
                        <h4 class="chart-card-title">👥 Role Distribution (Top 8)</h4>
                        <div class="chart-wrapper">
                            <canvas id="roleDistributionChart" width="400" height="250"></canvas>
                        </div>
                    </div>
                </div>

                <!-- Row 3: User Health & Activity -->
                <div class="sunbird-analytics-row-3" id="sunbird-analytics-row-3" style="display: none;">
                    <div class="sunbird-analytics-card sunbird-analytics-card-wide">
                        <h4 class="chart-card-title">⏱️ Inactive Users Breakdown (Days Since Last Sign-In)</h4>
                        <div class="chart-wrapper">
                            <canvas id="inactiveBreakdownChart" width="500" height="150"></canvas>
                        </div>
                    </div>

                    <div class="sunbird-analytics-card">
                        <h4 class="chart-card-title">🧼 Identity Hygiene Score</h4>
                        <div class="insights-content" id="identity-hygiene-breakdown">
                            <!-- Populated dynamically -->
                        </div>
                    </div>
                </div>

                <!-- Row 2: Sign-In Insights -->
                <div class="sunbird-insights-row" id="sunbird-insights-row" style="display: none;">
                    <div class="sunbird-insights-card">
                        <h4 class="chart-card-title">📍 Top Sign-In Locations</h4>
                        <div class="insights-content">
                            <table class="insights-table" id="top-locations-table">
                                <thead>
                                    <tr>
                                        <th>Location</th>
                                        <th>Sign-Ins</th>
                                    </tr>
                                </thead>
                                <tbody id="top-locations-body">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div class="sunbird-insights-card">
                        <h4 class="chart-card-title">📈 Sign-In Activity Timeline</h4>
                        <div class="insights-content">
                            <div id="timeline-container" class="timeline-container">
                                <!-- Populated dynamically -->
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Row 1: Charts -->
                <div class="identity-charts-grid">
                    <!-- Job Title Distribution -->
                    <div class="identity-chart-card">
                        <h4 class="chart-card-title">Job Title Distribution</h4>
                        <div class="chart-wrapper">
                            <canvas id="jobTitleChart" width="300" height="250"></canvas>
                        </div>
                    </div>

                    <!-- Contact Completeness -->
                    <div class="identity-chart-card">
                        <h4 class="chart-card-title">Contact Completeness</h4>
                        <div class="chart-wrapper">
                            <canvas id="contactChart" width="300" height="250"></canvas>
                        </div>
                    </div>

                    <!-- User Type Distribution -->
                    <div class="identity-chart-card">
                        <h4 class="chart-card-title">User Type Distribution</h4>
                        <div class="chart-wrapper">
                            <canvas id="userTypeChart" width="300" height="250"></canvas>
                        </div>
                    </div>

                    <!-- Active Status -->
                    <div class="identity-chart-card">
                        <h4 class="chart-card-title">Active Status</h4>
                        <div class="chart-wrapper">
                            <canvas id="activeStatusChart" width="300" height="250"></canvas>
                        </div>
                    </div>
                </div>

                <!-- Row 2: Health Score & Missing Data -->
                <div class="identity-health-section">
                    <!-- User Health Score -->
                    <div class="identity-health-card">
                        <h4 class="chart-card-title">User Data Health Score</h4>
                        <div class="health-score-display">
                            <div class="health-score-gauge">
                                <div class="health-score-value" id="healthScoreValue">0</div>
                                <div class="health-score-label">/ 100</div>
                            </div>
                            <div class="health-score-bar">
                                <div class="health-score-progress" id="healthScoreProgress" style="width: 0%"></div>
                            </div>
                        </div>
                    </div>

                    <!-- Missing Data Breakdown -->
                    <div class="identity-health-card">
                        <h4 class="chart-card-title">Missing Data Breakdown</h4>
                        <div class="missing-data-list">
                            <div class="missing-data-item">
                                <span class="missing-label">Missing Job Titles</span>
                                <span class="missing-count" id="missingJobTitles">0</span>
                            </div>
                            <div class="missing-data-item">
                                <span class="missing-label">Missing Phone Numbers</span>
                                <span class="missing-count" id="missingPhones">0</span>
                            </div>
                            <div class="missing-data-item">
                                <span class="missing-label">Complete Profiles</span>
                                <span class="missing-count" id="completeProfiles">0</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Row 3: Admin Users & Risk Indicator -->
                <div class="identity-admin-section">
                    <!-- Admin Users List -->
                    <div class="identity-admin-card">
                        <h4 class="chart-card-title">👑 Admin Users List</h4>
                        <div class="admin-users-container">
                            <div id="admin-users-list">
                                <p style="text-align: center; color: #999;">Loading admin users...</p>
                            </div>
                        </div>
                    </div>

                    <!-- Risk Indicator -->
                    <div class="identity-risk-card">
                        <h4 class="chart-card-title">🚨 Risk Indicator</h4>
                        <div class="risk-indicator-container">
                            <div id="risk-summary">
                                <p style="text-align: center; color: #999;">Analyzing risks...</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Row 4: Security Insights -->
                <div class="identity-security-section">
                    <!-- Security Insights -->
                    <div class="identity-insights-card">
                        <h4 class="chart-card-title">⚠️ Security Insights</h4>
                        <div id="security-insights-list" class="security-insights-container">
                            <p style="text-align: center; color: #999;">Loading security insights...</p>
                        </div>
                    </div>
                </div>

                <!-- Row 5: Detailed Risk & Security Analysis -->
                <div class="identity-risk-panel">
                    <h4 class="chart-card-title">⚠️ Detailed Risk & Security Analysis</h4>
                    <div class="risk-items">
                        <div id="riskCritical" class="risk-item risk-critical" style="display:none;">
                            <i class="fas fa-exclamation-circle"></i>
                            <span id="riskCriticalText">Critical: Master Admin detected</span>
                        </div>
                        <div class="risk-item risk-medium">
                            <i class="fas fa-exclamation-triangle"></i>
                            <span id="riskMediumText">Medium Risk: Users without job titles and phone numbers</span>
                        </div>
                        <div class="risk-item risk-low">
                            <i class="fas fa-info-circle"></i>
                            <span>Low Risk: Shared mailboxes detected in user list</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function populateIdentityTable() {
    const tableBody = document.getElementById('users-table-body');
    const table = document.getElementById('users-table');
    
    console.log('[Identity Table] ====== POPULATE TABLE START ======');
    console.log('[Identity Table] Searching for table body with ID: users-table-body');
    console.log('[Identity Table] Searching for table with ID: users-table');
    
    if (!tableBody) {
        console.error('[Identity Table] ❌ Table body not found');
        console.error('[Identity Table] Document body innerHTML preview:', document.body.innerHTML.substring(0, 500));
        return;
    }
    
    console.log('[Identity Table] ✅ Table body found');
    console.log(`[Identity Table] Populating table with ${microsoftUsersData.length} users (Sunbird: ${isSunbirdDashboard})`);
    console.log('[Identity Table] Sample user data:', microsoftUsersData[0]);

    tableBody.innerHTML = '';
    console.log('[Identity Table] ✅ Cleared table body');

    // Update table headers based on dashboard type
    if (table) {
        const thead = table.querySelector('thead tr');
        if (thead) {
            console.log('[Identity Table] ✅ Table head found');
            if (isSunbirdDashboard) {
                thead.innerHTML = `
                    <th>Name</th>
                    <th>Email</th>
                    <th>Job Title</th>
                    <th>Roles</th>
                    <th>Type</th>
                    <th>MFA</th>
                    <th>Auth Methods</th>
                    <th>Risk</th>
                    <th>Status</th>
                    <th>Last Sign-In</th>
                    <th>Location</th>
                    <th>Device</th>
                    <th>Phone</th>
                `;
            } else {
                thead.innerHTML = `
                    <th>Name</th>
                    <th>Email</th>
                    <th>Job Title</th>
                    <th>Phone</th>
                    <th>Roles</th>
                    <th>Type</th>
                    <th>Status</th>
                `;
            }
        }
    }

    if (microsoftUsersData.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="${isSunbirdDashboard ? 13 : 7}" style="text-align: center; padding: 20px;">No users found</td></tr>`;
        return;
    }

    microsoftUsersData.forEach((user, index) => {
        const row = document.createElement('tr');

        if (isSunbirdDashboard) {
            // Render Sunbird enhanced columns
            const jobTitle = (user.jobTitle && user.jobTitle !== 'No Title' && user.jobTitle.trim() !== '') ? user.jobTitle : '—';
            const phone = (user.mobilePhone && user.mobilePhone !== 'N/A' && user.mobilePhone?.trim() !== '') ? user.mobilePhone : '—';
            
            // Fix: Handle roles array - could be array of strings or objects with name property
            const roles = user.roles || [];
            const rolesDisplay = roles.length > 0 
                ? roles.map(role => {
                    const roleName = typeof role === 'string' ? role : (role?.name || 'Unknown Role');
                    return `<span class="role-badge">${roleName}</span>`;
                }).join(' ')
                : '—';

            // MFA Status: Show both enabled status and method count
            const authMethodCount = user.authMethodCount || 0;
            const mfaStatus = user.mfaEnabled ? `✅ Yes (${authMethodCount})` : `❌ No (${authMethodCount})`;
            
            const riskLevel = user.riskLevel || 'SAFE';
            const riskBadgeClass = riskLevel === 'HIGH' ? 'risk-badge-high' : 
                                  riskLevel === 'MEDIUM' ? 'risk-badge-medium' : 
                                  'risk-badge-safe';
            const riskIcon = riskLevel === 'HIGH' ? '🔴' : 
                           riskLevel === 'MEDIUM' ? '🟡' : 
                           '🟢';

            const lastSignInText = (user.lastSignIn && user.lastSignIn.dateTime) ? 
                getTimeAgoString(new Date(user.lastSignIn.dateTime)) : 'Never';

            // Location: Already formatted in backend as "City, Country"
            const locationDisplay = (user.lastSignIn && user.lastSignIn.location && user.lastSignIn.location !== 'No sign-in') ? user.lastSignIn.location : 'No sign-in';
            
            // Device: Show device name  
            let deviceDisplay = 'Unknown';
            if (user.lastSignIn && user.lastSignIn.device) {
                deviceDisplay = user.lastSignIn.device.toLowerCase().includes('unknown') ? 'Unknown' : user.lastSignIn.device;
            }

            // Log first row for debugging
            if (index === 0) {
                console.log('[Identity Table] Row 0 data:', {
                    jobTitle,
                    roles: rolesDisplay,
                    mfaStatus,
                    riskLevel,
                    lastSignInText,
                    location: locationDisplay,
                    device: deviceDisplay
                });
            }

            row.innerHTML = `
                <td>${user.displayName || 'Unknown'}</td>
                <td>${user.mail || user.userPrincipalName || 'N/A'}</td>
                <td>${jobTitle}</td>
                <td class="roles-cell">${rolesDisplay}</td>
                <td>
                    <span class="user-type-badge ${user.isExternal ? 'external' : 'internal'}">
                        ${user.isExternal ? 'External' : 'Internal'}
                    </span>
                </td>
                <td>${mfaStatus}</td>
                <td>${authMethodCount}</td>
                <td><span class="${riskBadgeClass}">${riskIcon} ${riskLevel}</span></td>
                <td>
                    <span class="user-status-badge active">Active</span>
                </td>
                <td>${lastSignInText}</td>
                <td><span class="location-cell" title="${locationDisplay}">${locationDisplay}</span></td>
                <td><span class="device-cell" title="${deviceDisplay}">${deviceDisplay}</span></td>
                <td>${phone}</td>
            `;
        } else {
            // Render standard columns (original)
            const jobTitle = (user.jobTitle && user.jobTitle !== 'No Title') ? user.jobTitle : '<span style="color: #999;">—</span>';
            const phone = (user.mobilePhone && user.mobilePhone !== 'N/A') ? user.mobilePhone : '<span style="color: #999;">—</span>';
            
            const roles = userRolesMap[user.id] || [];
            const rolesDisplay = roles.length > 0 
                ? roles.map(role => `<span class="role-badge">${role}</span>`).join('')
                : '<span style="color: #999;">—</span>';

            row.innerHTML = `
                <td>${user.displayName || 'N/A'}</td>
                <td>${user.mail || user.userPrincipalName || 'N/A'}</td>
                <td>${jobTitle}</td>
                <td>${phone}</td>
                <td class="roles-cell">${rolesDisplay}</td>
                <td>
                    <span class="user-type-badge ${user.isExternal ? 'external' : 'internal'}">
                        ${user.isExternal ? 'External' : 'Internal'}
                    </span>
                </td>
                <td>
                    <span class="user-status-badge active">Active</span>
                </td>
            `;
        }

        tableBody.appendChild(row);

        if (index === 0) {
            console.log('[Identity Table] First user added:', user.displayName);
        }
    });
    console.log(`[Identity Table] Total rows added: ${microsoftUsersData.length}`);
}



function initializeProjectsList() {
    const projectsGrid = document.getElementById('projects-grid');
    if (!projectsGrid) return;
    applyCachedProjectCards();
    projectsGrid.innerHTML = '';
    
    const carouselProjects = getFilteredProjects();
    document.getElementById('project-total').textContent = carouselProjects.length;
    
    // Default start index to 1 for Sunbird clients so index 0 (Credential Security) is on the left blur.
    currentProjectIndex = isSunbirdUser() ? 1 : 0;
    selectedProjectId = null;
    previewLockedByClick = false;
    
    displayCurrentProject();
    const token = localStorage.getItem('authToken');
    const isLoggedIn = sessionStorage.getItem('isLoggedIn') === 'true';
    if (token && isLoggedIn) {
        fetchDuoStats();
        fetchIdentityAccessData();
        fetchApplicationsData(); 
        fetchDevicesCardData();
        fetchEmailCardData();
        fetchNetworkSecurityCardData();
    }
}

function getProjectMetricValue(projectId, labelPattern, fallback = '0') {
    const project = mockProjects.find(item => Number(item.id) === Number(projectId));
    const metric = project?.cardMetrics?.find(item => labelPattern.test(String(item.label || '')));
    return metric ? toMetricValue(metric.value, fallback) : fallback;
}

function getMobileTotalStorageValue() {
    const data = cachedSunbirdBackupData || readSunbirdBackupSnapshot?.() || {};
    const summary = data.summary || {};
    const value = summary.totalStorageGB ?? summary.totalStorage ?? data.totalStorageGB;
    if (value == null || value === '') return '0 GB';
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return `${numeric} GB`;
    return String(value);
}

function updatePortalMobileDomainSummary() {
    const setText = (id, value) => {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    };

    const totalUsers = getProjectMetricValue(2, /total users/i);
    const totalDevices = getProjectMetricValue(3, /total devices/i);
    const totalApps = getProjectMetricValue(8, /total apps/i);
    const totalStorage = getMobileTotalStorageValue();

    setText('mobile-total-users', totalUsers);
    setText('mobile-total-devices', totalDevices);
    setText('mobile-total-apps', totalApps);
    setText('mobile-total-storage', totalStorage);

}
function displayCurrentProject() {
    const isPhoneProjectLayout = window.matchMedia('(max-width: 600px)').matches;
    const carouselProjects = isPhoneProjectLayout ? getPhoneFilteredProjects() : getFilteredProjects();
    if (carouselProjects.length === 0) return;
    
    const projectsGrid = document.getElementById('projects-grid');
    projectsGrid.classList.toggle('project-grid-updating', projectGridHasRendered);
    projectsGrid.innerHTML = '';
    const visibleProjects = isPhoneProjectLayout
        ? carouselProjects
        : carouselProjects.slice(currentProjectIndex, currentProjectIndex + 3);
    
    visibleProjects.forEach((project, index) => {
        const projectCard = createProjectCard(project);
        
        if (!project.noDashboard) {
            projectCard.addEventListener('mouseenter', () => {
                if (!previewLockedByClick) {
                    showProjectPreview(project);
                    moveProjectPreviewUnderCard(projectCard);
                }
            });
            
            projectCard.addEventListener('mouseleave', () => {
                if (!previewLockedByClick) {
                    hideProjectPreview();
                }
            });
            
            projectCard.addEventListener('click', (event) => {
                if (event.target.closest('[data-network-security-cta]')) {
                    openDashboard(project);
                    return;
                }

                const previewSection = document.getElementById('project-preview-section');
                const isSameProjectPreview = previewLockedByClick && selectedProjectId === project.id && previewSection?.classList.contains('visible');

                if (isSameProjectPreview) {
                    previewLockedByClick = false;
                    selectedProjectId = null;
                    projectCard.classList.remove('glow-selected');
                    hideProjectPreview();
                    return;
                }

                const allCards = document.querySelectorAll('.project-card');
                allCards.forEach(card => card.classList.remove('glow-selected'));

                previewLockedByClick = true;
                selectedProjectId = project.id;
                projectCard.classList.add('glow-selected');
                showProjectPreview(project);
                moveProjectPreviewUnderCard(projectCard);
            });
        }
        
        projectsGrid.appendChild(projectCard);
    });

    if (isPhoneProjectLayout) {
        clearSidePeekCards();
    } else {
        renderSidePeekCards();
    }
    projectGridHasRendered = true;
    
    document.getElementById('project-current').textContent = currentProjectIndex + 1;
    
    updateNavigationButtons();
    updatePortalMobileDomainSummary();
}

function clearSidePeekCards() {
    ['side-peek-prev-card', 'side-peek-next-card'].forEach(id => {
        const element = document.getElementById(id);
        if (element) element.innerHTML = '';
    });
}

function moveProjectPreviewUnderCard(projectCard) {
    const previewSection = document.getElementById('project-preview-section');
    if (!previewSection || !projectCard || !window.matchMedia('(max-width: 600px)').matches) return;
    projectCard.insertAdjacentElement('afterend', previewSection);
}

function renderSidePeekCards() {
    const carouselProjects = getFilteredProjects();
    const sidePeekPrev = document.getElementById('side-peek-prev');
    const sidePeekNext = document.getElementById('side-peek-next');
    const sidePeekPrevCard = document.getElementById('side-peek-prev-card');
    const sidePeekNextCard = document.getElementById('side-peek-next-card');

    if (!sidePeekPrevCard || !sidePeekNextCard || !sidePeekPrev || !sidePeekNext) return;

    sidePeekPrevCard.innerHTML = '';
    sidePeekNextCard.innerHTML = '';

    const prevProject = carouselProjects[currentProjectIndex - 1];
    const nextProject = carouselProjects[currentProjectIndex + 3];

    if (prevProject) {
        const prevCard = createProjectCard(prevProject);
        prevCard.classList.add('no-interaction');
        sidePeekPrevCard.appendChild(prevCard);

        // Credential Security Card (ID 9) logic
        if (prevProject.id === 9) {
            sidePeekPrev.classList.remove('no-interaction');
            
            const handleExpand = () => {
                sidePeekPrevCard.classList.add('expanded-left');
            };
            
            const handleCollapse = () => {
                if (!isCredentialSecurityLocked) {
                    sidePeekPrevCard.classList.remove('expanded-left');
                }
            };
            
            sidePeekPrev.onmouseenter = handleExpand;
            sidePeekPrev.onmouseleave = handleCollapse;
            
            sidePeekPrev.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                isCredentialSecurityLocked = !isCredentialSecurityLocked;
                if (isCredentialSecurityLocked) {
                    handleExpand();
                } else {
                    handleCollapse();
                }
            };
        } else {
            sidePeekPrev.onmouseenter = null;
            sidePeekPrev.onmouseleave = null;
            sidePeekPrev.onclick = null;
        }
    }

    if (nextProject) {
        const nextCard = createProjectCard(nextProject);
        nextCard.classList.add('no-interaction');
        sidePeekNextCard.appendChild(nextCard);
        
        // Network Security Card vertical expansion logic (ID 10)
        if (nextProject.id === 10) {
            sidePeekNext.classList.remove('no-interaction');
            
            const handleExpand = () => {
                sidePeekNextCard.classList.add('expanded');
            };
            
            const handleCollapse = () => {
                if (!isNetworkSecurityLocked) {
                    sidePeekNextCard.classList.remove('expanded');
                }
            };
            
            sidePeekNext.onmouseenter = handleExpand;
            sidePeekNext.onmouseleave = handleCollapse;
            
            sidePeekNext.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                if (e.target.closest('[data-network-security-cta]')) {
                    openDashboard(nextProject);
                    return;
                }
                isNetworkSecurityLocked = !isNetworkSecurityLocked;
                if (isNetworkSecurityLocked) {
                    handleExpand();
                } else {
                    handleCollapse();
                }
            };
        } else {
            sidePeekNext.onmouseenter = null;
            sidePeekNext.onmouseleave = null;
            sidePeekNext.onclick = null;
        }
    }

    sidePeekPrev.classList.toggle('is-empty', !prevProject);
    sidePeekNext.classList.toggle('is-empty', !nextProject);

    syncSidePeekCardSizing();
}

function syncSidePeekCardSizing() {
    const shell = document.querySelector('.projects-carousel-shell');
    const mainCard = document.querySelector('#projects-grid .project-card');
    if (!shell || !mainCard) return;

    const mainCardRect = mainCard.getBoundingClientRect();
    const mainCardWidth = mainCard.offsetWidth || mainCardRect.width;
    const mainCardHeight = mainCard.offsetHeight || mainCardRect.height;
    if (mainCardHeight <= 0 || mainCardWidth <= 0) return;

    // Match side cards to main project card size.
    shell.style.setProperty('--side-peek-card-width', `${Math.round(mainCardWidth)}px`);
    shell.style.setProperty('--side-peek-card-height', `${Math.round(mainCardHeight)}px`);

    const supportCard = document.getElementById('support-card');
    if (supportCard) {
        const shellRect = shell.getBoundingClientRect();
        const supportRect = supportCard.getBoundingClientRect();
        const scale = shell.offsetWidth ? shellRect.width / shell.offsetWidth : 1;
        const expandedHeight = scale > 0 ? (supportRect.bottom - shellRect.top) / scale : 0;
        if (expandedHeight > mainCardHeight) {
            shell.style.setProperty('--side-peek-expanded-height', `${Math.round(expandedHeight)}px`);
        }
    }
}

function readSunbirdNetworkSecuritySnapshot() {
    try {
        const snapshot = JSON.parse(localStorage.getItem(SUNBIRD_NETWORK_SECURITY_CACHE_KEY) || 'null');
        if (!snapshot?.savedAt) return null;
        const age = Date.now() - new Date(snapshot.savedAt).getTime();
        return age < SUNBIRD_CARD_CACHE_TTL_MS ? snapshot : null;
    } catch (_) {
        return null;
    }
}

function saveSunbirdNetworkSecuritySnapshot(data) {
    try {
        localStorage.setItem(SUNBIRD_NETWORK_SECURITY_CACHE_KEY, JSON.stringify({
            ...data,
            savedAt: new Date().toISOString()
        }));
    } catch (_) {}
}

function normalizeNetworkSecurityData(data = {}) {
    const overview = data.overview || {};
    return {
        success: data.success !== false,
        fetchedAt: data.fetchedAt || new Date().toISOString(),
        message: data.message || '',
        account: data.account || {},
        overview: {
            securityStatus: overview.securityStatus || 'No data configured',
            protectedApps: Number(overview.protectedApps || 0),
            enrolledDevices: Number(overview.enrolledDevices || 0),
            registeredWarpDevices: Number(overview.registeredWarpDevices || 0),
            gatewayPolicies: Number(overview.gatewayPolicies || 0),
            activeGatewayPolicies: Number(overview.activeGatewayPolicies || overview.gatewayPolicies || 0),
            identityProviders: Number(overview.identityProviders || 0),
            identityProvider: overview.identityProvider || 'Not configured',
            recentAccessEvents: Number(overview.recentAccessEvents || 0),
            lastAccessEvent: overview.lastAccessEvent || null,
            dlpProfiles: Number(overview.dlpProfiles || 0),
            warpProfiles: Number(overview.warpProfiles || 0),
            virtualNetworks: Number(overview.virtualNetworks || 0),
            appCategories: Number(overview.appCategories || 0),
            gatewayProxyEnabled: Boolean(overview.gatewayProxyEnabled),
            udpProxyEnabled: Boolean(overview.udpProxyEnabled),
            certificateEnabled: Boolean(overview.certificateEnabled),
            tlsDecryptEnabled: Boolean(overview.tlsDecryptEnabled),
            zonesAvailable: Number(overview.zonesAvailable || 0),
            endpointFamilies: Number(overview.endpointFamilies || 0),
            endpointFamiliesAvailable: Number(overview.endpointFamiliesAvailable || 0),
            endpointFamiliesWithGaps: Number(overview.endpointFamiliesWithGaps || 0),
            auditLogs: Number(overview.auditLogs || 0),
            accountLogs: Number(overview.accountLogs || 0),
            securityInsights: Number(overview.securityInsights || 0),
            applicationSecurityReports: Number(overview.applicationSecurityReports || 0),
            apiGatewayOperations: Number(overview.apiGatewayOperations || 0),
            casbFindings: Number(overview.casbFindings || 0),
            tunnels: Number(overview.tunnels || 0),
            cloudforceRequests: Number(overview.cloudforceRequests || 0),
            intelFeeds: Number(overview.intelFeeds || 0),
            dnsFirewallRules: Number(overview.dnsFirewallRules || 0),
            loadBalancerPools: Number(overview.loadBalancerPools || 0),
            loadBalancerMonitors: Number(overview.loadBalancerMonitors || 0),
            magicWanSites: Number(overview.magicWanSites || 0),
            magicWanRoutes: Number(overview.magicWanRoutes || 0),
            mtlsCertificates: Number(overview.mtlsCertificates || 0),
            accessGroups: Number(overview.accessGroups || 0),
            accessOrganizations: Number(overview.accessOrganizations || 0),
            accessCertificates: Number(overview.accessCertificates || 0),
            warpConnectors: Number(overview.warpConnectors || 0),
            teamnetRoutes: Number(overview.teamnetRoutes || 0),
            teamsDexTests: Number(overview.teamsDexTests || 0)
        },
        apps: Array.isArray(data.apps) ? data.apps : [],
        identityProviders: Array.isArray(data.identityProviders) ? data.identityProviders : [],
        policies: Array.isArray(data.policies) ? data.policies : [],
        devices: Array.isArray(data.devices) ? data.devices : [],
        deviceRegistrations: Array.isArray(data.deviceRegistrations) ? data.deviceRegistrations : [],
        devicePosture: Array.isArray(data.devicePosture) ? data.devicePosture : [],
        gatewayRules: Array.isArray(data.gatewayRules) ? data.gatewayRules : [],
        gatewayConfig: data.gatewayConfig || {},
        gatewayLists: Array.isArray(data.gatewayLists) ? data.gatewayLists : [],
        gatewayLogging: data.gatewayLogging || null,
        deviceSettings: data.deviceSettings || null,
        warpProfiles: Array.isArray(data.warpProfiles) ? data.warpProfiles : [],
        accessLogs: Array.isArray(data.accessLogs) ? data.accessLogs : [],
        virtualNetworks: Array.isArray(data.virtualNetworks) ? data.virtualNetworks : [],
        gatewayAppTypes: Array.isArray(data.gatewayAppTypes) ? data.gatewayAppTypes : [],
        dlpProfiles: Array.isArray(data.dlpProfiles) ? data.dlpProfiles : [],
        zones: Array.isArray(data.zones) ? data.zones : [],
        auditLogs: Array.isArray(data.auditLogs) ? data.auditLogs : [],
        accountLogs: Array.isArray(data.accountLogs) ? data.accountLogs : [],
        securityInsights: Array.isArray(data.securityInsights) ? data.securityInsights : [],
        applicationSecurityReports: Array.isArray(data.applicationSecurityReports) ? data.applicationSecurityReports : [],
        apiGatewayOperations: Array.isArray(data.apiGatewayOperations) ? data.apiGatewayOperations : [],
        casbFindings: Array.isArray(data.casbFindings) ? data.casbFindings : [],
        tunnels: Array.isArray(data.tunnels) ? data.tunnels : [],
        cloudforceRequests: Array.isArray(data.cloudforceRequests) ? data.cloudforceRequests : [],
        intelFeeds: Array.isArray(data.intelFeeds) ? data.intelFeeds : [],
        dnsFirewallRules: Array.isArray(data.dnsFirewallRules) ? data.dnsFirewallRules : [],
        loadBalancerPools: Array.isArray(data.loadBalancerPools) ? data.loadBalancerPools : [],
        loadBalancerMonitors: Array.isArray(data.loadBalancerMonitors) ? data.loadBalancerMonitors : [],
        magicWanSites: Array.isArray(data.magicWanSites) ? data.magicWanSites : [],
        magicWanRoutes: Array.isArray(data.magicWanRoutes) ? data.magicWanRoutes : [],
        mtlsCertificates: Array.isArray(data.mtlsCertificates) ? data.mtlsCertificates : [],
        accessGroups: Array.isArray(data.accessGroups) ? data.accessGroups : [],
        accessOrganizations: Array.isArray(data.accessOrganizations) ? data.accessOrganizations : [],
        accessCertificates: Array.isArray(data.accessCertificates) ? data.accessCertificates : [],
        warpConnectors: Array.isArray(data.warpConnectors) ? data.warpConnectors : [],
        teamnetRoutes: Array.isArray(data.teamnetRoutes) ? data.teamnetRoutes : [],
        teamsDexTests: Array.isArray(data.teamsDexTests) ? data.teamsDexTests : [],
        permissionMatrix: Array.isArray(data.permissionMatrix) ? data.permissionMatrix : [],
        endpointGroups: data.endpointGroups && typeof data.endpointGroups === 'object' ? data.endpointGroups : {},
        sections: data.sections || {}
    };
}

function getCurrentNetworkSecurityData() {
    return latestNetworkSecurityData || readSunbirdNetworkSecuritySnapshot() || null;
}

function getEmptyCloudflareSecuritySignals() {
    return {
        alerts: [],
        incidents: [],
        recommendations: [],
        activityFeed: [],
        reportProblems: [],
        reportRecommendations: [],
        reportEvents: [],
        notificationCount: 0,
        highCount: 0,
        primaryLabel: 'Cloudflare One clean',
        scorePenalty: 0
    };
}

function buildCloudflareSecuritySignals(inputData = getCurrentNetworkSecurityData()) {
    if (!inputData) return getEmptyCloudflareSecuritySignals();
    const hasEvidence = inputData.success === false
        || Boolean(inputData.message || inputData.fetchedAt || inputData.savedAt)
        || Object.keys(inputData.overview || {}).length > 0
        || ['apps', 'devices', 'gatewayRules', 'accessLogs', 'dlpProfiles', 'permissionMatrix', 'sections'].some(key => {
            const value = inputData[key];
            return Array.isArray(value) ? value.length > 0 : value && Object.keys(value).length > 0;
        });
    if (!hasEvidence) return getEmptyCloudflareSecuritySignals();
    const data = normalizeNetworkSecurityData(inputData || {});
    const overview = data.overview;
    const now = data.fetchedAt || new Date().toISOString();
    const alerts = [];
    const incidents = [];
    const recommendations = [];
    const activityFeed = [];
    const reportProblems = [];
    const reportEvents = [];
    const addAlert = ({ id, title, description, severity = 'medium', category = 'Cloudflare One', status = 'newAlert', incident = false, recommendation }) => {
        const alert = {
            id: `cloudflare-${id}`,
            title,
            description,
            severity,
            status,
            source: 'Cloudflare One',
            vendor: 'Cloudflare',
            category,
            created: now,
            cloudflareOneSignal: true
        };
        alerts.push(alert);
        activityFeed.push({
            id: alert.id,
            type: incident ? 'cloudflare-incident' : 'cloudflare-alert',
            severity,
            message: title,
            timestamp: now,
            source: 'Cloudflare One',
            cloudflareOneSignal: true
        });
        reportEvents.push({
            title,
            detail: description,
            severity,
            status,
            source: 'Cloudflare One',
            category,
            timestamp: now,
            cloudflareOneSignal: true
        });
        if (incident) {
            incidents.push({
                id: `${alert.id}-incident`,
                displayName: title,
                description,
                severity,
                status: status === 'resolved' ? 'resolved' : 'active',
                assignedTo: 'StackOps SOC',
                source: 'Cloudflare One',
                category,
                created: now,
                cloudflareOneSignal: true
            });
            reportProblems.push({
                title,
                detail: description,
                severity,
                source: 'Cloudflare One',
                owner: 'StackOps SOC',
                status: 'Action required',
                cloudflareOneSignal: true
            });
        }
        if (recommendation) {
            recommendations.push({
                priority: severity === 'critical' ? 'critical' : severity === 'high' ? 'high' : 'medium',
                title: recommendation,
                detail: description,
                source: 'Cloudflare One',
                cloudflareOneSignal: true
            });
        }
    };

    if (data.success === false) {
        addAlert({
            id: 'data-unavailable',
            title: 'Cloudflare One evidence unavailable',
            description: data.message || 'The Cloudflare Zero Trust API did not return current evidence.',
            severity: 'high',
            category: 'Cloudflare API',
            incident: true,
            recommendation: 'Restore Cloudflare API evidence collection'
        });
    }
    if (overview.gatewayProxyEnabled === false) {
        addAlert({
            id: 'gateway-proxy-disabled',
            title: 'Cloudflare Gateway proxy disabled',
            description: 'Gateway traffic inspection is not currently enabled in the Cloudflare One snapshot.',
            severity: 'high',
            category: 'Gateway',
            incident: true,
            recommendation: 'Enable Cloudflare Gateway proxy or document the exception'
        });
    }
    if (overview.tlsDecryptEnabled === false) {
        addAlert({
            id: 'tls-decrypt-disabled',
            title: 'Cloudflare TLS decrypt disabled',
            description: 'TLS inspection is disabled, limiting visibility into encrypted web traffic.',
            severity: 'medium',
            category: 'Gateway',
            recommendation: 'Review TLS decrypt policy readiness'
        });
    }
    if (overview.udpProxyEnabled === false) {
        addAlert({
            id: 'udp-proxy-disabled',
            title: 'Cloudflare UDP proxy disabled',
            description: 'UDP proxy support is disabled, which may leave selected traffic outside Gateway inspection.',
            severity: 'medium',
            category: 'Gateway',
            recommendation: 'Validate whether UDP proxy should be enabled'
        });
    }
    if (overview.dlpProfiles === false) {
        addAlert({
            id: 'dlp-missing',
            title: 'Cloudflare DLP profiles missing',
            description: 'No DLP profiles are available, so sensitive data detection is not evidenced.',
            severity: 'medium',
            category: 'DLP',
            recommendation: 'Create or verify Cloudflare DLP profiles'
        });
    }
    if (overview.protectedApps === false) {
        addAlert({
            id: 'access-apps-missing',
            title: 'No Cloudflare protected apps evidenced',
            description: 'Cloudflare Access did not provide protected applications for this snapshot.',
            severity: 'medium',
            category: 'Access',
            recommendation: 'Confirm Cloudflare Access app coverage'
        });
    }
    if (overview.identityProviders === false) {
        addAlert({
            id: 'identity-provider-missing',
            title: 'Cloudflare identity provider not evidenced',
            description: 'No Cloudflare Access identity provider is available in the latest snapshot.',
            severity: 'high',
            category: 'Identity',
            incident: true,
            recommendation: 'Connect or verify the Cloudflare Access identity provider'
        });
    }

    data.accessLogs
        .filter(log => /block|deny|fail/i.test(String(log.action || log.status || '')))
        .slice(0, 4)
        .forEach((log, index) => {
            addAlert({
                id: `access-block-${log.id || index}`,
                title: `Cloudflare Access ${log.action || 'blocked'} event`,
                description: [log.userEmail, log.appName, log.country, log.ipAddress].filter(Boolean).join(' | ') || 'Cloudflare Access recorded a denied or blocked request.',
                severity: 'high',
                category: 'Access',
                incident: true,
                recommendation: 'Review denied Cloudflare Access activity'
            });
        });

    Object.entries(data.sections || {}).forEach(([key, section]) => {
        if (!section || !['error', 'permission_unavailable'].includes(section.status)) return;
        addAlert({
            id: `section-${key}`,
            title: `Cloudflare ${section.label || key} evidence needs attention`,
            description: section.message || 'Cloudflare data for this control is incomplete or unavailable.',
            severity: section.status === 'error' ? 'high' : 'medium',
            category: 'Cloudflare API',
            incident: section.status === 'error',
            recommendation: 'Review Cloudflare API permissions for this evidence section'
        });
    });


    data.permissionMatrix
        .filter(family => ['permission_unavailable', 'error'].includes(String(family.status || '')))
        .slice(0, 4)
        .forEach(family => {
            addAlert({
                id: `permission-${family.key || family.id}`,
                title: `${family.module || 'Cloudflare'} evidence gap`,
                description: `${family.endpointFamily || family.permission || 'Cloudflare API'} is ${family.status === 'error' ? 'temporarily unavailable' : 'not available with current permissions'}.`,
                severity: family.status === 'error' ? 'high' : 'medium',
                category: family.module || 'Cloudflare API',
                incident: family.status === 'error',
                recommendation: 'Review Cloudflare API token permissions for this evidence family'
            });
        });

    data.casbFindings.slice(0, 3).forEach((finding, index) => {
        addAlert({
            id: `casb-${finding.id || finding.uuid || index}`,
            title: finding.name || finding.title || 'Cloudflare CASB finding',
            description: finding.description || finding.status || 'CASB reported a SaaS posture finding.',
            severity: /critical|high/i.test(String(finding.severity || finding.priority || '')) ? 'high' : 'medium',
            category: 'CASB Dashboard',
            incident: /critical|high/i.test(String(finding.severity || finding.priority || '')),
            recommendation: 'Review Cloudflare CASB findings in Security Alerts'
        });
    });

    data.securityInsights.slice(0, 3).forEach((finding, index) => {
        addAlert({
            id: `security-insight-${finding.id || index}`,
            title: finding.title || finding.name || 'Cloudflare security insight',
            description: finding.description || finding.status || 'Cloudflare Security Insights reported a posture finding.',
            severity: /critical|high/i.test(String(finding.severity || finding.priority || '')) ? 'high' : 'medium',
            category: 'Security Dashboard',
            recommendation: 'Review Cloudflare Security Insights evidence'
        });
    });
    const highCount = alerts.filter(alert => ['critical', 'high'].includes(String(alert.severity || '').toLowerCase())).length;
    return {
        alerts,
        incidents,
        recommendations,
        activityFeed,
        reportProblems,
        reportRecommendations: recommendations,
        reportEvents,
        notificationCount: alerts.length + incidents.length,
        highCount,
        primaryLabel: alerts[0]?.title || 'Cloudflare One clean',
        scorePenalty: highCount * 6 + Math.max(0, alerts.length - highCount) * 3
    };
}

function augmentSunbirdSecurityDataWithCloudflare(data = {}) {
    const signals = buildCloudflareSecuritySignals();
    if (!signals.notificationCount) return data;
    const payload = data.payload && typeof data.payload === 'object' ? data.payload : data;
    const stripCloudflare = row => !row?.cloudflareOneSignal && !/^cloudflare-/i.test(String(row?.id || ''));
    const alerts = [...signals.alerts, ...(Array.isArray(payload.alerts) ? payload.alerts.filter(stripCloudflare) : [])];
    const incidents = [...signals.incidents, ...(Array.isArray(payload.incidents) ? payload.incidents.filter(stripCloudflare) : [])];
    const baseAlerts = alerts.filter(alert => !alert.cloudflareOneSignal);
    const baseIncidents = incidents.filter(incident => !incident.cloudflareOneSignal);
    const activityFeed = [...signals.activityFeed, ...(Array.isArray(payload.activityFeed) ? payload.activityFeed.filter(stripCloudflare) : [])];
    const recommendations = [...signals.recommendations, ...(Array.isArray(payload.recommendations) ? payload.recommendations.filter(stripCloudflare) : [])];
    const baseSummary = payload.summary || {};
    const baseHigh = baseAlerts.filter(alert => ['critical', 'high'].includes(String(alert.severity || '').toLowerCase())).length;
    const baseActive = baseIncidents.filter(incident => ['active', 'inprogress', 'newalert'].includes(String(incident.status || '').toLowerCase())).length;
    const baseTotal = baseAlerts.length;
    const calculatedBaseScore = calculateSunbirdSecurityScore({
        alerts: baseAlerts,
        incidents: baseIncidents,
        threats: payload.threats || [],
        suspiciousSignIns: payload.signIns?.suspicious || []
    });
    const securityScore = Number(baseSummary.cloudflareIntegrated ? calculatedBaseScore : baseSummary.securityScore ?? calculatedBaseScore);
    const mergedPayload = {
        ...payload,
        alerts,
        incidents,
        activityFeed,
        recommendations,
        sourceDistribution: null,
        categoryDistribution: null,
        attackTimeline: null,
        mitre: null,
        topTargetedUsers: null,
        summary: {
            ...baseSummary,
            highSeverityAlerts: baseHigh + signals.alerts.filter(alert => ['critical', 'high'].includes(String(alert.severity || '').toLowerCase())).length,
            activeIncidents: baseActive + signals.incidents.filter(incident => ['active', 'inprogress', 'newalert'].includes(String(incident.status || '').toLowerCase())).length,
            totalAlerts: baseTotal + signals.alerts.length,
            securityScore: Math.max(0, Math.min(100, securityScore - signals.scorePenalty)),
            cloudflareAlerts: signals.alerts.length,
            cloudflareIncidents: signals.incidents.length,
            cloudflareIntegrated: true
        }
    };
    return data.payload && typeof data.payload === 'object'
        ? { ...data, payload: mergedPayload }
        : { ...data, ...mergedPayload };
}

function refreshCloudflareLinkedSecuritySurfaces() {
    if (cachedSunbirdSecurityData) {
        cachedSunbirdSecurityData = augmentSunbirdSecurityDataWithCloudflare(cachedSunbirdSecurityData);
    }
    if (sunbirdSecurityDashboardData) {
        sunbirdSecurityDashboardData = normalizeSunbirdSecurityData(sunbirdSecurityDashboardData);
    }
    if (document.getElementById('sunbird-security-dashboard')) {
        renderSunbirdSecurityDashboard();
    }
    if (typeof isSunbirdBillingViewActive === 'function' && isSunbirdBillingViewActive('security')) {
        renderSunbirdSecurityAlertsView(false);
    }
}

function formatNetworkSecurityDate(value) {
    if (!value) return 'No access events';
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return 'No access events';
    return getTimeAgoString(date);
}

function networkSecurityBoolLabel(value) {
    return value ? 'Enabled' : 'Disabled';
}

function compactNetworkIdentityProvider(value) {
    const text = String(value || '').trim();
    if (!text || /not configured/i.test(text)) return 'None';
    if (/azure\s*ad|entra/i.test(text)) return 'Azure';
    if (/one[-\s]?time|otp/i.test(text)) return 'OTP';
    return text.length > 10 ? text.slice(0, 9) + '...' : text;
}

function getCloudflareSecurityHealthBreakdown(data) {
    const normalized = normalizeNetworkSecurityData(data);
    const overview = normalized.overview;
    const permissionFamilies = normalized.permissionMatrix || [];
    const readableFamilies = Number(overview.endpointFamiliesAvailable || 0);
    const totalFamilies = Math.max(1, Number(overview.endpointFamilies || permissionFamilies.length || 1));
    const policyCount = Math.max(1, overview.gatewayPolicies + normalized.policies.length);
    const activePolicyRate = Math.min(1, (overview.activeGatewayPolicies + normalized.policies.length) / policyCount);
    const identityReady = /not configured/i.test(overview.identityProvider) ? 0 : 1;
    const zeroTrustCoverage = Math.min(30, (overview.protectedApps > 0 ? 10 : 0) + (overview.activeGatewayPolicies > 0 ? 8 : 0) + (identityReady ? 6 : 0) + (readableFamilies / totalFamilies) * 6);
    const accessPolicyStrength = Math.min(20, (activePolicyRate * 10) + (normalized.policies.length > 0 ? 4 : 0) + (normalized.accessGroups.length > 0 ? 3 : 0) + (normalized.accessCertificates.length > 0 || normalized.mtlsCertificates.length > 0 ? 3 : 0));
    const devicePostureCompliance = Math.min(15, (overview.enrolledDevices > 0 ? 6 : 0) + (normalized.devicePosture.length > 0 ? 5 : 0) + (overview.warpProfiles > 0 ? 4 : 0));
    const threatFindings = normalized.securityInsights.length + normalized.applicationSecurityReports.length + normalized.casbFindings.length + normalized.intelFeeds.length + normalized.dnsFirewallRules.length;
    const blockedOrDenied = normalized.accessLogs.filter(log => /block|deny|fail/i.test(String(log.action || log.status || ''))).length;
    const threatActivityControl = Math.max(0, 15 - Math.min(10, threatFindings * 2) - Math.min(5, blockedOrDenied));
    const tunnelConnectorHealth = Math.min(10, (normalized.tunnels.length > 0 ? 3 : 0) + (normalized.warpConnectors.length > 0 ? 2 : 0) + (overview.virtualNetworks > 0 ? 2 : 0) + (overview.loadBalancerPools > 0 || overview.loadBalancerMonitors > 0 ? 2 : 0) + (overview.magicWanSites > 0 || overview.magicWanRoutes > 0 ? 1 : 0));
    const endpointIssues = Object.values(normalized.sections || {}).filter(section => ['error', 'permission_unavailable'].includes(section?.status)).length;
    const auditGovernanceHygiene = Math.max(0, Math.min(10, (normalized.auditLogs.length > 0 || normalized.accountLogs.length > 0 ? 5 : 0) + (normalized.permissionMatrix.length > 0 ? 3 : 0) + (endpointIssues === 0 ? 2 : 0) - Math.min(4, endpointIssues)));

    return {
        zeroTrustCoverage,
        accessPolicyStrength,
        devicePostureCompliance,
        threatActivityControl,
        tunnelConnectorHealth,
        auditGovernanceHygiene,
        score: Math.round(zeroTrustCoverage + accessPolicyStrength + devicePostureCompliance + threatActivityControl + tunnelConnectorHealth + auditGovernanceHygiene)
    };
}

function getNetworkSecurityScore(data) {
    return Math.max(0, Math.min(100, getCloudflareSecurityHealthBreakdown(data).score));
}

function updateNetworkSecurityProjectCard(data) {
    const project = mockProjects.find(p => p.id === 10);
    if (!project) return;

    const normalized = normalizeNetworkSecurityData(data);
    const overview = normalized.overview;
    const score = getNetworkSecurityScore(normalized);
    const sectionErrors = Object.values(normalized.sections || {}).filter(section => section.status === 'error').length;
    const permissionGaps = Object.values(normalized.sections || {}).filter(section => section.status === 'permission_unavailable').length;
    const cloudflareSignals = buildCloudflareSecuritySignals(normalized);
    const cloudflareHigh = cloudflareSignals.alerts.filter(alert => ['critical', 'high'].includes(String(alert.severity || '').toLowerCase())).length;
    const logRecords = normalized.accessLogs.length + normalized.auditLogs.length + normalized.accountLogs.length;

    latestNetworkSecurityData = normalized;
    project.networkSecuritySnapshot = normalized;
    project.status = normalized.success ? 'active' : 'error';
    project.securityScore = score;
    project.risks = {
        critical: sectionErrors + cloudflareSignals.incidents.filter(incident => String(incident.severity || '').toLowerCase() === 'critical').length,
        high: permissionGaps + cloudflareHigh,
        medium: cloudflareSignals.alerts.filter(alert => String(alert.severity || '').toLowerCase() === 'medium').length
    };
    project.cardMetrics = [
        { label: "Protected Apps", value: `: ${overview.protectedApps}`, icon: "fas fa-lock" },
        { label: "Devices", value: `: ${overview.enrolledDevices}`, icon: "fas fa-laptop" },
        { label: "Gateway Rules", value: `: ${overview.gatewayPolicies}`, icon: "fas fa-filter" },
        { label: "Identity", value: `: ${compactNetworkIdentityProvider(overview.identityProvider)}`, icon: "fas fa-id-card" }
    ];
    project.cardFooter = normalized.success
        ? `${cloudflareSignals.notificationCount ? `${cloudflareSignals.notificationCount} Cloudflare item(s)` : overview.securityStatus} | ${logRecords} log record${logRecords === 1 ? '' : 's'}`
        : (normalized.message || 'Cloudflare data unavailable');
    project.lastUpdate = new Date().toLocaleTimeString();
    saveProjectCardToCache(project);
}

async function fetchNetworkSecurityCardData(forceRefresh = false) {
    const project = mockProjects.find(p => p.id === 10);
    if (!project || !isSunbirdUser()) return null;

    if (!forceRefresh) {
        const cached = readSunbirdNetworkSecuritySnapshot();
        if (cached) {
            updateNetworkSecurityProjectCard(cached);
            displayCurrentProject();
            refreshCloudflareLinkedSecuritySurfaces();
        }
    }

    try {
        const token = localStorage.getItem('authToken');
        if (!token) return null;
        if (!hasRealProjectMetrics(project)) {
            project.status = 'loading';
            displayCurrentProject();
        }

        const response = await fetch('/api/cloudflare/network-security/summary', {
            method: 'GET',
            cache: 'no-store',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();
        if (!response.ok || data.success === false) {
            throw new Error(data.message || `Cloudflare data unavailable (${response.status})`);
        }

        const normalized = normalizeNetworkSecurityData(data);
        saveSunbirdNetworkSecuritySnapshot(normalized);
        updateNetworkSecurityProjectCard(normalized);
        displayCurrentProject();
        refreshCloudflareLinkedSecuritySurfaces();
        if (document.getElementById('sunbird-network-security-dashboard')) {
            renderSunbirdNetworkSecurityDashboard(normalized);
        }
        return normalized;
    } catch (error) {
        console.error('[Network Security] Cloudflare fetch failed:', error.message);
        const fallback = normalizeNetworkSecurityData({
            success: false,
            message: error.message,
            overview: {}
        });
        updateNetworkSecurityProjectCard(fallback);
        displayCurrentProject();
        refreshCloudflareLinkedSecuritySurfaces();
        if (document.getElementById('sunbird-network-security-dashboard')) {
            renderSunbirdNetworkSecurityDashboard(fallback);
        }
        return fallback;
    }
}

function renderNetworkSecurityCardPanel(project) {
    const data = normalizeNetworkSecurityData(project.networkSecuritySnapshot || latestNetworkSecurityData || {});
    const overview = data.overview;
    const isLoading = project.status === 'loading' && !latestNetworkSecurityData;
    const lastEvent = formatNetworkSecurityDate(overview.lastAccessEvent);
    const gatewayTone = overview.gatewayProxyEnabled ? 'good' : 'warn';
    const identityTone = /not configured/i.test(overview.identityProvider) ? 'warn' : 'good';
    const dlpTone = overview.dlpProfiles > 0 ? 'good' : 'neutral';
    const warpTone = overview.warpProfiles > 0 ? 'good' : 'neutral';
    const privateNetworkTone = overview.virtualNetworks > 0 ? 'good' : 'warn';
    const udpTone = overview.udpProxyEnabled ? 'good' : 'warn';
    const tlsTone = overview.tlsDecryptEnabled ? 'good' : 'neutral';
    const cloudflareSignals = buildCloudflareSecuritySignals(data);
    const logRecords = data.accessLogs.length + data.auditLogs.length + data.accountLogs.length;
    const notificationTone = cloudflareSignals.highCount ? 'bad' : cloudflareSignals.notificationCount ? 'warn' : 'good';
    const notificationLabel = cloudflareSignals.notificationCount
        ? `${cloudflareSignals.notificationCount} item${cloudflareSignals.notificationCount === 1 ? '' : 's'}`
        : 'Clear';

    if (isLoading) {
        return `
            <div class="network-security-compact-panel is-loading">
                <div class="network-security-skeleton wide"></div>
                <div class="network-security-skeleton-grid">
                    <span></span><span></span><span></span><span></span>
                </div>
                <div class="network-security-skeleton tall"></div>
            </div>
        `;
    }

    return `
        <div class="network-security-compact-panel">
            <div class="network-security-status-line">
                <span class="network-security-status-dot ${project.status === 'error' ? 'bad' : 'good'}"></span>
                <span>${escapeIdentityText(`Health Score: ${overview.securityStatus}`)}</span>
                <strong>${escapeIdentityText(String(getNetworkSecurityScore(data)))}%</strong>
            </div>
            <div class="network-security-notification-strip tone-${notificationTone}">
                <span><i class="fas fa-bell"></i>${escapeIdentityText(cloudflareSignals.notificationCount ? 'Cloudflare review' : 'Cloudflare normal')}</span>
                <strong>${escapeIdentityText(notificationLabel)}</strong>
            </div>
            <div class="network-security-mini-grid">
                <div><span>WARP</span><strong>${escapeIdentityText(String(overview.registeredWarpDevices || overview.enrolledDevices))}</strong></div>
                <div><span>Logs</span><strong>${escapeIdentityText(String(logRecords))}</strong></div>
                <div><span>DLP</span><strong>${escapeIdentityText(String(overview.dlpProfiles))}</strong></div>
                <div><span>Data</span><strong>${escapeIdentityText(overview.endpointFamilies ? `${overview.endpointFamiliesAvailable}/${overview.endpointFamilies}` : String(overview.appCategories))}</strong></div>
            </div>
            <div class="network-security-signal-list">
                <div class="network-security-signal">
                    <span><i class="fas fa-user-shield"></i> Identity</span>
                    <strong class="${identityTone}">${escapeIdentityText(compactNetworkIdentityProvider(overview.identityProvider))}</strong>
                </div>
                <div class="network-security-signal">
                    <span><i class="fas fa-route"></i> Gateway Proxy</span>
                    <strong class="${gatewayTone}">${networkSecurityBoolLabel(overview.gatewayProxyEnabled)}</strong>
                </div>
                <div class="network-security-signal">
                    <span><i class="fas fa-clock"></i> Last Access</span>
                    <strong>${escapeIdentityText(lastEvent)}</strong>
                </div>
                <div class="network-security-signal">
                    <span><i class="fas fa-fingerprint"></i> DLP Readiness</span>
                    <strong class="${dlpTone}">${overview.dlpProfiles ? `${overview.dlpProfiles} profiles` : 'No profiles'}</strong>
                </div>
                <div class="network-security-signal">
                    <span><i class="fas fa-shield-halved"></i> WARP Profiles</span>
                    <strong class="${warpTone}">${overview.warpProfiles ? `${overview.warpProfiles} profiles` : 'No profiles'}</strong>
                </div>
                <div class="network-security-signal">
                    <span><i class="fas fa-diagram-project"></i> Private Network</span>
                    <strong class="${privateNetworkTone}">${overview.virtualNetworks ? `${overview.virtualNetworks} ready` : 'Not ready'}</strong>
                </div>
                <div class="network-security-signal">
                    <span><i class="fas fa-satellite-dish"></i> UDP Proxy</span>
                    <strong class="${udpTone}">${networkSecurityBoolLabel(overview.udpProxyEnabled)}</strong>
                </div>
                <div class="network-security-signal">
                    <span><i class="fas fa-certificate"></i> TLS Decrypt</span>
                    <strong class="${tlsTone}">${networkSecurityBoolLabel(overview.tlsDecryptEnabled)}</strong>
                </div>
            </div>
        </div>
    `;
}

function renderSunbirdNetworkSecurityShell() {
    return `
        <section class="sunbird-network-security-dashboard" id="sunbird-network-security-dashboard">
            <div class="sunbird-id-header">
                <button id="sunbird-network-back" class="sunbird-id-back-btn" type="button"><span class="sunbird-id-back-icon" aria-hidden="true">&larr;</span><span>Back</span></button>
                <div><h2>Network Security</h2><p>Cloudflare One, WARP, Gateway, Access, and DLP posture.</p></div>
                <div class="sunbird-id-microsoft-badge cloudflare-badge network-security-brand-square" aria-label="Cloudflare One">
                    <img src="Images/cloudflare.png" alt="" aria-hidden="true">
                    <span>Cloudflare One</span>
                </div>
            </div>
            <div id="sunbird-network-security-content">${renderSunbirdPremiumLoader('Loading Cloudflare Zero Trust')}</div>
        </section>
    `;
}

function getNetworkRows(items, columns, emptyText) {
    const safeItems = Array.isArray(items) ? items : [];
    if (!safeItems.length) return `<tr><td colspan="${columns.length}" class="sunbird-empty-row">${escapeIdentityText(emptyText)}</td></tr>`;
    return safeItems.map(item => `
        <tr>
            ${columns.map(column => `<td>${escapeIdentityText(formatNetworkEvidenceValue(column.value(item)))}</td>`).join('')}
        </tr>
    `).join('');
}

function getNetworkEvidenceValue(item, keys = []) {
    if (!item || typeof item !== 'object') return null;
    for (const key of keys) {
        const value = key.split('.').reduce((current, part) => current?.[part], item);
        if (value !== undefined && value !== null && value !== '') return value;
    }
    return null;
}

function formatNetworkEvidenceValue(value) {
    if (value === true) return 'Enabled';
    if (value === false) return 'Disabled';
    if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? '' : 's'}`;
    if (value && typeof value === 'object') {
        const compact = JSON.stringify(value);
        return compact.length > 160 ? `${compact.slice(0, 157)}...` : compact;
    }
    return value ?? 'Not available';
}
function getNetworkEvidenceShortId(value) {
    if (!value) return null;
    const text = String(value);
    return text.length > 14 ? `${text.slice(0, 8)}...${text.slice(-4)}` : text;
}

function getNetworkEvidenceName(item, fallback = 'Cloudflare record') {
    const value = getNetworkEvidenceValue(item, [
        'name', 'title', 'display_name', 'displayName', 'description', 'deviceName', 'userEmail',
        'policyName', 'ruleName', 'profileName', 'applicationName', 'appName', 'domain', 'hostname',
        'action', 'event.action', 'actor.email', 'actor.name', 'user.email', 'resource.name', 'resource.type',
        'type', 'category'
    ]);
    if (value) return value;
    return fallback;
}

function getNetworkEvidenceDetail(item) {
    const parts = [
        getNetworkEvidenceValue(item, ['resource.name', 'resource.type']),
        getNetworkEvidenceValue(item, ['deviceName', 'userEmail', 'email', 'actor.email', 'actor.name', 'actor.type']),
        getNetworkEvidenceValue(item, ['applicationName', 'appName', 'policyName', 'ruleName', 'profileName']),
        getNetworkEvidenceValue(item, ['interface', 'source', 'service', 'ipAddress', 'ip', 'country', 'virtualIpv4', 'virtualIpv6', 'tunnelType']),
        getNetworkEvidenceValue(item, ['lastSeen', 'created_at', 'createdAt', 'when', 'timestamp', 'updated_at', 'last_seen'])
    ].filter(Boolean).map(formatNetworkEvidenceValue);
    return parts.length ? parts.join(' | ') : 'Details available';
}

function getNetworkSectionKey(groupOrKey) {
    if (groupOrKey && typeof groupOrKey === 'object') return groupOrKey.sectionKey || groupOrKey.key;
    return groupOrKey;
}

function getNetworkSectionStatus(data, groupOrKey, items = []) {
    const key = getNetworkSectionKey(groupOrKey);
    if (key === 'permissionMatrix' || key === 'account') return items.length ? 'available' : 'empty';
    const section = data.sections?.[key];
    if (section?.status) return section.status;
    return items.length ? 'available' : 'empty';
}

function getNetworkEvidenceStatusLabel(data, groupOrKey, items = []) {
    const status = getNetworkSectionStatus(data, groupOrKey, items);
    const count = Array.isArray(items) ? items.length : 0;
    if (status === 'permission_unavailable') return `Permission unavailable | ${count} records`;
    if (status === 'error') return `Unavailable | ${count} records`;
    if (status === 'empty') return `No data available | ${count} records`;
    if (status === 'not_requested') return `Not collected | ${count} records`;
    return `Available | ${count} records`;
}

function getNetworkEvidenceEmptyText(data, group) {
    const section = data.sections?.[getNetworkSectionKey(group)];
    const status = getNetworkSectionStatus(data, group, group.items || []);
    if (status === 'permission_unavailable') return `${group.title} is not available with the current Cloudflare token permissions.`;
    if (status === 'error') return `${group.title} is temporarily unavailable${section?.message ? `: ${section.message}` : '.'}`;
    if (status === 'not_requested') return `${group.title} was not collected in this refresh.`;
    return `${group.title} has no data yet. Cloudflare responded successfully, but nothing is configured or active in this area.`;
}

function renderNetworkEvidenceTable(title, items, columns, emptyText, statusLabel = null) {
    const safeItems = Array.isArray(items) ? items : [];
    return `
        <article class="network-dashboard-panel network-evidence-section">
            <div class="network-evidence-section-title">
                <h3>${escapeIdentityText(title)}</h3>
                <span>${escapeIdentityText(statusLabel || `${safeItems.length} records`)}</span>
            </div>
            <div class="network-dashboard-table-wrap">
                <table class="network-dashboard-table network-evidence-table">
                    <thead><tr>${columns.map(column => `<th>${escapeIdentityText(column.label)}</th>`).join('')}</tr></thead>
                    <tbody>${getNetworkRows(safeItems, columns, emptyText)}</tbody>
                </table>
            </div>
        </article>
    `;
}

function renderNetworkGenericEvidenceTable(title, items, emptyText, statusLabel = null) {
    return renderNetworkEvidenceTable(title, items, [
        { label: 'Name', value: item => getNetworkEvidenceName(item) },
        { label: 'Status', value: item => formatNetworkEvidenceValue(getNetworkEvidenceValue(item, ['status', 'state', 'enabled', 'health', 'severity', 'priority'])) },
        { label: 'Type', value: item => getNetworkEvidenceValue(item, ['type', 'family', 'kind', 'category', 'serviceMode', 'service_mode']) },
        { label: 'Detail', value: item => getNetworkEvidenceDetail(item) }
    ], emptyText, statusLabel);
}

function getNetworkEvidenceGroups(data) {
    const accountEvidence = data.account && Object.keys(data.account).length ? [data.account] : [];
    const gatewayConfigEvidence = networkEvidenceObjectHasData(data.gatewayConfig) ? [data.gatewayConfig] : [];
    const gatewayLoggingEvidence = networkEvidenceObjectHasData(data.gatewayLogging) ? [data.gatewayLogging] : [];
    const deviceSettingsEvidence = networkEvidenceObjectHasData(data.deviceSettings) ? [data.deviceSettings] : [];
    const sectionEvidence = Object.entries(data.sections || {}).map(([key, section]) => ({ key, ...section }));

    return [
        { key: 'account', title: 'Account Summary', items: accountEvidence, group: 'api', columns: [
            { label: 'Account', value: item => item.name || item.id },
            { label: 'Type', value: item => item.type },
            { label: 'Created', value: item => formatNetworkSecurityDate(item.createdOn) },
            { label: 'Reference', value: item => getNetworkEvidenceShortId(item.id) }
        ] },
        { key: 'permissionMatrix', title: 'API Permission Families', items: data.permissionMatrix, group: 'api', columns: [
            { label: '#', value: item => item.id || item.key },
            { label: 'Permission', value: item => item.permission },
            { label: 'Endpoint Family', value: item => item.endpointFamily },
            { label: 'Module', value: item => item.module },
            { label: 'Status', value: item => item.status },
            { label: 'Records', value: item => item.recordCount ?? 0 }
        ] },
        { key: 'zones', title: 'Zones', items: data.zones, group: 'api' },
        { key: 'sections', title: 'Endpoint Section Status', items: sectionEvidence, group: 'api', columns: [
            { label: 'Endpoint', value: item => item.label || item.key },
            { label: 'Status', value: item => item.status },
            { label: 'Records', value: item => item.count ?? 0 },
            { label: 'Message', value: item => item.message || 'OK' }
        ] },
        { key: 'accessLogs', title: 'Access Audit Logs', items: data.accessLogs, group: 'logs', columns: [
            { label: 'User', value: item => item.userEmail },
            { label: 'Application', value: item => item.appName },
            { label: 'Action', value: item => item.action },
            { label: 'Country', value: item => item.country },
            { label: 'IP', value: item => item.ipAddress },
            { label: 'Time', value: item => formatNetworkSecurityDate(item.timestamp) }
        ] },
        { key: 'auditLogs', title: 'Account Audit Logs', items: data.auditLogs, group: 'logs', columns: [
            { label: 'Actor', value: item => getNetworkEvidenceValue(item, ['actor.email', 'actor.name', 'actor.type', 'user.email']) || getNetworkEvidenceName(item, 'Audit event') },
            { label: 'Action', value: item => getNetworkEvidenceValue(item, ['action', 'event.action', 'operation', 'type']) },
            { label: 'Resource', value: item => getNetworkEvidenceValue(item, ['resource.name', 'resource.type']) },
            { label: 'Interface', value: item => getNetworkEvidenceValue(item, ['interface', 'source', 'service']) },
            { label: 'Time', value: item => formatNetworkSecurityDate(getNetworkEvidenceValue(item, ['when', 'created_at', 'createdAt', 'timestamp'])) },
            { label: 'Detail', value: item => getNetworkEvidenceDetail(item) }
        ] },
        { key: 'accountLogs', title: 'Platform Logs', items: data.accountLogs, group: 'logs', columns: [
            { label: 'Event', value: item => getNetworkEvidenceName(item, 'Platform event') },
            { label: 'Action', value: item => getNetworkEvidenceValue(item, ['action', 'event.action', 'operation', 'type']) },
            { label: 'Actor / Source', value: item => getNetworkEvidenceValue(item, ['actor.email', 'actor.name', 'source', 'service', 'interface']) },
            { label: 'Time', value: item => formatNetworkSecurityDate(getNetworkEvidenceValue(item, ['when', 'created_at', 'createdAt', 'timestamp'])) },
            { label: 'Detail', value: item => getNetworkEvidenceDetail(item) }
        ] },
        { key: 'apps', title: 'Protected Applications', items: data.apps, group: 'access', columns: [
            { label: 'Application', value: item => item.name },
            { label: 'Type', value: item => item.type },
            { label: 'Domain', value: item => item.domain },
            { label: 'Policies', value: item => Array.isArray(item.policies) ? item.policies.length : 0 }
        ] },
        { key: 'policies', title: 'Access Policies', items: data.policies, group: 'access', columns: [
            { label: 'Policy', value: item => item.name },
            { label: 'Decision', value: item => item.decision },
            { label: 'Session', value: item => item.sessionDuration },
            { label: 'Requires', value: item => Array.isArray(item.requires) ? item.requires.length : 0 }
        ] },
        { key: 'identityProviders', title: 'Identity Providers', items: data.identityProviders, group: 'identity', columns: [
            { label: 'Provider', value: item => item.name },
            { label: 'Type', value: item => item.type },
            { label: 'Status', value: item => item.status },
            { label: 'Reference', value: item => getNetworkEvidenceShortId(item.id) }
        ] },
        { key: 'accessGroups', title: 'Access Groups', items: data.accessGroups, group: 'identity' },
        { key: 'accessOrganizations', title: 'Access Organizations', items: data.accessOrganizations, group: 'identity' },
        { key: 'mtlsCertificates', title: 'Account mTLS Certificates', items: data.mtlsCertificates, group: 'identity' },
        { key: 'accessCertificates', title: 'Access mTLS Certificates', items: data.accessCertificates, group: 'identity' },
        { key: 'devices', title: 'Devices', items: data.devices, group: 'devices', columns: [
            { label: 'Device', value: item => item.name },
            { label: 'User', value: item => item.userEmail },
            { label: 'OS', value: item => item.os },
            { label: 'WARP', value: item => item.warpVersion },
            { label: 'Last Seen', value: item => formatNetworkSecurityDate(item.lastSeen) },
            { label: 'Status', value: item => item.status }
        ] },
        { key: 'deviceRegistrations', title: 'Device Registrations', items: data.deviceRegistrations, group: 'devices', columns: [
            { label: 'User', value: item => item.userEmail || item.deviceName },
            { label: 'Device', value: item => item.deviceName },
            { label: 'Status', value: item => item.status },
            { label: 'Network', value: item => getNetworkEvidenceValue(item, ['virtualIpv4', 'virtualIpv6', 'tunnelType']) },
            { label: 'Last Seen', value: item => formatNetworkSecurityDate(item.lastSeen) }
        ] },
        { key: 'devicePosture', title: 'Device Posture Rules', items: data.devicePosture, group: 'devices', columns: [
            { label: 'Rule', value: item => item.name },
            { label: 'Type', value: item => item.type },
            { label: 'Status', value: item => item.enabled },
            { label: 'Schedule', value: item => getNetworkEvidenceValue(item, ['schedule', 'frequency', 'interval']) || 'Continuous' }
        ] },
        { key: 'deviceSettings', title: 'Device Settings', items: deviceSettingsEvidence, group: 'devices', columns: [
            { label: 'Setting', value: item => item.name || 'Account device settings' },
            { label: 'Gateway Proxy', value: item => formatNetworkEvidenceValue(item.gatewayProxyEnabled) },
            { label: 'UDP Proxy', value: item => formatNetworkEvidenceValue(item.udpProxyEnabled) },
            { label: 'Certificate', value: item => formatNetworkEvidenceValue(item.certificateEnabled) },
            { label: 'Virtual IP', value: item => formatNetworkEvidenceValue(item.useZtVirtualIp) }
        ] },
        { key: 'warpProfiles', title: 'WARP Profiles', items: data.warpProfiles, group: 'infrastructure', columns: [
            { label: 'Profile', value: item => item.name },
            { label: 'Mode', value: item => item.serviceMode },
            { label: 'Enabled', value: item => item.enabled },
            { label: 'Precedence', value: item => item.precedence }
        ] },
        { key: 'warpConnectors', title: 'WARP Connectors', items: data.warpConnectors, group: 'infrastructure' },
        { key: 'virtualNetworks', title: 'Virtual Networks', items: data.virtualNetworks, group: 'infrastructure', columns: [
            { label: 'Network', value: item => item.name },
            { label: 'Default', value: item => item.isDefault },
            { label: 'Status', value: item => item.status || 'Configured' },
            { label: 'Reference', value: item => getNetworkEvidenceShortId(item.id) }
        ] },
        { key: 'teamnetRoutes', title: 'Network Routes', items: data.teamnetRoutes, group: 'infrastructure' },
        { key: 'tunnels', title: 'Cloudflare Tunnels', items: data.tunnels, group: 'infrastructure' },
        { key: 'loadBalancerPools', title: 'Load Balancer Pools', items: data.loadBalancerPools, group: 'infrastructure' },
        { key: 'loadBalancerMonitors', title: 'Load Balancer Monitors', items: data.loadBalancerMonitors, group: 'infrastructure' },
        { key: 'magicWanSites', title: 'Magic WAN Sites', items: data.magicWanSites, group: 'infrastructure' },
        { key: 'magicWanRoutes', title: 'Magic WAN Routes', items: data.magicWanRoutes, group: 'infrastructure' },
        { key: 'gatewayConfig', title: 'Gateway Configuration', items: gatewayConfigEvidence, group: 'gateway', columns: [
            { label: 'Gateway Proxy', value: item => getNetworkEvidenceValue(item, ['gateway_proxy_enabled', 'settings.gateway_proxy.enabled', 'settings.gateway_proxy_enabled']) },
            { label: 'TLS Decrypt', value: item => getNetworkEvidenceValue(item, ['tls_decrypt.enabled', 'settings.tls_decrypt.enabled']) },
            { label: 'UDP Proxy', value: item => getNetworkEvidenceValue(item, ['gateway_udp_proxy_enabled', 'udp_proxy.enabled', 'settings.gateway_udp_proxy_enabled']) },
            { label: 'Certificate', value: item => getNetworkEvidenceValue(item, ['root_certificate_installation_enabled', 'settings.certificate', 'certificate']) },
            { label: 'Created', value: item => formatNetworkSecurityDate(getNetworkEvidenceValue(item, ['created_at', 'createdAt'])) }
        ] },
        { key: 'gatewayRules', title: 'Gateway Rules', items: data.gatewayRules, group: 'gateway', columns: [
            { label: 'Rule', value: item => item.name },
            { label: 'Action', value: item => item.action },
            { label: 'Enabled', value: item => item.enabled },
            { label: 'Precedence', value: item => item.precedence }
        ] },
        { key: 'gatewayLists', title: 'Gateway Lists', items: data.gatewayLists, group: 'gateway', columns: [
            { label: 'List', value: item => item.name },
            { label: 'Type', value: item => item.type },
            { label: 'Entries', value: item => item.count },
            { label: 'Description', value: item => item.description }
        ] },
        { key: 'gatewayLogging', title: 'Gateway Logging', items: gatewayLoggingEvidence, group: 'gateway', columns: [
            { label: 'Setting', value: () => 'Gateway logging' },
            { label: 'DNS', value: item => formatNetworkEvidenceValue(item.dnsLogAll) },
            { label: 'HTTP', value: item => formatNetworkEvidenceValue(item.httpLogAll) },
            { label: 'L4', value: item => formatNetworkEvidenceValue(item.l4LogAll) }
        ] },
        { key: 'gatewayAppTypes', title: 'Gateway App Catalog', items: data.gatewayAppTypes, group: 'gateway' },
        { key: 'dlpProfiles', title: 'DLP Profiles', items: data.dlpProfiles, group: 'gateway', columns: [
            { label: 'Profile', value: item => item.name },
            { label: 'Enabled', value: item => item.enabled },
            { label: 'Entries', value: item => item.entries },
            { label: 'Detections', value: item => item.detections }
        ] },
        { key: 'securityInsights', title: 'Security Insights', items: data.securityInsights, group: 'security' },
        { key: 'applicationSecurityReports', title: 'Application Security Reports', items: data.applicationSecurityReports, group: 'security' },
        { key: 'apiGatewayOperations', sectionKey: 'apiGateway', title: 'API Gateway Discovery', items: data.apiGatewayOperations, group: 'security' },
        { key: 'casbFindings', title: 'CASB Findings', items: data.casbFindings, group: 'security' },
        { key: 'cloudforceRequests', title: 'Cloudforce One', items: data.cloudforceRequests, group: 'security' },
        { key: 'intelFeeds', title: 'Intel Feeds', items: data.intelFeeds, group: 'security' },
        { key: 'dnsFirewallRules', sectionKey: 'dnsFirewall', title: 'DNS Firewall', items: data.dnsFirewallRules, group: 'security' },
        { key: 'teamsDexTests', title: 'Teams DEX', items: data.teamsDexTests, group: 'security' }
    ];
}

function networkEvidenceObjectHasData(value) {
    if (value === null || value === undefined || value === '') return false;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value !== 'object') return true;
    return Object.values(value).some(entry => networkEvidenceObjectHasData(entry));
}

function networkEvidenceGroupHasRows(group) {
    const items = Array.isArray(group.items) ? group.items : [];
    if (!items.length) return false;
    if (items.length === 1 && items[0] && typeof items[0] === 'object' && !Array.isArray(items[0])) {
        return networkEvidenceObjectHasData(items[0]);
    }
    return true;
}

function renderNetworkEvidenceGroup(data, groupKey) {
    const visibleGroups = getNetworkEvidenceGroups(data)
        .filter(group => group.group === groupKey)
        .filter(networkEvidenceGroupHasRows);
    if (!visibleGroups.length) return '';
    return `
        <div class="network-evidence-section-stack">
            ${visibleGroups
                .map(group => group.columns
                    ? renderNetworkEvidenceTable(group.title, group.items, group.columns, getNetworkEvidenceEmptyText(data, group), getNetworkEvidenceStatusLabel(data, group, group.items))
                    : renderNetworkGenericEvidenceTable(group.title, group.items, getNetworkEvidenceEmptyText(data, group), getNetworkEvidenceStatusLabel(data, group, group.items)))
                .join('')}
        </div>
    `;
}

function renderNetworkMetricsGraph(data) {
    const overview = data.overview;
    const apiTotal = Math.max(1, Number(overview.endpointFamilies || data.permissionMatrix.length || 1));
    const available = Number(overview.endpointFamiliesAvailable || 0);
    const gaps = Number(overview.endpointFamiliesWithGaps || 0);
    const empty = Math.max(0, apiTotal - available - gaps);
    const clientEvidenceGroups = getNetworkEvidenceGroups(data).filter(group => group.group !== 'api');
    const totalEvidenceRows = clientEvidenceGroups.reduce((sum, group) => sum + (Array.isArray(group.items) ? group.items.length : 0), 0);
    const totalCloudflareRecords = Math.max(1, data.permissionMatrix.reduce((sum, family) => sum + Number(family.recordCount || 0), 0), totalEvidenceRows);
    const records = [
        { label: 'Readable Cloudflare areas', value: available, total: apiTotal, evidence: 'Cloudflare collection status' },
        { label: 'Areas needing review', value: gaps, total: apiTotal, evidence: 'Cloudflare collection status' },
        { label: 'Areas with no data', value: empty, total: apiTotal, evidence: 'Cloudflare collection status' },
        { label: 'All log records', value: data.accessLogs.length + data.auditLogs.length + data.accountLogs.length, total: totalCloudflareRecords, evidence: 'accessLogs + auditLogs + accountLogs' },
        { label: 'Infrastructure records', value: data.tunnels.length + data.warpConnectors.length + data.loadBalancerPools.length + data.loadBalancerMonitors.length + data.magicWanSites.length + data.magicWanRoutes.length + data.teamnetRoutes.length, total: totalCloudflareRecords, evidence: 'infrastructure tables' },
        { label: 'Security intelligence records', value: data.securityInsights.length + data.applicationSecurityReports.length + data.apiGatewayOperations.length + data.casbFindings.length + data.cloudforceRequests.length + data.intelFeeds.length + data.dnsFirewallRules.length + data.teamsDexTests.length, total: totalCloudflareRecords, evidence: 'security intel tables' }
    ];
    const healthBreakdown = getCloudflareSecurityHealthBreakdown(data);
    const healthRecords = [
        { label: 'Zero Trust Coverage', value: healthBreakdown.zeroTrustCoverage, total: 30, evidence: 'Access + Gateway + DLP + endpoint coverage' },
        { label: 'Access Policy Strength', value: healthBreakdown.accessPolicyStrength, total: 20, evidence: 'Access apps, policies, identity providers' },
        { label: 'Device Posture Compliance', value: healthBreakdown.devicePostureCompliance, total: 15, evidence: 'Devices, posture rules, WARP profiles' },
        { label: 'Threat Activity Control', value: healthBreakdown.threatActivityControl, total: 15, evidence: 'Security insights, CASB, intel, DNS firewall' },
        { label: 'Tunnel / Connector Health', value: healthBreakdown.tunnelConnectorHealth, total: 10, evidence: 'Tunnels, WARP connectors, virtual networks' },
        { label: 'Audit / Governance Hygiene', value: healthBreakdown.auditGovernanceHygiene, total: 10, evidence: 'Audit logs + endpoint gaps' }
    ];
    const controlTotal = Math.max(1, data.apps.length + data.gatewayRules.length + data.devices.length + data.dlpProfiles.length);
    const activityTotal = Math.max(1, data.auditLogs.length + data.accessLogs.length + data.gatewayAppTypes.length + data.securityInsights.length + data.applicationSecurityReports.length + data.casbFindings.length + data.intelFeeds.length);

    return `
        <div class="network-dashboard-panels network-metrics-graph-grid">
            <article class="network-dashboard-panel network-evidence-section">
                <div class="network-evidence-section-title">
                    <h3>Cloudflare Metrics</h3>
                    <span>${escapeIdentityText(String(data.permissionMatrix.length || overview.endpointFamilies || 0))} areas</span>
                </div>
                <div class="network-metric-bars">
                    ${records.map(record => {
                        const percent = Math.max(0, Math.min(100, Math.round((Number(record.value || 0) / Math.max(1, Number(record.total || 1))) * 100)));
                        return `
                            <div class="network-metric-bar-row">
                                <div><span>${escapeIdentityText(record.label)}</span><strong>${escapeIdentityText(String(record.value))}</strong></div>
                                <i style="--network-bar:${percent}%"></i>
                                <small>Evidence: ${escapeIdentityText(record.evidence)}</small>
                            </div>
                        `;
                    }).join('')}
                </div>
            </article>
            <article class="network-dashboard-panel network-evidence-section">
                <div class="network-evidence-section-title">
                    <h3>Security Health Score</h3>
                    <span>${escapeIdentityText(String(healthBreakdown.score))}%</span>
                </div>
                <div class="network-health-ring-grid">
                    ${healthRecords.slice(0, 4).map(record => {
                        const percent = Math.max(0, Math.min(100, Math.round((Number(record.value || 0) / Math.max(1, Number(record.total || 1))) * 100)));
                        return `
                            <div class="network-health-ring-card">
                                <span class="network-health-ring" style="--network-ring:${percent}%"><b>${escapeIdentityText(String(percent))}%</b></span>
                                <small>${escapeIdentityText(record.label)}</small>
                            </div>
                        `;
                    }).join('')}
                </div>
                <div class="network-metric-bars compact-health-bars">
                    ${healthRecords.map(record => {
                        const percent = Math.max(0, Math.min(100, Math.round((Number(record.value || 0) / Math.max(1, Number(record.total || 1))) * 100)));
                        return `
                            <div class="network-metric-bar-row">
                                <div><span>${escapeIdentityText(record.label)}</span><strong>${escapeIdentityText(`${Math.round(record.value)}/${record.total}`)}</strong></div>
                                <i style="--network-bar:${percent}%"></i>
                                <small>Evidence: ${escapeIdentityText(record.evidence)}</small>
                            </div>
                        `;
                    }).join('')}
                </div>
            </article>
            <article class="network-dashboard-panel network-evidence-section">
                <div class="network-evidence-section-title">
                    <h3>Control Inventory</h3>
                    <span>${escapeIdentityText(String(controlTotal))} records</span>
                </div>
                <div class="network-metric-bars">
                    <div class="network-metric-bar-row"><div><span>Protected Apps</span><strong>${escapeIdentityText(String(data.apps.length))}</strong></div><i style="--network-bar:${Math.round((data.apps.length / controlTotal) * 100)}%"></i><small>Evidence: Access applications</small></div>
                    <div class="network-metric-bar-row"><div><span>Gateway Rules</span><strong>${escapeIdentityText(String(data.gatewayRules.length))}</strong></div><i style="--network-bar:${Math.round((data.gatewayRules.length / controlTotal) * 100)}%"></i><small>Evidence: Gateway policy rules</small></div>
                    <div class="network-metric-bar-row"><div><span>Devices</span><strong>${escapeIdentityText(String(data.devices.length))}</strong></div><i style="--network-bar:${Math.round((data.devices.length / controlTotal) * 100)}%"></i><small>Evidence: Zero Trust devices</small></div>
                    <div class="network-metric-bar-row"><div><span>DLP Profiles</span><strong>${escapeIdentityText(String(data.dlpProfiles.length))}</strong></div><i style="--network-bar:${Math.round((data.dlpProfiles.length / controlTotal) * 100)}%"></i><small>Evidence: DLP profiles</small></div>
                </div>
            </article>
            <article class="network-dashboard-panel network-evidence-section">
                <div class="network-evidence-section-title">
                    <h3>Activity Volume</h3>
                    <span>${escapeIdentityText(String(activityTotal))} records</span>
                </div>
                <div class="network-metric-bars">
                    <div class="network-metric-bar-row"><div><span>Audit Events</span><strong>${escapeIdentityText(String(data.auditLogs.length))}</strong></div><i style="--network-bar:${Math.round((data.auditLogs.length / activityTotal) * 100)}%"></i><small>Evidence: Account audit logs</small></div>
                    <div class="network-metric-bar-row"><div><span>Access Events</span><strong>${escapeIdentityText(String(data.accessLogs.length))}</strong></div><i style="--network-bar:${Math.round((data.accessLogs.length / activityTotal) * 100)}%"></i><small>Evidence: Access request logs</small></div>
                    <div class="network-metric-bar-row"><div><span>Gateway Catalog</span><strong>${escapeIdentityText(String(data.gatewayAppTypes.length))}</strong></div><i style="--network-bar:${Math.round((data.gatewayAppTypes.length / activityTotal) * 100)}%"></i><small>Evidence: Gateway app catalog</small></div>
                    <div class="network-metric-bar-row"><div><span>Threat Intel</span><strong>${escapeIdentityText(String(data.securityInsights.length + data.applicationSecurityReports.length + data.casbFindings.length + data.intelFeeds.length))}</strong></div><i style="--network-bar:${Math.round(((data.securityInsights.length + data.applicationSecurityReports.length + data.casbFindings.length + data.intelFeeds.length) / activityTotal) * 100)}%"></i><small>Evidence: security intel tables</small></div>
                </div>
            </article>
        </div>
    `;
}
function getNetworkEvidenceItems(data, key) {
    const pick = (items, mapper, fallback) => {
        const safeItems = Array.isArray(items) ? items : [];
        if (!safeItems.length) return [{ title: fallback, metaParts: ['No Cloudflare data is available for this signal yet.'] }];
        return safeItems.slice(0, 4).map(mapper);
    };

    if (key === 'protectedApps') {
        return pick(data.apps, app => ({
            title: app.name || app.domain || 'Protected application',
            metaParts: [app.type || app.appType || 'Access app', app.domain, Array.isArray(app.policies) ? `${app.policies.length} polic${app.policies.length === 1 ? 'y' : 'ies'}` : null].filter(Boolean)
        }), 'No protected applications found');
    }

    if (key === 'enrolledDevices') {
        return pick(data.devices, device => ({
            title: device.name || device.userEmail || 'Enrolled device',
            metaParts: [device.userEmail, device.os, device.warpVersion ? `WARP ${device.warpVersion}` : null, device.lastSeen ? `Seen ${formatNetworkSecurityDate(device.lastSeen)}` : null].filter(Boolean)
        }), 'No enrolled devices found');
    }

    if (key === 'gatewayRules') {
        return pick(data.gatewayRules, rule => ({
            title: rule.name || 'Gateway rule',
            metaParts: [rule.action || 'Policy action', rule.enabled ? 'Enabled' : 'Disabled', rule.precedence != null ? `Precedence ${rule.precedence}` : null].filter(Boolean)
        }), 'No Gateway rules found');
    }

    if (key === 'identityProviders') {
        return pick(data.identityProviders, provider => ({
            title: provider.name || 'Identity provider',
            metaParts: [provider.type || 'Provider', provider.status || 'Configured'].filter(Boolean)
        }), 'No identity providers found');
    }

    if (key === 'accessEvents') {
        return pick(data.accessLogs, event => ({
            title: event.userEmail || event.appName || 'Access event',
            metaParts: [event.appName, event.action, event.country, event.timestamp ? formatNetworkSecurityDate(event.timestamp) : null].filter(Boolean)
        }), 'No recent Access events found');
    }

    return pick(data.dlpProfiles, profile => ({
        title: profile.name || 'DLP profile',
        metaParts: [profile.enabled ? 'Enabled' : 'Configured', `${profile.entries || 0} detector entries`].filter(Boolean)
    }), 'No DLP profiles found');
}

function renderNetworkEvidencePopover(metric, data) {
    const evidenceItems = getNetworkEvidenceItems(data, metric.key);
    return `
        <div class="network-evidence-popover" role="dialog" aria-label="${escapeIdentityText(metric.label)} evidence">
            <div class="network-evidence-header">
                <span>Evidence</span>
                <strong>${escapeIdentityText(metric.evidenceLabel)}</strong>
            </div>
            <div class="network-evidence-list">
                ${evidenceItems.map(item => `
                    <div class="network-evidence-row">
                        <span>${escapeIdentityText(item.title)}</span>
                        <small>
                            ${(Array.isArray(item.metaParts) && item.metaParts.length ? item.metaParts : [item.meta || 'Details available from Cloudflare']).map(part => `<b>${escapeIdentityText(part)}</b>`).join('')}
                        </small>
                    </div>
                `).join('')}
            </div>
            <p>Click the evidence action to pin this proof card.</p>
        </div>
    `;
}

function setupNetworkEvidenceInteractions(content) {
    const cards = Array.from(content.querySelectorAll('[data-network-evidence-card]'));
    if (!cards.length) return;

    const closeLockedEvidence = () => {
        cards.forEach(card => card.classList.remove('evidence-locked'));
    };

    cards.forEach(card => {
        const trigger = card.querySelector('[data-network-evidence-trigger]');
        if (!trigger) return;
        trigger.addEventListener('click', event => {
            event.preventDefault();
            event.stopPropagation();
            const shouldLock = !card.classList.contains('evidence-locked');
            closeLockedEvidence();
            card.classList.toggle('evidence-locked', shouldLock);
        });
    });

    if (window.networkEvidenceOutsideHandler) {
        document.removeEventListener('click', window.networkEvidenceOutsideHandler);
    }
    window.networkEvidenceOutsideHandler = event => {
        if (!event.target.closest('[data-network-evidence-card]')) closeLockedEvidence();
    };
    document.addEventListener('click', window.networkEvidenceOutsideHandler);

    if (window.networkEvidenceKeyHandler) {
        document.removeEventListener('keydown', window.networkEvidenceKeyHandler);
    }
    window.networkEvidenceKeyHandler = event => {
        if (event.key === 'Escape') closeLockedEvidence();
    };
    document.addEventListener('keydown', window.networkEvidenceKeyHandler);
}

function renderNetworkSecurityOverview(data) {
    const overview = data.overview;
    const metrics = [
        { key: 'protectedApps', label: 'Protected Apps', value: overview.protectedApps, icon: 'fas fa-lock', evidenceLabel: 'Access applications' },
        { key: 'enrolledDevices', label: 'Enrolled Devices', value: overview.enrolledDevices, icon: 'fas fa-laptop', evidenceLabel: 'Device posture' },
        { key: 'gatewayRules', label: 'Gateway Rules', value: overview.gatewayPolicies, icon: 'fas fa-filter', evidenceLabel: 'Gateway policy rules' },
        { key: 'identityProviders', label: 'Identity Providers', value: overview.identityProviders, icon: 'fas fa-id-card', evidenceLabel: 'SSO providers' },
        { key: 'accessEvents', label: 'Access Events', value: overview.recentAccessEvents, icon: 'fas fa-clock', evidenceLabel: 'Recent access logs' },
        { key: 'dlpProfiles', label: 'DLP Profiles', value: overview.dlpProfiles, icon: 'fas fa-fingerprint', evidenceLabel: 'Data protection profiles' }
    ];

    return `
        <div class="network-dashboard-kpis">
            ${metrics.map(metric => `
                <article class="network-dashboard-kpi" data-network-evidence-card>
                    <i class="${metric.icon}"></i>
                    <strong>${escapeIdentityText(metric.value)}</strong>
                    <span>${escapeIdentityText(metric.label)}</span>
                    <button type="button" class="network-evidence-trigger" data-network-evidence-trigger aria-label="View ${escapeIdentityText(metric.label)} evidence">
                        <i class="fas fa-magnifying-glass-chart" aria-hidden="true"></i>
                        <span>View Evidence</span>
                    </button>
                    ${renderNetworkEvidencePopover(metric, data)}
                </article>
            `).join('')}
        </div>
        <div class="network-dashboard-panels">
            <article class="network-dashboard-panel">
                <h3>Executive Snapshot</h3>
                <div class="network-dashboard-list">
                    <div><span>Status</span><strong>${escapeIdentityText(overview.securityStatus)}</strong></div>
                    <div><span>Identity Provider</span><strong>${escapeIdentityText(overview.identityProvider)}</strong></div>
                    <div><span>Last Access Event</span><strong>${escapeIdentityText(formatNetworkSecurityDate(overview.lastAccessEvent))}</strong></div>
                    <div><span>Data Coverage</span><strong>${escapeIdentityText(overview.endpointFamilies ? `${overview.endpointFamiliesAvailable}/${overview.endpointFamilies} ready` : 'Not measured')}</strong></div>
                </div>
            </article>
            <article class="network-dashboard-panel">
                <h3>Gateway Readiness</h3>
                <div class="network-dashboard-list">
                    <div><span>Gateway Proxy</span><strong>${networkSecurityBoolLabel(overview.gatewayProxyEnabled)}</strong></div>
                    <div><span>UDP Proxy</span><strong>${networkSecurityBoolLabel(overview.udpProxyEnabled)}</strong></div>
                    <div><span>TLS Decrypt</span><strong>${networkSecurityBoolLabel(overview.tlsDecryptEnabled)}</strong></div>
                    <div><span>Infrastructure</span><strong>${escapeIdentityText(`${overview.tunnels || 0} tunnel(s), ${overview.loadBalancerPools || 0} pool(s)`)}</strong></div>
                </div>
            </article>
        </div>
    `;
}

function renderSunbirdNetworkSecurityDashboard(inputData = latestNetworkSecurityData) {
    const data = normalizeNetworkSecurityData(inputData || {});
    latestNetworkSecurityData = data;
    const content = document.getElementById('sunbird-network-security-content');
    if (!content) return;

    const tabs = [
        { label: 'Overview', panel: renderNetworkSecurityOverview(data), pinned: true },
        { label: 'Metrics', panel: renderNetworkMetricsGraph(data), pinned: true },
        { label: 'Logs', panel: renderNetworkEvidenceGroup(data, 'logs') },
        { label: 'Access', panel: renderNetworkEvidenceGroup(data, 'access') },
        { label: 'Infrastructure', panel: renderNetworkEvidenceGroup(data, 'infrastructure') },
        { label: 'Gateway / DLP', panel: renderNetworkEvidenceGroup(data, 'gateway') },
        { label: 'Security Intel', panel: renderNetworkEvidenceGroup(data, 'security') },
        { label: 'Identity / Certs', panel: renderNetworkEvidenceGroup(data, 'identity') },
        { label: 'Devices', panel: renderNetworkEvidenceGroup(data, 'devices') }
    ].filter(tab => tab.pinned || String(tab.panel || '').trim());

    content.innerHTML = `
        ${data.success ? '' : `<div class="network-dashboard-error"><i class="fas fa-circle-exclamation"></i>${escapeIdentityText(data.message || 'Cloudflare data unavailable')}</div>`}
        <label class="network-dashboard-tab-select-wrap">
            <span>View</span>
            <select class="network-dashboard-tab-select" data-network-tab-select aria-label="Network Security section">
                ${tabs.map((tab, index) => `<option value="${index}" ${index === 0 ? 'selected' : ''}>${escapeIdentityText(tab.label)}</option>`).join('')}
            </select>
        </label>
        <div class="network-dashboard-tabs" role="tablist">
            ${tabs.map((tab, index) => `
                <button type="button" class="network-dashboard-tab ${index === 0 ? 'active' : ''}" data-network-tab="${index}">${escapeIdentityText(tab.label)}</button>
            `).join('')}
        </div>
        ${tabs.map((tab, index) => `
            <div class="network-dashboard-tab-panel ${index === 0 ? 'active' : ''}" data-network-panel="${index}">${tab.panel}</div>
        `).join('')}
    `;

    const activateNetworkTab = (target) => {
        content.querySelectorAll('[data-network-tab]').forEach(tab => tab.classList.toggle('active', tab.dataset.networkTab === target));
        content.querySelectorAll('[data-network-panel]').forEach(panel => panel.classList.toggle('active', panel.dataset.networkPanel === target));
        const select = content.querySelector('[data-network-tab-select]');
        if (select && select.value !== target) select.value = target;
    };
    content.querySelectorAll('[data-network-tab]').forEach(button => {
        button.addEventListener('click', () => activateNetworkTab(button.dataset.networkTab));
    });
    content.querySelector('[data-network-tab-select]')?.addEventListener('change', event => activateNetworkTab(event.target.value));
    setupNetworkEvidenceInteractions(content);
}
function openSunbirdNetworkSecurityDashboard() {
    const dashboardView = document.getElementById('dashboard-view');
    const projectsView = document.getElementById('projects-view');
    if (!dashboardView) return;
    if (projectsView) projectsView.style.display = 'none';
    dashboardView.style.display = 'block';
    dashboardView.style.visibility = 'visible';
    dashboardView.style.opacity = '1';
    [
        'sunbird-identity-active',
        'sunbird-device-active',
        'sunbird-email-active',
        'sunbird-security-active',
        'sunbird-backup-active',
        'sunbird-applications-active',
        'sunbird-reports-active'
    ].forEach(className => dashboardView.classList.remove(className));
    dashboardView.classList.add('sunbird-network-security-active');
    captureDashboardViewHTML();
    dashboardView.innerHTML = renderSunbirdNetworkSecurityShell();
    document.getElementById('sunbird-network-back')?.addEventListener('click', goBackToProjects);
    renderSunbirdNetworkSecurityDashboard(latestNetworkSecurityData || readSunbirdNetworkSecuritySnapshot() || {});
    fetchNetworkSecurityCardData(true);
}

function goToPreviousProject() {
    if (currentProjectIndex > 0) {
        currentProjectIndex--;
        previewLockedByClick = false;
        selectedProjectId = null;
        displayCurrentProject();
    }
}

function goToNextProject() {
    const carouselProjects = getFilteredProjects();
    const maxStartIndex = Math.max(0, carouselProjects.length - 3);
    if (currentProjectIndex < maxStartIndex) {
        currentProjectIndex++;
        previewLockedByClick = false;
        selectedProjectId = null;
        displayCurrentProject();
    }
}

function updateNavigationButtons() {
    const carouselProjects = getFilteredProjects();
    const navPrev = document.getElementById('nav-prev');
    const navNext = document.getElementById('nav-next');
    const sidePeekPrev = document.getElementById('side-peek-prev');
    const sidePeekNext = document.getElementById('side-peek-next');

    const maxStartIndex = Math.max(0, carouselProjects.length - 3);
    const disablePrev = currentProjectIndex === 0;
    const disableNext = currentProjectIndex >= maxStartIndex;

    if (navPrev) navPrev.disabled = disablePrev;
    if (navNext) navNext.disabled = disableNext;
    if (sidePeekPrev) sidePeekPrev.disabled = disablePrev;
    if (sidePeekNext) sidePeekNext.disabled = disableNext;
}

function showProjectPreview(project) {
    let previewSection = document.getElementById('project-preview-section');
    previewSection.classList.add('visible');

    const previewModel = buildProjectPreviewModel(project);
    const topMetricsHTML = previewModel.topMetrics.map(metric => `
        <div class="preview-stat-item">
            <div class="preview-stat-icon ${metric.tone || 'info'}">
                <i class="${metric.icon}"></i>
            </div>
            <div class="preview-stat-info">
                <span class="preview-stat-label">${metric.label}</span>
                <span class="preview-stat-value">${metric.value}</span>
            </div>
        </div>
    `).join('');

    const riskBreakdownHTML = previewModel.riskBreakdown.map(item => `
        <div class="risk-item ${item.tone}">
            <span class="risk-label">${item.label}</span>
            <span class="risk-value">${item.value}</span>
        </div>
    `).join('');

    const feedHTML = (previewModel.miniFeed || []).slice(0, 3).map(item => `
        <div class="preview-feed-item">
            <i class="${item.icon || 'fas fa-circle'}"></i>
            <span>${item.text}</span>
        </div>
    `).join('');

    previewSection.innerHTML = `
        <div class="preview-container" id="preview-container">
            <div class="preview-header">
                <h3><i class="fas fa-info-circle"></i> ${project.name}</h3>
                <p class="preview-subtitle">${project.type}</p>
            </div>

            <div class="preview-row preview-row-metrics">
                ${topMetricsHTML}
            </div>

            <div class="preview-row preview-row-risk">
                <h4><i class="fas fa-chart-bar"></i> Risk Breakdown</h4>
                <div class="risk-breakdown">
                    ${riskBreakdownHTML}
                </div>
            </div>

            <div class="preview-row preview-row-insights">
                <div class="preview-insight-line">${previewModel.keyInsight}</div>
                <div class="preview-mini-feed">${feedHTML || '<div class="preview-feed-item"><i class="fas fa-check-circle"></i><span>Live activity is stable</span></div>'}</div>
            </div>

            <div class="glow-wrap">
                <div class="glowing-border-layer"></div>
                <button class="btn-view-full-dashboard" onclick="openDashboard(mockProjects.find(p => p.id === ${project.id}))">
                    <i class="fas fa-arrow-right"></i> View Full Dashboard
                </button>
            </div>
        </div>
    `;
}

function hideProjectPreview() {
    const previewSection = document.getElementById('project-preview-section');
    if (previewSection) {
        previewSection.classList.remove('visible');
    }
}

// Small black "data source" chip (same look as the Cloudflare One badge on the
// Network Security card). Microsoft Graph for Graph-backed cards, 1Password for
// the Credential Security card.
function renderMicrosoftGraphBadgeMarkup() {
    return `<span class="sunbird-id-ms-logo" aria-hidden="true"><i></i><i></i><i></i><i></i></span>`;
}

function renderProjectCardProviderBadge(project) {
    if (!project) return '';
    if (Number(project.id) === 9) {
        return `<div class="card-provider-badge card-provider-badge--onepassword" aria-label="1Password"><img src="Images/1password.webp" alt="" aria-hidden="true"></div>`;
    }
    if (project.microsoftGraphEnabled === true) {
        return `<div class="card-provider-badge card-provider-badge--ms" aria-label="Microsoft Graph">${renderMicrosoftGraphBadgeMarkup()}</div>`;
    }
    return '';
}

// Microsoft Graph chip for the billing-card panels that are Graph-backed
// (Security Alerts, Backup & Recovery, Applications).
function renderSunbirdPanelProviderBadge() {
    return `<div class="card-provider-badge card-provider-badge--ms card-provider-badge--panel" aria-label="Microsoft Graph">${renderMicrosoftGraphBadgeMarkup()}</div>`;
}

function createProjectCard(project) {
    const card = document.createElement('div');
    card.className = 'project-card' + (project.noDashboard ? ' no-interaction' : '');
    card.setAttribute('data-project-id', project.id);
    setNonSunbirdBlurGate(card, shouldBlurGateForNonSunbird() && NON_SUNBIRD_BLUR_PROJECT_IDS.includes(Number(project.id)));
    
    const risksCount = project.risks.critical + project.risks.high + project.risks.medium;
    const networkSecurityCtaHTML = project.id === 10
        ? `<div class="network-security-card-footer">
                <div class="network-security-card-cta" data-network-security-cta="true" role="button" tabindex="0" aria-label="Open full Network Security dashboard">
                    <span><i class="fas fa-arrow-up-right-from-square" aria-hidden="true"></i>Open</span>
                </div>
                <div class="network-security-brand-pill network-security-brand-square" aria-label="Cloudflare One">
                    <img src="Images/cloudflare.png" alt="" aria-hidden="true">
                    <span>Cloudflare One</span>
                </div>
           </div>`
        : '';
    const networkSecurityPanelHTML = project.id === 10 ? renderNetworkSecurityCardPanel(project) : '';
    const providerBadgeHTML = renderProjectCardProviderBadge(project);
    if (providerBadgeHTML) card.classList.add('has-provider-badge');

    const isSummaryCard = isSummaryProjectCard(project);
    const metrics = isSummaryCard ? normalizeSummaryMetrics(project) : (project.cardMetrics || []);
    const statusMeta = getSummaryCardStatusMeta(project);
    const isInactiveProject = String(project.status || '').toLowerCase() === 'inactive';
    const riskDotClass = isInactiveProject
        ? 'critical'
        : project.risks.critical > 0 ? 'critical' : project.risks.high > 0 ? 'high' : (project.risks.medium > 0 ? 'medium' : 'success');
    const riskDotTitle = isInactiveProject
        ? 'Inactive'
        : project.risks.critical > 0 ? project.risks.critical + ' Critical' : project.risks.high > 0 ? project.risks.high + ' High' : (project.risks.medium > 0 ? project.risks.medium + ' Medium' : 'No Risks detected');

    // Build metrics section from cardMetrics array
    let metricsHTML = '';
    if (metrics.length > 0) {
        const renderMetrics = isSummaryCard ? metrics.slice(0, 4) : metrics;
        metricsHTML = renderMetrics.map(metric => {
            if (isSummaryCard && statusMeta.status === 'loading') {
                return `
                    <div class="project-info-item metric-loading">
                        <i class="${metric.icon}"></i>
                        <div class="metric-skeleton-wrap">
                            <span class="metric-skeleton-label"></span>
                            <span class="metric-skeleton-value"></span>
                        </div>
                    </div>
                `;
            }

            return `
                <div class="project-info-item">
                    <i class="${metric.icon}"></i>
                    <div class="metric-content-wrap">
                        <span class="metric-label-text">${metric.label}</span>
                        <span class="metric-value-text">${toMetricValue(metric.value)}</span>
                    </div>
                </div>
            `;
        }).join('');
    }
    
    card.innerHTML = `
        <div class="project-card-header">
            <div class="project-icon">
                ${project.image ? `<img src="${project.image}" alt="${project.name}">` : `<i class="${project.icon}"></i>`}
            </div>
            <div class="project-title">
                <h3>${project.name}</h3>
                <p class="project-type">${project.type}</p>
            </div>
            <span class="project-status-badge status-${project.status.toLowerCase()}">
                ${project.status}
            </span>

        </div>
        <div class="project-info">
            ${metricsHTML}
        </div>
        ${networkSecurityPanelHTML}
        <div class="project-risks">
            <span>${project.cardFooter || 'Risks: ' + risksCount}</span>
            <div class="risk-indicator">
                ${providerBadgeHTML}
                <div class="risk-dot ${riskDotClass}" title="${riskDotTitle}"></div>
            </div>
        </div>
        ${networkSecurityCtaHTML}
    `;

    const networkSecurityCta = card.querySelector('[data-network-security-cta]');
    if (networkSecurityCta) {
        const openNetworkDashboard = (event) => {
            event.preventDefault();
            event.stopPropagation();
            openDashboard(project);
        };
        networkSecurityCta.addEventListener('click', openNetworkDashboard);
        networkSecurityCta.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                openNetworkDashboard(event);
            }
        });
    }
    
    return card;
}

function buildProjectPreviewModel(project) {
    if (project.isIdentityCard) return buildIdentityPreviewModel(project);
    if (project.isDevicesCard) return buildDevicesPreviewModel(project);
    if (project.isEmailSecurityCard) return buildEmailPreviewModel(project);
    if (project.isApplicationsCard) return buildApplicationsPreviewModel(project);
    if (project.isBackupRecoveryCard) return buildBackupPreviewModel(project);

    return {
        topMetrics: [
            { label: 'Critical Risks', value: project.risks.critical, icon: 'fas fa-exclamation-circle', tone: 'critical' },
            { label: 'Security Score', value: `${project.securityScore}%`, icon: 'fas fa-shield-alt', tone: 'success' },
            { label: 'System Uptime', value: `${project.uptime}%`, icon: 'fas fa-server', tone: 'info' }
        ],
        riskBreakdown: [
            { label: 'High', value: project.risks.high, tone: 'critical' },
            { label: 'Medium', value: project.risks.medium, tone: 'high' },
            { label: 'Safe', value: Math.max(0, (project.securityScore || 0) - project.risks.high - project.risks.medium), tone: 'medium' }
        ],
        keyInsight: 'Security summary synced just now',
        miniFeed: []
    };
}

function formatIdentityPreviewSignIn(user) {
    const time = getIdentityLastSignInTime(user);
    const freshness = time ? getTimeAgoString(new Date(time)) : 'No live sign-in time';
    const location = user?.lastSignIn?.location || 'Unknown location';
    const status = user?.lastSignIn?.status && !/success/i.test(user.lastSignIn.status) ? ` (${user.lastSignIn.status})` : '';
    return `${user.displayName || 'User'} signed in ${freshness} from ${location}${status}`;
}

function buildIdentityPreviewModel() {
    const users = (Array.isArray(microsoftUsersData) ? microsoftUsersData : []).map(normalizeSunbirdIdentityUser);
    const adminSet = new Set(Object.keys(userRolesMap || {}));

    users.forEach(user => {
        if ((user.roles || []).length > 0) adminSet.add(user.id);
    });

    const adminCount = adminSet.size;
    const usersWithoutMfa = users.filter(user => !user.mfaEnabled).length;
    const inactiveUsers = users.filter(user => getIdentityDaysSinceSignIn(user) > 30).length;
    const highRiskUsers = users.filter(user => String(user.riskLevel || '').toUpperCase() === 'HIGH').length;
    const adminWithoutMfa = users.filter(user => adminSet.has(user.id) && !user.mfaEnabled).length;
    const mediumRiskUsers = users.filter(user => String(user.riskLevel || '').toUpperCase() === 'MEDIUM').length + Math.max(0, inactiveUsers - highRiskUsers);
    const safeUsers = Math.max(0, users.length - highRiskUsers - mediumRiskUsers);

    const recentSignIns = users
        .filter(user => getIdentityLastSignInTime(user) > 0)
        .sort((a, b) => getIdentityLastSignInTime(b) - getIdentityLastSignInTime(a))
        .slice(0, 3)
        .map(user => ({
            icon: 'fas fa-sign-in-alt',
            text: formatIdentityPreviewSignIn(user)
        }));

    const keyInsight = recentSignIns.length > 0
        ? 'Live latest sign-ins'
        : adminWithoutMfa > 0
        ? `${adminWithoutMfa} admins do not have MFA enabled`
        : inactiveUsers > 0
            ? `${inactiveUsers} users have not signed in within 30 days`
            : 'Identity posture is stable across active users';

    return {
        topMetrics: [
            { label: 'High Risk Users', value: highRiskUsers, icon: 'fas fa-user-shield', tone: 'critical' },
            { label: 'Users Without MFA', value: usersWithoutMfa, icon: 'fas fa-key', tone: 'warning' },
            { label: 'Privileged Accounts', value: adminCount, icon: 'fas fa-crown', tone: 'info' },
            { label: 'Inactive (30+ days)', value: inactiveUsers, icon: 'fas fa-user-clock', tone: 'warning' }
        ],
        riskBreakdown: [
            { label: 'High', value: highRiskUsers + adminWithoutMfa, tone: 'critical' },
            { label: 'Medium', value: mediumRiskUsers, tone: 'high' },
            { label: 'Safe', value: safeUsers, tone: 'medium' }
        ],
        keyInsight,
        miniFeed: recentSignIns
    };
}

function buildDevicesPreviewModel() {
    const data = normalizeSunbirdDevicesData(latestDevicesCardData || {});
    const summary = data.summary || {};
    const devices = Array.isArray(data.devices) ? data.devices : [];
    const metrics = data.metrics || {};
    const totalDevices = summary.totalDevices ?? getSunbirdMetricNumber(metrics, ['TotalDevices', 'totalDevices'], devices.length);
    const compliantDevices = summary.compliantDevices ?? devices.filter(d => normalizeSunbirdDeviceCompliance(d) === 'compliant').length;
    const graceDevices = devices.filter(d => String(d.complianceState || '').toLowerCase() === 'ingraceperiod').length;
    const encryptedDevices = summary.encryptedDevices ?? devices.filter(d => d.isEncrypted).length;
    const nonCompliant = summary.nonCompliantDevices ?? getSunbirdMetricNumber(metrics, ['NonCompliant', 'nonCompliant'], devices.filter(d => normalizeSunbirdDeviceCompliance(d) === 'noncompliant').length);
    const notEncrypted = Math.max(0, totalDevices - encryptedDevices);
    const staleDevices = data.activityBreakdown?.stale7days ?? summary.staleDevices ?? 0;
    const highRisk = summary.highRiskDevices ?? devices.filter(d => getSunbirdDeviceRiskLevel(d) === 'high').length;
    const mediumRisk = devices.length ? devices.filter(d => getSunbirdDeviceRiskLevel(d) === 'medium').length : graceDevices + staleDevices;
    const healthy = compliantDevices;

    const keyInsight =
        notEncrypted > 0
            ? `${notEncrypted} devices are not encrypted`
            : graceDevices > 0
            ? `${graceDevices} devices are in grace period`
            : staleDevices > 0
            ? `${staleDevices} devices have stale sync status`
            : 'Device security posture is healthy';
    const feed = (data.alerts || []).slice(0, 3).map(alert => ({
        icon: 'fas fa-laptop-medical',
        text: alert.title || alert.message || 'Device compliance updated'
    }));

    return {
        topMetrics: [
            { label: 'Total Devices', value: totalDevices, icon: 'fas fa-desktop', tone: 'info' },
            { label: 'Compliant', value: compliantDevices, icon: 'fas fa-check-circle', tone: 'success' },
            { label: 'Grace Period', value: graceDevices, icon: 'fas fa-hourglass-half', tone: 'warning' },
            { label: 'Non-Compliant', value: nonCompliant, icon: 'fas fa-times-circle', tone: 'critical' }
        ],
        riskBreakdown: [
            { label: 'High', value: highRisk, tone: 'critical' },
            { label: 'Medium', value: mediumRisk, tone: 'high' },
            { label: 'Healthy', value: healthy, tone: 'medium' }
        ],
        keyInsight,
        miniFeed: feed
    };
}

function buildEmailPreviewModel() {
    const data = normalizeSunbirdEmailData(latestEmailCardData || {});
    const model = buildSunbirdEmailModel(data);
    const summary = model.summary || {};
    const mailSummary = summary.mailActivity || {};
    const phishing = model.evidence.phishingAlerts.length;
    const malware = model.evidence.malwareAlerts.length;
    const spam = model.evidence.spamAlerts.length;
    const activeThreats = summary.activeThreats || 0;
    const highSeverity = summary.highSeverityAlerts || 0;
    const targetedUsers = summary.affectedUsersCount || 0;
    const openIncidents = summary.activeIncidents || 0;
    const keyInsight = targetedUsers > 0
        ? `${targetedUsers} users targeted by email threats today`
        : highSeverity > 0
            ? 'High severity malware or phishing alert detected'
            : mailSummary.activeMailboxes
                ? `${mailSummary.activeMailboxes} active mailboxes with ${mailSummary.totalMailActivity || 0} mail activity events`
                : 'Email threat activity is currently controlled';
    const feed = (model.alerts || []).slice(0, 3).map(alert => ({
        icon: 'fas fa-bell',
        text: `${alert.title || alert.description || 'New email threat signal observed'}${alert.created ? ` (${formatSunbirdDateTime(alert.created)})` : ''}`
    }));
    if (!feed.length) {
        model.evidence.mailActivityUsers.slice(0, 3).forEach(user => {
            feed.push({
                icon: 'fas fa-envelope-open-text',
                text: `${user.displayName || user.userPrincipalName}: ${user.sendCount || 0} sent, ${user.receiveCount || 0} received`
            });
        });
    }

    return {
        topMetrics: [
            { label: 'Active Threats', value: activeThreats, icon: 'fas fa-radiation', tone: 'critical' },
            { label: 'High Severity Alerts', value: highSeverity, icon: 'fas fa-triangle-exclamation', tone: 'critical' },
            { label: 'Users Targeted', value: targetedUsers, icon: 'fas fa-user-shield', tone: 'warning' },
            { label: 'Open Incidents', value: openIncidents, icon: 'fas fa-bug', tone: 'warning' }
        ],
        riskBreakdown: [
            { label: 'Phishing', value: phishing, tone: 'critical' },
            { label: 'Malware', value: malware, tone: 'high' },
            { label: 'Mail Events', value: mailSummary.totalMailActivity || spam, tone: 'medium' }
        ],
        keyInsight,
        miniFeed: feed
    };
}

function buildBackupPreviewModel() {
    const data = normalizeSunbirdBackupData(cachedSunbirdBackupData || {});
    const model = buildSunbirdBackupModel(data);
    const summary = model.summary || {};
    const topRows = model.rows.slice().sort((a, b) => b.storageGB - a.storageGB).slice(0, 3);
    const keyInsight = model.evidence.inactiveRows.length
        ? `${model.evidence.inactiveRows.length} inactive or stale owners hold recoverable data`
        : model.summary.totalStorageGB
            ? `${model.summary.totalStorageGB} GB represented across Microsoft 365 reports`
            : 'Backup and recovery evidence is awaiting cached Graph report data';
    return {
        topMetrics: [
            { label: 'Total Storage', value: `${summary.totalStorageGB || 0} GB`, icon: 'fas fa-database', tone: 'info' },
            { label: 'OneDrive', value: `${summary.oneDriveStorageGB || 0} GB`, icon: 'fas fa-cloud', tone: 'info' },
            { label: 'SharePoint', value: `${summary.sharePointStorageGB || 0} GB`, icon: 'fas fa-sitemap', tone: 'warning' },
            { label: 'Exchange', value: `${summary.exchangeStorageGB || 0} GB`, icon: 'fas fa-envelope', tone: 'success' }
        ],
        riskBreakdown: [
            { label: 'High', value: model.evidence.staleRows.length, tone: 'critical' },
            { label: 'Medium', value: model.evidence.highStorageRows.length, tone: 'high' },
            { label: 'Coverage', value: `${model.scores.backupCoverageScore}%`, tone: 'medium' }
        ],
        keyInsight,
        miniFeed: topRows.map(row => ({
            icon: row.service === 'SharePoint' ? 'fas fa-sitemap' : row.service === 'Exchange' ? 'fas fa-envelope' : 'fas fa-cloud',
            text: `${row.name}: ${row.storageGB} GB (${row.service})`
        }))
    };
}

function buildApplicationsPreviewModel() {
    const apps = Array.isArray(applicationsData) ? applicationsData : [];
    const total = apps.length;
    const external = apps.filter(app => app.isExternal).length;
    const highRisk = apps.filter(app => calculateAppRisk(app).level === 'high').length;
    const highAccess = apps.filter(app => (app.userCount || 0) >= 20).length;
    const highBucket = apps.filter(app => app.isExternal && ((app.scopeCount || 0) + (app.roleCount || 0) > 10)).length;
    const mediumBucket = apps.filter(app => (app.userCount || 0) > 10 && (app.userCount || 0) < 20).length;
    const safeBucket = Math.max(0, total - highBucket - mediumBucket);
    const topExternal = apps.filter(app => app.isExternal).sort((a, b) => (b.userCount || 0) - (a.userCount || 0))[0];
    const keyInsight = topExternal
        ? `External app has access to ${topExternal.userCount || 0} users`
        : highRisk > 0
            ? 'App with excessive permissions detected'
            : 'Application access posture is stable';
    const feed = apps
        .sort((a, b) => (b.userCount || 0) - (a.userCount || 0))
        .slice(0, 3)
        .map(app => ({
            icon: 'fas fa-cube',
            text: `${app.displayName || app.name || 'Application'} activity at ${app.userCount || 0} users`
        }));

    return {
        topMetrics: [
            { label: 'Total Applications', value: total, icon: 'fas fa-cubes', tone: 'info' },
            { label: 'External Applications', value: external, icon: 'fas fa-globe', tone: 'warning' },
            { label: 'High Risk Applications', value: highRisk, icon: 'fas fa-triangle-exclamation', tone: 'critical' },
            { label: 'Apps High Access', value: highAccess, icon: 'fas fa-users', tone: 'warning' }
        ],
        riskBreakdown: [
            { label: 'High', value: highBucket, tone: 'critical' },
            { label: 'Medium', value: mediumBucket, tone: 'high' },
            { label: 'Safe', value: safeBucket, tone: 'medium' }
        ],
        keyInsight,
        miniFeed: feed
    };
}

// ============================================
//  Identity Protection DATA API
// ============================================
// Fetches detailed Microsoft user and role data
// for the  Identity Protection dashboard tab

// Fetch  Identity Protection data from API
async function fetchIdentityData(project) {
    try {
        console.log('[Identity] Fetching cached identity metrics...');
        const authToken = localStorage.getItem('authToken');
        
        const response = await fetch('/api/db/identity-metrics', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (!response.ok || !data.success) {
            throw new Error(data.message || 'Failed to fetch users');
        }
        
        const metrics = data.metrics || {};
        const totalUsers = metrics.TotalUsers || metrics.totalUsers || 0;
        const activeUsers = metrics.ActiveUsers || metrics.activeUsers || 0;
        const adminRoles = metrics.AdminRoles || metrics.adminRoles || 0;
        const securityScore = metrics.SecurityScore || metrics.securityScore || 0;

        microsoftUsersData = microsoftUsersData || [];
        project.cardMetrics = [
            { label: "Total Users", value: `: ${totalUsers}`, icon: "fas fa-users" },
            { label: "Active (24h)", value: `: ${activeUsers}`, icon: "fas fa-user-check" },
            { label: "Admin Roles", value: `: ${adminRoles}`, icon: "fas fa-crown" },
            { label: "Security Score", value: `: ${securityScore}`, icon: "fas fa-shield-alt" }
        ];
        project.status = 'active';
        project.securityScore = securityScore;
        project.lastUpdate = new Date().toLocaleTimeString();
        project.cardFooter = `Users: ${totalUsers} | Active: ${activeUsers}`;
        saveProjectCardToCache(project);
        displayCurrentProject();
        
    } catch (error) {
        console.error('[Identity] Error:', error);
        if (project) {
            project.status = 'error';
            project.cardFooter = 'Data unavailable';
            displayCurrentProject();
        }
        showNotification('Failed to load  Identity Protection data', false);
    }
}

/* UTILITIES */
function updateCopyrightYear() {
    const copyrightElement = document.getElementById('copyright-year');
    if (copyrightElement) {
        copyrightElement.textContent = new Date().getFullYear();
    }
}

function renderPoweredByBadge(provider) {
    return '';
}

function renderSunbirdFullDashboardButton(target) {
    let icon = 'fa-chart-line';
    if (target === 'security') icon = 'fa-shield-alt';
    if (target === 'backup') icon = 'fa-hdd';
    if (target === 'applications') icon = 'fa-cubes'; // Icon for apps
    
    return `
        <div class="sunbird-dashboard-btn-wrap">
            <button class="sunbird-dashboard-btn" onclick="window.openSunbirdFullDashboard('${target}')">
                <i class="fas ${icon}"></i> View Full Dashboard
            </button>
        </div>
    `;
}

function renderSunbirdPlaceholderView(title, icon, subtitle = 'Coming soon') {
    return `
        <div class="sunbird-panel-view">
            <div class="billing-card-header">
                <i class="fas ${icon}"></i>
                <h3>${title}</h3>
            </div>
            <p class="sunbird-panel-error">${subtitle}</p>
        </div>
    `;
}

window.openSunbirdFullDashboard = function(target) {
    let project = null;
    
    if (target === 'security') {
        project = mockProjects.find(p => p.isSecurityCard);
    } else if (target === 'backup') {
        project = mockProjects.find(p => p.isBackupRecoveryCard);
    } else if (target === 'applications') {
        // Look for the Applications project card to launch its dashboard
        project = mockProjects.find(p => p.isApplicationsCard);
    }

    if (!project) {
        console.warn(`[Sunbird] Full dashboard target not found: ${target}`);
        return;
    }

    openDashboard(project);
};

// ============================================
// BILLING & INVOICE API
// ============================================
// Retrieves billing information, invoices, and payment status
// for the billing dashboard card

/* BILLING & GOVERNANCE CARDS */
function renderBillingStatusCard(message = 'Refreshing billing information...') {
    return `
        <div class="billing-card-header">
            <i class="fas fa-credit-card"></i>
            <h3>Billing Statement</h3>
        </div>
        <div class="governance-content">
            <div class="sunbird-empty-row">${escapeIdentityText(message)}</div>
        </div>
    `;
}

function getBillingCacheKey() {
    try {
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        const scope = String(user.email || sessionStorage.getItem('userEmail') || user.id || 'anonymous').toLowerCase();
        return `${BILLING_CACHE_KEY}:${scope}`;
    } catch (error) {
        return `${BILLING_CACHE_KEY}:anonymous`;
    }
}

async function initializeBillingCard() {
    const billingCard = document.getElementById('billing-card');
    if (!billingCard) return;
    syncNonSunbirdBlurGatedPanels();

    // Prevent async races from overwriting the active Sunbird mini-view.
    // If the user is currently viewing another menu item, don't render billing HTML into the container.
    if (isSunbirdUser() && billingCard.dataset?.sunbirdView && billingCard.dataset.sunbirdView !== 'billing') {
        syncSunbirdLeftMenuHeight();
        return;
    }
    
    const token = localStorage.getItem('authToken');
    const localUser = localStorage.getItem('user');
    
    if (!token) {
        const isSessionLoggedIn = sessionStorage.getItem('isLoggedIn') === 'true' || !!localUser;
        if (isSessionLoggedIn) {
            if (isSunbirdUser() && !isSunbirdBillingViewActive('billing') && billingCard.dataset?.sunbirdView) return;
            billingCard.innerHTML = isSunbirdUser()
                ? renderBillingStatusCard('Refreshing billing information...')
                : '<p style="color: #bdbdbd; text-align: left; padding: 20px;">Loading billing information...</p>';
            cachedSunbirdBillingHtml = billingCard.innerHTML;
            setTimeout(() => {
                if (!localStorage.getItem('authToken')) return;
                initializeBillingCard();
            }, 450);
            return;
        }
        if (billingAuthRetryCount < 6) {
            billingAuthRetryCount += 1;
            billingCard.innerHTML = isSunbirdUser()
                ? renderBillingStatusCard('Preparing billing view...')
                : '<p style="color: #bdbdbd; text-align: left; padding: 20px;">Preparing your billing view...</p>';
            setTimeout(() => initializeBillingCard(), 350);
            return;
        }
        if (isSunbirdUser() && !isSunbirdBillingViewActive('billing') && billingCard.dataset?.sunbirdView) return;
        billingCard.innerHTML = '<p style="color: #bdbdbd; text-align: center; padding: 20px;">Please log in to view billing information.</p>';
        cachedSunbirdBillingHtml = billingCard.innerHTML;
        return;
    }

    billingAuthRetryCount = 0;

    // Stale-while-revalidate render for instant paint.
    try {
        const rawCache = localStorage.getItem(getBillingCacheKey());
        if (rawCache) {
            const parsed = JSON.parse(rawCache);
            if (parsed?.html) {
                billingCard.innerHTML = parsed.html;
                cachedSunbirdBillingHtml = parsed.html;
            }
        }
    } catch (_) {}

    if (!billingCard.innerHTML.trim()) {
        billingCard.innerHTML = renderBillingStatusCard('Refreshing billing information...');
        cachedSunbirdBillingHtml = billingCard.innerHTML;
    }
    
    try {
        const response = await fetch('/api/client/latest-invoice', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (response.status === 401 || response.status === 403) {
            // Token expired or invalid
            clearClientPortalAuthState();
            if (isSunbirdUser() && !isSunbirdBillingViewActive('billing')) return;
            billingCard.innerHTML = '<p style="color: #bdbdbd; text-align: center; padding: 20px;">Session expired. Please log in again.</p>';
            cachedSunbirdBillingHtml = billingCard.innerHTML;
            localStorage.removeItem(getBillingCacheKey());
            return;
        }
        
        if (!response.ok) {
            throw new Error(`Failed to fetch invoice: ${response.status}`);
        }
        
        const invoice = await response.json();
        
        if (!invoice) {
            if (isSunbirdUser() && !isSunbirdBillingViewActive('billing')) return;
            billingCard.innerHTML = `
                <div class="billing-card-header">
                    <i class="fas fa-credit-card"></i>
                    <h3>Billing Statement</h3>
                </div>
                <p style="color: #bdbdbd; text-align: center; padding: 20px;">No active billing</p>
            `;
            cachedSunbirdBillingHtml = billingCard.innerHTML;
            return;
        }
        
        const currency = 'R';
        const totalAmount = parseFloat(invoice.TotalAmount || 0);
        const items = invoice.items || [];
        const status = invoice.Status || 'Pending';
        
        // Format due date
        const dueDate = invoice.DueDate ? new Date(invoice.DueDate) : null;
        const dueDateString = dueDate ? dueDate.toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric' }) : 'N/A';
        
        // Payment status color
        let statusColor = '#ffc107'; // yellow for pending
        if (status.toLowerCase() === 'paid') {
            statusColor = '#28a745'; // green
        } else if (status.toLowerCase() === 'overdue') {
            statusColor = '#dc3545'; // red
        }
        
        // Display all items
        const billingItemsHtml = items.map(item => {
            const itemTotal = parseFloat(item.Total || item.UnitPrice || 0).toFixed(2);
            const serviceCategory = item.ServiceCategory || item.Category || item.Description || 'Service';
            return `
                <div class="billing-item">
                    <span class="billing-item-name">${serviceCategory}</span>
                    <span class="billing-item-cost">${currency}${parseFloat(itemTotal).toLocaleString()}</span>
                </div>
            `;
        }).join('');
        
        if (isSunbirdUser() && !isSunbirdBillingViewActive('billing')) return;
        billingCard.innerHTML = `
            <div class="billing-card-header">
                <i class="fas fa-credit-card"></i>
                <h3>Billing Statement</h3>
            </div>
            <div class="billing-amount">
                <span class="billing-currency">${currency}</span>${totalAmount.toLocaleString()}
            </div>
            <div class="billing-summary">
                <div class="billing-summary-item">
                    <span class="billing-summary-label">Monthly Subscription</span>
                    <span class="billing-summary-value">${currency}${totalAmount.toLocaleString()}</span>
                </div>
                <div class="billing-summary-item">
                    <span class="billing-summary-label">Total Services</span>
                    <span class="billing-summary-value">${items.length}</span>
                </div>
                <div class="billing-summary-item">
                    <span class="billing-summary-label">Payment Status</span>
                    <span class="billing-summary-value" style="color: ${statusColor}; text-transform: capitalize;">${status}</span>
                </div>
                <div class="billing-summary-item">
                    <span class="billing-summary-label">Due Date</span>
                    <span class="billing-summary-value" style="color: var(--primary);">${dueDateString}</span>
                </div>
            </div>
            <div class="billing-items">
                ${billingItemsHtml}
            </div>
            <div class="billing-warning">
                <div class="warning-icon">
                    <i class="fas fa-exclamation-circle"></i>
                </div>
                <div class="warning-text">
                    <p><strong>Friendly Reminder:</strong></p>
                    <p>A quick reminder to complete your payment by the due date.</p>
                </div>
            </div>
        `;
        cachedSunbirdBillingHtml = billingCard.innerHTML;
        localStorage.setItem(getBillingCacheKey(), JSON.stringify({
            html: billingCard.innerHTML,
            cachedAt: Date.now()
        }));
    } catch (error) {
        console.error('Error loading billing card:', error);
        if (isSunbirdUser() && !isSunbirdBillingViewActive('billing')) return;
        if (!billingCard.innerHTML || billingCard.innerHTML.trim().length === 0) {
            billingCard.innerHTML = `
                <div class="billing-card-header">
                    <i class="fas fa-credit-card"></i>
                    <h3>Billing Statement</h3>
                </div>
                <p style="color: #bdbdbd; text-align: center; padding: 20px;">Error loading billing information</p>
            `;
            cachedSunbirdBillingHtml = billingCard.innerHTML;
        }
    } finally {
        ensureSunbirdBillingCardDimensions();
        // If this renderer completed after the user navigated away, don't force-switch tabs.
        if (isSunbirdUser() && isSunbirdBillingViewActive('billing') === false) {
            syncSunbirdLeftMenuHeight();
            return;
        }
        // Keep Sunbird menu aligned to the rendered billing card height.
        syncSunbirdLeftMenuHeight();
    }
}

// Make toggleBillingItems globally accessible
window.toggleBillingItems = function() {
    const moreItems = document.getElementById('billing-items-more');
    const seeMoreBtn = document.getElementById('billing-see-more-btn');
    
    if (moreItems && seeMoreBtn) {
        const isHidden = moreItems.style.display === 'none';
        moreItems.style.display = isHidden ? 'block' : 'none';
        const icon = seeMoreBtn.querySelector('i');
        const text = seeMoreBtn.querySelector('span');
        
        if (isHidden) {
            text.textContent = 'See Less';
            icon.classList.remove('fa-chevron-down');
            icon.classList.add('fa-chevron-up');
        } else {
            text.textContent = 'See More';
            icon.classList.remove('fa-chevron-up');
            icon.classList.add('fa-chevron-down');
        }
    }
};

// Switch billing menu for Sunbird users
window.switchBillingMenu = async function(menuItem) {
    sunbirdBillingMenuSelection = menuItem;

    const leftMenu = document.querySelector('.sunbird-left-menu');
    if (leftMenu) {
        leftMenu.classList.remove('is-open');
        leftMenu.querySelector('.sunbird-menu-current')?.setAttribute('aria-expanded', 'false');
    }

    const menuItems = document.querySelectorAll('.sunbird-menu-item');
    menuItems.forEach(item => item.classList.remove('active'));
    
    const activeItem = document.querySelector(`.sunbird-menu-item[data-menu="${menuItem}"]`);
    if (activeItem) {
        activeItem.classList.add('active');
    }

    updateSunbirdMobileMenuCurrent(menuItem);

    const billingCard = document.getElementById('billing-card');
    if (!billingCard) return;
    billingCard.dataset.sunbirdView = menuItem;

    const placeholderViews = {
        architecture: { title: 'Architecture', icon: 'fa-sitemap' },
        sla: { title: 'SLA', icon: 'fa-handshake' }
    };

    if (placeholderViews[menuItem]) {
        billingCard.innerHTML = renderSunbirdPlaceholderView(
            placeholderViews[menuItem].title,
            placeholderViews[menuItem].icon
        );
        ensureSunbirdBillingCardDimensions();
        syncSunbirdLeftMenuHeight();
        return;
    }

    if (menuItem === 'billing') {
        // Always render billing view when selected so click visibly affects the container.
        await initializeBillingCard();
        return;
    }

    if (menuItem === 'operations') {
        await renderSunbirdOperationsView();
        return;
    }

    if (menuItem === 'security') {
        await renderSunbirdSecurityAlertsView(false);
        return;
    }

    if (menuItem === 'backup') {
        await renderSunbirdBackupRecoveryView(false);
        return;
    }

    if (menuItem === 'reports') {
        await renderSunbirdReportsView(false);
        return;
    }

    if (menuItem === 'risks') {
        await renderSunbirdRisksView(false);
    }

    // NEW: Route for Applications
    if (menuItem === 'applications') {
        await renderSunbirdApplicationsView(false);
        return;
    }
};

function ensureSunbirdBillingCardDimensions() {
    if (!isSunbirdUser()) return;
    const billingCard = document.getElementById('billing-card');
    const stackedCards = document.querySelector('.dashboard-card-vertical-container');
    const governanceCard = document.getElementById('governance-card');
    const supportCard = document.getElementById('support-card');
    if (!billingCard) return;

    const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
    const clearLockedHeights = () => {
        billingCard.style.height = '';
        if (stackedCards) {
            stackedCards.style.height = '';
            stackedCards.style.gridTemplateRows = '';
        }
        if (governanceCard) governanceCard.style.height = '';
        if (supportCard) supportCard.style.height = '';
    };

    clearLockedHeights();

    if (window.matchMedia('(max-width: 768px)').matches) {
        return;
    }

    const isCompactLaptop = viewportWidth <= 1680;
    const isSmallLaptop = viewportWidth <= 1440;
    const stackGap = isCompactLaptop ? 10 : 11.2;
    const minimumRightCardHeight = isSmallLaptop ? 220 : (isCompactLaptop ? 235 : 260);
    const minimumStackHeight = (minimumRightCardHeight * 2) + stackGap;
    const minimumBillingHeight = isSmallLaptop ? 330 : 360;
    const targetHeight = Math.max(minimumBillingHeight, minimumStackHeight);
    const availableStackHeight = targetHeight - stackGap;
    const governanceHeight = Math.max(minimumRightCardHeight, Math.floor(availableStackHeight / 2));
    const supportHeight = Math.max(minimumRightCardHeight, availableStackHeight - governanceHeight);

    billingCard.style.height = `${targetHeight}px`;

    if (stackedCards && governanceCard && supportCard) {
        stackedCards.style.height = `${targetHeight}px`;
        stackedCards.style.gridTemplateRows = `${governanceHeight}px ${stackGap}px ${supportHeight}px`;
        governanceCard.style.height = `${governanceHeight}px`;
        supportCard.style.height = `${supportHeight}px`;
    }
}

async function fetchSunbirdSecurityEventsData() {
    const token = localStorage.getItem('authToken');
    if (!token) throw new Error('Authentication required');

    const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };
    for (const endpoint of ['/api/db/security-events', '/api/security-events']) {
        const response = await fetch(endpoint, { headers });
        const data = await response.json();
        if (response.ok && data.success) return augmentSunbirdSecurityDataWithCloudflare(data);
    }
    throw new Error('Security events data unavailable');
}

async function fetchSunbirdBackupRecoveryData() {
    const token = localStorage.getItem('authToken');
    if (!token) throw new Error('Authentication required');

    const response = await fetch('/api/db/backup-recovery', {
        cache: 'no-store',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    });

    if (!response.ok) {
        throw new Error(`Failed to fetch backup data (${response.status})`);
    }

    const data = await response.json();
    if (!data.success) {
        throw new Error(data.message || 'Invalid backup response');
    }
    return data;
}

function getSunbirdReportHeaders() {
    const token = localStorage.getItem('authToken');
    if (!token) throw new Error('Authentication required');
    return {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };
}

async function fetchSunbirdReportsData(range = sunbirdReportsRange, forceRefresh = false) {
    if (!forceRefresh && cachedSunbirdReportsData?.selectedRange === range) {
        console.log(`[Reports] Using cached ${range} report data.`);
        return cachedSunbirdReportsData;
    }
    if (sunbirdReportsRequests.has(range)) {
        console.log(`[Reports] Reusing ${range} report request already in progress.`);
        return sunbirdReportsRequests.get(range);
    }

    const request = (async () => {
        console.log(`[Reports] Loading report history, daily snapshots, and audit logs for ${range}.`);
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 90000);
        let response;
        let responseBody;
        try {
            response = await fetch(`/api/sunbird/reports?range=${encodeURIComponent(range)}&limit=30`, {
                cache: 'no-store',
                headers: getSunbirdReportHeaders(),
                signal: controller.signal
            });
            responseBody = await response.text();
        } catch (error) {
            if (error.name === 'AbortError') {
                throw new Error('Report summary is taking too long. Please try again; the dashboard has not been left running.');
            }
            throw error;
        } finally {
            clearTimeout(timeout);
        }
        let data;
        try {
            data = responseBody ? JSON.parse(responseBody) : {};
        } catch (_) {
            throw new Error(response.ok
                ? 'Reports returned an invalid response. Please refresh and try again.'
                : `Reports are unavailable (${response.status}). Please try again shortly.`);
        }
        if (!response.ok || !data.success) {
            console.error('[Reports] Load failed:', response.status, data);
            throw new Error(data.message || `Reports are unavailable (${response.status})`);
        }
        console.log('[Reports] Loaded:', {
            reports: data.reports?.length || 0,
            dailySnapshots: (data.reports || []).filter(report => report.type === 'daily').length,
            auditLogs: data.logs?.length || 0,
            events: data.overview?.events?.length || 0
        });
        cachedSunbirdReportsData = { ...data, selectedRange: range };
        return cachedSunbirdReportsData;
    })();
    sunbirdReportsRequests.set(range, request);
    try {
        return await request;
    } finally {
        if (sunbirdReportsRequests.get(range) === request) {
            sunbirdReportsRequests.delete(range);
        }
    }
}

function formatSunbirdReportDate(value, includeTime = false) {
    if (!value) return 'Not yet';
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return 'Not yet';
    return new Intl.DateTimeFormat('en-ZA', {
        dateStyle: 'medium',
        ...(includeTime ? { timeStyle: 'short' } : {})
    }).format(date);
}

function getSunbirdReportScoreTone(score) {
    const value = Number(score || 0);
    return value >= 85 ? 'good' : value >= 70 ? 'warn' : 'bad';
}

function getSunbirdReportItemTitle(item) {
    return typeof item === 'string' ? item : item?.title || 'Report insight';
}

function getSunbirdReportItemDetail(item) {
    return typeof item === 'string' ? '' : item?.detail || '';
}

function isSunbirdTechnicalNoiseText(value) {
    const text = String(value || '').toLowerCase();
    if (!text) return false;
    return [
        'failed_source_mismatch',
        'failed_invalid_json',
        'failed_rate_limited',
        'failed_terminal',
        'json parse failed',
        'invalid_json',
        'azure response',
        'sqlstate',
        'econnreset',
        'connection_reset',
        'timeout',
        'stack trace',
        'internalSourcePath'.toLowerCase(),
        'debugsourcepath',
        'batch accounting failed',
        'rawresponsepreview',
        'token threshold'
    ].some(marker => text.includes(marker));
}

function filterSunbirdInsightItems(items = []) {
    return (Array.isArray(items) ? items : [])
        .filter(item => {
            const title = getSunbirdReportItemTitle(item);
            const detail = getSunbirdReportItemDetail(item);
            const rawStatus = typeof item === 'object' ? String(item?.status || item?.state || '') : '';
            if (isSunbirdTechnicalNoiseText(`${title} ${detail}`)) return false;
            if (/^(failed_source_mismatch|failed_invalid_json|failed_terminal|failed_rate_limited)$/i.test(rawStatus)) return false;
            return true;
        });
}

function formatSunbirdExecutiveSummaryHtml(summaryText = '') {
    const text = String(summaryText || '').replace(/\r\n/g, '\n').trim();
    if (!text) {
        return '<p>No executive summary is available.</p>';
    }
    const markers = [
        { key: 'What changed since the last report:', label: 'What changed since the last report' },
        { key: 'Historical trend analysis:', label: 'Historical trend analysis' },
        { key: 'Control gaps and remediation progress:', label: 'Control gaps and remediation progress' },
        { key: 'Confidence:', label: 'Confidence' }
    ];
    const positions = markers
        .map(marker => ({ ...marker, index: text.indexOf(marker.key) }))
        .filter(marker => marker.index >= 0)
        .sort((left, right) => left.index - right.index);

    if (!positions.length) {
        return text
            .split(/\n{2,}/)
            .map(block => block.trim())
            .filter(Boolean)
            .map(block => `<p>${escapeIdentityText(block).replace(/\n/g, '<br>')}</p>`)
            .join('');
    }

    const intro = text.slice(0, positions[0].index).trim();
    const sections = positions.map((marker, index) => {
        const start = marker.index + marker.key.length;
        const end = index + 1 < positions.length ? positions[index + 1].index : text.length;
        const value = text.slice(start, end).trim();
        return { label: marker.label, value };
    }).filter(section => section.value && !isSunbirdTechnicalNoiseText(section.value));

    const introHtml = intro ? `<p>${escapeIdentityText(intro).replace(/\n/g, '<br>')}</p>` : '';
    const sectionHtml = sections.map(section => `
        <article class="sunbird-report-exec-section">
            <strong>${escapeIdentityText(section.label)}</strong>
            <p>${escapeIdentityText(section.value).replace(/\n/g, '<br>')}</p>
        </article>
    `).join('');

    return `<div class="sunbird-report-exec-summary">${introHtml}${sectionHtml}</div>`;
}

function renderSunbirdReportVisualPanel(data = {}, buckets = getSunbirdReportEvidenceBuckets(data)) {
    const summary = data.overview?.summary || {};
    const reports = Array.isArray(data.reports) ? data.reports : [];
    const latestDomains = Array.isArray(data.latestReport?.domainBreakdown) ? data.latestReport.domainBreakdown : [];
    const domainScores = data.overview?.domainScores || {};
    const sourceDomainScores = Object.keys(domainScores).length
        ? domainScores
        : Object.fromEntries(latestDomains.map(domain => [domain.domainKey || domain.domainName, domain.healthScore]));
    const domainRows = Object.entries(sourceDomainScores)
        .filter(([, value]) => value != null && Number.isFinite(Number(value)))
        .map(([key, value]) => ({
            key,
            score: Math.max(0, Math.min(100, Number(value))),
            label: key.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase())
        }))
        .sort((left, right) => right.score - left.score);

    const rawMetricRows = latestDomains
        .flatMap(domain => Object.entries(domain.rawMetrics || {}).map(([metric, value]) => ({
            domain: getSunbirdReportDomainName(domain),
            metric: metric.replace(/([A-Z])/g, ' $1').replace(/_/g, ' ').trim(),
            value: Math.max(0, Number(value || 0))
        })))
        .filter(metric => Number.isFinite(metric.value) && metric.value >= 0)
        .sort((left, right) => right.value - left.value);
    const rawMetricMax = Math.max(1, ...rawMetricRows.map(metric => metric.value));

    const failures = Math.max(0, Number(summary.failures || buckets.problems.length || 0));
    const successes = Math.max(0, Number(summary.successes || buckets.successes.length || 0));
    const actions = Math.max(0, Number(buckets.recommendations.length || 0));
    const totalPie = Math.max(1, failures + successes + actions);
    const failuresPct = Math.round((failures / totalPie) * 100);
    const successesPct = Math.round((successes / totalPie) * 100);
    const actionsPct = Math.max(0, 100 - failuresPct - successesPct);

    const currentHealthScore = Number(summary.healthScore ?? data.latestReport?.summary?.healthScore ?? data.latestReport?.healthScore);
    const historicalTrendReports = reports
        .slice()
        .sort((left, right) => new Date(left.periodEnd || left.createdAt || 0) - new Date(right.periodEnd || right.createdAt || 0))
        .slice(-8);
    // A live report can be available before it has been saved into report history.
    // Show that current score as the first chart point instead of implying no data.
    const trendReports = historicalTrendReports.length
        ? historicalTrendReports
        : Number.isFinite(currentHealthScore)
            ? [{ healthScore: currentHealthScore, createdAt: data.latestReport?.createdAt || new Date().toISOString(), isCurrentSnapshot: true }]
            : [];
    const trendPoints = trendReports.map((report, index, all) => {
        const score = Math.max(0, Math.min(100, Number(report.healthScore || report.summary?.healthScore || 0)));
        const x = all.length === 1 ? 50 : (index / (all.length - 1)) * 92 + 4;
        const y = 100 - score;
        return {
            x: Number(x.toFixed(2)),
            y: Number(y.toFixed(2)),
            score,
            date: report.periodEnd || report.createdAt,
            isCurrentSnapshot: Boolean(report.isCurrentSnapshot)
        };
    });

    if (!domainRows.length && !trendPoints.length) return '';

    const trendPath = trendPoints.map(point => `${point.x},${point.y}`).join(' ');
    const latestTrend = trendPoints[trendPoints.length - 1];

    return `
        <section class="sunbird-report-visual-panel">
            <div class="sunbird-report-card-title">
                <span><i class="fas fa-chart-pie"></i> Live metrics and charts</span>
                <small>Real-time evidence only</small>
            </div>
            <div class="sunbird-report-visual-grid">
                <article class="sunbird-report-pie-card">
                    <div class="sunbird-report-pie" style="--fail:${failuresPct};--success:${successesPct};--actions:${actionsPct};"></div>
                    <div class="sunbird-report-pie-legend">
                        <span><i class="tone-fail"></i> Failures ${failures}</span>
                        <span><i class="tone-success"></i> Successes ${successes}</span>
                        <span><i class="tone-action"></i> Actions ${actions}</span>
                    </div>
                </article>
                <article class="sunbird-report-trend-card">
                    <svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-label="Health trend">
                        <polyline points="${escapeIdentityText(trendPath)}" />
                        ${trendPoints.map(point => `<circle cx="${point.x}" cy="${point.y}" r="2.4"><title>${escapeIdentityText(formatSunbirdReportDate(point.date))}: ${point.score}%</title></circle>`).join('')}
                    </svg>
                    <div class="sunbird-report-trend-meta">
                        <span>${latestTrend?.isCurrentSnapshot ? 'Health trend (current snapshot)' : `Health trend (${trendPoints.length || 0} report${trendPoints.length === 1 ? '' : 's'})`}</span>
                        <strong>${latestTrend ? `${latestTrend.score}%` : 'Awaiting health score'}</strong>
                    </div>
                </article>
                <article class="sunbird-report-domain-bars">
                    ${domainRows.length ? domainRows.map(domain => `
                        <div class="sunbird-report-domain-bar-row">
                            <span>${escapeIdentityText(domain.label)}</span>
                            <div><i style="width:${domain.score}%"></i></div>
                            <strong>${domain.score}%</strong>
                        </div>
                    `).join('') : '<span class="sunbird-report-chart-empty">No current domain health scores were emitted.</span>'}
                </article>
                <article class="sunbird-report-raw-metrics-card">
                    <div class="sunbird-report-raw-metrics-head"><strong>Raw dashboard metrics</strong><span>Latest collected evidence</span></div>
                    <div class="sunbird-report-raw-metrics-list">
                        ${rawMetricRows.length ? rawMetricRows.map(metric => `
                            <div class="sunbird-report-raw-metric-row">
                                <span title="${escapeIdentityText(metric.domain)}">${escapeIdentityText(metric.metric)}</span>
                                <div><i style="width:${Math.max(2, (metric.value / rawMetricMax) * 100)}%"></i></div>
                                <strong>${metric.value.toLocaleString()}</strong>
                            </div>
                        `).join('') : '<span class="sunbird-report-chart-empty">No raw metric categories were stored in this report.</span>'}
                    </div>
                </article>
            </div>
        </section>
    `;
}

function getSunbirdReportEvidenceBuckets(data = cachedSunbirdReportsData || {}) {
    const overview = data.overview || {};
    const analysis = overview.analysis || {};
    const events = Array.isArray(overview.events) ? overview.events : [];
    const cloudflareSignals = buildCloudflareSecuritySignals();
    const problems = Array.isArray(analysis.failures) && analysis.failures.length
        ? analysis.failures
        : Array.isArray(overview.failures) && overview.failures.length
            ? overview.failures
            : events.filter(event => ['critical', 'high'].includes(String(event.severity || '').toLowerCase()));
    return {
        problems: filterSunbirdInsightItems([...cloudflareSignals.reportProblems, ...problems]),
        successes: filterSunbirdInsightItems(Array.isArray(analysis.successes) && analysis.successes.length ? analysis.successes : (overview.successes || [])),
        recommendations: filterSunbirdInsightItems([...cloudflareSignals.reportRecommendations, ...(Array.isArray(analysis.recommendations) && analysis.recommendations.length ? analysis.recommendations : (overview.recommendations || []))]),
        events: filterSunbirdInsightItems([...cloudflareSignals.reportEvents, ...events])
    };
}

function getSunbirdReportSummaryValue(report = {}, key) {
    const summary = report.summary || {};
    if (key === 'healthScore') return Number(report.healthScore ?? summary.healthScore ?? 0);
    return Number(summary[key] ?? report[key] ?? 0);
}

function getSunbirdReportDeltaMeta(current, previous, invert = false) {
    const delta = Number(current || 0) - Number(previous || 0);
    if (delta === 0) return { tone: 'neutral', icon: 'fa-equals', label: 'No change' };
    const improved = invert ? delta < 0 : delta > 0;
    return {
        tone: improved ? 'good' : 'bad',
        icon: delta > 0 ? 'fa-arrow-up' : 'fa-arrow-down',
        label: `${delta > 0 ? '+' : ''}${delta}`
    };
}

function getSunbirdReportCurrentMetricMeta(value, metric) {
    const amount = Math.max(0, Number(value || 0));
    if (metric === 'health') {
        return { tone: getSunbirdReportScoreTone(amount), icon: 'fa-shield-heart', label: `${amount}% current health` };
    }
    if (metric === 'risks') {
        return amount
            ? { tone: amount >= 5 ? 'bad' : 'warn', icon: 'fa-triangle-exclamation', label: `${amount} active risk${amount === 1 ? '' : 's'}` }
            : { tone: 'good', icon: 'fa-shield-check', label: 'No active risks' };
    }
    return amount
        ? { tone: 'good', icon: 'fa-circle-check', label: `${amount} validated win${amount === 1 ? '' : 's'}` }
        : { tone: 'neutral', icon: 'fa-circle-info', label: 'No validated wins yet' };
}

function getSunbirdReportResolvedCount(data = {}, buckets = getSunbirdReportEvidenceBuckets(data)) {
    const reports = data.reports || [];
    const previousFailures = getSunbirdReportSummaryValue(reports[1], 'failures');
    const currentFailures = Number(data.overview?.summary?.failures ?? buckets.problems.length ?? 0);
    const resolvedFromTrend = reports[1] ? Math.max(0, previousFailures - currentFailures) : 0;
    const resolvedEvents = buckets.events.filter(event => {
        const status = String(event.status || event.outcome || '').toLowerCase();
        return status.includes('resolved') || status.includes('remediated') || status.includes('closed');
    }).length;
    return Math.max(resolvedFromTrend, resolvedEvents);
}

function getSunbirdReportBusinessImpact(item, key = 'recommendations') {
    const itemMeta = item && typeof item === 'object' ? item : {};
    const text = `${getSunbirdReportItemTitle(item)} ${getSunbirdReportItemDetail(item)} ${itemMeta.source || itemMeta.category || itemMeta.severity || ''}`.toLowerCase();
    if (key === 'successes') return 'Business value: control is working and reducing operational risk.';
    if (text.includes('cloudflare') || text.includes('gateway') || text.includes('warp') || text.includes('zero trust')) return 'Business impact: improves Zero Trust coverage, traffic inspection, and network access assurance.';
    if (text.includes('backup') || text.includes('retention') || text.includes('restore')) return 'Business impact: protects recovery, continuity, and data-loss exposure.';
    if (text.includes('identity') || text.includes('mfa') || text.includes('sign-in') || text.includes('admin')) return 'Business impact: lowers account takeover and privilege misuse risk.';
    if (text.includes('email') || text.includes('phishing') || text.includes('malware') || text.includes('mailbox')) return 'Business impact: reduces mailbox compromise and client communication risk.';
    if (text.includes('device') || text.includes('compliance') || text.includes('endpoint')) return 'Business impact: improves endpoint trust and audit readiness.';
    if (text.includes('application') || text.includes('app') || text.includes('consent')) return 'Business impact: improves app governance and access visibility.';
    if (key === 'problems') return 'Business impact: unresolved exposure that may affect security posture or compliance confidence.';
    return 'Business impact: improves measurable security posture and executive assurance.';
}

function getSunbirdReportOwnerStatus(item = {}, key = 'recommendations') {
    const itemMeta = item && typeof item === 'object' ? item : {};
    const title = getSunbirdReportItemTitle(item).toLowerCase();
    const priority = String(itemMeta.priority || itemMeta.severity || '').toLowerCase();
    const owner = itemMeta.owner || itemMeta.assignee || itemMeta.assignedTo
        || (title.includes('cloudflare') || title.includes('gateway') || title.includes('warp') ? 'Network security owner'
            : title.includes('backup') || title.includes('restore') ? 'Backup owner'
            : title.includes('email') || title.includes('mailbox') ? 'Messaging admin'
                : title.includes('identity') || title.includes('mfa') || title.includes('sign-in') ? 'Identity admin'
                    : title.includes('app') || title.includes('consent') ? 'App governance'
                        : key === 'problems' ? 'StackOps SOC' : 'StackOps service desk');
    const status = itemMeta.status || itemMeta.state
        || (priority === 'critical' || priority === 'high' ? 'Urgent action'
            : priority === 'low' ? 'Monitor'
                : key === 'successes' ? 'Validated' : 'Planned review');
    return { owner, status };
}

function getSunbirdReportIntelligence(data = {}, buckets = getSunbirdReportEvidenceBuckets(data)) {
    const summary = data.overview?.summary || {};
    const reports = data.reports || [];
    const currentReport = reports[0] || {};
    const previousReport = reports[1];
    const health = Number(summary.healthScore ?? currentReport.healthScore ?? 0);
    const failures = Number(summary.failures ?? getSunbirdReportSummaryValue(currentReport, 'failures') ?? buckets.problems.length);
    const successes = Number(summary.successes ?? getSunbirdReportSummaryValue(currentReport, 'successes') ?? buckets.successes.length);
    const previousHealth = previousReport ? getSunbirdReportSummaryValue(previousReport, 'healthScore') : NaN;
    const previousFailures = previousReport ? getSunbirdReportSummaryValue(previousReport, 'failures') : NaN;
    const previousSuccesses = previousReport ? getSunbirdReportSummaryValue(previousReport, 'successes') : NaN;
    const topSignal = buckets.problems[0] || buckets.recommendations[0] || buckets.successes[0];
    const enterpriseBusinessImpact = String(
        data.overview?.analysis?.businessImpactSummary ||
        data.latestReport?.analysis?.businessImpactSummary ||
        ''
    ).trim();
    return {
        health,
        failures,
        successes,
        hasPreviousReport: Boolean(previousReport),
        healthTrend: previousReport ? getSunbirdReportDeltaMeta(health, previousHealth) : getSunbirdReportCurrentMetricMeta(health, 'health'),
        failureTrend: previousReport ? getSunbirdReportDeltaMeta(failures, previousFailures, true) : getSunbirdReportCurrentMetricMeta(failures, 'risks'),
        successTrend: previousReport ? getSunbirdReportDeltaMeta(successes, previousSuccesses) : getSunbirdReportCurrentMetricMeta(successes, 'successes'),
        resolvedCount: getSunbirdReportResolvedCount(data, buckets),
        topImpact: enterpriseBusinessImpact || (topSignal ? getSunbirdReportBusinessImpact(topSignal, buckets.problems[0] ? 'problems' : 'recommendations') : 'Business impact: this view will become more specific as additional evidence is collected.')
    };
}

function renderSunbirdReportTrendBadge(meta) {
    return `<span class="sunbird-report-trend-badge tone-${meta.tone}"><i class="fas ${meta.icon}"></i>${escapeIdentityText(meta.label)}</span>`;
}

function renderSunbirdReportValueStrip(data = {}, buckets = getSunbirdReportEvidenceBuckets(data)) {
    const intelligence = getSunbirdReportIntelligence(data, buckets);
    const healthLabel = intelligence.hasPreviousReport ? 'Health trend' : 'Security health';
    return `
        <div class="sunbird-report-value-strip">
            <div class="sunbird-report-value-pill">
                <span>${healthLabel}</span>
                <strong>${renderSunbirdReportTrendBadge(intelligence.healthTrend)}</strong>
            </div>
            <div class="sunbird-report-value-pill">
                <span>Risk movement</span>
                <strong>${renderSunbirdReportTrendBadge(intelligence.failureTrend)}</strong>
            </div>
            <div class="sunbird-report-value-pill">
                <span>Resolved</span>
                <strong>${Number(intelligence.resolvedCount || 0)}</strong>
            </div>
        </div>
    `;
}

function renderSunbirdReportValuePanel(data = {}, buckets = getSunbirdReportEvidenceBuckets(data)) {
    const intelligence = getSunbirdReportIntelligence(data, buckets);
    return `
        <section class="sunbird-report-value-panel">
            <div class="sunbird-report-card-title">
                <span><i class="fas fa-chart-bar"></i> Value intelligence</span>
                <small>What changed, what matters, and what is now safer</small>
            </div>
            <div class="sunbird-report-value-grid">
                <article>
                    <span>Health trend</span>
                    <strong>${renderSunbirdReportTrendBadge(intelligence.healthTrend)}</strong>
                    <p>${intelligence.hasPreviousReport ? 'Security health compared with the previous generated report.' : 'Latest reported security health from current evidence.'}</p>
                </article>
                <article>
                    <span>Risk movement</span>
                    <strong>${renderSunbirdReportTrendBadge(intelligence.failureTrend)}</strong>
                    <p>${intelligence.hasPreviousReport ? 'Problem count movement since the last report.' : 'Current evidence requiring attention.'}</p>
                </article>
                <article>
                    <span>Client wins</span>
                    <strong>${renderSunbirdReportTrendBadge(intelligence.successTrend)}</strong>
                    <p>${intelligence.hasPreviousReport ? 'Confirmed successes added to the evidence record.' : 'Validated positive outcomes in current evidence.'}</p>
                </article>
                <article>
                    <span>${intelligence.hasPreviousReport ? 'Resolved since last report' : 'Resolved in current report'}</span>
                    <strong>${Number(intelligence.resolvedCount || 0)}</strong>
                    <p>${intelligence.hasPreviousReport ? 'Issues closed, remediated, or reduced from the previous report.' : 'Issues closed or remediated in the current report.'}</p>
                </article>
            </div>
            <div class="sunbird-report-impact-banner">
                <span>Business impact</span>
                <strong>${escapeIdentityText(intelligence.topImpact)}</strong>
            </div>
        </section>
    `;
}

function getSunbirdReportIdentityFieldValues(data = {}) {
    const source = data.identityDomain?.intelligenceOutput || {};
    const risks = Array.isArray(source.risks) ? source.risks : [];
    const keyFindings = Array.isArray(source.keyFindings) ? source.keyFindings : [];

    const fields = {
        domainExecutiveSummary: String(source.domainExecutiveSummary || ''),
        businessImpact: String(source.businessImpact || ''),
        healthScore: source.healthScore ?? source.scoreSummary?.healthScore ?? null,
        riskScore: source.riskScore ?? source.scoreSummary?.riskScore ?? null,
        findings: Array.isArray(source.findings) ? source.findings : [...risks, ...keyFindings],
        recommendations: Array.isArray(source.recommendations) ? source.recommendations : []
    };
    return fields;
}

function normalizeIdentityRiskDetail(finding = {}) {
    const affected = Array.isArray(finding.affectedEntities) && finding.affectedEntities.length
        ? finding.affectedEntities
        : (Array.isArray(finding.evidenceRows) ? finding.evidenceRows : []);
    const evidence = Array.isArray(finding.evidence) && finding.evidence.length
        ? finding.evidence
        : (Array.isArray(finding.evidenceUsed) ? finding.evidenceUsed : []);
    return {
        title: finding.title || finding.patternFound || '',
        severity: finding.severity || finding.priority || finding.riskLevel || 'Observed',
        impact: finding.impact || finding.businessImpact || finding.whyItMatters || finding.description || finding.detail || '',
        description: finding.description || finding.detail || finding.whatHappened || '',
        whyItMatters: finding.whyItMatters || finding.reasoning || finding.businessImpact || finding.description || finding.detail || '',
        evidenceSummary: finding.evidenceSummary || '',
        action: finding.firstAction || finding.recommendedAction || finding.recommendation || finding.detail || '',
        evidence: evidence.map(entry => ({
            label: entry?.label || entry?.title || entry?.evidenceSource || entry?.sourceMetric || '',
            sourceMetric: entry?.sourceMetric || '',
            evidenceSource: entry?.evidenceSource || entry?.sourceLabel || '',
            entityCount: Number(entry?.entityCount || 0)
        })),
        evidenceRecordCount: Number(finding.evidenceRecordCount || 0),
        evidenceCategory: finding.evidenceCategory || 'Identity evidence',
        affectedEntities: affected.map(entity => {
            const lastSignIn = entity?.lastSignIn && typeof entity.lastSignIn === 'object' ? entity.lastSignIn : {};
            return {
            entityEmail: entity.entityEmail || '',
            userPrincipalName: entity.userPrincipalName || '',
            displayName: entity.displayName || entity.entityName || entity.entityDisplayName || '',
            roles: Array.isArray(entity.roles) ? entity.roles : [],
            mfaEnabled: entity.mfaEnabled ?? null,
            lastSignIn: {
                device: lastSignIn.device || '',
                location: lastSignIn.location || '',
                daysSince: lastSignIn.daysSince ?? '',
                status: lastSignIn.status || '',
                dateTime: lastSignIn.dateTime || ''
            }
            };
        }),
        evidenceRecords: (Array.isArray(finding.evidenceRecords) && finding.evidenceRecords.length
            ? finding.evidenceRecords
            : affected).map(entity => {
                const lastSignIn = entity?.lastSignIn && typeof entity.lastSignIn === 'object' ? entity.lastSignIn : {};
                return {
                    entityEmail: entity?.entityEmail || entity?.mail || '',
                    userPrincipalName: entity?.userPrincipalName || entity?.entityUser || '',
                    displayName: entity?.displayName || entity?.entityName || entity?.entityDisplayName || '',
                    roles: Array.isArray(entity?.roles) ? entity.roles.map(role => typeof role === 'object' ? role?.name || role?.displayName || '' : role).filter(Boolean) : [],
                    mfaEnabled: entity?.mfaEnabled ?? null,
                    riskLevel: entity?.riskLevel || '',
                    lastSignIn: {
                        device: lastSignIn.device || '',
                        location: lastSignIn.location || '',
                        daysSince: lastSignIn.daysSince ?? '',
                        status: lastSignIn.status || ''
                    }
                };
            })
    };
}

function getIdentityRecommendationPoints(action = '') {
    const points = String(action)
        .split(/(?:;|\.(?=\s+[A-Z]))/)
        .map(point => point.trim())
        .filter(Boolean);
    return points.length ? points.slice(0, 4) : ['Review the supporting evidence and assign an owner.'];
}

function renderIdentityEvidenceRecords(finding) {
    const records = finding.evidenceRecords.slice(0, 10);
    const remaining = Math.max(0, Number(finding.evidenceRecordCount || records.length) - records.length);
    if (!records.length) {
        return '<p class="sunbird-report-identity-no-evidence">No readable identity records were included with this Azure finding.</p>';
    }
    return `
        <ul class="sunbird-report-identity-evidence-list">
            ${records.map(record => {
                const identity = record.displayName || record.userPrincipalName || record.entityEmail || 'Identity record';
                const signIn = [record.lastSignIn.location, record.lastSignIn.device, record.lastSignIn.status]
                    .filter(Boolean)
                    .join(' | ');
                const posture = [
                    record.mfaEnabled == null ? '' : record.mfaEnabled ? 'MFA enabled' : 'MFA not enabled',
                    record.riskLevel ? `Risk ${record.riskLevel}` : '',
                    record.roles.length ? record.roles.join(', ') : '',
                    record.lastSignIn.daysSince === '' ? '' : `${record.lastSignIn.daysSince} days since sign-in`
                ].filter(Boolean).join(' | ');
                return `
                    <li>
                        <strong>${escapeIdentityText(identity)}</strong>
                        <span>${escapeIdentityText(record.entityEmail || record.userPrincipalName || 'No email returned')}</span>
                        ${posture ? `<small>${escapeIdentityText(posture)}</small>` : ''}
                        ${signIn ? `<small>${escapeIdentityText(signIn)}</small>` : ''}
                    </li>
                `;
            }).join('')}
        </ul>
        ${remaining ? `<p class="sunbird-report-identity-more-evidence">${remaining} additional affected identity record${remaining === 1 ? '' : 's'} are available in the Identity dashboard.</p>` : ''}
    `;
}

function renderSunbirdReportIdentityFieldSection(data = {}) {
    const values = getSunbirdReportIdentityFieldValues(data);
    const findings = values.findings.map(normalizeIdentityRiskDetail).filter(finding => finding.title).slice(0, 8);
    const entityByIdentity = new Map();
    findings.flatMap(finding => finding.affectedEntities).forEach(entity => {
        const identity = String(entity.entityEmail || entity.userPrincipalName || entity.displayName || '').toLowerCase();
        if (identity && !entityByIdentity.has(identity)) entityByIdentity.set(identity, entity);
    });
    const entities = Array.from(entityByIdentity.values()).slice(0, 10);
    return `
        <section class="sunbird-report-identity-field-section">
            <div class="sunbird-report-card-title">
                <span><i class="fas fa-user-shield"></i> Identity Protection Report</span>
                <small>Current identity security posture</small>
            </div>
            <div class="sunbird-report-identity-field-grid">
                <article>
                    <strong>Domain summary</strong>
                    <p>${escapeIdentityText(values.domainExecutiveSummary || 'The latest Azure identity analysis did not include a domain summary.')}</p>
                </article>
                <article>
                    <strong>Business impact</strong>
                    <p>${escapeIdentityText(values.businessImpact || 'Business impact is detailed within the current findings below.')}</p>
                </article>
                <article>
                    <strong>Health score</strong>
                    <p>${values.healthScore == null ? 'Not assessed' : `${Number(values.healthScore)}%`}</p>
                </article>
                <article>
                    <strong>Risk score</strong>
                    <p>${values.riskScore == null ? 'Not assessed' : `${Number(values.riskScore)}%`}</p>
                </article>
            </div>
            <div class="sunbird-report-identity-findings">
                <div class="sunbird-report-identity-findings-header">
                    <h3>Key identity findings</h3>
                    <span>${findings.length} current identity findings</span>
                </div>
                <div class="sunbird-report-identity-findings-grid">
                    ${findings.length ? findings.map(finding => `
                        <article class="sunbird-report-identity-finding-card">
                            <strong>${escapeIdentityText(finding.title)}</strong>
                            ${finding.description ? `<div class="sunbird-report-identity-field-row"><span>FINDING</span><p>${escapeIdentityText(finding.description)}</p></div>` : ''}
                            <div class="sunbird-report-identity-field-row"><span>SEVERITY</span><p>${escapeIdentityText(finding.severity)}</p></div>
                            <div class="sunbird-report-identity-field-row"><span>IMPACT</span><p>${escapeIdentityText(finding.impact || 'Impact is recorded in the Azure finding context.')}</p></div>
                            <div class="sunbird-report-identity-field-row"><span>WHY IT MATTERS</span><p>${escapeIdentityText(finding.whyItMatters || finding.impact || 'This finding requires review against the supporting evidence.')}</p></div>
                            <div class="sunbird-report-identity-field-row sunbird-report-identity-evidence-row"><span>EVIDENCE</span><div>${renderIdentityEvidenceRecords(finding)}</div></div>
                            <div class="sunbird-report-identity-field-row sunbird-report-identity-recommendation-row"><span>RECOMMENDATIONS</span><ul>${getIdentityRecommendationPoints(finding.action).map(point => `<li>${escapeIdentityText(point)}</li>`).join('')}</ul></div>
                        </article>
                    `).join('') : '<div class="sunbird-report-empty">Azure did not return identity findings for this reporting period.</div>'}
                </div>
            </div>
            ${entities.length ? `
                <div class="sunbird-report-identity-entities">
                    <div class="sunbird-report-card-title"><span>Top affected entities</span><small>Entities associated with the findings</small></div>
                    <div class="sunbird-report-identity-entities-grid">
                        ${entities.map(entity => `
                            <article>
                                <strong>${escapeIdentityText(entity.displayName || entity.userPrincipalName || entity.entityEmail || 'Unknown identity')}</strong>
                                <span>${escapeIdentityText(entity.entityEmail || 'No email returned')}</span>
                                <small>${escapeIdentityText(entity.userPrincipalName || 'No user principal name returned')}</small>
                                <small>${escapeIdentityText(entity.roles.join(', ') || 'No roles returned')}</small>
                                <small>${entity.mfaEnabled == null ? 'MFA status not returned' : entity.mfaEnabled ? 'MFA enabled' : 'MFA disabled'}</small>
                                <small>${escapeIdentityText(entity.lastSignIn.location || 'No sign-in location returned')}</small>
                                <small>${escapeIdentityText(entity.lastSignIn.device || 'No sign-in device returned')}</small>
                                <small>${escapeIdentityText(entity.lastSignIn.daysSince === '' ? 'No sign-in age returned' : `${entity.lastSignIn.daysSince} days since sign-in`)}</small>
                            </article>
                        `).join('')}
                    </div>
                </div>
            ` : ''}
        </section>
    `;
}

function getSunbirdLatestReportPayload(data = {}) {
    const latest = data?.latestReport;
    return latest && typeof latest === 'object' ? latest : null;
}

function getSunbirdReportDomainName(domain = {}) {
    const value = String(domain?.domainName || domain?.domainKey || 'Domain').trim();
    if (!value) return 'Domain';
    return value.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
}

function getSunbirdReportSeverityTone(value = '') {
    const text = String(value || '').toLowerCase();
    if (/critical|high|severe|failed/.test(text)) return 'failure';
    if (/medium|moderate|warning|warn/.test(text)) return 'warn';
    if (/low|good|healthy|safe|resolved|success/.test(text)) return 'success';
    return 'neutral';
}

function unwrapSunbirdEvidenceRow(item) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return { value: item };
    return ['evidenceRow', 'affectedEntity', 'data', 'entity', 'record', 'ProcessedEvidenceJson'].reduce((row, key) => {
        const nested = row?.[key];
        return nested && typeof nested === 'object' && !Array.isArray(nested) ? { ...row, ...nested } : row;
    }, { ...item });
}

function isSunbirdOpaqueEvidenceValue(value) {
    const text = String(value || '').trim();
    return !text || /^\d+$/.test(text) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(text)
        || /(?:internalSourcePath|sourcePath|snapshotId|runId)/i.test(text);
}

function humanizeSunbirdEvidenceLabel(value) {
    return String(value || '').replace(/[_-]+/g, ' ').replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/\b\w/g, char => char.toUpperCase()).trim();
}

function formatSunbirdEvidenceText(value) {
    return String(value ?? '').replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?\b/g, match => {
        const formatted = formatSunbirdReportDate(match, true);
        return formatted === 'Not yet' ? match : formatted;
    }).trim();
}
function normalizeSunbirdLiveEvidenceRows(items = [], finding = {}) {
    return (Array.isArray(items) ? items : []).map(item => {
        const row = unwrapSunbirdEvidenceRow(item);
        const title = [row.displayName, row.entityName, row.entityDisplayName, row.deviceName, row.entityDeviceName,
            row.title, row.alertName, row.controlName, row.applicationName, row.profileName, row.activity, row.endpointFamily, row.module, row.key, row.name,
            row.userPrincipalName, row.entityEmail, row.mail, row.userEmail, row.user, row.actor, row.resource,
            row.recipient, row.sender, row.entityId].map(value => String(value || '').trim()).find(value => value && !isSunbirdOpaqueEvidenceValue(value)) || '';
        const fields = [];
        const add = (label, value) => {
            const text = formatSunbirdEvidenceText(Array.isArray(value) ? value.filter(Boolean).join(', ') : value);
            if (!text || text.toLowerCase() === title.toLowerCase()) return;
            const entry = label ? `${label}: ${text}` : text;
            if (!fields.some(current => current.toLowerCase() === entry.toLowerCase())) fields.push(entry);
        };
        add('User', row.entityEmail || row.mail || row.userPrincipalName || row.userEmail || row.user);
        add('Sender', row.sender); add('Recipient', row.recipient);
        add('Device', row.deviceName && row.deviceName !== title ? row.deviceName : row.entityDeviceName);
        add('Operating system', [row.operatingSystem, row.osVersion].filter(Boolean).join(' '));
        add('Compliance', row.complianceState || row.complianceStatus); add('Encryption', row.encryptionStatus); add('Management', row.managementAgent);
        add('Publisher', row.publisherName); add('Application type', row.type); add('Roles', row.roles); add('Policies', row.policies);
        add('Action', row.action || row.managementAction || row.remediationAction); add('Area', row.area); add('Owner', row.ownerStatus);
        add('Control', row.controlName || row.policyName); add('Category', row.category); add('Status', row.status || row.state);
        add('Severity', row.severity || row.riskLevel); add('Location', row.location); add('IP address', row.ipAddress); add('Failure reason', row.failureReason);
        add('Files', row.files); add('Storage', row.storage); add('Role count', row.roleCount); add('User count', row.userCount); add('Scope count', row.scopeCount);
        if (row.mfaEnabled != null) add('MFA', row.mfaEnabled ? 'Enabled' : 'Not enabled');
        if (row.hasAdminRole != null) add('Administrator role', row.hasAdminRole ? 'Present' : 'Not present');
        if (row.isExternal != null) add('External application', row.isExternal ? 'Yes' : 'No');
        if (row.enabled != null) add('Enabled', row.enabled ? 'Yes' : 'No');
        String(row.description || row.detail || row.validationReason || row.governanceIssue || row.auditImpact || row.evidenceSummary || '').split(/\s*\|\s*/).filter(Boolean).forEach(value => add('', value));
        add('Last sign-in', typeof row.lastSignIn === 'string' ? row.lastSignIn : '');
        add('Last sync', row.lastSyncDateTime); add('Event time', row.eventTime); add('Created', row.createdDateTime); add('Last seen', row.lastSeen); add('Last activity', row.lastActivity);
        const identity = [row.entityId, row.id, row.recordId, row.sourceAlertId, row.alertId, row.userPrincipalName, row.entityEmail,
            row.mail, row.deviceName, row.controlName, row.applicationName, row.displayName, row.title, row.name]
            .map(value => String(value || '').trim().toLowerCase()).find(Boolean) || `${title}|${fields.join('|')}`.toLowerCase();
        return {
            _identity: identity,
            title,
            detail: fields.slice(0, 2).join(' · '),
            facts: fields.slice(2, 7),
            severity: String(row.severity || row.riskLevel || row.priority || ''),
            source: humanizeSunbirdEvidenceLabel(row.sourceMetric || row.evidenceSource || row.category || finding.sourceMetric || '')
        };
    }).filter(row => row.title && !isSunbirdTechnicalNoiseText(`${row.title} ${row.detail}`));
}

function mergeSunbirdDomainEvidenceRows(embedded = [], live = []) {
    const merged = new Map();
    [...embedded, ...live].forEach(row => {
        const key = row._identity || `${row.title}|${row.detail}`.toLowerCase();
        const previous = merged.get(key);
        merged.set(key, previous ? {
            ...previous,
            ...row,
            detail: String(row.detail || '').length > String(previous.detail || '').length ? row.detail : previous.detail,
            severity: row.severity || previous.severity,
            source: row.source || previous.source,
            facts: (row.facts?.length || 0) > (previous.facts?.length || 0) ? row.facts : previous.facts
        } : row);
    });
    return Array.from(merged.values());
}

function getSunbirdDomainFindingEvidenceCount(finding = {}) {
    return getSunbirdDomainFindingEvidenceRows(finding).length;
}

function applySunbirdDomainEvidenceState(currentRows = [], liveRows = [], failed = false) {
    const rows = liveRows.length ? mergeSunbirdDomainEvidenceRows(currentRows, liveRows) : currentRows;
    return { rows, count: rows.length, status: failed ? 'saved' : liveRows.length ? 'enriched' : 'saved' };
}
function getSunbirdDomainFindingEvidenceRows(finding = {}) {
    const embedded = ['evidence', 'evidenceRows', 'affectedEntities', 'evidenceRecords']
        .flatMap(field => Array.isArray(finding?.[field]) ? finding[field] : []);
    const rows = normalizeSunbirdLiveEvidenceRows(embedded, finding);
    return rows.length ? mergeSunbirdDomainEvidenceRows([], rows) : [];
}
function getSunbirdDomainFindingEvidenceIds(finding = {}) {
    const fields = ['affectedEntityIds', 'recordIds', 'sourceAlertIds', 'evidenceIds', 'entityIds'];
    return [...new Set(fields.flatMap(field => Array.isArray(finding?.[field]) ? finding[field] : [])
        .map(value => String(value || '').trim()).filter(Boolean))];
}

async function loadSunbirdDomainFindingLiveEvidence(payload = {}) {
    const domainKey = String(payload?.domainKey || '').trim();
    const evidenceIds = getSunbirdDomainFindingEvidenceIds(payload?.finding);
    if (!domainKey || !evidenceIds.length) return [];
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
        const params = new URLSearchParams({ domainKey, evidenceIds: evidenceIds.join(',') });
        const response = await fetch('/api/sunbird/reports/live-evidence?' + params.toString(), { cache: 'no-store', headers: getSunbirdReportHeaders(), signal: controller.signal });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.success) throw new Error(data.message || 'Evidence request failed (' + response.status + ')');
        return normalizeSunbirdLiveEvidenceRows(data.evidence, payload.finding);
    } finally {
        clearTimeout(timeout);
    }
}
function renderSunbirdDomainEvidenceRows(rows = []) {
    return rows.map(row => `
        <article class="sunbird-report-evidence-row">
            <div class="sunbird-report-evidence-main">
                <strong>${escapeIdentityText(row.title)}</strong>
                <span>${escapeIdentityText(row.detail)}</span>
                ${row.facts?.length ? `<ul class="sunbird-report-evidence-facts">${row.facts.map(fact => `<li>${escapeIdentityText(fact)}</li>`).join('')}</ul>` : ''}
            </div>
            <div class="sunbird-report-evidence-meta">
                ${row.severity ? `<em>${escapeIdentityText(row.severity)}</em>` : ''}
                ${row.source ? `<small>${escapeIdentityText(row.source)}</small>` : ''}
            </div>
        </article>
    `).join('');
}

function setSunbirdReportDomainFilter(domainKey = 'all') {
    sunbirdReportDomainFilter = String(domainKey || 'all');
    if (cachedSunbirdReportsData) renderSunbirdReportsCenter(cachedSunbirdReportsData);
}

function closeSunbirdDomainFindingEvidence() {
    document.getElementById('sunbird-report-domain-evidence-modal')?.remove();
    document.removeEventListener('keydown', handleSunbirdDomainFindingEvidenceEscape);
}

function handleSunbirdDomainFindingEvidenceEscape(event) {
    if (event.key === 'Escape') closeSunbirdDomainFindingEvidence();
}

function openSunbirdDomainFindingEvidence(evidenceKey) {
    const key = String(evidenceKey || '');
    const payload = sunbirdReportDomainEvidenceMap.get(key);
    if (!payload) {
        showNotification('Evidence details are not available for this finding yet.', false);
        return;
    }
    closeSunbirdDomainFindingEvidence();
    const explicitEvidenceIds = getSunbirdDomainFindingEvidenceIds(payload.finding);
    let rows = getSunbirdDomainFindingEvidenceRows(payload.finding);
    const tone = getSunbirdReportSeverityTone(payload.finding?.severity);
    const modal = document.createElement('div');
    modal.id = 'sunbird-report-domain-evidence-modal';
    modal.className = `sunbird-id-modal sunbird-report-evidence-modal open tone-${tone === 'failure' ? 'danger' : tone === 'success' ? 'success' : 'events'}`;
    modal.innerHTML = `
        <div class="sunbird-id-modal-backdrop" onclick="window.closeSunbirdDomainFindingEvidence()"></div>
        <div class="sunbird-id-modal-panel sunbird-report-evidence-panel" role="dialog" aria-modal="true" aria-labelledby="sunbird-report-domain-evidence-title">
            <div class="sunbird-id-modal-header sunbird-report-evidence-header">
                <div>
                    <h3 id="sunbird-report-domain-evidence-title"><i class="fas fa-magnifying-glass-chart"></i> ${escapeIdentityText(payload.domainName)} - ${escapeIdentityText(payload.finding?.title || 'Finding evidence')}</h3>
                    <p>${escapeIdentityText(payload.finding?.impact || payload.finding?.whyItMatters || 'Evidence captured from the latest intelligent report only.')}</p>
                </div>
                <button type="button" onclick="window.closeSunbirdDomainFindingEvidence()" class="sunbird-id-modal-close" aria-label="Close finding evidence">&times;</button>
            </div>
            <div class="sunbird-id-evidence-summary sunbird-report-evidence-summary" id="sunbird-report-domain-evidence-summary">
                <span id="sunbird-report-domain-evidence-count">${rows.length} explicitly linked evidence row${rows.length === 1 ? '' : 's'}</span>
                <span>${escapeIdentityText(payload.finding?.severity || 'Observed')}</span>
                <span>${escapeIdentityText(humanizeSunbirdEvidenceLabel(payload.finding?.sourceMetric) || 'Latest report output')}</span>
            </div>
            <div class="sunbird-id-evidence-list sunbird-report-evidence-list" id="sunbird-report-domain-evidence-list">
                ${rows.length ? renderSunbirdDomainEvidenceRows(rows) : '<div class="sunbird-report-evidence-empty">No source evidence was linked for this finding.</div>'}
            </div>
            <div class="sunbird-id-modal-actions">
                <button type="button" class="sunbird-id-evidence-btn" onclick="window.closeSunbirdDomainFindingEvidence()">Close</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    document.addEventListener('keydown', handleSunbirdDomainFindingEvidenceEscape);
    // Evidence is rendered from the finding's explicit links only. A metric such as
    // totalUsers is an aggregate, not a relationship to every record in a domain.
    if (explicitEvidenceIds.length) {
        const count = modal.querySelector('#sunbird-report-domain-evidence-count');
        if (count) count.textContent = `${rows.length} embedded evidence row${rows.length === 1 ? '' : 's'} · checking for current details`;
        loadSunbirdDomainFindingLiveEvidence(payload).then(liveRows => {
            if (!document.body.contains(modal)) return;
            const currentCount = modal.querySelector('#sunbird-report-domain-evidence-count');
            const list = modal.querySelector('#sunbird-report-domain-evidence-list');
            const state = applySunbirdDomainEvidenceState(rows, liveRows);
            rows = state.rows;
            if (currentCount) currentCount.textContent = String(state.count) + ' linked evidence row' + (state.count === 1 ? '' : 's');
            if (list) list.innerHTML = renderSunbirdDomainEvidenceRows(rows);
            const cardCount = document.getElementById(`sunbird-report-domain-evidence-count-${key}`);
            if (cardCount) cardCount.textContent = `Open evidence (${state.count})`;
        }).catch(error => {
            console.error('[Reports] Finding evidence load failed:', error);
            if (!document.body.contains(modal)) return;
            const state = applySunbirdDomainEvidenceState(rows, [], true);
            rows = state.rows;
            const currentCount = modal.querySelector('#sunbird-report-domain-evidence-count');
            if (currentCount) currentCount.textContent = String(state.count) + ' saved evidence row' + (state.count === 1 ? '' : 's') + ' · current details unavailable';
        });
    }
}

function renderSunbirdReportDomainBreakdown(data = {}) {
    const latest = getSunbirdLatestReportPayload(data);
    const domains = Array.isArray(latest?.domainBreakdown) ? latest.domainBreakdown : [];
    const visibleDomains = domains.filter(domain => {
        const findings = Array.isArray(domain?.findings) ? domain.findings : [];
        return findings.length || domain?.summary || domain?.businessImpact;
    });
    sunbirdReportDomainEvidenceMap.clear();
    if (!latest || !visibleDomains.length) return '';

    const domainOptions = visibleDomains.map(domain => ({
        key: String(domain.domainKey || '').trim() || String(domain.domainName || '').toLowerCase().replace(/\s+/g, '_') || 'domain',
        label: getSunbirdReportDomainName(domain)
    }));
    const selectedKey = sunbirdReportDomainFilter || 'all';
    const filteredDomains = selectedKey === 'all'
        ? visibleDomains
        : visibleDomains.filter(domain => {
            const key = String(domain.domainKey || '').trim() || String(domain.domainName || '').toLowerCase().replace(/\s+/g, '_');
            return key === selectedKey;
        });

    return `
        <section class="sunbird-report-domain-breakdown">
            <div class="sunbird-report-card-title">
                <span><i class="fas fa-layer-group"></i> Full domain intelligence (latest per-domain analysis)</span>
                <small>${escapeIdentityText(formatSunbirdReportDate(latest.createdAt || latest.periodEnd, true))}</small>
            </div>
            <div class="sunbird-report-domain-filter-row" role="group" aria-label="Domain filter">
                <button type="button" class="${selectedKey === 'all' ? 'active' : ''}" onclick="window.setSunbirdReportDomainFilter('all')">All domains</button>
                ${domainOptions.map(option => `
                    <button type="button" class="${selectedKey === option.key ? 'active' : ''}" onclick="window.setSunbirdReportDomainFilter('${escapeIdentityText(option.key)}')">${escapeIdentityText(option.label)}</button>
                `).join('')}
            </div>
            <div class="sunbird-report-domain-breakdown-grid">
                ${filteredDomains.map((domain, domainIndex) => {
                    const domainName = getSunbirdReportDomainName(domain);
                    const findings = (Array.isArray(domain.findings) ? domain.findings : [])
                        .filter(finding => !isSunbirdTechnicalNoiseText(`${finding?.title || ''} ${finding?.impact || ''} ${finding?.whyItMatters || ''}`))
                        ;
                    const recommendations = (Array.isArray(domain.recommendations) ? domain.recommendations : [])
                        .filter(item => !isSunbirdTechnicalNoiseText(item))
                        ;
                    return `
                        <article class="sunbird-report-domain-detail-card">
                            <header>
                                <h3>${escapeIdentityText(domainName)}</h3>
                                <small>${escapeIdentityText(domain.analysedAt ? `Last analysed ${formatSunbirdReportDate(domain.analysedAt, true)}` : 'Analysis time not returned')}</small>
                                <div class="sunbird-report-domain-score-pills">
                                    <span class="tone-${getSunbirdReportScoreTone(domain.healthScore)}">Health ${domain.healthScore == null ? 'n/a' : `${Number(domain.healthScore)}%`}</span>
                                    <span class="tone-${getSunbirdReportScoreTone(100 - Number(domain.riskScore || 0))}">Risk ${domain.riskScore == null ? 'n/a' : `${Number(domain.riskScore)}%`}</span>
                                </div>
                            </header>
                            ${domain.summary ? `<p class="sunbird-report-domain-summary">${escapeIdentityText(domain.summary)}</p>` : ''}
                            ${domain.businessImpact ? `<p class="sunbird-report-domain-impact"><strong>Business impact:</strong> ${escapeIdentityText(domain.businessImpact)}</p>` : ''}
                            ${findings.length ? `
                                <div class="sunbird-report-domain-findings-list">
                                    ${findings.map((finding, findingIndex) => {
                                        const evidenceKey = `${domainIndex}-${findingIndex}`;
                                        sunbirdReportDomainEvidenceMap.set(evidenceKey, { domainName, domainKey: domain.domainKey, finding });
                                        const tone = getSunbirdReportSeverityTone(finding.severity || finding.riskLevel || finding.priority || '');
                                        const recommendation = String(finding.recommendation || '').trim();
                                        return `
                                            <button type="button" class="sunbird-report-domain-finding tone-${tone}" onclick="window.openSunbirdDomainFindingEvidence('${evidenceKey}')">
                                                <div class="sunbird-report-domain-finding-head">
                                                    <strong>${escapeIdentityText(finding.title || 'Domain finding')}</strong>
                                                    <em>${escapeIdentityText(finding.severity || 'Observed')}</em>
                                                </div>
                                                ${finding.impact ? `<p>${escapeIdentityText(finding.impact)}</p>` : ''}
                                                ${finding.whyItMatters ? `<small>${escapeIdentityText(finding.whyItMatters)}</small>` : ''}
                                                ${recommendation ? `<small class="sunbird-report-domain-recommend">Next: ${escapeIdentityText(recommendation)}</small>` : ''}
                                                <span class="sunbird-report-domain-evidence-cta" id="sunbird-report-domain-evidence-count-${evidenceKey}">Open evidence (${getSunbirdDomainFindingEvidenceCount(finding)})</span>
                                            </button>
                                        `;
                                    }).join('')}
                                </div>
                            ` : ''}
                            ${recommendations.length ? `
                                <div class="sunbird-report-domain-rec-block">
                                    <strong>Priority actions</strong>
                                    <ul>${recommendations.map(item => `<li>${escapeIdentityText(item)}</li>`).join('')}</ul>
                                </div>
                            ` : ''}
                        </article>
                    `;
                }).join('')}
            </div>
        </section>
    `;
}

function renderSunbirdReportKpiButton({ key, value, label, tone, meta }) {
    return `
        <button type="button" class="sunbird-report-kpi tone-${tone}" onclick="window.openSunbirdReportEvidence('${key}')">
            <strong>${Number(value || 0)}</strong>
            <span>${escapeIdentityText(label)}</span>
            ${meta ? `<small>${escapeIdentityText(meta)}</small>` : ''}
        </button>
    `;
}

function renderSunbirdReportRecommendationPreview(recommendations = []) {
    const rows = recommendations.slice(0, 2);
    return `
        <div class="sunbird-report-recommendations-preview">
            <div class="sunbird-report-rec-head">
                <span><i class="fas fa-sparkles"></i> Recommendations</span>
                <button type="button" onclick="window.openSunbirdReportEvidence('recommendations')">View all</button>
            </div>
            <div class="sunbird-report-rec-list">
                ${rows.length ? rows.map(item => {
                    const meta = getSunbirdReportOwnerStatus(item, 'recommendations');
                    return `
                        <button type="button" class="sunbird-report-rec-item" onclick="window.openSunbirdReportEvidence('recommendations')">
                            <strong>${escapeIdentityText(getSunbirdReportItemTitle(item))}</strong>
                            ${getSunbirdReportItemDetail(item) ? `<small>${escapeIdentityText(getSunbirdReportItemDetail(item))}</small>` : ''}
                            <span><em>${escapeIdentityText(meta.owner)}</em><em>${escapeIdentityText(meta.status)}</em></span>
                        </button>
                    `;
                }).join('') : '<div class="sunbird-report-rec-empty">No urgent actions are required.</div>'}
            </div>
        </div>
    `;
}

function getSunbirdReportModalConfig(key) {
    const configs = {
        problems: {
            title: 'Problems requiring attention',
            subtitle: 'Evidence-backed issues from the latest reporting period.',
            tone: 'danger',
            icon: 'fa-triangle-exclamation',
            empty: 'No problems were recorded in this period.'
        },
        successes: {
            title: 'Confirmed successes',
            subtitle: 'Positive outcomes the report can prove from collected evidence.',
            tone: 'success',
            icon: 'fa-circle-check',
            empty: 'No successes have been recorded yet.'
        },
        recommendations: {
            title: 'Recommended next actions',
            subtitle: 'Prioritized actions that turn the report into a client roadmap.',
            tone: 'recommendation',
            icon: 'fa-sparkles',
            empty: 'No recommendations are required right now.'
        },
        events: {
            title: 'Evidence timeline',
            subtitle: 'Timestamped events behind the report health score.',
            tone: 'events',
            icon: 'fa-stream',
            empty: 'No timestamped events were recorded.'
        }
    };
    return configs[key] || configs.problems;
}

function renderSunbirdReportEvidenceRows(key, rows = []) {
    if (!rows.length) return '';
    if (key === 'events') {
        return rows.slice(0, 80).map(event => {
            const impact = getSunbirdReportBusinessImpact(event, 'events');
            return `
                <article class="sunbird-report-evidence-row">
                    <div class="sunbird-report-evidence-main">
                        <strong>${escapeIdentityText(event.title || 'Report event')}</strong>
                        <span>${escapeIdentityText(event.detail || event.asset || event.status || 'Evidence observed')}</span>
                        <p>${escapeIdentityText(impact)}</p>
                    </div>
                    <div class="sunbird-report-evidence-meta">
                        <em>${escapeIdentityText(event.severity || 'info')}</em>
                        <small>${escapeIdentityText(event.source || 'Dashboard')}</small>
                        <time>${escapeIdentityText(formatSunbirdReportDate(event.timestamp, true))}</time>
                    </div>
                </article>
            `;
        }).join('');
    }
    return rows.slice(0, 80).map(item => {
        const impact = getSunbirdReportBusinessImpact(item, key);
        const ownerStatus = getSunbirdReportOwnerStatus(item, key);
        const itemMeta = item && typeof item === 'object' ? item : {};
        return `
            <article class="sunbird-report-evidence-row">
                <div class="sunbird-report-evidence-main">
                    <strong>${escapeIdentityText(getSunbirdReportItemTitle(item))}</strong>
                    <span>${escapeIdentityText(getSunbirdReportItemDetail(item) || 'Evidence item')}</span>
                    <p>${escapeIdentityText(impact)}</p>
                    ${key === 'recommendations' || key === 'problems' ? `
                        <div class="sunbird-report-owner-row">
                            <em>Owner: ${escapeIdentityText(ownerStatus.owner)}</em>
                            <em>Status: ${escapeIdentityText(ownerStatus.status)}</em>
                        </div>
                    ` : ''}
                </div>
                <div class="sunbird-report-evidence-meta">
                    ${itemMeta.priority ? `<em>${escapeIdentityText(itemMeta.priority)}</em>` : ''}
                    ${itemMeta.source ? `<small>${escapeIdentityText(itemMeta.source)}</small>` : ''}
                    ${itemMeta.status ? `<small>${escapeIdentityText(itemMeta.status)}</small>` : ''}
                </div>
            </article>
        `;
    }).join('');
}

function closeSunbirdReportEvidence() {
    document.getElementById('sunbird-report-evidence-modal')?.remove();
    document.removeEventListener('keydown', handleSunbirdReportEvidenceEscape);
}

function handleSunbirdReportEvidenceEscape(event) {
    if (event.key === 'Escape') closeSunbirdReportEvidence();
}

function openSunbirdReportEvidence(key) {
    const data = cachedSunbirdReportsData;
    if (!data) {
        showNotification('Report evidence is still loading', false);
        return;
    }
    const buckets = getSunbirdReportEvidenceBuckets(data);
    const rows = buckets[key] || [];
    const config = getSunbirdReportModalConfig(key);
    closeSunbirdReportEvidence();
    const overview = data.overview || {};
    const summary = overview.summary || {};
    const modal = document.createElement('div');
    modal.id = 'sunbird-report-evidence-modal';
    modal.className = `sunbird-id-modal sunbird-report-evidence-modal open tone-${config.tone}`;
    modal.innerHTML = `
        <div class="sunbird-id-modal-backdrop" onclick="window.closeSunbirdReportEvidence()"></div>
        <div class="sunbird-id-modal-panel sunbird-report-evidence-panel" role="dialog" aria-modal="true" aria-labelledby="sunbird-report-evidence-title">
            <div class="sunbird-id-modal-header sunbird-report-evidence-header">
                <div>
                    <h3 id="sunbird-report-evidence-title"><i class="fas ${config.icon}"></i> ${escapeIdentityText(config.title)}</h3>
                    <p>${escapeIdentityText(config.subtitle)}</p>
                </div>
                <button type="button" onclick="window.closeSunbirdReportEvidence()" class="sunbird-id-modal-close" aria-label="Close report evidence">&times;</button>
            </div>
            <div class="sunbird-id-evidence-summary sunbird-report-evidence-summary">
                <span>${rows.length} item${rows.length === 1 ? '' : 's'}</span>
                <span>Health ${Number(summary.healthScore || 0)}%</span>
                <span>${Number(summary.totalEvents || buckets.events.length || 0)} events</span>
            </div>
            <div class="sunbird-id-evidence-list sunbird-report-evidence-list">
                ${rows.length ? renderSunbirdReportEvidenceRows(key, rows) : `<div class="sunbird-report-evidence-empty">${escapeIdentityText(config.empty)}</div>`}
            </div>
            <div class="sunbird-id-modal-actions">
                <button type="button" class="sunbird-id-evidence-btn" onclick="window.closeSunbirdReportEvidence(); window.openSunbirdReportsDashboard()">Open Report Center</button>
                <button type="button" class="sunbird-id-evidence-btn" onclick="window.closeSunbirdReportEvidence()">Close</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    document.addEventListener('keydown', handleSunbirdReportEvidenceEscape);
}

function renderSunbirdReportMiniHistory(reports = []) {
    if (!reports.length) {
        return '<div class="sunbird-report-empty">No generated reports yet. Daily evidence collection is ready.</div>';
    }
    return reports.slice(0, 3).map(report => `
        <button type="button" class="sunbird-report-mini-row" onclick="window.downloadSunbirdReportPdf(${Number(report.id)})">
            <span class="sunbird-report-mini-icon"><i class="fas fa-file-pdf"></i></span>
            <span class="sunbird-report-mini-copy">
                <strong>${escapeIdentityText(report.type === 'weekly' ? 'Weekly report' : 'Generated report')}</strong>
                <small>${escapeIdentityText(formatSunbirdReportDate(report.periodEnd))}</small>
            </span>
            <span class="sunbird-report-mini-score tone-${getSunbirdReportScoreTone(report.healthScore)}">${Number(report.healthScore || 0)}%</span>
            <i class="fas fa-download" aria-hidden="true"></i>
        </button>
    `).join('');
}

async function renderSunbirdReportsView(forceRefresh = false) {
    const billingCard = document.getElementById('billing-card');
    if (!billingCard || !isSunbirdBillingViewActive('reports')) return;
    try {
        if (forceRefresh || !cachedSunbirdReportsData) {
            billingCard.innerHTML = renderSunbirdPremiumLoader('Building report summary');
        }
        const data = await fetchSunbirdReportsData('30d', forceRefresh);
        if (!isSunbirdBillingViewActive('reports')) return;
        const overview = data.overview || {};
        const summary = overview.summary || {};
        const analysis = overview.analysis || {};
        const lastReport = data.reports?.[0];
        const evidenceBuckets = getSunbirdReportEvidenceBuckets(data);
        billingCard.innerHTML = `
            <div class="sunbird-panel-view sunbird-report-preview">
                <div class="billing-card-header sunbird-report-preview-header">
                    <i class="fas fa-chart-line"></i>
                    <div>
                        <h3>Automated Reports</h3>
                        <span>Daily evidence, Friday delivery</span>
                    </div>
                    <span class="sunbird-report-live-pill"><i></i> Active</span>
                </div>

                <div class="sunbird-report-preview-scroll">
                    <div class="sunbird-report-score-strip">
                        <div class="sunbird-report-score tone-${getSunbirdReportScoreTone(summary.healthScore)}">
                            <div>
                                <span>Security health</span>
                                <strong>${Number(summary.healthScore || 0)}%</strong>
                                <small>${escapeIdentityText(summary.status || 'Evidence live')}</small>
                            </div>
                        </div>
                        <div class="sunbird-report-kpi-grid">
                            ${renderSunbirdReportKpiButton({ key: 'problems', value: Math.max(Number(summary.failures || 0), evidenceBuckets.problems.length), label: 'Problems', tone: 'danger', meta: 'View evidence' })}
                            ${renderSunbirdReportKpiButton({ key: 'successes', value: Math.max(Number(summary.successes || 0), evidenceBuckets.successes.length), label: 'Successes', tone: 'success', meta: 'Client wins' })}
                            ${renderSunbirdReportKpiButton({ key: 'recommendations', value: evidenceBuckets.recommendations.length, label: 'Actions', tone: 'recommendation', meta: 'Next steps' })}
                            ${renderSunbirdReportKpiButton({ key: 'events', value: Math.max(Number(summary.totalEvents || 0), evidenceBuckets.events.length), label: 'Events', tone: 'events', meta: 'Timeline' })}
                        </div>
                    </div>

                    ${renderSunbirdReportValueStrip(data, evidenceBuckets)}

                    <div class="sunbird-report-ai-note">
                        <span class="sunbird-report-ai-mark"><i class="fas fa-clipboard-check"></i></span>
                        <div>
                            <strong>Evidence summary</strong>
                            <p>${escapeIdentityText(analysis.executiveSummary || 'Dashboard evidence is being summarized into a focused operational report.')}</p>
                        </div>
                    </div>

                    ${renderSunbirdReportRecommendationPreview(evidenceBuckets.recommendations)}

                    <div class="sunbird-report-preview-section">
                        <div class="sunbird-report-preview-label">
                            <span>Recent reports</span>
                            <small>${lastReport ? `Last generated ${escapeIdentityText(formatSunbirdReportDate(lastReport.createdAt, true))}` : 'History starts from activation'}</small>
                        </div>
                        <div class="sunbird-report-mini-history">
                            ${renderSunbirdReportMiniHistory(data.reports || [])}
                        </div>
                    </div>
                </div>

                <div class="sunbird-dashboard-btn-wrap sunbird-report-actions">
                    <button class="sunbird-dashboard-btn" onclick="window.openSunbirdReportsDashboard()">
                        <i class="fas fa-arrow-up-right-from-square"></i> Open Report Center
                    </button>
                    <button class="sunbird-report-get-intel" onclick="window.getIntelligentReport && window.getIntelligentReport()">
                        <i class="fas fa-brain"></i> Get intelligent report
                    </button>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('[Sunbird Reports] Error:', error);
        if (!isSunbirdBillingViewActive('reports')) return;
        billingCard.innerHTML = `
            <div class="sunbird-panel-view">
                <div class="billing-card-header"><i class="fas fa-chart-line"></i><h3>Automated Reports</h3></div>
                <p class="sunbird-panel-error">Unable to load report evidence right now.</p>
                <div class="sunbird-dashboard-btn-wrap">
                    <button class="sunbird-dashboard-btn" onclick="window.renderSunbirdReportsView(true)">
                        <i class="fas fa-rotate"></i> Try again
                    </button>
                </div>
            </div>
        `;
    } finally {
        ensureSunbirdBillingCardDimensions();
        syncSunbirdLeftMenuHeight();
    }
}

function renderSunbirdReportsShell() {
    return `
        <section class="sunbird-identity-dashboard sunbird-reports-dashboard" id="sunbird-reports-dashboard">
            <div class="sunbird-id-header sunbird-report-center-header">
                <button id="sunbird-reports-back" class="sunbird-id-back-btn" type="button">
                    <span class="sunbird-id-back-icon" aria-hidden="true">&larr;</span>
                    <span>Back</span>
                </button>
                <div>
                    <div class="sunbird-report-eyebrow">Automated reporting</div>
                    <h2>Automated Reports</h2>
                </div>
                <div class="sunbird-report-brand-lockup" aria-label="StackOps and StackCTRL">

                </div>
            </div>

            <div class="sunbird-report-toolbar">
                <div class="sunbird-report-range-group" role="group" aria-label="Report time frame">
                    <button type="button" data-report-range="7d">7 days</button>
                    <button type="button" data-report-range="30d" class="active">30 days</button>
                    <button type="button" data-report-range="90d">90 days</button>
                    <button type="button" data-report-range="since">Since activation</button>
                </div>
                <button id="sunbird-report-intelligent-btn" class="sunbird-report-primary-btn" type="button">
                    <i class="fas fa-brain"></i>
                    Get intelligent report
                </button>
            </div>

            <div id="sunbird-report-center-content">
                ${renderSunbirdPremiumLoader('Loading report history')}
            </div>
        </section>
    `;
}

function renderSunbirdReportDomainScores(scores = {}) {
    const labels = {
        security: 'Security',
        identity: 'Identity',
        devices: 'Devices',
        email: 'Email',
        applications: 'Applications',
        backup: 'Backup'
    };
    return Object.entries(labels).map(([key, label]) => {
        const score = scores[key];
        const displayScore = score == null ? 0 : Number(score);
        return `
            <div class="sunbird-report-domain">
                <div><span>${label}</span><strong>${score == null ? 'No data' : `${displayScore}%`}</strong></div>
                <div class="sunbird-report-domain-track"><i class="tone-${getSunbirdReportScoreTone(displayScore)}" style="width:${Math.max(0, Math.min(100, displayScore))}%"></i></div>
            </div>
        `;
    }).join('');
}

function renderSunbirdReportInsightList(items = [], tone = 'neutral', emptyText = 'Nothing recorded', key = '') {
    const filteredItems = filterSunbirdInsightItems(items);
    if (!filteredItems.length) return `<div class="sunbird-report-empty">${escapeIdentityText(emptyText)}</div>`;
    return filteredItems.map(item => {
        const ownerStatus = getSunbirdReportOwnerStatus(item, key);
        return `
            <article class="sunbird-report-insight tone-${tone}">
                <i class="fas ${tone === 'success' ? 'fa-check' : tone === 'failure' ? 'fa-exclamation' : 'fa-arrow-right'}"></i>
                <div>
                    <strong>${escapeIdentityText(getSunbirdReportItemTitle(item))}</strong>
                    ${getSunbirdReportItemDetail(item) ? `<p>${escapeIdentityText(getSunbirdReportItemDetail(item))}</p>` : ''}
                    ${key ? `<small class="sunbird-report-insight-impact">${escapeIdentityText(getSunbirdReportBusinessImpact(item, key))}</small>` : ''}
                    ${key === 'recommendations' || key === 'problems' ? `
                        <div class="sunbird-report-insight-meta">
                            <em>${escapeIdentityText(ownerStatus.owner)}</em>
                            <em>${escapeIdentityText(ownerStatus.status)}</em>
                        </div>
                    ` : ''}
                </div>
            </article>
        `;
    }).join('');
}

function renderSunbirdReportHistoryRows(reports = []) {
    if (!reports.length) return '<tr><td colspan="7" class="sunbird-id-empty">No generated reports yet.</td></tr>';
    return reports.map(report => `
        <tr>
            <td><span class="sunbird-report-type">${escapeIdentityText(report.type || 'manual')}</span></td>
            <td>${escapeIdentityText(formatSunbirdReportDate(report.periodStart))}</td>
            <td>${escapeIdentityText(formatSunbirdReportDate(report.periodEnd))}</td>
            <td><span class="sunbird-report-table-score tone-${getSunbirdReportScoreTone(report.healthScore)}">${Number(report.healthScore || 0)}%</span></td>
            <td>${Number(report.summary?.failures || 0)}</td>
            <td><span class="sunbird-report-delivery ${report.emailStatus === 'sent' ? 'sent' : ''}">${escapeIdentityText(report.emailStatus || 'not-sent')}</span></td>
            <td><button type="button" class="sunbird-id-evidence-btn" onclick="window.downloadSunbirdReportPdf(${Number(report.id)})"><i class="fas fa-download"></i> PDF</button></td>
        </tr>
    `).join('');
}

function renderSunbirdReportAuditRows(logs = []) {
    const filteredLogs = (Array.isArray(logs) ? logs : []).filter(log => !isSunbirdTechnicalNoiseText(`${log?.message || ''} ${log?.eventType || ''}`));
    if (!filteredLogs.length) return '<div class="sunbird-report-empty">No report automation logs are available for this period.</div>';
    const iconByStatus = {
        success: 'fa-check',
        failed: 'fa-xmark',
        started: 'fa-ellipsis',
        info: 'fa-circle-info'
    };
    return filteredLogs.slice(0, 80).map(log => `
        <article class="sunbird-report-log-row tone-${escapeIdentityText(log.status || 'info')}">
            <span class="sunbird-report-log-icon"><i class="fas ${iconByStatus[log.status] || 'fa-circle-info'}"></i></span>
            <div>
                <strong>${escapeIdentityText(log.message || log.eventType || 'Report activity')}</strong>
                <small>${escapeIdentityText(String(log.eventType || '').replaceAll('_', ' '))}</small>
            </div>
            <time>${escapeIdentityText(formatSunbirdReportDate(log.createdAt, true))}</time>
        </article>
    `).join('');
}

function renderSunbirdReportEventRows(events = []) {
    const filteredEvents = filterSunbirdInsightItems(events);
    if (!filteredEvents.length) return '<tr><td colspan="6" class="sunbird-id-empty">No timestamped problems or activity were recorded.</td></tr>';
    return filteredEvents.slice(0, 40).map(event => `
        <tr>
            <td>${escapeIdentityText(formatSunbirdReportDate(event.timestamp, true))}</td>
            <td><span class="sunbird-severity-pill ${escapeIdentityText(event.severity || 'low')}">${escapeIdentityText(event.severity || 'info')}</span></td>
            <td>${escapeIdentityText(event.title || 'Event')}</td>
            <td>${escapeIdentityText(event.source || 'Dashboard')}</td>
            <td>${escapeIdentityText(event.status || 'observed')}</td>
            <td>${escapeIdentityText(event.asset || event.detail || '-')}</td>
        </tr>
    `).join('');
}

function renderSunbirdReportsCenter(data) {
    const content = document.getElementById('sunbird-report-center-content');
    if (!content) return;
    const overview = data.overview || {};
    const summary = overview.summary || {};
    const analysis = overview.analysis || {};
    const settings = data.settings || {};
    const evidenceBuckets = getSunbirdReportEvidenceBuckets(data);
    const successItems = filterSunbirdInsightItems(analysis.successes || overview.successes || []);
    const failureItems = filterSunbirdInsightItems(analysis.failures || overview.failures || []);
    const recommendationItems = filterSunbirdInsightItems(analysis.recommendations || overview.recommendations || []);
    const visibleLogs = (Array.isArray(data.logs) ? data.logs : []).filter(log => !isSunbirdTechnicalNoiseText(`${log?.message || ''} ${log?.eventType || ''}`));
    const visibleEvents = filterSunbirdInsightItems(overview.events || []);
    const sectionCards = [
        successItems.length ? `
            <article class="sunbird-report-section-card">
                <div class="sunbird-report-card-title"><span>What went well</span><small>${successItems.length} outcomes</small></div>
                <div class="sunbird-report-insight-list">
                    ${renderSunbirdReportInsightList(successItems, 'success', 'No confirmed successes yet.', 'successes')}
                </div>
            </article>
        ` : '',
        failureItems.length ? `
            <article class="sunbird-report-section-card">
                <div class="sunbird-report-card-title"><span>Failures and attention</span><small>${failureItems.length} items</small></div>
                <div class="sunbird-report-insight-list">
                    ${renderSunbirdReportInsightList(failureItems, 'failure', 'No failures were recorded.', 'problems')}
                </div>
            </article>
        ` : '',
        recommendationItems.length ? `
            <article class="sunbird-report-section-card">
                <div class="sunbird-report-card-title"><span>Recommended next actions</span><small>Prioritized</small></div>
                <div class="sunbird-report-insight-list">
                    ${renderSunbirdReportInsightList(recommendationItems, 'neutral', 'No actions are required.', 'recommendations')}
                </div>
            </article>
        ` : ''
    ].filter(Boolean).join('');
    content.innerHTML = `
        <div class="sunbird-report-hero-grid">
            <article class="sunbird-report-health-card tone-${getSunbirdReportScoreTone(summary.healthScore)}">
                <div class="sunbird-report-health-copy">
                    <span>Security health score</span>
                    <p>${escapeIdentityText(summary.status || 'Collecting evidence')}</p>
                </div>
                <div class="sunbird-report-health-ring" style="--report-score:${Math.max(0, Math.min(100, Number(summary.healthScore || 0)))}">
                    <i></i>
                    <span>${Number(summary.healthScore || 0)}%</span>
                </div>
            </article>

            <article class="sunbird-report-ai-card">
                <div class="sunbird-report-card-title"><span><i class="fas fa-sparkles"></i> Executive brief</span><small>Latest enterprise synthesis</small></div>
                ${formatSunbirdExecutiveSummaryHtml(analysis.executiveSummary || '')}
                <div class="sunbird-report-ai-stats">
                    <span><strong>${Number(summary.failures || 0)}</strong> failures</span>
                    <span><strong>${Number(summary.successes || 0)}</strong> successes</span>
                    <span><strong>${Number(summary.totalEvents || 0)}</strong> events</span>
                </div>
            </article>

            <article class="sunbird-report-automation-card">
                <div class="sunbird-report-card-title"><span><i class="fas fa-clock-rotate-left"></i> Automation</span><b class="${settings.lastHourlyAutomationStatus && !String(settings.lastHourlyAutomationStatus).startsWith('failed') ? 'active' : ''}">${settings.lastHourlyAutomationStatus || 'Awaiting first run'}</b></div>
                <div class="sunbird-report-schedule-row"><span>Collection</span><strong>Every hour</strong></div>                <div class="sunbird-report-schedule-row"><span>Time zone</span><strong>${escapeIdentityText(settings.timeZoneLabel || 'SAST (UTC+02:00)')}</strong></div>
                <div class="sunbird-report-schedule-row"><span>Last automation</span><strong>${escapeIdentityText(formatSunbirdReportDate(settings.lastHourlyAutomationAt, true))}</strong></div>
                <div class="sunbird-report-schedule-row"><span>Latest status</span><strong>${escapeIdentityText(settings.lastHourlyAutomationStatus || 'No completed hourly run yet')}</strong></div>
                ${settings.lastHourlyAutomationRunId ? `<p class="sunbird-report-delivery-note">Run #${escapeIdentityText(settings.lastHourlyAutomationRunId)} · Snapshot #${escapeIdentityText(settings.lastHourlyAutomationSnapshotId || '—')} · Report #${escapeIdentityText(settings.lastHourlyAutomationReportId || '—')}${settings.lastHourlyAutomationMessage ? `<br>${escapeIdentityText(settings.lastHourlyAutomationMessage)}` : ''}</p>` : ''}
                <div class="sunbird-report-schedule-row"><span>Delivery</span><strong>Friday, ${String(settings.deliveryHour || 8).padStart(2, '0')}:00 SAST</strong></div>
                 <p class="sunbird-report-delivery-note">Each successful hourly run creates a PDF and sends its result to the automation recipient. Friday delivery remains available for the chosen client recipient.</p>
                <label class="sunbird-report-email-field">
                    <span>Chosen PDF recipient</span>
                    <input id="sunbird-report-recipient" type="email" multiple placeholder="name@sunbird.eu" value="${escapeIdentityText(settings.recipientEmail || '')}">
                </label>
                <div class="sunbird-report-setting-actions">
                    <label><input id="sunbird-report-weekly-enabled" type="checkbox" ${settings.weeklyEnabled ? 'checked' : ''}> Weekly email</label>
                    <button type="button" onclick="window.saveSunbirdReportSettings()">Save</button>
                </div>
            </article>
        </div>

        ${renderSunbirdReportValuePanel(data, evidenceBuckets)}

    ${renderSunbirdReportVisualPanel(data, evidenceBuckets)}

        ${renderSunbirdReportDomainBreakdown(data)}

        ${sectionCards ? `<div class="sunbird-report-main-grid">${sectionCards}</div>` : ''}

        <section class="sunbird-id-table-section sunbird-report-table-section">
            <div class="sunbird-report-table-heading">
                <div><h3>Report history</h3><p>Daily evidence snapshots, weekly reports, and on-demand PDFs since activation.</p></div>
                <span>Active since ${escapeIdentityText(formatSunbirdReportDate(settings.activeSince))}</span>
            </div>
            <div class="sunbird-id-table-wrap">
                <table class="sunbird-id-table sunbird-report-history-table">
                    <thead><tr><th>Type</th><th>From</th><th>To</th><th>Health</th><th>Failures</th><th>Delivery</th><th>File</th></tr></thead>
                    <tbody>${renderSunbirdReportHistoryRows(data.reports || [])}</tbody>
                </table>
            </div>
        </section>

        ${visibleLogs.length ? `<section class="sunbird-report-log-section">
            <div class="sunbird-report-table-heading">
                <div><h3>Report automation log</h3><p>Collection, generation, downloads, settings, and email delivery activity.</p></div>
                <span>${Number(visibleLogs.length || 0)} log entries</span>
            </div>
            <div class="sunbird-report-log-list">${renderSunbirdReportAuditRows(visibleLogs)}</div>
        </section>` : ''}

        ${visibleEvents.length ? `<section class="sunbird-id-table-section sunbird-report-table-section">
            <div class="sunbird-report-table-heading">
                <div><h3>Evidence timeline</h3><p>What happened, when it happened, and where it came from.</p></div>
                <span>${escapeIdentityText(formatSunbirdReportDate(data.range?.start))} - ${escapeIdentityText(formatSunbirdReportDate(data.range?.end))}</span>
            </div>
            <div class="sunbird-id-table-wrap">
                <table class="sunbird-id-table sunbird-report-events-table">
                    <thead><tr><th>Time</th><th>Severity</th><th>Event</th><th>Source</th><th>Status</th><th>User / asset</th></tr></thead>
                    <tbody>${renderSunbirdReportEventRows(visibleEvents)}</tbody>
                </table>
            </div>
        </section>` : ''}
    `;
}

function setupSunbirdReportsDashboard() {
    document.getElementById('sunbird-reports-back')?.addEventListener('click', goBackToProjects);
    document.querySelectorAll('[data-report-range]').forEach(button => {
        button.addEventListener('click', async () => {
            document.querySelectorAll('[data-report-range]').forEach(item => item.classList.remove('active'));
            button.classList.add('active');
            sunbirdReportsRange = button.dataset.reportRange || '30d';
            await loadSunbirdReportsDashboardData(true);
        });
    });
    document.getElementById('sunbird-report-intelligent-btn')?.addEventListener('click', () => {
        window.getIntelligentReport();
    });
}

async function loadSunbirdReportsDashboardData(forceRefresh = false) {
    const requestId = ++sunbirdReportsRequestId;
    const content = document.getElementById('sunbird-report-center-content');
    const lastKnownData = cachedSunbirdReportsData;
    // Keep the usable report view on screen while a fresh PDF/report refresh is queued.
    // Replacing it with a loader made a transient backend delay look like a broken card.
    if (content && forceRefresh && !lastKnownData) content.innerHTML = renderSunbirdPremiumLoader('Refreshing report evidence');
    try {
        const data = await fetchSunbirdReportsData(sunbirdReportsRange, forceRefresh);
        if (requestId !== sunbirdReportsRequestId) return;
        renderSunbirdReportsCenter(data);
    } catch (error) {
        if (requestId !== sunbirdReportsRequestId || !content) return;
        if (lastKnownData) {
            cachedSunbirdReportsData = lastKnownData;
            renderSunbirdReportsCenter(lastKnownData);
            showNotification(`The latest report refresh is delayed. Showing the last verified report: ${error.message}`, false);
            return;
        }
        content.innerHTML = `<div class="sunbird-report-load-error"><i class="fas fa-circle-exclamation"></i><p>${escapeIdentityText(error.message)}</p><button type="button" onclick="window.loadSunbirdReportsDashboardData(true)">Try again</button></div>`;
    }
}
function openSunbirdReportsDashboard() {
    const dashboardView = document.getElementById('dashboard-view');
    const projectsView = document.getElementById('projects-view');
    if (!dashboardView) return;
    if (projectsView) projectsView.style.display = 'none';
    dashboardView.style.display = 'block';
    dashboardView.style.visibility = 'visible';
    dashboardView.style.opacity = '1';
    [
        'sunbird-identity-active',
        'sunbird-device-active',
        'sunbird-email-active',
        'sunbird-security-active',
        'sunbird-backup-active',
        'sunbird-applications-active'
    ].forEach(className => dashboardView.classList.remove(className));
    dashboardView.classList.add('sunbird-reports-active');
    captureDashboardViewHTML();
    dashboardView.innerHTML = renderSunbirdReportsShell();
    setupSunbirdReportsDashboard();
    loadSunbirdReportsDashboardData(false);
}

window.generateSunbirdReport = async function(range = sunbirdReportsRange, downloadWhenReady = true, includeAi = true) {
    const button = document.getElementById(includeAi ? 'sunbird-report-intelligent-btn' : 'sunbird-report-generate-btn')
        || document.getElementById('sunbird-report-intelligent-btn');
    const original = button?.innerHTML;
    if (button) {
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Building report';
    }
    showPdfLoadingOverlay(includeAi ? 'Building your report...' : 'Building your report...');
    try {
        console.log(`[Reports] Starting on-demand ${range} report generation. AI included: ${includeAi}`);
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 120000);
        let response;
        let data;
        try {
            response = await fetch('/api/sunbird/reports/generate', {
                method: 'POST',
                headers: getSunbirdReportHeaders(),
                body: JSON.stringify({ range, includeAi }),
                signal: controller.signal
            });
            const responseBody = await response.text();
            try {
                data = responseBody ? JSON.parse(responseBody) : {};
            } catch (_) {
                throw new Error(response.ok ? 'Report generation returned an invalid response.' : `Report generation failed (${response.status}).`);
            }
        } catch (requestError) {
            if (requestError.name === 'AbortError') throw new Error('Report generation is still running. The existing report remains available; please try again shortly.');
            throw requestError;
        } finally {
            clearTimeout(timeout);
        }        if (!response.ok || !data.success) {
            console.error('[Reports] Generation failed:', response.status, data);
            throw new Error(data.message || `Report generation failed (${response.status})`);
        }
        console.log(`[Reports] Report #${data.report.id} generated and saved to history.`);
        // Retain the last verified view as a fallback while the new report is indexed.
        const statusMessage = 'Report generated and downloading';
        showNotification(downloadWhenReady ? statusMessage : 'Report generated and saved', true);
        if (downloadWhenReady) await window.downloadSunbirdReportPdf(data.report.id);
        if (document.getElementById('sunbird-reports-dashboard')) await loadSunbirdReportsDashboardData(true);
        if (isSunbirdBillingViewActive('reports')) await renderSunbirdReportsView(true);
    } catch (error) {
        showNotification(error.message || 'Report generation failed', false);
    } finally {
        hidePdfLoadingOverlay();
        if (button) {
            button.disabled = false;
            button.innerHTML = original;
        }
    }
};

// Shortcut handler for the new Get intelligent report button
window.getIntelligentReport = async function() {
    try {
        const range = sunbirdReportsRange || '30d';
        showNotification('Requesting enhanced report — this may take a moment', true);
        await window.generateSunbirdReport(range, true, true);
    } catch (err) {
        showNotification(err.message || 'Could not request intelligent report', false);
    }
};

window.downloadSunbirdReportPdf = async function(reportId) {
    showPdfLoadingOverlay('Preparing your PDF for download...');
    try {
        console.log(`[Reports] Requesting PDF download for report #${reportId}.`);
        const response = await fetch(`/api/sunbird/reports/${encodeURIComponent(reportId)}/pdf`, {
            headers: getSunbirdReportHeaders()
        });
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.message || 'PDF download failed');
        }
        const blob = await response.blob();
        if (!blob || blob.size === 0) {
            throw new Error('Received empty PDF from server');
        }
        console.log(`[Reports] PDF response content type: ${response.headers.get('Content-Type')}, size: ${blob.size}`);
        const disposition = response.headers.get('Content-Disposition') || '';
        const filenameMatch = disposition.match(/filename="([^"]+)"/i);
        const filename = filenameMatch?.[1] || `StackCTRL-Report-${reportId}.pdf`;
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.style.display = 'none';
        document.body.appendChild(link);
        if (typeof MouseEvent === 'function') {
            link.dispatchEvent(new MouseEvent('click'));
        } else {
            link.click();
        }
        setTimeout(() => {
            link.remove();
            URL.revokeObjectURL(url);
        }, 15000);
        console.log(`[Reports] Download started: ${filename}`);
        hidePdfLoadingOverlay();
        showNotification(`Report ${filename} downloading...`, true);
    } catch (error) {
        console.error('[Reports] PDF download failed:', error);
        hidePdfLoadingOverlay();
        showNotification(error.message || 'PDF download failed', false);
    }
};

window.saveSunbirdReportSettings = async function() {
    const recipient = document.getElementById('sunbird-report-recipient')?.value || '';
    const weeklyEnabled = Boolean(document.getElementById('sunbird-report-weekly-enabled')?.checked);
    const recipients = recipient.split(/[;,]/).map(item => item.trim()).filter(Boolean);
    const invalidRecipients = recipients.filter(item => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(item));
    if (invalidRecipients.length) {
        showNotification('Please enter valid report recipient email addresses', false);
        return;
    }
    if (weeklyEnabled && recipients.length === 0) {
        showNotification('Choose at least one report recipient before enabling weekly email', false);
        return;
    }
    try {
        console.log('[Reports] Saving automation settings:', { recipient, weeklyEnabled });
        const response = await fetch('/api/sunbird/reports/settings', {
            method: 'PUT',
            headers: getSunbirdReportHeaders(),
            body: JSON.stringify({ recipientEmail: recipient, weeklyEnabled })
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            console.error('[Reports] Settings update failed:', response.status, data);
            throw new Error(data.message || `Settings could not be saved (${response.status})`);
        }
        // Retain the last verified view as a fallback while the new report is indexed.
        showNotification('Report automation settings saved', true);
        await loadSunbirdReportsDashboardData(true);
    } catch (error) {
        showNotification(error.message || 'Settings could not be saved', false);
    }
};

window.openSunbirdReportsDashboard = openSunbirdReportsDashboard;
window.renderSunbirdReportsView = renderSunbirdReportsView;
window.loadSunbirdReportsDashboardData = loadSunbirdReportsDashboardData;
window.openSunbirdReportEvidence = openSunbirdReportEvidence;
window.closeSunbirdReportEvidence = closeSunbirdReportEvidence;
window.setSunbirdReportDomainFilter = setSunbirdReportDomainFilter;
window.openSunbirdDomainFindingEvidence = openSunbirdDomainFindingEvidence;
window.closeSunbirdDomainFindingEvidence = closeSunbirdDomainFindingEvidence;

async function fetchBackupCardData() {
    const project = mockProjects.find(p => p.isBackupRecoveryCard);
    if (!project || !isSunbirdUser()) return;
    try {
        const data = await fetchSunbirdBackupRecoveryData();
        cachedSunbirdBackupData = normalizeSunbirdBackupData(data);
        saveSunbirdBackupSnapshot(cachedSunbirdBackupData);
        updateBackupProjectCardFromData(cachedSunbirdBackupData);
    } catch (error) {
        console.warn('[Backup Card] Unable to load cached backup data:', error.message);
    }
}

async function renderSunbirdSecurityAlertsView(forceRefresh = false) {
    const billingCard = document.getElementById('billing-card');
    if (!billingCard) return;

    try {
        if (!isSunbirdBillingViewActive('security')) return;
        if (!cachedSunbirdSecurityData) {
            billingCard.innerHTML = `
                <div class="sunbird-panel-view">
                    <div class="billing-card-header">
                        <i class="fas fa-shield-alt"></i>
                        <h3>Security Alerts</h3>
                    </div>
                    <div class="sunbird-mini-stats">
                        <div class="sunbird-mini-stat">
                            <span>High Severity Alerts</span>
                            <strong>0</strong>
                        </div>
                        <div class="sunbird-mini-stat">
                            <span>Security Incidents</span>
                            <strong>0</strong>
                        </div>
                    </div>
                    <div class="sunbird-section-container">
                        <h4 class="sunbird-section-heading">
                            <i class="fas fa-exclamation-triangle"></i> Security Incidents
                        </h4>
                        <div class="sunbird-incidents-table-wrap">
                            <table class="sunbird-incidents-table">
                                <thead>
                                    <tr>
                                        <th>Incident Name</th>
                                        <th>Severity</th>
                                        <th>Status</th>
                                        <th>Assigned To</th>
                                    </tr>
                                </thead>
                                <tbody><tr><td colspan="4" class="sunbird-empty-row">Refreshing latest security evidence...</td></tr></tbody>
                            </table>
                        </div>
                    </div>
                    <div class="sunbird-section-container">
                        <h4 class="sunbird-section-heading">
                            <i class="fas fa-stream"></i> Real-Time Activity Feed
                        </h4>
                        <div class="sunbird-activity-feed">
                            <div class="sunbird-activity-empty">Refreshing latest activity</div>
                        </div>
                    </div>
                    ${renderSunbirdFullDashboardButton('security')}
                </div>
            `;
            ensureSunbirdBillingCardDimensions();
            syncSunbirdLeftMenuHeight();
        }

        if (forceRefresh || !cachedSunbirdSecurityData) {
            cachedSunbirdSecurityData = await fetchSunbirdSecurityEventsData();
        }

        const data = cachedSunbirdSecurityData;
        const incidents = (data.incidents || []).slice(0, 10);
        const highSeverityAlerts = data.summary?.highSeverityAlerts || 0;
        const activeIncidents = data.summary?.activeIncidents || 0;

        const rowsHtml = incidents.length
            ? incidents.map(incident => `
                <tr>
                    <td>${incident.displayName || 'Unknown Incident'}</td>
                    <td><span class="sunbird-severity-pill ${String(incident.severity || 'medium').toLowerCase()}">${incident.severity || 'medium'}</span></td>
                    <td>${incident.status || 'active'}</td>
                    <td>${incident.assignedTo || 'Unassigned'}</td>
                </tr>
            `).join('')
            : '<tr><td colspan="4" class="sunbird-empty-row">No incidents found</td></tr>';

        if (!isSunbirdBillingViewActive('security')) return;
        
        // Build activity feed items from the activityFeed array sent by backend
        // This includes incidents, alerts, and suspicious sign-ins
        const activityFeed = cachedSunbirdSecurityData.activityFeed || [];
        console.log('[Sunbird Security Alerts] 📋 Activity Feed Items:', activityFeed.length);
        
        const activityFeedHtml = activityFeed.length
            ? activityFeed.map(item => {
                const severityColor = item.severity === 'critical' ? '#ff6b6b' : item.severity === 'high' ? '#ff9f40' : '#ffc107';
                const itemIcon = /cloudflare/i.test(`${item.type || ''} ${item.source || ''}`) ? 'CF' : item.type === 'incident' ? '🔴' : item.type === 'alert' ? '⚠️' : item.type === 'signin' ? '🔑' : '•';
                return `
                    <div class="sunbird-activity-item">
                        <span class="sunbird-activity-severity" style="background-color: ${severityColor}"></span>
                        <div class="sunbird-activity-content">
                            <p class="sunbird-activity-title">${itemIcon} ${item.message || 'Activity detected'}</p>
                            <p class="sunbird-activity-meta">${new Date(item.timestamp).toLocaleTimeString()} • ${item.type}</p>
                        </div>
                    </div>
                `;
            }).join('')
            : '<div class="sunbird-activity-empty">No recent activity</div>';
        
        console.log('[Sunbird Security Alerts] 📊 Data prepared - High Severity: %d, Active Incidents: %d, Total Incidents: %d, Activity Items: %d', highSeverityAlerts, activeIncidents, incidents.length, activityFeed.length);
        
        billingCard.innerHTML = `
            <div class="sunbird-panel-view">
                <div class="billing-card-header">
                    <i class="fas fa-shield-alt"></i>
                    <h3>Security Alerts</h3>
                </div>
                <div class="sunbird-mini-stats">
                    <div class="sunbird-mini-stat">
                        <span>High Severity Alerts</span>
                        <strong>${highSeverityAlerts}</strong>
                    </div>
                    <div class="sunbird-mini-stat">
                        <span>Security Incidents</span>
                        <strong>${activeIncidents}</strong>
                    </div>
                </div>
                
                <!-- Security Incidents Table Section -->
                <div class="sunbird-section-container">
                    <h4 class="sunbird-section-heading">
                        <i class="fas fa-exclamation-triangle"></i> Security Incidents
                    </h4>
                    <div class="sunbird-incidents-table-wrap">
                        <table class="sunbird-incidents-table">
                            <thead>
                                <tr>
                                    <th>Incident Name</th>
                                    <th>Severity</th>
                                    <th>Status</th>
                                    <th>Assigned To</th>
                                </tr>
                            </thead>
                            <tbody>${rowsHtml}</tbody>
                        </table>
                    </div>
                </div>
                
                <!-- Real-Time Activity Feed Section -->
                <div class="sunbird-section-container">
                    <h4 class="sunbird-section-heading">
                        <i class="fas fa-stream"></i> Real-Time Activity Feed
                    </h4>
                    <div class="sunbird-activity-feed">
                        ${activityFeedHtml}
                    </div>
                </div>
                
                ${renderSunbirdFullDashboardButton('security')}
            </div>
            ${renderSunbirdPanelProviderBadge()}
        `;
    } catch (error) {
        console.error('[Sunbird Security Alerts] Error:', error);
        if (!isSunbirdBillingViewActive('security')) return;
        if (billingCard.querySelector('.sunbird-panel-view')) {
            ensureSunbirdBillingCardDimensions();
            syncSunbirdLeftMenuHeight();
            return;
        }
        billingCard.innerHTML = `
            <div class="sunbird-panel-view">
                <div class="billing-card-header">
                    <i class="fas fa-shield-alt"></i>
                    <h3>Security Alerts</h3>
                </div>
                <p class="sunbird-panel-error">Unable to load security alerts right now.</p>
                ${renderSunbirdFullDashboardButton('security')}
            </div>
        `;
    } finally {
        ensureSunbirdBillingCardDimensions();
        syncSunbirdLeftMenuHeight();
    }
}

async function renderSunbirdBackupRecoveryView(forceRefresh = false) {
    const billingCard = document.getElementById('billing-card');
    if (!billingCard) return;

    try {
        if (!isSunbirdBillingViewActive('backup')) return;
        billingCard.innerHTML = renderSunbirdPremiumLoader('Loading backup and recovery');

        if (forceRefresh || !cachedSunbirdBackupData) {
            cachedSunbirdBackupData = await fetchSunbirdBackupRecoveryData();
        }

        const data = cachedSunbirdBackupData;
        updateBackupProjectCardFromData(data);
        const summary = data.summary || {};
        const byService = data.storage?.byService || {};

        if (!isSunbirdBillingViewActive('backup')) return;
        billingCard.innerHTML = `
            <div class="sunbird-panel-view">
                <div class="billing-card-header">
                    <i class="fas fa-hdd"></i>
                    <h3>Backup & Recovery</h3>
                </div>

                <div class="sunbird-mini-stats">
                    <div class="sunbird-mini-stat">
                        <span>Total Storage</span>
                        <strong>${summary.totalStorageGB || 0} GB</strong>
                    </div>
                    <div class="sunbird-mini-stat">
                        <span>Active Users</span>
                        <strong>${summary.activeUsersCount || 0}</strong>
                    </div>
                </div>

                <div class="sunbird-section-title">Storage by Service</div>
                <div class="sunbird-storage-list">
                    <div class="sunbird-storage-row"><span>OneDrive</span><strong>${byService.onedrive || 0} GB</strong></div>
                    <div class="sunbird-storage-row"><span>SharePoint</span><strong>${byService.sharepoint || 0} GB</strong></div>
                    <div class="sunbird-storage-row"><span>Exchange</span><strong>${byService.exchange || 0} GB</strong></div>
                </div>
                ${renderSunbirdFullDashboardButton('backup')}
            </div>
            ${renderSunbirdPanelProviderBadge()}
        `;
    } catch (error) {
        console.error('[Sunbird Backup Recovery] Error:', error);
        if (!isSunbirdBillingViewActive('backup')) return;
        billingCard.innerHTML = `
            <div class="sunbird-panel-view">
                <div class="billing-card-header">
                    <i class="fas fa-hdd"></i>
                    <h3>Backup & Recovery</h3>
                </div>
                <p class="sunbird-panel-error">Unable to load backup and recovery data right now.</p>
                ${renderSunbirdFullDashboardButton('backup')}
            </div>
        `;
    } finally {
        ensureSunbirdBillingCardDimensions();
        syncSunbirdLeftMenuHeight();
    }
}

async function renderSunbirdApplicationsView(forceRefresh = false) {
    const billingCard = document.getElementById('billing-card');
    if (!billingCard) return;

    try {
        if (!isSunbirdBillingViewActive('applications')) return;
        if (forceRefresh || !sunbirdApplicationsPayload) {
            billingCard.innerHTML = renderSunbirdPremiumLoader('Loading applications access');
        } else {
            billingCard.innerHTML = renderSunbirdApplicationsBillingMarkup(buildSunbirdApplicationsModel());
        }

        if (forceRefresh || !sunbirdApplicationsPayload) {
            await fetchApplicationsData();
        }
        if (!isSunbirdBillingViewActive('applications')) return;
        billingCard.innerHTML = renderSunbirdApplicationsBillingMarkup(buildSunbirdApplicationsModel());
    } catch (error) {
        console.error('[Sunbird Applications View] Error:', error);
        if (!isSunbirdBillingViewActive('applications')) return;
        billingCard.innerHTML = `
            <div class="sunbird-panel-view">
                <div class="billing-card-header">
                    <i class="fas fa-cubes"></i>
                    <h3>Applications & Access</h3>
                </div>
                <p class="sunbird-panel-error">Unable to load applications data right now.</p>
                ${renderSunbirdFullDashboardButton('applications')}
            </div>
        `;
    } finally {
        ensureSunbirdBillingCardDimensions();
        syncSunbirdLeftMenuHeight();
    }
}

function renderSunbirdApplicationsBillingMarkup(model) {
    const topApps = model.applications
        .slice()
        .sort((a, b) => (b.userCount || 0) - (a.userCount || 0))
        .slice(0, 6);
    const riskRows = [
        { label: 'External apps', value: model.summary.externalApplications, tone: model.summary.externalApplications ? 'bad' : 'good' },
        { label: 'High risk apps', value: model.summary.highRiskApps, tone: model.summary.highRiskApps ? 'bad' : 'good' },
        { label: 'Excessive permissions', value: model.summary.excessivePermissionApps, tone: model.summary.excessivePermissionApps ? 'warn' : 'good' },
        { label: 'High access apps', value: model.summary.highAccessApps, tone: model.summary.highAccessApps ? 'warn' : 'good' }
    ];
    const topAppsHtml = topApps.length ? topApps.map(app => `
        <button type="button" class="sunbird-storage-row sunbird-app-preview-row" onclick='openSunbirdApplicationAppEvidence(${JSON.stringify(app.id)})'>
            <span>${escapeIdentityText(app.name || 'Unknown App')} <small>${escapeIdentityText(app.type || 'Unknown')}</small></span>
            <strong>${app.userCount || 0} users</strong>
        </button>
    `).join('') : '<div class="sunbird-empty-row" style="padding: 16px;">No cached application inventory found yet</div>';

    return `
        <div class="sunbird-panel-view">
            <div class="billing-card-header">
                <i class="fas fa-cubes"></i>
                <h3>Applications & Access</h3>
            </div>

            <div class="sunbird-mini-stats sunbird-app-preview-stats">
                <div class="sunbird-mini-stat"><span>Total Apps</span><strong>${model.summary.totalApplications || 0}</strong></div>
                <div class="sunbird-mini-stat"><span>External</span><strong>${model.summary.externalApplications || 0}</strong></div>
                <div class="sunbird-mini-stat"><span>High Risk</span><strong>${model.summary.highRiskApps || 0}</strong></div>
                <div class="sunbird-mini-stat"><span>Score</span><strong>${model.governanceScore || 100}%</strong></div>
            </div>

            <div class="sunbird-app-preview-scroll">
                <div class="sunbird-section-title">Access risk summary</div>
                <div class="sunbird-app-risk-grid">
                    ${riskRows.map(row => `<div class="sunbird-app-risk-mini tone-${row.tone}"><span>${escapeIdentityText(row.label)}</span><strong>${row.value || 0}</strong></div>`).join('')}
                </div>

                <div class="sunbird-section-title">Top apps by assigned access</div>
                <div class="sunbird-storage-list sunbird-app-preview-list">
                    ${topAppsHtml}
                </div>
            </div>

            ${renderSunbirdFullDashboardButton('applications')}
        </div>
        ${renderSunbirdPanelProviderBadge()}
    `;
}

function renderSunbirdPremiumLoader(message) {
    return `
        <div class="sunbird-panel-view sunbird-panel-loader-wrap">
            <div class="sunbird-premium-loader" aria-live="polite">
                <div class="sunbird-stack-loader-shell">
                    <div class="sunbird-stack-loader-ring"></div>
                    <img src="Images/Logos/StackCTRLLoading.png" alt="" class="sunbird-stack-loader-logo">
                </div>
                <p class="sunbird-panel-loading">${message}</p>
            </div>
        </div>
    `;
}

let sunbirdMenuResizeObserver = null;

const SUNBIRD_MENU_LABELS = {
    security: { label: 'Security Alerts', icon: 'fas fa-shield-alt' },
    operations: { label: 'Operations', icon: 'fas fa-tasks' },
    backup: { label: 'Backup & Recovery', icon: 'fas fa-hdd' },
    reports: { label: 'Reports', icon: 'fas fa-chart-line' },
    risks: { label: 'Risks', icon: 'fas fa-triangle-exclamation' },
    architecture: { label: 'Architecture', icon: 'fas fa-sitemap' },
    sla: { label: 'SLA', icon: 'fas fa-handshake' },
    applications: { label: 'Applications', icon: 'fas fa-cubes' },
        billing: { label: 'Billing Statement', icon: 'fas fa-file-invoice' }
};

function updateSunbirdMobileMenuCurrent(menuItem = sunbirdBillingMenuSelection) {
    const currentButton = document.querySelector('.sunbird-menu-current');
    if (!currentButton) return;

    const meta = SUNBIRD_MENU_LABELS[menuItem] || SUNBIRD_MENU_LABELS.security;
    currentButton.innerHTML = `
        <span class="sunbird-menu-current-main">
            <i class="${meta.icon}"></i>
            <span>${meta.label}</span>
        </span>
        <i class="fas fa-chevron-down sunbird-menu-current-chevron" aria-hidden="true"></i>
    `;
    currentButton.setAttribute('aria-label', `Open Control Center menu. Current view: ${meta.label}`);
}

window.toggleSunbirdMobileMenu = function() {
    const leftMenu = document.querySelector('.sunbird-left-menu');
    if (!leftMenu) return;
    const isOpen = leftMenu.classList.toggle('is-open');
    const currentButton = leftMenu.querySelector('.sunbird-menu-current');
    if (currentButton) currentButton.setAttribute('aria-expanded', String(isOpen));
};

function syncSunbirdLeftMenuHeight() {
    if (!isSunbirdUser()) return;

    const billingCard = document.getElementById('billing-card');
    const leftMenu = document.querySelector('.sunbird-left-menu');
    const wrapper = leftMenu?.parentElement;
    if (!billingCard || !leftMenu || !wrapper) return;

    if (window.matchMedia('(max-width: 768px)').matches) {
        leftMenu.style.height = 'auto';
        leftMenu.style.top = 'auto';
        wrapper.style.removeProperty('--sunbird-connector-y');
        return;
    }

    // Keep the menu sized to its content, but vertically centered
    // to the billing card for a "control rail" look.
    const billingRect = billingCard.getBoundingClientRect();
    const wrapperRect = wrapper.getBoundingClientRect();
    const billingTopOffset = billingRect.top - wrapperRect.top;

    if (billingRect.height > 0) {
        // Ensure the menu hugs its items (no forced height).
        leftMenu.style.height = 'auto';

        // Measure after letting height auto-apply.
        const menuRect = leftMenu.getBoundingClientRect();

        // Align menu center to billing card center.
        const billingCenterY = billingTopOffset + (billingRect.height / 2);
        let desiredTop = billingCenterY - (menuRect.height / 2);

        // Clamp within wrapper.
        const maxTop = Math.max(0, wrapperRect.height - menuRect.height);
        desiredTop = Math.max(0, Math.min(desiredTop, maxTop));

        leftMenu.style.top = `${desiredTop}px`;

        // Keep connector aligned to billing card center.
        wrapper.style.setProperty('--sunbird-connector-y', `${billingCenterY}px`);
    }
}

// Initialize Sunbird left menu (called during dashboard initialization)
function initializeSunbirdLeftMenu() {
    if (!isSunbirdUser()) return;
    
    const dashboardCardsSection = document.querySelector('.dashboard-cards-section');
    if (!dashboardCardsSection) return;
    
    // Check if wrapper already exists
    const existingWrapper = dashboardCardsSection.parentElement;
    if (existingWrapper.classList.contains('dashboard-with-menu')) return;
    
    // Create wrapper
    const wrapper = document.createElement('div');
    wrapper.className = 'dashboard-with-menu';
    
    // Create left menu
    const leftMenu = document.createElement('div');
    leftMenu.className = 'sunbird-left-menu';
    leftMenu.innerHTML = `
        <div class="sunbird-menu-heading">Control Center</div>
        <button class="sunbird-menu-current" type="button" aria-expanded="false" onclick="window.toggleSunbirdMobileMenu()"></button>
        <button class="sunbird-menu-item" type="button" data-menu="security" onclick="window.switchBillingMenu('security')">
            <i class="fas fa-shield-alt"></i><span>Security Alerts</span>
        </button>
        <button class="sunbird-menu-item" type="button" data-menu="operations" onclick="window.switchBillingMenu('operations')">
            <i class="fas fa-tasks"></i><span>Operations</span>
        </button>
        <button class="sunbird-menu-item" type="button" data-menu="backup" onclick="window.switchBillingMenu('backup')">
            <i class="fas fa-hdd"></i><span>Backup & Recovery</span>
        </button>
        <button class="sunbird-menu-item" type="button" data-menu="reports" onclick="window.switchBillingMenu('reports')">
            <i class="fas fa-chart-line"></i><span>Reports</span>
        </button>
        <button class="sunbird-menu-item" type="button" data-menu="risks" onclick="window.switchBillingMenu('risks')">
            <i class="fas fa-triangle-exclamation"></i><span>Risks</span>
        </button>
        <button class="sunbird-menu-item" type="button" data-menu="architecture" onclick="window.switchBillingMenu('architecture')">
            <i class="fas fa-sitemap"></i><span>Architecture</span>
        </button>
        <button class="sunbird-menu-item" type="button" data-menu="sla" onclick="window.switchBillingMenu('sla')">
            <i class="fas fa-handshake"></i><span>SLA</span>
        </button>
        <button class="sunbird-menu-item" type="button" data-menu="applications" onclick="window.switchBillingMenu('applications')">
            <i class="fas fa-cubes"></i><span>Applications</span>
        </button>
        <button class="sunbird-menu-item" type="button" data-menu="billing" onclick="window.switchBillingMenu('billing')">
            <i class="fas fa-file-invoice"></i><span>Billing Statement</span>
        </button>
    `;
    
    // Insert wrapper before dashboard-cards-section
    dashboardCardsSection.parentElement.insertBefore(wrapper, dashboardCardsSection);
    
    // Add menu and dashboard to wrapper
    wrapper.appendChild(leftMenu);
    wrapper.appendChild(dashboardCardsSection);

    window.switchBillingMenu(sunbirdBillingMenuSelection);
    syncSunbirdLeftMenuHeight();

    // Keep menu height aligned with billing card when content changes.
    if ('ResizeObserver' in window) {
        const billingCard = document.getElementById('billing-card');
        if (billingCard) {
            if (sunbirdMenuResizeObserver) {
                sunbirdMenuResizeObserver.disconnect();
            }
            sunbirdMenuResizeObserver = new ResizeObserver(() => {
                syncSunbirdLeftMenuHeight();
            });
            sunbirdMenuResizeObserver.observe(billingCard);
        }
    }
}

function initializeGovernanceCard() {
    const governanceCard = document.getElementById('governance-card');
    if (!governanceCard) return;
    syncNonSunbirdBlurGatedPanels();
    
    const client = isSunbirdUser() ? 'sunbird' : 'default';

    if (client === 'sunbird') {
        ensureSunbirdGovernanceEvidenceModal();
        const cached = getSunbirdCachedCardData(SUNBIRD_GOVERNANCE_CACHE_KEY, { allowStale: true });
        if (cached?.rows) {
            window.sunbirdGovernanceSource = cached.source || {};
            renderSunbirdGovernanceCard(governanceCard, cached.rows);
        } else {
            renderSunbirdGovernanceCard(governanceCard, getSunbirdGovernanceInstantRows());
        }
        ensureSunbirdBillingCardDimensions();
        syncSunbirdLeftMenuHeight();
        fetchSunbirdGovernanceData(governanceCard);
        return;
    }

    let governanceData = [
        'Change Management',
        'End-user awareness',
        'Configurations',
        'Site documentation'
    ];
    
    const governanceHtml = governanceData.map(item => `
        <div class="governance-item">
            <i class="fas fa-check-circle" style="color: #28a745;"></i>
            <span class="governance-item-text">${item}</span>
        </div>
    `).join('');
    
    governanceCard.innerHTML = `
        <div class="governance-card-header">
            <i class="fas fa-shield-alt"></i>
            <h3>Governance & Compliance</h3>
        </div>
        <div class="governance-content">
            ${governanceHtml}
        </div>
    `;
}

function getSunbirdCachedCardData(cacheKey, options = {}) {
    try {
        const raw = localStorage.getItem(getSunbirdScopedCardCacheKey(cacheKey));
        if (!raw) return null;
        const cached = JSON.parse(raw);
        if (!cached?.savedAt) return null;
        if (!options.allowStale && Date.now() - cached.savedAt > SUNBIRD_CARD_CACHE_TTL_MS) return null;
        return cached.payload || null;
    } catch (error) {
        return null;
    }
}

function setSunbirdCachedCardData(cacheKey, payload) {
    try {
        localStorage.setItem(getSunbirdScopedCardCacheKey(cacheKey), JSON.stringify({ savedAt: Date.now(), payload }));
    } catch (error) {
        // Live API data is still rendered if browser storage is unavailable.
    }
}

function getSunbirdScopedCardCacheKey(cacheKey) {
    try {
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        return `${cacheKey}:${String(user.email || user.id || user.access || 'sunbird').toLowerCase()}`;
    } catch (error) {
        return `${cacheKey}:sunbird`;
    }
}

function getSunbirdGovernanceInstantRows() {
    return [
        {
            area: 'Access review',
            activity: 'Review users',
            source: 'Framework',
            frequency: 'Quarterly',
            evidence: 'Latest governance evidence is refreshing in the background.',
            status: 'Pending'
        },
        {
            area: 'Admin review',
            activity: 'Review roles',
            source: 'Framework',
            frequency: 'Quarterly',
            evidence: 'Latest privileged role evidence is refreshing in the background.',
            status: 'Pending'
        }
    ];
}

function getSunbirdComplianceInstantControls() {
    return [
        {
            name: 'MFA on all accounts',
            area: 'Identity',
            insight: 'Live evidence refreshing',
            evidenceData: { status: 'Latest MFA evidence is refreshing in the background.' }
        },
        {
            name: 'Admin accounts limited',
            area: 'Identity',
            insight: 'Live evidence refreshing',
            evidenceData: { status: 'Latest privileged account evidence is refreshing in the background.' }
        }
    ];
}

function renderSunbirdGovernanceCard(governanceCard, rows) {
    const safeRows = Array.isArray(rows) ? rows : [];
    window.sunbirdGovernanceRows = safeRows;
    const rowsHtml = safeRows.length ? safeRows.map((row, index) => `
        <tr>
            <td>${escapeIdentityText(row.area || 'Governance')}</td>
            <td>
                <div class="sunbird-governance-activity-cell">${escapeIdentityText(row.activity || 'Review')}</div>
                <button class="sunbird-risk-view-btn sunbird-governance-evidence-btn" onclick="window.openSunbirdGovernanceEvidence(${index})">
                    View Evidence
                </button>
            </td>
            <td>${escapeIdentityText(getSunbirdGovernanceDisplaySource(row))}</td>
            <td>${escapeIdentityText(row.frequency || 'As required')}</td>
        </tr>
    `).join('') : '<tr><td colspan="4" class="sunbird-empty-row">No governance evidence available</td></tr>';

    governanceCard.innerHTML = `
        <div class="governance-card-header">
            <i class="fas fa-shield-alt"></i>
            <h3>Governance</h3>
        </div>
        <div class="governance-content sunbird-governance-content">
            <div class="sunbird-governance-table-wrap">
                <table class="sunbird-incidents-table sunbird-governance-table">
                    <thead>
                        <tr>
                            <th>Governance Area</th>
                            <th>Activity</th>
                            <th>Source</th>
                            <th>Frequency</th>
                        </tr>
                    </thead>
                    <tbody>${rowsHtml}</tbody>
                </table>
            </div>
        </div>
    `;
}

async function fetchSunbirdGovernanceData(governanceCard) {
    let renderedCached = false;
    try {
        const cached = getSunbirdCachedCardData(SUNBIRD_GOVERNANCE_CACHE_KEY, { allowStale: true });
        if (cached?.rows) {
            renderSunbirdGovernanceCard(governanceCard, cached.rows);
            window.sunbirdGovernanceSource = cached.source || {};
            renderedCached = true;
            ensureSunbirdBillingCardDimensions();
            syncSunbirdLeftMenuHeight();
        }

        const token = localStorage.getItem('authToken');
        const response = await fetch('/api/sunbird/governance', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) throw new Error('Failed to fetch governance data');
        const data = await response.json();
        const rows = Array.isArray(data.rows) ? data.rows : [];
        window.sunbirdGovernanceRows = rows;
        window.sunbirdGovernanceSource = {
            source: data.source || 'unknown',
            fetchedAt: data.fetchedAt,
            warning: data.warning
        };
        setSunbirdCachedCardData(SUNBIRD_GOVERNANCE_CACHE_KEY, { rows, source: window.sunbirdGovernanceSource });
        renderSunbirdGovernanceCard(governanceCard, rows);
        ensureSunbirdBillingCardDimensions();
        syncSunbirdLeftMenuHeight();
    } catch (error) {
        console.error('[Governance] Error:', error);
        if (renderedCached || governanceCard.querySelector('.sunbird-governance-table')) {
            ensureSunbirdBillingCardDimensions();
            syncSunbirdLeftMenuHeight();
            return;
        }
        window.sunbirdGovernanceRows = [];
        governanceCard.innerHTML = `
            <div class="governance-card-header">
                <i class="fas fa-shield-alt"></i>
                <h3>Governance</h3>
            </div>
            <div class="governance-content sunbird-governance-content">
                <div style="color: #ef4444; padding: 10px; text-align: center;">Failed to load governance evidence.</div>
            </div>
        `;
        ensureSunbirdBillingCardDimensions();
        syncSunbirdLeftMenuHeight();
    }
}

function getSunbirdGovernanceDisplaySource(row = {}) {
    const area = String(row.area || '').toLowerCase();
    const checklistAreas = ['mfa audit', 'device audit', 'log review', 'backup review', 'restore testing', 'policy review'];
    const frameworkAreas = ['access review', 'admin review', 'security review', 'threat review', 'ai review', 'software review', 'incident review', 'data review', 'awareness review'];

    if (checklistAreas.includes(area)) return 'Checklist';
    if (frameworkAreas.includes(area)) return 'Framework';

    const rawSource = String(row.source || '');
    if (/checklist/i.test(rawSource)) return 'Checklist';
    if (/framework/i.test(rawSource)) return 'Framework';
    if (/manual/i.test(rawSource)) return 'Manual Review';
    return 'Framework';
}

function deriveGovernanceStatus(row) {
    if (row?.status) return row.status;
    const mapDays = {
        Monthly: 35,
        Quarterly: 100,
        Annual: 395
    };
    if (!row?.lastReviewed) {
        return row?.frequency === 'Ongoing' ? 'Pending' : 'Overdue';
    }

    const reviewedAt = new Date(row.lastReviewed);
    if (Number.isNaN(reviewedAt.getTime())) return 'Pending';
    if (row.frequency === 'Triggered') return 'Completed';
    if (row.frequency === 'Ongoing') return 'Completed';

    const maxAgeDays = mapDays[row.frequency] || 90;
    const ageDays = (Date.now() - reviewedAt.getTime()) / (1000 * 60 * 60 * 24);
    return ageDays > maxAgeDays ? 'Overdue' : 'Completed';
}

function ensureSunbirdGovernanceEvidenceModal() {
    if (document.getElementById('sunbird-governance-evidence-modal')) return;

    const modal = document.createElement('div');
    modal.id = 'sunbird-governance-evidence-modal';
    modal.className = 'sunbird-governance-evidence-modal';
    modal.innerHTML = `
        <div class="sunbird-governance-modal-dialog" role="dialog" aria-modal="true" aria-labelledby="sunbird-governance-modal-title">
            <button class="sunbird-governance-modal-close" type="button" aria-label="Close">
                <i class="fas fa-times"></i>
            </button>
            <h4 id="sunbird-governance-modal-title">Governance Evidence</h4>
            <div class="sunbird-governance-modal-meta" id="sunbird-governance-modal-meta"></div>
            <div class="sunbird-governance-modal-status-wrap">
                <span class="sunbird-governance-modal-status-label">Status</span>
                <span class="sunbird-governance-modal-status" id="sunbird-governance-modal-status">Pending</span>
            </div>
            <div class="sunbird-governance-modal-evidence-title">Supporting Evidence</div>
            <div class="sunbird-governance-modal-evidence-text" id="sunbird-governance-modal-evidence"></div>
        </div>
    `;

    modal.addEventListener('click', (event) => {
        if (event.target === modal) {
            modal.classList.remove('open');
        }
    });

    const closeBtn = modal.querySelector('.sunbird-governance-modal-close');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => modal.classList.remove('open'));
    }

    document.body.appendChild(modal);
}

window.openSunbirdGovernanceEvidence = function(index) {
    const rows = Array.isArray(window.sunbirdGovernanceRows) ? window.sunbirdGovernanceRows : [];
    const row = rows[index];
    const modal = document.getElementById('sunbird-governance-evidence-modal');
    if (!row || !modal) return;

    const status = deriveGovernanceStatus(row);
    const reviewedLabel = row.lastReviewed
        ? `Last reviewed: ${new Date(row.lastReviewed).toLocaleDateString()}`
        : 'Last reviewed: Pending review';

    const meta = modal.querySelector('#sunbird-governance-modal-meta');
    const statusEl = modal.querySelector('#sunbird-governance-modal-status');
    const evidenceEl = modal.querySelector('#sunbird-governance-modal-evidence');
    const titleEl = modal.querySelector('#sunbird-governance-modal-title');

    if (titleEl) titleEl.textContent = row.area;
    if (meta) {
        meta.innerHTML = `
            <div><strong>Activity:</strong> ${escapeIdentityText(row.activity || 'Review')}</div>
            <div><strong>Frequency:</strong> ${escapeIdentityText(row.frequency || 'As required')}</div>
            <div>${escapeIdentityText(reviewedLabel)}</div>
        `;
    }
    if (statusEl) {
        statusEl.textContent = status;
        statusEl.className = `sunbird-governance-modal-status ${status.toLowerCase()}`;
    }
    if (evidenceEl) {
        const evidenceData = renderSunbirdEvidenceDetails(row.evidenceData);

        evidenceEl.innerHTML = `
            <p style="margin-top: 0;">${escapeIdentityText(row.evidence || (status === 'Completed' ? 'Completed' : 'Pending review'))}</p>
            ${evidenceData ? `<div style="display: grid; gap: 8px; margin-top: 12px;">${evidenceData}</div>` : ''}
        `;
    }

    modal.classList.add('open');
};

function shouldHideEvidenceKey(key) {
    return /source|endpoint|cache|graph_api|graph_available|graph_reports|report_sources/i.test(String(key || ''));
}

function formatEvidenceLabel(key) {
    return String(key || '')
        .replace(/_/g, ' ')
        .replace(/\b\w/g, char => char.toUpperCase());
}

function renderEvidenceRecord(record) {
    if (!record || typeof record !== 'object') return `<span>${escapeIdentityText(record)}</span>`;
    const fields = Object.entries(record)
        .filter(([key]) => !shouldHideEvidenceKey(key))
        .map(([key, value]) => `<span><strong>${escapeIdentityText(formatEvidenceLabel(key))}:</strong> ${escapeIdentityText(value ?? 'N/A')}</span>`)
        .join('<br>');
    return fields || '<span>No details available</span>';
}

function renderEvidenceArray(label, rows) {
    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) return '';
    return `
        <div style="padding: 10px; background: rgba(255,255,255,0.04); border-radius: 4px;">
            <div style="color: #cbd5e1; font-weight: 200; margin-bottom: 8px;">${escapeIdentityText(formatEvidenceLabel(label))}</div>
            <div class="sunbird-evidence-record-list" style="display: grid; gap: 8px; max-height: 180px; overflow: auto; padding-right: 4px;">
                ${list.map(item => `
                    <div style="padding: 8px; background: rgba(15,23,42,0.55); border: 1px solid rgba(148,163,184,0.18); border-radius: 4px; color: #e2e8f0;">
                        ${renderEvidenceRecord(item)}
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

function renderSunbirdEvidenceDetails(evidenceData) {
    if (!evidenceData || typeof evidenceData !== 'object') return '';
    return Object.entries(evidenceData)
        .filter(([key]) => !shouldHideEvidenceKey(key))
        .map(([key, value]) => {
            if (Array.isArray(value)) return renderEvidenceArray(key, value);
            if (value && typeof value === 'object') return renderEvidenceArray(key, [value]);
            return `<div style="display: flex; justify-content: space-between; gap: 12px; padding: 8px; background: rgba(255,255,255,0.05); border-radius: 4px;">
                <span style="color: #94a3b8;">${escapeIdentityText(formatEvidenceLabel(key))}</span>
                <span style="font-weight: 200; color: #e2e8f0; text-align: right;">${escapeIdentityText(value ?? 'N/A')}</span>
            </div>`;
        })
        .filter(Boolean)
        .join('');
}

function initializeSupportCard() {
    const supportCard = document.getElementById('support-card');
    if (!supportCard) return;
    syncNonSunbirdBlurGatedPanels();
    
    // 🚨 STRICT SCOPE CONTROL: Non-Sunbird clients get the standard Support & SLA card
    if (!isSunbirdUser()) {
        supportCard.innerHTML = `
            <div class="secondary-card-header">
                <i class="fas fa-headset"></i>
                <h3>Support & SLA</h3>
            </div>
            <div class="governance-content">
                <div class="governance-item">
                    <i class="fas fa-clock"></i>
                    <span class="governance-item-text"><strong>8am - 5pm Priority Support</strong> - Response in 1 hour</span>
                </div>
                <div class="governance-item">
                    <i class="fas fa-phone"></i>
                    <span class="governance-item-text"><strong>Dedicated Support Team</strong> - 1 assigned engineer</span>
                </div>
                <div class="governance-item">
                    <i class="fas fa-tachometer-alt"></i>
                    <span class="governance-item-text"><strong>99.9% Uptime SLA</strong> - Guaranteed availability</span>
                </div>
            </div>
        `;
        return;
    }

    // 🚨 SUNBIRD ONLY LOGIC: Live Compliance Validation
    const cached = getSunbirdCachedCardData(SUNBIRD_COMPLIANCE_CACHE_KEY, { allowStale: true });
    if (cached?.controls) {
        window.sunbirdComplianceSource = cached.source || {};
        renderSunbirdComplianceCard(supportCard, cached.controls);
    } else {
        renderSunbirdComplianceCard(supportCard, getSunbirdComplianceInstantControls());
    }
    ensureSunbirdComplianceEvidenceModal();
    ensureSunbirdBillingCardDimensions();
    syncSunbirdLeftMenuHeight();

    // Fetch dynamic API data
    fetchSunbirdComplianceData(supportCard);
}

function renderSunbirdComplianceCard(supportCard, controls) {
    const safeControls = Array.isArray(controls) ? controls : [];
    window.sunbirdComplianceControls = safeControls;
    const tableRows = safeControls.map((control, index) => {
        const insight = String(control.insight || '');
        const isDanger = insight.includes('🔴');
        const isWarning = insight.includes('🟡');
        const insightClass = isDanger ? 'color: #ef4444;' : (isWarning ? 'color: #f59e0b;' : 'color: #10b981;');

        return `
            <tr>
                <td>
                    <div style="font-weight: 200; margin-bottom: 4px;">${escapeIdentityText(control.name || 'Control')}</div>
                    <button class="sunbird-risk-view-btn" onclick="window.openSunbirdComplianceEvidence(${index})">
                        View Evidence
                    </button>
                </td>
                <td style="color: #cbd5e1;">${escapeIdentityText(control.area || 'Identity')}</td>
                <td style="font-weight: 200; ${insightClass}">${escapeIdentityText(insight || 'No insight available')}</td>
            </tr>
        `;
    }).join('');

    supportCard.innerHTML = `
        <div class="secondary-card-header">
            <i class="fas fa-certificate"></i>
            <h3>Compliance Validation</h3>
        </div>
        <div class="governance-content sunbird-governance-content">
            <div class="sunbird-governance-table-wrap">
                <table class="sunbird-incidents-table sunbird-governance-table">
                    <thead>
                        <tr>
                            <th>Control Name</th>
                            <th>Area</th>
                            <th>Insight</th>
                        </tr>
                    </thead>
                    <tbody>${tableRows || '<tr><td colspan="3" class="sunbird-empty-row">No compliance controls available</td></tr>'}</tbody>
                </table>
            </div>
        </div>
    `;
}

async function fetchSunbirdComplianceData(supportCard) {
    let renderedCached = false;
    try {
        const cached = getSunbirdCachedCardData(SUNBIRD_COMPLIANCE_CACHE_KEY, { allowStale: true });
        if (cached?.controls) {
            renderSunbirdComplianceCard(supportCard, cached.controls);
            window.sunbirdComplianceSource = cached.source || {};
            renderedCached = true;
            ensureSunbirdComplianceEvidenceModal();
            ensureSunbirdBillingCardDimensions();
            syncSunbirdLeftMenuHeight();
        }

        const token = localStorage.getItem('authToken');
        const response = await fetch('/api/sunbird/compliance-controls', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!response.ok) throw new Error('Failed to fetch compliance data');
        const data = await response.json();
        
        window.sunbirdComplianceControls = data.controls || [];
        window.sunbirdComplianceSource = {
            source: data.source || 'unknown',
            fetchedAt: data.fetchedAt,
            warning: data.warning
        };

        setSunbirdCachedCardData(SUNBIRD_COMPLIANCE_CACHE_KEY, {
            controls: window.sunbirdComplianceControls,
            source: window.sunbirdComplianceSource
        });
        renderSunbirdComplianceCard(supportCard, window.sunbirdComplianceControls);

        ensureSunbirdComplianceEvidenceModal();
    } catch (error) {
        console.error('[Compliance] Error:', error);
        if (renderedCached || supportCard.querySelector('.sunbird-governance-table')) {
            ensureSunbirdComplianceEvidenceModal();
            ensureSunbirdBillingCardDimensions();
            syncSunbirdLeftMenuHeight();
            return;
        }
        supportCard.innerHTML = `
            <div class="secondary-card-header">
                <i class="fas fa-certificate"></i>
                <h3>Compliance Validation</h3>
            </div>
            <div class="governance-content sunbird-governance-content">
                <div style="color: #ef4444; padding: 10px; text-align: center;">Failed to load compliance validation.</div>
            </div>
        `;
    } finally {
        ensureSunbirdBillingCardDimensions();
        syncSunbirdLeftMenuHeight();
    }
}

function ensureSunbirdComplianceEvidenceModal() {
    if (document.getElementById('sunbird-compliance-evidence-modal')) return;

    const modal = document.createElement('div');
    modal.id = 'sunbird-compliance-evidence-modal';
    modal.className = 'sunbird-governance-evidence-modal'; 
    modal.innerHTML = `
        <div class="sunbird-governance-modal-dialog" role="dialog" aria-modal="true" aria-labelledby="sunbird-compliance-modal-title">
            <button class="sunbird-governance-modal-close" type="button" aria-label="Close">
                <i class="fas fa-times"></i>
            </button>
            <h4 id="sunbird-compliance-modal-title">Control Evidence</h4>
            <div class="sunbird-governance-modal-meta" id="sunbird-compliance-modal-meta"></div>
            <div class="sunbird-governance-modal-evidence-title" style="margin-top: 15px;">Evidence Details</div>
            <div class="sunbird-governance-modal-evidence-text" id="sunbird-compliance-modal-evidence"></div>
        </div>
    `;

    modal.addEventListener('click', (event) => {
        if (event.target === modal) modal.classList.remove('open');
    });

    const closeBtn = modal.querySelector('.sunbird-governance-modal-close');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => modal.classList.remove('open'));
    }

    document.body.appendChild(modal);
}

window.openSunbirdComplianceEvidence = function(index) {
    const controls = Array.isArray(window.sunbirdComplianceControls) ? window.sunbirdComplianceControls : [];
    const control = controls[index];
    const modal = document.getElementById('sunbird-compliance-evidence-modal');
    if (!control || !modal) return;

    const titleEl = modal.querySelector('#sunbird-compliance-modal-title');
    const metaEl = modal.querySelector('#sunbird-compliance-modal-meta');
    const evidenceEl = modal.querySelector('#sunbird-compliance-modal-evidence');

    if (titleEl) titleEl.textContent = `Evidence: ${control.name}`;
    
    if (metaEl) {
        metaEl.innerHTML = `
            <div style="margin-bottom: 4px;"><strong>Area:</strong> ${control.area}</div>
            <div style="margin-bottom: 4px;"><strong>Insight:</strong> ${control.insight}</div>
        `;
    }

    if (evidenceEl) {
        const evidenceHtml = renderSunbirdEvidenceDetails(control.evidenceData || {});
        evidenceEl.innerHTML = evidenceHtml
            ? `<div style="display: grid; gap: 8px; margin-top: 10px;">${evidenceHtml}</div>`
            : '<div class="sunbird-empty-row">No detailed evidence is available for this control.</div>';
    }

    modal.classList.add('open');
};

/* RESIZE HANDLER */
window.addEventListener('resize', () => {
    ensureSunbirdBillingCardDimensions();
    syncSunbirdLeftMenuHeight();
    syncSidePeekCardSizing();
    if (currentProject && charts.risk) {
        Object.values(charts).forEach(chart => {
            if (chart) {
                chart.resize();
            }
        });
    }
});

/* ============================================ */
/* Dashboard Tabs & Microsoft Graph Integration */
/* ============================================ */

// Initialize tabs when project dashboard is loaded
function initializeTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    // Show tabs only if project has tabs enabled
    const dashboardTabs = document.getElementById('dashboard-tabs');
    
    // Always clear and hide all tab contents first
    tabContents.forEach(content => {
        content.classList.remove('active');
        smoothHide(content, 0); // No fade for initial setup
    });
    tabBtns.forEach(btn => {
        btn.classList.remove('active');
    });
    
    if (currentProject && currentProject.hasTabs) {
        smoothShow(dashboardTabs, 250);
        
        // Add event listeners to tab buttons (remove duplicates by cloning)
        tabBtns.forEach(btn => {
            const newBtn = btn.cloneNode(true);
            btn.parentNode.replaceChild(newBtn, btn);
        });
        
        // Query buttons again after cloning
        const freshTabBtns = document.querySelectorAll('.tab-btn');
        freshTabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const tabId = btn.getAttribute('data-tab');
                switchTab(tabId, document.querySelectorAll('.tab-btn'), document.querySelectorAll('.tab-content'));
                
                // Fetch Microsoft users when switching to identity tab
                if (tabId === 'identity-tab' && currentProject.microsoftGraphEnabled) {
                    fetchMicrosoftUsersData();
                }
            });
        });
        
        // Set default tab to "all"
        const allTab = document.getElementById('all-tab');
        if (allTab) {
            allTab.classList.add('active');
            smoothShow(allTab, 250);
        }
        document.querySelector('[data-tab="all-tab"]').classList.add('active');
    } else {
        smoothHide(dashboardTabs, 250);
        // Show the all-tab content when no project-specific tabs
        const allTab = document.getElementById('all-tab');
        if (allTab) {
            allTab.classList.add('active');
            smoothShow(allTab, 250);
        }
    }
}

function switchTab(tabId, tabBtns, tabContents) {
    // Hide all tabs with smooth transition
    tabContents.forEach(content => {
        content.classList.remove('active');
        smoothHide(content, 200);
    });
    
    // Deactivate all buttons
    tabBtns.forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab with smooth transition
    const selectedTab = document.getElementById(tabId);
    if (selectedTab) {
        selectedTab.classList.add('active');
        smoothShow(selectedTab, 200);
    }
    
    // Activate selected button
    const selectedBtn = document.querySelector(`[data-tab="${tabId}"]`);
    if (selectedBtn) {
        selectedBtn.classList.add('active');
    }
    
    console.log(`[Tabs] Switched to tab: ${tabId}`);
}

// ============================================
// MICROSOFT GRAPH USERS & ROLES API
// ============================================
// Fetches and displays Microsoft user data, roles, and access information
// for the Identity tab in the dashboard

// Fetch Microsoft users from the API
async function fetchMicrosoftUsersData() {
    try {
        const token = localStorage.getItem('authToken');
        if (!token) {
            showNotification('Authentication required. Please log in again.', false);
            return;
        }
        
        console.log('[Identity Details] Fetching users...');
        
        const response = await fetch('/api/db/identity-details', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to fetch Microsoft users');
        }
        
        const data = await response.json();
        microsoftUsersData = data.users || [];
        microsoftRolesData = Array.isArray(data.roleAssignments) ? data.roleAssignments : [];
        buildUserRolesMap();
        
        console.log(`[Microsoft Graph] Retrieved ${microsoftUsersData.length} users`);
        
        populateMicrosoftUsersTable(microsoftUsersData);
        updateIdentityStats(microsoftUsersData);
        
    } catch (error) {
        console.error('[Microsoft Graph] Error fetching users:', error.message);
        showNotification(`Failed to load Microsoft users: ${error.message}`, false);
        
        // Show error in table
        const tbody = document.getElementById('microsoft-users-tbody');
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 20px; color: #dc3545;">
                <i class="fas fa-exclamation-circle"></i> Error loading users: ${error.message}
            </td></tr>`;
        }
    }
}

// ============================================
// USER DATA DISPLAY & TABLE RENDERING
// ============================================
// Renders Microsoft user data in tables, applies filters,
// and displays identity analytics statistics

// Populate the Microsoft users table
function populateMicrosoftUsersTable(users) {
    const tbody = document.getElementById('microsoft-users-tbody');
    if (!tbody) return;
    
    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 20px; color: #94a3b8;">No users found</td></tr>';
        return;
    }
    
    const rows = users.map(user => `
        <tr>
            <td>${user.displayName}</td>
            <td>${user.mail}</td>
            <td>${user.jobTitle}</td>
            <td>${user.mobilePhone}</td>
            <td>
                <span class="user-type ${user.isExternal ? 'external' : 'internal'}">
                    ${user.isExternal ? 'External' : 'Internal'}
                </span>
            </td>
            <td>
                <span class="user-status">${user.status}</span>
            </td>
        </tr>
    `).join('');
    
    tbody.innerHTML = rows;
    
    console.log('[Microsoft Graph] Table updated with ' + users.length + ' users');
}

// Update identity stats
function updateIdentityStats(users) {
    const totalUsers = users.length;
    const externalUsers = users.filter(u => u.isExternal).length;
    const missingData = users.filter(u => 
        !u.jobTitle || u.jobTitle === 'No Title' || !u.phone || u.phone === 'N/A'
    ).length;
    
    document.getElementById('ms-total-users').textContent = totalUsers;
    document.getElementById('ms-external-users').textContent = externalUsers;
    document.getElementById('ms-missing-data').textContent = missingData;
    
    // Format timestamp
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit',
        hour12: true 
    });
    document.getElementById('ms-last-updated').textContent = timeStr;
    
    console.log(`[Identity Stats] Total: ${totalUsers}, External: ${externalUsers}, Missing Data: ${missingData}`);
}

// Filter Microsoft users based on search and checkboxes
function filterMicrosoftUsers() {
    const searchInput = document.getElementById('microsoft-user-search');
    const filterExternal = document.getElementById('filter-external').checked;
    const filterNoJobTitle = document.getElementById('filter-no-jobTitle').checked;
    
    const searchTerm = searchInput.value.toLowerCase();
    
    let filtered = microsoftUsersData.filter(user => {
        // Search filter
        const displayName = (user.displayName || '').toLowerCase();
        const email = (user.mail || user.userPrincipalName || user.email || '').toLowerCase();

        if (searchTerm && !displayName.includes(searchTerm) && !email.includes(searchTerm)) {
            return false;
        }
        
        // External users filter
        if (filterExternal && !user.isExternal) {
            return false;
        }
        
        // Missing job title filter
        if (filterNoJobTitle && user.jobTitle && user.jobTitle !== 'No Title') {
            return false;
        }
        
        return true;
    });
    
    populateMicrosoftUsersTable(filtered);
    console.log(`[Filter] Showing ${filtered.length} of ${microsoftUsersData.length} users`);
}

// Add search input listener
document.addEventListener('DOMContentLoaded', () => {
    const microsoftSignInButton = document.getElementById('microsoft-signin-btn');
    if (microsoftSignInButton) {
        microsoftSignInButton.addEventListener('click', () => {
            microsoftSignInButton.setAttribute('aria-busy', 'true');
            microsoftSignInButton.disabled = true;
        });
    }

    const searchInput = document.getElementById('microsoft-user-search');
    if (searchInput) {
        searchInput.addEventListener('input', filterMicrosoftUsers);
    }
});

// ============================================================================
// SUNBIRD ONLY: OPERATIONS REMEDIATION ENGINE
// ============================================================================
function renderSunbirdOperationsCard(billingCard, tasks, options = {}) {
    const safeTasks = Array.isArray(tasks) ? tasks : [];
    window.sunbirdOperationsTasks = safeTasks;

    const rowsHtml = safeTasks.length
        ? safeTasks.map((task, index) => {
            const isHigh = task.priority === 'High';
            const isMed = task.priority === 'Medium';
            const badgeClass = isHigh ? 'op-priority-high' : (isMed ? 'op-priority-medium' : 'op-priority-low');
            const dotColor = isHigh ? '#f87171' : (isMed ? '#fbbf24' : '#34d399');
            const insightClass = isHigh ? 'op-insight-danger' : (isMed ? 'op-insight-warning' : 'op-insight-success');

            return `
                <tr>
                    <td style="font-weight: 200; color: #e2e8f0;">${escapeIdentityText(task.task || 'Review task')}</td>
                    <td style="color: #94a3b8;">${escapeIdentityText(task.area || 'Operations')}</td>
                    <td>
                        <span class="op-priority-badge ${badgeClass}">
                            <span style="width: 6px; height: 6px; border-radius: 50%; background: ${dotColor};"></span>
                            ${escapeIdentityText(task.priority || 'Low')}
                        </span>
                    </td>
                    <td class="op-insight-text ${insightClass}">${escapeIdentityText(task.insight || 'No insight available')}</td>
                    <td>
                        <button class="sunbird-risk-view-btn" onclick="window.openSunbirdOperationsModal(${index})">
                            View Evidence
                        </button>
                    </td>
                </tr>
            `;
        }).join('')
        : `<tr><td colspan="5" class="sunbird-empty-row">${escapeIdentityText(options.emptyMessage || 'No active tasks required. System is healthy.')}</td></tr>`;

    billingCard.innerHTML = `
        <div class="sunbird-panel-view">
            <div class="billing-card-header">
                <i class="fas fa-tasks"></i>
                <h3>Operations Action Queue</h3>
            </div>
            <div class="sunbird-section-title" style="margin-bottom: 10px;">Live Remediation Required</div>
            
            <div class="sunbird-incidents-table-wrap" style="max-height: 400px;">
                <table class="sunbird-incidents-table">
                    <thead>
                        <tr>
                            <th>Task</th>
                            <th>Area</th>
                            <th>Priority</th>
                            <th>Insight</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="operations-tbody">
                        ${rowsHtml}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

async function renderSunbirdOperationsView() {
    const billingCard = document.getElementById('billing-card');
    if (!billingCard) return;

    ensureSunbirdOperationsModal();

    const cached = getSunbirdCachedCardData(SUNBIRD_OPERATIONS_CACHE_KEY, { allowStale: true });
    if (cached?.tasks) {
        window.sunbirdOperationsSource = cached.source || {};
        renderSunbirdOperationsCard(billingCard, cached.tasks);
    } else {
        window.sunbirdOperationsSource = {};
        renderSunbirdOperationsCard(billingCard, [], { emptyMessage: 'Refreshing latest operations queue...' });
    }

    ensureSunbirdBillingCardDimensions();
    syncSunbirdLeftMenuHeight();

    // 2. Fetch Live Tasks
    try {
        const token = localStorage.getItem('authToken');
        const response = await fetch('/api/sunbird/operations', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!response.ok) throw new Error('Failed to fetch operations');
        const data = await response.json();
        
        window.sunbirdOperationsTasks = data.tasks || [];
        window.sunbirdOperationsSource = {
            source: data.source || 'unknown',
            fetchedAt: data.fetchedAt,
            warning: data.warning
        };

        setSunbirdCachedCardData(SUNBIRD_OPERATIONS_CACHE_KEY, {
            tasks: window.sunbirdOperationsTasks,
            source: window.sunbirdOperationsSource
        });

        if (!isSunbirdBillingViewActive('operations')) return;
        renderSunbirdOperationsCard(billingCard, window.sunbirdOperationsTasks);

    } catch (error) {
        console.error('[Operations] Error:', error);
        if (billingCard.querySelector('.sunbird-panel-view')) {
            ensureSunbirdBillingCardDimensions();
            syncSunbirdLeftMenuHeight();
            return;
        }
        billingCard.innerHTML = `
            <div class="sunbird-panel-view">
                <div class="billing-card-header">
                    <i class="fas fa-tasks"></i>
                    <h3>Operations Action Queue</h3>
                </div>
                <p class="sunbird-panel-error">Failed to load operations queue.</p>
            </div>
        `;
    } finally {
        ensureSunbirdBillingCardDimensions();
        syncSunbirdLeftMenuHeight();
    }
}

function ensureSunbirdOperationsModal() {
    if (document.getElementById('sunbird-operations-modal')) return;

    const modal = document.createElement('div');
    modal.id = 'sunbird-operations-modal';
    modal.className = 'sunbird-governance-evidence-modal'; 
    modal.innerHTML = `
        <div class="sunbird-governance-modal-dialog" role="dialog" aria-modal="true" style="max-width: 550px;">
            <button class="sunbird-governance-modal-close" type="button" aria-label="Close" onclick="document.getElementById('sunbird-operations-modal').classList.remove('open')">
                <i class="fas fa-times"></i>
            </button>
            <h4 id="op-modal-title" style="color: #e2e8f0; font-size: 1.1rem; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 10px; margin-bottom: 15px;">Operations Evidence</h4>
            
            <div style="display: flex; flex-direction: column; gap: 15px;">
                <div style="background: rgba(255,255,255,0.03); padding: 12px; border-radius: 8px; border-left: 3px solid #fbbf24;">
                    <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 4px;">Evidence Summary</div>
                    <div id="op-modal-why" style="font-size: 0.9rem; color: #cbd5e1; line-height: 1.5;"></div>
                </div>

                <div style="background: rgba(255,255,255,0.03); padding: 12px; border-radius: 8px; border-left: 3px solid #f87171;">
                    <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 4px;">Proof / Affected Records</div>
                    <div id="op-modal-affected" style="font-size: 0.9rem; color: #cbd5e1; font-weight: 200;"></div>
                </div>

                <div style="background: rgba(0, 110, 255, 0.05); padding: 12px; border-radius: 8px; border-left: 3px solid #3b82f6;">
                    <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 8px;">Recommended Next Steps</div>
                    <div id="op-modal-remediation" style="font-size: 0.9rem; color: #e2e8f0; line-height: 1.6; white-space: pre-wrap;"></div>
                </div>
            </div>
            
            <div style="margin-top: 20px; display: flex; justify-content: flex-end;">
                <button class="btn-fix-this" style="background: #3b82f6; color: white;" onclick="document.getElementById('sunbird-operations-modal').classList.remove('open')">Acknowledge</button>
            </div>
        </div>
    `;

    document.body.appendChild(modal);
}

window.openSunbirdOperationsModal = function(index) {
    const task = window.sunbirdOperationsTasks[index];
    if (!task) return;

    document.getElementById('op-modal-title').innerHTML = `<i class="fas fa-clipboard-check" style="color: #3b82f6; margin-right: 8px;"></i> ${escapeIdentityText(task.task)}`;
    document.getElementById('op-modal-why').textContent = task.why;
    const affectedEl = document.getElementById('op-modal-affected');
    if (affectedEl) {
        const evidenceRows = Array.isArray(task.evidenceRows) ? task.evidenceRows : [];
        affectedEl.innerHTML = `
            <div style="margin-bottom: ${evidenceRows.length ? '10px' : '0'};">${escapeIdentityText(task.affected || 'No affected entities listed.')}</div>
            ${evidenceRows.length ? renderEvidenceArray('Affected records', evidenceRows) : ''}
        `;
    }
    document.getElementById('op-modal-remediation').textContent = task.remediation;

    document.getElementById('sunbird-operations-modal').classList.add('open');
};
function isPortalMobileLayout() {
    return window.matchMedia('(max-width: 1024px)').matches;
}

function syncPortalMobileUserName() {
    const name = document.getElementById('user-name')?.textContent?.trim() || 'Client';
    ['portal-mobile-user-name', 'portal-mobile-profile-name'].forEach(id => {
        const element = document.getElementById(id);
        if (element) element.textContent = name;
    });
}

function setPortalMobileTab(tab) {
    const view = document.getElementById('projects-view');
    if (!view) return;
    ['home', 'dashboard', 'alerts', 'profile', 'control'].forEach(name => view.classList.toggle(`portal-mobile-tab-${name}`, name === tab));
    document.querySelectorAll('.portal-mobile-nav-item').forEach(button => {
        const active = button.dataset.mobileTab === tab;
        button.classList.toggle('active', active);
        button.toggleAttribute('aria-current', active);
        if (active) button.setAttribute('aria-current', 'page');
    });
    if (tab === 'alerts') window.switchBillingMenu?.('security');
    window.scrollTo({ top: 0, behavior: 'smooth' });
    if (tab === 'control') window.switchBillingMenu?.('operations');
}

function renderPortalMobileHealth(health) {
    const value = Math.max(0, Math.min(100, Math.round(Number(health) || 0)));
    const text = document.getElementById('portal-mobile-health-value');
    const ring = document.getElementById('portal-mobile-health-ring');
    const status = document.getElementById('portal-mobile-health-status');
    if (text) text.textContent = `${value}%`;
    const tone = value >= 85 ? '#34d399' : value >= 70 ? '#facc15' : value >= 50 ? '#fb923c' : '#f87171';
    if (ring) { ring.setAttribute('stroke-dasharray', `${value}, 100`); ring.style.stroke = tone; }
    if (status) {
        status.style.color = tone;
        status.classList.remove('is-warning', 'is-critical');
        status.textContent = value >= 85 ? 'All systems operational' : value >= 70 ? 'Attention recommended' : value >= 50 ? 'Action recommended' : 'Action required';
    }
}

function formatPortalMobileAlertTime(timestamp) {
    const date = new Date(timestamp);
    if (!timestamp || Number.isNaN(date.getTime())) return 'Recent';
    const minutes = Math.max(0, Math.round((Date.now() - date.getTime()) / 60000));
    return minutes < 1 ? 'Just now' : minutes < 60 ? `${minutes}m ago` : minutes < 1440 ? `${Math.round(minutes / 60)}h ago` : `${Math.round(minutes / 1440)}d ago`;
}

function renderPortalMobileAlerts(items = []) {
    const list = document.getElementById('portal-mobile-alerts-list');
    if (!list) return;
    if (!items.length) {
        list.innerHTML = '<div class="portal-mobile-alert-empty">No active alerts</div>';
        return;
    }
    list.innerHTML = items.slice(0, 3).map(item => {
        const severity = ['critical', 'high', 'medium', 'warning'].includes(String(item.severity).toLowerCase()) ? String(item.severity).toLowerCase() : 'low';
        const title = escapeIdentityText(item.message || item.displayName || item.title || 'Security alert');
        const detail = escapeIdentityText(item.source || item.type || item.category || 'Security activity');
        return `<div class="portal-mobile-alert-item"><span class="portal-mobile-alert-icon severity-${severity}"><i class="fas fa-bell"></i></span><div class="portal-mobile-alert-body"><p class="portal-mobile-alert-title">${title}</p><p class="portal-mobile-alert-meta">${detail} · ${formatPortalMobileAlertTime(item.timestamp || item.createdDateTime || item.created)}</p></div><span class="portal-mobile-alert-dot severity-${severity}"></span></div>`;
    }).join('');
}

function renderPortalMobileQuickActions() {
    const grid = document.getElementById('portal-mobile-quick-grid');
    if (!grid || grid.dataset.ready) return;
    const actions = [['Projects', 'fa-folder-open', () => setPortalMobileTab('dashboard')], ['Security Alerts', 'fa-bell', () => setPortalMobileTab('alerts')], ['Chat Support', 'fa-comments', () => document.getElementById('chatbot-toggle')?.click()]];
    if (isSunbirdUser()) actions.splice(2, 0, ['Reports', 'fa-file-alt', () => { setPortalMobileTab('alerts'); window.switchBillingMenu?.('reports'); }]);
    actions.forEach(([label, icon, action]) => {
        const button = document.createElement('button');
        button.type = 'button'; button.className = 'portal-mobile-quick-btn';
        button.innerHTML = `<i class="fas ${icon}" aria-hidden="true"></i><span>${label}</span>`;
        button.addEventListener('click', action); grid.appendChild(button);
    });
    grid.dataset.ready = 'true';
}

async function refreshPortalMobileDashboard() {
    if (!isPortalMobileLayout() || sessionStorage.getItem('isLoggedIn') !== 'true') return;
    syncPortalMobileUserName(); renderPortalMobileQuickActions();
    try {
        const reports = await fetchSunbirdReportsData('30d');
        renderPortalMobileHealth(getSunbirdReportIntelligence(reports).health);
    } catch (error) { console.warn('[Mobile Portal] Report health unavailable:', error.message); }
    try {
        const security = cachedSunbirdSecurityData || await fetchSunbirdSecurityEventsData();
        cachedSunbirdSecurityData = security;
        renderPortalMobileAlerts(security.activityFeed || security.incidents || []);
    } catch (error) { console.warn('[Mobile Portal] Security alerts unavailable:', error.message); }
}

function initializePortalMobileDashboard() {
    document.querySelectorAll('.portal-mobile-nav-item').forEach(button => button.addEventListener('click', () => setPortalMobileTab(button.dataset.mobileTab || 'home')));
    document.getElementById('portal-mobile-view-all-alerts')?.addEventListener('click', () => setPortalMobileTab('alerts'));
    document.querySelectorAll('.mobile-control-panel-link').forEach(button => button.addEventListener('click', () => {
        closeMobileMenu();
        setPortalMobileTab('control');
        if (button.dataset.controlMenu) window.switchBillingMenu?.(button.dataset.controlMenu);
        const targetId = button.dataset.controlPanelTarget;
        if (targetId) setTimeout(() => document.getElementById(targetId)?.scrollIntoView({ block: 'start', behavior: 'smooth' }), 80);
    }));
    document.getElementById('portal-mobile-profile-logout')?.addEventListener('click', handleLogout);
    syncPortalMobileUserName(); updatePortalMobileDomainSummary(); refreshPortalMobileDashboard();
}
