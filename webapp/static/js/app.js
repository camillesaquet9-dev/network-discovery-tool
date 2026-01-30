/**
 * Network Discovery Viewer - Application JavaScript
 * Handles file upload, data visualization, and user interactions
 */

// Global state
let appData = null;
let chart = null;

// DOM Elements
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const uploadSection = document.getElementById('uploadSection');
const dashboardSection = document.getElementById('dashboardSection');
const searchInput = document.getElementById('searchInput');
const filterType = document.getElementById('filterType');
const themeToggle = document.getElementById('themeToggle');

// ============================================
// Initialization
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initDragDrop();
    initEventListeners();
});

function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

function initDragDrop() {
    // Drag events
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(event => {
        dropZone.addEventListener(event, preventDefaults);
        document.body.addEventListener(event, preventDefaults);
    });

    ['dragenter', 'dragover'].forEach(event => {
        dropZone.addEventListener(event, () => dropZone.classList.add('drag-over'));
    });

    ['dragleave', 'drop'].forEach(event => {
        dropZone.addEventListener(event, () => dropZone.classList.remove('drag-over'));
    });

    dropZone.addEventListener('drop', handleDrop);
    dropZone.addEventListener('click', () => fileInput.click());
}

function initEventListeners() {
    fileInput.addEventListener('change', handleFileSelect);
    themeToggle.addEventListener('click', toggleTheme);
    searchInput.addEventListener('input', debounce(filterTable, 300));
    filterType.addEventListener('change', filterTable);
}

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

// ============================================
// File Handling
// ============================================

function handleDrop(e) {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        processFile(files[0]);
    }
}

function handleFileSelect(e) {
    if (e.target.files.length > 0) {
        processFile(e.target.files[0]);
    }
}

async function processFile(file) {
    if (!file.name.endsWith('.json')) {
        showToast('Veuillez sélectionner un fichier JSON', 'error');
        return;
    }

    try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.error) {
            showToast(result.error, 'error');
            return;
        }

        showToast(`Fichier chargé: ${result.hosts_count} hôtes sur ${result.networks_count} réseaux`, 'success');

        // Load the data
        await loadDashboard();

    } catch (error) {
        console.error('Upload error:', error);
        showToast('Erreur lors du chargement du fichier', 'error');
    }
}

// ============================================
// Dashboard
// ============================================

async function loadDashboard() {
    try {
        // Fetch all data
        const [dataRes, statsRes] = await Promise.all([
            fetch('/api/data'),
            fetch('/api/stats')
        ]);

        appData = await dataRes.json();
        const stats = await statsRes.json();

        // Switch views
        uploadSection.classList.add('hidden');
        dashboardSection.classList.remove('hidden');

        // Update stats
        updateStats(stats);

        // Render charts
        renderTypeChart(stats.type_distribution);
        renderVendorsList(stats.unique_vendors, appData.discovered_hosts);

        // Render networks
        renderNetworks(appData.discovered_networks, appData.discovered_hosts);

        // Populate filter
        populateTypeFilter(stats.type_distribution);

        // Render hosts table
        renderHostsTable(appData.discovered_hosts);

    } catch (error) {
        console.error('Dashboard error:', error);
        showToast('Erreur lors du chargement des données', 'error');
    }
}

function updateStats(stats) {
    document.getElementById('statHosts').textContent = stats.total_hosts;
    document.getElementById('statNetworks').textContent = stats.total_networks;
    document.getElementById('statPorts').textContent = stats.open_ports;
    document.getElementById('statServices').textContent = stats.unique_services.length;
}

// ============================================
// Charts
// ============================================

function renderTypeChart(distribution) {
    const ctx = document.getElementById('typeChart').getContext('2d');

    if (chart) {
        chart.destroy();
    }

    const colors = {
        WEBSERVER: '#10b981',
        WEBCLIENT: '#3b82f6',
        FIREWALL: '#ef4444',
        NAT: '#f59e0b',
        DNS: '#a855f7',
        ROUTER: '#14b8a6',
        DATABASE: '#ec4899',
        MAILSERVER: '#f97316',
        UNKNOWN: '#94a3b8'
    };

    const labels = Object.keys(distribution);
    const data = Object.values(distribution);
    const bgColors = labels.map(l => colors[l] || '#94a3b8');

    chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: bgColors,
                borderWidth: 0,
                hoverOffset: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        usePointStyle: true,
                        padding: 15,
                        font: {
                            family: 'Inter',
                            size: 12
                        }
                    }
                }
            },
            cutout: '65%'
        }
    });
}

function renderVendorsList(vendors, hosts) {
    const container = document.getElementById('vendorsList');

    // Count hosts per vendor
    const vendorCounts = {};
    hosts.forEach(host => {
        const vendor = host.mac_vendor || 'Inconnu';
        vendorCounts[vendor] = (vendorCounts[vendor] || 0) + 1;
    });

    // Sort by count
    const sorted = Object.entries(vendorCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    container.innerHTML = sorted.map(([vendor, count]) => `
        <div class="vendor-item">
            <div class="vendor-icon">
                <i class="fas fa-microchip"></i>
            </div>
            <div class="vendor-info">
                <div class="vendor-name">${escapeHtml(vendor)}</div>
                <div class="vendor-count">${count} équipement${count > 1 ? 's' : ''}</div>
            </div>
        </div>
    `).join('');
}

// ============================================
// Networks
// ============================================

function renderNetworks(networks, hosts) {
    const container = document.getElementById('networksGrid');

    container.innerHTML = networks.map(network => {
        // Count hosts in this network
        const count = hosts.filter(h => isInNetwork(h.ip, network)).length;

        return `
            <div class="network-card">
                <div class="network-icon">
                    <i class="fas fa-network-wired"></i>
                </div>
                <div class="network-info">
                    <h4>${escapeHtml(network)}</h4>
                    <p>${count} hôte${count > 1 ? 's' : ''} actif${count > 1 ? 's' : ''}</p>
                </div>
            </div>
        `;
    }).join('');
}

function isInNetwork(ip, network) {
    // Simple check based on first 3 octets for /24 networks
    const [netPart] = network.split('/');
    const netOctets = netPart.split('.').slice(0, 3).join('.');
    const ipOctets = ip.split('.').slice(0, 3).join('.');
    return netOctets === ipOctets;
}

// ============================================
// Hosts Table
// ============================================

function populateTypeFilter(distribution) {
    const options = Object.keys(distribution).map(type =>
        `<option value="${type}">${type}</option>`
    ).join('');
    filterType.innerHTML = '<option value="">Tous les types</option>' + options;
}

function renderHostsTable(hosts) {
    const tbody = document.getElementById('hostsTableBody');

    tbody.innerHTML = hosts.map(host => {
        const ports = host.ports || [];
        const openPorts = ports.filter(p => p.state === 'open');

        return `
            <tr data-ip="${host.ip}">
                <td><strong>${escapeHtml(host.ip)}</strong></td>
                <td>${escapeHtml(host.hostname || 'N/A')}</td>
                <td>
                    <span class="type-badge ${host.functional_type}">
                        ${getTypeIcon(host.functional_type)} ${host.functional_type}
                    </span>
                </td>
                <td class="mono">${escapeHtml(host.mac || 'N/A')}</td>
                <td>${escapeHtml(host.mac_vendor || 'N/A')}</td>
                <td>
                    <div class="ports-list">
                        ${openPorts.slice(0, 4).map(p =>
                            `<span class="port-badge open">${p.port}/${p.protocol}</span>`
                        ).join('')}
                        ${openPorts.length > 4 ? `<span class="port-badge">+${openPorts.length - 4}</span>` : ''}
                    </div>
                </td>
                <td>
                    <button class="btn-icon" onclick="showHostDetails('${host.ip}')" title="Voir les détails">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function getTypeIcon(type) {
    const icons = {
        WEBSERVER: '<i class="fas fa-globe"></i>',
        WEBCLIENT: '<i class="fas fa-desktop"></i>',
        FIREWALL: '<i class="fas fa-shield-alt"></i>',
        NAT: '<i class="fas fa-random"></i>',
        DNS: '<i class="fas fa-server"></i>',
        ROUTER: '<i class="fas fa-project-diagram"></i>',
        DATABASE: '<i class="fas fa-database"></i>',
        MAILSERVER: '<i class="fas fa-envelope"></i>',
        UNKNOWN: '<i class="fas fa-question"></i>'
    };
    return icons[type] || icons.UNKNOWN;
}

function filterTable() {
    const searchTerm = searchInput.value.toLowerCase();
    const typeFilter = filterType.value;

    const rows = document.querySelectorAll('#hostsTableBody tr');

    rows.forEach(row => {
        const ip = row.dataset.ip;
        const host = appData.discovered_hosts.find(h => h.ip === ip);

        if (!host) return;

        const matchesSearch = !searchTerm ||
            host.ip.toLowerCase().includes(searchTerm) ||
            (host.hostname || '').toLowerCase().includes(searchTerm) ||
            (host.mac || '').toLowerCase().includes(searchTerm) ||
            (host.mac_vendor || '').toLowerCase().includes(searchTerm) ||
            host.services.some(s => (s.name || '').toLowerCase().includes(searchTerm));

        const matchesType = !typeFilter || host.functional_type === typeFilter;

        row.style.display = matchesSearch && matchesType ? '' : 'none';
    });
}

// ============================================
// Host Details Modal
// ============================================

async function showHostDetails(ip) {
    try {
        const response = await fetch(`/api/host/${ip}`);
        const host = await response.json();

        if (host.error) {
            showToast(host.error, 'error');
            return;
        }

        const modal = document.getElementById('hostModal');
        const modalTitle = document.getElementById('modalTitle');
        const modalBody = document.getElementById('modalBody');

        modalTitle.textContent = host.hostname || host.ip;

        const ports = host.ports || [];
        const openPorts = ports.filter(p => p.state === 'open');

        modalBody.innerHTML = `
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Adresse IP</div>
                    <div class="info-value mono">${escapeHtml(host.ip)}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Hostname</div>
                    <div class="info-value">${escapeHtml(host.hostname || 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Type fonctionnel</div>
                    <div class="info-value">
                        <span class="type-badge ${host.functional_type}">
                            ${getTypeIcon(host.functional_type)} ${host.functional_type}
                        </span>
                    </div>
                </div>
                <div class="info-item">
                    <div class="info-label">Adresse MAC</div>
                    <div class="info-value mono">${escapeHtml(host.mac || 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Fabricant</div>
                    <div class="info-value">${escapeHtml(host.mac_vendor || 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Système d'exploitation</div>
                    <div class="info-value">${escapeHtml(host.os || 'Non détecté')}</div>
                </div>
            </div>

            <h3 style="margin: 1.5rem 0 0.5rem; font-size: 1rem;">
                <i class="fas fa-plug" style="color: var(--accent-primary);"></i>
                Ports et Services (${openPorts.length} ouverts)
            </h3>

            ${ports.length > 0 ? `
                <table class="ports-table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>État</th>
                            <th>Service</th>
                            <th>Produit</th>
                            <th>Version</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${ports.map(p => `
                            <tr>
                                <td><strong>${p.port}</strong></td>
                                <td>${p.protocol}</td>
                                <td><span class="state-badge ${p.state}">${p.state}</span></td>
                                <td>${escapeHtml(p.service || 'N/A')}</td>
                                <td>${escapeHtml(p.product || 'N/A')}</td>
                                <td>${escapeHtml(p.version || 'N/A')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            ` : '<p style="color: var(--text-secondary);">Aucun port détecté</p>'}
        `;

        modal.classList.remove('hidden');

    } catch (error) {
        console.error('Error loading host details:', error);
        showToast('Erreur lors du chargement des détails', 'error');
    }
}

function closeModal() {
    document.getElementById('hostModal').classList.add('hidden');
}

// Close modal on escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal();
    }
});

// ============================================
// Theme
// ============================================

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
}

function updateThemeIcon(theme) {
    const icon = themeToggle.querySelector('i');
    icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
}

// ============================================
// Toast Notifications
// ============================================

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
        <span>${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'toastIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ============================================
// Utilities
// ============================================

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
