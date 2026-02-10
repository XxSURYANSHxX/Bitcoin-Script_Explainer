/**
 * Bitcoin Script Explainer - Analytics Dashboard JavaScript
 * Polls backend for stats and activity, updates UI in real-time
 */

// Configuration
const API_BASE_URL = 'http://127.0.0.1:8000'; // Change this for production deployment
const POLL_INTERVAL = 5000; // 5 seconds

// DOM Elements
const lifetimeViewsEl = document.getElementById('lifetimeViews');
const activeUsersEl = document.getElementById('activeUsers');
const totalScriptsEl = document.getElementById('totalScripts');
const uniqueSessionsEl = document.getElementById('uniqueSessions');
const activityFeedEl = document.getElementById('activityFeed');
const refreshBtn = document.getElementById('refreshBtn');

let pollInterval = null;

/**
 * Fetch and display stats from /stats endpoint
 */
async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE_URL}/stats`);
        if (response.ok) {
            const data = await response.json();
            updateStats(data);
        } else {
            console.error('Failed to fetch stats:', response.status);
        }
    } catch (error) {
        console.error('Error fetching stats:', error);
        showError('Unable to connect to API');
    }
}

/**
 * Update stats display with fetched data
 */
function updateStats(data) {
    lifetimeViewsEl.textContent = formatNumber(data.lifetime_views);
    activeUsersEl.textContent = formatNumber(data.current_active_users);
    totalScriptsEl.textContent = formatNumber(data.total_scripts_explained);

    // Calculate unique sessions (rough estimate based on lifetime views)
    const uniqueSessions = Math.floor(data.lifetime_views * 0.7); // Rough estimate
    uniqueSessionsEl.textContent = formatNumber(uniqueSessions);
}

/**
 * Fetch and display activity from /activity endpoint
 */
async function fetchActivity() {
    try {
        const response = await fetch(`${API_BASE_URL}/activity`);
        if (response.ok) {
            const data = await response.json();
            updateActivity(data.recent_events);
        } else {
            console.error('Failed to fetch activity:', response.status);
        }
    } catch (error) {
        console.error('Error fetching activity:', error);
    }
}

/**
 * Update activity feed display
 */
function updateActivity(events) {
    if (!events || events.length === 0) {
        activityFeedEl.innerHTML = '<div class="activity-loading">No recent activity</div>';
        return;
    }

    activityFeedEl.innerHTML = events.map(event => createActivityItem(event)).join('');
}

/**
 * Create HTML for a single activity item
 */
function createActivityItem(event) {
    const icon = event.event_type === 'page_visit' ? '👁️' : '📜';
    const typeText = event.event_type === 'page_visit' ? 'Page Visit' : 'Script Explained';
    const iconClass = event.event_type.replace('_', '-');
    const timeAgo = formatTimeAgo(event.timestamp);

    return `
        <div class="activity-item">
            <div class="activity-icon ${iconClass}">${icon}</div>
            <div class="activity-details">
                <div class="activity-type">${typeText}</div>
                <div class="activity-time">${timeAgo}</div>
            </div>
        </div>
    `;
}

/**
 * Format large numbers with commas
 */
function formatNumber(num) {
    return num.toLocaleString('en-US');
}

/**
 * Format timestamp into "time ago" format
 */
function formatTimeAgo(timestamp) {
    try {
        const date = new Date(timestamp);
        const now = new Date();
        const diffMs = now - date;
        const diffSecs = Math.floor(diffMs / 1000);
        const diffMins = Math.floor(diffSecs / 60);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);

        if (diffSecs < 60) {
            return 'Just now';
        } else if (diffMins < 60) {
            return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
        } else if (diffHours < 24) {
            return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        } else if (diffDays < 7) {
            return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
        } else {
            return date.toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        }
    } catch (error) {
        return timestamp;
    }
}

/**
 * Show error message
 */
function showError(message) {
    lifetimeViewsEl.textContent = '--';
    activeUsersEl.textContent = '--';
    totalScriptsEl.textContent = '--';
    uniqueSessionsEl.textContent = '--';
    activityFeedEl.innerHTML = `<div class="activity-loading">${message}</div>`;
}

/**
 * Refresh all data
 */
async function refreshData() {
    await Promise.all([fetchStats(), fetchActivity()]);
}

/**
 * Start polling
 */
function startPolling() {
    // Initial fetch
    refreshData();

    // Poll every 5 seconds
    pollInterval = setInterval(refreshData, POLL_INTERVAL);
}

/**
 * Stop polling
 */
function stopPolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
}

// Event Listeners
refreshBtn.addEventListener('click', refreshData);

// Handle page visibility changes (pause polling when tab is hidden)
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        stopPolling();
    } else {
        startPolling();
    }
});

// Initialize on page load
document.addEventListener('DOMContentLoaded', startPolling);
