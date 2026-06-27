// Background Service Worker for Phishing Guard
// Manages badge display on the extension icon

// Store scan results per tab: { tabId: { url, verdict } }
const tabResults = {};

// --- Badge Display ---
function setBadge(tabId, verdict) {
    let text = '';
    let color = '#666666';

    switch (verdict) {
        case 'SAFE':
            text = '✓';
            color = '#22c55e'; // Green
            break;
        case 'WARNING':
            text = '!';
            color = '#f59e0b'; // Amber
            break;
        case 'PHISHING':
            text = '✕';
            color = '#ef4444'; // Red
            break;
        default:
            text = '';
            color = '#666666';
    }

    chrome.action.setBadgeText({ text: text, tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
    chrome.action.setBadgeTextColor({ color: '#ffffff', tabId: tabId });
}

function clearBadge(tabId) {
    chrome.action.setBadgeText({ text: '', tabId: tabId });
    delete tabResults[tabId];
}

// --- Listen for messages from popup.js ---
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_RESULT') {
        const { tabId, url, verdict } = message;
        tabResults[tabId] = { url: url, verdict: verdict };
        setBadge(tabId, verdict);
        sendResponse({ success: true });
    }
    return true; // Keep message channel open for async
});

// --- Clear badge when user navigates to a different page ---
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url || changeInfo.status === 'loading') {
        const stored = tabResults[tabId];
        if (stored) {
            // Get the new URL
            const newUrl = changeInfo.url || tab.url;
            if (newUrl && newUrl !== stored.url) {
                // URL changed → clear badge
                clearBadge(tabId);
            }
        }
    }
});

// --- Clear badge when tab is closed ---
chrome.tabs.onRemoved.addListener((tabId) => {
    clearBadge(tabId);
});

// --- Restore badge when user switches back to a scanned tab ---
chrome.tabs.onActivated.addListener(async (activeInfo) => {
    const tabId = activeInfo.tabId;
    const stored = tabResults[tabId];
    if (stored) {
        // Tab has a stored result, ensure badge is displayed
        setBadge(tabId, stored.verdict);
    }
    // No stored result → badge stays empty (default)
});
