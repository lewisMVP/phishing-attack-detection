document.addEventListener('DOMContentLoaded', function() {
    // 1. Get current tab URL
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        let currentTab = tabs[0];
        let url = currentTab.url;
        let tabId = currentTab.id;
        document.getElementById('current-url').textContent = url;

        // 2. Handle Scan Button
        document.getElementById('scan-btn').addEventListener('click', async () => {
            const btn = document.getElementById('scan-btn');
            const btnText = btn.querySelector('.btn-text');
            const resultDiv = document.getElementById('result');
            const errorDiv = document.getElementById('error');
            const statusCard = document.getElementById('status-card');
            const statusIcon = document.getElementById('status-icon');
            const verdictElem = document.getElementById('verdict');
            const verdictDesc = document.getElementById('verdict-desc');
            
            // UI Loading State
            btnText.textContent = "Analyzing...";
            btn.disabled = true;
            resultDiv.classList.add('hidden');
            errorDiv.classList.add('hidden');
            
            statusCard.className = "status-card scanning";
            statusIcon.innerHTML = `<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
            </svg>`;
            verdictElem.textContent = "Scanning...";
            verdictDesc.textContent = "Collecting page data for analysis";

            try {
                let htmlContent = "";
                let screenshotBase64 = "";

                // --- STEP A: CAPTURE PAGE HTML (Safe Mode) ---
                try {
                    const htmlResults = await chrome.scripting.executeScript({
                        target: { tabId: tabId },
                        func: () => document.documentElement.outerHTML
                    });
                    htmlContent = htmlResults[0]?.result || "";
                    console.log("HTML captured length:", htmlContent.length);
                } catch (e) {
                    console.warn("Could not capture HTML (Restricted page or Browser Error):", e);
                }

                // --- STEP B: CAPTURE SCREENSHOT (Safe Mode) ---
                try {
                    screenshotBase64 = await chrome.tabs.captureVisibleTab(null, {format: 'jpeg', quality: 50});
                    console.log("Screenshot captured!");
                } catch (e) {
                     console.warn("Could not capture Screenshot:", e);
                }

                // --- STEP C: SEND TO SERVER ---
                verdictElem.textContent = "Processing...";
                verdictDesc.textContent = "AI is analyzing the website";
                
                const API_URL = 'https://phishing-detection-api.onrender.com/predict'; // Change to localhost for dev
                const response = await fetch(API_URL, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        url: url,
                        html_content: htmlContent,       
                        screenshot_base64: screenshotBase64 
                    })
                });

                if (!response.ok) throw new Error('Server connection failed');

                const data = await response.json();
                const confidencePercent = Math.round(data.confidence * 100);

                // 4. Update UI
                resultDiv.classList.remove('hidden');
                
                if (data.final_verdict === 'PHISHING') {
                    statusCard.className = "status-card phishing";
                    statusIcon.innerHTML = `<svg width="48" height="48" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                        <path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>
                    </svg>`;
                    verdictElem.textContent = "Threat Detected";
                    verdictDesc.textContent = "This website appears to be a phishing attempt";
                } else {
                    statusCard.className = "status-card safe";
                    statusIcon.innerHTML = `<svg width="48" height="48" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5zm-2 15l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>
                    </svg>`;
                    verdictElem.textContent = "Website Safe";
                    verdictDesc.textContent = "No threats detected on this website";
                }

                document.getElementById('confidence').textContent = confidencePercent + "%";
                document.getElementById('confidence-fill').style.width = confidencePercent + "%";
                document.getElementById('score').textContent = data.details.url_score.toFixed(2);
                
                console.log("Modules run:", data.details.modules_run);

            } catch (err) {
                console.error(err);
                document.getElementById('error-text').textContent = err.message;
                errorDiv.classList.remove('hidden');
                statusCard.className = "status-card neutral";
                statusIcon.innerHTML = `<svg width="48" height="48" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
                </svg>`;
                verdictElem.textContent = "Scan Failed";
                verdictDesc.textContent = "Could not connect to the analysis server";
            } finally {
                btnText.textContent = "Scan Again";
                btn.disabled = false;
            }
        });
    });
});