// DDoS Protection Client-Side Script
// This script adds protection without changing page appearance

(function() {
    // Configuration
    const config = {
        requestThrottling: true,        // Throttle rapid requests
        honeypotProtection: true,       // Add invisible honeypot elements
        browserFingerprinting: true,    // Check for bot fingerprints
        requestValidation: true,        // Add validation tokens to requests
        maxRequestsPerSecond: 50,       // Maximum requests allowed per second
        cooldownPeriod: 2000,           // Cooldown period in ms after hitting limit
        tokenRefreshInterval: 300000    // Token refresh interval (5 minutes)
    };

    // Request tracking
    let requestCount = 0;
    let lastRequestTime = 0;
    let cooldownActive = false;
    let validationToken = '';
    
    // Generate a validation token
    function generateToken() {
        const randomBytes = new Uint8Array(16);
        window.crypto.getRandomValues(randomBytes);
        return Array.from(randomBytes, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    // Initialize validation token
    validationToken = generateToken();
    
    // Refresh token periodically
    setInterval(() => {
        validationToken = generateToken();
    }, config.tokenRefreshInterval);
    
    // Add validation token to all AJAX requests
    if (config.requestValidation) {
        const originalXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function() {
            const originalSend = this.send;
            this.send = function(data) {
                // Add validation headers
                this.setRequestHeader('X-Request-Validation', validationToken);
                
                // Throttle if needed
                if (config.requestThrottling) {
                    const now = Date.now();
                    
                    // Check if in cooldown
                    if (cooldownActive) {
                        console.warn('Request blocked due to rate limiting cooldown');
                        return;
                    }
                    
                    // Reset counter if more than 1 second has passed
                    if (now - lastRequestTime > 1000) {
                        requestCount = 0;
                        lastRequestTime = now;
                    }
                    
                    // Increment counter
                    requestCount++;
                    
                    // Check if limit exceeded
                    if (requestCount > config.maxRequestsPerSecond) {
                        console.warn('Request rate limit exceeded, entering cooldown');
                        cooldownActive = true;
                        setTimeout(() => {
                            cooldownActive = false;
                            requestCount = 0;
                        }, config.cooldownPeriod);
                        return;
                    }
                }
                
                return originalSend.apply(this, arguments);
            };
            return originalXHROpen.apply(this, arguments);
        };
        
        // Also protect fetch API
        const originalFetch = window.fetch;
        window.fetch = function(resource, options) {
            // Initialize options if not provided
            options = options || {};
            
            // Add validation headers
            options.headers = options.headers || {};
            if (typeof options.headers.append === 'function') {
                options.headers.append('X-Request-Validation', validationToken);
            } else {
                options.headers['X-Request-Validation'] = validationToken;
            }
            
            // Throttle if needed
            if (config.requestThrottling) {
                const now = Date.now();
                
                // Check if in cooldown
                if (cooldownActive) {
                    console.warn('Request blocked due to rate limiting cooldown');
                    return new Promise((resolve, reject) => {
                        reject(new Error('Request blocked due to rate limiting'));
                    });
                }
                
                // Reset counter if more than 1 second has passed
                if (now - lastRequestTime > 1000) {
                    requestCount = 0;
                    lastRequestTime = now;
                }
                
                // Increment counter
                requestCount++;
                
                // Check if limit exceeded
                if (requestCount > config.maxRequestsPerSecond) {
                    console.warn('Request rate limit exceeded, entering cooldown');
                    cooldownActive = true;
                    setTimeout(() => {
                        cooldownActive = false;
                        requestCount = 0;
                    }, config.cooldownPeriod);
                    return new Promise((resolve, reject) => {
                        reject(new Error('Request rate limit exceeded'));
                    });
                }
            }
            
            return originalFetch.call(this, resource, options);
        };
    }
    
    // Add honeypot elements to detect bots
    if (config.honeypotProtection) {
        // Create invisible honeypot elements that only bots would interact with
        const honeypot = document.createElement('div');
        honeypot.style.opacity = '0';
        honeypot.style.position = 'absolute';
        honeypot.style.height = '0';
        honeypot.style.overflow = 'hidden';
        honeypot.style.visibility = 'hidden';
        honeypot.innerHTML = `
            <a href="/bot-trap" id="honeypot-link">Click here</a>
            <form id="honeypot-form">
                <input type="text" name="honeypot-field" id="honeypot-input">
                <button type="submit">Submit</button>
            </form>
        `;
        document.body.appendChild(honeypot);
        
        // Monitor honeypot interactions
        document.getElementById('honeypot-link').addEventListener('click', function(e) {
            e.preventDefault();
            console.warn('Bot detected: Honeypot link clicked');
            // Report bot activity to server
            navigator.sendBeacon('/report-bot', JSON.stringify({
                type: 'honeypot_link',
                timestamp: Date.now()
            }));
        });
        
        document.getElementById('honeypot-form').addEventListener('submit', function(e) {
            e.preventDefault();
            console.warn('Bot detected: Honeypot form submitted');
            // Report bot activity to server
            navigator.sendBeacon('/report-bot', JSON.stringify({
                type: 'honeypot_form',
                timestamp: Date.now()
            }));
        });
        
        document.getElementById('honeypot-input').addEventListener('input', function() {
            console.warn('Bot detected: Honeypot input filled');
            // Report bot activity to server
            navigator.sendBeacon('/report-bot', JSON.stringify({
                type: 'honeypot_input',
                timestamp: Date.now()
            }));
        });
    }
    
    // Browser fingerprinting to detect bots
    if (config.browserFingerprinting) {
        // Check for common bot fingerprints
        const botDetected = (
            // Check for headless browser
            navigator.webdriver ||
            // Check for automation
            navigator.userAgent.includes('Headless') ||
            // Check for inconsistent properties
            (window.chrome && !window.chrome.runtime) ||
            // Check for missing properties
            !window.outerWidth || !window.outerHeight ||
            // Check for suspicious plugins length
            navigator.plugins.length === 0
        );
        
        if (botDetected) {
            console.warn('Bot detected: Suspicious browser fingerprint');
            // Report bot activity to server
            navigator.sendBeacon('/report-bot', JSON.stringify({
                type: 'suspicious_fingerprint',
                timestamp: Date.now()
            }));
        }
    }
    
    // Log initialization
    console.log('DDoS protection initialized');
})();
