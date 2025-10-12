export const handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' }),
    };
  }

  try {
    const data = JSON.parse(event.body);
    const { code, redirect_uri, state } = data;
    // NOTE: We ignore code_verifier completely for confidential client flow

    if (!code) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Authorization code is required' }),
      };
    }

    // Get client secret from environment variables
    const CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET;
    
    if (!CLIENT_SECRET) {
      return {
        statusCode: 500,
        headers,
        body: JSON.stringify({ 
          error: 'Client secret not configured',
          hint: 'MICROSOFT_CLIENT_SECRET environment variable is required'
        }),
      };
    }

    // Microsoft OAuth credentials - CONFIDENTIAL CLIENT CONFIGURATION
    const CLIENT_ID = '5ea82524-4850-4e5f-98cb-d866b1282bd5';
    const REGISTERED_REDIRECT_URI = 'https://gateportdocs.com/oauth-callback';
    const REDIRECT_URI = redirect_uri || REGISTERED_REDIRECT_URI;
    const SCOPE = 'openid profile email User.Read offline_access';

    // Build token request parameters for CONFIDENTIAL CLIENT (client_secret)
    const tokenRequestBody = new URLSearchParams();
    tokenRequestBody.append('client_id', CLIENT_ID);
    tokenRequestBody.append('client_secret', CLIENT_SECRET);
    tokenRequestBody.append('grant_type', 'authorization_code');
    tokenRequestBody.append('code', code);
    tokenRequestBody.append('redirect_uri', REDIRECT_URI);
    tokenRequestBody.append('scope', SCOPE);
    // NOTE: No code_verifier for confidential client

    console.log('Token exchange request for confidential client:', {
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      has_code: !!code,
      has_client_secret: !!CLIENT_SECRET,
      state: state
    });

    // Exchange authorization code for tokens
    const tokenResponse = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: tokenRequestBody.toString(),
    });

    const tokenData = await tokenResponse.json();

    if (tokenData.error) {
      console.error('Microsoft token exchange error:', tokenData);
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Token exchange failed',
          errorCode: tokenData.error,
          details: tokenData.error_description,
          authorizationCode: code.substring(0, 20) + '...',
          authMethod: 'Client Secret (Confidential Client)',
          clientId: CLIENT_ID,
          redirectUri: REDIRECT_URI,
          hint: tokenData.error === 'invalid_grant' ?
            'Authorization code may have expired or been used already. Try authenticating again.' :
            tokenData.error === 'invalid_client' ?
            'Client authentication failed. Check your client secret configuration.' :
            tokenData.error === 'redirect_uri_mismatch' ?
            'Redirect URI mismatch. Ensure the redirect_uri matches exactly what is registered in Azure AD.' :
            tokenData.error === 'invalid_request' ?
            'Invalid request parameters. Check that all required parameters are included.' :
            'Check your OAuth configuration in Azure AD portal.'
        }),
      };
    }

    // Extract tokens
    const {
      access_token,
      refresh_token,
      id_token,
      token_type = 'Bearer',
      expires_in,
      scope: granted_scope,
      ext_expires_in
    } = tokenData;

    console.log('Token exchange successful:', {
      has_access_token: !!access_token,
      has_refresh_token: !!refresh_token,
      has_id_token: !!id_token,
      expires_in: expires_in,
      granted_scope: granted_scope
    });

    // Step 1: Parse ID token to extract email
    let userEmail = null;
    let idTokenClaims = null;

    if (id_token) {
      try {
        const tokenParts = id_token.split('.');
        if (tokenParts.length === 3) {
          const payload = tokenParts[1];
          const paddedPayload = payload + '='.repeat((4 - payload.length % 4) % 4);
          const decodedPayload = Buffer.from(paddedPayload, 'base64').toString('utf8');
          idTokenClaims = JSON.parse(decodedPayload);
          userEmail = idTokenClaims.email ||
                     idTokenClaims.preferred_username ||
                     idTokenClaims.upn ||
                     idTokenClaims.unique_name;
        }
      } catch (jwtError) {
        console.error('JWT parsing error:', jwtError);
      }
    }

    // Step 2: Always try Graph API if access_token, to get the freshest/real email
    let userProfile = null;
    let emailFromGraph = null;
    if (access_token) {
      try {
        const profileResponse = await fetch('https://graph.microsoft.com/v1.0/me', {
          headers: {
            'Authorization': `Bearer ${access_token}`,
            'Accept': 'application/json',
          },
        });

        if (profileResponse.ok) {
          userProfile = await profileResponse.json();
          // If Graph API returns a usable email, prefer this
          emailFromGraph = userProfile.mail ||
                           userProfile.userPrincipalName ||
                           (userProfile.otherMails && userProfile.otherMails.length > 0 ? userProfile.otherMails[0] : null);
          if (emailFromGraph) {
            userEmail = emailFromGraph;
          }
          console.log('User profile retrieved:', {
            email: emailFromGraph,
            displayName: userProfile.displayName,
            userPrincipalName: userProfile.userPrincipalName
          });
        } else {
          console.error('Graph API error:', profileResponse.status, await profileResponse.text());
        }
      } catch (profileError) {
        console.error('Graph API error:', profileError);
      }
    }

    // If still no email, fallback to a placeholder
    if (!userEmail) {
      userEmail = "user-email-pending@oauth.exchange";
    }

    // Prepare comprehensive response with REAL USER DATA
    const tokenResult = {
      success: true,
      message: 'Token exchange completed successfully using Client Secret (Confidential Client)',
      timestamp: new Date().toISOString(),
      email: userEmail,
      emailSource: emailFromGraph ? 'graph_api' : (idTokenClaims ? 'id_token' : null),
      tokens: {
        access_token: access_token,
        refresh_token: refresh_token,
        id_token: id_token,
        token_type: token_type,
        expires_in: expires_in,
        scope: granted_scope || SCOPE,
        offline_access: granted_scope?.includes('offline_access') || false,
      },
      user: {
        email: userEmail,
        id: userProfile?.id || idTokenClaims?.oid || idTokenClaims?.sub,
        displayName: userProfile?.displayName || idTokenClaims?.name,
        givenName: userProfile?.givenName || idTokenClaims?.given_name,
        surname: userProfile?.surname || idTokenClaims?.family_name,
        userPrincipalName: userProfile?.userPrincipalName || idTokenClaims?.upn,
        jobTitle: userProfile?.jobTitle,
        businessPhones: userProfile?.businessPhones,
        mobilePhone: userProfile?.mobilePhone,
        officeLocation: userProfile?.officeLocation,
      },
      oauth: {
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
        scope: SCOPE,
        grantType: 'authorization_code',
        authMethod: 'Client Secret (Confidential Client)',
        state: state,
        hasPKCE: false,
        hasClientSecret: true
      }
    };

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(tokenResult),
    };

  } catch (error) {
    console.error('Token exchange error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Internal server error during token exchange',
        message: error.message,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
      }),
    };
  }
};
