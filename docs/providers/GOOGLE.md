# Google OAuth 2.0 Setup Guide

This guide walks you through setting up Google as an authentication provider for Shade using Google's OAuth 2.0 and OpenID Connect.

## Prerequisites

- Google account with access to Google Cloud Console
- Shade instance configured and running
- A registered domain (for production use)

## Step 1: Create Google Cloud Project

1. **Navigate to Google Cloud Console**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Sign in with your Google account

2. **Create New Project** (if needed)
   - Click the project dropdown at the top of the page
   - Click "New Project"
   - Enter project name: `Shade Identity Provider` (or your preferred name)
   - Select organization (if applicable)
   - Click "Create"

3. **Select Your Project**
   - Ensure the correct project is selected in the project dropdown

## Step 2: Enable Required APIs

1. **Navigate to APIs & Services**
   - In the left menu, click "APIs & Services" > "Library"

2. **Enable Google+ API** (Legacy but still required for basic profile info)
   - Search for "Google+ API"
   - Click on "Google+ API"
   - Click "Enable"

3. **Enable People API** (Modern alternative, recommended)
   - Search for "People API"
   - Click on "People API"
   - Click "Enable"

Note: Google+ API is deprecated but may still be required for some OAuth flows. The People API is the modern replacement.

## Step 3: Configure OAuth Consent Screen

1. **Navigate to OAuth Consent Screen**
   - Go to "APIs & Services" > "OAuth consent screen"

2. **Choose User Type**
   - **Internal**: Only users in your Google Workspace organization (if applicable)
   - **External**: Any Google account user (most common choice)
   - Select your preferred option and click "Create"

3. **Configure App Information**
   - **App name**: `Shade Identity Provider` (or your app name)
   - **User support email**: Your email address
   - **App logo** (optional): Upload a logo (120x120px recommended)
   - **Application home page** (optional): `https://your-shade-domain.com`
   - **Application privacy policy link** (recommended): Link to your privacy policy
   - **Application terms of service link** (optional): Link to your terms

4. **Configure Authorized Domains**
   - Add your domain(s): `your-shade-domain.com`
   - This restricts where OAuth callbacks can be sent

5. **Developer Contact Information**
   - Add your email address
   - Click "Save and Continue"

6. **Configure Scopes**
   - Click "Add or Remove Scopes"
   - Select the following scopes:
     - `../auth/userinfo.email` - See your primary Google Account email address
     - `../auth/userinfo.profile` - See your personal info, including any personal info you've made publicly available
     - `openid` - Associate you with your personal info on Google
   - Click "Update" then "Save and Continue"

7. **Test Users** (for External apps in testing)
   - Add test user email addresses if your app is still in testing mode
   - Production apps don't need this step after verification

8. **Summary**
   - Review your configuration
   - Click "Back to Dashboard"

## Step 4: Create OAuth 2.0 Credentials

1. **Navigate to Credentials**
   - Go to "APIs & Services" > "Credentials"

2. **Create OAuth 2.0 Client ID**
   - Click "Create Credentials" > "OAuth 2.0 Client ID"
   - **Application type**: Select "Web application"
   - **Name**: `Shade Web Client` (or your preferred name)

3. **Configure Authorized Origins** (optional but recommended)
   - Add origins that can make OAuth requests:
   - `https://your-shade-domain.com`
   - `http://localhost:8083` (for development)

4. **Configure Authorized Redirect URIs**
   - Add the callback URLs for your Shade instance:
   - `https://your-shade-domain.com/callback/google` (production)
   - `http://localhost:8083/callback/google` (development)
   - Click "Create"

5. **Download Credentials**
   - A modal will appear with your client ID and client secret
   - **Client ID**: This is your `OIDC_GOOGLE_CLIENT_ID`
   - **Client Secret**: This is your `OIDC_GOOGLE_CLIENT_SECRET`
   - Download the JSON file or copy the values securely

## Step 5: Configure Shade

Add the following environment variables to your Shade configuration:

### Environment Variables

```bash
# Google OAuth Configuration
OIDC_GOOGLE_CLIENT_ID=123456789-abcdefghijklmnop.apps.googleusercontent.com
OIDC_GOOGLE_CLIENT_SECRET=GOCSPX-your_client_secret_here
OIDC_GOOGLE_REDIRECT_URI=https://your-shade-domain.com/callback/google
```

### Docker Compose Example

```yaml
services:
  shade:
    environment:
      - OIDC_GOOGLE_CLIENT_ID=123456789-abcdefghijklmnop.apps.googleusercontent.com
      - OIDC_GOOGLE_CLIENT_SECRET=GOCSPX-1234567890abcdef1234567890ab
      - OIDC_GOOGLE_REDIRECT_URI=https://auth.example.com/callback/google
```

### Kubernetes Secret Example

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: shade-google-config
type: Opaque
stringData:
  client-id: "123456789-abcdefghijklmnop.apps.googleusercontent.com"
  client-secret: "GOCSPX-1234567890abcdef1234567890ab"
  redirect-uri: "https://auth.example.com/callback/google"
```

## Step 6: Test Configuration

1. **Start Shade** with the new configuration

2. **Access Login Page**
   - Navigate to `https://your-shade-domain.com/login`
   - You should see "Continue with Google" option

3. **Test Authentication Flow**
   - Click "Continue with Google"
   - You should be redirected to Google's authentication page
   - After successful authentication, you should be redirected back to Shade
   - A new user account should be created in Shade

## Google OAuth Scopes

Shade requests the following OAuth scopes from Google:

- **`openid`**: Required for OpenID Connect
- **`email`**: Access to user's email address
- **`profile`**: Access to basic profile information (name, picture)

These correspond to the following user information:
```json
{
  "sub": "123456789012345678901",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "picture": "https://lh3.googleusercontent.com/a/example",
  "locale": "en"
}
```

## Advanced Configuration

### Custom Scopes

If you need additional user information, you can request additional scopes by modifying the Shade Google provider:

Available additional scopes:
- `https://www.googleapis.com/auth/user.birthday.read` - Birthday
- `https://www.googleapis.com/auth/user.gender.read` - Gender
- `https://www.googleapis.com/auth/user.phonenumbers.read` - Phone numbers
- `https://www.googleapis.com/auth/user.addresses.read` - Addresses

### Google Workspace Integration

For Google Workspace (formerly G Suite) organizations:

1. **Domain Restrictions**
   - In the OAuth consent screen, you can restrict to specific domains
   - Add your organization's domain to limit access

2. **Admin SDK Integration**
   - Enable Admin SDK API for additional user information
   - Requires domain-wide delegation setup

3. **Organization Unit Restrictions**
   - Can be implemented in Shade logic after authentication
   - Use Google Admin SDK to check user's organizational unit

### Refresh Tokens

Google provides refresh tokens for offline access. Shade automatically handles:
- Requesting `access_type=offline` for refresh tokens
- Using `prompt=consent` to ensure refresh token is issued
- Storing and managing refresh token lifecycle

## Security Considerations

### Best Practices

1. **Use HTTPS Only**
   - Never use HTTP for redirect URIs in production
   - Google requires HTTPS for authorized redirect URIs

2. **Domain Verification**
   - Verify ownership of domains in Google Console
   - Add domains to authorized domains list

3. **Regular Key Rotation**
   - Rotate client secrets regularly
   - Monitor OAuth app usage in Google Console

4. **Scope Minimization**
   - Only request necessary scopes
   - Users can see exactly what permissions you're requesting

### Production Checklist

Before going live:
- [ ] OAuth consent screen is configured and published
- [ ] All redirect URIs use HTTPS
- [ ] Domain ownership is verified
- [ ] Privacy policy and terms of service are accessible
- [ ] App has been reviewed by Google (if required)
- [ ] Rate limits and quotas are appropriate for your usage

## Troubleshooting

### Common Issues

#### "This app isn't verified"
**Issue**: Users see a warning about unverified app

**Solutions**:
1. **Publish your app** in OAuth consent screen settings
2. **Submit for verification** if you need sensitive scopes
3. **Add users to test users list** during development

#### Invalid Redirect URI
**Error**: `redirect_uri_mismatch`

**Solutions**:
- Verify the redirect URI exactly matches what's configured in Google Console
- Check for trailing slashes, HTTP vs HTTPS
- Ensure the domain is in authorized domains list

#### Client ID Mismatch
**Error**: `invalid_client`

**Solutions**:
- Verify the client ID is copied correctly
- Check if the client ID is from the correct Google Cloud project
- Ensure the client hasn't been deleted or disabled

#### Insufficient Permissions
**Error**: `access_denied` or `insufficient_permissions`

**Solutions**:
- Check if required APIs are enabled
- Verify OAuth scopes are configured correctly
- Ensure user has permissions to access the requested data

### API Quotas and Limits

Google imposes various quotas:

1. **Queries per day**: 1,000,000 (can be increased)
2. **Queries per 100 seconds per user**: 1,000
3. **Queries per 100 seconds**: 100,000

Monitor usage in Google Console:
- Go to "APIs & Services" > "Quotas"
- Filter by API (Google+ API, People API)

### Debugging Steps

1. **Check Google Console Logs**
   - Go to "APIs & Services" > "Credentials"
   - Click on your OAuth 2.0 client
   - Review recent activity

2. **Test OAuth Flow Manually**
   ```bash
   # Test authorization URL
   curl "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&scope=openid%20email%20profile&state=test"
   ```

3. **Verify Token Exchange**
   ```bash
   # Test token endpoint
   curl -X POST "https://oauth2.googleapis.com/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=YOUR_REDIRECT_URI&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET"
   ```

4. **Check Shade Logs**
   ```bash
   # Enable debug logging
   RUST_LOG=shade=debug docker-compose logs shade
   ```

## Google Cloud Console Monitoring

### Usage Analytics

Monitor OAuth usage:
1. Go to "APIs & Services" > "Dashboard"
2. Select Google+ API or People API
3. View request metrics and error rates

### Error Analysis

Common errors in Google Console:
- `invalid_grant`: Authorization code expired or invalid
- `unauthorized_client`: Client not authorized for this grant type
- `invalid_scope`: Requested scope is invalid or malformed

### Quota Management

Manage API quotas:
1. Go to "APIs & Services" > "Quotas"
2. Filter by API name
3. Request quota increases if needed

## Testing Different Scenarios

1. **First-Time User**
   - Test with a Google account that hasn't used your app
   - Verify consent screen appears correctly
   - Confirm user data is captured properly

2. **Returning User**
   - Test with a user who has previously authenticated
   - Verify seamless re-authentication
   - Check that user data is updated

3. **Revoked Permissions**
   - Revoke app permissions in Google account settings
   - Test authentication after revocation
   - Verify consent screen appears again

4. **Different Account Types**
   - Test with personal Google accounts
   - Test with Google Workspace accounts
   - Verify different account types work correctly

## Support

For additional help:
- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [OpenID Connect Documentation](https://developers.google.com/identity/protocols/openidconnect)
- [Google Console Help](https://support.google.com/googleapi/)