# GitHub OAuth Setup Guide

This guide walks you through setting up GitHub as an authentication provider for Shade using GitHub's OAuth Apps.

## Prerequisites

- GitHub account with appropriate permissions
- Shade instance configured and running
- Administrative access to the GitHub organization (if using organization-level OAuth Apps)

## Step 1: Create OAuth App

### Personal Account OAuth App

1. **Navigate to GitHub Settings**
   - Go to [GitHub.com](https://github.com) and sign in
   - Click your profile picture in the top right
   - Select "Settings" from the dropdown

2. **Access Developer Settings**
   - In the left sidebar, scroll down and click "Developer settings"
   - Click "OAuth Apps" in the left menu

3. **Create New OAuth App**
   - Click "New OAuth App" button
   - Fill in the application details:
     - **Application name**: `Shade Identity Provider` (or your preferred name)
     - **Homepage URL**: `https://your-shade-domain.com`
     - **Application description** (optional): `Self-hosted identity provider using Shade`
     - **Authorization callback URL**: `https://your-shade-domain.com/callback/github`

4. **Click "Register application"**

### Organization OAuth App (Recommended for Teams)

1. **Navigate to Organization Settings**
   - Go to your organization page: `https://github.com/your-organization`
   - Click the "Settings" tab

2. **Access Developer Settings**
   - In the left sidebar, click "Developer settings"
   - Click "OAuth Apps"

3. **Follow the same steps as above** to create the OAuth App

## Step 2: Configure OAuth App Settings

1. **Note Application Credentials**
   After creation, you'll see the app details page with:
   - **Client ID**: This is your `OIDC_GITHUB_CLIENT_ID`
   - **Client Secret**: Click "Generate a new client secret" to create your `OIDC_GITHUB_CLIENT_SECRET`

2. **Configure Additional Settings**
   - **Homepage URL**: Update if needed for your production domain
   - **Authorization callback URL**: Add multiple URLs if you have different environments:
     - `https://auth.example.com/callback/github` (production)
     - `http://localhost:8080/callback/github` (development)
     - `https://staging.example.com/callback/github` (staging)

3. **Advanced Settings**
   - **Enable Device Flow**: Leave unchecked (not needed for web applications)
   - **Request user authorization (OAuth) during installation**: Check this for better UX

## Step 3: Configure Shade

Add the following environment variables to your Shade configuration:

### Environment Variables

```bash
# GitHub OAuth Configuration
OIDC_GITHUB_CLIENT_ID=your_github_client_id
OIDC_GITHUB_CLIENT_SECRET=your_github_client_secret
OIDC_GITHUB_REDIRECT_URI=https://your-shade-domain.com/callback/github
```

### Docker Compose Example

```yaml
services:
  shade:
    environment:
      - OIDC_GITHUB_CLIENT_ID=Iv1.a1b2c3d4e5f6g7h8
      - OIDC_GITHUB_CLIENT_SECRET=1234567890abcdef1234567890abcdef12345678
      - OIDC_GITHUB_REDIRECT_URI=https://auth.example.com/callback/github
```

### Kubernetes Secret Example

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: shade-github-config
type: Opaque
stringData:
  client-id: "Iv1.a1b2c3d4e5f6g7h8"
  client-secret: "1234567890abcdef1234567890abcdef12345678"
  redirect-uri: "https://auth.example.com/callback/github"
```

## Step 4: Test Configuration

1. **Start Shade** with the new configuration

2. **Access Login Page**
   - Navigate to `https://your-shade-domain.com/login`
   - You should see "Continue with GitHub" option

3. **Test Authentication Flow**
   - Click "Continue with GitHub"
   - You should be redirected to GitHub's authentication page
   - After successful authentication, you should be redirected back to Shade

## GitHub API Permissions

Shade requests the following OAuth scopes from GitHub:

- **`user:email`**: Access to user's email addresses
  - Includes primary email
  - Includes email verification status
  - Required for user identification

Note: GitHub OAuth Apps automatically include access to public profile information.

## Advanced Configuration

### Organization Restrictions

If you want to restrict access to specific GitHub organizations:

1. **Organization Settings**
   - In your organization, go to Settings > Member privileges
   - Under "Third-party application access policy"
   - Configure restrictions for OAuth Apps

2. **App Installation Requirements**
   - Consider using GitHub Apps instead of OAuth Apps for fine-grained permissions
   - GitHub Apps can be installed per-organization with specific permissions

### Email Privacy Settings

GitHub users can choose to keep their email addresses private. Shade handles this by:

1. **Requesting `user:email` scope** to access all email addresses
2. **Falling back to primary email** from the user profile if public
3. **Using the GitHub API** to fetch email addresses directly

If a user has no public email, Shade will fetch their primary email through the GitHub API.

### Custom User Mapping

You can customize how GitHub user data maps to Shade users by modifying the provider configuration. The following GitHub profile fields are available:

```json
{
  "id": 12345678,
  "login": "octocat",
  "name": "The Octocat",
  "email": "octocat@github.com",
  "avatar_url": "https://github.com/images/error/octocat_happy.gif",
  "company": "GitHub",
  "location": "San Francisco",
  "bio": "There once was...",
  "public_repos": 2,
  "followers": 20,
  "following": 0,
  "created_at": "2008-01-14T04:33:35Z"
}
```

## Security Considerations

### OAuth App vs GitHub App

**OAuth Apps** (what we're using):
- ✅ Simpler to set up
- ✅ Works with personal and organization accounts
- ❌ Broader permissions (act on behalf of user)
- ❌ No fine-grained permissions

**GitHub Apps** (alternative):
- ✅ Fine-grained permissions
- ✅ Better security model
- ✅ Can be installed per-organization
- ❌ More complex setup
- ❌ May be overkill for authentication only

### Best Practices

1. **Use Organization OAuth Apps** when possible for better control
2. **Regularly rotate client secrets**
3. **Monitor OAuth App usage** in GitHub settings
4. **Review permissions** periodically
5. **Use HTTPS** for all callback URLs

## Troubleshooting

### Common Issues

#### Invalid Redirect URI
**Error**: `The redirect_uri MUST match the registered callback URL for this application.`

**Solution**: Verify the redirect URI in GitHub matches exactly what Shade is configured to use. Common issues:
- HTTP vs HTTPS mismatch
- Port number differences
- Trailing slash differences

#### Application Suspended
**Error**: `This application has been suspended.`

**Solutions**:
- Check if the OAuth App violates GitHub's terms
- Contact GitHub support if suspended incorrectly
- Verify the app is not being used maliciously

#### Rate Limiting
**Error**: `API rate limit exceeded`

**Solutions**:
- Implement proper rate limiting in Shade
- Use authenticated requests (they have higher rate limits)
- Cache user data when possible

#### Email Access Issues
**Error**: User authentication succeeds but no email is available

**Solutions**:
- Ensure `user:email` scope is requested
- Check if user has set email to private
- Verify GitHub API access is working

### Debugging Steps

1. **Check GitHub OAuth App Settings**
   - Verify client ID and secret
   - Confirm callback URL is correct
   - Check if app is active

2. **Test GitHub API Access**
   ```bash
   # Test with your access token
   curl -H "Authorization: token YOUR_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        https://api.github.com/user
   ```

3. **Check Shade Logs**
   ```bash
   # Enable debug logging
   RUST_LOG=shade=debug docker-compose logs shade
   ```

4. **Verify OAuth Flow**
   - Check network tab in browser developer tools
   - Verify redirect parameters
   - Confirm state parameter is passed correctly

### Testing Different Scenarios

1. **New User Registration**
   - Use a GitHub account that hasn't logged into Shade before
   - Verify user is created correctly

2. **Existing User Login**
   - Test with a user who has previously logged in
   - Verify user data is updated appropriately

3. **Private Email Users**
   - Test with a GitHub account that has email set to private
   - Verify Shade can still access email through API

4. **Organization Members**
   - Test with users from different organizations
   - Verify organization restrictions work if configured

## GitHub Enterprise

For GitHub Enterprise Server installations:

1. **Update OAuth URLs**
   ```bash
   # For GitHub Enterprise Server
   GITHUB_BASE_URL=https://github.company.com
   ```

2. **Configure Custom Endpoints**
   The provider automatically detects GitHub Enterprise and adjusts endpoints:
   - Authorization: `https://github.company.com/login/oauth/authorize`
   - Token: `https://github.company.com/login/oauth/access_token`
   - User API: `https://github.company.com/api/v3/user`

3. **SSL Certificate Considerations**
   - Ensure valid SSL certificates for GitHub Enterprise
   - Configure Shade to trust custom CA if needed

## Monitoring and Analytics

### OAuth App Usage

Monitor your OAuth App usage in GitHub:
1. Go to your OAuth App settings
2. Click on the app name
3. View the "Advanced" tab for usage statistics

### User Authentication Metrics

Track authentication metrics in Shade:
```sql
-- GitHub authentication attempts
SELECT 
  DATE_TRUNC('day', created_at) as date,
  COUNT(*) as github_logins
FROM audit_logs 
WHERE action = 'user.login' 
AND details->>'provider' = 'github'
GROUP BY date
ORDER BY date;
```

## Support

For additional help:
- [GitHub OAuth Apps Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps)
- [GitHub API Documentation](https://docs.github.com/en/rest)
- [OAuth 2.0 Specification](https://tools.ietf.org/html/rfc6749)