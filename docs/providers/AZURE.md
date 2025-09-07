# Microsoft Entra ID (Azure AD) Setup Guide

This guide walks you through setting up Microsoft Entra ID (formerly Azure AD) as an authentication provider for Shade.

## Prerequisites

- Azure subscription with appropriate permissions
- Access to Azure Active Directory admin center
- Shade instance configured and running

## Step 1: Create App Registration

1. **Navigate to Azure Portal**
   - Go to [Azure Portal](https://portal.azure.com/)
   - Sign in with your Azure account

2. **Access Azure Active Directory**
   - Search for "Azure Active Directory" in the top search bar
   - Select "Azure Active Directory" from the results

3. **Create New App Registration**
   - In the left menu, click "App registrations"
   - Click "New registration" button
   - Fill in the application details:
     - **Name**: `Shade Identity Provider` (or your preferred name)
     - **Supported account types**: Choose based on your needs:
       - "Accounts in this organizational directory only" (single tenant)
       - "Accounts in any organizational directory" (multi-tenant)
       - "Accounts in any organizational directory and personal Microsoft accounts"
     - **Redirect URI**: Select "Web" and enter: `https://your-shade-domain.com/callback/entra`

4. **Click Register**

## Step 2: Configure Authentication

1. **Note Important Values**
   After registration, you'll see the app overview page. Note these values:
   - **Application (client) ID**: This is your `OIDC_ENTRA_CLIENT_ID`
   - **Directory (tenant) ID**: This is your `OIDC_ENTRA_TENANT_ID`

2. **Add Additional Redirect URIs** (if needed)
   - Click "Authentication" in the left menu
   - Under "Redirect URIs", add any additional URLs:
     - `https://auth.example.com/callback/entra` (production)
     - `http://localhost:8080/callback/entra` (development)

3. **Configure Token Settings**
   - In the "Authentication" section, under "Implicit grant and hybrid flows":
     - ✅ Check "ID tokens" (recommended for OpenID Connect)
   - Under "Advanced settings":
     - Set "Allow public client flows" to "No" (recommended for server-side apps)

## Step 3: Create Client Secret

1. **Navigate to Certificates & Secrets**
   - In your app registration, click "Certificates & secrets" in the left menu

2. **Create New Client Secret**
   - Click "New client secret"
   - Add a description: `Shade Identity Provider Secret`
   - Choose expiration period:
     - 6 months (more secure, requires rotation)
     - 12 months
     - 24 months
     - Custom
   - Click "Add"

3. **Copy the Secret Value**
   - **Important**: Copy the secret value immediately - it won't be shown again
   - This is your `OIDC_ENTRA_CLIENT_SECRET`

## Step 4: Configure API Permissions

1. **Navigate to API Permissions**
   - Click "API permissions" in the left menu

2. **Review Default Permissions**
   By default, the following permissions are granted:
   - `User.Read` (Microsoft Graph)

3. **Add Additional Permissions** (if needed)
   - Click "Add a permission"
   - Select "Microsoft Graph"
   - Choose "Delegated permissions"
   - Commonly used permissions for identity providers:
     - `openid` - Required for OpenID Connect
     - `profile` - Access to user's profile information
     - `email` - Access to user's email address
     - `User.Read` - Read user profile

4. **Grant Admin Consent** (if required)
   - If any permissions require admin consent, click "Grant admin consent for [Your Organization]"
   - This step may require global administrator privileges

## Step 5: Configure Shade

Add the following environment variables to your Shade configuration:

### Environment Variables

```bash
# Microsoft Entra ID Configuration
OIDC_ENTRA_TENANT_ID=your_tenant_id_here
OIDC_ENTRA_CLIENT_ID=your_client_id_here
OIDC_ENTRA_CLIENT_SECRET=your_client_secret_here
OIDC_ENTRA_REDIRECT_URI=https://your-shade-domain.com/callback/entra
```

### Docker Compose Example

```yaml
services:
  shade:
    environment:
      - OIDC_ENTRA_TENANT_ID=12345678-1234-1234-1234-123456789abc
      - OIDC_ENTRA_CLIENT_ID=87654321-4321-4321-4321-cba987654321
      - OIDC_ENTRA_CLIENT_SECRET=your_secret_value_here
      - OIDC_ENTRA_REDIRECT_URI=https://auth.example.com/callback/entra
```

### Kubernetes Secret Example

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: shade-entra-config
type: Opaque
stringData:
  tenant-id: "12345678-1234-1234-1234-123456789abc"
  client-id: "87654321-4321-4321-4321-cba987654321"
  client-secret: "your_secret_value_here"
  redirect-uri: "https://auth.example.com/callback/entra"
```

## Step 6: Test Configuration

1. **Start Shade** with the new configuration

2. **Access Login Page**
   - Navigate to `https://your-shade-domain.com/login`
   - You should see "Continue with Microsoft" option

3. **Test Authentication Flow**
   - Click "Continue with Microsoft"
   - You should be redirected to Microsoft's authentication page
   - After successful authentication, you should be redirected back to Shade

## Advanced Configuration

### Custom Claims

To access additional user information, you may need to configure token claims:

1. **Navigate to Token Configuration**
   - In your app registration, click "Token configuration"

2. **Add Optional Claims**
   - Click "Add optional claim"
   - Choose token type: "ID"
   - Select desired claims:
     - `family_name` - User's last name
     - `given_name` - User's first name
     - `picture` - User's profile picture URL
     - `preferred_username` - User's preferred username

### Group Claims

To include group membership in tokens:

1. **Add Groups Claim**
   - In "Token configuration", click "Add groups claim"
   - Select groups to include in tokens
   - Choose ID and/or access tokens
   - Configure group claim format

### Conditional Access

For additional security, configure Conditional Access policies:

1. **Navigate to Conditional Access**
   - In Azure AD, go to Security > Conditional Access

2. **Create New Policy**
   - Target your Shade application
   - Configure conditions (users, locations, devices)
   - Set access controls (require MFA, compliant devices, etc.)

## Troubleshooting

### Common Issues

#### Invalid Redirect URI
**Error**: `AADSTS50011: The redirect URI specified in the request does not match the redirect URIs configured for the application.`

**Solution**: Verify the redirect URI in Azure matches exactly what Shade is configured to use.

#### Invalid Client Secret
**Error**: `AADSTS7000215: Invalid client secret is provided.`

**Solutions**:
- Verify the client secret is correctly copied
- Check if the secret has expired
- Generate a new client secret if needed

#### Insufficient Permissions
**Error**: `AADSTS65001: The user or administrator has not consented to use the application.`

**Solutions**:
- Grant admin consent for the application
- Ensure required permissions are configured
- Check if additional permissions are needed

#### Tenant Configuration Issues
**Error**: `AADSTS50020: User account from identity provider does not exist in tenant.`

**Solutions**:
- Verify the tenant ID is correct
- Check if the user exists in the configured tenant
- Ensure the account type configuration matches your needs

### Debugging Steps

1. **Check Azure AD Logs**
   - Navigate to Azure AD > Sign-in logs
   - Filter by application name
   - Review error details

2. **Verify Configuration**
   ```bash
   # Test Entra ID well-known endpoint
   curl "https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
   ```

3. **Check Shade Logs**
   ```bash
   # Enable debug logging
   RUST_LOG=shade=debug docker-compose logs shade
   ```

### Security Best Practices

1. **Rotate Secrets Regularly**
   - Set appropriate expiration periods
   - Implement secret rotation procedures
   - Monitor secret expiration dates

2. **Use Least Privilege**
   - Only request necessary permissions
   - Regularly review granted permissions
   - Remove unused permissions

3. **Enable Additional Security**
   - Implement Conditional Access policies
   - Require multi-factor authentication
   - Monitor sign-in activities

4. **Secure Configuration**
   - Use HTTPS for all redirect URIs
   - Store secrets securely (environment variables, key vaults)
   - Never commit secrets to version control

## Support

For additional help:
- [Microsoft Identity Platform Documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
- [Azure AD App Registration Guide](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- [OpenID Connect with Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc)