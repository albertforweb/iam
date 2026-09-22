# IAM integration guide

IAM is the identity provider and OAuth/OIDC authorization server. Applications own the meaning of their roles and permissions. A role name is never global: `admin` in one application is unrelated to `admin` in another application.

## Local configuration

```text
IAM_DB_PATH=/absolute/path/iam.db
IAM_ADMIN_USERNAME=admin
IAM_ADMIN_PASSWORD=<at least 12 characters in production>
IAM_ISSUER=https://iam.example.com
IAM_OIDC_KEY_FILE=/secure/path/iam.oidc.key
IAM_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
IAM_OAUTH_REQUIRE_PKCE=true
IAM_METRICS_ENABLED=false
IAM_APPLICATIONS_CONFIG=/absolute/path/applications.json
IAM_VAULTS_FILE=/absolute/path/.vaults
```

In development, IAM creates a local `iam.oidc.key` if no key file or `IAM_OIDC_PRIVATE_KEY_PEM` is configured. Production must provide a protected key file or private key and must back it up separately from the database.

## Recommended user integration

1. Register a `public` client for a browser/mobile application or a `confidential` client for a server-rendered application.
2. Register exact HTTPS redirect URIs and the application’s allowed scopes.
3. Redirect users to the discovered authorization endpoint with `response_type=code`, `state`, `nonce`, `code_challenge`, and `code_challenge_method=S256`.
4. Exchange the one-time code at the token endpoint. Use HTTP Basic for confidential clients; public clients use PKCE and no secret.
5. Validate the ID token issuer, signature, audience, nonce, and expiry. Validate access tokens against the application API audience and required scope.
6. Use UserInfo or introspection when claims must be refreshed. Do not use the IAM database directly.

Discovery: `GET /.well-known/openid-configuration`

Machine-readable contract: [`openapi.yaml`](./openapi.yaml)

## Application registration paths

IAM supports two application-registration paths:

1. **Deployment bootstrap**: `applications.json` contains non-secret definitions for known
   applications. IAM creates missing confidential/service clients during startup and writes their
   generated client IDs and secrets to `.vaults` next to the IAM code by default. Existing clients
   must have a matching secret in `.vaults`; a mismatch stops startup instead of silently rotating a
   credential in use by an application. Override the paths with `IAM_APPLICATIONS_CONFIG` and
   `IAM_VAULTS_FILE` when required by deployment.
2. **Runtime administration**: an IAM administrator can use `POST /v1/clients` or the Applications
   page in the IAM UI. The response contains the client secret once. IAM stores only a hash, so the
   administrator or provisioning system must save the returned secret in the application’s secret
   manager immediately.

The default bootstrap file registers `mainsite` and `blogs-api`. `blogs-api` is the resource-server
audience used by the token-exchange flow; the application is named Blogs in the configuration.
`.vaults` is ignored by Git and is written with mode `0600`. It must still be protected by the host
and deployment system.

## Application authorization

Define permissions such as `invoice:read` and roles such as `billing_manager` under the application’s client ID. Assign users through:

```text
PUT /v1/clients/{clientId}/users/{userId}/roles
{
  "roles": ["billing_manager"],
  "contextType": "tenant",
  "contextId": "tenant-123"
}
```

The application must still enforce resource-level business rules. IAM only supplies identity and the application-scoped grant context.

Applications can reconcile their own versioned role and permission definitions with IAM:

```text
PUT /v1/clients/{clientId}/authorization-manifest
Authorization: Basic base64(client-id:client-secret)
{
  "version": "1.0.0",
  "permissions": [
    { "name": "blogs:content:read", "description": "Read blog content" }
  ],
  "roles": [
    { "name": "subscriber", "permissions": ["blogs:content:read"] }
  ]
}
```

The operation is idempotent and application-scoped. It adds or updates definitions, preserves
stable IAM IDs and existing assignments, and does not delete definitions omitted from a later
manifest. Declared permissions are also added to the application client’s allowed scopes. Removing
or retiring a permission requires a separate administrative lifecycle operation.

## Delegated access to another application API

An aggregator must not send its own audience token to another application API. Configure an IAM administrator delegation policy first:

```text
POST /v1/clients/{mainsiteClientId}/delegations
{
  "targetClientId": "blogs-api",
  "allowedScopes": ["blogs:read", "blogs:comment"]
}
```

The target client must already define those permissions and include them in its `allowedScopes`. The source client must be confidential or service-type and enable the token-exchange grant.

Then exchange the signed-in user’s mainsite access token for a short-lived blogs-audience token:

```text
POST /oauth/token
Authorization: Basic base64(mainsite-client-id:mainsite-client-secret)
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange&
subject_token=<mainsite-user-access-token>&
subject_token_type=urn:ietf:params:oauth:token-type:access_token&
audience=blogs-api&
scope=blogs:read
```

The blogs API should validate `iss`, signature, `aud=blogs-api`, expiry, and scopes. It should use `sub` as the user identity and apply blogs-owned authorization. Do not trust a caller-supplied user ID header, and do not map mainsite roles implicitly. IAM currently does not create the target application membership during exchange; application-specific JIT or automatic provisioning will be added with the membership implementation.

## Migration

`/api/auth/*` remains available for compatibility. First-party Adventure and IAM UIs use `/v1/*`. New integrations must use `/v1/*` and OIDC discovery. Legacy endpoints will be removed after all consumers have migrated.
