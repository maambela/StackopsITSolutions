# GOOGLE SECRET MANAGER SETUP GUIDE

**Purpose:** Properly manage credentials using Google Secret Manager instead of hardcoding in files  
**Status:** Implementation guide for remediation  
**Timeline:** Complete IMMEDIATELY as part of incident response

---

## HOW GOOGLE SECRET MANAGER WORKS

### Current Setup (Good)
Your `cloudbuild.yaml` already references Google Secret Manager correctly:
```yaml
--update-secrets: 'DB_USER=DB_USER:latest,DB_PASSWORD=DB_PASSWORD:latest'
```

This means:
- ✅ Secrets are NOT in your Git repository
- ✅ Secrets are stored securely in Google Cloud
- ✅ Deployment retrieves secrets at runtime
- ✅ Only authenticated services can access

### Problem (Current)
Your `app.yaml` contradicts this by having hardcoded values:
```yaml
# ❌ WRONG - In app.yaml (version controlled)
SUPABASE_SERVICE_ROLE_KEY: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
EMAIL_PASS: "Cxzdsaewq123$"
DB_PASSWORD: "@TakalaniSandani2005"
```

---

## STEP 1: CREATE SECRETS IN GOOGLE SECRET MANAGER

### 1.1 Using Google Cloud Console (GUI)
```
1. Go to: https://console.cloud.google.com/security/secret-manager
2. Select project: stackops-backend-475222
3. Click: "Create Secret"

For each secret:
- Name: [SECRET_NAME] (e.g., "DB_PASSWORD")
- Value: [SECRET_VALUE] (e.g., "@TakalaniSandani2005")
- Replication: Automatic
- Click: "Create Secret"
```

### 1.2 Using gcloud CLI (Recommended)
```bash
# First, authenticate:
gcloud auth login
gcloud config set project stackops-backend-475222

# Create each secret:
gcloud secrets create DB_USER \
    --replication-policy="automatic" \
    --data-file=- << EOF
root
EOF

gcloud secrets create DB_PASSWORD \
    --replication-policy="automatic" \
    --data-file=- << EOF
[NEW_ROTATED_PASSWORD_HERE]
EOF

gcloud secrets create SUPABASE_SERVICE_ROLE_KEY \
    --replication-policy="automatic" \
    --data-file=- << EOF
[NEW_ROTATED_KEY_HERE]
EOF

gcloud secrets create EMAIL_USER \
    --replication-policy="automatic" \
    --data-file=- << EOF
info@stackopsit.co.za
EOF

gcloud secrets create EMAIL_PASS \
    --replication-policy="automatic" \
    --data-file=- << EOF
[NEW_ROTATED_PASSWORD_HERE]
EOF

gcloud secrets create SMTP_HOST \
    --replication-policy="automatic" \
    --data-file=- << EOF
smtpout.secureserver.net
EOF

gcloud secrets create SMTP_PORT \
    --replication-policy="automatic" \
    --data-file=- << EOF
465
EOF

gcloud secrets create SMTP_USER \
    --replication-policy="automatic" \
    --data-file=- << EOF
info@stackopsit.co.za
EOF

gcloud secrets create SMTP_PASS \
    --replication-policy="automatic" \
    --data-file=- << EOF
[NEW_ROTATED_PASSWORD_HERE]
EOF

gcloud secrets create ACCESS_TOKEN_SECRET \
    --replication-policy="automatic" \
    --data-file=- << EOF
[NEW_ROTATED_SECRET_HERE]
EOF

gcloud secrets create SUPABASE_URL \
    --replication-policy="automatic" \
    --data-file=- << EOF
https://mrubwknihpwlgreoroso.supabase.co
EOF

gcloud secrets create DB_NAME \
    --replication-policy="automatic" \
    --data-file=- << EOF
consultation_db
EOF

gcloud secrets create DB_HOST \
    --replication-policy="automatic" \
    --data-file=- << EOF
localhost
EOF

# Verify all secrets created:
gcloud secrets list
```

### 1.3 Verify Secrets Created
```bash
# List all secrets:
gcloud secrets list

# View secret content (only for verification):
gcloud secrets versions access latest --secret=DB_PASSWORD

# Audit who accessed secrets:
gcloud logging read "resource.type=secretmanager.googleapis.com" --limit 50
```

---

## STEP 2: GRANT CLOUD RUN SERVICE ACCOUNT ACCESS

### 2.1 Find Your Cloud Run Service Account
```bash
# List service accounts:
gcloud iam service-accounts list

# Your Cloud Run uses a service account like:
# PROJECTID@appspot.gserviceaccount.com
# or
# cloud-run-service@PROJECTID.iam.gserviceaccount.com

# Find the one used by stackops-backend:
gcloud run services describe stackops-backend --region us-central1 --format="value(spec.template.spec.serviceAccountName)"
```

### 2.2 Grant Secret Access
```bash
# Get your service account email:
SERVICE_ACCOUNT="[SERVICE_ACCOUNT_EMAIL]"

# Grant permission for EACH secret:
gcloud secrets add-iam-policy-binding DB_PASSWORD \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding DB_USER \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding SUPABASE_SERVICE_ROLE_KEY \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/secretmanager.secretAccessor"

# ... repeat for all secrets ...

# Or use a script to grant all at once:
for secret in DB_PASSWORD DB_USER SUPABASE_SERVICE_ROLE_KEY EMAIL_PASS EMAIL_USER SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS ACCESS_TOKEN_SECRET SUPABASE_URL DB_NAME DB_HOST; do
    gcloud secrets add-iam-policy-binding "${secret}" \
        --member="serviceAccount:${SERVICE_ACCOUNT}" \
        --role="roles/secretmanager.secretAccessor"
done

# Verify permissions:
gcloud secrets get-iam-policy DB_PASSWORD
```

---

## STEP 3: UPDATE CLOUD RUN DEPLOYMENT

### 3.1 Current cloudbuild.yaml (Already Correct!)
Your `cloudbuild.yaml` already has the right structure:
```yaml
--update-secrets: 'DB_USER=DB_USER:latest,DB_PASSWORD=DB_PASSWORD:latest,...'
```

This means at deployment:
- Cloud Run retrieves the latest version of each secret
- Secret is injected as an environment variable
- Application reads from `process.env.DB_PASSWORD`

### 3.2 Verify cloudbuild.yaml Completeness
Ensure ALL secrets are listed:
```yaml
# Current in cloudbuild.yaml:
--update-secrets: 'DB_USER=DB_USER:latest,DB_PASSWORD=DB_PASSWORD:latest,AZURE_TENANT_ID=AZURE_TENANT_ID:latest,...'

# Should include:
- [x] DB_USER
- [x] DB_PASSWORD  
- [x] SUPABASE_SERVICE_ROLE_KEY
- [x] SUPABASE_URL
- [x] EMAIL_USER
- [x] EMAIL_PASS
- [x] SMTP_HOST
- [x] SMTP_PORT
- [x] SMTP_USER
- [x] SMTP_PASS
- [x] ACCESS_TOKEN_SECRET
- [x] DB_NAME
- [x] DB_HOST
```

If any are missing, update cloudbuild.yaml:
```yaml
# Add to --update-secrets line:
,SMTP_HOST=SMTP_HOST:latest,SMTP_PORT=SMTP_PORT:latest,SMTP_USER=SMTP_USER:latest,SMTP_PASS=SMTP_PASS:latest
```

---

## STEP 4: UPDATE application.yaml

### 4.1 Remove All Secrets (Keep Non-Secrets)
**BEFORE (❌ WRONG):**
```yaml
env_variables:
  # Supabase Credentials
  USE_SUPABASE: "true"
  SUPABASE_URL: "https://mrubwknihpwlgreoroso.supabase.co"
  SUPABASE_SERVICE_ROLE_KEY: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  
  # Email Credentials
  EMAIL_USER: "info@stackopsit.co.za"
  EMAIL_PASS: "Cxzdsaewq123$"
  SMTP_HOST: "smtpout.secureserver.net"
  SMTP_PORT: "465"
  SMTP_SECURE: "true"
  
  # Secrets
  ACCESS_TOKEN_SECRET: "7a076e42670cfe26193655fe5f48b776defe078754ca16fb9ae0a054b354d335"
  
  # Database
  DB_HOST: "localhost"
  DB_USER: "root"
  DB_PASSWORD: "@TakalaniSandani2005"
  DB_NAME: "consultation_db"
```

**AFTER (✅ CORRECT):**
```yaml
env_variables:
  # Non-Sensitive Configuration
  USE_SUPABASE: "true"
  SMTP_PORT: "465"
  SMTP_SECURE: "true"
  DB_NAME: "consultation_db"
  DB_HOST: "localhost"
  
  # IMPORTANT: All secrets (passwords, API keys, tokens) are loaded from Google Secret Manager
  # They are defined in the Cloud Run deployment (cloudbuild.yaml)
  # Do NOT add secrets here
```

### 4.2 Commit Updated app.yaml
```bash
git add app.yaml
git commit -m "feat: remove hardcoded secrets, use Google Secret Manager"
git push origin main
```

---

## STEP 5: TEST LOCALLY

### 5.1 Create .env File (Local Development)
**Never commit this file** - it's in .gitignore

```env
# .env (local testing only, never commit)
USE_SUPABASE=true
SUPABASE_URL=https://mrubwknihpwlgreoroso.supabase.co
SUPABASE_SERVICE_ROLE_KEY=[LOCAL_VALUE_FROM_SECRET_MANAGER]

EMAIL_USER=info@stackopsit.co.za
EMAIL_PASS=[LOCAL_VALUE_FROM_SECRET_MANAGER]
SMTP_HOST=smtpout.secureserver.net
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=info@stackopsit.co.za
SMTP_PASS=[LOCAL_VALUE_FROM_SECRET_MANAGER]

ACCESS_TOKEN_SECRET=[LOCAL_VALUE_FROM_SECRET_MANAGER]

DB_HOST=localhost
DB_USER=root
DB_PASSWORD=[LOCAL_VALUE_FROM_SECRET_MANAGER]
DB_NAME=consultation_db
```

### 5.2 Test Application Locally
```bash
# Install dependencies:
npm install

# Load .env and run:
node server.js

# Should see:
# ✅ Database connected
# ✅ Server listening on port 3000
# ✅ Email service configured
# ✅ Supabase initialized
```

### 5.3 Test Database Connection
```bash
# In your app's startup logs:
# Should show: "Connected to database: consultation_db"

# Run a test query in the app
# Should return data without authentication errors
```

---

## STEP 6: DEPLOY TO STAGING

### 6.1 Deploy to Staging Cloud Run
```bash
# Push to staging branch:
git checkout -b staging
git push origin staging

# This triggers cloudbuild.yaml with staging configuration
# Monitor the build:
gcloud builds log [BUILD_ID] --stream

# Check Cloud Run service:
gcloud run services describe stackops-backend --region us-central1
```

### 6.2 Test Staging Deployment
```bash
# Get staging URL:
gcloud run services describe stackops-backend --region us-central1 --format="value(status.url)"

# Test endpoints:
curl https://[STAGING_URL]/health
curl -X POST https://[STAGING_URL]/api/auth/signin -d '{"email":"test@example.com","password":"test"}'

# Check logs for any secret-related errors:
gcloud logging read "resource.type=cloud_run_service AND resource.labels.service_name=stackops-backend" \
    --filter="severity>=ERROR" \
    --limit 20
```

### 6.3 Monitor Staging (30 minutes)
- [ ] No errors in Cloud Logging
- [ ] No 500 responses
- [ ] Database queries successful
- [ ] Email sending works
- [ ] Authentication successful
- [ ] API responses normal

---

## STEP 7: DEPLOY TO PRODUCTION

### 7.1 Deploy to Production
```bash
# Merge staging to main:
git checkout main
git pull origin main
git merge staging
git push origin main

# Monitor production build:
gcloud builds log [BUILD_ID] --stream

# Verify Cloud Run update:
gcloud run services describe stackops-backend --region us-central1
```

### 7.2 Production Verification (Continuous for 24 hours)
```bash
# Monitor error logs:
gcloud logging read "resource.type=cloud_run_service AND resource.labels.service_name=stackops-backend AND severity>=ERROR" --limit 100

# Check metrics:
gcloud monitoring time-series list --filter='resource.type=cloud_run_service AND metric.type=run.googleapis.com/request_count'

# Review user reports:
# - Check support inbox
# - Monitor social media
# - Internal Slack notifications
```

---

## STEP 8: SECURE SECRET MANAGER

### 8.1 Enable Audit Logging
```bash
# Enable Cloud Audit Logs (if not already):
gcloud logging write secret_access "Secret Manager access audit"

# Query audit logs:
gcloud logging read "resource.type=secretmanager.googleapis.com" --format json --limit 50
```

### 8.2 Set Up Alerts
```bash
# Create alert for suspicious access:
gcloud alpha monitoring policies create \
    --display-name="Secret Manager Access Alert" \
    --condition-display-name="Multiple failed access attempts" \
    --condition-threshold-value=5 \
    --condition-threshold-duration=300s
```

### 8.3 Enable Secret Versioning
```bash
# Verify secret versioning is enabled:
gcloud secrets versions list DB_PASSWORD

# Archive old versions (keep for audit trail):
gcloud secrets versions destroy [OLD_VERSION_NUMBER] --secret=DB_PASSWORD
```

### 8.4 Configure Secret Rotation
```bash
# Enable automatic rotation (if available):
# Note: This requires custom Cloud Functions

# OR manual rotation schedule:
# Every 90 days:
# 1. Generate new secret value
# 2. gcloud secrets versions add DB_PASSWORD --data-file=- << EOF[NEW_VALUE]EOF
# 3. Test in staging
# 4. Deploy to production
# 5. Archive old version
```

---

## STEP 9: UPDATE DEVELOPMENT DOCUMENTATION

### 9.1 Create Setup Instructions
**File: docs/SETUP.md**

```markdown
# Development Setup

## Prerequisites
- Node.js 22+
- Google Cloud SDK
- MySQL client

## Environment Setup

### 1. Clone Repository
\`\`\`bash
git clone https://github.com/stackops/repo.git
cd repo
npm install
\`\`\`

### 2. Get Secrets from Google Secret Manager
\`\`\`bash
# Option A: Manual (one-time)
gcloud secrets versions access latest --secret=DB_PASSWORD > .env_db_password

# Option B: Automatic (using helper script)
./scripts/setup-secrets.sh
\`\`\`

### 3. Create .env File
\`\`\`bash
cp .env.example .env
# Edit .env with values from Google Secret Manager
\`\`\`

### 4. Run Application
\`\`\`bash
npm start
# Should see: Server running on port 3000
\`\`\`

## Security Notes
- ❌ Never commit .env files
- ❌ Never hardcode secrets in code
- ✅ Always load from Google Secret Manager (production)
- ✅ Always use .env files (local development)
```

### 9.2 Create Secret Rotation Runbook
**File: docs/SECRET_ROTATION.md**

```markdown
# Secret Rotation Procedure

## Every 90 Days

### 1. Generate New Secret
\`\`\`bash
NEW_SECRET=\$(openssl rand -base64 32)
echo \$NEW_SECRET
\`\`\`

### 2. Update in Google Secret Manager
\`\`\`bash
gcloud secrets versions add DB_PASSWORD --data-file=- << EOF
\${NEW_SECRET}
EOF
\`\`\`

### 3. Test in Staging
\`\`\`bash
gcloud run services update stackops-backend-staging \
    --region us-central1 \
    --update-secrets DB_PASSWORD=DB_PASSWORD:latest
\`\`\`

### 4. Deploy to Production
[Same as staging]

### 5. Archive Old Version
\`\`\`bash
# List versions:
gcloud secrets versions list DB_PASSWORD

# Destroy old:
gcloud secrets versions destroy [OLD_VERSION_NUMBER] --secret=DB_PASSWORD
\`\`\`
```

---

## TROUBLESHOOTING

### Issue: "Secret Manager API is not enabled"
```bash
# Solution:
gcloud services enable secretmanager.googleapis.com
```

### Issue: "Permission denied while accessing Secret Manager"
```bash
# Solution: Check service account permissions
gcloud secrets get-iam-policy DB_PASSWORD

# Grant access if needed:
gcloud secrets add-iam-policy-binding DB_PASSWORD \
    --member="serviceAccount:[SERVICE_ACCOUNT]" \
    --role="roles/secretmanager.secretAccessor"
```

### Issue: "Secret contains invalid characters"
```bash
# Some special characters need escaping:
# Use --data-file=- instead of --data=
gcloud secrets versions add DB_PASSWORD --data-file=- << EOF
password_with_$pecial_chars
EOF
```

### Issue: "Application can't read secrets in Cloud Run"
```bash
# Check logs:
gcloud logging read "resource.type=cloud_run_service" --limit 50

# Verify environment variables are injected:
# In Cloud Run console, check "Variables" tab under Service details
```

---

## SUMMARY

### What Changed
| Before | After |
|--------|-------|
| Secrets hardcoded in app.yaml | Secrets in Google Secret Manager |
| Visible to everyone with repo access | Accessible only to authorized services |
| In Git history forever | Audited and rotatable |
| Risk: Exposed in Git | Risk: Mitigated |

### Security Improvement
- ✅ Secrets no longer in version control
- ✅ Automatic audit logging of access
- ✅ Easy rotation without code changes
- ✅ Role-based access control
- ✅ Encryption at rest and in transit

### Next Steps
1. Create all secrets in Google Secret Manager
2. Grant Cloud Run service account access
3. Verify cloudbuild.yaml completeness
4. Update app.yaml (remove secrets)
5. Test locally with .env
6. Deploy to staging
7. Deploy to production
8. Archive credentials in app.yaml

---

**References:**
- Google Secret Manager Docs: https://cloud.google.com/secret-manager/docs
- Cloud Run Configuration: https://cloud.google.com/run/docs/configuring/environment-variables
- Best Practices: https://cloud.google.com/architecture/secrets-management
