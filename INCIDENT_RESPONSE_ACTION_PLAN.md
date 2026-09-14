# IMMEDIATE ACTION PLAN - Credential Exposure Response

**Status:** CRITICAL - SECURITY INCIDENT  
**Created:** 2026-09-14  
**Priority:** URGENT - Complete within 24 hours

---

## ⚠️ INCIDENT SUMMARY

**What Happened:**
- Production credentials found in version-controlled files (`app.yaml`, `server.js`)
- Files exposed to AI agents (Claude, GitHub Copilot, Codex)
- Credentials in Git history accessible to anyone with repo access
- Duration: Since repository creation (check `git log --all --oneline app.yaml`)

**Who Has Seen These Credentials:**
1. ✅ GitHub staff (repository platform access)
2. ✅ All repository collaborators
3. ✅ Claude AI agent (this audit)
4. ✅ Any GitHub App with repository access
5. ✅ Potentially: GitHub Copilot (if enabled)
6. ⚠️ Unknown: Attackers (if repository was public or compromised)

**What's Exposed:**
- Email account password
- MySQL database password (root access)
- Supabase JWT service token
- Application JWT signing secret
- Google Cloud project details
- Azure/Microsoft Entra credentials (references)
- Cloudflare credentials (references)

---

## PHASE 1: EMERGENCY RESPONSE (Next 4 Hours)

### STEP 1: Notify Key Personnel (0-15 minutes)
- [ ] **Notify:** Project manager, tech lead, security officer
- [ ] **Message Template:**
  ```
  SECURITY ALERT - URGENT
  Production credentials exposed in GitHub repository
  Severity: CRITICAL
  Action Required: Immediate credential rotation
  Meeting: Schedule emergency call within 1 hour
  ```
- [ ] **Assign:** Who will own each remediation task
- [ ] **Document:** Record incident date/time in incident log

### STEP 2: Assess Exposure Scope (15-30 minutes)
- [ ] **Repository Status:**
  - [ ] Is this repo public or private?
  - [ ] If public, how long has it been public?
  - [ ] Has it been cloned/forked?
- [ ] **Access Review:**
  ```bash
  # Command to run in repository:
  git log --all --format="%h %an %ae %ad" --date=short -- app.yaml
  ```
  - [ ] When was app.yaml last modified?
  - [ ] Who has made changes?
- [ ] **Collaborator Audit:**
  - [ ] How many people have access?
  - [ ] List all GitHub accounts with access
  - [ ] Identify suspicious or external access
- [ ] **Deployment Review:**
  - [ ] Is current production using these credentials?
  - [ ] Have these credentials been rotated before?
  - [ ] When were they last changed?

### STEP 3: Begin Credential Rotation (30-90 minutes)
**⚠️ CRITICAL: Complete all rotations before continuing**

#### 3A: Email Password
```bash
# Action: Change password for info@stackopsit.co.za
# Platform: GoDaddy (smtpout.secureserver.net) or email provider

TODO:
- [ ] Log into email provider
- [ ] Generate strong new password: $(openssl rand -base64 32)
- [ ] Update password
- [ ] Test SMTP connection with new credentials
- [ ] Update in Google Secret Manager
- [ ] Update in deployment system
- [ ] Test email sending in production
```

**New Password:** `[SECURELY STORE - DO NOT COMMIT]`  
**Verified:** [ ] Working in staging [ ] Working in production

#### 3B: MySQL Database Password
```bash
# Action: Reset root password on MySQL instance
# Location: [YOUR DATABASE HOST]

TODO:
- [ ] Connect to MySQL with OLD password:
      mysql -u root -p[OLD_PASSWORD] -h [DB_HOST]
- [ ] Execute:
      ALTER USER 'root'@'localhost' IDENTIFIED BY '[NEW_PASSWORD]';
      FLUSH PRIVILEGES;
- [ ] Disconnect
- [ ] Test new connection:
      mysql -u root -p[NEW_PASSWORD] -h [DB_HOST]
- [ ] Update all application connection strings
- [ ] Update Google Secret Manager
- [ ] Update deployment configurations
- [ ] Restart application instances
- [ ] Verify application can connect to database
```

**New Password:** `[SECURELY STORE - DO NOT COMMIT]`  
**Verified:** [ ] Rotation complete [ ] App connected [ ] Data integrity OK

#### 3C: Supabase Service Role Key
```bash
# Action: Rotate API keys in Supabase dashboard
# Location: https://app.supabase.com

TODO:
- [ ] Log into Supabase project: mrubwknihpwlgreoroso
- [ ] Navigate to: Settings → API
- [ ] Locate: Service Role Key (your exposed key)
- [ ] Click: "Rotate" or regenerate
- [ ] Copy new service role key
- [ ] Update in app.yaml (temporarily)
- [ ] Update in Google Secret Manager
- [ ] Deploy new key to production
- [ ] Verify application still works
- [ ] Check Supabase logs for suspicious activity
- [ ] Review RLS policies (Row Level Security)
```

**New Key:** `[SECURELY STORE - DO NOT COMMIT]`  
**Verified:** [ ] Rotated [ ] App deployed [ ] Services working

#### 3D: ACCESS_TOKEN_SECRET (JWT Signing Key)
```bash
# Action: Generate new JWT signing secret
# Impact: All existing authentication tokens become invalid

TODO:
- [ ] Generate new secret:
      node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
- [ ] Update in .env file (NOT in repo)
- [ ] Update in Google Secret Manager
- [ ] Deploy to staging first
- [ ] Test authentication flow in staging
- [ ] NOTIFY USERS: "All sessions will be invalidated"
- [ ] Deploy to production
- [ ] Monitor user login volume
- [ ] Check for increased support tickets
```

**New Secret:** `[SECURELY STORE - DO NOT COMMIT]`  
**Verified:** [ ] Generated [ ] Deployed [ ] All users need to login again [ ] No errors

#### 3E: Azure/Microsoft Entra Credentials
```bash
# Action: Rotate Azure service principal credentials
# Location: https://portal.azure.com or Microsoft Entra

TODO:
- [ ] List all service principals used:
      az ad app list --query "[].displayName"
- [ ] For each credential:
      - [ ] Create new credential in Azure
      - [ ] Update in application
      - [ ] Test in staging
      - [ ] Deploy to production
      - [ ] Delete old credential (wait 24hrs for safety)
- [ ] Check Azure Audit Logs for unauthorized access
```

**Status:** [ ] All Azure credentials rotated

#### 3F: Cloudflare API Token
```bash
# Action: Rotate Cloudflare API token
# Location: https://dash.cloudflare.com/?to=/:account/profile/api-tokens

TODO:
- [ ] Log into Cloudflare dashboard
- [ ] Navigate: My Profile → API Tokens
- [ ] Locate: Exposed token
- [ ] Create NEW token with same permissions
- [ ] Update in deployment system
- [ ] Test Cloudflare integration
- [ ] Delete old token
```

**Status:** [ ] Token rotated

### STEP 4: Secure Credentials (90-120 minutes)
- [ ] **Verify all credentials in Google Secret Manager:**
  ```bash
  gcloud secrets list --filter="name:DATABASE_PASSWORD OR name:SUPABASE OR name:ACCESS_TOKEN"
  ```
- [ ] **Verify app.yaml no longer has hardcoded secrets**
- [ ] **Verify .env files are in .gitignore**
- [ ] **Test production deployment:**
  - [ ] All services online
  - [ ] No authentication errors
  - [ ] Database accessible
  - [ ] Email sending works
  - [ ] APIs responding

---

## PHASE 2: GIT HISTORY CLEANUP (Next 4-24 Hours)

⚠️ **WARNING:** This step rewrites Git history - coordinate with entire team before executing

### STEP 5: Prepare for History Rewrite (Before You Start)
- [ ] **Notify team:** No commits for next 2 hours
- [ ] **Backup:** Create backup of repository
  ```bash
  git clone --mirror https://github.com/yourorg/repo.git repo-backup.git
  ```
- [ ] **Stop CI/CD:** Disable auto-deploys during rewrite
- [ ] **Branch:** Create new branch from main
  ```bash
  git checkout main
  git pull origin main
  git checkout -b security/credential-cleanup
  ```

### STEP 6: Remove Credentials from History
**Option A: Using git-filter-repo (RECOMMENDED)**

```bash
# Install:
pip install git-filter-repo

# Create file listing credentials to replace:
cat > /tmp/creds.txt << 'EOF'
Cxzdsaewq123$
@TakalaniSandani2005
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1ydWJ3a25paHB3bGdyZW9yb3NvIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MDM5MjQ2NiwiZXhwIjoyMDc1OTY4NDY2fQ.ikGYNgHS3OY3JTBVN10sbPmwHSkeHwOf-gPNi5psEZs
7a076e42670cfe26193655fe5f48b776defe078754ca16fb9ae0a054b354d335
EOF

# Create replacement mapping:
cat > /tmp/replacements.txt << 'EOF'
Cxzdsaewq123$ ==> [REDACTED_EMAIL_PASSWORD]
@TakalaniSandani2005 ==> [REDACTED_DB_PASSWORD]
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... ==> [REDACTED_SUPABASE_KEY]
7a076e42670cfe26193655fe5f48b776defe078754ca16fb9ae0a054b354d335 ==> [REDACTED_TOKEN_SECRET]
EOF

# Run filter (IRREVERSIBLE):
git filter-repo --replace-text /tmp/replacements.txt

# Verify changes:
git log -p -- app.yaml | grep -i password  # Should show [REDACTED]

# Force push (requires admin access):
git push origin main --force-with-lease
git push origin --all --force-with-lease
git push origin --tags --force-with-lease
```

**Option B: Using BFG Repo-Cleaner (EASIER)**

```bash
# Install: https://rtyley.github.io/bfg-repo-cleaner/
# Download bfg jar file

# Create credentials file:
cat > creds-to-remove.txt << 'EOF'
Cxzdsaewq123$
@TakalaniSandani2005
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1ydWJ3a25paHB3bGdyZW9yb3NvIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MDM5MjQ2NiwiZXhwIjoyMDc1OTY4NDY2fQ.ikGYNgHS3OY3JTBVN10sbPmwHSkeHwOf-gPNi5psEZs
7a076e42670cfe26193655fe5f48b776defe078754ca16fb9ae0a054b354d335
EOF

# Run BFG:
bfg --replace-text creds-to-remove.txt --no-blob-protection repo

# Clean and push:
cd repo
git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push origin main --force-with-lease
git push origin --all --force-with-lease
```

### STEP 7: Verify History Cleaned
- [ ] **Confirm credentials removed:**
  ```bash
  git log -p -- app.yaml | grep -i "password\|secret\|token" | grep -v "REDACTED"
  # Should return NO RESULTS
  ```
- [ ] **Verify current app.yaml doesn't have secrets:**
  ```bash
  cat app.yaml | grep -i "password\|secret\|token" | grep -v "REDACTED"
  # Should return NO RESULTS or only [REDACTED] values
  ```
- [ ] **Test application still works after history rewrite**

### STEP 8: Notify Team of History Rewrite
- [ ] **Message:** "Git history has been rewritten. You must re-clone the repository:"
  ```bash
  cd ~
  rm -rf old-repo
  git clone https://github.com/yourorg/repo.git new-repo
  ```
- [ ] **For those with local clones:**
  ```bash
  git fetch origin
  git reset --hard origin/main
  ```

---

## PHASE 3: CONFIGURATION UPDATES (Today)

### STEP 9: Create Proper Environment Configuration
- [ ] **Create `.env.example` (with NO secrets):**
  ```env
  # .env.example - Copy to .env and fill in values from Google Secret Manager
  
  # Supabase Configuration
  SUPABASE_URL=https://mrubwknihpwlgreoroso.supabase.co
  SUPABASE_SERVICE_ROLE_KEY=your_key_from_secret_manager
  
  # Email Configuration
  EMAIL_USER=info@stackopsit.co.za
  EMAIL_PASS=your_password_from_secret_manager
  SMTP_HOST=smtpout.secureserver.net
  SMTP_PORT=465
  SMTP_SECURE=true
  
  # Database Configuration
  DB_HOST=localhost
  DB_USER=root
  DB_PASSWORD=your_password_from_secret_manager
  DB_NAME=consultation_db
  
  # Application Secrets
  ACCESS_TOKEN_SECRET=your_secret_from_secret_manager
  
  # Azure/Microsoft Configuration
  AZURE_TENANT_ID=your_value_from_secret_manager
  AZURE_CLIENT_ID=your_value_from_secret_manager
  AZURE_CLIENT_SECRET=your_value_from_secret_manager
  
  # Cloudflare Configuration
  CLOUDFLARE_ACCOUNT_ID=your_value_from_secret_manager
  CLOUDFLARE_API_TOKEN=your_value_from_secret_manager
  ```
- [ ] **Verify `.gitignore` has:**
  ```
  .env
  .env.local
  .env.*.local
  .env.production.local
  .DS_Store
  node_modules/
  .vscode/
  dist/
  build/
  ```

### STEP 10: Update Deployment Pipeline
- [ ] **Verify cloudbuild.yaml uses Secret Manager (already does):**
  ```bash
  grep "update-secrets" cloudbuild.yaml
  # Should show all secrets loaded from Secret Manager
  ```
- [ ] **Update app.yaml to remove hardcoded secrets:**
  - Remove all `SUPABASE_SERVICE_ROLE_KEY`, `EMAIL_PASS`, `DB_PASSWORD`, `ACCESS_TOKEN_SECRET`
  - Leave only non-sensitive environment variables
  - Include comment: "Secrets loaded from Google Secret Manager"

### STEP 11: Test Everything
- [ ] **Staging Deployment:**
  - [ ] Deploy with new credentials
  - [ ] Run smoke tests
  - [ ] Verify all services working
- [ ] **Production Deployment:**
  - [ ] Deploy with new credentials
  - [ ] Monitor for errors
  - [ ] Verify all services working
  - [ ] Check application logs
  - [ ] Test user login flow
  - [ ] Test email sending
  - [ ] Test database operations

---

## PHASE 4: SECURITY HARDENING (This Week)

### STEP 12: GitHub Security Configuration
- [ ] **Enable Branch Protection on `main` branch:**
  - GitHub → Settings → Branches → Add Rule
  - Pattern: `main`
  - Require status checks to pass
  - Require code reviews (minimum 1)
  - Dismiss stale pull request approvals
  - Require signed commits

- [ ] **Enable Secret Scanning:**
  - GitHub → Settings → Code Security & Analysis
  - Enable "Secret scanning" (alerts on exposed secrets)
  - Enable "Push protection" (prevents secrets being committed)

- [ ] **Enable Dependabot:**
  - GitHub → Settings → Code Security & Analysis
  - Enable "Dependabot alerts"
  - Enable "Dependabot security updates"

- [ ] **Review Collaborators:**
  - GitHub → Settings → Collaborators
  - Remove unnecessary access
  - Verify correct permission levels

- [ ] **Audit Deployed Keys:**
  - GitHub → Settings → Deploy Keys
  - Verify all are necessary
  - Remove unused keys

- [ ] **Review GitHub Apps:**
  - GitHub → Settings → Installed Apps
  - Verify all are necessary and trusted

### STEP 13: Audit & Logging
- [ ] **Enable Google Cloud Audit Logging:**
  ```bash
  gcloud logging read "resource.type=cloud_run_service AND jsonPayload.service_name=stackops-backend" --limit 100 --format json
  ```
  - Verify audit logs are recording all changes
  - Set up log retention (minimum 90 days)
  - Create alerts for suspicious activity

- [ ] **Review Application Logs:**
  - Check for any unauthorized access attempts
  - Monitor for failed authentication
  - Look for data exfiltration attempts

### STEP 14: Credential Rotation Schedule
- [ ] **Create rotation policy:**
  - Every 90 days: Rotate service account credentials
  - Every 6 months: Rotate long-lived credentials
  - Immediately: Upon any security incident
  - Document in security policy

---

## PHASE 5: TEAM TRAINING (This Week)

### STEP 15: Security Training
- [ ] **Schedule team meeting:** "Secrets Management Best Practices"
  - Why hardcoding secrets is dangerous
  - How to properly handle credentials
  - Use of .env files and .gitignore
  - Google Secret Manager usage

- [ ] **Code Review Guidelines:**
  - All PRs must be reviewed for hardcoded secrets
  - Use automated scanning in CI/CD
  - Document the rule in CONTRIBUTING.md

### STEP 16: Documentation Updates
- [ ] **Create SECURITY.md:**
  ```markdown
  # Security Policy
  
  ## Responsible Disclosure
  If you discover a security vulnerability, please email: [security@stackopsit.co.za]
  
  ## Credential Management
  - Never commit credentials to Git
  - Use .env files (gitignored) for local development
  - Use Google Secret Manager for production
  - Rotate credentials every 90 days
  
  ## Incident Response
  [Document incident procedures]
  ```

- [ ] **Update README.md:**
  - Add "Setup Development Environment" section
  - Include .env.example usage instructions
  - Mention Google Secret Manager for production

---

## VERIFICATION CHECKLIST

### Pre-Deployment Verification
- [ ] All credentials rotated
- [ ] Git history cleaned (if applicable)
- [ ] app.yaml updated (no hardcoded secrets)
- [ ] .gitignore properly configured
- [ ] .env.example created and committed
- [ ] Google Secret Manager has all secrets
- [ ] cloudbuild.yaml references Secret Manager
- [ ] Branch protection enabled
- [ ] Secret scanning enabled
- [ ] All tests passing
- [ ] Staging deployment successful
- [ ] Production deployment successful

### Post-Deployment Verification (24 Hours)
- [ ] No errors in application logs
- [ ] Users can log in successfully
- [ ] Email sending works
- [ ] Database queries successful
- [ ] No suspicious access in audit logs
- [ ] GitHub shows no exposed secrets
- [ ] Monitoring shows normal operation
- [ ] Support team reports no issues

---

## INCIDENT RESPONSE DOCUMENTATION

**Incident ID:** [Auto-assigned]  
**Date Discovered:** 2026-09-14  
**Severity:** CRITICAL  
**Status:** IN PROGRESS  

### Timeline
- 2026-09-14 00:00 - Credentials exposed (git history)
- 2026-09-14 [TIME] - Incident discovered via security audit
- 2026-09-14 [TIME] - Phase 1: Credential rotation began
- 2026-09-14 [TIME] - Phase 2: Git history cleanup
- 2026-09-14 [TIME] - Phase 3: Configuration updated
- 2026-09-14 [TIME] - Phase 4: Security hardening
- 2026-09-14 [TIME] - Phase 5: Team training completed
- 2026-09-14 [TIME] - INCIDENT CLOSED (all phases complete)

### Post-Incident Review (Schedule: 1 week after incident)
- [ ] Root cause analysis complete
- [ ] All recommendations implemented
- [ ] Security controls verified
- [ ] Lessons learned documented
- [ ] Team training completed
- [ ] Policies updated

---

## EMERGENCY CONTACTS

| Role | Name | Email | Phone |
|------|------|-------|-------|
| Tech Lead | [NAME] | [EMAIL] | [PHONE] |
| Security Officer | [NAME] | [EMAIL] | [PHONE] |
| Project Manager | [NAME] | [EMAIL] | [PHONE] |
| Compliance Officer | [NAME] | [EMAIL] | [PHONE] |

---

**CRITICAL: Follow this checklist step-by-step. Do not skip steps.**

**Once complete, verify all items before closing this incident.**
