# SECURITY AUDIT REPORT - StackOps/Sunbird GitHub Repository
**Report Date:** 2026-09-14  
**Severity Level:** 🔴 CRITICAL - IMMEDIATE ACTION REQUIRED

---

## EXECUTIVE SUMMARY

Your GitHub repository contains **EXPOSED PRODUCTION CREDENTIALS** that are currently accessible to:
- All GitHub collaborators
- Any person with repository read access
- All AI agents (Claude, Copilot, Codex) that have accessed this repository
- Google Cloud Build systems
- Anyone viewing Git history

**REQUIRED IMMEDIATE ACTIONS:**
1. Rotate ALL credentials listed in this report
2. Revoke exposed API keys and service tokens
3. Remove sensitive data from Git history
4. Enable branch protection and secret scanning

---

## 1. CRITICAL CREDENTIAL LEAKS

### 1.1 Email Service Credentials (app.yaml)
**Location:** `app.yaml` lines 9-15
**Severity:** 🔴 CRITICAL

```
EMAIL_USER: "info@stackopsit.co.za"
EMAIL_PASS: "Cxzdsaewq123$"
SMTP_HOST: "smtpout.secureserver.net"
SMTP_PORT: "465"
SMTP_USER: "info@stackopsit.co.za"
SMTP_PASS: "Cxzdsaewq123$"
```

**Risk:** Email account compromised → mass phishing attacks, credential resets intercepted

**Action Required:**
- [ ] Change email password immediately
- [ ] Review email account activity
- [ ] Enable 2FA on email account
- [ ] Audit forwarding rules and recovery addresses

---

### 1.2 Database Credentials (app.yaml)
**Location:** `app.yaml` lines 20-23
**Severity:** 🔴 CRITICAL

```
DB_HOST: "localhost"
DB_USER: "root"
DB_PASSWORD: "@TakalaniSandani2005"
DB_NAME: "consultation_db"
```

**Risk:** Direct database access → data exfiltration, deletion, ransomware

**Action Required:**
- [ ] Reset MySQL root password immediately
- [ ] Rotate service account password
- [ ] Review database access logs
- [ ] Change all application database user passwords
- [ ] Audit database for unauthorized access
- [ ] Enable database audit logging

---

### 1.3 Supabase Service Role Key (app.yaml)
**Location:** `app.yaml` lines 5-6
**Severity:** 🔴 CRITICAL

```
SUPABASE_URL: "https://mrubwknihpwlgreoroso.supabase.co"
SUPABASE_SERVICE_ROLE_KEY: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Risk:** Full backend access to Supabase instance → complete data compromise

**Action Required:**
- [ ] Rotate Supabase service role key immediately
- [ ] Rotate anon key if exposed
- [ ] Review Supabase RLS (Row Level Security) policies
- [ ] Check Supabase audit logs for suspicious activity
- [ ] Enable Supabase IP restriction if available
- [ ] Review data access logs for all tables

---

### 1.4 Application Secrets (app.yaml & server.js)
**Location:** `app.yaml` line 17 and `server.js` line 64
**Severity:** 🔴 CRITICAL

```
ACCESS_TOKEN_SECRET: "7a076e42670cfe26193655fe5f48b776defe078754ca16fb9ae0a054b354d335"
```

**Risk:** JWT token signing compromise → forge auth tokens, impersonate users, bypass authentication

**Action Required:**
- [ ] Regenerate ACCESS_TOKEN_SECRET immediately
- [ ] Invalidate all existing JWT tokens (requires user re-login)
- [ ] Rotate all service tokens

---

## 2. INFORMATION DISCLOSURE RISKS

### 2.1 Cloud Infrastructure Exposure (cloudbuild.yaml)
**Location:** `cloudbuild.yaml` lines 1-50
**Severity:** 🟠 HIGH

**Exposed Information:**
- Google Cloud Project ID: `stackops-backend-475222`
- GCP Region: `us-central1`
- Cloud Artifact Registry: `us-central1-docker.pkg.dev/stackops-backend-475222/stackops-repo/`
- Cloud SQL Instance: `stackops-backend-475222:us-central1:stackops-db`
- Cloud Run service name: `stackops-backend`
- Secret Manager references (names visible):
  - `DB_USER`, `DB_PASSWORD`
  - `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
  - `MICROSOFT_TENANT_ID`, `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`
  - `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`
  - `STACKCTRL_AUTOMATION_TRIGGER_SECRET`
  - `ENTRA_PORTAL_TENANT_ID`, `ENTRA_PORTAL_CLIENT_ID`, `ENTRA_PORTAL_CLIENT_SECRET`

**Risk:** Attackers now know:
- Your GCP project structure
- All Azure/Microsoft Entra integration details
- Cloudflare integration
- Which services exist (for targeted attacks)
- Build and deployment process

**Action Required:**
- [ ] Keep cloudbuild.yaml in Git but move to private repo only
- [ ] Review GCP Project IAM roles and access logs
- [ ] Audit all service accounts mentioned
- [ ] Enable Cloud Audit Logs (already in place: CLOUD_LOGGING_ONLY)

---

### 2.2 Git Repository Metadata Exposure
**Severity:** 🟠 HIGH

**Exposed Information:**
- Commit history visible showing all changes and credentials
- Branch structure and deployment workflow
- Deployment timing and patterns
- Developer identities from commits

**Risk:** Historical data can be used to track system changes, find older vulnerabilities

---

## 3. AI AGENT & CODEX EXPOSURE RISK

### 3.1 How AI Agents Access Your Code
**Risk Level:** 🟠 HIGH

When you share this repository with AI agents (Claude, GitHub Copilot, Codex, etc.):

1. **Copilot/Codex Integration:**
   - If GitHub Copilot is enabled on this repo: **ALL CODE INDEXED** including credentials
   - Copilot uses code for model training (depending on settings)
   - Microsoft and OpenAI have access to repository content

2. **Claude/External AI Access:**
   - When you paste code or link to repos in conversations
   - All files readable in workspace become training data potentially
   - Credentials become part of conversation logs

3. **This Audit Interaction:**
   - **I (Claude) now have access to all your credentials**
   - These credentials are in this conversation transcript
   - This transcript may be stored (depending on your usage settings)

**Action Required:**
- [ ] Immediately revoke ALL credentials listed above
- [ ] Disable Copilot on this repository: GitHub Settings → Copilot
- [ ] Review "Copilot Enablement" in org settings
- [ ] Never paste sensitive files into AI chat tools
- [ ] Request Claude conversation deletion for this session (contains credentials)
- [ ] Check GitHub Settings → Code Security & Analysis → Secret Scanning

---

## 4. WHAT GETS DISPLAYED IN PINGS/COMMANDS

### 4.1 Git Configuration Exposure
**Risk:** When running Git commands, your account is displayed:

```bash
# Git config reveals:
git config user.name      # Shows: Your Name
git config user.email     # Shows: Your email
git log                    # Shows: All commits with credentials (if in messages/diffs)
git remote -v             # Shows: Repository URLs
```

**Does it show credentials?**
- ✅ **YES** if credentials are in:
  - Commit messages (DON'T DO THIS)
  - File diffs (already happened here)
  - Git history (use `git log` to search)
- ✅ **YES** if GitHub SSH key is compromised
- ✅ **YES** if Personal Access Token (PAT) is exposed

**Action Required:**
- [ ] Review your Git config: `git config --list`
- [ ] Check SSH keys: `ssh-keygen -l -f ~/.ssh/id_rsa.pub`
- [ ] Rotate GitHub Personal Access Tokens
- [ ] Check GitHub account security: github.com/settings/security

---

### 4.2 Environment Variable Exposure
**Risk:** When you run commands, environment variables may leak:

```bash
# These commands may expose credentials:
env                       # Shows all environment variables
printenv                  # Shows all environment variables
echo $SUPABASE_SERVICE_ROLE_KEY  # Direct exposure
ps aux                    # May show process environment variables
```

**Does it show credentials in your case?**
- ✅ **YES** - All are in `app.yaml` which is version controlled
- ⚠️ **CONDITIONAL** - If set in shell, depends on process inspection permissions

---

## 5. GITHUB ACCOUNT SECURITY AUDIT

### 5.1 Repository Access & Permissions
**Current Status:** NEEDS VERIFICATION

**Questions to Answer:**
- [ ] How many people have access to this repository?
- [ ] Are access levels (Admin/Write/Read) appropriate?
- [ ] Are GitHub Apps connected? (Check Settings → Installed apps)
- [ ] Is this repository public or private? (**CRITICAL IF PUBLIC**)
- [ ] Are deployment keys present?

**Action Required:**
- [ ] View Repository → Settings → Collaborators
- [ ] Remove unnecessary collaborators
- [ ] Change access levels if over-privileged
- [ ] Review GitHub Apps with repository access

---

### 5.2 GitHub Security Features
**Recommended Status:**

| Feature | Status | Action |
|---------|--------|--------|
| **Branch Protection** | ⚠️ Unknown | Enable: Require status checks, dismiss stale PRs, require code reviews |
| **Secret Scanning** | ⚠️ Likely Disabled | Enable in Settings → Security & Analysis → Secret Scanning |
| **Dependabot Alerts** | ⚠️ Unknown | Enable in Settings → Code Security & Analysis |
| **Code Scanning (Codeql)** | ⚠️ Unknown | Enable: Creates security-focused workflows |
| **2FA on Account** | ⚠️ Unknown | Verify in github.com/settings/security |
| **SSH Keys** | ⚠️ Unknown | Review and rotate: github.com/settings/keys |
| **Personal Access Tokens** | ⚠️ Unknown | Rotate and audit: github.com/settings/tokens |
| **Audit Log** | ⚠️ Unknown | Review: github.com/settings/audit-log (org only) |

**Action Required:**
```bash
# Check if Secret Scanning would have caught these:
# GitHub's secret scanning patterns would flag:
# - ✅ SUPABASE_SERVICE_ROLE_KEY (JWT pattern)
# - ✅ ACCESS_TOKEN_SECRET (hex pattern)
# - ⚠️ Email password (depends on pattern)
# - ✅ Database password (depends on pattern)
```

---

## 6. GIT HISTORY CONTAMINATION

### 6.1 Credentials in Commit History
**Severity:** 🔴 CRITICAL

All credentials are stored in Git history:
```bash
# To view:
git log --all -S "ACCESS_TOKEN_SECRET"
git log --oneline | grep -i "secret\|credential\|password\|token"
git log -p -- app.yaml  # Shows all historical changes
```

**Action Required:**
- [ ] Use `git-filter-repo` to remove credentials from history (irreversible):
  ```bash
  # WARNING: This rewrites history - coordinate with team
  git filter-repo --replace-text credentials.txt
  git push --force-with-lease origin main
  ```
- [ ] Or use BFG Repo-Cleaner (easier):
  ```bash
  bfg --replace-text credentials.txt repo
  git push --force-with-lease origin main
  ```

---

## 7. EXPOSURE TIMELINE & MITIGATION

### 7.1 When Were Credentials Exposed?
- ✅ Since first commit to Git (check: `git log --all --oneline app.yaml`)
- ✅ To anyone with repository access
- ✅ To GitHub staff (they have visibility)
- ✅ To any AI agent that accessed this repo
- ✅ To me (Claude) in this audit

### 7.2 Assume Compromise
**Security Best Practice:** Treat all exposed credentials as **COMPROMISED** regardless of actual usage.

**Worst-Case Scenario:**
- Attacker gains access to:
  - ✅ Email account → intercepts password resets, 2FA codes
  - ✅ MySQL database → exfiltrates all consultation data
  - ✅ Supabase → accesses all user data
  - ✅ GCP project → cloud infrastructure takeover
  - ✅ Azure/Microsoft Entra → enterprise directory compromise
  - ✅ Cloudflare → DNS/WAF compromise
  - ✅ All user sessions via forged JWT tokens

---

## 8. REMEDIATION CHECKLIST

### PHASE 1: IMMEDIATE (Next 24 Hours)
- [ ] **STOP** - Do not use these credentials for new deployments
- [ ] **ROTATE IMMEDIATELY:**
  - [ ] Email password (info@stackopsit.co.za)
  - [ ] MySQL root password
  - [ ] Supabase service role key
  - [ ] ACCESS_TOKEN_SECRET
  - [ ] All Azure/Microsoft service principal credentials
  - [ ] Cloudflare API token
- [ ] **REVOKE:**
  - [ ] SSH keys in GitHub
  - [ ] GitHub Personal Access Tokens
  - [ ] GCP service account keys
- [ ] **ALERT:**
  - [ ] Notify all team members
  - [ ] Contact security team
  - [ ] Monitor logs for unauthorized access

### PHASE 2: SHORT-TERM (This Week)
- [ ] Remove credentials from Git history using `git-filter-repo`
- [ ] Force push cleaned history (requires admin access)
- [ ] Create `.env.example` file showing structure WITHOUT values
- [ ] Create `.gitignore` entries:
  ```
  .env
  .env.local
  .env.*.local
  app.yaml
  config/secrets.yml
  ```
- [ ] Update all deployment systems to use Google Secret Manager
- [ ] Enable GitHub Secret Scanning
- [ ] Enable Branch Protection Rules
- [ ] Audit all GCP service accounts and IAM roles

### PHASE 3: ONGOING (This Month)
- [ ] Implement proper secrets management:
  - [ ] Use Google Secret Manager (already referenced in cloudbuild.yaml)
  - [ ] Use GitHub Secrets for CI/CD (not in repo)
  - [ ] Use environment-specific `.env` files (git-ignored)
- [ ] Implement least-privilege access controls
- [ ] Regular credential rotation schedule
- [ ] Automated secret scanning in CI/CD
- [ ] Security code review training for team
- [ ] Regular security audits

---

## 9. DETECTION: What Happens Next?

### 9.1 Can Attackers Use These Credentials?
**Email Account:**
- ✅ YES - Can send emails as info@stackopsit.co.za
- ✅ YES - Can reset other account passwords
- ✅ Impact: Phishing, impersonation, account takeover

**MySQL Database:**
- ✅ YES - Full root access (all privileges)
- ✅ YES - Can read, modify, delete all data
- ✅ Impact: Data breach, ransomware, service disruption

**Supabase:**
- ✅ YES - Service role has admin privileges
- ✅ YES - Can bypass row-level security
- ✅ Impact: Complete data compromise

**JWT Secret:**
- ✅ YES - Can forge authentication tokens
- ✅ YES - Can impersonate any user
- ✅ Impact: Account takeover, unauthorized access

### 9.2 Detecting Unauthorized Access
**To Check:**
```bash
# Email logs
# Database audit logs
# Supabase activity logs (if available)
# GCP audit logs: gcloud logging read "[resource.type=...]"
# Application logs: check for suspicious JWT tokens
# Login attempts: review authentication logs
```

---

## 10. RECOMMENDATIONS FOR FUTURE PREVENTION

### 10.1 Development Best Practices
```javascript
// ❌ NEVER DO THIS:
const secret = "hardcoded_secret_123";
const API_KEY = "sk-1234567890abcdef";

// ✅ ALWAYS DO THIS:
const secret = process.env.ACCESS_TOKEN_SECRET;
const API_KEY = process.env.AZURE_OPENAI_KEY;

// ✅ Load from environment:
require('dotenv').config(); // Good for development
// Use Google Secret Manager for production (already in cloudbuild.yaml)
```

### 10.2 Secure Configuration Management
```yaml
# ❌ app.yaml (CURRENT - WRONG):
SUPABASE_SERVICE_ROLE_KEY: "actual_secret_here"

# ✅ cloudbuild.yaml (CORRECT - ALREADY DOING THIS):
--update-secrets: 'SUPABASE_SERVICE_ROLE_KEY=SUPABASE_SERVICE_ROLE_KEY:latest'

# ✅ .env.example (REFERENCE - NO SECRETS):
SUPABASE_URL=https://mrubwknihpwlgreoroso.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_key_here_from_secret_manager
```

### 10.3 Git Pre-Commit Hooks
```bash
# Install pre-commit hook to prevent secret commits:
npm install --save-dev husky lint-staged
npm install --save-dev @leaks/detect-secrets

# Or use existing tools:
# - detect-secrets
# - gitleaks
# - truffleHog
```

### 10.4 CI/CD Best Practices
- ✅ Use Google Secret Manager (already configured)
- ✅ Never log secrets in build output
- ✅ Use `--quiet` flag (already in cloudbuild.yaml)
- ✅ Implement audit logging
- ✅ Rotate credentials regularly

---

## 11. IMPACT ASSESSMENT

### 11.1 Data at Risk
| Asset | Access Level | Exposure |
|-------|--------------|----------|
| Consultation Database | Full (root) | ✅ CRITICAL |
| User Credentials | Full (read) | ✅ CRITICAL |
| Client Data | Full | ✅ CRITICAL |
| Project Information | Full | ✅ CRITICAL |
| Email Communications | Read/Send | ✅ CRITICAL |
| Application Users | Full | ✅ CRITICAL |
| Authentication System | Full | ✅ CRITICAL |

### 11.2 Compliance Implications
- ⚠️ **GDPR:** Data exposure may require breach notification
- ⚠️ **POPIA (South Africa):** Personal information of South African users affected
- ⚠️ **SOC 2:** Credential exposure is a critical finding
- ⚠️ **ISO 27001:** Multiple control failures (A.8.2.1, A.8.3.2, A.12.2.1)

**Action Required:**
- [ ] Notify legal team about potential breach
- [ ] Determine if user notification required
- [ ] Document incident response
- [ ] File incident report if required by law

---

## 12. NEXT STEPS

### Immediate Action (Do Now)
1. **Assign Owner:** Who is responsible for remediation?
2. **Rotate Credentials:** Execute PHASE 1 checklist
3. **Notify Team:** Create incident response meeting
4. **Pause Deployment:** Don't deploy with exposed credentials

### Follow-Up Actions (This Week)
1. Run `git-filter-repo` to clean history
2. Implement `.env` files and `.gitignore`
3. Update CI/CD to use Secret Manager exclusively
4. Enable all GitHub security features
5. Conduct team security training

### Long-Term (This Month)
1. Implement automated secret scanning
2. Establish credential rotation schedule
3. Regular security audits (quarterly)
4. Penetration testing
5. Security code review training

---

## 13. RESOURCES & TOOLS

### Secret Management
- Google Secret Manager: https://cloud.google.com/secret-manager
- GitHub Secrets: https://docs.github.com/en/actions/security-guides/encrypted-secrets
- HashiCorp Vault: https://www.vaultproject.io/

### Git History Cleaning
- git-filter-repo: https://github.com/newren/git-filter-repo
- BFG Repo-Cleaner: https://rtyley.github.io/bfg-repo-cleaner/
- GitHub Removing Sensitive Data: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository

### Security Scanning
- GitHub Advanced Security: https://github.com/features/security
- OWASP Secret Scanning: https://owasp.org/www-community/attacks/Secret_Scanning
- Detect-Secrets: https://github.com/Yelp/detect-secrets

### Credential Rotation
- Supabase Key Rotation: https://supabase.com/docs/guides/api/keys
- Google Cloud Secret Manager: https://cloud.google.com/secret-manager/docs/managing-secrets

---

## CONTACT & ESCALATION

**For Security Incidents:**
- Report to: [SECURITY CONTACT]
- Severity: CRITICAL
- Timeline: URGENT - Address within 24 hours

**Audit Performed By:** Security Audit System  
**Report Date:** 2026-09-14  
**Next Review:** After remediation completion

---

## APPENDIX A: CREDENTIALS EXPOSED (Summary)

| Credential | Type | Status | Action |
|-----------|------|--------|--------|
| info@stackopsit.co.za | Email Password: `Cxzdsaewq123$` | 🔴 EXPOSED | ROTATE NOW |
| SMTP Credentials | Email: `Cxzdsaewq123$` | 🔴 EXPOSED | ROTATE NOW |
| MySQL root | Password: `@TakalaniSandani2005` | 🔴 EXPOSED | ROTATE NOW |
| Supabase Service Key | JWT Token (visible) | 🔴 EXPOSED | ROTATE NOW |
| ACCESS_TOKEN_SECRET | Hex: `7a076e42...` | 🔴 EXPOSED | REGENERATE NOW |
| GCP Project | ID: `stackops-backend-475222` | 🟠 DISCLOSED | AUDIT NOW |
| Azure Tenant IDs | Multiple mentioned | 🟠 DISCLOSED | AUDIT NOW |
| Cloudflare Account | Details referenced | 🟠 DISCLOSED | AUDIT NOW |

---

**END OF SECURITY AUDIT REPORT**

⚠️ **This report contains sensitive information. Keep it in a secure location and do not share with unauthorized parties.**
