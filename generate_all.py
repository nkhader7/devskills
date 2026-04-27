#!/usr/bin/env python3
"""Generate all devskills YAML skill files from gitleaks rule definitions."""
import os
import yaml

BASE = "/home/runner/work/devskills/devskills/skills"


def token_cost(regex="", has_entropy=False, has_allowlist=False, has_path_filter=False, severity="high"):
    est = 100
    if len(regex) > 100:
        est += 50
    if has_entropy:
        est += 25
    if has_allowlist:
        est += 25
    if has_path_filter:
        est += 10
    if severity == "critical":
        est += 25
    elif severity == "high":
        est += 10
    return {"estimate": est, "model_agnostic": True, "unit": "tokens"}


def skill(id_, name, desc, category, severity, tags, regex="", entropy=None, keywords=None,
          path_filter=None, allowlist=None, action="rotate", docs="", finding_type="secret", impact=""):
    tc = token_cost(regex, entropy is not None, allowlist is not None, path_filter is not None, severity)
    detection = {}
    if regex:
        detection["regex"] = regex
    if entropy is not None:
        detection["entropy"] = entropy
    if keywords:
        detection["keywords"] = keywords
    if path_filter:
        detection["path_filter"] = path_filter
    if allowlist:
        detection["allowlist"] = allowlist
    return {
        "id": id_,
        "version": "1.0.0",
        "name": name,
        "description": desc,
        "category": category,
        "severity": severity,
        "tags": tags,
        "token_cost": tc,
        "detection": detection,
        "remediation": {"action": action, "docs": docs},
        "report": {"finding_type": finding_type, "impact": impact or f"Exposed {name} can lead to unauthorized access."}
    }


def write(path, skills):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(skills, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    print(f"Wrote {path} ({len(skills)} skills)")


# ── Cloud ────────────────────────────────────────────────────────────────────

write(f"{BASE}/cloud/aws.yaml", [
    skill("aws-access-key-id", "AWS Access Key ID",
          "Detects AWS Access Key IDs which provide programmatic access to AWS services.",
          "cloud", "critical", ["aws", "cloud", "access-key"],
          regex=r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
          keywords=["akia", "agpa", "aida", "aroa", "aipa", "anpa", "anva", "asia"],
          docs="https://docs.aws.amazon.com/general/latest/gr/aws-security-credentials.html",
          impact="Full AWS account access possible."),
    skill("aws-secret-access-key", "AWS Secret Access Key",
          "Detects AWS Secret Access Keys.",
          "cloud", "critical", ["aws", "cloud", "secret-key"],
          regex=r"(?i)aws[_\-\.]?(?:secret)?[_\-\.]?(?:access)?[_\-\.]?key['"]*\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})",
          entropy=3.5,
          keywords=["aws_secret", "aws_secret_access_key"],
          docs="https://docs.aws.amazon.com/general/latest/gr/aws-security-credentials.html",
          impact="Full AWS account access possible."),
    skill("aws-mws-key", "AWS MWS Key",
          "Detects Amazon MWS authentication tokens.",
          "cloud", "high", ["aws", "mws"],
          regex=r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
          keywords=["amzn.mws."],
          docs="https://developer-docs.amazon.com/sp-api/",
          impact="Unauthorized access to Amazon Marketplace Web Service."),
])

write(f"{BASE}/cloud/gcp.yaml", [
    skill("gcp-api-key", "GCP API Key",
          "Detects Google Cloud Platform API keys.",
          "cloud", "high", ["gcp", "google", "api-key"],
          regex=r"AIza[0-9A-Za-z\-_]{35}",
          keywords=["aiza"],
          docs="https://cloud.google.com/docs/authentication/api-keys",
          impact="Unauthorized use of GCP services."),
    skill("gcp-service-account", "GCP Service Account JSON",
          "Detects GCP service account key files.",
          "cloud", "critical", ["gcp", "google", "service-account"],
          regex=r'"type"\s*:\s*"service_account"',
          keywords=["service_account"],
          docs="https://cloud.google.com/iam/docs/service-accounts",
          impact="Full GCP project access via service account impersonation."),
])

write(f"{BASE}/cloud/azure.yaml", [
    skill("azure-subscription-key", "Azure Subscription Key",
          "Detects Azure Cognitive Services subscription keys.",
          "cloud", "high", ["azure", "microsoft", "cognitive-services"],
          regex=r"(?i)(?:azure|ocp-apim)[_\-\.]?(?:subscription)?[_\-\.]?key['"]*\s*[:=]\s*['"]?([a-f0-9]{32})",
          keywords=["azure", "ocp-apim-subscription-key"],
          docs="https://docs.microsoft.com/en-us/azure/cognitive-services/",
          impact="Unauthorized access to Azure Cognitive Services."),
    skill("azure-client-secret", "Azure Client Secret",
          "Detects Azure AD client secrets.",
          "cloud", "critical", ["azure", "microsoft", "client-secret"],
          regex=r"(?i)azure[_\-\.]?client[_\-\.]?secret['"]*\s*[:=]\s*['"]?([a-zA-Z0-9~._-]{34,40})",
          keywords=["azure_client_secret", "azure-client-secret"],
          docs="https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal",
          impact="Unauthorized Azure AD access."),
])

write(f"{BASE}/cloud/digitalocean.yaml", [
    skill("digitalocean-access-token", "DigitalOcean Access Token",
          "Detects DigitalOcean personal access tokens.",
          "cloud", "critical", ["digitalocean", "cloud", "access-token"],
          regex=r"(?i)(?:digital.?ocean|do)[_\-\.]?(?:access[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([a-f0-9]{64})",
          keywords=["digitalocean", "do_access_token"],
          docs="https://docs.digitalocean.com/reference/api/create-personal-access-token/",
          impact="Full DigitalOcean account control."),
    skill("digitalocean-refresh-token", "DigitalOcean Refresh Token",
          "Detects DigitalOcean OAuth refresh tokens.",
          "cloud", "high", ["digitalocean", "oauth", "refresh-token"],
          regex=r"(?i)digital.?ocean[_\-\.]?refresh[_\-\.]?token['"]*\s*[:=]\s*['"]?([a-f0-9]{64})",
          keywords=["digitalocean_refresh_token"],
          docs="https://docs.digitalocean.com/reference/api/oauth/",
          impact="OAuth account access token refresh."),
    skill("digitalocean-pat", "DigitalOcean PAT",
          "Detects DigitalOcean PATs with dop_ prefix.",
          "cloud", "critical", ["digitalocean", "pat"],
          regex=r"dop_v1_[a-f0-9]{64}",
          keywords=["dop_v1_"],
          docs="https://docs.digitalocean.com/reference/api/create-personal-access-token/",
          impact="Full DigitalOcean account access."),
])

write(f"{BASE}/cloud/heroku.yaml", [
    skill("heroku-api-key", "Heroku API Key",
          "Detects Heroku API keys.",
          "cloud", "high", ["heroku", "cloud", "api-key"],
          regex=r"(?i)heroku[_\-\.]?(?:api[_\-\.]?)?key['"]*\s*[:=]\s*['"]?([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})",
          keywords=["heroku", "heroku_api_key"],
          docs="https://devcenter.heroku.com/articles/platform-api-reference",
          impact="Unauthorized Heroku application management."),
    skill("heroku-api-accept-beta", "Heroku API Accept Beta",
          "Detects Heroku API keys in Accept Beta headers.",
          "cloud", "high", ["heroku", "cloud", "beta"],
          regex=r"(?i)heroku-accept-beta\s*[:=]\s*['"]?([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})",
          keywords=["heroku-accept-beta"],
          docs="https://devcenter.heroku.com/articles/platform-api-reference",
          impact="Heroku API beta access."),
])

write(f"{BASE}/cloud/alibaba.yaml", [
    skill("alibaba-access-key-id", "Alibaba Access Key ID",
          "Detects Alibaba Cloud Access Key IDs.",
          "cloud", "high", ["alibaba", "cloud", "access-key"],
          regex=r"LTAI[a-zA-Z0-9]{20}",
          keywords=["ltai"],
          docs="https://www.alibabacloud.com/help/en/ram/user-guide/create-an-accesskey-pair",
          impact="Unauthorized access to Alibaba Cloud services."),
    skill("alibaba-secret-key", "Alibaba Secret Key",
          "Detects Alibaba Cloud Secret Keys.",
          "cloud", "critical", ["alibaba", "cloud", "secret-key"],
          regex=r"(?i)alibaba[_\-\.]?(?:cloud)?[_\-\.]?(?:access)?[_\-\.]?(?:key)?[_\-\.]?secret['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{30})",
          entropy=3.5,
          keywords=["alibaba_cloud_access_key_secret"],
          docs="https://www.alibabacloud.com/help/en/ram/user-guide/create-an-accesskey-pair",
          impact="Full Alibaba Cloud account access."),
])

write(f"{BASE}/cloud/flyio.yaml", [
    skill("flyio-access-token", "Fly.io Access Token",
          "Detects Fly.io access tokens.",
          "cloud", "high", ["flyio", "cloud", "access-token"],
          regex=r"fo1_[A-Za-z0-9_\-]{43}",
          keywords=["fo1_"],
          docs="https://fly.io/docs/flyctl/auth-token/",
          impact="Unauthorized Fly.io application management."),
])

write(f"{BASE}/cloud/cloudflare.yaml", [
    skill("cloudflare-api-key", "Cloudflare API Key",
          "Detects Cloudflare global API keys.",
          "cloud", "critical", ["cloudflare", "api-key"],
          regex=r"(?i)cloudflare[_\-\.]?(?:api[_\-\.]?)?key['"]*\s*[:=]\s*['"]?([a-f0-9]{37})",
          keywords=["cloudflare", "cloudflare_api_key"],
          docs="https://developers.cloudflare.com/fundamentals/api/get-started/keys/",
          impact="Full Cloudflare account control."),
    skill("cloudflare-api-token", "Cloudflare API Token",
          "Detects Cloudflare API tokens.",
          "cloud", "high", ["cloudflare", "api-token"],
          regex=r"(?i)cloudflare[_\-\.]?(?:api[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([A-Za-z0-9_\-]{40})",
          keywords=["cloudflare_api_token"],
          docs="https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
          impact="Cloudflare zone/account access."),
    skill("cloudflare-ca-key", "Cloudflare CA Key",
          "Detects Cloudflare CA (origin) keys.",
          "cloud", "critical", ["cloudflare", "ca-key", "tls"],
          regex=r"v1\.0-[A-Za-z0-9\-_]{146}",
          keywords=["v1.0-"],
          docs="https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/",
          impact="Unauthorized TLS certificate issuance."),
])

write(f"{BASE}/cloud/fastly.yaml", [
    skill("fastly-api-key", "Fastly API Key",
          "Detects Fastly API keys.",
          "cloud", "high", ["fastly", "cdn", "api-key"],
          regex=r"(?i)fastly[_\-\.]?(?:api[_\-\.]?)?key['"]*\s*[:=]\s*['"]?([A-Za-z0-9_\-]{32})",
          keywords=["fastly", "fastly_api_key"],
          docs="https://developer.fastly.com/reference/api/#authentication",
          impact="Unauthorized Fastly CDN configuration changes."),
])

write(f"{BASE}/cloud/linode.yaml", [
    skill("linode-api-key", "Linode API Key",
          "Detects Linode personal access tokens.",
          "cloud", "high", ["linode", "cloud", "api-key"],
          regex=r"(?i)linode[_\-\.]?(?:api[_\-\.]?)?(?:key|token)['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{64})",
          keywords=["linode", "linode_api_key"],
          docs="https://www.linode.com/docs/products/platform/accounts/guides/manage-api-tokens/",
          impact="Unauthorized Linode server management."),
])

write(f"{BASE}/cloud/scaleway.yaml", [
    skill("scaleway-api-key", "Scaleway API Key",
          "Detects Scaleway API keys.",
          "cloud", "high", ["scaleway", "cloud", "api-key"],
          regex=r"SCW[A-Z0-9]{38}",
          keywords=["scw"],
          docs="https://www.scaleway.com/en/docs/identity-and-access-management/iam/how-to/create-api-keys/",
          impact="Unauthorized Scaleway infrastructure access."),
])

write(f"{BASE}/cloud/vultr.yaml", [
    skill("vultr-api-key", "Vultr API Key",
          "Detects Vultr API keys.",
          "cloud", "high", ["vultr", "cloud", "api-key"],
          regex=r"(?i)vultr[_\-\.]?(?:api[_\-\.]?)?key['"]*\s*[:=]\s*['"]?([A-Z0-9]{36})",
          keywords=["vultr", "vultr_api_key"],
          docs="https://www.vultr.com/api/",
          impact="Unauthorized Vultr VPS management."),
])

write(f"{BASE}/cloud/hcloud.yaml", [
    skill("hcloud-api-token", "Hetzner Cloud API Token",
          "Detects Hetzner Cloud API tokens.",
          "cloud", "high", ["hcloud", "hetzner", "cloud", "api-token"],
          regex=r"(?i)h(?:etzner)?cloud[_\-\.]?(?:api[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{64})",
          keywords=["hcloud", "hetzner"],
          docs="https://docs.hetzner.cloud/#authentication",
          impact="Unauthorized Hetzner Cloud server management."),
])

write(f"{BASE}/cloud/deta.yaml", [
    skill("deta-api-key", "Deta API Key",
          "Detects Deta space API keys.",
          "cloud", "high", ["deta", "cloud", "api-key"],
          regex=r"(?i)deta[_\-\.]?(?:api[_\-\.]?)?key['"]*\s*[:=]\s*['"]?([a-z0-9_]{40})",
          keywords=["deta_api_key"],
          docs="https://deta.space/docs/en/reference/cli/reference#deta-auth",
          impact="Unauthorized Deta project access."),
])

write(f"{BASE}/cloud/planetscale.yaml", [
    skill("planetscale-api-key", "PlanetScale API Key",
          "Detects PlanetScale database API keys.",
          "cloud", "high", ["planetscale", "database", "cloud", "api-key"],
          regex=r"pscale_tkn_[A-Za-z0-9\-_]{43}",
          keywords=["pscale_tkn_"],
          docs="https://planetscale.com/docs/concepts/service-tokens",
          impact="Unauthorized PlanetScale database access."),
    skill("planetscale-password", "PlanetScale Database Password",
          "Detects PlanetScale database passwords.",
          "cloud", "critical", ["planetscale", "database", "password"],
          regex=r"pscale_pw_[A-Za-z0-9\-_\.]{43}",
          keywords=["pscale_pw_"],
          docs="https://planetscale.com/docs/concepts/connection-strings",
          impact="Direct database access with full credentials."),
    skill("planetscale-oauth-token", "PlanetScale OAuth Token",
          "Detects PlanetScale OAuth tokens.",
          "cloud", "high", ["planetscale", "oauth"],
          regex=r"pscale_oauth_[A-Za-z0-9\-_]{32,}",
          keywords=["pscale_oauth_"],
          docs="https://api-docs.planetscale.com/reference/authentication",
          impact="PlanetScale account OAuth access."),
])

write(f"{BASE}/cloud/vercel.yaml", [
    skill("vercel-api-token", "Vercel API Token",
          "Detects Vercel API tokens.",
          "cloud", "high", ["vercel", "cloud", "api-token"],
          regex=r"(?i)vercel[_\-\.]?(?:api[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{24})",
          keywords=["vercel", "vercel_api_token"],
          docs="https://vercel.com/docs/rest-api#authentication",
          impact="Unauthorized Vercel deployment management."),
])

write(f"{BASE}/cloud/firebase.yaml", [
    skill("firebase-cloud-messaging", "Firebase Cloud Messaging Key",
          "Detects FCM server keys.",
          "cloud", "high", ["firebase", "google", "fcm", "cloud-messaging"],
          regex=r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",
          keywords=["aaaa"],
          docs="https://firebase.google.com/docs/cloud-messaging",
          impact="Unauthorized push notifications to all app users."),
])

# ── Source Control ────────────────────────────────────────────────────────────

write(f"{BASE}/source-control/github.yaml", [
    skill("github-pat", "GitHub Personal Access Token",
          "Detects classic GitHub personal access tokens.",
          "source-control", "critical", ["github", "git", "pat"],
          regex=r"ghp_[0-9a-zA-Z]{36}",
          keywords=["ghp_"],
          docs="https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
          impact="Full GitHub repository and account access."),
    skill("github-fine-grained-pat", "GitHub Fine-Grained PAT",
          "Detects GitHub fine-grained personal access tokens.",
          "source-control", "high", ["github", "git", "pat", "fine-grained"],
          regex=r"github_pat_[0-9a-zA-Z_]{82}",
          keywords=["github_pat_"],
          docs="https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
          impact="Scoped GitHub repository access."),
    skill("github-oauth", "GitHub OAuth Token",
          "Detects GitHub OAuth access tokens.",
          "source-control", "critical", ["github", "oauth"],
          regex=r"gho_[0-9a-zA-Z]{36}",
          keywords=["gho_"],
          docs="https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps",
          impact="OAuth-scoped GitHub account access."),
    skill("github-app-token", "GitHub App Token",
          "Detects GitHub App installation tokens.",
          "source-control", "high", ["github", "app", "installation-token"],
          regex=r"ghs_[0-9a-zA-Z]{36}",
          keywords=["ghs_"],
          docs="https://docs.github.com/en/developers/apps/building-github-apps/authenticating-with-github-apps",
          impact="GitHub App installation access."),
    skill("github-refresh-token", "GitHub Refresh Token",
          "Detects GitHub OAuth refresh tokens.",
          "source-control", "high", ["github", "oauth", "refresh-token"],
          regex=r"ghr_[0-9a-zA-Z]{36}",
          keywords=["ghr_"],
          docs="https://docs.github.com/en/developers/apps/building-oauth-apps/refreshing-user-to-server-access-tokens",
          impact="GitHub OAuth token refresh capability."),
])

write(f"{BASE}/source-control/gitlab.yaml", [
    skill("gitlab-pat", "GitLab Personal Access Token",
          "Detects GitLab personal access tokens.",
          "source-control", "critical", ["gitlab", "git", "pat"],
          regex=r"glpat-[0-9a-zA-Z\-_]{20}",
          keywords=["glpat-"],
          docs="https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html",
          impact="Full GitLab repository and account access."),
    skill("gitlab-ptt", "GitLab Pipeline Trigger Token",
          "Detects GitLab pipeline trigger tokens.",
          "source-control", "high", ["gitlab", "pipeline", "trigger"],
          regex=r"glptt-[0-9a-zA-Z\-_]{20}",
          keywords=["glptt-"],
          docs="https://docs.gitlab.com/ee/ci/triggers/",
          impact="Unauthorized pipeline triggering."),
    skill("gitlab-rrt", "GitLab Runner Registration Token",
          "Detects GitLab runner registration tokens.",
          "source-control", "high", ["gitlab", "runner", "registration"],
          regex=r"GR1348941[0-9a-zA-Z\-_]{20}",
          keywords=["gr1348941"],
          docs="https://docs.gitlab.com/runner/register/",
          impact="Unauthorized runner registration to GitLab."),
    skill("gitlab-deploy-token", "GitLab Deploy Token",
          "Detects GitLab deploy tokens.",
          "source-control", "high", ["gitlab", "deploy"],
          regex=r"gldt-[0-9a-zA-Z\-_]{20}",
          keywords=["gldt-"],
          docs="https://docs.gitlab.com/ee/user/project/deploy_tokens/",
          impact="Unauthorized deployment access."),
    skill("gitlab-cicd-var", "GitLab CI/CD Variable",
          "Detects potential GitLab CI/CD variable exposure.",
          "source-control", "medium", ["gitlab", "cicd", "variable"],
          regex=r"(?i)CI_(?:JOB|RUNNER|DEPLOY)_TOKEN\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})",
          keywords=["ci_job_token", "ci_runner_token", "ci_deploy_token"],
          docs="https://docs.gitlab.com/ee/ci/variables/",
          impact="Exposure of CI/CD pipeline credentials."),
])

write(f"{BASE}/source-control/bitbucket.yaml", [
    skill("bitbucket-client-id", "Bitbucket Client ID",
          "Detects Bitbucket OAuth consumer client IDs.",
          "source-control", "medium", ["bitbucket", "oauth", "client-id"],
          regex=r"(?i)bitbucket[_\-\.]?(?:client[_\-\.]?)?id['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{32})",
          keywords=["bitbucket", "bitbucket_client_id"],
          docs="https://developer.atlassian.com/cloud/bitbucket/oauth-2/",
          impact="Bitbucket OAuth client exposure."),
    skill("bitbucket-client-secret", "Bitbucket Client Secret",
          "Detects Bitbucket OAuth consumer client secrets.",
          "source-control", "critical", ["bitbucket", "oauth", "client-secret"],
          regex=r"(?i)bitbucket[_\-\.]?(?:client[_\-\.]?)?secret['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{32})",
          keywords=["bitbucket_client_secret"],
          docs="https://developer.atlassian.com/cloud/bitbucket/oauth-2/",
          impact="Full Bitbucket OAuth account access."),
])

# ── Communication ─────────────────────────────────────────────────────────────

write(f"{BASE}/communication/slack.yaml", [
    skill("slack-api-token", "Slack API Token",
          "Detects Slack API tokens.",
          "communication", "high", ["slack", "messaging", "api-token"],
          regex=r"xox[baprs]-([0-9a-zA-Z]{10,48})",
          keywords=["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"],
          docs="https://api.slack.com/authentication/token-types",
          impact="Unauthorized Slack workspace access."),
    skill("slack-webhook", "Slack Webhook URL",
          "Detects Slack incoming webhook URLs.",
          "communication", "medium", ["slack", "webhook"],
          regex=r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
          keywords=["hooks.slack.com"],
          docs="https://api.slack.com/messaging/webhooks",
          impact="Unauthorized message posting to Slack channels."),
    skill("slack-app-token", "Slack App-Level Token",
          "Detects Slack app-level tokens.",
          "communication", "high", ["slack", "app-token"],
          regex=r"xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+",
          keywords=["xapp-"],
          docs="https://api.slack.com/authentication/token-types#app-level",
          impact="Slack app-level access including Socket Mode."),
    skill("slack-config-access-token", "Slack Config Access Token",
          "Detects Slack configuration access tokens.",
          "communication", "high", ["slack", "config-token"],
          regex=r"xoxe\.xox[bp]-\d-[A-Z0-9]+-\d+",
          keywords=["xoxe.xoxb-", "xoxe.xoxp-"],
          docs="https://api.slack.com/authentication/config-tokens",
          impact="Slack workspace configuration access."),
    skill("slack-config-refresh-token", "Slack Config Refresh Token",
          "Detects Slack configuration refresh tokens.",
          "communication", "high", ["slack", "config-refresh-token"],
          regex=r"xoxe-\d-[A-Z0-9]+-\d+",
          keywords=["xoxe-"],
          docs="https://api.slack.com/authentication/config-tokens",
          impact="Slack configuration token refresh capability."),
    skill("slack-user-token", "Slack User Token",
          "Detects Slack user tokens (xoxp-).",
          "communication", "high", ["slack", "user-token"],
          regex=r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{13}-[a-z0-9]{32}",
          keywords=["xoxp-"],
          docs="https://api.slack.com/authentication/token-types#user",
          impact="User-level Slack workspace access."),
    skill("slack-bot-token", "Slack Bot Token",
          "Detects Slack bot tokens (xoxb-).",
          "communication", "high", ["slack", "bot-token"],
          regex=r"xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}",
          keywords=["xoxb-"],
          docs="https://api.slack.com/authentication/token-types#bot",
          impact="Bot-level Slack workspace access."),
    skill("slack-legacy-bot-token", "Slack Legacy Bot Token",
          "Detects legacy Slack bot tokens.",
          "communication", "medium", ["slack", "legacy", "bot-token"],
          regex=r"xoxb-[0-9]{11}-[a-zA-Z0-9]{24}",
          keywords=["xoxb-"],
          docs="https://api.slack.com/authentication/token-types",
          impact="Legacy bot access to Slack."),
    skill("slack-legacy-workspace-token", "Slack Legacy Workspace Token",
          "Detects legacy Slack workspace tokens.",
          "communication", "medium", ["slack", "legacy", "workspace-token"],
          regex=r"xoxa-2-[0-9]{11}-[0-9]{11}-[0-9]{11}-[a-z0-9]{32}",
          keywords=["xoxa-2-"],
          docs="https://api.slack.com/authentication/token-types",
          impact="Legacy Slack workspace access."),
])

write(f"{BASE}/communication/discord.yaml", [
    skill("discord-api-token", "Discord API Token",
          "Detects Discord bot tokens.",
          "communication", "high", ["discord", "gaming", "api-token"],
          regex=r"(?i)discord[_\-\.]?(?:api[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})",
          keywords=["discord", "discord_token"],
          docs="https://discord.com/developers/docs/reference#authentication",
          impact="Full Discord bot control."),
    skill("discord-client-id", "Discord Client ID",
          "Detects Discord application client IDs.",
          "communication", "medium", ["discord", "client-id"],
          regex=r"(?i)discord[_\-\.]?(?:client[_\-\.]?)?id['"]*\s*[:=]\s*['"]?([0-9]{18,19})",
          keywords=["discord_client_id"],
          docs="https://discord.com/developers/docs/topics/oauth2",
          impact="Discord OAuth client exposure."),
    skill("discord-client-secret", "Discord Client Secret",
          "Detects Discord OAuth client secrets.",
          "communication", "critical", ["discord", "oauth", "client-secret"],
          regex=r"(?i)discord[_\-\.]?(?:client[_\-\.]?)?secret['"]*\s*[:=]\s*['"]?([A-Za-z0-9_\-]{32})",
          keywords=["discord_client_secret"],
          docs="https://discord.com/developers/docs/topics/oauth2",
          impact="Full Discord OAuth account access."),
])

write(f"{BASE}/communication/teams.yaml", [
    skill("ms-teams-webhook", "Microsoft Teams Webhook",
          "Detects Microsoft Teams incoming webhook URLs.",
          "communication", "medium", ["teams", "microsoft", "webhook"],
          regex=r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9\-_@\.]+",
          keywords=["webhook.office.com"],
          docs="https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook",
          impact="Unauthorized message posting to Teams channels."),
])

write(f"{BASE}/communication/telegram.yaml", [
    skill("telegram-bot-token", "Telegram Bot API Token",
          "Detects Telegram Bot API tokens.",
          "communication", "high", ["telegram", "bot", "api-token"],
          regex=r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",
          keywords=["telegram", "telegrambot"],
          docs="https://core.telegram.org/bots/api#authorizing-your-bot",
          impact="Full control of Telegram bot including reading messages."),
])

write(f"{BASE}/communication/gitter.yaml", [
    skill("gitter-access-token", "Gitter Access Token",
          "Detects Gitter access tokens.",
          "communication", "high", ["gitter", "communication", "access-token"],
          regex=r"(?i)gitter[_\-\.]?(?:access[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([A-Za-z0-9_]{40})",
          keywords=["gitter", "gitter_token"],
          docs="https://developer.gitter.im/docs/authentication",
          impact="Unauthorized Gitter room access."),
])

# ── Payment ───────────────────────────────────────────────────────────────────

write(f"{BASE}/payment/stripe.yaml", [
    skill("stripe-access-token", "Stripe Access Token",
          "Detects Stripe restricted/secret API keys.",
          "payment", "critical", ["stripe", "payment", "api-key"],
          regex=r"(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24,}",
          keywords=["sk_live_", "sk_test_", "rk_live_"],
          docs="https://stripe.com/docs/keys",
          impact="Unauthorized payment processing and financial data access."),
    skill("stripe-webhook", "Stripe Webhook Secret",
          "Detects Stripe webhook signing secrets.",
          "payment", "high", ["stripe", "webhook"],
          regex=r"whsec_[A-Za-z0-9+/]{32,}",
          keywords=["whsec_"],
          docs="https://stripe.com/docs/webhooks/signatures",
          impact="Webhook signature bypass, unauthorized event injection."),
])

write(f"{BASE}/payment/paypal.yaml", [
    skill("paypal-braintree-access-token", "PayPal Braintree Access Token",
          "Detects Braintree access tokens.",
          "payment", "critical", ["paypal", "braintree", "access-token"],
          regex=r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
          keywords=["access_token$production$"],
          docs="https://developer.paypal.com/braintree/docs/start/overview",
          impact="Unauthorized Braintree payment processing."),
])

write(f"{BASE}/payment/square.yaml", [
    skill("square-access-token", "Square Access Token",
          "Detects Square OAuth access tokens.",
          "payment", "critical", ["square", "payment", "access-token"],
          regex=r"sq0atp-[0-9A-Za-z\-_]{22}",
          keywords=["sq0atp-"],
          docs="https://developer.squareup.com/docs/oauth-api/overview",
          impact="Unauthorized Square payment operations."),
    skill("square-secret-key", "Square Secret Key",
          "Detects Square OAuth secret keys.",
          "payment", "critical", ["square", "payment", "secret-key"],
          regex=r"sq0csp-[0-9A-Za-z\-_]{43}",
          keywords=["sq0csp-"],
          docs="https://developer.squareup.com/docs/oauth-api/overview",
          impact="Full Square OAuth account access."),
])

write(f"{BASE}/payment/shopify.yaml", [
    skill("shopify-shared-secret", "Shopify Shared Secret",
          "Detects Shopify app shared secrets.",
          "payment", "critical", ["shopify", "ecommerce", "shared-secret"],
          regex=r"shpss_[a-fA-F0-9]{32}",
          keywords=["shpss_"],
          docs="https://shopify.dev/apps/auth/oauth/api-access-modes",
          impact="Shopify app authentication bypass."),
    skill("shopify-access-token", "Shopify Access Token",
          "Detects Shopify access tokens.",
          "payment", "critical", ["shopify", "ecommerce", "access-token"],
          regex=r"shpat_[a-fA-F0-9]{32}",
          keywords=["shpat_"],
          docs="https://shopify.dev/apps/auth/oauth/api-access-modes",
          impact="Full Shopify store management access."),
    skill("shopify-custom-access-token", "Shopify Custom Access Token",
          "Detects Shopify custom app access tokens.",
          "payment", "critical", ["shopify", "ecommerce"],
          regex=r"shpca_[a-fA-F0-9]{32}",
          keywords=["shpca_"],
          docs="https://shopify.dev/apps/auth/oauth/api-access-modes",
          impact="Shopify custom app access."),
    skill("shopify-private-app-token", "Shopify Private App Token",
          "Detects Shopify private app tokens.",
          "payment", "critical", ["shopify", "ecommerce", "private-app"],
          regex=r"shppa_[a-fA-F0-9]{32}",
          keywords=["shppa_"],
          docs="https://shopify.dev/apps/auth/oauth/api-access-modes",
          impact="Shopify private app full access."),
])

write(f"{BASE}/payment/twilio.yaml", [
    skill("twilio-api-key", "Twilio API Key",
          "Detects Twilio API keys.",
          "payment", "high", ["twilio", "sms", "api-key"],
          regex=r"SK[0-9a-fA-F]{32}",
          keywords=["twilio", "sk"],
          docs="https://www.twilio.com/docs/iam/api-keys",
          impact="Unauthorized SMS/voice messaging via Twilio."),
    skill("twilio-auth-token", "Twilio Auth Token",
          "Detects Twilio Auth Tokens.",
          "payment", "critical", ["twilio", "sms", "auth-token"],
          regex=r"(?i)twilio[_\-\.]?auth[_\-\.]?token['"]*\s*[:=]\s*['"]?([0-9a-f]{32})",
          keywords=["twilio_auth_token"],
          docs="https://www.twilio.com/docs/iam/keys/auth-token-and-how-to-change-it",
          impact="Full Twilio account access."),
])

write(f"{BASE}/payment/adyen.yaml", [
    skill("adyen-api-key", "Adyen API Key",
          "Detects Adyen API keys.",
          "payment", "critical", ["adyen", "payment", "api-key"],
          regex=r"AQE[a-zA-Z0-9]{6,}[=]{1,2}",
          keywords=["aqe"],
          docs="https://docs.adyen.com/development-resources/api-credentials",
          impact="Unauthorized payment processing via Adyen."),
])

# ── AI/ML ─────────────────────────────────────────────────────────────────────

write(f"{BASE}/ai-ml/openai.yaml", [
    skill("openai-api-key", "OpenAI API Key",
          "Detects OpenAI API keys.",
          "ai-ml", "high", ["openai", "ai", "api-key"],
          regex=r"sk-[A-Za-z0-9]{48}",
          keywords=["sk-"],
          docs="https://platform.openai.com/docs/api-reference/authentication",
          impact="Unauthorized OpenAI API usage with cost impact."),
    skill("openai-org-api-key", "OpenAI Organization API Key",
          "Detects new-format OpenAI organization API keys.",
          "ai-ml", "high", ["openai", "ai", "api-key", "org"],
          regex=r"sk-proj-[A-Za-z0-9_\-]{48,}",
          keywords=["sk-proj-"],
          docs="https://platform.openai.com/docs/api-reference/authentication",
          impact="Unauthorized OpenAI org-level API usage."),
])

write(f"{BASE}/ai-ml/anthropic.yaml", [
    skill("anthropic-api-key", "Anthropic API Key",
          "Detects Anthropic Claude API keys.",
          "ai-ml", "high", ["anthropic", "claude", "ai", "api-key"],
          regex=r"sk-ant-api03-[A-Za-z0-9\-_]{95}",
          keywords=["sk-ant-api03-"],
          docs="https://docs.anthropic.com/claude/docs/authentication",
          impact="Unauthorized use of Anthropic/Claude AI API."),
])

write(f"{BASE}/ai-ml/huggingface.yaml", [
    skill("huggingface-access-token", "Hugging Face Access Token",
          "Detects Hugging Face user access tokens.",
          "ai-ml", "high", ["huggingface", "ml", "access-token"],
          regex=r"hf_[A-Za-z0-9]{36}",
          keywords=["hf_"],
          docs="https://huggingface.co/docs/hub/security-tokens",
          impact="Unauthorized model access/upload on Hugging Face Hub."),
])

write(f"{BASE}/ai-ml/cohere.yaml", [
    skill("cohere-api-key", "Cohere API Key",
          "Detects Cohere NLP API keys.",
          "ai-ml", "high", ["cohere", "nlp", "ai", "api-key"],
          regex=r"(?i)cohere[_\-\.]?(?:api[_\-\.]?)?key['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{40})",
          keywords=["cohere", "cohere_api_key"],
          docs="https://docs.cohere.com/reference/versioning",
          impact="Unauthorized NLP API usage."),
])

write(f"{BASE}/ai-ml/replicate.yaml", [
    skill("replicate-api-token", "Replicate API Token",
          "Detects Replicate model inference API tokens.",
          "ai-ml", "high", ["replicate", "ml", "api-token"],
          regex=r"r8_[A-Za-z0-9]{40}",
          keywords=["r8_"],
          docs="https://replicate.com/docs/reference/http",
          impact="Unauthorized model inference and cost incurrence on Replicate."),
])

# ── Monitoring ────────────────────────────────────────────────────────────────

write(f"{BASE}/monitoring/sentry.yaml", [
    skill("sentry-dsn", "Sentry DSN",
          "Detects Sentry Data Source Names.",
          "monitoring", "medium", ["sentry", "monitoring", "dsn"],
          regex=r"https://[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+",
          keywords=["sentry.io", "ingest.sentry.io"],
          docs="https://docs.sentry.io/product/sentry-basics/dsn-explainer/",
          impact="Unauthorized Sentry error event ingestion."),
    skill("sentry-auth-token", "Sentry Auth Token",
          "Detects Sentry authentication tokens.",
          "monitoring", "high", ["sentry", "monitoring", "auth-token"],
          regex=r"(?i)sentry[_\-\.]?(?:auth[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([a-f0-9]{64})",
          keywords=["sentry_auth_token"],
          docs="https://docs.sentry.io/api/auth/",
          impact="Unauthorized Sentry project/org management."),
])

write(f"{BASE}/monitoring/datadog.yaml", [
    skill("datadog-api-key", "Datadog API Key",
          "Detects Datadog API keys.",
          "monitoring", "high", ["datadog", "monitoring", "api-key"],
          regex=r"(?i)datadog[_\-\.]?(?:api[_\-\.]?)?key['"]*\s*[:=]\s*['"]?([a-f0-9]{32})",
          keywords=["datadog", "dd_api_key"],
          docs="https://docs.datadoghq.com/account_management/api-app-keys/",
          impact="Unauthorized Datadog metric/log submission."),
    skill("datadog-app-key", "Datadog App Key",
          "Detects Datadog application keys.",
          "monitoring", "high", ["datadog", "monitoring", "app-key"],
          regex=r"(?i)datadog[_\-\.]?(?:app|application)[_\-\.]?key['"]*\s*[:=]\s*['"]?([a-f0-9]{40})",
          keywords=["datadog_app_key", "dd_app_key"],
          docs="https://docs.datadoghq.com/account_management/api-app-keys/",
          impact="Full Datadog account configuration access."),
])

write(f"{BASE}/monitoring/newrelic.yaml", [
    skill("newrelic-browser-api-key", "New Relic Browser API Key",
          "Detects New Relic Browser API keys.",
          "monitoring", "medium", ["newrelic", "monitoring", "browser-api"],
          regex=r"NRJS-[0-9a-f]{32}",
          keywords=["nrjs-"],
          docs="https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/",
          impact="New Relic browser monitoring access."),
    skill("newrelic-user-api-key", "New Relic User API Key",
          "Detects New Relic user API keys.",
          "monitoring", "high", ["newrelic", "monitoring", "user-api"],
          regex=r"NRAK-[A-Z0-9]{27}",
          keywords=["nrak-"],
          docs="https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/",
          impact="Full New Relic account query access."),
    skill("newrelic-license-key", "New Relic License Key",
          "Detects New Relic ingest license keys.",
          "monitoring", "high", ["newrelic", "monitoring", "license-key"],
          regex=r"(?:[A-Z]{2}[0-9a-f]{42})NRAL",
          keywords=["nral"],
          docs="https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/",
          impact="Unauthorized data ingest to New Relic."),
    skill("newrelic-admin-api-key", "New Relic Admin API Key",
          "Detects New Relic admin/REST API keys.",
          "monitoring", "critical", ["newrelic", "monitoring", "admin"],
          regex=r"NRAA-[A-Fa-f0-9]{42}",
          keywords=["nraa-"],
          docs="https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/",
          impact="Full New Relic admin API access."),
])

write(f"{BASE}/monitoring/logdna.yaml", [
    skill("logdna-api-key", "LogDNA API Key",
          "Detects LogDNA (now Mezmo) API keys.",
          "monitoring", "high", ["logdna", "mezmo", "monitoring", "api-key"],
          regex=r"(?i)logdna[_\-\.]?(?:api[_\-\.]?)?key['"]*\s*[:=]\s*['"]?([a-f0-9]{32})",
          keywords=["logdna", "logdna_api_key"],
          docs="https://docs.mezmo.com/docs/logdna-api",
          impact="Unauthorized log ingestion and access."),
])

write(f"{BASE}/monitoring/rollbar.yaml", [
    skill("rollbar-access-token", "Rollbar Access Token",
          "Detects Rollbar access tokens.",
          "monitoring", "high", ["rollbar", "monitoring", "access-token"],
          regex=r"(?i)rollbar[_\-\.]?(?:access[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([a-f0-9]{32})",
          keywords=["rollbar", "rollbar_access_token"],
          docs="https://docs.rollbar.com/reference/authentication",
          impact="Unauthorized Rollbar error tracking access."),
])

write(f"{BASE}/monitoring/bugsnag.yaml", [
    skill("bugsnag-api-key", "Bugsnag API Key",
          "Detects Bugsnag API keys.",
          "monitoring", "high", ["bugsnag", "monitoring", "api-key"],
          regex=r"(?i)bugsnag[_\-\.]?(?:api[_\-\.]?)?key['"]*\s*[:=]\s*['"]?([a-f0-9]{32})",
          keywords=["bugsnag", "bugsnag_api_key"],
          docs="https://bugsnagapiv2.docs.apiary.io/",
          impact="Unauthorized Bugsnag error data access."),
])

# ── Infrastructure ────────────────────────────────────────────────────────────

write(f"{BASE}/infrastructure/hashicorp.yaml", [
    skill("hashicorp-vault-token", "HashiCorp Vault Token",
          "Detects HashiCorp Vault tokens.",
          "infrastructure", "critical", ["vault", "hashicorp", "secret-management"],
          regex=r"(?:hvs|hvb|hvr)\.[A-Za-z0-9_\-]{24,}",
          keywords=["hvs.", "hvb.", "hvr."],
          docs="https://developer.hashicorp.com/vault/docs/concepts/tokens",
          impact="Unauthorized secret retrieval from Vault."),
    skill("hashicorp-tf-api-token", "HashiCorp Terraform Cloud API Token",
          "Detects Terraform Cloud API tokens.",
          "infrastructure", "high", ["terraform", "hashicorp", "api-token"],
          regex=r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-=]{60,}",
          keywords=["atlasv1."],
          docs="https://developer.hashicorp.com/terraform/cloud-docs/users-teams-organizations/api-tokens",
          impact="Unauthorized Terraform Cloud workspace management."),
])

write(f"{BASE}/infrastructure/docker.yaml", [
    skill("docker-hub-pat", "Docker Hub PAT",
          "Detects Docker Hub personal access tokens.",
          "infrastructure", "high", ["docker", "container", "pat"],
          regex=r"dckr_pat_[A-Za-z0-9\-_]{27}",
          keywords=["dckr_pat_"],
          docs="https://docs.docker.com/docker-hub/access-tokens/",
          impact="Unauthorized Docker Hub image push/pull."),
])

write(f"{BASE}/infrastructure/kubernetes.yaml", [
    skill("kubernetes-service-account-token", "Kubernetes Service Account Token",
          "Detects Kubernetes service account tokens.",
          "infrastructure", "critical", ["kubernetes", "k8s", "service-account"],
          regex=r"eyJhbGciOiJSUzI1NiIsImtpZCI6",
          keywords=["eyjalgoiojrsuzI1NiIsimtpZci6"],
          docs="https://kubernetes.io/docs/reference/access-authn-authz/authentication/",
          impact="Kubernetes cluster API access with service account permissions."),
])

write(f"{BASE}/infrastructure/ansible.yaml", [
    skill("ansible-vault-password", "Ansible Vault Password",
          "Detects Ansible vault encrypted content and password exposure.",
          "infrastructure", "critical", ["ansible", "vault", "password"],
          regex=r"\$ANSIBLE_VAULT;[0-9\.]+;AES256",
          keywords=["$ansible_vault"],
          docs="https://docs.ansible.com/ansible/latest/user_guide/vault.html",
          impact="Ansible encrypted secrets may be brute-forced."),
])

write(f"{BASE}/infrastructure/pulumi.yaml", [
    skill("pulumi-api-token", "Pulumi API Token",
          "Detects Pulumi service API tokens.",
          "infrastructure", "high", ["pulumi", "iac", "api-token"],
          regex=r"pul-[a-f0-9]{40}",
          keywords=["pul-"],
          docs="https://www.pulumi.com/docs/reference/service-rest-api/#authentication",
          impact="Unauthorized Pulumi stack and infrastructure management."),
])

write(f"{BASE}/infrastructure/codecov.yaml", [
    skill("codecov-access-token", "Codecov Access Token",
          "Detects Codecov upload tokens.",
          "infrastructure", "high", ["codecov", "ci", "access-token"],
          regex=r"(?i)codecov[_\-\.]?(?:access[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([a-f0-9]{32})",
          keywords=["codecov", "codecov_token"],
          docs="https://docs.codecov.com/docs/codecov-tokens",
          impact="Unauthorized Codecov report manipulation."),
])

# ── Database ──────────────────────────────────────────────────────────────────

write(f"{BASE}/database/mysql.yaml", [
    skill("mysql-connection-string", "MySQL Connection String",
          "Detects MySQL database connection strings.",
          "database", "critical", ["mysql", "database", "connection-string"],
          regex=r"mysql://[^:]+:[^@]+@[^/]+/[^\s'\"]+",
          keywords=["mysql://"],
          docs="https://dev.mysql.com/doc/connector-python/en/connector-python-connectargs.html",
          impact="Direct database access with embedded credentials."),
])

write(f"{BASE}/database/postgres.yaml", [
    skill("postgres-connection-string", "PostgreSQL Connection String",
          "Detects PostgreSQL database connection strings.",
          "database", "critical", ["postgres", "database", "connection-string"],
          regex=r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^\s'\"]+",
          keywords=["postgres://", "postgresql://"],
          docs="https://www.postgresql.org/docs/current/libpq-connect.html",
          impact="Direct PostgreSQL database access with embedded credentials."),
])

write(f"{BASE}/database/mongodb.yaml", [
    skill("mongodb-connection-string", "MongoDB Connection String",
          "Detects MongoDB connection strings.",
          "database", "critical", ["mongodb", "database", "connection-string"],
          regex=r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s'\"]+",
          keywords=["mongodb://", "mongodb+srv://"],
          docs="https://www.mongodb.com/docs/manual/reference/connection-string/",
          impact="Direct MongoDB database access."),
])

write(f"{BASE}/database/redis.yaml", [
    skill("redis-connection-string", "Redis Connection String",
          "Detects Redis connection strings with authentication.",
          "database", "high", ["redis", "database", "connection-string"],
          regex=r"rediss?://[^:]*:[^@]+@[^\s'\"]+",
          keywords=["redis://", "rediss://"],
          docs="https://redis.io/docs/manual/security/",
          impact="Unauthorized Redis data access."),
])

write(f"{BASE}/database/firebase.yaml", [
    skill("firebase-rtdb", "Firebase RTDB URL with Secret",
          "Detects Firebase Realtime Database URLs with secrets.",
          "database", "high", ["firebase", "database", "rtdb"],
          regex=r"https://[a-z0-9\-]+\.firebaseio\.com",
          keywords=["firebaseio.com"],
          docs="https://firebase.google.com/docs/database/security",
          impact="Unauthorized Firebase real-time database access."),
])

write(f"{BASE}/database/elastic.yaml", [
    skill("elastic-api-key", "Elasticsearch API Key",
          "Detects Elasticsearch API keys.",
          "database", "high", ["elasticsearch", "elastic", "api-key"],
          regex=r"(?i)elastic[_\-\.]?(?:api[_\-\.]?)?key['"]*\s*[:=]\s*['"]?([A-Za-z0-9+/=]{50,})",
          entropy=3.5,
          keywords=["elasticsearch", "elastic_api_key"],
          docs="https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html",
          impact="Unauthorized Elasticsearch index access."),
])

# ── Package Managers ──────────────────────────────────────────────────────────

write(f"{BASE}/package-managers/npm.yaml", [
    skill("npm-access-token", "npm Access Token",
          "Detects npm registry access tokens.",
          "package-managers", "high", ["npm", "package-manager", "access-token"],
          regex=r"npm_[A-Za-z0-9]{36}",
          keywords=["npm_"],
          docs="https://docs.npmjs.com/creating-and-viewing-access-tokens",
          impact="Unauthorized npm package publishing."),
    skill("npmrc-auth-token", ".npmrc Auth Token",
          "Detects authentication tokens in .npmrc files.",
          "package-managers", "high", ["npm", "npmrc", "auth-token"],
          regex=r"//[a-z0-9\-\.]+\.npm(?:js)?\.(?:org|com)/:[_\-]authToken=[a-zA-Z0-9\-_=]+",
          keywords=["_authtoken=", "//registry.npmjs.org"],
          path_filter=r"(?i)\.npmrc$",
          docs="https://docs.npmjs.com/configuring-npm/npmrc",
          impact="npm registry authentication exposure."),
])

write(f"{BASE}/package-managers/pypi.yaml", [
    skill("pypi-api-token", "PyPI API Token",
          "Detects PyPI package publishing tokens.",
          "package-managers", "high", ["pypi", "python", "package-manager", "api-token"],
          regex=r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}",
          keywords=["pypi-"],
          docs="https://pypi.org/help/#apitoken",
          impact="Unauthorized PyPI package publishing."),
])

write(f"{BASE}/package-managers/nuget.yaml", [
    skill("nuget-api-key", "NuGet API Key",
          "Detects NuGet package publishing API keys.",
          "package-managers", "high", ["nuget", "dotnet", "package-manager", "api-key"],
          regex=r"oy2[A-Za-z0-9]{43}",
          keywords=["oy2"],
          docs="https://docs.microsoft.com/en-us/nuget/nuget-org/publish-a-package",
          impact="Unauthorized NuGet package publishing."),
])

write(f"{BASE}/package-managers/rubygems.yaml", [
    skill("rubygems-api-key", "RubyGems API Key",
          "Detects RubyGems.org API keys.",
          "package-managers", "high", ["rubygems", "ruby", "package-manager", "api-key"],
          regex=r"rubygems_[a-f0-9]{48}",
          keywords=["rubygems_"],
          docs="https://guides.rubygems.org/api-key-scopes/",
          impact="Unauthorized RubyGems package publishing."),
])

# ── Social Media ──────────────────────────────────────────────────────────────

write(f"{BASE}/social-media/twitter.yaml", [
    skill("twitter-api-key", "Twitter/X API Key",
          "Detects Twitter/X API keys.",
          "social-media", "high", ["twitter", "x", "social-media", "api-key"],
          regex=r"(?i)twitter[_\-\.]?(?:api[_\-\.]?)?(?:key|consumer[_\-\.]?key)['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{25})",
          keywords=["twitter", "twitter_api_key"],
          docs="https://developer.twitter.com/en/docs/authentication/oauth-1-0a/api-key-and-secret",
          impact="Twitter API access for reading/posting tweets."),
    skill("twitter-secret-key", "Twitter/X API Secret Key",
          "Detects Twitter/X API secret keys.",
          "social-media", "high", ["twitter", "x", "social-media", "secret-key"],
          regex=r"(?i)twitter[_\-\.]?(?:api[_\-\.]?)?secret['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{50})",
          keywords=["twitter_secret", "twitter_api_secret_key"],
          docs="https://developer.twitter.com/en/docs/authentication/oauth-1-0a/api-key-and-secret",
          impact="Twitter API OAuth signing capability."),
    skill("twitter-access-token", "Twitter/X Access Token",
          "Detects Twitter/X access tokens.",
          "social-media", "high", ["twitter", "x", "social-media", "access-token"],
          regex=r"(?i)twitter[_\-\.]?access[_\-\.]?token['"]*\s*[:=]\s*['"]?([0-9]+-[A-Za-z0-9]{40})",
          keywords=["twitter_access_token"],
          docs="https://developer.twitter.com/en/docs/authentication/oauth-1-0a/obtaining-user-access-tokens",
          impact="Twitter account access token exposure."),
    skill("twitter-bearer-token", "Twitter/X Bearer Token",
          "Detects Twitter/X bearer tokens.",
          "social-media", "high", ["twitter", "x", "social-media", "bearer-token"],
          regex=r"AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%=]{10,}",
          keywords=["aaaaaaaaaaaaaaaaaaaaaa"],
          docs="https://developer.twitter.com/en/docs/authentication/oauth-2-0/bearer-tokens",
          impact="Twitter app-only API access."),
])

write(f"{BASE}/social-media/facebook.yaml", [
    skill("facebook-access-token", "Facebook Access Token",
          "Detects Facebook access tokens.",
          "social-media", "high", ["facebook", "meta", "social-media", "access-token"],
          regex=r"EAA[C-F][a-zA-Z0-9]+",
          keywords=["eaac", "eaad", "eaae", "eaaf"],
          docs="https://developers.facebook.com/docs/facebook-login/access-tokens/",
          impact="Unauthorized Facebook account/page access."),
    skill("facebook-page-access-token", "Facebook Page Access Token",
          "Detects Facebook page access tokens.",
          "social-media", "high", ["facebook", "meta", "social-media", "page-token"],
          regex=r"(?i)(?:facebook|fb)[_\-\.]?page[_\-\.]?(?:access[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{80,})",
          keywords=["fb_page_access_token", "facebook_page_access_token"],
          docs="https://developers.facebook.com/docs/pages/access-tokens",
          impact="Unauthorized Facebook page management."),
])

write(f"{BASE}/social-media/instagram.yaml", [
    skill("instagram-access-token", "Instagram Access Token",
          "Detects Instagram Basic Display API access tokens.",
          "social-media", "high", ["instagram", "meta", "social-media", "access-token"],
          regex=r"(?i)instagram[_\-\.]?(?:access[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([A-Za-z0-9_\-\.]{20,})",
          keywords=["instagram", "instagram_access_token"],
          docs="https://developers.facebook.com/docs/instagram-basic-display-api/guides/getting-access-tokens-and-permissions",
          impact="Instagram account read access."),
])

write(f"{BASE}/social-media/linkedin.yaml", [
    skill("linkedin-client-secret", "LinkedIn Client Secret",
          "Detects LinkedIn OAuth client secrets.",
          "social-media", "high", ["linkedin", "oauth", "client-secret"],
          regex=r"(?i)linkedin[_\-\.]?(?:client[_\-\.]?)?secret['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{16})",
          keywords=["linkedin", "linkedin_client_secret"],
          docs="https://learn.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow",
          impact="LinkedIn OAuth access for user profile data."),
])

# ── Generic ───────────────────────────────────────────────────────────────────

write(f"{BASE}/generic/private-key.yaml", [
    skill("rsa-private-key", "RSA Private Key",
          "Detects RSA private keys.",
          "generic", "critical", ["rsa", "crypto", "private-key"],
          regex=r"-----BEGIN RSA PRIVATE KEY-----",
          keywords=["begin rsa private key"],
          docs="https://en.wikipedia.org/wiki/RSA_(cryptosystem)",
          impact="Compromise of RSA encryption/signing capability."),
    skill("ec-private-key", "EC Private Key",
          "Detects elliptic curve private keys.",
          "generic", "critical", ["ec", "crypto", "private-key"],
          regex=r"-----BEGIN EC PRIVATE KEY-----",
          keywords=["begin ec private key"],
          docs="https://en.wikipedia.org/wiki/Elliptic-curve_cryptography",
          impact="Compromise of EC encryption/signing."),
    skill("pgp-private-key", "PGP Private Key Block",
          "Detects PGP private key blocks.",
          "generic", "critical", ["pgp", "crypto", "private-key"],
          regex=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
          keywords=["begin pgp private key block"],
          docs="https://www.openpgp.org/",
          impact="PGP identity and message decryption compromise."),
    skill("openssh-private-key", "OpenSSH Private Key",
          "Detects OpenSSH private keys.",
          "generic", "critical", ["ssh", "crypto", "private-key"],
          regex=r"-----BEGIN OPENSSH PRIVATE KEY-----",
          keywords=["begin openssh private key"],
          docs="https://www.openssh.com/",
          impact="SSH authentication bypass."),
    skill("dsa-private-key", "DSA Private Key",
          "Detects DSA private keys.",
          "generic", "critical", ["dsa", "crypto", "private-key"],
          regex=r"-----BEGIN DSA PRIVATE KEY-----",
          keywords=["begin dsa private key"],
          docs="https://en.wikipedia.org/wiki/Digital_Signature_Algorithm",
          impact="DSA signing key compromise."),
    skill("pkcs8-private-key", "PKCS8 Private Key",
          "Detects PKCS8 private keys.",
          "generic", "critical", ["pkcs8", "crypto", "private-key"],
          regex=r"-----BEGIN PRIVATE KEY-----",
          keywords=["begin private key"],
          docs="https://datatracker.ietf.org/doc/html/rfc5958",
          impact="PKCS8 private key compromise."),
])

write(f"{BASE}/generic/jwt.yaml", [
    skill("jwt-token", "JWT Token",
          "Detects JSON Web Tokens.",
          "generic", "medium", ["jwt", "token", "authentication"],
          regex=r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
          keywords=["eyj"],
          docs="https://jwt.io/introduction",
          impact="JWT token exposure may allow session hijacking if not expired."),
    skill("jwt-base64", "JWT Base64 Encoded",
          "Detects base64-encoded JWTs in code.",
          "generic", "medium", ["jwt", "base64", "token"],
          regex=r"ZXlK[A-Za-z0-9+/=]+",
          keywords=["zxlk"],
          docs="https://jwt.io/introduction",
          impact="Encoded JWT exposure enabling session access."),
])

write(f"{BASE}/generic/generic-api-key.yaml", [
    skill("generic-api-key", "Generic API Key",
          "Detects potential generic API keys.",
          "generic", "low", ["generic", "api-key"],
          regex=r"(?i)(?:api[_\-\.]?key|apikey)['"]*\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,45})",
          entropy=3.5,
          keywords=["api_key", "apikey", "api-key"],
          docs="",
          impact="Potential unauthorized API access depending on the service."),
])

write(f"{BASE}/generic/generic-secret.yaml", [
    skill("generic-secret", "Generic Secret",
          "Detects potential hardcoded generic secrets.",
          "generic", "low", ["generic", "secret", "password"],
          regex=r"(?i)(?:secret|password|passwd|pwd)['"]*\s*[:=]\s*['"]?([a-zA-Z0-9_\-!@#$%^&*]{8,})",
          entropy=3.5,
          keywords=["secret", "password", "passwd", "pwd"],
          docs="",
          impact="Potential credential exposure."),
])

write(f"{BASE}/generic/credentials.yaml", [
    skill("hardcoded-credentials", "Hardcoded Credentials",
          "Detects hardcoded username/password combinations.",
          "generic", "medium", ["credentials", "username", "password"],
          regex=r"(?i)(?:username|user)['"]*\s*[:=]\s*['"]?([a-zA-Z0-9_\-\.@+]{3,})['"]*.*(?:password|passwd|pwd)['"]*\s*[:=]\s*['"]?([a-zA-Z0-9_\-!@#$%^&*]{6,})",
          keywords=["username", "password", "credentials"],
          docs="",
          impact="Direct authentication bypass with exposed credentials."),
])

# ── Misc ──────────────────────────────────────────────────────────────────────

write(f"{BASE}/misc/sendgrid.yaml", [
    skill("sendgrid-api-token", "SendGrid API Token",
          "Detects SendGrid API tokens.",
          "misc", "high", ["sendgrid", "email", "api-token"],
          regex=r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
          keywords=["sg."],
          docs="https://docs.sendgrid.com/ui/account-and-settings/api-keys",
          impact="Unauthorized email sending via SendGrid."),
])

write(f"{BASE}/misc/mailgun.yaml", [
    skill("mailgun-private-api-key", "Mailgun Private API Key",
          "Detects Mailgun private API keys.",
          "misc", "high", ["mailgun", "email", "api-key"],
          regex=r"key-[0-9a-zA-Z]{32}",
          keywords=["key-"],
          docs="https://documentation.mailgun.com/en/latest/api-intro.html#authentication",
          impact="Unauthorized email sending/receiving via Mailgun."),
])

write(f"{BASE}/misc/mailchimp.yaml", [
    skill("mailchimp-api-key", "Mailchimp API Key",
          "Detects Mailchimp API keys.",
          "misc", "high", ["mailchimp", "email", "marketing", "api-key"],
          regex=r"[0-9a-f]{32}-us[0-9]{1,2}",
          keywords=["-us"],
          docs="https://mailchimp.com/developer/marketing/docs/fundamentals/",
          impact="Unauthorized Mailchimp list/campaign management."),
])

write(f"{BASE}/misc/postman.yaml", [
    skill("postman-api-token", "Postman API Token",
          "Detects Postman API tokens.",
          "misc", "medium", ["postman", "api-testing", "api-token"],
          regex=r"PMAK-[0-9a-f]{24}-[0-9a-f]{34}",
          keywords=["pmak-"],
          docs="https://learning.postman.com/docs/developer/postman-api/authentication/",
          impact="Unauthorized Postman workspace access."),
])

write(f"{BASE}/misc/zapier.yaml", [
    skill("zapier-webhook", "Zapier Webhook URL",
          "Detects Zapier webhook URLs.",
          "misc", "medium", ["zapier", "webhook", "automation"],
          regex=r"https://hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+/",
          keywords=["hooks.zapier.com"],
          docs="https://zapier.com/help/create/code-webhooks",
          impact="Unauthorized Zapier automation trigger."),
])

write(f"{BASE}/misc/jira.yaml", [
    skill("jira-api-token", "Jira API Token",
          "Detects Atlassian Jira API tokens.",
          "misc", "high", ["jira", "atlassian", "api-token"],
          regex=r"(?i)jira[_\-\.]?(?:api[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{24})",
          keywords=["jira", "jira_api_token"],
          docs="https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/",
          impact="Unauthorized Jira project access."),
])

write(f"{BASE}/misc/zendesk.yaml", [
    skill("zendesk-secret-key", "Zendesk Secret Key",
          "Detects Zendesk API keys.",
          "misc", "high", ["zendesk", "support", "api-key"],
          regex=r"(?i)zendesk[_\-\.]?(?:api[_\-\.]?)?(?:key|token)['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{40})",
          keywords=["zendesk", "zendesk_api_key"],
          docs="https://developer.zendesk.com/api-reference/introduction/security-and-auth/",
          impact="Unauthorized Zendesk support ticket access."),
])

write(f"{BASE}/misc/intercom.yaml", [
    skill("intercom-api-key", "Intercom API Key",
          "Detects Intercom API keys.",
          "misc", "high", ["intercom", "support", "api-key"],
          regex=r"(?i)intercom[_\-\.]?(?:api[_\-\.]?)?(?:key|token)['"]*\s*[:=]\s*['"]?([A-Za-z0-9_]{40,})",
          keywords=["intercom", "intercom_api_key"],
          docs="https://developers.intercom.com/building-apps/docs/authentication-types",
          impact="Unauthorized Intercom customer data access."),
])

write(f"{BASE}/misc/freshdesk.yaml", [
    skill("freshdesk-access-token", "Freshdesk Access Token",
          "Detects Freshdesk API tokens.",
          "misc", "high", ["freshdesk", "support", "access-token"],
          regex=r"(?i)freshdesk[_\-\.]?(?:api[_\-\.]?)?(?:key|token)['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{20,})",
          keywords=["freshdesk"],
          docs="https://developer.freshdesk.com/api/",
          impact="Unauthorized Freshdesk support data access."),
])

write(f"{BASE}/misc/amplitude.yaml", [
    skill("amplitude-api-key", "Amplitude API Key",
          "Detects Amplitude analytics API keys.",
          "misc", "high", ["amplitude", "analytics", "api-key"],
          regex=r"(?i)amplitude[_\-\.]?(?:api[_\-\.]?)?key['"]*\s*[:=]\s*['"]?([a-f0-9]{32})",
          keywords=["amplitude", "amplitude_api_key"],
          docs="https://www.docs.developers.amplitude.com/analytics/apis/http-v2-api-quickstart/",
          impact="Unauthorized analytics event ingestion."),
])

# ── Analytics ─────────────────────────────────────────────────────────────────

write(f"{BASE}/analytics/mixpanel.yaml", [
    skill("mixpanel-api-key", "Mixpanel API Key",
          "Detects Mixpanel project tokens and API keys.",
          "analytics", "high", ["mixpanel", "analytics", "api-key"],
          regex=r"(?i)mixpanel[_\-\.]?(?:api[_\-\.]?)?(?:key|token)['"]*\s*[:=]\s*['"]?([a-f0-9]{32})",
          keywords=["mixpanel", "mixpanel_api_key"],
          docs="https://developer.mixpanel.com/reference/authentication",
          impact="Unauthorized analytics data access."),
])

write(f"{BASE}/analytics/segment.yaml", [
    skill("segment-write-key", "Segment Write Key",
          "Detects Segment analytics write keys.",
          "analytics", "high", ["segment", "analytics", "write-key"],
          regex=r"(?i)segment[_\-\.]?(?:write[_\-\.]?)?key['"]*\s*[:=]\s*['"]?([A-Za-z0-9]{40})",
          keywords=["segment", "segment_write_key"],
          docs="https://segment.com/docs/connections/find-writekey/",
          impact="Unauthorized analytics event injection."),
])

write(f"{BASE}/analytics/heap.yaml", [
    skill("heap-io-api-key", "Heap.io API Key",
          "Detects Heap.io analytics API keys.",
          "analytics", "high", ["heap", "analytics", "api-key"],
          regex=r"(?i)heap[_\-\.]?(?:api[_\-\.]?)?(?:key|token)['"]*\s*[:=]\s*['"]?([0-9]{10})",
          keywords=["heap", "heap_api_key"],
          docs="https://developers.heap.io/reference/api-overview",
          impact="Unauthorized Heap analytics data access."),
])

# ── Ecommerce ─────────────────────────────────────────────────────────────────

write(f"{BASE}/ecommerce/woocommerce.yaml", [
    skill("woocommerce-api-key", "WooCommerce API Key",
          "Detects WooCommerce REST API consumer keys.",
          "ecommerce", "high", ["woocommerce", "wordpress", "ecommerce", "api-key"],
          regex=r"ck_[a-f0-9]{40}",
          keywords=["ck_"],
          docs="https://woocommerce.github.io/woocommerce-rest-api-docs/",
          impact="Unauthorized WooCommerce store management."),
])

write(f"{BASE}/ecommerce/magento.yaml", [
    skill("magento-access-token", "Magento Access Token",
          "Detects Magento 2 REST API access tokens.",
          "ecommerce", "high", ["magento", "ecommerce", "access-token"],
          regex=r"(?i)magento[_\-\.]?(?:access[_\-\.]?)?token['"]*\s*[:=]\s*['"]?([a-z0-9]{32})",
          keywords=["magento", "magento_access_token"],
          docs="https://devdocs.magento.com/guides/v2.4/get-started/authentication/gs-authentication-token.html",
          impact="Unauthorized Magento store management."),
])

print("\nDone! All skill YAML files generated.")
