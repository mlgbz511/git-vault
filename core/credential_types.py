# core/credential_types.py
# Antigravity Git-Vault - 凭据类型单一事实源 (key type registry)
"""密钥/凭据类型单一事实源。

设计约束（已冻结，勿改）：
- 纯标准库，零外部依赖；任何下游模块（credential_vault / compliance_guard /
  git_credential_helper / sops_bridge）必须从这里取类型、前缀正则与能力位，禁止各自硬编码。
- 两大类存储域：
  client   客户端域，凭据在本地机器上、可用于 git push；
  platform 平台域（Actions/Dependabot/Codespaces secrets、GITHUB_TOKEN、OIDC id_token），
           平台侧注入不可本地读取、不能用于 push，归 ci_secret，不进本地凭据库。
- 前缀正则来自官方文档事实；官方未公开的前缀写 None，并在 rotation_hint 说明。
- prefix_regex 无 ^/$ 锚点，但带 lookaround 边界，例如
  (?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9_])：
  scanner 可把它直接塞进 SECRET_PATTERNS 用 re.finditer 扫文本而不误伤粘连串；
  re.search 与 re.fullmatch 同样可用（位置 0 的后顾恒成立）。
- parse_key_type()：严格解析，未知/非法返回 None，供 HTTP/API 入参校验；
  normalize_key_type()：落库兜底，未知归 generic_secret。
- 本文件不含任何真实密钥样值，测试一律使用假值。
"""
import re

# ---------------------------------------------------------------------------
# 平台名归一表：输入任意大小写/别名，输出 vault 既有的 platform 命名
# ---------------------------------------------------------------------------
PLATFORM_ALIASES = {
    "github": "github",
    "gh": "github",
    "github.com": "github",
    "git_hub": "github",
    "gh_hub": "github",
    "gitee": "gitee",
    "gt": "gitee",
    "gitee.com": "gitee",
    "oschina": "gitee",
    "gitlab": "gitlab",
    "gl": "gitlab",
    "gitlab.com": "gitlab",
    "git_lab": "gitlab",
}

_KEY_TYPE_ALIASES = {
    # 经典 PAT
    "pat": "pat_classic",
    "classic": "pat_classic",
    "classic_pat": "pat_classic",
    "personal_access_token": "pat_classic",
    # 细粒度 PAT
    "fine": "pat_fine",
    "fine_grained": "pat_fine",
    "fine_grained_pat": "pat_fine",
    "github_pat": "pat_fine",
    # SSH 用户密钥
    "ssh": "ssh_user_key",
    "ssh_key": "ssh_user_key",
    "ssh_user": "ssh_user_key",
    # 部署密钥
    "deploy": "deploy_key",
    "deploy_key_ssh": "deploy_key",
    # GitHub App 私钥
    "app": "app_private_key",
    "app_key": "app_private_key",
    "app_pem": "app_private_key",
    "github_app": "app_private_key",
    # App 安装令牌 (ghs_)
    "installation": "app_installation_token",
    "installation_token": "app_installation_token",
    "ghs": "app_installation_token",
    # OAuth 用户令牌 (gho_)
    "oauth": "oauth_user_token",
    "oauth_token": "oauth_user_token",
    "gho": "oauth_user_token",
    # gh CLI 令牌
    "gh_cli": "gh_cli_token",
    "ghcli": "gh_cli_token",
    "github_cli": "gh_cli_token",
    # 平台注入的 CI 机密
    "ci": "ci_secret",
    "actions_secret": "ci_secret",
    "dependabot_secret": "ci_secret",
    "codespaces_secret": "ci_secret",
    "github_token": "ci_secret",
    "oidc": "ci_secret",
    "id_token": "ci_secret",
    # GitLab PAT (glpat-)
    "gitlab_pat": "pat_gitlab",
    "glpat": "pat_gitlab",
    # App 用户令牌 (ghu_)
    "app_user": "app_user_token",
    "ghu": "app_user_token",
    # OAuth 刷新令牌 (ghr_)
    "refresh": "oauth_refresh_token",
    "refresh_token": "oauth_refresh_token",
    "ghr": "oauth_refresh_token",
    # 兜底
    "generic": "generic_secret",
    "other": "generic_secret",
    "secret": "generic_secret",
    "api_key": "generic_secret",
}

# ---------------------------------------------------------------------------
# 13 类密钥事实表。prefix_regex 带 lookaround 边界（None = 官方未公开固定前缀）。
# default_scope 是模板：owner/repos/permissions/environment 四键，
# 取用方必须深拷贝后填写，不要直接改本表对象（用 default_scope()）。
# ---------------------------------------------------------------------------
KEY_TYPES = {
    "pat_classic": {
        "id": "pat_classic",
        "label_zh": "经典个人访问令牌",
        "label_en": "Classic personal access token",
        "prefix_regex": r"(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9_])",
        "can_push": True,
        "storage_domain": "client",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {},
            "environment": None,
        },
        "docs_url": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
        "rotation_hint": "GitHub 设置 → Developer settings → Personal access tokens (classic) 撤销重建；GitLab PAT 见 pat_gitlab，Gitee 私人令牌前缀官方未公开，按帮助中心说明核对。",
        "expires_hint": "可选过期时间，可为永不过期；官方建议设置较短有效期（约 90 天内）并定期轮换。",
    },
    "pat_fine": {
        "id": "pat_fine",
        "label_zh": "细粒度个人访问令牌",
        "label_en": "Fine-grained personal access token",
        "prefix_regex": r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{82}(?![A-Za-z0-9_])",
        "can_push": True,
        "storage_domain": "client",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {"contents": "write"},
            "environment": None,
        },
        "docs_url": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token",
        "rotation_hint": "GitHub 设置 → Developer settings → Fine-grained tokens 撤销重建；按仓库粒度最小授权，权限与仓库清单变更后需重建。",
        "expires_hint": "必须设置过期时间，官方上限 1 年；按最小期限轮换。",
    },
    "pat_gitlab": {
        "id": "pat_gitlab",
        "label_zh": "GitLab 个人访问令牌",
        "label_en": "GitLab personal access token",
        "prefix_regex": r"(?<![A-Za-z0-9_])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",
        "can_push": True,
        "storage_domain": "client",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {"write_repository": "write"},
            "environment": None,
        },
        "docs_url": "https://docs.gitlab.com/user/profile/personal_access_tokens/",
        "rotation_hint": "GitLab 用户设置 → Access tokens 撤销重建；glpat- 后长度不固定（≥20），已按字符集 [A-Za-z0-9_-] 放宽匹配。",
        "expires_hint": "必须设置过期日期，最多 1 年（GitLab 强制）；到期自动失效，需提前轮换。",
    },
    "ssh_user_key": {
        "id": "ssh_user_key",
        "label_zh": "SSH 用户密钥",
        "label_en": "SSH user key",
        "prefix_regex": None,
        "can_push": True,
        "storage_domain": "client",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {"git": "write"},
            "environment": None,
        },
        "docs_url": "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account",
        "rotation_hint": "库内只存索引（私钥文件路径 + 公钥指纹 + 平台绑定），私钥文件不进库不复制；轮换在平台 SSH keys 页面删旧加新。无固定文本前缀，按 PEM/OPENSSH 私钥形态识别。",
        "expires_hint": "无平台侧过期；按组织策略人工轮换。",
    },
    "deploy_key": {
        "id": "deploy_key",
        "label_zh": "部署密钥",
        "label_en": "Deploy key",
        "prefix_regex": None,
        "can_push": True,
        "storage_domain": "client",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {"contents": "write"},
            "environment": None,
        },
        "docs_url": "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys",
        "rotation_hint": "仓库 Settings → Deploy keys 撤销重建；每仓一把、默认只读，需要写权限时显式开启。库内同样只存索引不存私钥文件。",
        "expires_hint": "无平台侧过期；随仓库/CI 生命周期轮换或撤销。",
    },
    "app_private_key": {
        "id": "app_private_key",
        "label_zh": "GitHub App 私钥",
        "label_en": "GitHub App private key",
        "prefix_regex": None,
        "can_push": True,
        "storage_domain": "client",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {"app": "metadata"},
            "environment": None,
        },
        "docs_url": "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps",
        "rotation_hint": "App 设置 → Private keys 生成新钥、删除旧钥；私钥只用于换 installation token，不进 argv/env。无固定文本前缀，按 PEM 私钥形态识别。",
        "expires_hint": "私钥本身不过期，泄漏或定期轮换时在 App 设置重签。",
    },
    "app_installation_token": {
        "id": "app_installation_token",
        "label_zh": "App 安装访问令牌",
        "label_en": "App installation access token",
        "prefix_regex": r"(?<![A-Za-z0-9_])ghs_[A-Za-z0-9]{36}(?![A-Za-z0-9_])",
        "can_push": True,
        "storage_domain": "client",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {"contents": "write"},
            "environment": None,
        },
        "docs_url": "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app",
        "rotation_hint": "由 App 私钥即时换发，不人工轮换；入库时必须记录 expires_at，过期前重新兑换。",
        "expires_hint": "1 小时固定有效期。",
    },
    "app_user_token": {
        "id": "app_user_token",
        "label_zh": "App 用户访问令牌",
        "label_en": "App user access token",
        "prefix_regex": r"(?<![A-Za-z0-9_])ghu_[A-Za-z0-9]{36}(?![A-Za-z0-9_])",
        "can_push": True,
        "storage_domain": "client",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {"contents": "write"},
            "environment": None,
        },
        "docs_url": "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app",
        "rotation_hint": "由 App 的 OAuth 流程即时签发，不人工轮换；独立于 gho_（OAuth App 令牌），不可互相替代。",
        "expires_hint": "8 小时有效期，可用刷新令牌续期。",
    },
    "oauth_user_token": {
        "id": "oauth_user_token",
        "label_zh": "OAuth 用户令牌",
        "label_en": "OAuth user token",
        "prefix_regex": r"(?<![A-Za-z0-9_])gho_[A-Za-z0-9]{36}(?![A-Za-z0-9_])",
        "can_push": True,
        "storage_domain": "client",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {},
            "environment": None,
        },
        "docs_url": "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps",
        "rotation_hint": "OAuth App 授权页撤销授权后重新走授权码流程；刷新令牌单独见 oauth_refresh_token（ghr_），刷新时原子替换。",
        "expires_hint": "长期有效直到撤销或过期；支持刷新令牌的 App 按其有效期轮换。",
    },
    "oauth_refresh_token": {
        "id": "oauth_refresh_token",
        "label_zh": "OAuth 刷新令牌",
        "label_en": "OAuth refresh token",
        "prefix_regex": r"(?<![A-Za-z0-9_])ghr_[A-Za-z0-9]{36}(?![A-Za-z0-9_])",
        "can_push": False,
        "storage_domain": "client",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {"refresh_token": "write"},
            "environment": None,
        },
        "docs_url": "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens",
        "rotation_hint": "刷新令牌一次性使用，换新后必须原子替换入库值；泄漏后到 App 授权页撤销重授权。ghr_ 本身不能直接调 API。",
        "expires_hint": "有独立有效期（通常 6 个月），随刷新轮换。",
    },
    "gh_cli_token": {
        "id": "gh_cli_token",
        "label_zh": "GitHub CLI 令牌",
        "label_en": "GitHub CLI token",
        "prefix_regex": None,
        "can_push": True,
        "storage_domain": "client",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {},
            "environment": None,
        },
        "docs_url": "https://cli.github.com/manual/gh_auth_token",
        "rotation_hint": "gh auth login 重新认证或 gh auth token 覆盖；实际值通常是 gho_ 前缀的 OAuth 令牌（见 oauth_user_token），官方未给 CLI 专属前缀，故本类不设正则。",
        "expires_hint": "跟随底层 OAuth 令牌，无独立过期。",
    },
    "ci_secret": {
        "id": "ci_secret",
        "label_zh": "平台 CI 机密",
        "label_en": "Platform CI secret",
        "prefix_regex": None,
        "can_push": False,
        "storage_domain": "platform",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {},
            "environment": None,
        },
        "docs_url": "https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions",
        "rotation_hint": "Actions/Dependabot/Codespaces secrets 在平台侧 Settings 轮换，本地不可读；GITHUB_TOKEN 与 OIDC id_token 为运行期即时签发，不轮换、不入库。",
        "expires_hint": "随工作流运行期有效；仓库/组织级 secret 长期有效直到平台侧更新。",
    },
    "generic_secret": {
        "id": "generic_secret",
        "label_zh": "通用密钥",
        "label_en": "Generic secret",
        "prefix_regex": None,
        "can_push": False,
        "storage_domain": "client",
        "default_scope": {
            "owner": None,
            "repos": [],
            "permissions": {},
            "environment": None,
        },
        "docs_url": "https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api",
        "rotation_hint": "未公开固定前缀、无法按形态识别；按来源服务文档轮换，并按服务名+环境变量名建立索引。",
        "expires_hint": "未知，由来源服务决定。",
    },
}

VALID_STORAGE_DOMAINS = ("client", "platform")


def _resolve_key_type(raw):
    """返回 KEY_TYPES 的 id；未知/非法输入返回 None（调用方自行决定失败策略）。"""
    if not isinstance(raw, str):
        return None
    key = raw.strip().lower().replace("-", "_").replace(" ", "_")
    if not key:
        return None
    if key in KEY_TYPES:
        return key
    return _KEY_TYPE_ALIASES.get(key)


def parse_key_type(raw):
    """严格解析：把输入归一为 KEY_TYPES 的 id；未知/非法输入返回 None。

    分工：HTTP/API 入参校验用 parse_key_type（非法值直接拒绝，不兜底）；
    落库与旧数据兼容用 normalize_key_type（未知归 generic_secret）。
    """
    return _resolve_key_type(raw)


def normalize_key_type(raw):
    """把任意输入归一为 KEY_TYPES 中已知的 id；无法识别时兜底 generic_secret。"""
    return _resolve_key_type(raw) or "generic_secret"


def is_push_capable(key_type):
    """该类型能否用于 git push；未知类型一律 False（失败即关闭）。"""
    resolved = _resolve_key_type(key_type)
    return bool(resolved and KEY_TYPES[resolved]["can_push"])


def platform_storable(key_type):
    """该类型是否允许写入本地凭据库；平台域(ci_secret)与未知类型一律 False。"""
    resolved = _resolve_key_type(key_type)
    return resolved is not None and KEY_TYPES[resolved]["storage_domain"] == "client"


def default_scope(key_type):
    """返回该类型作用域模板的深拷贝，供调用方填写 owner/repos/permissions/environment。"""
    template = KEY_TYPES[normalize_key_type(key_type)]["default_scope"]
    return {
        "owner": template["owner"],
        "repos": list(template["repos"]),
        "permissions": dict(template["permissions"]),
        "environment": template["environment"],
    }


def prefix_patterns():
    """返回 {id: 已编译正则}，只含确有固定前缀的类型；供扫描器直接复用。"""
    return {
        key: re.compile(entry["prefix_regex"])
        for key, entry in KEY_TYPES.items()
        if entry["prefix_regex"]
    }


def registered_platforms():
    """返回去重排序后的平台 canonical 名（PLATFORM_ALIASES 的值集合）。

    下游遍历平台时用它，禁止再硬编码 ["github","gitee","gitlab"]。
    """
    return tuple(sorted(set(PLATFORM_ALIASES.values())))


if __name__ == "__main__":
    # 自检：类型数量、字段完整性、正则可编译、无重复 id
    required = (
        "id", "label_zh", "label_en", "prefix_regex", "can_push",
        "storage_domain", "default_scope", "docs_url", "rotation_hint", "expires_hint",
    )
    assert len(KEY_TYPES) == 13, len(KEY_TYPES)
    for key, entry in KEY_TYPES.items():
        assert entry["id"] == key, key
        assert all(field in entry for field in required), key
        assert entry["storage_domain"] in VALID_STORAGE_DOMAINS, key
        assert set(entry["default_scope"]) == {"owner", "repos", "permissions", "environment"}, key
        if entry["prefix_regex"]:
            re.compile(entry["prefix_regex"])
    print("KEY_TYPES:", len(KEY_TYPES), sorted(KEY_TYPES))
