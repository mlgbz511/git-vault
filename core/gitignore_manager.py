# core/gitignore_manager.py
# Antigravity Git-Vault - Global .gitignore Architecture & Presets Manager
import os
import sys
import json
import re
import datetime
import subprocess
from typing import Dict, List, Any, Optional

VAULT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(VAULT_ROOT, "config")
DEFAULT_GLOBAL_GITIGNORE_PATH = os.path.join(CONFIG_DIR, ".gitignore_global")
CUSTOM_TEMPLATES_FILE = os.path.join(CONFIG_DIR, "gitignore_custom_templates.json")

# =========================================================================
# 预设模板库 (Git-Vault Official Presets)
# =========================================================================

PRESET_STRICT_SOURCE = """# =========================================================================
# Git-Vault 全局忽略规则 - 纯源码严格模式 (Pure Source Strict)
# 核心原则:
# 1. 彻底杜绝可执行二进制与动态链接库入库
# 2. 彻底杜绝无序高熵压缩包 (ZIP/TAR/7Z) 作为黑盒逃逸或撑爆 Git 存储
# 3. 严格隔离所有环境凭据、私钥及中间构建目录
# =========================================================================

# --- 1. 可执行程序与二进制镜像 (Executable & Binary Binaries) ---
*.exe
*.dll
*.so
*.dylib
*.bin
*.msi
*.iso
*.dmg
*.app
*.sys
*.drv
*.com
*.scr
*.cpl

# --- 2. 压缩包与二进制黑盒归档 (Archives & Compressed Bundles) ---
# 注意: 编译打包的发行包应发布在 GitHub/Gitee Releases 附件中，严禁放入 Git 版本树
*.zip
*.tar
*.gz
*.tar.gz
*.tgz
*.7z
*.rar
*.bz2
*.xz
*.apk
*.ipa
*.jar
*.war

# --- 3. 敏感密钥与环境凭据 (Secrets & Environment) ---
.env
.env.*
!.env.example
!.env.template
*.pem
*.key
*.pkcs12
*.pfx
*.p12
id_rsa
id_rsa*
id_ed25519
id_ed25519*
credentials.json
service-account*.json
token.txt
secret.txt

# --- 4. 常见开发语言构建产物与依赖 (Build Artifacts & Dependencies) ---
# Node / Frontend
node_modules/
dist/
build/
out/
.next/
.nuxt/
.vuepress/dist
.svelte-kit/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
pnpm-debug.log*

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
.venv/
ENV/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
.pytest_cache/
.mypy_cache/
.ruff_cache/

# Java / Kotlin
target/
bin/
*.class
.gradle/
build/

# C / C++ / C# / .NET
[Bb]in/
[Oo]bj/
[Dd]ebug/
[Rr]elease/
*.pdb
*.ilk
*.aps
*.ncb
*.suo
*.user
*.useroscc
*.sln.docstates
*.o
*.obj

# Go & Rust
/target/
vendor/

# --- 5. 操作系统与 IDE 杂质 (OS & Editor Garbage) ---
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db
desktop.ini

.idea/
*.swp
*.swo
*~
.project
.classpath
.settings/
"""

PRESET_GENERAL_DEV = """# =========================================================================
# Git-Vault 全局忽略规则 - 通用开发模式 (General Development)
# 核心原则:
# 过滤常见构建产物、IDE/系统垃圾与凭据，放行轻量文档与常规测试数据
# =========================================================================

# --- 1. 可执行二进制程序 (Executable Binaries) ---
*.exe
*.dll
*.so
*.dylib
*.bin
*.msi

# --- 2. 敏感凭据 (Secrets) ---
.env
.env.*
!.env.example
*.pem
*.key
credentials.json
id_rsa*

# --- 3. 构建产物与依赖 (Builds) ---
node_modules/
dist/
build/
__pycache__/
*.py[cod]
.venv/
venv/
target/
bin/
obj/

# --- 4. 操作系统与编辑器 (OS & Editors) ---
.DS_Store
Thumbs.db
desktop.ini
.idea/
*.swp
"""

PRESET_MINIMAL = """# =========================================================================
# Git-Vault 全局忽略规则 - 极简系统杂质过滤 (Minimal OS Garbage)
# =========================================================================
.DS_Store
Thumbs.db
desktop.ini
*.tmp
*~
"""

PRESETS: Dict[str, Dict[str, Any]] = {
    "strict": {
        "id": "strict",
        "name": "纯源码严格模式 (推荐工程基线)",
        "badge": "[推荐 严格工程]",
        "description": "一网打尽: 彻底拦截可执行二进制 (*.exe, *.dll) 与压缩包 (*.zip, *.tar.gz)，杜绝黑盒逃逸与 Git 仓库膨胀，拦截所有凭据与编译目录。",
        "immutable": True,
        "content": PRESET_STRICT_SOURCE
    },
    "general": {
        "id": "general",
        "name": "通用开发模式",
        "badge": "[标准开发]",
        "description": "拦截常见构建目录、IDE/系统文件与 *.exe/*.dll，保留对常规归档压缩包的放行支持。",
        "immutable": True,
        "content": PRESET_GENERAL_DEV
    },
    "minimal": {
        "id": "minimal",
        "name": "极简杂质清理模式",
        "badge": "[轻量]",
        "description": "仅拦截 .DS_Store, Thumbs.db 等系统垃圾文件，不干涉项目内部构建产物。",
        "immutable": True,
        "content": PRESET_MINIMAL
    }
}

# =========================================================================
# 自定义模板管理 (Custom Templates Persistence)
# =========================================================================

def load_custom_templates() -> Dict[str, Dict[str, Any]]:
    """读取所有用户自定义的 Git 忽略规则模板"""
    if not os.path.exists(CUSTOM_TEMPLATES_FILE):
        return {}
    try:
        with open(CUSTOM_TEMPLATES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}

def save_custom_template(
    template_id: str,
    name: str,
    content: str,
    description: str = ""
) -> Dict[str, Any]:
    """保存或更新用户自定义模板（禁止覆盖官方内置预设）"""
    t_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", template_id.strip()).lower()
    if not t_id:
        return {"success": False, "error": "模板标识符 (ID) 不能为空"}
    if t_id in PRESETS:
        return {"success": False, "error": f"模板 ID '{t_id}' 与官方只读预设冲突，禁止覆盖"}
    if not name or not name.strip():
        name = t_id
    if not content or not content.strip():
        return {"success": False, "error": "模板规则内容不能为空"}

    templates = load_custom_templates()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    existing = templates.get(t_id, {})
    
    templates[t_id] = {
        "id": t_id,
        "name": name.strip(),
        "badge": "[自定义模板]",
        "description": description.strip() or "用户自定义全局规则模板",
        "immutable": False,
        "content": content.strip() + "\n",
        "created_at": existing.get("created_at", now_str),
        "updated_at": now_str
    }

    try:
        os.makedirs(os.path.dirname(CUSTOM_TEMPLATES_FILE), exist_ok=True)
        with open(CUSTOM_TEMPLATES_FILE, "w", encoding="utf-8") as f:
            json.dump(templates, f, indent=2, ensure_ascii=False)
        return {"success": True, "template": templates[t_id]}
    except Exception as e:
        return {"success": False, "error": f"保存自定义模板文件失败: {str(e)}"}

def delete_custom_template(template_id: str) -> Dict[str, Any]:
    """删除指定的自定义模板（官方预设受保护不可删）"""
    t_id = template_id.strip().lower()
    if t_id in PRESETS:
        return {"success": False, "error": f"'{t_id}' 为官方只读内置预设，禁止删除"}
    templates = load_custom_templates()
    if t_id not in templates:
        return {"success": False, "error": f"未找到自定义模板: {t_id}"}
    
    del templates[t_id]
    try:
        with open(CUSTOM_TEMPLATES_FILE, "w", encoding="utf-8") as f:
            json.dump(templates, f, indent=2, ensure_ascii=False)
        return {"success": True, "id": t_id}
    except Exception as e:
        return {"success": False, "error": f"删除自定义模板失败: {str(e)}"}

def get_presets_meta() -> List[Dict[str, Any]]:
    """获取所有官方预设元数据列表（只读）"""
    res = []
    for k, v in PRESETS.items():
        res.append({
            "id": v["id"],
            "name": v["name"],
            "badge": v["badge"],
            "description": v["description"],
            "immutable": True
        })
    return res

def get_custom_templates_meta() -> List[Dict[str, Any]]:
    """获取所有自定义模板元数据列表"""
    templates = load_custom_templates()
    res = []
    for k, v in templates.items():
        res.append({
            "id": v["id"],
            "name": v["name"],
            "badge": v.get("badge", "[自定义模板]"),
            "description": v.get("description", ""),
            "immutable": False,
            "created_at": v.get("created_at", ""),
            "updated_at": v.get("updated_at", "")
        })
    return res

def get_current_global_excludesfile() -> str:
    """获取当前 Git 全局配置中的 core.excludesfile 路径"""
    try:
        proc = subprocess.run(
            ["git", "config", "--global", "--get", "core.excludesfile"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return ""

def get_global_gitignore_status() -> Dict[str, Any]:
    """查询全局 .gitignore 完整治理状态（支持官方预设与自定义模板探测）"""
    configured_path = get_current_global_excludesfile()
    is_active = bool(configured_path and os.path.exists(configured_path))
    content = ""
    matched_preset = "custom"
    is_immutable = False

    if configured_path and os.path.exists(configured_path):
        try:
            with open(configured_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            content = f"# 读取失败: {e}"

    norm_content = content.strip().replace("\r\n", "\n")
    
    # 1. 优先比对官方预设
    for pid, pdata in PRESETS.items():
        if norm_content == pdata["content"].strip().replace("\r\n", "\n"):
            matched_preset = pid
            is_immutable = True
            break

    # 2. 次选比对用户自定义模板
    if matched_preset == "custom":
        custom_templates = load_custom_templates()
        for cid, cdata in custom_templates.items():
            if norm_content == cdata.get("content", "").strip().replace("\r\n", "\n"):
                matched_preset = cid
                is_immutable = False
                break

    return {
        "is_configured": bool(configured_path),
        "is_active": is_active,
        "configured_path": configured_path,
        "default_recommended_path": DEFAULT_GLOBAL_GITIGNORE_PATH,
        "current_preset": matched_preset,
        "is_immutable": is_immutable,
        "content": content,
        "presets": get_presets_meta(),
        "custom_templates": get_custom_templates_meta()
    }

def apply_global_gitignore(preset_id: str, custom_content: Optional[str] = None, target_path: Optional[str] = None) -> Dict[str, Any]:
    """应用指定官方预设、自定义模板或自由规则为全局 .gitignore"""
    custom_templates = load_custom_templates()

    if preset_id in PRESETS:
        content_to_write = PRESETS[preset_id]["content"]
    elif preset_id in custom_templates:
        content_to_write = custom_templates[preset_id]["content"]
    elif preset_id == "custom":
        if not custom_content or not custom_content.strip():
            return {"success": False, "error": "自定义规则内容不能为空"}
        content_to_write = custom_content.strip() + "\n"
    else:
        return {"success": False, "error": f"未知的预设或模板选项: {preset_id}"}

    file_path = target_path or DEFAULT_GLOBAL_GITIGNORE_PATH
    norm_path = os.path.abspath(file_path).replace("\\", "/")

    try:
        os.makedirs(os.path.dirname(norm_path), exist_ok=True)
        with open(norm_path, "w", encoding="utf-8") as f:
            f.write(content_to_write)
    except Exception as e:
        return {"success": False, "error": f"写入全局 .gitignore 文件失败: {str(e)}"}

    # 配置到 Git 全局 core.excludesfile
    try:
        proc = subprocess.run(
            ["git", "config", "--global", "core.excludesfile", norm_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        if proc.returncode != 0:
            return {"success": False, "error": f"git config 写入失败: {proc.stderr.strip()}"}
    except Exception as e:
        return {"success": False, "error": f"执行 git config 命令异常: {str(e)}"}

    return {
        "success": True,
        "preset_id": preset_id,
        "configured_path": norm_path,
        "message": f"[OK] 已成功将规则 '{preset_id}' 应用为 Git 全局忽略规则 (core.excludesfile -> {norm_path})"
    }

def clear_global_gitignore() -> Dict[str, Any]:
    """清空 Git 全局 core.excludesfile 配置"""
    try:
        proc = subprocess.run(
            ["git", "config", "--global", "--unset", "core.excludesfile"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        return {
            "success": True,
            "message": "[OK] 已清除 Git 全局 core.excludesfile 配置。"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
