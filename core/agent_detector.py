# core/agent_detector.py
# Antigravity Git-Vault - Real-time Agent Model Self-Identification Engine
import os
import glob
import sqlite3
import re
from typing import Dict, Any, Optional

def detect_active_agent_model(workspace_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Real-time self-identification of the active AI model powering the Antigravity agent.
    Probes Antigravity conversation metadata database, session variables, and environment.
    """
    convo_id = os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
    app_data = os.environ.get("ANTIGRAVITY_APP_DATA_DIR", os.path.expanduser("~/.gemini/antigravity"))
    
    # 1. Target active conversation DB
    target_db = None
    if convo_id and app_data:
        p = os.path.join(app_data, "conversations", f"{convo_id}.db")
        if os.path.exists(p):
            target_db = p

    # If no specific convo_id in env (e.g. running in background daemon), find latest modified DB
    if not target_db and app_data:
        conv_dir = os.path.join(app_data, "conversations")
        if os.path.exists(conv_dir):
            try:
                dbs = glob.glob(os.path.join(conv_dir, "*.db"))
                if dbs:
                    target_db = max(dbs, key=os.path.getmtime)
            except Exception:
                pass

    # 2. Extract model name from conversation protobuf metadata
    if target_db and os.path.exists(target_db):
        try:
            conn = sqlite3.connect(f"file:{target_db}?mode=ro", uri=True)
            try:
                cur = conn.cursor()
                cur.execute("SELECT data FROM gen_metadata ORDER BY rowid DESC LIMIT 1")
                row = cur.fetchone()
                if row and row[0]:
                    blob = row[0]
                    tail = blob[-250:]
                    # Match \xaa\x01<len><name>
                    m = re.search(rb"\xaa\x01.([A-Za-z0-9_. -]+(?:\([^)]+\))?)", tail)
                    if m:
                        raw_name = m.group(1).decode("utf-8", errors="ignore").strip()
                        # Clean e.g. "Gemini 3.8 Flash (High)" -> "Gemini-3.8-Flash"
                        clean = re.sub(r"\s*\([^)]*\)", "", raw_name).strip().replace(" ", "-")
                        return {
                            "success": True,
                            "raw_name": raw_name,
                            "model_slug": clean,
                            "signature": f"GV_AGY_{clean}",
                            "source": "antigravity_metadata_probe",
                            "db_file": os.path.basename(target_db)
                        }
            finally:
                conn.close()
        except Exception:
            pass

    # 3. Check environment variables
    env_model = os.environ.get("AGY_MODEL") or os.environ.get("ANTIGRAVITY_MODEL") or os.environ.get("MODEL_NAME")
    if env_model:
        clean = re.sub(r"\s*\([^)]*\)", "", env_model).strip().replace(" ", "-")
        return {
            "success": True,
            "raw_name": env_model.strip(),
            "model_slug": clean,
            "signature": f"GV_AGY_{clean}",
            "source": "environment_variable",
            "db_file": None
        }

    # 4. Fallback default
    return {
        "success": False,
        "raw_name": "Gemini 3.8 Flash",
        "model_slug": "Gemini-3.8-Flash",
        "signature": "GV_AGY_Gemini-3.8-Flash",
        "source": "fallback_default",
        "db_file": None
    }

def get_default_agent_signature() -> str:
    """Convenience helper to get current signature string directly."""
    return detect_active_agent_model()["signature"]
