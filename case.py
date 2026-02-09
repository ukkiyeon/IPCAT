import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

def _safe_name(s: str, max_len: int = 80) -> str:
    s = (s or "").strip()
    s = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "_", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:max_len] if s else "UNKNOWN"

@dataclass
class CaseInfo:
    case_id: str
    case_name: str
    investigator: str = ""
    organization: str = ""
    contact: str = ""
    description: str = ""
    start_time_utc: str = ""
    case_root: str = ""

    @staticmethod
    def create_from_input(base_dir: str = "cases"):
        print("\n=== Case Information ===")
        case_id = input("Case ID: ").strip()
        case_name = input("Case Name: ").strip()
        investigator = input("Investigator Name: ").strip()
        organization = input("Organization: ").strip()
        contact = input("Contact Info: ").strip()
        description = input("Case Description: ").strip()

        case_id_s = _safe_name(case_id)
        case_name_s = _safe_name(case_name)

        folder_name = f"{case_id_s}_{case_name_s}"
        case_root = os.path.join(os.getcwd(), base_dir, folder_name)
        os.makedirs(case_root, exist_ok=True)  # ✅ Case folder

        start_time_utc = datetime.now(timezone.utc).isoformat()

        meta_path = os.path.join(case_root, "case_info.json")
        try:
            import json
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump({
                    "case_id": case_id,
                    "case_name": case_name,
                    "investigator": investigator,
                    "organization": organization,
                    "contact": contact,
                    "description": description,
                    "start_time_utc": start_time_utc,
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        return CaseInfo(
            case_id=case_id,
            case_name=case_name,
            investigator=investigator,
            organization=organization,
            contact=contact,
            description=description,
            start_time_utc=start_time_utc,
            case_root=case_root,
        )
