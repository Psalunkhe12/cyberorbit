import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
try:
    from dotenv import load_dotenv
    dotenv_path = BASE_DIR / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path)
except ImportError:
    pass



class Settings:
    # Project Paths
    BASE_DIR: Path = BASE_DIR
    SECURITY_DATA_DIR: Path = BASE_DIR / "security-data"
    EVE_JSON_PATH: Path = SECURITY_DATA_DIR / "suricata-output" / "eve.json"
    PCAP_DIR: Path = SECURITY_DATA_DIR / "pcaps"
    MODEL_DIR: Path = BASE_DIR / "backend" / "ml" / "models"

    # Supabase Credentials
    SUPABASE_URL: str = os.getenv("VITE_SUPABASE_URL", os.getenv("SUPABASE_URL", ""))
    SUPABASE_KEY: str = os.getenv("VITE_SUPABASE_ANON_KEY", os.getenv("SUPABASE_SERVICE_ROLE_KEY", os.getenv("SUPABASE_KEY", "")))

    # Gemini AI Settings
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

    # Risk Scoring Thresholds
    RISK_THRESHOLD_CRITICAL: int = 80
    RISK_THRESHOLD_HIGH: int = 60
    RISK_THRESHOLD_MEDIUM: int = 40

    # ML Settings
    ANOMALY_CONTAMINATION: float = 0.05
    MODEL_PATH: Path = MODEL_DIR / "isolation_forest.pkl"
    def __init__(self):
        pass

settings = Settings()

