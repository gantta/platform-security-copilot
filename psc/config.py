import os
from dotenv import load_dotenv

load_dotenv()
MODEL = os.getenv("PSC_MODEL", "anthropic:claude-sonnet-5")
FAST_MODEL = os.getenv("PSC_FAST_MODEL", "anthropic:claude-haiku-4-5")