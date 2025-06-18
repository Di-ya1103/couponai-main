import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Debug environment variables
print("Env DB_HOST:", os.getenv("DB_HOST"))
print("Env DB_PORT:", os.getenv("DB_PORT"))
print("Env DB_PASSWORD:", os.getenv("DB_PASSWORD"))
print("Env MISTRAL_API_KEY:", os.getenv("MISTRAL_API_KEY"))

class Config:
    MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY")
    DB_CONFIG = {
        "host": os.getenv("DB_HOST", "localhost"),
        "user": os.getenv("DB_USER", "root"),
        "password": os.getenv("DB_PASSWORD", "root"),
        "database": os.getenv("DB_NAME", "coupon"),
        "port": int(os.getenv("DB_PORT", "3306")),
        "charset": "utf8mb4"
    }