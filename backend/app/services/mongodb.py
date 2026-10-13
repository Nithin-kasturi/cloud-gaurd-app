
import os

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "cloudguard")

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is missing from the environment.")

client = MongoClient(
    MONGODB_URI,
    serverSelectionTimeoutMS=5000,
)

database = client[MONGODB_DATABASE]


def check_mongodb_connection() -> dict:
    """Verify connectivity without modifying database contents."""
    client.admin.command("ping")
    return {
        "connected": True,
        "database": MONGODB_DATABASE,
    }
