import os
from dnvote import load_dotenv

load_dotenv()

print("API KEY =", os.getenv("GROQ_API_KEY"))
