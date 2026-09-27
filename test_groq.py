import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")
if not api_key:
    print("[ERROR] GROQ_API_KEY not found in environment or .env file.")
    exit(1)

client = Groq(api_key=api_key)

chat_completion = client.chat.completions.create(
    messages=[
        {
            "role": "user",
            "content": "Respond with a quick cybersecurity greeting and confirmation that the API is working.",
        }
    ],
    model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
)

print("[GROQ TEST SUCCESS]")
print(chat_completion.choices[0].message.content)