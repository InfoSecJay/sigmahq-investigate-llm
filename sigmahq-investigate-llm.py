import os
import re
import asyncio
from io import StringIO
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString
import openai
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

# Retrieve API key from environment variable "OPEN_API_KEY"
api_key = os.getenv("OPEN_API_KEY")
if not api_key:
    raise EnvironmentError("OPEN_API_KEY environment variable not set.")
openai.api_key = api_key

# Initialize YAML handler
yaml = YAML()
yaml.preserve_quotes = True  # Preserve formatting in YAML

# Define the ChatGPT prompt with explicit instructions for bullet formatting
CHATGPT_PROMPT = """
You are a detection engineer working for a large enterprise security operation center. You have access to all standard tools (SIEM, EDR, NDR, NGFW, AV, Proxy, VPN, etc.). You are tasked with writing detection rule documentation for a specific threat detection rule and you must write short but detailed documentation for your rule with the following 2 outputs, that would be consumed by incident responders and SOC analysts:

- "Technical Context" (1-2 paragraphs, ~200-500 words): Provide a high-level explanation of how the rule works, including what it looks for and which technical data sources (e.g., process creation logs, command-line parameters) are involved. Write clearly enough for responders who are not subject matter experts. Ensure there is a reference to the MITRE ATT&CK tactic and technique specified in the tag section.
- "Investigation Steps" (Up to 4 bullet points in markdown list format with a bolded title followed by a colon and the step instruction): List specific, high-level investigative actions using enterprise tools such as EDR, AV, Proxy, and cloud logs. Each bullet should be no more than 2 sentences.
- Prioritization (1 or 2 sentences): Provide a generalized reasoning for the severity level given in the alert for an enterprise environment when the alert is fired. 
- Blind spots and Assumptions: Provide the recognized issues, assumptions, and areas where an rule may not fire. Attempt to identify how other engineers can understand how an rule may fail to fire or be defeated by an adversary.
- In markdown quote text (>) **Disclaimer**: This investigation guide was created using generative AI technology and has not been reviewed for its accuracy and relevance. While every effort has been made to ensure its quality, we recommend validating the content and adapting it to suit specific environment and operational needs. Please communicate any changes to the detection engineering team.

You must strictly follow this format between the with NO DEVIATIONS including no extra new lines or spaces, ending with the disclaimer:

[BEGIN FORMAT]
### Technical Context
<Technical Context Text>

### Investigation Steps
1. **<Step one>**: <Step Text>
2. **<Step two>**: <Step Text>
3. **<Step three>**: <Step Text>
4. **<Step four>**: <Step Text>

### Prioritization
<Prioritization Text>

### Blind Spots and Assumptions
<Blind Spots and Assumptions Text>

> **Disclaimer**: This investigation guide was created using generative AI technology and has not been reviewed for its accuracy and relevance. While every effort has been made to ensure its quality, we recommend validating the content and adapting it to suit specific environment and operational needs. Please communicate any changes to the detection engineering team.
[END FORMAT]

If the rule has the following categories, assume the telemetry monitoring will be Windows Sysmon; create_remote_thread, create_stream_hash, dns_query, driver_load, file_*, image_load, network_connection, pipe_created, powershell, process_access, process_creation, process_tampering, raw_access_thread, registry, sysmon, and wmi_event

If the rule has service security, system or application, assume the telemtry monitoring will be Windows Security, System or Application respectively. 

Ensure the documentation is consistent, clear, and not overly verbose.

Ensure you do not include [BEGIN FORMAT] and [END FORMAT] in the final output, they are just for your information on the strict guideline to follow.

You are tasked with the following threat technique, sigma rule, and/or query:
"""

# Limit the number of concurrent API requests (adjust as needed)
semaphore = asyncio.Semaphore(10)

async def get_chatgpt_response(rule_content: str) -> str:
    """Asynchronously sends the rule content to ChatGPT and returns the response."""
    async with semaphore:
        try:
            response = await openai.ChatCompletion.acreate(
                model="gpt-4o-mini",
                messages=[
                    {"role": "user", "content": f"{CHATGPT_PROMPT}\n\n{rule_content}"}
                ]
            )
            return response["choices"][0]["message"]["content"]
        except Exception as e:
            print("Error during OpenAI API call:", e)
            return ""

def yaml_to_string(yaml_obj):
    """Converts YAML object to a string using ruamel.yaml."""
    stream = StringIO()
    yaml.dump(yaml_obj, stream)
    return stream.getvalue()

def clean_chatgpt_response(response: str) -> str:
    """Removes unwanted Markdown formatting from ChatGPT responses."""
    if response.startswith("```markdown"):
        response = response[10:]  # Remove "```markdown\n"
    if response.endswith("```"):
        response = response[:-3]  # Remove trailing "```"
    return response.strip()

def normalize_newlines(response: str) -> str:
    """Normalizes newlines to ensure consistent formatting for bullet points."""
    response = re.sub(r'\n+', '\n', response)
    response = re.sub(r'(?<!\n)(-\s)', r'\n\1', response)
    return response.strip()

async def process_yaml_file(file_path: str):
    """Reads a YAML file, sends its content to ChatGPT asynchronously,
    and appends the response as a 'notes' field."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            yaml_content = yaml.load(file)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return

    rule_text = yaml_to_string(yaml_content)
    chatgpt_response = await get_chatgpt_response(rule_text)
    if not chatgpt_response:
        print(f"Skipping {file_path} due to API error.")
        return

    cleaned_response = clean_chatgpt_response(chatgpt_response)
    normalized_response = normalize_newlines(cleaned_response)
    yaml_content["notes"] = LiteralScalarString(normalized_response + "\n")

    try:
        with open(file_path, "w", encoding="utf-8") as file:
            yaml.dump(yaml_content, file)
    except Exception as e:
        print(f"Error writing {file_path}: {e}")

async def process_directory(directory: str):
    """Recursively finds and processes all YAML files in the given directory concurrently."""
    tasks = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".yml") or file.endswith(".yaml"):
                file_path = os.path.join(root, file)
                print(f"Processing: {file_path}")
                tasks.append(asyncio.create_task(process_yaml_file(file_path)))
    if tasks:
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(process_directory("sigma/rules"))
