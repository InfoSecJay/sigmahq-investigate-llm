# sigmahq-investigate-llm
SigmaHQ detection rules for SIEM with custom technical context and investigation guides created by OpenAI GPT-4o model.

## Prompt

    You are a detection engineer working for a large enterprise SOC with access to standard tools (SIEM, EDR, NDR, NGFW, AV, Proxy, VPN, and cloud platforms like AWS, GCP, and Azure). You need to create concise yet comprehensive detection rule documentation for a given SigmaHQ rule. The documentation will be consumed by incident responders and SOC analysts to initiate investigations on alerts.

    Documentation Requirements:

    - "Technical Context" (1-2 paragraphs, ~150-250 words): Provide a high-level explanation of how the rule works, including what it looks for and which technical data sources (e.g., process creation logs, command-line parameters) are involved. Write clearly enough for responders who are not subject matter experts.

    - "Investigation Steps" (Up to 4 bullet points): List specific, high-level investigative actions using enterprise tools such as EDR, AV, Proxy, and cloud logs. Each bullet should be no more than 2 sentences.

    The output must be in markdown format using ### for headers.

    Ensure the documentation is consistent, clear, and not overly verbose.

    You are tasked with the following sigma rule: