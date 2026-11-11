# AI-Assisted Security Alert Triage

**Wazuh → n8n → AI Agent → Slack**

A cybersecurity lab project that automates the intake, filtering, AI-assisted analysis, and Slack notification of selected Wazuh security alerts.

> **Project status:** Demonstrated in a lab using a Windows endpoint, Wazuh, n8n, OpenRouter, an AI Agent, and Slack. This README describes the implementation documented in the accompanying 44-page project report. It does not claim production readiness.

## Overview

The project connects Wazuh alert monitoring to an n8n workflow. Wazuh sends alert data to an n8n webhook over HTTP `POST`. The workflow extracts selected alert fields, applies a rule-level filter, sends qualifying alerts to an AI Agent for concise SOC-style triage, and forwards the generated summary to a Slack channel.

The AI prompt is designed to distinguish observed evidence from analysis, avoid inventing missing details, preserve the observed command line, and avoid unsupported containment recommendations.

## Architecture

```text
Windows endpoint
      |
      | Windows security events
      v
    Wazuh
      |
      | Custom integration sends alert JSON via HTTP POST
      v
 n8n Webhook
      |
      v
 Extract Alert Context
      |
      v
   IF filter
      |
      | qualifying alerts
      v
    AI Agent <---- OpenRouter chat model
      |
      v
  Slack message
```

### Main components

| Component | Role in this project |
|---|---|
| **Wazuh** | Monitors endpoint security events, generates alerts, and forwards selected alerts. |
| **Windows 10 endpoint** | Generates the PowerShell process-creation test event. |
| **Kali Linux** | Used to connect to the Wazuh server over SSH and configure the custom integration. |
| **n8n** | Orchestrates the webhook, field extraction, filtering, AI analysis, and Slack delivery. |
| **OpenRouter** | Provides the model API connection used by the n8n AI Agent. |
| **AI Agent** | Produces a concise SOC-style alert using the supplied evidence. |
| **Slack** | Receives the generated alert in a dedicated channel. |

The report identifies `deepseek/deepseek-v4-flash` as the model used through OpenRouter.

## Workflow

1. **Receive the alert:** An n8n Webhook node accepts JSON data using HTTP `POST`.
2. **Test the webhook:** A sample JSON alert is sent with `curl` to the n8n test URL.
3. **Extract alert context:** An Edit Fields (Set) node, renamed `Extract Alert Context`, selects fields used downstream.
4. **Filter alerts:** An IF node checks the Wazuh `rule_level` before an alert is sent to the AI Agent.
5. **Analyze the alert:** The AI Agent uses an OpenRouter chat model and a SOC analyst prompt.
6. **Send to Slack:** A Slack node sends the AI Agent's `output` to the configured channel.
7. **Connect Wazuh:** A custom Wazuh integration reads the alert JSON and sends it to the n8n production webhook.
8. **Validate end to end:** A PowerShell test generates an encoded-command process event; the resulting alert is checked in Wazuh, processed by n8n, and delivered to Slack.

## Alert context fields

The report documents extracting the following fields before AI analysis:

- `rule_id`
- `rule_level`
- `description`
- `event_id`
- `Provider`
- `User`
- `Process`
- `Command Line`
- `Target File`
- `Process ID`
- `Parent Process ID`
- `Raw Message`

The AI prompt also references hostname and MITRE ATT&CK information when those fields are present in the incoming data. Field names and JSON paths must match the actual Wazuh payload and the n8n node output.

## AI triage behavior

The prompt instructs the AI Agent to:

- Use only facts explicitly present in the supplied alert fields.
- Avoid inventing event IDs, MITRE ATT&CK techniques, users, processes, files, commands, or attacker behavior.
- Treat missing fields as missing rather than infer their values.
- Separate observed evidence from analysis.
- Describe only what the event demonstrates (for example, file creation versus process execution).
- Preserve the observed command line exactly when available.
- Decode encoded or transformed content only when it can be interpreted reliably.
- Avoid recommending containment unless the evidence justifies it.
- Keep the Slack message concise and use Slack-compatible formatting.

The documented Slack alert format includes:

- Host, user, process, and Wazuh severity level
- What happened
- Observed command
- Decoded / interpreted content
- Why it matters
- MITRE ATT&CK
- Recommended action

The AI is instructed not to calculate or reassign severity; severity is supplied by Wazuh and handled by the workflow.

## Implementation notes

### n8n workflow

The documented workflow uses these nodes:

- **Webhook** — receives the Wazuh alert.
- **Edit Fields (Set)** — renamed `Extract Alert Context`.
- **IF** — applies the rule-level condition.
- **AI Agent** — analyzes the selected alert fields.
- **OpenRouter Chat Model** — supplies the model to the AI Agent.
- **Slack: Send Message** — posts `{{$json.output}}` to the selected channel.

The Slack app is documented with the `chat:write` bot scope. The bot must be invited to the destination channel before it can post there.

### Wazuh integration

The report documents creating a custom integration at:

```text
/var/ossec/integrations/custom-n8n
```

The integration reads the Wazuh alert file as JSON and sends the alert to the n8n production webhook using HTTP `POST`.

The report also documents:

- Setting the integration file permissions with `chmod 750`.
- Assigning ownership to `root` and the group to `wazuh`.
- Adding the integration configuration to `/var/ossec/etc/ossec.conf`.
- Restarting the Wazuh manager after configuration.

The exact integration script and XML configuration are shown in the accompanying project PDF screenshots. Review those commands against your own Wazuh version and environment before using them.

### Windows process auditing and custom detection

To capture process creation and command-line information, the report documents enabling Windows process-creation auditing and command-line inclusion.

Commands shown in the report:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

Verify the auditing setting:

```powershell
auditpol /get /subcategory:"Process Creation"
```

The documented test creates a PowerShell command that decodes to:

```powershell
Write-Output "n8n-wazuh-test"
```

The report identifies the resulting process-creation event as Windows Security Event ID `4688`.

A custom Wazuh rule is documented in:

```text
/var/ossec/etc/rules/local_rules.xml
```

The report records custom rule ID `100500`, severity `12`, and description:

```text
PowerShell EncodedCommand executed on Windows endpoint
```

It also documents validating and restarting Wazuh:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

To inspect generated alerts:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

To search for the documented custom rule:

```bash
sudo grep '"id":"100500"' /var/ossec/logs/alerts/alerts.json | tail -3
```

## Testing and validation

The project report describes the following validation sequence:

1. Send a sample JSON alert to the n8n **test webhook**.
2. Confirm that n8n receives the event.
3. Confirm that `Extract Alert Context` selects the intended fields.
4. Check that the IF node routes alerts according to the configured rule-level condition.
5. Confirm that the AI Agent returns a structured SOC-style summary.
6. Confirm that the Slack node posts the AI Agent output to the configured channel.
7. Configure Wazuh to use the **production webhook** after the workflow is published.
8. Run the PowerShell test on the Windows endpoint.
9. Confirm the generated Wazuh alert, n8n execution, and Slack notification.

### Test URL versus Production URL

- **Test URL:** Use while developing and testing the n8n workflow. The webhook must be listening for a test event.
- **Production URL:** Configure Wazuh to use this after the workflow is activated/published.

Do not publish a live webhook URL in a public repository. Store it in the appropriate configuration or secret store.

## Troubleshooting documented in the project

### 1. PowerShell execution policy

The report documents using this process-scoped command to run the test script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

This applies to the current PowerShell process rather than changing the machine-wide execution policy.

### 2. Alert-level threshold mismatch

The report identifies a mismatch between the Wazuh integration threshold and the n8n IF-node threshold. It explains that Wazuh was configured to forward alerts at level `7` and above, while the n8n IF node used a higher threshold, causing some alerts (including level `9`) to stop before reaching the AI Agent.

The report's recommendation is to make the two thresholds consistent. It specifically suggests forwarding level `7+` from Wazuh and setting the n8n condition to `rule_level >= 7`.

**Important:** The earlier workflow section also describes an IF condition of `rule_level >= 9`, and its wording inconsistently says that this means level 10 or higher. A numeric condition of `>= 9` includes level 9. Confirm the intended threshold in the actual n8n workflow and Wazuh configuration before deployment.

### 3. Missing process-creation and command-line data

The report describes enabling Windows process-creation auditing and command-line auditing, creating a custom Wazuh rule for PowerShell `-EncodedCommand`, validating the Wazuh configuration, restarting the manager, and checking `alerts.json` for the generated alert.

## Requirements and configuration

Based on the documented implementation, you need:

- A Wazuh manager with access to the endpoint alerts.
- A Windows endpoint configured to generate the relevant process-creation audit events.
- Kali Linux or another SSH client to administer the Wazuh server.
- An n8n instance that can receive webhook requests.
- An OpenRouter API account and API key.
- A Slack workspace, Slack app, bot token, and destination channel.
- Network connectivity from the Wazuh server to the n8n webhook.

Exact versions, resource sizing, firewall rules, and a complete reproducible deployment package are **not specified** in the report.

## Security considerations

This project handles security telemetry and service credentials. Before publishing or deploying it:

- Never commit OpenRouter API keys, Slack bot tokens, Slack signing secrets, or other credentials.
- Rotate/revoke any credential that has ever been exposed in a document, screenshot, repository, or public link.
- Review every screenshot as well as selectable PDF text; credentials can remain visible inside images even when text has been redacted.
- Replace live webhook URLs and environment-specific hostnames with placeholders in public examples.
- Restrict webhook access and Slack bot permissions to what the workflow requires.
- Avoid sending unnecessary endpoint or user data to an external model provider.
- Review AI-generated triage before taking incident-response actions. The AI output is an aid for analysts, not an authoritative verdict.

## Limitations and scope

This is a lab demonstration of an alert-triage and notification pipeline. The documented workflow sends selected alerts to an AI Agent and posts the resulting summary to Slack. The report does not demonstrate automated endpoint isolation, remediation, ticket creation, or a full incident-response lifecycle.

The AI prompt is designed to reduce unsupported claims, but model output should still be reviewed by a human analyst.

## Project documentation

The accompanying project PDF contains the detailed, screenshot-based walkthrough of:

- n8n workflow construction (Steps 1–15)
- Wazuh custom integration setup
- Slack app and channel configuration
- Windows PowerShell testing
- Troubleshooting and threshold alignment
- Webhook, HTTP `POST`, and test-versus-production URL explanations

## Author

**[Ibrahim Elsaeed Elmenshawy]**  
Cybersecurity | SOC | SIEM | Security Automation

Add your LinkedIn profile, repository links, and any additional project links here.

---

*This README was prepared from the accompanying project documentation. Verify environment-specific values, thresholds, credentials, and configuration syntax against your actual lab before reuse.*
