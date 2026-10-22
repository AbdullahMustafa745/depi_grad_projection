| normalized_field | wazuh_field | meaning | example | validation_status |
|---|---|---|---|---|
| `timestamp` | `timestamp` | Time when the event was generated | Actual event timestamp | Validated |
| `agent.name` | `agent.name` | Name of the monitored endpoint | `MyUbuntu` | Validated |
| `agent.id` | `agent.id` | Unique Wazuh agent identifier | `001` | Validated |
| `rule.id` | `rule.id` | Identifier of the Wazuh detection rule | `5501` | Validated |
| `rule.level` | `rule.level` | Severity level assigned by the Wazuh rule | `3` | Validated |
| `rule.description` | `rule.description` | Description of the detected event | `PAM: Login session opened` | Validated |
| `manager.name` | `manager.name` | Name of the Wazuh manager | `WZH-Server` | Validated |
| `data.srcip` | `data.srcip` | Source IP address when extracted from an event | Actual source IP | To validate |
| `data.dstuser` | `data.dstuser` | Destination username when extracted from an event | Actual username | To validate |
| `full_log` | `full_log` | Original log message associated with the event | Actual event message | To validate |
