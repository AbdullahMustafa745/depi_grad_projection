| Normalized Field | Windows Raw Log (Sysmon/Security) | FortiGate Raw Log (Syslog) | Nginx Raw Log (Web Access) | Description |
|---|---|---|---|---|
| `source.ip` | `IpAddress` / `SourceIp` | `srcip` | `remote_addr` | IP address of the source or attacker |
| `destination.ip` | `DestinationIp` | `dstip` | `server_addr` | IP address of the target |
| `user.name` | `TargetUserName` | `user` | `remote_user` | Name of the user who performed the action |
| `event.action` | `EventID` (e.g., 4625) | `action` (e.g., deny) | `request_method` | Type of event or action performed |
| `process.name` | `Image` / `NewProcessName` | *N/A* | *N/A* | Name of the process or running program |
