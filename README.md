# Microsoft NPS Syslog Connector
Syslog send / parser tool for Microsoft NPS / RADIUS logs  
### Installation
- Save the script and configuration file to the NPS server
### Execution
- On first run, you may want to backfill data from logs currently in place on the NPS server.
  - To do this, execute: ```NPS-Syslog.ps1 $true```  
- On subsequent runs, simply execute NPS-Syslog.ps1  
- If the parser has not run for some period of time, you can catch up by again running the backfill command.  
