# Microsoft NPS Syslog Connector
## NOTE: Work in progress
Syslog connector/parser for Microsoft NPS server logs  
This tool has been tested on Server 2016 and Server 2022-based Microsoft NPS servers and is designed to run as an unprivileged local user with only read/list access needed to the NPS log folder.  

## Prerequisites
1. A Windows NPS server with PowerShell enabled  
2. A Syslog UDP collector to receive events  

## Installation
1. Download the latest release .ZIP file  
2. Right-click the downloaded file, click Properties, and click "Unblock"  
3. Extract the .ZIP to a single directory  
4. Edit NPS-Syslog-Config.xml to match your environment settings  
5. Once you are familiar with the operation and have successfully backfilled your logs, you can create a scheduled task  
    - Open Computer Management and create a local user account with a strong password and no group memberships beyond, "Users"  
    - Open mmc.exe and load the Local Group Policy Snap-In.  
      - Add the user you created to the, “Log on as a batch job” right.  
      - This can be found in Computer Configuration->Windows Settings->Local Policies->User Rights Assignments  
    - Configure a trigger of, "At startup."  
    - Configure a command of, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  
    - Set the execution argument to, "-File C:\Path\To\Install\ParseNPSLogs.ps1"
    - Configure the task to run as the local user you created  

### Execution
- On first run, you will likely want to backfill data from logs currently in place on the NPS server.  
  - To do this, execute: ```ParseNPSLogs.ps1 $true```  
  - Expect execution to take about 1 second for every 10MB of logfile.  If you cancel before the process has completed, it will not save the backfill state.  
- On subsequent runs, simply execute ParseNPSLogs.ps1  
- If the parser has not run for some period of time, you can catch up by again running the backfill command.  

## Operation
### Configuration
#### NPS-Syslog-Config.xml
- Edit this file to specify your Syslog UDP server details.  
- If you have a RADIUS test user, specify that username in the "ignoreuser" field.  
### Two files control the execution of the NPS-to-Syslog script
#### NPS-Syslog.ps1
This is the main program script.  The tool can process about 10MB of log data per second, so plan accordingly if you will be backfilling a large amount of data.  
#### radius_functions.ps1
This file contains lookup functions for various log status fields, converting from numbers to human-readable text  
### User Account
A local user named, “npslog” is created by the installer with a unique, strong password.  The user account is configured with no password expiration and is not added to any privileged security groups.  
### Group Policy Settings
This setting is handled by the installer.  Open mmc.exe and load the Local Group Policy.  The new “npslog” user is added to the, “Log on as a batch job” right.  This can be found in Computer Configuration->Windows Settings->Local Policies->User Rights Assignments  
## Troubleshooting
### I need to edit the scheduled task but do not know the password for the "npslog" user account
1. Open Computer Management and reset the password for the npslog user.  Always use a complex password with a minimum length of 15 characters.
2. Once the password has been changed, open Task Scheduler and edit the task, "NPS to Syslog," specifying this new password when saving the task.
### I need to backfill data again because my Syslog server was offline/unreachable during the first run
1. Delete the backfilled.txt file
### The script was not running for a few days so I have a gap in logs sent to Syslog
1. Edit backfilled.txt and set the date (in YYMMDD format) to the file prior to where you would like to resume the backfill process.  
2. Run ```NPS-Syslog.ps1 $true```
