# Microsoft NPS Syslog Connector
## NOTE: Work in progress
Syslog connector/parser for Microsoft NPS server logs
This tool has been tested on Server 2016 and Server 2022-based Microsoft NPS servers and is designed to run as an unprivileged local user with only read/list access needed to the NPS log folder.  
  
## Installation  
1. Download
2. Run installer
3. Configure Syslog details  

## Prerequisites
1. A Windows NPS server with PowerShell enabled
2. A Syslog UDP collector to receive events

## Installation
1. Download the latest release .ZIP file.
2. Right-click the downloaded file, click Properties, and click "Unblock"
3. Extract the .ZIP to a single directory.
4. Launch PowerShell as an administrator, navigate to the directory with the unzipped files.
5. Type .\NPS-Syslog-Install.ps1 to run the installer.
6. Follow the directions at the end of the process to complete SimpleFIM setup.

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


### Installation
- Save the script and configuration file to the NPS server
### Execution
- On first run, you may want to backfill data from logs currently in place on the NPS server.
  - To do this, execute: ```NPS-Syslog.ps1 $true```  
- On subsequent runs, simply execute NPS-Syslog.ps1  
- If the parser has not run for some period of time, you can catch up by again running the backfill command.  