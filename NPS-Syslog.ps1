# Many thanks to https://github.com/geek-at for the basis used to develop the NPS log parser.

<#

BACKFILL: If $true, Load any files found within the specified NPS log path.
     If backfill has previously run (as indicated by the presence of a .\backfilled.txt file,
     backfill beginning on the day following the previous run.
BACKFILL: If $false, just open today's file, fill according to the .\lasttime.txt DTS, and tail the log to catch new events.
#>
param([bool]$BACKFILLFLAG = $false)

Try {. .\radius_functions.ps1} # load the field translation functions
Catch {
    Write-Console 'Failed to load required translation functions from radius_functions.ps1'
    Write-Console 'It is possible you need to change your PowerShell execution policy.  See https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.3'
    Write-Console 'Example execution policy command:'
    Write-Console 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser'
    exit 3
    }
    
$ConfigFile = '.\NPS-Syslog-Config.xml'
$ConfigParams = [xml](get-content $ConfigFile) # load the configuration file

# load the configuration values into script variables
$PATH = $ConfigParams.configuration.log.path.value
$SyslogTarget = $ConfigParams.configuration.server.fqdn.value
$SyslogPort = $ConfigParams.configuration.server.port.value
$IGNOREUSER = $ConfigParams.configuration.option.ignoreuser.value

# This computer's NETBIOS name, used for Syslog
$NPSHostname = $env:COMPUTERNAME

# flag used to track whether we're in follow mode or fill/backfill mode
$FOLLOWINGLOG = $false

# initialize the UDP socket writer
if ($SyslogTarget -ne "syslog.hostname.here") {
    $UdpClient = New-Object System.Net.Sockets.UdpClient $SyslogTarget, $SyslogPort
    }
else {
    Write-Output "ERROR: Syslog hostname not configured.  Quitting.  Please review NPS-Syslog-Config.xml"
    exit 3
    }

# load the timestamp for the last loaded log entry so we can be sure we don't double-load events
if (Test-Path -Path .\lasttime.txt -PathType Leaf){$lasttime = Get-Content .\lasttime.txt -Raw}
else {$lasttime = 0} # if there is no timestamp file, just initialize the timestamp to 0

# this function simply writes the passed value to .\lasttime.txt.  The file tracks the last loaded log entry.
function saveLastTime($time)
{
    $time | Out-File -FilePath .\lasttime.txt
}

# this function is called each time the script is loaded.
# In backfill mode, it will be called once for each log file to load.
# In standard mode, it will be called once only to catch up today's log file.
function fill($backfill)
{
    if(!$backfill) # if we're not in backfill mode, look for today's log file
    {
	$datestring = (Get-Date).ToString("yyMMdd")
        $file = $PATH + '\IN' + $datestring + '.log'
    }
    else # if we're in backfill mode, use the file name passed in as an argument
    {
        $file = $backfill
    }

    # if we don't find the log file, do nothing.
    if (-not(Test-Path -Path $file -PathType Leaf)) {
        Write-Output "No log file $file found to backfill."
    }
    else { # we have a file to process.
        Write-Output "...Processing $file..."

        $fileHandle = [System.IO.File]::Open($file,[System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite) # get the file handle
        $fileBytes = New-Object byte[] $fileHandle.Length
        $FileContent = New-Object System.Text.UTF8Encoding $true
        while ($fileHandle.Read($fileBytes, 0 , $fileBytes.Length)) {
            $fileRead = $FileContent.GetString($fileBytes)
            }

        $fileHandle.Close()
        $fileHandle.Dispose()

        $fileRead = $fileRead -split "`r`n"

        forEach ($d in $FileRead) # read each line of the log file
        {
            parseLog $d # call the parser to push any valid logs to Syslog
        }
    }

<#
    else { # we have a file to process.
        Write-Output "...Processing $file..."

        $fileHandle = [System.IO.File]::OpenText($file) # get the file handle

        while ($d = $fileHandle.ReadLine()) # read each line of the log file (used to have :nextLine label)
        {
            parseLog $d # call the parser to push any valid logs to InfluxDB
        }
        # finished reading file.  Close handle.
        $fileHandle.Close()
        $fileHandle.Dispose()
    }
#>

}

# this function is called only once we're caught up and now need to operate in tail mode.
function follow()
{
    # build the file name variable for today's log file
    $datestring = (Get-Date).ToString("yyMMdd")
    $file = $PATH + '\IN' + $datestring + '.log'

    # if we don't find the log file, keep trying every few minutes, as NPS may not have written an event yet.
    while (-not(Test-Path -Path $file -PathType Leaf)) {
        $datestringnow = (Get-Date).ToString("yyMMdd")
        if ($datestringnow -eq $datestring) {
            Write-Output "No log file $file found to tail.  Waiting for an event to be written..."
            Start-Sleep -Seconds 30
            fill $false
        }
        else { # if the day changed, we need to open a new log file.  Reload the script and quit execution.
            powershell.exe -File ".\NPS-Syslog.ps1"
	        exit 0
        }
    }
    $FOLLOWINGLOG = $true # indicate that we're now in log follow mode
    Write-Output "...Tailing log file $file"
    Get-Content -Wait -Tail 0 -Path $file | % {parseLog} # continue to listen for file changes, sending each new line to the parseLog function
}

# this function receives either pipeline input (from the follow() function), or a string (from the fill($backfill) function) passed as a parameter
# the CSV string is parsed and reformatted according to RFC3164 and the SendTo-Syslog function is called with the final payload
function parseLog($f)
{
    if(!$f){ # if our input was received from the pipeline, assign the value to $f
    	$f = $_
    }
    if($f.Length -lt 2){return} # this is an empty line.  Return.
    if($f.Contains($IGNOREUSER)){return} # this line contains our ignoreuser string.  Return.
    $f = $f.Trim()
    $g = $f.Split(',')
    $date = $g[2].Replace('"', '')
    $time = $g[3].Replace('"', '')

    #$timestamp = [DateTime]::ParseExact(($date + " " + $time), "yyyy-MM-dd H:m:s", $null).Ticks / 10000000 # European DT format
    $timestamp = [DateTime]::ParseExact(($date + " " + $time), "MM/dd/yyyy H:m:s", $null).Ticks / 10000000 # US DT Format
    
    if ($FOLLOWINGLOG){ # if we're in follow (Get-Content -tail) mode, check to make sure the day has not changed on us
    	$logDayofMonth = $date.Split('/')
    	$currentDayofMonth = Get-Date -Format "dd"
     	if($currentDayofMonth -gt $logDayofMonth[1]){ # if the day changed, we need to open a new log file.  Reload the script and quit execution.
      	    powershell.exe -File ".\NPS-Syslog.ps1"
	        exit 0
      	}
    }
    if ($timestamp -le $lasttime){return} # if we've already processed a log with this date/time, return.
    $logDTS = [DateTime]::ParseExact(($date + " " + $time), "MM/dd/yyyy H:m:s", $null) # Get-Date ($date + " " + $time) -Format 'MM/dd/yyyy HH:mm:ss'
    if ($LogDTS.day -lt 10) { $syslogDTS = $LogDTS.tostring("MMM  d yyyy HH:mm:ss") } else { $syslogDTS = $LogDTS.tostring("MMM dd yyyy HH:mm:ss") }
    $server = $g[0].Replace('"', '')
    $origin = $g[6].Replace('"', '')
    $uname = $g[7].Replace('"', '')
    $type = $g[4].Replace('"', '')
    $client = $g[5].Replace('"', '')

    if($client.Contains('/'))
    {
        $startTrim = $client.IndexOf('/') + 1
        $endTrim = $client.length - $startTrim
        $client = $client.Substring($startTrim,$endTrim)
    }

    $client_mac = $g[8].Replace('"', '').Replace(':', '-').Trim()
    if($client_mac.Contains('|'))
    {
        $client_mac = $client_mac.Substring(0,$client_mac.IndexOf('|'))  ## EAT THE DOUBLE MAC
    }
    if ($client_mac -and -not $client_mac.Contains(':') -and $client_mac.Length -eq 12)
    {
        $client_mac = $client_mac.Insert(10,"-")
        $client_mac = $client_mac.Insert(8,"-")
        $client_mac = $client_mac.Insert(6,"-")
        $client_mac = $client_mac.Insert(4,"-")
        $client_mac = $client_mac.Insert(2,"-")
    }

    $ap_ip = $g[15].Replace('"', '')
    $ap_radname_full = $g[16].ToLower().Replace('"', '')
    $specific_switch = $g[11].ToLower().Replace('"', '')
    $policy = $g[60].Replace('"', '')
    $auth = TranslateAuth($g[23].Replace('"', ''))
    $policy2 = $g[24]
    $reason = $g[25].Replace('"', '')
    $rs = TranslateReason($reason)
    $authmethod = $g[30]

    $tt = TranslatePackageType($type)
    $tq = [Math]::Round($timestamp / 900) * 900

    if ($origin.Contains('\'))
    {
        $startTrim = $origin.IndexOf('\') + 1
        $endTrim = $origin.length - $startTrim
        $OU = $origin.Substring(0,$origin.IndexOf('\'))
        $origin_client = $origin.Substring($startTrim,$endTrim)
    }
    elseif ($origin.Contains('/'))
    {
        $startTrim = $origin.IndexOf('/') + 1
        $endTrim = $origin.length - $startTrim
        $OU = $origin.Substring(0,$origin.IndexOf('/'))
        $origin_client = $origin.Substring($startTrim,$endTrim)
    }
    else
    {
        $origin_client = $origin
    }

    if($OU) {$OU = sanitizeString($OU)}
    else {$OU = ''}

    $origin_client = sanitizeString($origin_client)

    switch($type) # check to see what type of log this is so we know what fields are important to send to the database
    {
        1 { #Requesting access - auth, informational

            # Making sure all tag values are set and if not, set them to "0"
            $policy2 = if ($policy2) { sanitizeString($policy2) } else { 'nomatch' }
            $client_mac = if ($client_mac) { $client_mac } else { '0' }
            $ap_radname_full = if ($ap_radname_full) { $ap_radname_full } else { '0' }
            $origin_client = if ($origin_client) { $origin_client } else { '0' }
            $details = $syslogDTS + " " + $NPSHostname + " NPS_RADIUS: AUTH-REQUEST | Device: " + $ap_radname_full + " | DeviceIP: " + $ap_ip + " | Client: " + $origin_client + " | MAC: " + $client_mac + " | Policy: " + $policy2
            SendTo-Syslog "auth" "informational" $details
            }

        2 { #Accepted - auth, notice

            # Making sure all tag values are set and if not, set them to "0"
            $authmethod =  if ($authmethod) { sanitizeString($authmethod) } else { 'other' }
            $OU = if ($OU) { $OU } else { '0' }
            $ap_radname_full = if ($ap_radname_full) { $ap_radname_full } else { '0' }
            $origin_client = if ($origin_client) { $origin_client } else { '0' }
            $details = $syslogDTS + " " + $NPSHostname + " NPS_RADIUS: AUTH-ACCEPT | Device: " + $ap_radname_full + " | DeviceIP: " + $ap_ip + " | AuthMethod: " + $authmethod + " | Client: " + $origin_client + " | OU: " + $OU
            SendTo-Syslog "auth" "notice" $details
            }

        3 { #Rejected - auth, error

            #making sure all tag values are set and if not, set them to "0"
            $ap_radname_full = if ($ap_radname_full) { $ap_radname_full } else { '0' }
            $reason = if ($reason) { $reason } else { '0' }
            $origin_client = if ($origin_client) { $origin_client } else { '0' }
            $rs = if ($rs) { $rs } else { '0' }
            $details = $syslogDTS + " " + $NPSHostname + " NPS_RADIUS: AUTH-REJECTED | Device: " + $ap_radname_full + " | DeviceIP: " + $ap_ip + " | Reason: " + $reason + " | Client: " + $origin_client + " | Extended: " + $rs
            SendTo-Syslog "auth" "error" $details
          }

        4 { #Accounting-Request - In sample logs we observed a large number of events of no value, so we filter out anything lacking details about a client (name, or user, or MAC)
                # auth, informational
            #making sure all tag values are set and if not, set them to "0"
            $ap_radname_full = if ($specific_switch) { $specific_switch } else { $ap_radname_full }
            $origin_client = if ($origin_client) { $origin_client } else { '0' }
            if ($client_mac) {
                $details = $syslogDTS + " " + $NPSHostname + " NPS_RADIUS: ACCOUNTING-REQUEST | Device: " + $ap_radname_full + " | DeviceIP: " + $ap_ip + " | Client: " + $origin_client + " | MAC: " + $client_mac
                SendTo-Syslog "auth" "informational" $details
            } 
            else {
                if ($client) {
                $details = $syslogDTS + " " + $NPSHostname + " NPS_RADIUS: ACCOUNTING-REQUEST | Device: " + $ap_radname_full + " | DeviceIP: " + $ap_ip + " | Client: " + $client
                SendTo-Syslog "auth" "informational" $details
                }
            }
          }

        5 { #Accounting-Response - auth, informational

            #making sure all tag values are set and if not, set them to "0"
            $client_mac = if ($client_mac) { $client_mac } else { '0' }
            $ap_radname_full = if ($ap_radname_full) { $ap_radname_full } else { '0' }
            $origin_client = if ($origin_client) { $origin_client } else { '0' }
            $details = $syslogDTS + " " + $NPSHostname + " NPS_RADIUS: ACCOUNTING-RESPONSE | Device: " + $ap_radname_full + " | DeviceIP: " + $ap_ip + " | Client: " + $origin_client + " | MAC: " + $client_mac
            SendTo-Syslog "auth" "informational" $details
            }

        11 { #Access-Challenge - auth, informational

            #making sure all tag values are set and if not, set them to "0"
            $policy2 = if ($policy2) { sanitizeString($policy2) } else { 'nomatch' }
            $client_mac = if ($client_mac) { $client_mac } else { '0' }
            $ap_radname_full = if ($ap_radname_full) { $ap_radname_full } else { '0' }
            $origin_client = if ($origin_client) { $origin_client } else { '0' }
            $details = $syslogDTS + " " + $NPSHostname + " NPS_RADIUS: AUTH-CHALLENGE | Device: " + $ap_radname_full + " | DeviceIP: " + $ap_ip + " | Client: " + $origin_client + " | MAC: " + $client_mac + " | Policy: " + $policy2
            SendTo-Syslog "auth" "informational" $details
            }
        #default {}
    }
    saveLastTime($timestamp)
}

# The SendTo-Syslog function is adapted from https://www.sans.org/blog/powershell-function-to-send-udp-syslog-message-packets/ with many thanks!
function SendTo-SysLog
{
    param ([String]$Facility, [String]$Severity, [String]$Content)
 
    switch -regex ($Facility)
        {
        'kern' {$Facility = 0 * 8 ; break }
        'user' {$Facility = 1 * 8 ; break }
        'mail' {$Facility = 2 * 8 ; break }
        'system' {$Facility = 3 * 8 ; break }
        'auth' {$Facility = 4 * 8 ; break }
        'syslog' {$Facility = 5 * 8 ; break }
        'lpr' {$Facility = 6 * 8 ; break }
        'news' {$Facility = 7 * 8 ; break }
        'uucp' {$Facility = 8 * 8 ; break }
        'cron' {$Facility = 9 * 8 ; break }
        'authpriv' {$Facility = 10 * 8 ; break }
        'ftp' {$Facility = 11 * 8 ; break }
        'ntp' {$Facility = 12 * 8 ; break }
        'logaudit' {$Facility = 13 * 8 ; break }
        'logalert' {$Facility = 14 * 8 ; break }
        'clock' {$Facility = 15 * 8 ; break }
        'local0' {$Facility = 16 * 8 ; break }
        'local1' {$Facility = 17 * 8 ; break }
        'local2' {$Facility = 18 * 8 ; break }
        'local3' {$Facility = 19 * 8 ; break }
        'local4' {$Facility = 20 * 8 ; break }
        'local5' {$Facility = 21 * 8 ; break }
        'local6' {$Facility = 22 * 8 ; break }
        'local7' {$Facility = 23 * 8 ; break }
        default {$Facility = 23 * 8 } #Default is local7
        }
    
    switch -regex ($Severity)
        {
        '^em' {$Severity = 0 ; break } #Emergency
        '^a' {$Severity = 1 ; break } #Alert
        '^c' {$Severity = 2 ; break } #Critical
        '^er' {$Severity = 3 ; break } #Error
        '^w' {$Severity = 4 ; break } #Warning
        '^n' {$Severity = 5 ; break } #Notice
        '^i' {$Severity = 6 ; break } #Informational
        '^d' {$Severity = 7 ; break } #Debug
        default {$Severity = 5 } #Default is Notice
        }
    $privalue = [int]$Facility + [int]$Severity
    $pri = "<" + $privalue + ">"
    
    $msg = $pri + $Content

    # Convert message to array of ASCII bytes.
    $bytearray = $([System.Text.Encoding]::ASCII).getbytes($msg)
    
    # RFC3164 Section 4.1: "The total length of the packet MUST be 1024 bytes or less."
    # "Packet" is not "PRI + HEADER + MSG", and IP header = 20, UDP header = 8, hence:
    if ($bytearray.count -gt 996) { $bytearray = $bytearray[0..995] }

    # Send the Syslog message...
    $UdpClient.Send($bytearray, $bytearray.length) | out-null

} # End SendTo-SysLog

# This function is likely unnecessary for Syslog.  Keeping just in case we need to do some string sanitizing.
function sanitizeString($string)
{
    $StringRet = $string.trim()
    #if($StringRet.Contains(',')){$stringRet = $stringRet.replace(',','\,')}
    #if($StringRet.Contains(' ')){$stringRet = $stringRet.replace(' ','\ ')}
    #if($StringRet.Contains('=')){$stringRet = $stringRet.replace('=','\=')}
    return $stringRet
}

# START READING LOGS...
if($BACKFILLFLAG -eq $true)
{
    if (Test-Path -Path .\backfilled.txt -PathType Leaf){
    	$backfillDTS = Get-Content .\backfilled.txt
        $today = Get-Date -Format 'yyMMdd'
        if($backfillDTS -eq $today){fill $false}
        else{
            $readableDate = $backfillDTS.Substring(2,2) + '/' + $backfillDTS.Substring(4,2) + '/' + $backfillDTS.Substring(0,2)
            Write-Output "WARNING: Data was already backfilled on $readableDate.  *****TO OVERRIDE, PLEASE DELETE THE FILE .\backfilled.txt AND RE-RUN THE SCRIPT*****"
            $catchup = Read-Host 'Press c to catch up since the last time you backfilled data through today OR press ENTER to load todays log'
            if($catchup.ToLower() -eq 'c'){
                Write-Output "Catching up"
                $logList = Get-ChildItem $PATH -File -Filter *.log | Sort-Object -Property Name
                Foreach ($backfillFile in $logList){
                    $fileDate = $backfillFile.Name
                    $fileDate = $fileDate -replace '.log',''
                    $fileDate = $fileDate -replace 'IN',''
                    if($fileDate -gt $backfillDTS){
    	                Write-Output "...Backfilling log data for $backfillFile..."
    	                fill $backfillFile.FullName
                    }
                    else{Write-Output "Skipping $backfillFile..."}
                }
                (Get-Date).ToString("yyMMdd") | Out-File -FilePath .\backfilled.txt
            } 
            else {fill $false}
        }
    }
    else{
        $logList = Get-ChildItem $PATH -File -Filter *.log | Sort-Object -Property Name
        Foreach ($backfillFile in $logList){
    	    Write-Output "...Backfilling log data for $backfillFile..."
    	    fill $backfillFile.FullName
        }
        Get-Date -Format 'yyMMdd' | Out-File -FilePath .\backfilled.txt
    }
}
else{ # script was called with no parameters, simply parse today's log and then follow/tail to capture any new events.
    fill $false
    }
# once any backfill work is complete, just call follow to continually watch today's log file
follow
