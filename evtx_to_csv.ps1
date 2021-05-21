$Filename_host = "Server01"
$Last_Mth = (get-date).AddMonths(-1).ToString('yyyyMM')
$csv_File_Path = "D:\Audit Log\$Last_Mth\"
$csv_File = $csv_File_Path + "audit_log_$Last_Mth($Filename_host).csv"

If(!(test-path $csv_File_Path))
{
      New-Item -ItemType Directory -Force -Path $csv_File_Path
}

#3 Days before of previous month (Ensure can get the oldest log of last month)
#$From_Log_date = '05/21/2021'
$From_Log_date = (get-date -day 1 -Hour 0 -Minute 0 -Second 0).AddDays(-3) | Get-Date -Format "MM/dd/yyyy"

#Tomorrow (get the latest log)
#$To_Log_date = '05/22/2021'
$To_Log_date = (Get-date).AddDays(1) | Get-Date -Format "MM/dd/yyyy"

$Log_list = Get-ChildItem C:\Windows\System32\winevt\Logs\*Security*.evtx | where-object {$_.LastWriteTime -gt $From_Log_date -and $_.LastWriteTime -lt $To_Log_date}

echo $Log_list

Get-Winevent -FilterHashtable @{Path=$Log_list; ID=4624,4648,4672,4634,4779,4778,4647} | 
	select @{n="Level";e={$_.LevelDisplayName}}, @{n="Date and Time";e={$_.TimeCreated}}, @{n="Source";e={$_.ProviderName}}, @{n="Event ID";e={$_.Id}}, @{n="Task Category";e={$_.TaskDisplayName}}, 
		@{n='Message';e={ (($_.Message | Select -First 1) -Split "`n")[0] }}, 
		@{n="UserAccount";e={If ($_.ID -eq 4672 -or $_.ID -eq 4634) {$_.Properties.Value[1]} elseif ($_.ID -eq 4778 -or $_.ID -eq 4779) {$_.Properties.Value[0]} else {$_.Properties.Value[5]}}},
		@{n="UserDomain";e={If ($_.ID -eq 4672 -or $_.ID -eq 4634) {$_.Properties.Value[2]} elseif ($_.ID -eq 4778 -or $_.ID -eq 4779) {$_.Properties.Value[1]} else {$_.Properties.Value[6]}}},
		@{n="Logon Type";e={If ($_.ID -eq 4624){$_.Properties.Value[8]}}},
		@{n="Process Name";e={If ($_.ID -eq 4624){$_.Properties.Value[17]}}},
		@{n="WorkstationName";e={If ($_.ID -eq 4624){$_.Properties.Value[11]} elseif ($_.ID -eq 4778 -or $_.ID -eq 4779) {$_.Properties.Value[4]}}},
		@{n="SourceNetworkAddress";e={If ($_.ID -eq 4624){$_.Properties.Value[18]} elseif ($_.ID -eq 4778 -or $_.ID -eq 4779) {$_.Properties.Value[5]}}} | sort-object -Property "Date and Time" | export-csv $csv_File -NoTypeInformation
