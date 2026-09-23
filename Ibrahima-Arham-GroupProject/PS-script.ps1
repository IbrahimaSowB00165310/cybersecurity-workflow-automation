$current_direct = Split-Path -Parent $MyInvocation.MyCommand.Path

# fonction to get the log file
function get-the-log-file {
 param(
 [string]$filepath
 )
 if ([string]::IsNullOrWhiteSpace($filepath)) {
 while ($true) {
 $filepath = Read-Host "Please enter the Path of the log file !"
 if ([string]::IsNullOrWhiteSpace($filepath)) {
 Write-Host "You have to enter a path, try again" -ForegroundColor red
 continue
 }
 if (!(Test-Path $filepath)) {
 Write-Host " the path '$filepath' does not exist. Try again" -ForegroundColor red
 continue
 }
 if (!(Test-Path $filepath -PathType Leaf)) {
 Write-Host "Path exists but is not a file" -ForegroundColor Red
 continue
 }
 
 break
 }
 }
 return $filepath
 }



$thefilepath = get-the-log-file

#putting the failed loging into the refused_login variable
$refused_login = Get-Content $thefilepath |
where-object { $_ -match "user unknown|authentication failure|invalid user|Failed password" }
$table_of_refused_login = $refused_login |
 Select-String -Pattern "^(\d{4}-\d{2}-\d{2}).*?(\d{2}:\d{2}:\d{2}).*?(\d{1,3}(?:\.\d{1,3}){3})" | #checking with regex
 ForEach-Object {
  [PSCustomObject]@{
     Date = $_.matches[0].groups[1].value
     Time = $_.matches[0].groups[2].value
     Ip = $_.matches[0].groups[3].value
 }
}

$current_date = Get-Date -Format "yyyyMMdd_HHmmss" #getting the curent date

$table_of_refused_login | Sort-Object Date,Time -Descending |
Export-Csv -Path (Join-Path $current_direct ("${current_date}_suspicious_IPs_login.csv")) -NoTypeInformation #creating the new suspicious file as CSV

python (Join-Path $current_direct "Python-script.py") #lunching the Python script from here