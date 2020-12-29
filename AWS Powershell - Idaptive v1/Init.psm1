# Copyright 2019 IDaptive, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Import-Module .\AWS.SSO.Powershell.psm1 3>$null 4>$null -force
Import-Module .\PowerShell.REST.psm1 3>$null 4>$null -force

#Version 10.3
# If Verbose is enabled, we'll pass it through
$enableVerbose = ($PSBoundParameters['Verbose'] -eq $true)


function Init-Authenticate([string]$Tenant="pod0.idaptive.app", [string]$Location)
{
    if ($VerbosePreference -eq "Continue") {
         Write-Host "Making debug on. Note that it will log incoming and outgoing REST messages which can contain sensetive information" -foregroundcolor "red"
    }
	if ($Tenant -NotLike "*.centrify.com" -and $Tenant -NotMatch "^(.+).idaptive.(app|qa)$") {
		$Tenant = $($Tenant)+".centrify.com"
	}
    if (!$Region) {
#        Write-Host "Using default region us-west-2"
		$Region = "us-west-2"
	}
    if (!$Location) {
        Write-Host "Using following default credential file location"
        $UserHome = $env:USERPROFILE
        $Location = $UserHome + "\.aws\credentials"
        Write-Host $Location
    }
	$Tenant = "https://"+$($Tenant)
	Write-Verbose ("Authenticating on " + $Tenant)
    Write-Verbose("Credentials will be save in " + $Location)
    Authenticate-AWS $Tenant $Region $Location
	Write-Host "--------------------------COMPLETE---------------------------" -foregroundcolor Green
}
