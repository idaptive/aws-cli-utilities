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

<#
 .Synopsis
  Performs a REST call against the CIS platform.

 .Description
  Performs a REST call against the CIS platform (JSON POST)

 .Parameter Endpoint
  Required - The target host for the call (i.e. https://cloud.idaptive.com)

 .Parameter Method
  Required - The method to call (i.e. /security/logout)

 .Parameter Token
  Optional - The bearer token retrieved after authenticating, necessary for
  authenticated calls to succeed.

 .Parameter ObjectContent
  Optional - A powershell object which will be provided as the POST arguments
  to the API after passing through ConvertTo-Json.  Overrides JsonContent.

 .Parameter JsonContent
  Optional - A string which will be posted as the application/json body for
  the call to the API.

 .Example
   # Get current user details
   InvokeREST -Endpoint "https://cloud.idaptive.com" -Method "/security/whoami"
#>
function InvokeREST {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $endpoint,
        [Parameter(Mandatory=$true)]
        [string] $method,
        [string] $token = $null,
        $objectContent = $null,
        [string]$jsonContent = $null,
        $websession = $null,
        [bool]$includeSessionInResult = $false
    )

	# Force use of tls 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $methodEndpoint = $endpoint + $method
    Write-Verbose "Calling $methodEndpoint"

    $addHeaders = @{
        "X-CENTRIFY-NATIVE-CLIENT" = "1"
    }

    if(![string]::IsNullOrEmpty($token))
    {
        $addHeaders.Authorization = "Bearer " + $token
    }

    if($objectContent -ne $null)
    {
        $jsonContent = $objectContent | ConvertTo-Json
    }

    if(!$jsonContent)
    {
        Write-Verbose "No body provided"
        $jsonContent = "[]"
    }

#	Write-Host $methodEndpoint -foregroundcolor "magenta"
#	Write-Host $objectContent -foregroundcolor "green"
#	Write-Host $jsonContent -foregroundcolor "cyan"
#	Write-Host $addHeaders -foregroundcolor "blue"
    if(!$websession)
    {
        Write-Verbose "Creating new session variable"
        $response = Invoke-RestMethod -Uri $methodEndpoint -ContentType "application/json" -Method Post -Body $jsonContent -SessionVariable websession -Headers $addHeaders
    }
    else
    {
        Write-Verbose "Using existing session variable $websession"
        $response = Invoke-RestMethod -Uri $methodEndpoint -ContentType "application/json" -Method Post -Body $jsonContent -WebSession $websession
    }

	$global:myresp = $response
    if($includeSessionInResult)
    {
        $resultObject = @{}
        $resultObject.RestResult = $response
        $resultObject.WebSession = $websession

        return $resultObject
    }
    else
    {
        return $response
    }
}

<#
 .Synopsis
  Performs an interactive MFA login, and outpus a bearer token (Field name "BearerToken").

 .Description
  Performs an interactive MFA login, and retrieves a token suitable for making
  additional API calls as a Bearer token (Authorization header).  Output is an object
  where field "BearerToken" contains the resulting token, or "Error" contains an error
  message from failed authentication. Result object also contains Endpoint for pipeline.

 .Parameter Endpoint
  The first month to display.

 .Example
   # MFA login to cloud.idaptive.com
   InteractiveLogin-GetToken -Endpoint "https://cloud.idaptive.com"
#>
function InteractiveLogin-GetToken {
    [CmdletBinding()]
    param(
        [string] $endpoint = "https://cloud.idaptive.com",
        [Parameter(Mandatory=$true)]
        [string] $username = ""
    )

    Write-Verbose "Initiating MFA against $endpoint for $username"
    $startArg = @{}
    $startArg.User = $username
    $startArg.Version = "1.0"

    $restResult = InvokeREST -Endpoint $endpoint -Method "/security/startauthentication" -Token $null -ObjectContent $startArg -IncludeSessionInResult $true
    $startAuthResult = $restResult.RestResult

    # First, see if we need to repeat our call against a different pod
    if($startAuthResult.success -eq $true -and $startAuthResult.Result.PodFqdn -ne $null)
    {
        $endpoint = "https://" + $startAuthResult.Result.PodFqdn
        Write-Verbose "Auth redirected to $endpoint"
        $restResult = InvokeREST -Endpoint $endpoint -Method "/security/startauthentication" -Token $null -ObjectContent $startArg -WebSession $restResult.WebSession -IncludeSessionInResult $true
        $startAuthResult = $restResult.RestResult
    }

    # Get the session id to use in handshaking for MFA
    $authSessionId = $startAuthResult.Result.SessionId
    $tenantId = $startAuthResult.Result.TenantId

    # Also get the collection of challenges we need to satisfy
    $challengeCollection = $startAuthResult.Result.Challenges

    # We need to satisfy 1 of each challenge collection
    for($x = 0; $x -lt $challengeCollection.Count; $x++)
    {
        # Present the user with the options available to them
        for($mechIdx = 0; $mechIdx -lt $challengeCollection[$x].Mechanisms.Count; $mechIdx++)
        {
            $mechDescription = Internal-MechToDescription -Mech $challengeCollection[$x].Mechanisms[$mechIdx]
            Write-Host "Mechanism $mechIdx => $mechDescription"
        }

        [int]$selectedMech = 0
        if($challengeCollection[$x].Mechanisms.Count -ne 1)
        {
            $selectedMech = Read-Host "Choose mechanism"
        }

        $mechResult = Internal-AdvanceForMech -Mech $challengeCollection[$x].Mechanisms[$selectedMech] -Endpoint $endpoint -TenantId $tenantId -SessionId $authSessionId -WebSession $restResult.WebSession
    }

    $finalResult = @{}
    $finalResult.Endpoint = $endpoint
    $finalResult.BearerToken = $restResult.WebSession.Cookies.GetCookies($endpoint)[".ASPXAUTH"].value

    Write-Output $finalResult
}

function Internal-AdvanceForMech {
    param(
        $mech,
        $endpoint,
        $tenantId,
        $sessionId,
        $websession
    )

    $advanceArgs = @{}
    $advanceArgs.TenantId = $tenantId
    $advanceArgs.SessionId = $sessionId
    $advanceArgs.MechanismId = $mech.MechanismId
    $advanceArgs.PersistentLogin = $false

    $prompt = Internal-MechToPrompt -Mech $mech

    # Password, or other 'secret' string
    if($mech.AnswerType -eq "Text" -or $mech.AnswerType -eq "StartTextOob")
    {
        if($mech.AnswerType -eq "StartTextOob")
        {
            $advanceArgs.Action = "StartOOB"
            $advanceResult = (InvokeREST -Endpoint $endpoint -Method "/security/advanceauthentication" -Token $null -ObjectContent $advanceArgs -WebSession $websession -IncludeSessionInResult $true).RestResult
        }

        $responseSecure = Read-Host $prompt -assecurestring
        $responseBstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($responseSecure)
        $responsePlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($responseBstr)

        $advanceArgs.Answer = "PASSWORDGOESHERE"
        $advanceArgs.Action = "Answer"

        # Powershell's ConvertTo-Json likes to escape things, generally this is okay - but passwords shouldn't be touched
        #  so instead we serialize to Json, then substitute the actual password.
        $advanceArgsJson = $advanceArgs | ConvertTo-Json
        $advanceArgsJson = $advanceArgsJson.Replace("PASSWORDGOESHERE", $responsePlain)

        $advanceResult = (InvokeREST -Endpoint $endpoint -Method "/security/advanceauthentication" -Token $null -JsonContent $advanceArgsJson -WebSession $websession -IncludeSessionInResult $true).RestResult
        if($advanceResult.success -ne $true -or
            ($advanceResult.Result.Summary -ne "StartNextChallenge" -and $advanceResult.Result.Summary -ne "LoginSuccess" -and $advanceResult.Result.Summary -ne "NewPackage")
        )
        {
            throw $advanceResult.Message
        }

        return $advanceResult
        break
    }
    # Out of band code or link which must be invoked remotely, we poll server
    elseif($mech.AnswerType -eq "StartOob")
    {
            # We ping advance once to get the OOB mech going, then poll for success or abject fail
            $advanceArgs.Action = "StartOOB"
            $advanceResult = (InvokeREST -Endpoint $endpoint -Method "/security/advanceauthentication" -Token $null -ObjectContent $advanceArgs -WebSession $websession -IncludeSessionInResult $true).RestResult

            Write-Host $prompt
            $advanceArgs.Action = "Poll"
            do
            {
                Write-Host -NoNewline "."
                $advanceResult = (InvokeREST -Endpoint $endpoint -Method "/security/advanceauthentication" -Token $null -ObjectContent $advanceArgs -WebSession $websession -IncludeSessionInResult $true).RestResult
                Start-Sleep -s 1
            } while($advanceResult.success -eq $true -and $advanceResult.Result.Summary -eq "OobPending")

            Write-Host ""   # new line

            # Polling done, did we succeed in our challenge?
            if($advanceResult.success -ne $true -or
                ($advanceResult.Result.Summary -ne "StartNextChallenge" -and $advanceResult.Result.Summary -ne "LoginSuccess" -and $advanceResult.Result.Summary -ne "NewPackage")
            )
            {
                throw $advanceResult.Message
            }
            return $advanceResult
            break
    }
}

# Internal function, maps mechanism to description for selection
function Internal-MechToDescription {
    param(
        $mech
    )

    if($mech.PromptSelectMech -ne $null)
    {
        return $mech.PromptSelectMech
    }

    $mechName = $mech.Name
    switch($mechName)
    {
        "UP" {
            return "Password"
        }
        "SMS" {
            return "SMS to number ending in " + $mech.PartialDeviceAddress
        }
        "EMAIL" {
            return "Email to address ending with " + $mech.PartialAddress
        }
        "PF" {
            return "Phone call to number ending with " + $mech.PartialPhoneNumber
        }
        "OATH" {
            return "OATH compatible client"
        }
        "SQ" {
            return "Security Question"
        }
        default {
            return $mechName
        }
    }
}

# Internal function, maps mechanism to prompt once selected
function Internal-MechToPrompt {
    param(
        $mech
    )

    if($mech.PromptMechChosen -ne $null)
    {
        return $mech.PromptMechChosen
    }

    $mechName = $mech.Name
    switch ($mechName)
    {
        "UP" {
            return "Password: "
        }
        "SMS" {
            return "Enter the code sent via SMS to number ending in " + $mech.PartialDeviceAddress
        }
        "EMAIL" {
            return "Please click or open the link sent to the email to address ending with " + $mech.PartialAddress
        }
        "PF" {
            return "Calling number ending with " + $mech.PartialPhoneNumber + " please follow the spoken prompt"
        }
        "OATH" {
            return "Enter your current OATH code"
        }
        "SQ" {
            return "Enter the response to your secret question"
        }
        default {
            return $mechName
        }
    }
}

function Elevate($token, $challenge, $elevate, $username) {

    Write-Verbose ("Initiating MFA challenge on " + $token.endpoint)

	[string]$global:bearerToken = $token.BearerToken
	$restArg = @{}
	$restArg.Version = "1.0"
	$restArg.ChallengeStateId = $challenge
	$restArg.Elevate = $elevate

	$global:myrestarg = $restArg
    Write-Verbose "Starting challenge"
    $restResult = InvokeREST -Endpoint $token.Endpoint -Method "/security/startchallenge" -Token $bearerToken  -ObjectContent $restArg
	$global:myresult1 = $restResult

	$startAuthResult = $restResult
	$endpoint = $token.Endpoint
	$global:thisendpt = $endpoint
    # Get the session id to use in handshaking for MFA
    $authSessionId = $startAuthResult.Result.SessionId
    $tenantId = $startAuthResult.Result.TenantId

    # Also get the collection of challenges we need to satisfy
    $challengeCollection = $startAuthResult.Result.Challenges

    # We need to satisfy 1 of each challenge collection
    for($x = 0; $x -lt $challengeCollection.Count; $x++)
    {
        # Present the user with the options available to them
        for($mechIdx = 0; $mechIdx -lt $challengeCollection[$x].Mechanisms.Count; $mechIdx++)
        {
            $mechDescription = Internal-MechToDescription -Mech $challengeCollection[$x].Mechanisms[$mechIdx]
            Write-Host "Mechanism $mechIdx => $mechDescription"
        }

        [int]$selectedMech = 0
        if($challengeCollection[$x].Mechanisms.Count -ne 1)
        {
            $selectedMech = Read-Host "Choose mechanism"
        }

        $mechResult = Internal-AdvanceForMech -Mech $challengeCollection[$x].Mechanisms[$selectedMech] -Endpoint $endpoint -TenantId $tenantId -SessionId $authSessionId -WebSession $restResult.WebSession
    }

    $finalResult = @{}
    $finalResult.Endpoint = $endpoint
#    $finalResult.BearerToken = $restResult.WebSession.Cookies.GetCookies($endpoint)[".ASPXAUTH"].value
	$finalResult.BearerToken = $mechResult.Result.Auth

    Write-Output $finalResult
}

Export-ModuleMember -function InvokeREST
Export-ModuleMember -function InteractiveLogin-GetToken
Export-ModuleMember -function Elevate
