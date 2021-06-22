<#  
    Title:          VMware Carbon Black Cloud - Endpoint Standard Data Connector
    Language:       PowerShell
    Version:        1.1
    Author:         Luke Wegener - based on prior work by Microsoft provided under MIT License https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/LICENSE
    Last Modified:  22 June 2021
    Comment:        Modified the CarbonBlackAPI Function to use the Carbon Black Enriched Events Search API as the legacy Events API is deprecated and doesnt appear to work
                    Requires additional environment variable: orgKey used by the API

    DESCRIPTION
    This Function App calls the VMware Carbon Black Cloud - Endpoint Standard (formerly CB Defense) REST API (https://developer.carbonblack.com/reference/carbon-black-cloud/cb-defense/latest/rest-api/) to pull the Carbon Black
    Audit, Notification and Event logs. The response from the CarbonBlack API is recieved in JSON format. This function will build the signature and authorization header 
    needed to post the data to the Log Analytics workspace via the HTTP Data Connector API. The Function App will post each log type to their individual tables in Log Analytics, for example,
    CarbonBlackAuditLogs_CL, CarbonBlackNotifications_CL and CarbonBlackEvents_CL.
#>
# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format
$currentUTCtime = (Get-Date).ToUniversalTime()
$logAnalyticsUri = $env:logAnalyticsUri

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

# The function will call the Carbon Black API and retrieve the Audit, Event, and Notifications Logs
function CarbonBlackAPI()
{
    $workspaceId = $env:workspaceId
    $workspaceSharedKey = $env:workspaceKey
    $hostName = $env:uri
    $apiSecretKey = $env:apiKey
    $apiId = $env:apiId
    $orgKey = $env:orgKey
    $SIEMapiKey = $env:SIEMapiKey
    $SIEMapiId = $env:SIEMapiId
    $time = $env:timeInterval
    $AuditLogTable = "CarbonBlackAuditLogs"
    $EventLogTable = "CarbonBlackEvents"
    $NotificationTable  = "CarbonBlackNotifications"

    $startTime = [System.DateTime]::UtcNow.AddMinutes(-$($time)).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $now = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Remove if addition slash or space added in hostName
    $hostName = $hostName.Trim() -replace "[.*/]$",""

    if ([string]::IsNullOrEmpty($logAnalyticsUri))
    {
        $logAnalyticsUri = "https://" + $workspaceId + ".ods.opinsights.azure.com"
    }
    
    # Returning if the Log Analytics Uri is in incorrect format.
    # Sample format supported: https://" + $customerId + ".ods.opinsights.azure.com
    if($logAnalyticsUri -notmatch 'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$')
    {
        throw "VMware Carbon Black: Invalid Log Analytics Uri."
    }    

    $authHeaders = @{
        "X-Auth-Token" = "$($apiSecretKey)/$($apiId)"
    }

    $auditLogsResult = Invoke-RestMethod -Headers $authHeaders -Uri ([System.Uri]::new("$($hostName)/integrationServices/v3/auditlogs"))

    $eventSearchUri = "$($hostName)/api/investigate/v2/orgs/$($orgKey)/enriched_events/search_jobs"
    
    # Enriched Events Search API requires a POST request with body to initiate event search. Template body definition follows
    $eventSearchBody = [ordered]@{
        criteria = @{
            org_id = @(
                $orgKey
            )
        }
        fields = @('*')
        rows = 10000
        sort = @(
            @{
                field = "device_timestamp"
                order = "asc"
            }
        )
        start = 0
        time_range = @{
            end = $now
            start = $startTime
        }
    }

    $eventSearch = Invoke-RestMethod -Method Post -Headers $authHeaders -Uri ([System.Uri]::new("$($eventSearchUri)")) -Body $($eventSearchBody | ConvertTo-Json) -ContentType 'application/json'

    if ($auditLogsResult.success -eq $true)
    {
        $AuditLogsJSON = $auditLogsResult.notifications | ConvertTo-Json -Depth 5
        if (-not([string]::IsNullOrWhiteSpace($AuditLogsJSON)))
        {
            $responseObj = (ConvertFrom-Json $AuditLogsJSON)
            $status = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($AuditLogsJSON)) -logType $AuditLogTable;
            Write-Host("$($responseObj.count) new Carbon Black Audit Events as of $([DateTime]::UtcNow). Pushed data to Azure sentinel Status code:$($status)")
        }
        else
        {
            Write-Host "No new Carbon Black Audit Events as of $([DateTime]::UtcNow)"
        }
    }
    else
    {
        Write-Host "AuditLogsResult API status failed , Please check."
    }

    if ($eventSearch.job_id) {
        
        $eventSearchStatusUri = "$($hostName)/api/investigate/v1/orgs/$($orgKey)/enriched_events/search_jobs/$($eventSearch.job_id)"
        
        # Wait for search results to become available
        do {
            
            $eventSearchStatus = Invoke-RestMethod -Method Get -Headers $authHeaders -Uri ([System.Uri]::new("$($eventSearchStatusUri)"))
        }
        while ($eventSearchStatus.contacted -ne $eventSearchStatus.completed)

        # Retrieve the search results
        $eventSearchResultUri = "$($hostName)/api/investigate/v2/orgs/$($orgKey)/enriched_events/search_jobs/$($eventSearch.job_id)/results"                      
        $eventSearchResult = Invoke-RestMethod -Method Get -Headers $authHeaders -Uri ([System.Uri]::new("$($eventSearchResultUri)"))
        $EventLogsJSON = $eventSearchResult.results | ConvertTo-Json -Depth 5
        
        if (-not([string]::IsNullOrWhiteSpace($EventLogsJSON))) {

			$totalResult = $eventSearchResult.num_found
			$start= 0
			$rows=100

			# Process the search results, per page
            for ($start; $start -le $totalResult; $start += $rows) {

				$eventPaginationURI = "?start=$($start)&rows=$($rows)"
				Write-Host("Pagination URI : $($eventSearchResultUri)$($eventPaginationURI)")  
				
                $eventSearchResult = Invoke-RestMethod -Method Get -Headers $authHeaders -Uri ([System.Uri]::new("$($eventSearchResultURI)$($eventPaginationURI)"))
				$EventLogsJSON = $eventSearchResult.results | ConvertTo-Json -Depth 5
				
                if (-not([string]::IsNullOrWhiteSpace($EventLogsJSON))) {

					$responseObj = (ConvertFrom-Json $EventLogsJSON)
					$status = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($EventLogsJSON)) -logType $EventLogTable;
					Write-Host("$($responseObj.count) new Carbon Black Events as of $([DateTime]::UtcNow). Pushed data to Azure sentinel Status code:$($status)")
				}
				
                Write-Host("Total Events result count $($eventSearchResult.totalResults) `n Events result count : $($eventSearchResult.results.Count) starting from : $($start)")
			}
        } 
        else {
            
            Write-Host "No new Carbon Black Events as of $([DateTime]::UtcNow)"
        }
    } 
    else {

        Write-Host "EventsResult API status failed , Please check."
    }

    if($SIEMapiKey -eq '<Optional>' -or  $SIEMapiId -eq '<Optional>'  -or [string]::IsNullOrWhitespace($SIEMapiKey) -or  [string]::IsNullOrWhitespace($SIEMapiId))
    {   
         Write-Host "No SIEM API ID and/or Key value was defined."   
    }
    else
    {                
        $authHeaders = @{"X-Auth-Token" = "$($SIEMapiKey)/$($SIEMapiId)"}
        $notifications = Invoke-RestMethod -Headers $authHeaders -Uri ([System.Uri]::new("$($hostName)/integrationServices/v3/notification"))
        if ($notifications.success -eq $true)
        {                
            $NotifLogJson = $notifications.notifications | ConvertTo-Json -Depth 5       
            if (-not([string]::IsNullOrWhiteSpace($NotifLogJson)))
            {
                $responseObj = (ConvertFrom-Json $NotifLogJson)
                $status = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($NotifLogJson)) -logType $NotificationTable;
                Write-Host("$($responseObj.count) new Carbon Black Notifications as of $([DateTime]::UtcNow). Pushed data to Azure sentinel Status code:$($status)")
            }
            else
            {
                    Write-Host "No new Carbon Black Notifications as of $([DateTime]::UtcNow)"
            }
        }
        else
        {
            Write-Host "Notifications API status failed , Please check."
        }
    }    
}

# Create the function to create the authorization signature
function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date;
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource;
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash);
    $keyBytes = [Convert]::FromBase64String($sharedKey);
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256;
    $sha256.Key = $keyBytes;
    $calculatedHash = $sha256.ComputeHash($bytesToHash);
    $encodedHash = [Convert]::ToBase64String($calculatedHash);
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash;
    return $authorization;
}

# Create the function to create and post the request
function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $TimeStampField = "DateValue"
    $method = "POST";
    $contentType = "application/json";
    $resource = "/api/logs";
    $rfc1123date = [DateTime]::UtcNow.ToString("r");
    $contentLength = $body.Length;
    $signature = Build-Signature -customerId $customerId -sharedKey $sharedKey -date $rfc1123date -contentLength $contentLength -method $method -contentType $contentType -resource $resource;
    $logAnalyticsUri = $logAnalyticsUri + $resource + "?api-version=2016-04-01"
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    };
    $response = Invoke-WebRequest -Body $body -Uri $logAnalyticsUri -Method $method -ContentType $contentType -Headers $headers -UseBasicParsing
    return $response.StatusCode
}

# Execute the Function to Pull CarbonBlack data and Post to the Log Analytics Workspace
CarbonBlackAPI

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"