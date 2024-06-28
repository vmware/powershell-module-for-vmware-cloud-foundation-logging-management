# Copyright 2024 Broadcom. All Rights Reserved.
# SPDX-License-Identifier: BSD-2

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Enable communication with self-signed certificates when using Powershell Core. If you require all communications
# to be secure and do not wish to allow communication with self-signed certificates, remove lines 19-39 before
# importing the module.

if ($PSEdition -eq 'Core') {
    $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck", $true)
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

if ($PSEdition -eq 'Desktop') {
    # Allow communication with self-signed certificates when using Windows PowerShell
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null


    if ("TrustAllCertificatePolicy" -as [type]) {} else {
        Add-Type @"
	using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertificatePolicy : ICertificatePolicy {
        public TrustAllCertificatePolicy() {}
		public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate certificate,
            WebRequest wRequest, int certificateProblem) {
            return true;
        }
	}
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertificatePolicy
    }
}

##########################################################################
#Region     Begin Non-exported Functions                            ######

Function Get-Password {
    param (
        [string]$username,
        [string]$password
    )

    if ([string]::IsNullOrEmpty($password)) {
        $secureString = Read-Host -Prompt "Enter the password for $username" -AsSecureString
        $password = ConvertFrom-SecureString $secureString -AsPlainText
    }
    return $password
}

#EndRegion  End Non-exported Functions                              ######
##########################################################################

##########################################################################
#Region     Begin Global Variables                                  ######

Set-Variable -Name "successStatus" -Value "SUCCESSFUL" -Scope Global
Set-Variable -Name "failureStatus" -Value "FAILED" -Scope Global
Set-Variable -Name "skippedStatus" -Value "SKIPPED" -Scope Global
Set-Variable -Name "preValidationFailureStatus" -Value "PRE_VALIDATION_FAILED" -Scope Global
Set-Variable -Name "postValidationFailureStatus" -Value "POST_VALIDATION_FAILED" -Scope Global
$global:esxiStatus = $null
$global:vcenterStatus = $null
$global:nsxStatus = $null
$global:sddcStatus = $null
$global:ariaLifecycleStatus = $null
$global:syslogProtocols = @("tcp", "udp")
$global:cfapiProtocols = @("http", "https")

#EndRegion  End Global Variables                                    ######
##########################################################################

##########################################################################
#Region     Begin Invoke Functions                                  ######

Function Invoke-LoggingConfigReport {
    <#
        .SYNOPSIS
        Generates an logging configuration report for a workload domain or all workload domains.

        .DESCRIPTION
        The Invoke-LoggingConfigAuditReport generates a logging configuration report for a VMware Cloud Foundation instance.

        .EXAMPLE
        Invoke-LoggingConfigReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser administrator@vsphere.local -sddcManagerPass VMw@re123! -sddcManagerLocalUser vcf -sddcManagerLocalPass VMw@re1! -reportPath "F:\Reporting" -darkMode -allDomains
        This example runs a logging configuration report for all workload domains within an SDDC Manager instance.

        .EXAMPLE
        Invoke-LoggingConfigReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser administrator@vsphere.local -sddcManagerPass VMw@re123! -sddcManagerLocalUser vcf -sddcManagerLocalPass VMw@re1! -reportPath "F:\Reporting" -darkMode -workloadDomain sfo-m01
        This example runs a logging configuration report for the provided workload domain within an SDDC Manager instance.

        .PARAMETER sddcManagerFqdn
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER sddcManagerUser
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER sddcManagerPass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER sddcManagerLocalUser
        The username to authenticate to the SDDC Manager appliance.

        .PARAMETER sddcManagerLocalPass
        The password to authenticate to the SDDC Manager appliance.

        .PARAMETER reportPath
        The path to save the report to.

        .PARAMETER allDomains
        Switch to run the report for all workload domains.

        .PARAMETER workloadDomain
        Switch to run the report for a specific workload domain.

        .PARAMETER darkMode
        Switch to use dark mode for the report.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerUser,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$sddcManagerPass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$sddcManagerLocalUser,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$sddcManagerLocalPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportPath,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$darkMode
    )

    $sddcManagerPass = Get-Password -username $sddcManagerUser -password $sddcManagerPass
    $sddcManagerLocalPass = Get-Password -username "root" -password $sddcManagerLocalPass

    Try {
        Clear-Host; Write-Host ""
        if (Test-VCFConnection -server $sddcManagerFqdn) {
            if (Test-VCFAuthentication -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass) {
                if ($reportPath.EndsWith("\") -or $reportPath.EndsWith("/")) {
                    $reportPath = $reportPath.TrimEnd("\", "/")
                }
                if (!(Test-Path -Path $reportPath)) { Write-Warning "Unable to locate report path $reportPath. Enter a valid path and retry."; Write-Host ""; Break }
                Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
                $defaultReport = Set-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -filename "logging-report"
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $reportname = $defaultReport.Split('.')[0] + "-" + $sddcManagerFqdn.Split(".")[0] + ".htm"
                    $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
                    $commandSwitch = "-allDomains"
                } else {
                    $reportname = $defaultReport.Split('.')[0] + "-" + $workloadDomain + ".htm"
                    $workflowMessage = "Workload Domain ($workloadDomain)"
                    $commandSwitch = "-workloadDomain $workloadDomain"
                }

                Write-LogMessage -Type INFO -Message "Starting the process of generating a logging configuration report for $workflowMessage." -Colour Yellow
                Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile."
                Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName."

                Write-LogMessage -Type INFO -Message "Collecting logging configuration across your $workflowMessage."

                $esxiLogConfig = Invoke-Expression "Publish-EsxiLoggingConfig -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass $($commandSwitch)"
                $vcenterLogConfig = Invoke-Expression "Publish-VcenterLoggingConfig -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass $($commandSwitch)"
                $sddcManagerLogConfig = Invoke-Expression "Publish-SddcManagerLoggingConfig -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -localUser $sddcManagerLocalUser -localPass $sddcManagerLocalPass"
                $nsxLogConfig = Invoke-Expression "Publish-NsxLoggingConfig -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass $($commandSwitch)"
                $ariaLifecycleLogConfig = Invoke-Expression "Publish-AriaLifecycleLoggingConfig -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass"
                $ariaOpsLogConfig = Invoke-Expression "Publish-AriaOpsLoggingConfig -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass"
                $ariaAutomationLogConfig = Invoke-Expression "Publish-AriaAutomationLoggingConfig -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass"
                $ariaOpsLogsLogConfig = Invoke-Expression "Publish-AriaOpsLogsLoggingConfig -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass"

                # Combine all information gathered into a single HTML report
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $reportData = "<h1>SDDC Manager: $sddcManagerFqdn</h1>"
                } else {
                    $reportData = "<h1>Workload Domain: $workloadDomain</h1>"
                }

                $reportData += $esxiLogConfig
                $reportData += $vcenterLogConfig
                $reportData += $sddcManagerLogConfig
                $reportData += $nsxLogConfig
                $reportData += $ariaLifecycleLogConfig
                $reportData += $ariaOpsLogConfig
                $reportData += $ariaAutomationLogConfig
                $reportData += $ariaOpsLogsLogConfig

                if ($PsBoundParameters.ContainsKey("darkMode")) {
                    $reportHeader = Save-ClarityReportHeader -dark
                } else {
                    $reportHeader = Save-ClarityReportHeader
                }
                $reportNavigation = Save-ClarityReportNavigation
                $reportFooter = Save-ClarityReportFooter

                $report = $reportHeader
                $report += $reportNavigation
                $report += $reportData
                $report += $reportFooter

                # Generate the report to an HTML file and then open it in the default browser
                Write-LogMessage -Type INFO -Message "Generating the Final Report and Saving to ($reportName)."
                $report | Out-File $reportName
                if (($PSVersionTable.OS).Split(' ')[0] -ne "Linux") {
                    Invoke-Item $reportName
                }
            }
        }
    } Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Invoke-LoggingConfigReport

#EndRegion  End Invoke Functions                                    ######
##########################################################################

##########################################################################
#Region     Begin Publish Functions                                 ######

Function Publish-EsxiLoggingConfig {
    <#
        .SYNOPSIS
        Publishes the logging configuration for ESXi hosts.

        .DESCRIPTION
        The Publish-EsxiLoggingConfig cmdlet returns logging configuration of all ESXi hosts.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server

        .EXAMPLE
        Publish-EsxiLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -allDomains
        This example returns the logging configuration of all ESXi hosts in your VCF environment.

        .EXAMPLE
        Publish-EsxiLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -workloadDomain sfo-w01
        This example returns the logging configuration of all ESXi hosts in the provided workload domain.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER allDomains
        Switch to publish the logging configuration for all workload domains.

        .PARAMETER workloadDomain
        Switch to publish the logging configuration for a specific workload domain.

        .PARAMETER json
        Switch to publish the logging configuration in JSON format.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$json
    )

    $pass = Get-Password -username $user -password $pass
    $preHtmlContent = '<a id="esxi-logging-configuration"></a><h3>ESXi</h3>'

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $esxiLogConfigObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('workloadDomain')) {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $workloadDomain)) {
                        if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                $clusters = Get-Cluster -Server $vcfVcenterDetails.fqdn
                                foreach ($cluster in $clusters) {
                                    $command = "Request-EsxiLoggingConfig -server $server -user $user -pass $pass -cluster $($cluster.name) -domain $workloadDomain"
                                    $esxiLogConfig = Invoke-Expression $command; $esxiLogConfigObject += $esxiLogConfig
                                }
                            }
                        }
                    }
                } elseif ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains ) {
                        if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain.name)) {
                            if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                                if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                    $clusters = Get-Cluster -Server $vcfVcenterDetails.fqdn
                                    foreach ($cluster in $clusters) {
                                        $command = "Request-EsxiLoggingConfig -server $server -user $user -pass $pass -cluster $($cluster.name) -domain $($domain.name)"
                                        $esxiLogConfig = Invoke-Expression $command; $esxiLogConfigObject += $esxiLogConfig
                                    }
                                }
                            }
                        }
                    }
                }
                if ($PsBoundParameters.ContainsKey('json')) {
                    $esxiLogConfigObject | ConvertTo-Json
                } else {
                    if ($esxiLogConfigObject) {
                        $esxiLogConfigObject = $esxiLogConfigObject | Sort-Object 'Workload Domain', 'Cluster', 'FQDN' | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
                    } else {
                        $esxiLogConfigObject = New-Object -TypeName psobject
                        $esxiLogConfigObject | Add-Member -notepropertyname "Error" -notepropertyvalue "Unable to retrieve the configuration details. Please check the script logs."
                        $esxiLogConfigObject = $esxiLogConfigObject | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
                    }
                    $esxiLogConfigObject = Convert-CssClassStyle -htmldata $esxiLogConfigObject
                    $esxiLogConfigObject
                }
            }
        }
    } Catch {
        Debug-CatchWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}

Export-ModuleMember -Function Publish-EsxiLoggingConfig

Function Publish-VcenterLoggingConfig {

    <#
        .SYNOPSIS
        Publishes the logging configuration for vCenter Server instances.

        .DESCRIPTION
        The Publish-VcenterLoggingConfig cmdlet returns logging configuration of all vCenter Server instances.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server

        .EXAMPLE
        Publish-VcenterLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -allDomains
        This example returns the logging configuration of all vCenter Server instances in your VCF environment.

        .EXAMPLE
        Publish-VcenterLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -workloadDomain sfo-w01
        This example returns the logging configuration of the vCenter server in the provided workload domain

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER allDomains
        Switch to publish the logging configuration for all workload domains.

        .PARAMETER workloadDomain
        Switch to publish the logging configuration for a specific workload domain.

        .PARAMETER json
        Switch to publish the logging configuration in JSON format.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$json
    )

    $pass = Get-Password -username $user -password $pass
    $preHtmlContent = '<a id="vcenter-logging-configuration"></a><h3>vCenter Server</h3>'

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $vCenterLogConfigObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('workloadDomain')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain | Where-Object { $_.name -eq $workloadDomain }
                } elseif ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                }
                foreach ($domain in $allWorkloadDomains ) {
                    $command = "Request-VcenterLoggingConfig -server $server -user $user -pass $pass -domain $($domain.name)"
                    $vCenterLogConfig = Invoke-Expression $command; $vCenterLogConfigObject += $vCenterLogConfig
                }

                if ($PsBoundParameters.ContainsKey('json')) {
                    $vCenterLogConfigObject | ConvertTo-Json
                } else {
                    if ($vCenterLogConfigObject) {
                        $vCenterLogConfigObject = $vCenterLogConfigObject | Sort-Object 'Workload Domain', 'FQDN' | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
                    } else {
                        $vCenterLogConfigObject = New-Object -TypeName psobject
                        $vCenterLogConfigObject | Add-Member -notepropertyname "Error" -notepropertyvalue "Unable to retrieve the configuration details. Please check the script logs."
                        $vCenterLogConfigObject = $vCenterLogConfigObject | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
                    }
                    $vCenterLogConfigObject = Convert-CssClassStyle -htmldata $vCenterLogConfigObject
                    $vCenterLogConfigObject
                }
            }
        }
    } Catch {
        Debug-CatchWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Publish-VcenterLoggingConfig

Function Publish-SddcManagerLoggingConfig {
    <#
        .SYNOPSIS
        Publishes the logging configuration for SDDC Manager.

        .DESCRIPTION
        The Publish-SddcManagerLoggingConfig cmdlet returns logging configuration of the SDDC Manager.

        .EXAMPLE
        Publish-SddcManagerLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -localUser vcf -localPass VMw@re1!
        This example returns the logging configuration of the SDDC Manager in your VCF environment.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER localUser
        The username to authenticate to the SDDC Manager appliance.

        .PARAMETER localPass
        The password to authenticate to the SDDC Manager appliance.

        .PARAMETER json
        Switch to publish the logging configuration in JSON format.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$localUser,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$localPass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$json
    )

    $pass = Get-Password -username $user -password $pass
    $preHtmlContent = '<a id="sddcManager-logging-configuration"></a><h3>SDDC Manager</h3>'

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $SddcManagerLogConfigObject = New-Object System.Collections.ArrayList
                $command = "Request-SddcManagerLoggingConfig -server $server -user $user -pass $pass -localUser $localUser -localPass $localPass"
                $SddcManagerLogConfig = Invoke-Expression $command; $SddcManagerLogConfigObject += $SddcManagerLogConfig
            }
        }

        if ($PsBoundParameters.ContainsKey('json')) {
            $SddcManagerLogConfigObject | ConvertTo-Json
        } else {
            if ($SddcManagerLogConfigObject) {
                $SddcManagerLogConfigObject = $SddcManagerLogConfigObject | Sort-Object 'Workload Domain', 'FQDN' | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
            } else {
                $SddcManagerLogConfigObject = New-Object -TypeName psobject
                $SddcManagerLogConfigObject | Add-Member -notepropertyname "Error" -notepropertyvalue "Unable to retrieve the configuration details. Please check the script logs."
                $SddcManagerLogConfigObject = $SddcManagerLogConfigObject | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
            }
            $SddcManagerLogConfigObject = Convert-CssClassStyle -htmldata $SddcManagerLogConfigObject
            $SddcManagerLogConfigObject
        }
    } Catch {
        Debug-CatchWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Publish-SddcManagerLoggingConfig

Function Publish-NsxLoggingConfig {
    <#
        .SYNOPSIS
        Publishes the logging configuration for NSX Managers and NSX Edges.

        .DESCRIPTION
        The Publish-NsxLoggingConfig cmdlet returns logging configuration of NSX Managers and NSX Edges.

        .EXAMPLE
        Publish-NsxLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -alldomains
        This example returns the logging configuration of the all the NSX Managers and NSX Edge Nodes in your VCF environment.

        .EXAMPLE
        Publish-NsxLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -workoadDomain sfo-m01
        This example returns the logging configuration of the NSX Manager and NSX Edge Nodes in the given workload domain.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER allDomains
        Switch to publish the logging configuration for all workload domains.

        .PARAMETER workloadDomain
        Switch to publish the logging configuration for a specific workload domain.

        .PARAMETER json
        Switch to publish the logging configuration in JSON format.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$json
    )

    $pass = Get-Password -username $user -password $pass
    $preHtmlContent = '<a id="nsx-logging-configuration"></a><h3>NSX</h3>'

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $nsxLogConfigObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('workloadDomain')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain | Where-Object { $_.name -eq $workloadDomain }
                } elseif ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                }
                foreach ($domain in $allWorkloadDomains ) {
                    $command = "Request-NsxLoggingConfig -server $server -user $user -pass $pass -domain $($domain.name)"
                    $nsxLogConfig = Invoke-Expression $command; $nsxLogConfigObject += $nsxLogConfig
                }

                if ($PsBoundParameters.ContainsKey('json')) {
                    $nsxLogConfigObject | ConvertTo-Json
                } else {
                    if ($nsxLogConfigObject) {
                        $nsxLogConfigObject = $nsxLogConfigObject | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
                    } else {
                        $nsxLogConfigObject = New-Object -TypeName psobject
                        $nsxLogConfigObject | Add-Member -notepropertyname "Error" -notepropertyvalue "Unable to retrieve the configuration details. Please check the script logs."
                        $nsxLogConfigObject = $nsxLogConfigObject | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
                    }
                    $nsxLogConfigObject = Convert-CssClassStyle -htmldata $nsxLogConfigObject
                    $nsxLogConfigObject
                }
            }
        }
    } Catch {
        Debug-CatchWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Publish-NsxLoggingConfig

Function Publish-AriaOpsLoggingConfig {
    <#
        .SYNOPSIS
        Publishes the logging configuration for VMware Aria Operations.

        .DESCRIPTION
        The Publish-AriaOpsLoggingConfig cmdlet returns logging configuration of VMware Aria Operations.

        .EXAMPLE
        Publish-AriaOpsLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123!
        This example returns the logging configuration of the VMware Aria Operations in your VCF environment.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER json
        Switch to publish the logging configuration in JSON format.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$json
    )

    $pass = Get-Password -username $user -password $pass
    $preHtmlContent = '<a id="aria-ops-logging-configuration"></a><h3>Aria Operations</h3>'
    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $ariaOpsLogConfigObject = New-Object System.Collections.ArrayList
                $command = "Request-AriaOpsLoggingConfig -server $server -user $user -pass $pass"
                $ariaOpsLogConfig = Invoke-Expression $command; $ariaOpsLogConfigObject += $ariaOpsLogConfig
            }
        }

        if ($PsBoundParameters.ContainsKey('json')) {
            $ariaOpsLogConfigObject | ConvertTo-Json
        } else {
            if ($ariaOpsLogConfigObject) {
                $ariaOpsLogConfigObject = $ariaOpsLogConfigObject | Sort-Object 'FQDN (Load Balancer)' | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
            } else {
                $ariaOpsLogConfigObject = New-Object -TypeName psobject
                $ariaOpsLogConfigObject | Add-Member -notepropertyname "Error" -notepropertyvalue "Unable to retrieve the configuration details. Please check the script logs."
                $ariaOpsLogConfigObject = $ariaOpsLogConfigObject | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
            }
            $ariaOpsLogConfigObject = Convert-CssClassStyle -htmldata $ariaOpsLogConfigObject
            $ariaOpsLogConfigObject
        }
    } Catch {
        Debug-CatchWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Publish-AriaOpsLoggingConfig

Function Publish-AriaAutomationLoggingConfig {
    <#
        .SYNOPSIS
        Publishes the logging configuration for VMware Aria Automation.

        .DESCRIPTION
        The Publish-AriaAutomationLoggingConfig cmdlet returns logging configuration of VMware Aria Automation.

        .EXAMPLE
        Publish-AriaAutomationLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123!
        This example returns the logging configuration of the VMware Aria Automation in your VCF environment.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER json
        Switch to publish the logging configuration in JSON format.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$json
    )

    $pass = Get-Password -username $user -password $pass
    $preHtmlContent = '<a id="aria-automation-logging-configuration"></a><h3>Aria Automation</h3>'

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $ariaAutomationLogConfigObject = New-Object System.Collections.ArrayList
                $command = "Request-AriaAutomationLoggingConfig -server $server -user $user -pass $pass"
                $ariaAutomationLogConfig = Invoke-Expression $command; $ariaAutomationLogConfigObject += $ariaAutomationLogConfig
            }
        }

        if ($PsBoundParameters.ContainsKey('json')) {
            $ariaAutomationLogConfigObject | ConvertTo-Json
        } else {
            if ($ariaAutomationLogConfigObject) {
                $ariaAutomationLogConfigObject = $ariaAutomationLogConfigObject | Sort-Object 'FQDN (Load Balancer)' | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
            } else {
                $ariaAutomationLogConfigObject = New-Object -TypeName psobject
                $ariaAutomationLogConfigObject | Add-Member -notepropertyname "Error" -notepropertyvalue "Unable to retrieve the configuration details. Please check the script logs."
                $ariaAutomationLogConfigObject = $ariaAutomationLogConfigObject | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
            }
            $ariaAutomationLogConfigObject = Convert-CssClassStyle -htmldata $ariaAutomationLogConfigObject
            $ariaAutomationLogConfigObject
        }
    } Catch {
        Debug-CatchWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Publish-AriaAutomationLoggingConfig

Function Publish-AriaLifecycleLoggingConfig {
    <#
        .SYNOPSIS
        Publishes the logging configuration for VMware Suite Aria Lifecycle.

        .DESCRIPTION
        The Publish-AriaLifecycleLoggingConfig cmdlet returns logging configuration of VMware Aria Suite Lifecycle.

        .EXAMPLE
        Publish-AriaLifecycleLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123!
        This example returns the logging configuration of the VMware Aria Suite Lifecycle in your VCF environment.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER json
        Switch to publish the logging configuration in JSON format.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$json
    )

    $pass = Get-Password -username $user -password $pass
    $preHtmlContent = '<a id="aria-lifecycle-logging-configuration"></a><h3>Aria Lifecycle</h3>'

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $command = "Request-AriaLifecycleLoggingConfig -server $server -user $user -pass $pass"
                $ariaLifecycleLogConfig = Invoke-Expression $command
            }
        }

        if ($PsBoundParameters.ContainsKey('json')) {
            $ariaLifecycleLogConfig | ConvertTo-Json
        } else {
            if ($ariaLifecycleLogConfig) {
                $ariaLifecycleLogConfig = $ariaLifecycleLogConfig | Sort-Object 'FQDN' | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
            } else {
                $ariaLifecycleLogConfig = New-Object -TypeName psobject
                $ariaLifecycleLogConfig | Add-Member -notepropertyname "Error" -notepropertyvalue "Unable to retrieve the configuration details. Please check the script logs."
                $ariaLifecycleLogConfig = $ariaOpsLogConfigObject | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
            }
            $ariaLifecycleLogConfig = Convert-CssClassStyle -htmldata $ariaLifecycleLogConfig
            $ariaLifecycleLogConfig
        }
    } Catch {
        Debug-CatchWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Publish-AriaLifecycleLoggingConfig

Function Publish-AriaOpsLogsLoggingConfig {
    <#
        .SYNOPSIS
        Publishes the logging configuration for VMware Aria Operations for Logs.

        .DESCRIPTION
        The Publish-AriaOpsLogsLoggingConfig cmdlet returns log forwarders and agents configuration from VMware Aria Operations for Logs.

        .EXAMPLE
        Publish-AriaOpsLogsLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123!
        This example returns the logging configuration of the VMware Aria Operations for Logs in your VCF environment.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER json
        Switch to publish the logging configuration in JSON format.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$json
    )

    $pass = Get-Password -username $user -password $pass
    $preHtmlContentAgents = '<a id="ariaopsforlogs-agents"></a><h3>Agents Status on Aria Operations for Logs</h3>'
    $preHtmlContentForwarders = '<a id="ariaopsforlog-forwarders"></a><h3>Log Forwarders on Aria Operations for Logs</h3>'

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $ariaOpsLogsLogConfigObject = New-Object System.Collections.ArrayList
                $command = "Request-AriaOpsLogsLoggingConfig -server $server -user $user -pass $pass"
                $ariaOpsLogsLogConfig = Invoke-Expression $command; $ariaOpsLogsLogConfigObject += $ariaOpsLogsLogConfig
                $agentConfig = $ariaOpsLogsLogConfigObject.Agents
                $forwardersConfig = $ariaOpsLogsLogConfigObject.Forwarders
            }
        }

        if ($PsBoundParameters.ContainsKey('json')) {
            $ariaOpsLogsLogConfigObject | ConvertTo-Json
        } else {
            if ($ariaOpsLogsLogConfigObject) {
                $agentConfig = $agentConfig | Sort-Object 'Hostname' | ConvertTo-Html -Fragment -PreContent $preHtmlContentAgents -As Table
                $forwardersConfig = $forwardersConfig | Sort-Object 'FQDN' | ConvertTo-Html -Fragment -PreContent $preHtmlContentForwarders -As Table
                $agentConfig = Convert-CssClassStyle -htmldata $agentConfig
                $forwardersConfig = Convert-CssClassStyle -htmldata $forwardersConfig
                $ariaOpsLogsLogConfigObject = $agentConfig + $forwardersConfig
            } else {
                $ariaOpsLogsLogConfigObject = New-Object -TypeName psobject
                $ariaOpsLogsLogConfigObject | Add-Member -notepropertyname "Error" -notepropertyvalue "Unable to retrieve the configuration details. Please check the script logs."
                $ariaOpsLogsLogConfigObject = $ariaOpsLogsLogConfigObject | ConvertTo-Html -Fragment -PreContent $preHtmlContent -As Table
                $ariaOpsLogsLogConfigObject = Convert-CssClassStyle -htmldata $ariaOpsLogsLogConfigObject
            }
            $ariaOpsLogsLogConfigObject
        }
    } Catch {
        Debug-CatchWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Publish-AriaOpsLogsLoggingConfig

#EndRegion  End Publish Functions                                   ######
##########################################################################

##########################################################################
#Region     Begin Request Functions                                 ######

Function Request-EsxiLoggingConfig {
    <#
        .SYNOPSIS
        Publishes the logging configuration for ESXi hosts.

        .DESCRIPTION
        The Publish-EsxiLoggingConfig cmdlet returns logging configuration of all ESXi hosts.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server

        .EXAMPLE
        Request-EsxiLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01
        This example returns the logging configuration of all ESXi hosts in your VCF environment.

        .EXAMPLE
        Request-EsxiLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01
        This example returns the logging configuration of all ESXi hosts in the provided workload domain.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain to retrieve the logging configuration from.

        .PARAMETER cluster
        The name of the cluster to retrieve the logging configuration from.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$cluster
    )

    $pass = Get-Password -username $user -password $pass

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                        if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                if (Get-Cluster | Where-Object { $_.Name -eq $cluster }) {
                                    $esxiLogConfig = New-Object System.Collections.Generic.List[System.Object]
                                    $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
                                    if ($esxiHosts) {
                                        Foreach ($esxiHost in $esxiHosts) {
                                            $esxiConfigObj = New-Object -TypeName psobject
                                            $esxiConfigObj | Add-Member -notepropertyname "Workload Domain" -notepropertyvalue $domain
                                            $esxiConfigObj | Add-Member -notepropertyname "Cluster" -notepropertyvalue $cluster
                                            $esxiConfigObj | Add-Member -notepropertyname "FQDN" -notepropertyvalue $esxiHost
                                            $esxiConfig = Get-VMHostSysLogServer -VMHost $esxiHost
                                            if ($esxiConfig) {
                                                $protocol = $esxiConfig.Host.Split("://")[0]
                                                $server = $esxiConfig.Host.Split("://")[1]
                                                $esxiConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue $server
                                                $esxiConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue (Convert-ProtocolToString -protocol $protocol)
                                                $esxiConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue $esxiConfig.Port
                                                $esxiConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'GREEN'
                                            } else {
                                                $esxiConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue "Not Available"
                                                $esxiConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue "Not Available"
                                                $esxiConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue "Not Available"
                                                $esxiConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'RED'
                                            }
                                            $esxiLogConfig.Add($esxiConfigObj)
                                            Remove-Variable -Name esxiConfigObj
                                        }
                                        return $esxiLogConfig
                                    } else {
                                        Write-Warning "No ESXi hosts found within cluster named ($cluster): PRE_VALIDATION_FAILED"
                                    }
                                } else {
                                    Write-Error "Unable to locate Cluster ($cluster) in vCenter Server ($($vcfVcenterDetails.fqdn)): PRE_VALIDATION_FAILED"
                                }
                            }
                        }
                    }
                } else {
                    Write-Error "Unable to find Workload Domain named ($domain) in the inventory of SDDC Manager ($server): PRE_VALIDATION_FAILED"
                }
            }
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Request-EsxiLoggingConfig

Function Request-VcenterLoggingConfig {
    <#
        .SYNOPSIS
        Requests the logging configuration for vCenter Server in a given domain.

        .DESCRIPTION
        The Request-VcenterLoggingConfig cmdlet returns logging configuration the vCenter Server in the given domain.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server

        .EXAMPLE
        Request-VcenterLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01
        This example returns the logging configuration of the vCenter Server in the provided workload domain

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain to retrieve the logging configuration from.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain
    )

    $pass = Get-Password -username $user -password $pass

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                        if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                $vcenterConfig = Invoke-GetLoggingForwarding
                                $vcenterConfigObj = New-Object -TypeName psobject
                                $vcenterConfigObj | Add-Member -notepropertyname "Workload Domain" -notepropertyvalue $domain
                                $vcenterConfigObj | Add-Member -notepropertyname "FQDN" -notepropertyvalue $vcfVcenterDetails.fqdn

                                if ($vcenterConfig) {
                                    $vcenterConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue $vcenterConfig.hostname
                                    $vcenterConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue (Convert-ProtocolToString -protocol $vcenterConfig.Protocol)
                                    $vcenterConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue $vcenterConfig.Port
                                    $vcenterConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'GREEN'
                                } else {
                                    $vcenterConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue "Not Available"
                                    $vcenterConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue "Not Available"
                                    $vcenterConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue "Not Available"
                                    $vcenterConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'RED'
                                }
                                $vCenterLogConfig = New-Object System.Collections.Generic.List[System.Object]
                                $vCenterLogConfig.Add($vcenterConfigObj)
                                Remove-Variable -Name vcenterConfigObj
                            }
                            return $vCenterLogConfig
                        }
                    } else {
                        Write-Warning "No vCenter Server found $($vcfVcenterDetails.fqdn): PRE_VALIDATION_FAILED"
                    }
                } else {
                    Write-Error "Unable to find Workload Domain named ($domain) in the inventory of SDDC Manager ($server): PRE_VALIDATION_FAILED"
                }
            }
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Request-VcenterLoggingConfig

Function Request-SddcManagerLoggingConfig {
    <#
        .SYNOPSIS
        Requests the logging configuration for SDDC Manager.

        .DESCRIPTION
        The Request-SddcManagerLoggingConfig gets the logging configuration from SDDC Manager.

        .EXAMPLE
        Request-SddcManagerLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -localUser vcf -localPass VMw@re1!
        This example gets the logging configuration from SDDC Manager.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER localUser
        The username to authenticate to the SDDC Manager appliance.

        .PARAMETER localPass
        The password to authenticate to the SDDC Manager appliance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$localUser,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$localPass
    )

    $scriptCommand = "cat /var/lib/loginsight-agent/liagent.ini"
    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if ($domain = Get-VCFWorkloadDomain | Where-Object { $_.type -eq "MANAGEMENT" }) {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain.name)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            $sddcManagerInstance = Get-VCFManager
                            $sddcManagerVmName = $sddcManagerInstance.fqdn.Split(".")[0]
                            $output = Invoke-VMScript -VM $sddcManagerVmName -ScriptText $scriptCommand -GuestUser $localUser -GuestPassword $localPass -Server $vcfVcenterDetails.fqdn -ErrorAction Stop
                            if ($output) {
                                $content = $output.ScriptOutput
                                $hostnameRegex = 'hostname=(.*)'
                                $protoRegex = 'proto=(.*)'
                                $portRegex = 'port=(\d+)'

                                $hostname = [regex]::Match($content, $hostnameRegex).Groups[1].Value
                                $proto = [regex]::Match($content, $protoRegex).Groups[1].Value
                                $port = [regex]::Match($content, $portRegex).Groups[1].Value
                                $sddcMgrConfigObj = New-Object -TypeName psobject
                                $sddcMgrConfigObj | Add-Member -notepropertyname "Workload Domain" -notepropertyvalue $domain.name
                                $sddcMgrConfigObj | Add-Member -notepropertyname "FQDN" -notepropertyvalue $server

                                if ($content) {
                                    $sddcMgrConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue $hostname
                                    $sddcMgrConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue (Convert-ProtocolToString -protocol $proto)
                                    $sddcMgrConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue $port
                                    $sddcMgrConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'GREEN'
                                } else {
                                    $sddcMgrConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue "Not Available"
                                    $sddcMgrConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue "Not Available"
                                    $sddcMgrConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue "Not Available"
                                    $sddcMgrConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'RED'
                                }
                                $sddcMgrLogConfig = New-Object System.Collections.Generic.List[System.Object]
                                $sddcMgrLogConfig.Add($sddcMgrConfigObj)
                                return $sddcMgrLogConfig
                            } else {
                                Write-Error "Unable to read liagent.ini configuration from SDDC Manager."
                            }
                        } else {
                            Write-Warning "No vCenter Server found $($vcfVcenterDetails.fqdn): PRE_VALIDATION_FAILED"
                        }
                    }
                }
            } else {
                Write-Error "Invalid Credentials for SDDC Manager ($server): PRE_VALIDATION_FAILED"
            }
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Request-SddcManagerLoggingConfig

Function Request-NsxLoggingConfig {
    <#
		.SYNOPSIS
        Return the logging configuration from NSX Manager and NSX Edge Nodes.

        .DESCRIPTION
        The Request-NsxLoggingConfig cmdlet retrieves the logging configuration from NSX Manager and NSX Edge Nodes.
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to NSX Manager
        - Gathers the NSX Edge Node details from NSX Manager cluster

        .EXAMPLE
        Request-NsxLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01
        This example retrieves the logging configuration from NSX Manager and NSX Edge Nodes for the given workload domain.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager.

        .PARAMETER user
        The username to authenticate to the SDDC Manager.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager.

        .PARAMETER domain
        The name of the workload domain to run against.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if ($nsxtManagerDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain -listNodes) {
                    if (Test-NSXTConnection -server $nsxtManagerDetails.fqdn) {
                        if (Test-NSXTAuthentication -server $nsxtManagerDetails.fqdn -user $nsxtManagerDetails.adminUser -pass $nsxtManagerDetails.AdminPass) {
                            $nsxMgrLogConfig = New-Object System.Collections.Generic.List[System.Object]
                            $nsxMgrConfigObj = New-Object -TypeName psobject
                            $nsxMgrConfig = Get-NsxtSyslogExporter -node
                            $nsxMgrConfigObj | Add-Member -notepropertyname "Workload Domain" -notepropertyvalue $domain
                            $nsxMgrConfigObj | Add-Member -notepropertyname "Resource" -notepropertyvalue "NSX Manager"
                            $nsxMgrConfigObj | Add-Member -notepropertyname "FQDN/Name" -notepropertyvalue $nsxtManagerDetails.fqdn

                            if ($nsxMgrConfig) {
                                $nsxMgrConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue $nsxMgrConfig.server
                                if ($nsxMgrConfig.protocol -eq "LI") {
                                    if ($nsxMgrConfig.port -eq "514" ) {
                                        $protocol = "SYSLOG over TCP"
                                    } else {
                                        $protocol = "SYSLOG over UDP"
                                    }
                                } else {
                                    $protocol = $nsxMgrConfig.protocol
                                }
                                $nsxMgrConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue $protocol
                                $nsxMgrConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue $nsxMgrConfig.port
                                $nsxMgrConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'GREEN'
                            } else {
                                $nsxMgrConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue "Not Available"
                                $nsxMgrConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue "Not Available"
                                $nsxMgrConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue "Not Available"
                                $nsxMgrConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'RED'
                            }
                            $nsxMgrLogConfig.Add($nsxMgrConfigObj)

                            $edgeNodes = (Get-NsxtEdgeCluster).members

                            if ($edgeNodes) {
                                foreach ($node in $edgeNodes) {
                                    $nsxEdgeConfigObj = New-Object -TypeName psobject
                                    $enConfig = Get-NsxtSyslogExporter -transport -id $node.transport_node_id
                                    $nsxEdgeConfigObj | Add-Member -notepropertyname "Workload Domain" -notepropertyvalue $domain
                                    $nsxEdgeConfigObj | Add-Member -notepropertyname "Resource" -notepropertyvalue "NSX Edge"
                                    $nsxEdgeConfigObj | Add-Member -notepropertyname "FQDN/Name" -notepropertyvalue $node.display_name
                                    if ($enConfig) {
                                        $nsxEdgeConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue $enConfig.server
                                        if ($enConfig.protocol -eq "LI") {
                                            if ($enConfig.port -eq "514" ) {
                                                $protocol = "SYSLOG over TCP"
                                            } else {
                                                $protocol = "SYSLOG over UDP"
                                            }
                                        } else {
                                            $protocol = $enConfig.protocol
                                        }
                                        $nsxEdgeConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue $protocol
                                        $nsxEdgeConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue $enConfig.port
                                        $nsxEdgeConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'GREEN'
                                    } else {
                                        $nsxEdgeConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue "Not Available"
                                        $nsxEdgeConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue "Not Available"
                                        $nsxEdgeConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue "Not Available"
                                        $nsxEdgeConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'RED'
                                    }
                                    $nsxMgrLogConfig.Add($nsxEdgeConfigObj)
                                }
                            } else {
                                $nsxEdgeConfigObj = New-Object -TypeName psobject
                                $nsxEdgeConfigObj | Add-Member -notepropertyname "NSX Edge" -notepropertyvalue "Not Found"
                                $nsxMgrLogConfig.Add($nsxEdgeConfigObj)
                            }
                            return $nsxMgrLogConfig
                        } else {
                            Write-Error "Unable to connect to NSX Manager $($nsxtManagerDetails.fqdn) with provided credentials"
                        }
                    }
                }
            }
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxLoggingConfig

Function Request-AriaOpsLoggingConfig {
    <#
        .SYNOPSIS
        Return the logging configuration from VMware Aria Operations.

        .DESCRIPTION
        The Request-AriaOpsLoggingConfig cmdlet returns logging configuration of VMware Aria Operations.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server

        .EXAMPLE
        Request-AriaOpsLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123!
        This example returns the logging configuration of VMware Aria Operations.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$pass
    )

    $pass = Get-Password -username $user -password $pass

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVropsDetails = Get-vROPsServerDetail -fqdn $server -username $user -password $pass)) {
                    if (Test-vROPSConnection -server $vcfVropsDetails.loadBalancerFqdn) {
                        if (Test-vROPSAuthentication -server $vcfVropsDetails.loadBalancerFqdn -user $vcfVropsDetails.adminUser -pass $vcfVropsDetails.adminPass) {
                            $vROpsConfig = Get-vROpsLogForwardingConfig -server $server -user $user -pass $pass
                            $vROpsConfigObj = New-Object -TypeName psobject
                            $vROpsConfigObj | Add-Member -notepropertyname "FQDN (Load Balancer)" -notepropertyvalue $vcfVropsDetails.loadBalancerFqdn
                            if ($vROpsConfig) {
                                $vROpsConfigObj | Add-Member -notepropertyname "Cluster" -notepropertyvalue $vROpsConfig.Cluster
                                $vROpsConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue $vROpsConfig.host
                                $vROpsConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue (Convert-ProtocolToString -protocol $vROpsConfig.Protocol)
                                $vROpsConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue $vROpsConfig.Port
                                $vROpsConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'GREEN'
                            } else {
                                $vROpsConfigObj | Add-Member -notepropertyname "Cluster" -notepropertyvalue "Not Available"
                                $vROpsConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue "Not Available"
                                $vROpsConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue "Not Available"
                                $vROpsConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue "Not Available"
                                $vROpsConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'RED'
                            }
                            $vROpsLogConfig = New-Object System.Collections.Generic.List[System.Object]
                            $vROpsLogConfig.Add($vROpsConfigObj)
                        }
                        return $vROpsLogConfig
                    } else {
                        Write-Error "Unable to connect to VMware Aria Operations ($vcfVropsDetails.loadBalancerFqdn): PRE_VALIDATION_FAILED"
                    }
                }
            } else {
                Write-Error "Unable to obtain VMware Aria Operations details from SDDC Manager ($fqdn), check deployment status: PRE_VALIDATION_FAILED"
            }
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Request-AriaOpsLoggingConfig

Function Request-AriaAutomationLoggingConfig {
    <#
        .SYNOPSIS
        Requests the logging configuration for VMware Aria Automation.

        .DESCRIPTION
        The Request-AriaAutomationLoggingConfig cmdlet returns logging configuration of VMware Aria Automation.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server
        - Validated that network connectivity and authentication is possible to Aria Automation

        .EXAMPLE
        Request-AriaAutomationLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123!
        This example returns the logging configuration of VMware Aria Automation.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass
    )

    $pass = Get-Password -username $user -password $pass

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVrslcmDetails = Get-vRSLCMServerDetail -fqdn $server -username $user -password $pass)) {
                    if (Test-vRSLCMAuthentication -server $vcfVrslcmDetails.fqdn -user $vcfVrslcmDetails.adminUser -pass $vcfVrslcmDetails.adminPass) {
                        if ($vraDetails = Get-vRAServerDetail -fqdn $server -username $user -password $pass -ErrorAction Stop) {
                            if (Test-vRAConnection -server $vRADetails.node1IpAddress) {
                                $vraRootPass = (Get-vRSLCMProductPassword -productId vra -nodeFqdn $vraDetails.fqdn[0] -vrslcmRootPass $vcfVrslcmDetails.rootPassword).password
                                $vraConfig = Get-vRAvRLIConfig -server $server -user $user -pass $pass -rootPass $vraRootPass
                                $vraConfigObj = New-Object -TypeName psobject
                                $vraConfigObj | Add-Member -notepropertyname "FQDN (Load Balancer)" -notepropertyvalue $vraDetails.loadBalancerFqdn
                                if (!($vraConfig -is [string])) {
                                    $vraConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue $vraConfig.host
                                    $vraConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue (Convert-ProtocolToString -protocol $vraConfig)
                                    $vraConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue $vraConfig.Port
                                    $vraConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'GREEN'
                                } else {
                                    $vraConfig = Get-vRASyslogConfig -server $server -user $user -pass $pass -vraRootPass $vraRootPass
                                    if (!($vraConfig -is [string])) {
                                        $vraConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue $vraConfig.host
                                        $vraConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue (Convert-ProtocolToString -protocol $vraConfig.protocol)
                                        $vraConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue $vraConfig.Port
                                        $vraConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'GREEN'
                                    } else {
                                        $vraConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue "Not Available"
                                        $vraConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue "Not Available"
                                        $vraConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue "Not Available"
                                        $vraConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'RED'
                                    }
                                }
                                $vraLogConfig = New-Object System.Collections.Generic.List[System.Object]
                                $vraLogConfig.Add($vraConfigObj)
                                return $vraLogConfig
                            } else {
                                Write-Error "Unable to connect to VMware Aria Automation $($vraDetails.loadBalancerFqdn): PRE_VALIDATION_FAILED"
                            }
                        }
                    }
                }
            }
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Request-AriaAutomationLoggingConfig

Function Request-AriaLifeCycleLoggingConfig {
    <#
        .SYNOPSIS
        Requests the logging configuration for VMware Aria Suite Lifecycle.

        .DESCRIPTION
        The Request-AriaLifeCycleLoggingConfig cmdlet returns logging configuration of VMware Aria LifeCycle
        The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server
        - Validated that network connectivity and authentication is possible to Aria Automation

        .EXAMPLE
        Request-AriaLifeCycleLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123!
        This example returns the logging configuration of VMware Aria Suite Lifecycle

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass
    )

    $pass = Get-Password -username $user -password $pass

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVrslcmDetails = Get-vRSLCMServerDetail -fqdn $server -username $user -password $pass)) {
                    if (Test-vRSLCMAuthentication -server $vcfVrslcmDetails.fqdn -user $vcfVrslcmDetails.adminUser -pass $vcfVrslcmDetails.adminPass) {
                        $vrslcmConfig = Get-VrslcmLIAgentSettings
                        $vrslcmConfigObj = New-Object -TypeName psobject
                        $vrslcmConfigObj | Add-Member -notepropertyname "FQDN" -notepropertyvalue $vcfVrslcmDetails.fqdn
                        if ($vrslcmConfig) {
                            $vrslcmConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue $vrslcmConfig.hostname
                            $vrslcmConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue (Convert-ProtocolToString -protocol $vrslcmConfig.protocol)
                            $vrslcmConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue $vrslcmConfig.PortNumber
                            $vrslcmConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'GREEN'
                        } else {
                            $vrslcmConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue "Not Available"
                            $vrslcmConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue"Not Available"
                            $vrslcmConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue "Not Available"
                            $vrslcmConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'RED'
                        }
                        $vrslcmLogConfig = New-Object System.Collections.Generic.List[System.Object]
                        $vrslcmLogConfig.Add($vrslcmConfigObj)
                        return $vrslcmLogConfig
                    } else {
                        Write-Error "Unable to connect to VMware Aria Suite Lifecycle: PRE_VALIDATION_FAILED"
                    }
                }
            }
        } else {
            Write-Warning "Unable to connect to SDDC Manager $($server) : PRE_VALIDATION_FAILED"
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Request-AriaLifecycleLoggingConfig

Function Request-AriaOpsLogsLoggingConfig {
    <#
        .SYNOPSIS
        Retrieves the logging configuration in VMware Aria Operations for Logs

        .DESCRIPTION
        The Request-AriaOpsLogsLoggingConfig cmdlet returns log forwarders and agents configuration from VMware Aria Operations for Logs.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server

        .EXAMPLE
        Request-AriaOpsLogsLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123!
        This example returns the logging configuration of VMware Aria Operations for Logs.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass
    )

    $pass = Get-Password -username $user -password $pass

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if ($vrliDetails = Get-vRLIServerDetail -fqdn $server -username $user -password $pass) {
                    if (Test-vRLIConnection -server $vrliDetails.fqdn) {
                        if (Test-vRLIAuthentication -server $vrliDetails.fqdn -user $vrliDetails.adminUser -pass $vrliDetails.adminPass) {
                            $vrliConfigObj = New-Object -TypeName psobject
                            $vrliForwardersConfig = Get-vRLILogForwarder
                            $vrliAgents = Get-vRLIAgents
                            $vrliForwadersList = New-Object System.Collections.Generic.List[System.Object]
                            $vrliAgentsList = New-Object System.Collections.Generic.List[System.Object]

                            if ($vrliForwardersConfig) {
                                foreach ($forwarderConfig in $vrliForwardersConfig) {
                                    $vrliForwardersConfigObj = New-Object -TypeName psobject
                                    $vrliForwardersConfigObj | Add-Member -notepropertyname "FQDN" -notepropertyvalue $vrliDetails.fqdn
                                    $vrliForwardersConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue $forwarderConfig.host
                                    $vrliForwardersConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue "$($forwarderConfig.protocol.ToUpper()) over $($forwarderConfig.transportProtocol.ToUpper())"
                                    $vrliForwardersConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue $forwarderConfig.Port
                                    $vrliForwardersConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'GREEN'
                                    $vrliForwadersList.add($vrliForwardersConfigObj)
                                }
                            } else {
                                $vrliForwardersConfigObj = New-Object -TypeName psobject
                                $vrliForwardersConfigObj | Add-Member -notepropertyname "FQDN" -notepropertyvalue $vrliDetails.fqdn
                                $vrliForwardersConfigObj | Add-Member -notepropertyname "Server" -notepropertyvalue "Not Available"
                                $vrliForwardersConfigObj | Add-Member -notepropertyname "Protocol" -notepropertyvalue"Not Available"
                                $vrliForwardersConfigObj | Add-Member -notepropertyname "Port" -notepropertyvalue "Not Available"
                                $vrliForwardersConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'RED'
                                $vrliForwadersList.add($vrliForwardersConfigObj)
                            }
                            $vrliConfigObj | Add-Member -notepropertyname "Forwarders" -NotePropertyValue $vrliForwadersList

                            if ($vrliAgents) {
                                foreach ($agent in $vrliAgents) {
                                    $vrliAgentsConfigObj = New-Object -TypeName psobject
                                    $vrliAgentsConfigObj | Add-Member -notepropertyname "FQDN" -notepropertyvalue $agent.fqdn
                                    $vrliAgentsConfigObj | Add-Member -notepropertyname "Version" -notepropertyvalue $agent.version.Substring(0, ($agent.version.LastIndexOf('.')))
                                    $vrliAgentsConfigObj | Add-Member -notepropertyname "OS" -notepropertyvalue $agent.os
                                    $date = [DateTimeOffset]::FromUnixTimeMilliseconds($agent.lastseen)
                                    $vrliAgentsConfigObj | Add-Member -notepropertyname "Last Active" -notepropertyvalue $date.DateTime
                                    $date = [DateTimeOffset]::FromUnixTimeMilliseconds($agent.statsAsOf)
                                    $vrliAgentsConfigObj | Add-Member -notepropertyname "Events Sent" -notepropertyvalue (Convert-NumberFormat -number $agent.totalEvts)
                                    $vrliAgentsConfigObj | Add-Member -notepropertyname "Events Dropped" -notepropertyvalue $agent.droppedEvts
                                    $vrliAgentsConfigObj | Add-Member -notepropertyname "Events Rate (per sec)" -notepropertyvalue $agent.evtRate
                                    if ($agent.agentStatus -eq "Active") {
                                        $vrliAgentsConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'GREEN'
                                    } else {
                                        $vrliAgentsConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue 'YELLOW'
                                    }
                                    $vrliAgentsList.add($vrliAgentsConfigObj)
                                }
                            } else {
                                $vrliAgentsConfigObj = New-Object -TypeName psobject
                                $vrliAgentsConfigObj | Add-Member -notepropertyname "FQDN" -notepropertyvalue "Not Available"
                                $vrliAgentsConfigObj | Add-Member -notepropertyname "Version" -notepropertyvalue "Not Available"
                                $vrliAgentsConfigObj | Add-Member -notepropertyname "OS" -notepropertyvalue "Not Available"
                                $date = [DateTimeOffset]::FromUnixTimeMilliseconds($agent.lastseen)
                                $vrliAgentsConfigObj | Add-Member -notepropertyname "Last Active" -notepropertyvalue "Not Available"
                                $date = [DateTimeOffset]::FromUnixTimeMilliseconds($agent.statsAsOf)
                                $vrliAgentsConfigObj | Add-Member -notepropertyname "Events Sent" -notepropertyvalue "Not Available"
                                $vrliAgentsConfigObj | Add-Member -notepropertyname "Events Dropped" -notepropertyvalue "Not Available"
                                $vrliAgentsConfigObj | Add-Member -notepropertyname "Events Rate (per sec)" -notepropertyvalue "Not Available"
                                $vrliAgentsConfigObj | Add-Member -notepropertyname "Alert" -notepropertyvalue "RED"
                                $vrliAgentsList.add($vrliAgentsConfigObj)
                            }
                            $vrliConfigObj | Add-Member -notepropertyname "Agents" -NotePropertyValue $vrliAgentsList
                            return $vrliConfigObj
                        } else {
                            Write-Error "Unable to connect to VMware Aria Operations for Logs $($vrliDetails.fqdn): PRE_VALIDATION_FAILED"
                        }
                    }
                }
            }
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($global:DefaultVIServers) {
            Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$false
        }
    }
}
Export-ModuleMember -Function Request-AriaOpsLogsLoggingConfig

#EndRegion  End Request Functions                                   ######
##########################################################################

##########################################################################
#Region     Begin Helper Functions                                  ######

Function Convert-NumberFormat {
    <#
        .SYNOPSIS
        Internal Function to convert a number to K, M or B format

        .EXAMPLE
        Convert-NumberFormat -number 497868429
        This converts the number to 497.87 M
    #>

    Param (
        [double]$number
    )

    switch ($number) {
        { $_ -ge 1e9 } { "$([math]::Round($_ / 1e9, 2)) B"; break }
        { $_ -ge 1e6 } { "$([math]::Round($_ / 1e6, 2)) M"; break }
        { $_ -ge 1e3 } { "$([math]::Round($_ / 1e3, 2)) K"; break }
        default { "$_"; break }
    }
}

Function Get-vRASyslogConfig {
    <#
		.SYNOPSIS
        Returns the syslog configuration on VMware Aria Automation.

        .DESCRIPTION
        The Get-vRASyslogConfig cmdlet returns the Remote Syslog configuration for VMware Aria
        Automation. The cmdlet connects to SDDC Manager using the -server, -user, and -password values and connects to
        the first VMware Aria Automation appliance using the -rootPass value.
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to Management Domain vCenter Server
        - Validates that network connectivity is possible to the first VMware Aria Automation appliance
        - Returns the remote Syslog configuration in VMware Aria Automation

        .EXAMPLE
        Get-vRASyslogConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -vraRootPass VMw@re123!
        This example returns the VMware Aria Operations for Logs logging configuration on VMware Aria Automation.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager.

        .PARAMETER user
        The username used to authenticate to SDDC Manager.

        .PARAMETER pass
        The password used to authenticate to SDDC Manager.

        .PARAMETER vraRootPass
        The root password to connect to the first VMware Aria Automation appliance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vraRootPass
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            if ($vraDetails = Get-vRAServerDetail -fqdn $server -username $user -password $pass -ErrorAction Stop) {
                                if (Test-vRAConnection -server $vRADetails.node1IpAddress) {
                                    $vmName = $vraDetails.fqdn | Select-Object -First 1
                                    $vmName = $vmName.Split(".")[0]
                                    if ((Get-VM -Name $vmName -WarningAction SilentlyContinue -ErrorAction SilentlyContinue )) {
                                        $scriptCommand = "vracli remote-syslog"
                                        $output = Invoke-VMScript -VM $vmName -ScriptText $scriptCommand -GuestUser root -GuestPassword $vraRootPass -Server $vcfVcenterDetails.fqdn
                                        if (($output.ScriptOutput).Contains('No Remote Syslog')) {
                                            Write-Output "VMware Aria Automation integration with Remote Syslog status 'Not Configured'."
                                        } elseif (($output.ScriptOutput).Contains('host')) {
                                            $jsonString = [regex]::Match($output.ScriptOutput, '\{.*\}', [System.Text.RegularExpressions.RegexOptions]::SingleLine).Value
                                            $json = $jsonString | ConvertFrom-JSON
                                            return $json.($json.PSObject.Properties.Name)
                                        } else {
                                            Write-Error "Returning the VMware Aria Automation integration with Remote Syslog: POST_VALIDATION_FAILED"
                                        }
                                    } else {
                                        Write-Error "Unable to locate a virtual machine named ($vmName) in vCenter Server ($($vcfVcenterDetails.fqdn)) inventory: PRE_VALIDATION_FAILED"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    }
}

Function Convert-ProtocolToString {
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$protocol
    )

    if ($global:syslogProtocols -contains $protocol) {
        return "SYSLOG over $($protocol.ToUpper())"
    } elseif ($global:cfapiProtocols -contains $protocol) {
        return "CFAPI via $($protocol.ToUpper())"
    } else {
        return $protocol.ToUpper()
    }
}
Function Get-vRLIAgents {
    <#
        .SYNOPSIS
        Get list of agent on Aria Operations for Logs.

        .DESCRIPTION
        The Get-vRLIAgents cmdlet gets a list of agents

        .EXAMPLE
        Get-vRLIAgents
        This example gets a list of agents.
    #>

    Try {
        $uri = "https://$vrliAppliance/api/v2/agent"
        $response = Invoke-RestMethod -Method 'GET' -Uri $Uri -Headers $vrliHeaders
        $response.agents
    } Catch {
        Write-Error $_.Exception.Message
    }
}

Function Get-NsxMissingLoggingStatus {
    <#
        .SYNOPSIS
        Gets the list of all nodes missing the logging-server configuration status.

        .DESCRIPTION
        The Get-NsxtLoggingStatus cmdlet gets the list of nodes missing logging-server configuration status if all nodes

        .EXAMPLE
        Get-NsxtLoggingStatus
        This example gets list of all the nodes missing the logging-server configuration status.
    #>

    Try {
        $uri = "https://$nsxtManager/api/v1/configs/central-config/logging-servers"
        $response = Invoke-RestMethod $uri -Method 'GET' -Headers $nsxtHeaders
        $response.nodes_missing_remote_logging_configuration
    } Catch {
        Write-Error $_.Exception.Message
    }
}

Function Get-VrslcmLIAgentSettings {
    <#
        .SYNOPSIS
        Get the settings for log insight agent in VMware Aria Suite Lifecycle.

        .DESCRIPTION
        The Get-VrslcmLIAgentSettings cmdlet gets the settings for log insight agent in VMware Aria Suite Lifecycle.

        .EXAMPLE
        Get-VrslcmLIAgentSettings
        This example gets the SSH services.
    #>

    Try {
        if ($vrslcmAppliance) {
            $uri = "https://$vrslcmAppliance/lcm/lcops/api/v2/settings/log-insight-agent"
            Invoke-RestMethod $uri -Method 'GET' -Headers $vrslcmHeaders
        } else {
            Write-Error "Not connected to VMware Aria Suite Lifecycle, run Request-vRSLCMToken and try again"
        }
    } Catch {
        Write-Error $_.Exception.Message
    }
}

Function Set-CreateReportDirectory {
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$path,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$filename = "report"
    )

    $filetimeStamp = Get-Date -Format "MM-dd-yyyy_hh_mm_ss"
    $Global:reportFolder = $path + '\LoggingManagement\'
    if ($PSEdition -eq "Core" -and ($PSVersionTable.OS).Split(' ')[0] -eq "Linux") {
        $reportFolder = Join-Path -Path (Split-Path -NoQualifier $reportFolder) -ChildPath ''
    }
    if (!(Test-Path -Path $reportFolder)) {
        New-Item -Path $reportFolder -ItemType "directory" | Out-Null
    }
    $reportName = $reportFolder + $filetimeStamp + "-$filename.htm"
    $reportName
}

#EndRegion  End Helper Functions                                    ######
##########################################################################

##########################################################################
#Region     Begin HTML Report Functions                             ######

Function Convert-CssClassStyle {
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [PSCustomObject]$htmlData
    )

    # Function to replace CSS Style
    # Function to replace Alerts with colour coded CSS Style
    $oldAlertOK = '<td>GREEN</td>'
    $newAlertOK = '<td class="alertOK">GREEN</td>'
    $oldAlertCritical = '<td>RED</td>'
    $newAlertCritical = '<td class="alertCritical">RED</td>'
    $oldAlertWarning = '<td>YELLOW</td>'
    $newAlertWarning = '<td class="alertWarning">YELLOW</td>'
    $oldTable = '<table>'
    $newTable = '<table class="table">'
    $oldAddLine = ':-: '
    $newNewLine = '<br/>'

    $htmlData = $htmlData -replace $oldAlertOK, $newAlertOK
    $htmlData = $htmlData -replace $oldAlertCritical, $newAlertCritical
    $htmlData = $htmlData -replace $oldAlertWarning, $newAlertWarning
    $htmlData = $htmlData -replace $oldTable, $newTable
    $htmlData = $htmlData -replace $oldAddLine, $newNewLine
    $htmlData
}
Function Save-ClarityReportHeader {
    Param (
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$dark
    )

    # Define the default Clarity Cascading Style Sheets (CSS) for the HTML report Header
    if ($PsBoundParameters.ContainsKey("dark")) {
        $clarityCssHeader = '
        <head>
        <style>
            <!--- Used Clarify CSS components for this project --->
            article, aside, details, figcaption, figure, footer, header, main, menu, nav, section, summary { display: block; }
            .main-container { display: flex; flex-direction: column; height: 100vh; background: var(--clr-global-app-background, #21333b); }
            header.header-6, .header.header-6 { background-color: #0e161b; }
            header, .header { display: flex; color: #fafafa; background-color: #0e161b; height: 3rem; white-space: nowrap; }
            .nav { display: flex; height: 1.8rem; list-style-type: none; align-items: center; margin: 0; width: 100%; white-space: nowrap; box-shadow: 0 -0.05rem 0 #495865 inset; }
            .nav .nav-item { display: inline-block; margin-right: 1.2rem; }
            .nav .nav-item.active > .nav-link { color: white; box-shadow: 0 -0.05rem 0 #495865 inset; }
            .nav .nav-link { color: #acbac3; font-size: 0.7rem; font-weight: 400; letter-spacing: normal; line-height: 1.8rem; display: inline-block; padding: 0 0.15rem; box-shadow: none; }
            .nav .nav-link.btn { text-transform: none; margin: 0; margin-bottom: -0.05rem; border-radius: 0; }
            .nav .nav-link:hover, .nav .nav-link:focus, .nav .nav-link:active { color: inherit; }
            .nav .nav-link:hover, .nav .nav-link.active { box-shadow: 0 -0.15rem 0 #4aaed9 inset; transition: box-shadow 0.2s ease-in; }
            .nav .nav-link:hover, .nav .nav-link:focus, .nav .nav-link:active, .nav .nav-link.active { text-decoration: none; }
            .nav .nav-link.active { color: white; font-weight: 400; }
            .nav .nav-link.nav-item { margin-right: 1.2rem; }
            .sub-nav, .subnav { display: flex; box-shadow: 0 -0.05rem 0 #cccccc inset; justify-content: space-between; align-items: center; background-color: #17242b; height: 1.8rem; }
            .sub-nav .nav, .subnav .nav { flex: 1 1 auto; padding-left: 1.2rem; }
            .sub-nav aside, .subnav aside { flex: 0 0 auto; display: flex; align-items: center; height: 1.8rem; padding: 0 1.2rem; }
            .sub-nav aside > :last-child, .subnav aside > :last-child { margin-right: 0; padding-right: 0; }
            .sidenav { line-height: 1.2rem; max-width: 15.6rem; min-width: 10.8rem; width: 18%; border-right: 0.05rem solid #152228; display: flex; flex-direction: column; }
            .sidenav .sidenav-content { flex: 1 1 auto; overflow-x: hidden; padding-bottom: 1.2rem; }
            .sidenav .sidenav-content .nav-link { border-radius: 0; border-top-left-radius: 0.15rem; border-bottom-left-radius: 0.15rem; display: inline-block; color: inherit; cursor: pointer; text-decoration: none; width: 100%; }
            .sidenav .sidenav-content > .nav-link { margin: 1.2rem 0 0 1.5rem; padding-left: 0.6rem; color: #acbac3; font-weight: 500; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 0.7rem; line-height: 1.2rem; letter-spacing: normal; }
            .sidenav .sidenav-content > .nav-link:hover { background: #324f62; }
            .sidenav .sidenav-content > .nav-link.active { background: #324f62; color: black; }
            .sidenav .nav-group { color: #acbac3; font-weight: 400; font-size: 0.7rem; letter-spacing: normal; margin-top: 1.2rem; width: 100%; }
            .sidenav .nav-group .nav-list, .sidenav .nav-group label { padding: 0 0 0 1.8rem; cursor: pointer; display: inline-block; width: 100%; }
            .sidenav .nav-group .nav-list { list-style: none; margin-top: 0; }
            .sidenav .nav-group .nav-list .nav-link {}
            .sidenav .nav-group .nav-list .nav-link:hover { background: #324f62; }
            .sidenav .nav-group .nav-list .nav-link.active { background: #324f62; color: black; }
            .sidenav .nav-group label { color: #acbac3; font-weight: 500; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 0.7rem; line-height: 1.2rem; letter-spacing: normal; }
            .sidenav .nav-group input[type=checkbox] { position: absolute; clip: rect(1px, 1px, 1px, 1px); clip-path: inset(50%); padding: 0; border: 0; height: 1px; width: 1px; overflow: hidden; white-space: nowrap; top: 0; left: 0; }
            .sidenav .nav-group input[type=checkbox]:focus + label { outline: #3b99fc auto 0.25rem; }
            .sidenav .collapsible label { padding: 0 0 0}
            .sidenav .collapsible label:after { content: ""; float: left; height: 0.5rem; width: 0.5rem; transform: translateX(-0.4rem) translateY(0.35rem); background-image: url("data:image/svg+xml;charset=utf8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2012%2012%22%3E%0A%20%20%20%20%3Cdefs%3E%0A%20%20%20%20%20%20%20%20%3Cstyle%3E.cls-1%7Bfill%3A%239a9a9a%3B%7D%3C%2Fstyle%3E%0A%20%20%20%20%3C%2Fdefs%3E%0A%20%20%20%20%3Ctitle%3ECaret%3C%2Ftitle%3E%0A%20%20%20%20%3Cpath%20class%3D%22cls-1%22%20d%3D%22M6%2C9L1.2%2C4.2a0.68%2C0.68%2C0%2C0%2C1%2C1-1L6%2C7.08%2C9.84%2C3.24a0.68%2C0.68%2C0%2C1%2C1%2C1%2C1Z%22%2F%3E%0A%3C%2Fsvg%3E%0A"); background-repeat: no-repeat; background-size: contain; vertical-align: middle; margin: 0; }
            .sidenav .collapsible input[type=checkbox]:checked ~ .nav-list, .sidenav .collapsible input[type=checkbox]:checked ~ ul { height: 0; display: none; }
            .sidenav .collapsible input[type=checkbox] ~ .nav-list, .sidenav .collapsible input[type=checkbox] ~ ul { height: auto; }
            .sidenav .collapsible input[type=checkbox]:checked ~ label:after { transform: rotate(-90deg) translateX(-0.35rem) translateY(-0.4rem); }
            body:not([cds-text]) { color: #acbac3; font-weight: 400; font-size: 0.7rem; letter-spacing: normal; line-height: 1.2rem; margin-bottom: 0px; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; margin-top: 0px !important; }
            html:not([cds-text]) { color: #eaedf0; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 125%; }
            a:link { color: #4aaed9; text-decoration: none; }
            h1:not([cds-text]) { color: #eaedf0; font-weight: 200; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 1.6rem; letter-spacing: normal; line-height: 2.4rem; margin-top: 1.2rem; margin-bottom: 0; }
            h2:not([cds-text]) { color: #eaedf0; font-weight: 200; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 1.4rem; letter-spacing: normal; line-height: 2.4rem; margin-top: 1.2rem; margin-bottom: 0; }
            h3:not([cds-text]) { color: #eaedf0; font-weight: 200; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 1.1rem; letter-spacing: normal; line-height: 1.2rem; margin-top: 1.2rem; margin-bottom: 0; }
            h4:not([cds-text]) { color: #eaedf0; font-weight: 200; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 0.9rem; letter-spacing: normal; line-height: 1.2rem; margin-top: 1.2rem; margin-bottom: 0; }
            .table th { color: #eaedf0; font-size: 0.55rem; font-weight: 600; letter-spacing: 0.03em; background-color: #1b2a32; vertical-align: bottom; border-bottom-style: solid; border-bottom-width: 0.05rem; border-bottom-color: #495865; border-top: 0 none; }
            .table { border-collapse: separate; border-style: solid; border-width: 0.05rem; border-color: #495865; border-radius: 0.15rem; background-color: #21333b; color: #acbac3; margin: 0; margin-top: 1.2rem; max-width: 100%; width: 100%; }

            h3 { display: block; font-size: 1.17em; margin-block-start: 1em; margin-block-end: 1em; margin-inline-start: 0px; margin-inline-end: 0px; font-weight: bold; }
            h4 { display: block; margin-block-start: 1.33em; margin-block-end: 1.33em; margin-inline-start: 0px; margin-inline-end: 0px; font-weight: bold; }
            .table th, .table td {font-size: 0.65rem; line-height: 0.7rem; border-top-style: solid; border-top-width: 0.05rem; border-top-color: #495865; padding: 0.55rem 0.6rem 0.55rem; text-align: left; vertical-align: top; }
            th { display: table-cell; vertical-align: inherit; font-weight: bold; text-align: -internal-center; }
            table { display: table; border-collapse: separate; box-sizing: border-box; text-indent: initial; border-spacing: 2px; border-color: gray; }
        '
    } else {
        $clarityCssHeader = '
        <head>
		<style>
			<!--- Used Clarify CSS components for this project --->
            article, aside, details, figcaption, figure, footer, header, main, menu, nav, section, summary { display: block; }
            .main-container { display: flex; flex-direction: column; height: 100vh; background: var(--clr-global-app-background, #fafafa); }
            header.header-6, .header.header-6 { background-color: var(--clr-header-6-bg-color, #00364d); }
            header, .header { display: flex; color: var(--clr-header-font-color, #fafafa); background-color: var(--clr-header-bg-color, #333333); height: 3rem; white-space: nowrap; }
            .nav {display: flex; height: 1.8rem; list-style-type: none; align-items: center; margin: 0; width: 100%; white-space: nowrap; box-shadow: 0 -0.05rem 0 #cccccc inset; box-shadow: 0 -0.05rem 0 var(--clr-nav-box-shadow-color, #cccccc) inset; }
            .nav .nav-item { display: inline-block; margin-right: 1.2rem; }
            .nav .nav-item.active > .nav-link { color: black; color: var(--clr-nav-link-active-color, black); box-shadow: 0 -0.05rem 0 #cccccc inset; box-shadow: 0 -0.05rem 0 var(--clr-nav-box-shadow-color, #cccccc) inset; }
            .nav .nav-link { color: #666666; color: var(--clr-nav-link-color, #666666); font-size: 0.7rem; font-weight: 400; font-weight: var(--clr-nav-link-font-weight, 400); letter-spacing: normal; line-height: 1.8rem; display: inline-block; padding: 0 0.15rem; box-shadow: none; }
            .nav .nav-link.btn { text-transform: none; margin: 0; margin-bottom: -0.05rem; border-radius: 0; }
            .nav .nav-link:hover, .nav .nav-link:focus, .nav .nav-link:active { color: inherit; }
            .nav .nav-link:hover, .nav .nav-link.active { box-shadow: 0 -0.15rem 0 #0072a3 inset; box-shadow: 0 -0.15rem 0 var(--clr-nav-active-box-shadow-color, #0072a3) inset; transition: box-shadow 0.2s ease-in; }
            .nav .nav-link:hover, .nav .nav-link:focus, .nav .nav-link:active, .nav .nav-link.active { text-decoration: none; }
            .nav .nav-link.active { color: black; color: var(--clr-nav-link-active-color, black); font-weight: 400; font-weight: var(--clr-nav-link-active-font-weight, 400); }
            .nav .nav-link.nav-item { margin-right: 1.2rem; }
            .sub-nav, .subnav { display: flex; box-shadow: 0 -0.05rem 0 #cccccc inset; box-shadow: 0 -0.05rem 0 var(--clr-nav-box-shadow-color, #cccccc) inset; justify-content: space-between; align-items: center; background-color: white; background-color: var(--clr-subnav-bg-color, white); height: 1.8rem; }
            .sub-nav .nav, .subnav .nav { flex: 1 1 auto; padding-left: 1.2rem; }
            .sub-nav aside, .subnav aside { flex: 0 0 auto; display: flex; align-items: center; height: 1.8rem; padding: 0 1.2rem; }
            .sub-nav aside > :last-child, .subnav aside > :last-child { margin-right: 0; padding-right: 0; }
            .sidenav { line-height: 1.2rem; max-width: 15.6rem; min-width: 10.8rem; width: 18%; border-right: 0.05rem solid #cccccc; display: flex; flex-direction: column; }
            .sidenav .collapsible label padding: 0 0 0 }
            .sidenav .nav-group label {color: #333333; color: var(--clr-sidenav-header-color, #333333); font-weight: 500; font-weight: var(--clr-sidenav-header-font-weight, 500); font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-family: var(--clr-sidenav-header-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 0.7rem; line-height: 1.2rem; letter-spacing: normal; }
            .sidenav { line-height: 1.2rem; max-width: 15.6rem; min-width: 10.8rem; width: 18%; border-right: 0.05rem solid #cccccc; display: flex; flex-direction: column; }
            .sidenav .sidenav-content { flex: 1 1 auto; overflow-x: hidden; padding-bottom: 1.2rem; }
            .sidenav .sidenav-content .nav-link { border-radius: 0; border-top-left-radius: 0.15rem; border-top-left-radius: var(--clr-sidenav-link-active-border-radius, 0.15rem); border-bottom-left-radius: 0.15rem; border-bottom-left-radius: var(--clr-sidenav-link-active-border-radius, 0.15rem); display: inline-block; color: inherit; cursor: pointer; text-decoration: none; width: 100%; }
            .sidenav .sidenav-content > .nav-link { margin: 1.2rem 0 0 1.5rem; padding-left: 0.6rem; color: #333333; color: var(--clr-sidenav-header-color, #333333); font-weight: 500; font-weight: var(--clr-sidenav-header-font-weight, 500); font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-family: var(--clr-sidenav-header-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif);font-size: 0.7rem; line-height: 1.2rem; letter-spacing: normal; }
            .sidenav .sidenav-content > .nav-link:hover { background: #e8e8e8; background: var(--clr-sidenav-link-hover-color, #e8e8e8); }
            .sidenav .sidenav-content > .nav-link.active { background: #d8e3e9; background: var(--clr-sidenav-link-active-bg-color, #d8e3e9); color: black; color: var(--clr-sidenav-link-active-color, black); }
            .sidenav .nav-group { color: #666666; color: var(--clr-sidenav-color, #666666); font-weight: 400; font-weight: var(--clr-sidenav-font-weight, 400); font-size: 0.7rem; letter-spacing: normal; margin-top: 1.2rem; width: 100%; }
            .sidenav .nav-group .nav-list, .sidenav .nav-group label { padding: 0 0 0 1.8rem; cursor: pointer; display: inline-block; width: 100%; }
            .sidenav .nav-group .nav-list { list-style: none; margin-top: 0; }
            .sidenav .nav-group .nav-list .nav-link { }
            .sidenav .nav-group .nav-list .nav-link:hover { background: #e8e8e8; background: var(--clr-sidenav-link-hover-color, #e8e8e8); }
            .sidenav .nav-group .nav-list .nav-link.active { background: #d8e3e9; background: var(--clr-sidenav-link-active-bg-color, #d8e3e9); color: black; color: var(--clr-sidenav-link-active-color, black); }
            .sidenav .nav-group label { color: #333333; color: var(--clr-sidenav-header-color, #333333); font-weight: 500; font-weight: var(--clr-sidenav-header-font-weight, 500); font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-family: var(--clr-sidenav-header-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 0.7rem; line-height: 1.2rem; letter-spacing: normal; }
            .sidenav .nav-group input[type=checkbox] { position: absolute; clip: rect(1px, 1px, 1px, 1px); clip-path: inset(50%); padding: 0; border: 0; height: 1px; width: 1px; overflow: hidden; white-space: nowrap; top: 0; left: 0; }
            .sidenav .nav-group input[type=checkbox]:focus + label { outline: #3b99fc auto 0.25rem; }
            .sidenav .collapsible label { padding: 0 0 0 1.3rem; }
            .sidenav .collapsible label:after { content: ""; float: left; height: 0.5rem; width: 0.5rem; transform: translateX(-0.4rem) translateY(0.35rem); background-image: url("data:image/svg+xml;charset=utf8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2012%2012%22%3E%0A%20%20%20%20%3Cdefs%3E%0A%20%20%20%20%20%20%20%20%3Cstyle%3E.cls-1%7Bfill%3A%239a9a9a%3B%7D%3C%2Fstyle%3E%0A%20%20%20%20%3C%2Fdefs%3E%0A%20%20%20%20%3Ctitle%3ECaret%3C%2Ftitle%3E%0A%20%20%20%20%3Cpath%20class%3D%22cls-1%22%20d%3D%22M6%2C9L1.2%2C4.2a0.68%2C0.68%2C0%2C0%2C1%2C1-1L6%2C7.08%2C9.84%2C3.24a0.68%2C0.68%2C0%2C1%2C1%2C1%2C1Z%22%2F%3E%0A%3C%2Fsvg%3E%0A"); background-repeat: no-repeat; background-size: contain; vertical-align: middle; margin: 0; }
            .sidenav .collapsible input[type=checkbox]:checked ~ .nav-list, .sidenav .collapsible input[type=checkbox]:checked ~ ul { height: 0; display: none; }
            .sidenav .collapsible input[type=checkbox] ~ .nav-list, .sidenav .collapsible input[type=checkbox] ~ ul { height: auto; }
            .sidenav .collapsible input[type=checkbox]:checked ~ label:after { transform: rotate(-90deg) translateX(-0.35rem) translateY(-0.4rem); }
            body:not([cds-text]) { color: var(--clr-p1-color, #666666); font-weight: var(--clr-p1-font-weight, 400); font-size: 0.7rem; letter-spacing: normal; line-height: 1.2rem; margin-bottom: 0px; font-family: var(--clr-font, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); margin-top: 0px !important; }
            html:not([cds-text]) { color: var(--clr-global-font-color, #666666); font-family: var(--clr-font, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 125%; }
            a:link { color: var(--clr-link-color, #0072a3); text-decoration: none; }
            h1:not([cds-text]) { color: var(--clr-h1-color, black); font-weight: var(--clr-h1-font-weight, 200); font-family: var(--clr-h1-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 1.6rem; letter-spacing: normal; line-height: 2.4rem; margin-top: 1.2rem; margin-bottom: 0px; }
			h2:not([cds-text]) { color: var(--clr-h2-color, black); font-weight: var(--clr-h2-font-weight, 200); font-family: var(--clr-h2-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 1.4rem; letter-spacing: normal; line-height: 2.4rem; margin-top: 1.2rem; margin-bottom: 0px; }
			h3:not([cds-text]) { color: var(--clr-h3-color, black); font-weight: var(--clr-h3-font-weight, 200); font-family: var(--clr-h3-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 1.1rem; letter-spacing: normal; line-height: 1.2rem; margin-top: 1.2rem; margin-bottom: 0px; }
			h4:not([cds-text]) { color: var(--clr-h4-color, black); font-weight: var(--clr-h4-font-weight, 200); font-family: var(--clr-h4-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 0.9rem; letter-spacing: normal; line-height: 1.2rem; margin-top: 1.2rem; margin-bottom: 0px; }
            .table th { color: var(--clr-thead-color, #666666); font-size: 0.55rem; font-weight: 600; letter-spacing: 0.03em; background-color: var(--clr-thead-bgcolor, #fafafa); vertical-align: bottom; border-bottom-style: solid; border-bottom-width: var(--clr-table-borderwidth, 0.05rem); border-bottom-color: var(--clr-table-border-color, #cccccc); border-top: 0px none; }
            .table { border-collapse: separate; border-style: solid; border-width: var(--clr-table-borderwidth, 0.05rem); border-color: var(--clr-table-border-color, #cccccc); border-radius: var(--clr-table-border-radius, 0.15rem); background-color: var(--clr-table-bgcolor, white); color: var(--clr-table-font-color, #666666); margin: 1.2rem 0px 0px; max-width: 100%; width: 100%; }

			a { background-color: transparent; }
			abbr[title] { border-bottom: none; text-decoration: underline dotted; }
			b, strong { font-weight: inherit; }
			b, strong { font-weight: bolder; }
			[type="checkbox"], [type="radio"] { box-sizing: border-box; padding: 0px; }
			pre { border-color: var(--clr-color-neutral-400, #cccccc); border-width: var(--clr-global-borderwidth, 0.05rem); border-style: solid; border-radius: var(--clr-global-borderradius, 0.15rem); }
			ul:not([cds-list]), ol:not([cds-list]) { list-style-position: inside; margin-left: 0px; margin-top: 0px; margin-bottom: 0px; padding-left: 0px; }
			li > ul:not([cds-list]) { margin-top: 0px; margin-left: 1.1em; }
			body p:not([cds-text]) { color: var(--clr-p1-color, #666666); font-weight: var(--clr-p1-font-weight, 400); font-size: 0.7rem; letter-spacing: normal; line-height: 1.2rem; margin-top: 1.2rem; margin-bottom: 0px; }
			a:visited { color: var(--clr-link-visited-color, #5659b8); text-decoration: none; }
			.main-container .content-container .content-area > :first-child { margin-top: 0px; }
			.nav .nav-link:hover, .nav .nav-link.active { box-shadow: 0 -0.15rem 0 var(--clr-nav-active-box-shadow-color, #0072a3) inset; transition: box-shadow 0.2s ease-in 0s; }
			.nav .nav-link.active { color: var(--clr-nav-link-active-color, black); font-weight: var(--clr-nav-link-active-font-weight, 400); }
			:root { --clr-subnav-bg-color:var(--clr-color-neutral-0); --clr-nav-box-shadow-color:var(--clr-color-neutral-400); }
			:root { --clr-sidenav-border-color:var(--clr-color-neutral-400); --clr-sidenav-border-width:var(--clr-global-borderwidth); --clr-sidenav-link-hover-color:var(--clr-color-neutral-200); --clr-sidenav-link-active-color:var(--clr-color-neutral-1000); --clr-sidenav-link-active-bg-color:var(--clr-global-selection-color); --clr-sidenav-link-active-border-radius:var(--clr-global-borderradius); --clr-sidenav-header-color:var(--clr-h6-color); --clr-sidenav-header-font-weight:var(--clr-h6-font-weight); --clr-sidenav-header-font-family:var(--clr-h6-font-family); --clr-sidenav-color:var(--clr-p1-color); --clr-sidenav-font-weight:var(--clr-p1-font-weight); }
			.table th, .table td { font-size: 0.65rem; line-height: 0.7rem; border-top-style: solid; border-top-width: var(--clr-table-borderwidth, 0.05rem); border-top-color: var(--clr-tablerow-bordercolor, #e8e8e8); padding: 0.55rem 0.6rem; text-align: left; vertical-align: top; }
        '
    }
    $clarityCssShared = '
            .alertOK { color: #61B715; font-weight: bold }
            .alertWarning { color: #FDD008; font-weight: bold }
            .alertCritical { color: #F55047; font-weight: bold }
            .table th, .table td { text-align: left; }

            :root { --cds-global-base: 20; }
            body { margin: 0px; }
            .main-container .content-container .sidenav { flex: 0 0 auto; order: -1; overflow: hidden; }
            .main-container .content-container .content-area > :first-child { margin-top: 0; }
            .main-container .content-container .content-area { flex: 1 1 auto; overflow-y: auto; -webkit-overflow-scrolling: touch; padding: 1.2rem 1.2rem 1.2rem 1.2rem; }
            .main-container header, .main-container .header { flex: 0 0 3rem; }
            .main-container .header .branding { max-width: auto; min-width: 0px; overflow: hidden; }
            .main-container .sub-nav, .main-container .subnav { flex: 0 0 1.8rem; }
            .main-container .content-container { display: flex; flex: 1 1 auto; min-height: 0.05rem; }
            header .branding, .header .branding { display: flex; flex: 0 0 auto; min-width: 10.2rem; padding: 0px 1.2rem; height: 3rem; }
            header .branding .title, .header .branding .title { color: #fafafa; font-weight: 400; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 0.8rem; letter-spacing: 0.01em; line-height: 3rem; text-decoration: none; }
            header .branding > a, header .branding > .nav-link, .header .branding > a, .header .branding > .nav-link { display: inline-flex; align-items: center; height: 3rem; }
            header .branding .clr-icon, header .branding cds-icon, header .branding clr-icon, .header .branding .clr-icon, .header .branding cds-icon, .header .branding clr-icon { flex-grow: 0; flex-shrink: 0; height: 1.8rem; width: 1.8rem; margin-right: 0.45rem; }

            ul:not([cds-list]), ol:not([cds-list]) { list-style-position: inside; margin-left: 0; margin-top: 0; margin-bottom: 0; padding-left: 0; }
            a { background-color: transparent; -webkit-text-decoration-skip: objects; }
            h1 { font-size: 2em; margin: 0.67em 0px; }
            img { border-style: none; }
            img { vertical-align: middle; }
            *, ::before, ::after { box-sizing: border-box; }
            *, ::before, ::after { box-sizing: inherit; }
            table { border-spacing: 0px; }
            pre { margin: 0.6rem 0px; }
            html { box-sizing: border-box; }
			html { -webkit-tap-highlight-color: transparent; }
            html { -ms-overflow-style: scrollbar; -webkit-tap-highlight-color: rgba(0, 0, 0, 0); }
            html { font-family: sans-serif; line-height: 1.15; -ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%; }
            .table tbody tr:first-child td { border-top: 0px none; }
			.table thead th:first-child { border-top-right-radius: 0px; border-bottom-right-radius: 0px; border-bottom-left-radius: 0px; border-top-left-radius: var(--clr-table-cornercellradius, 0.1rem); }
			.table thead th:last-child { border-top-left-radius: 0px; border-bottom-right-radius: 0px; border-bottom-left-radius: 0px; border-top-right-radius: var(--clr-table-cornercellradius, 0.1rem); }
			.table tbody:last-child tr:last-child td:first-child { border-top-left-radius: 0px; border-top-right-radius: 0px; border-bottom-right-radius: 0px; border-bottom-left-radius: var(--clr-table-cornercellradius, 0.1rem); }
			.table tbody:last-child tr:last-child td:last-child { border-top-left-radius: 0px; border-top-right-radius: 0px; border-bottom-left-radius: 0px; border-bottom-right-radius: var(--clr-table-cornercellradius, 0.1rem); }

            @font-face {font-family: ClarityCityRegular;src: url(data:font/ttf;base64,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AvQAWwLlABkEKwAeBCsAHgQrAB4EKwAeBCsAHgKlABwCoQATAqEAEwKhABMCoQATAqEAEwJlACwCZQAsAmUALAJlACwCLQAkAi0AJAItACQCLQAkAi0AJAItACQCLQAkAi0AJAItACQCLQAkA7IAJAJ7AFcCBwApAgcAKQIHACkCBwApAnsALwJZACsCpQAvAnsALwJHACwCRwAsAkcALAJHACwCRwAsAkcALAJYACwCRwAsAkcALAJYACwCRwAsAT0AGAJ2ACoCdgAqAnYAKgJZAFcA+QBLAPkAVwD5AFcA+f/2APn/7wD5/9IA+f/iAPkAMADv/84A7//OAiUAVwIlAFcA+QBXAPkAVwEWAFcBJwAcA4kAVwJZAFcCWQBXAlkAVwJZAFcCWQBXAmkAKgJpACoCaQAqAmkAKgJpACoCaQAqAmkAKgKBADMCaQAqBCAAKgJ7AFcCfABYAnsALwGMAFcBjABXAYwAVgGMAFcB3gAhAd4AIQHeACEB3gAhAkMAVwFZABUBuQAVAVkAFQJZAEsCWQBLAlkASwJZAEsCWQBLAlkASwJZAEsCWQBLAlkASwIRAAoDHQAQAx0AEAMdABADHQAQAx0AEAH/AAwCGAAJAhgACQIYAAkCGAAJAhgACQHbACEB2wAhAdsAIQHbACECewAvAnsALwJ7AC8CewAvAnsALwJ7AC8CewAvAnsALwJ7AC8CewAvArMAPAFlABQCNQAiAkYAHgJMABsCUQA3AmgAPwIDABYCbQA7AmgAMgFEAGwBOgBlATMAYwE1AGMC1ABsAT0AaAE9AGkCCQAiAgkAMwFBAG0BrgBfAc8AVgKxAC8BtAAAAbQAAAFIADUBSAAaAWIAFgFiABsBcgBpAXIAHQGvAFYCfQBWA64AVgMAAFYB4ABUAeAAUAHgAFQBGABQARgAVAIBACICAAAsATsAIgE6ACwBygBdARYAXQPoAAAB9AAAAPoAAAETAAAApgAAAU0AAAJcAFECkgBGAzkAUAKcAFUC8QA6Ak8AQgLPAIICFgBOAlMARALRAIMCUQBPAlEAOwIbAG0B/AA/A0YAPwS6AD8DqABJAsIAPwKYAD0DrQBKApUAVANBAFMBQgCDAAD/UgAA/10BBwAeAZEANQFbACYBJQAwAVsAJgGxAEsA8QBLAQMAHQHOAB0B4gBWASYAQwFNAD8BxABC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)
        </style>
        </head>
            <body>
                <div class="main-container">
                    <header class="header header-6">
                        <div class="branding">
                            <a href="">
                                <cds-icon shape="vm-bug">
                                    <img height="36px" width="36px" src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDI2LjIuMSwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPgo8c3ZnIHZlcnNpb249IjEuMSIgaWQ9IkxheWVyXzEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHg9IjBweCIgeT0iMHB4IgoJIHZpZXdCb3g9IjAgMCAzNiAzNiIgc3R5bGU9ImVuYWJsZS1iYWNrZ3JvdW5kOm5ldyAwIDAgMzYgMzY7IiB4bWw6c3BhY2U9InByZXNlcnZlIj4KPHN0eWxlIHR5cGU9InRleHQvY3NzIj4KCS5zdDB7ZmlsbDojMDA5MURBO30KCS5zdDF7ZmlsbDojMUQ0MjhBO30KCS5zdDJ7ZmlsbDojMDBDMUQ1O30KPC9zdHlsZT4KPHBhdGggY2xhc3M9InN0MCIgZD0iTTI4LjIsMzAuNGMtMC4zLDAtMC41LTAuMi0wLjYtMC40Yy0wLjItMC40LDAtMC44LDAuMy0wLjljMy45LTEuOCw2LjQtNS43LDYuNC05LjljMC0yLjMtMC43LTQuNC0yLTYuMwoJYy0xLjMtMS44LTMtMy4yLTUuMS00Yy0wLjQtMC4xLTAuNi0wLjYtMC40LTAuOWMwLjEtMC40LDAuNi0wLjYsMC45LTAuNGMyLjMsMC45LDQuMywyLjQsNS44LDQuNWMxLjUsMi4xLDIuMyw0LjUsMi4zLDcuMQoJYzAsNC44LTIuOCw5LjItNy4yLDExLjJDMjguNCwzMC40LDI4LjMsMzAuNCwyOC4yLDMwLjR6Ii8+CjxwYXRoIGNsYXNzPSJzdDEiIGQ9Ik0yMy4yLDExLjNjLTAuMSwwLTAuMiwwLTAuMywwYy0wLjUtMS44LTEuNi0zLjMtMy4xLTQuNWMtMS43LTEuMy0zLjctMi01LjgtMmMtNS4xLDAtOS4zLDQuMS05LjMsOS4yCgljMCwwLDAsMC4xLDAsMC4xYy0zLjUsMS4xLTUuNCw0LjktNC4zLDguNGMwLjYsMS44LDEuOSwzLjMsMy43LDQuMXYtMS42Yy0yLjUtMS41LTMuNC00LjctMS45LTcuMmMwLjctMS4zLDItMi4yLDMuNC0yLjVsMC42LTAuMQoJbDAtMC42YzAtMC4yLDAtMC40LDAtMC42YzAtNC4zLDMuNS03LjcsNy44LTcuN2MzLjYsMCw2LjgsMi41LDcuNiw2bDAuMSwwLjZsMC42LTAuMWMwLjIsMCwwLjUsMCwwLjcsMGMzLjYsMCw2LjUsMi45LDYuNSw2LjUKCWMwLDEuOS0wLjgsMy43LTIuMiw0Ljl2MS44YzIuMy0xLjQsMy43LTMuOSwzLjctNi42QzMxLjEsMTQuOCwyNy41LDExLjMsMjMuMiwxMS4zeiIvPgo8cGF0aCBjbGFzcz0ic3QyIiBkPSJNMS4yLDEyLjJjMCwwLTAuMSwwLTAuMSwwYy0wLjQtMC4xLTAuNi0wLjQtMC42LTAuOEMxLjcsNC45LDcuNCwwLjIsMTQsMC4yYzMuMSwwLDYuMiwxLjEsOC42LDMKCWMwLjksMC43LDEuNiwxLjUsMi4zLDIuM2MwLjIsMC4zLDAuMiwwLjgtMC4xLDFjLTAuMywwLjItMC44LDAuMi0xLTAuMWMtMC42LTAuOC0xLjMtMS41LTItMi4xYy0yLjItMS44LTUtMi43LTcuOC0yLjcKCWMtNiwwLTExLjEsNC4yLTEyLjIsMTBDMS44LDEyLDEuNSwxMi4yLDEuMiwxMi4yeiBNMTguMywxOGMtMC40LDAtMC43LDAuMy0wLjgsMC43YzAsMC40LDAuMywwLjcsMC43LDAuOGMwLDAsMCwwLDAuMSwwaDMuOQoJbC04LjUsOC4xYy0wLjMsMC4zLTAuMywwLjcsMCwxYzAuMywwLjMsMC43LDAuMywxLDBsOC41LTh2My45YzAsMC40LDAuNCwwLjcsMC44LDAuN2MwLjQsMCwwLjctMC4zLDAuNy0wLjdWMThMMTguMywxOEwxOC4zLDE4egoJIE0xNC43LDIzLjFWMThIOS42Yy0wLjQsMC0wLjcsMC40LTAuNywwLjhjMCwwLjQsMC4zLDAuNywwLjcsMC43aDIuNkw3LDI0LjJjLTAuMywwLjMtMC4zLDAuNywwLDFjMC4zLDAuMywwLjcsMC4zLDEsMGw1LjItNC44djIuNwoJYzAsMC40LDAuNCwwLjcsMC44LDAuN0MxNC40LDIzLjgsMTQuNywyMy41LDE0LjcsMjMuMUwxNC43LDIzLjF6IE0xOC44LDI4LjZjMCwwLjQsMC4zLDAuNywwLjcsMC43aDIuN2wtNC43LDUuMQoJYy0wLjMsMC4zLTAuMywwLjcsMCwxYzAuMywwLjMsMC43LDAuMywxLDBjMCwwLDAsMCwwLjEtMC4xbDQuNi01VjMzYzAsMC40LDAuMywwLjcsMC43LDAuOGMwLjQsMCwwLjctMC4zLDAuOC0wLjdjMCwwLDAsMCwwLTAuMQoJdi01LjFoLTUuMUMxOS4xLDI3LjksMTguOCwyOC4yLDE4LjgsMjguNkwxOC44LDI4LjZ6Ii8+Cjwvc3ZnPgo=" alt="VMware Cloud Foundation"/>
                                </cds-icon>
                                <span class="title">VMware Cloud Foundation</span>
                            </a>
                        </div>
                    </header>
    '
    $clarityCssHeader += $clarityCssShared
    $clarityCssHeader
}

Function Save-ClarityReportNavigation {
    $clarityCssNavigation = '
            <nav class="subnav">
            <ul class="nav">
            <li class="nav-item">
                <a class="nav-link active" href="">Logging Management - Configuration Report</a>
            </li>
            </ul>
        </nav>
        <div class="content-container">
        <nav class="sidenav">
        <section class="sidenav-content">
            <section class="nav-group collapsible">
                <ul class="nav-list">
                    <li><a class="nav-link" href="#esxi-logging-configuration">&nbsp;&nbsp;&nbsp;ESXi</a></li>
                    <li><a class="nav-link" href="#vcenter-logging-configuration">&nbsp;&nbsp;&nbsp;vCenter Server</a></li>
                    <li><a class="nav-link" href="#sddcmanager-logging-configuration">&nbsp;&nbsp;&nbsp;SDDC Manager</a></li>
                    <li><a class="nav-link" href="#nsx-logging-configuration">&nbsp;&nbsp;&nbsp;NSX</a></li>
                    <li><a class="nav-link" href="#aria-lifecycle-logging-configuration">&nbsp;&nbsp;&nbsp;Aria Lifecycle</a></li>
                    <li><a class="nav-link" href="#aria-ops-logging-configuration">&nbsp;&nbsp;&nbsp;Aria Operations</a></li>
                    <li><a class="nav-link" href="#aria-automation-logging-configuration">&nbsp;&nbsp;&nbsp;Aria Automation</a></li>
                    <input id="logging" type="checkbox"/>
                    <label for="logging">Aria Operations For Logs</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#ariaopsforlogs-agents">Agents</a></li>
                        <li><a class="nav-link" href="#ariaopsforlog-forwarders">Log Forwarders</a></li>
                    </ul>
                </ul>
            </section>
        </section>
        </nav>

        <div class="content-area">
    <div class="content-area">'
    $clarityCssNavigation
}
Function Save-ClarityReportFooter {
    # Define the default Clarity Cascading Style Sheets (CSS) for the HTML report Footer
    $clarityCssFooter = '
                </div>
            </div>
        </div>
    </body>
    </html>'
    $clarityCssFooter
}
#EndRegion  End HTML Report Functions                               ######
##########################################################################
