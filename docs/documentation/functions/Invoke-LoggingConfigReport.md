# Invoke-LoggingConfigReport

## SYNOPSIS

Generates a Logging Configuration report for a workload domain or all workload domains.

## SYNTAX

### All-WorkloadDomains

```powershell
Invoke-LoggingConfigReport -sddcManagerFqdn <String> -sddcManagerUser <String> [-sddcManagerPass <String>]
 [-sddcManagerLocalUser <String>] [-sddcManagerLocalPass <String>] -reportPath <String> [-allDomains]
 [-darkMode] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Invoke-LoggingConfigReport -sddcManagerFqdn <String> -sddcManagerUser <String> [-sddcManagerPass <String>]
 [-sddcManagerLocalUser <String>] [-sddcManagerLocalPass <String>] -reportPath <String>
 -workloadDomain <String> [-darkMode] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION

The Invoke-LoggingConfigAuditReport generates a logging configuration report for a VMware Cloud Foundation instance.

## EXAMPLES

### EXAMPLE 1

```powershell
Invoke-LoggingConfigReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser administrator@vsphere.local -sddcManagerPass VMw@re123! -sddcManagerLocalUser vcf -sddcManagerLocalPass VMw@re1! -reportPath "F:\Reporting" -darkMode -allDomains
This example runs a logging configuration report for all workload domains within an SDDC Manager instance.
```

### EXAMPLE 2

```powershell
Invoke-LoggingConfigReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser administrator@vsphere.local -sddcManagerPass VMw@re123! -sddcManagerLocalUser vcf -sddcManagerLocalPass VMw@re1! -reportPath "F:\Reporting" -darkMode -workloadDomain sfo-m01
This example runs a logging configuration report for the provided workload domain within an SDDC Manager instance.
```

## PARAMETERS

### -sddcManagerFqdn

The fully qualified domain name of the SDDC Manager instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -sddcManagerUser

The username to authenticate to the SDDC Manager instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -sddcManagerPass

The password to authenticate to the SDDC Manager instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -sddcManagerLocalUser

The username to authenticate to the SDDC Manager appliance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -sddcManagerLocalPass

The password to authenticate to the SDDC Manager appliance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -reportPath

The path to save the report to.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -allDomains

Switch to run the report for all workload domains.

```yaml
Type: SwitchParameter
Parameter Sets: All-WorkloadDomains
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -workloadDomain

Switch to run the report for a specific workload domain.

```yaml
Type: String
Parameter Sets: Specific-WorkloadDomain
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -darkMode

Switch to use dark mode for the report.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
