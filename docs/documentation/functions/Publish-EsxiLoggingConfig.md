# Publish-EsxiLoggingConfig

## Synopsis

Publishes the logging configuration for ESX hosts.

## Syntax

### All-WorkloadDomains

```powershell
Publish-EsxiLoggingConfig [-server] <String> [-user] <String> [-pass <String>] [-allDomains] [-json]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-EsxiLoggingConfig [-server] <String> [-user] <String> [-pass <String>] [-workloadDomain] <String> [-json]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Publish-EsxiLoggingConfig` cmdlet returns logging configuration of all ESX hosts.
The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity and authentication is possible to SDDC Manager.
- Validates that network connectivity and authentication is possible to vCenter.

## Examples

### Example 1

```powershell
Publish-EsxiLoggingConfig -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains
```

This example returns the logging configuration of all ESX hosts in your VCF environment.

### Example 2

```powershell
Publish-EsxiLoggingConfig -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name]
```

This example returns the logging configuration of all ESX hosts in a specified workload domain.

## Parameters

### -server

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

### -user

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

### -pass

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

### -allDomains

Switch to publish the logging configuration for all workload domains.

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

Switch to publish the logging configuration for a specific workload domain.

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

### -json

Switch to publish the logging configuration in JSON format.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
