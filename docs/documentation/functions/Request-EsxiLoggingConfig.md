# Request-EsxiLoggingConfig

## Synopsis

Publishes the logging configuration for ESX hosts.

## Syntax

```powershell
Request-EsxiLoggingConfig [-server] <String> [-user] <String> [-pass] <String> [-domain] <String>
 [-cluster] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Publish-EsxiLoggingConfig` cmdlet returns logging configuration of all ESX hosts.
The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity and authentication is possible to SDDC Manager.
- Validates that network connectivity and authentication is possible to vCenter.

## Examples

### Example 1

```powershell
Request-EsxiLoggingConfig -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -cluster [cluster_name]
```

This example returns the logging configuration of all ESX hosts in a specified cluster in a VCF instance.

### Example 2

```powershell
Request-EsxiLoggingConfig -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name]
```

This example returns the logging configuration of all ESX hosts in a specified workload domain in a VCF instance.

## Parameters

### -server

The fully qualified domain name of the SDDC Manager instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
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
Position: 2
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

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -domain

The name of the workload domain to retrieve the logging configuration from.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -cluster

The name of the cluster to retrieve the logging configuration from.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
