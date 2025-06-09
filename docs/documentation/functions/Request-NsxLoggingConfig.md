# Request-NsxLoggingConfig

## Synopsis

Return the logging configuration from NSX Manager and NSX Edge Nodes.

## Syntax

```powershell
Request-NsxLoggingConfig [-server] <String> [-user] <String> [-pass] <String> [-domain] <String>
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Request-NsxLoggingConfig` cmdlet retrieves the logging configuration from NSX Manager and NSX Edge Nodes.
The cmdlet connects to SDDC Manager using the -server, -user, and -password values.

- Validates that network connectivity and authentication is possible to SDDC Manager.
- Validates that network connectivity and authentication is possible to NSX Manager.
- Gathers the NSX Edge Node details from NSX Manager.

## Examples

### Example 1

```powershell
Request-NsxLoggingConfig -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name]
```

This example retrieves the logging configuration from NSX Manager and NSX Edge Nodes for a specified workload domain.

## Parameters

### -server

The fully qualified domain name of the SDDC Manager.

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

The username to authenticate to the SDDC Manager.

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

The password to authenticate to the SDDC Manager.

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

The name of the workload domain to run against.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
