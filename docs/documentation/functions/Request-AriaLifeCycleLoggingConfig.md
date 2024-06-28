# Request-AriaLifeCycleLoggingConfig

## Synopsis

Requests the logging configuration for VMware Aria Suite Lifecycle.

## Syntax

```powershell
Request-AriaLifeCycleLoggingConfig [-server] <String> [-user] <String> [-pass] <String>
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Request-AriaLifeCycleLoggingConfig` cmdlet returns logging configuration of VMware Aria LifeCycle
The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity and authentication is possible to SDDC Manager
- Validates that network connectivity and authentication is possible to vCenter Server
- Validated that network connectivity and authentication is possible to Aria Automation

## Examples

### Example 1

```powershell
Request-AriaLifeCycleLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123!
This example returns the logging configuration of VMware Aria Suite Lifecycle
```

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
