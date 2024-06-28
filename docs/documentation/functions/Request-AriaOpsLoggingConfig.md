# Request-AriaOpsLoggingConfig

## Synopsis

Return the logging configuration from VMware Aria Operations.

## Syntax

```powershell
Request-AriaOpsLoggingConfig [-server] <String> [-user] <String> [[-pass] <String>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Request-AriaOpsLoggingConfig` cmdlet returns logging configuration of VMware Aria Operations.
The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity and authentication is possible to SDDC Manager
- Validates that network connectivity and authentication is possible to vCenter Server

## Examples

### Example 1

```powershell
Request-AriaOpsLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123!
This example returns the logging configuration of VMware Aria Operations.
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

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
