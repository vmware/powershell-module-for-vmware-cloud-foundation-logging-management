# Request-SddcManagerLoggingConfig

## Synopsis

Requests the logging configuration for SDDC Manager.

## Syntax

```powershell
Request-SddcManagerLoggingConfig [-server] <String> [-user] <String> [[-pass] <String>] [-localUser] <String>
 [[-localPass] <String>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Request-SddcManagerLoggingConfig` gets the logging configuration from SDDC Manager.

## Examples

### Example 1

```powershell
Request-SddcManagerLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -localUser vcf -localPass VMw@re1!
This example gets the logging configuration from SDDC Manager.
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

### -localUser

The username to authenticate to the SDDC Manager appliance.

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

### -localPass

The password to authenticate to the SDDC Manager appliance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
