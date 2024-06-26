# Publish-AriaLifecycleLoggingConfig

## SYNOPSIS

Publishes the logging configuration for VMware Suite Aria Lifecycle.

## SYNTAX

```powershell
Publish-AriaLifecycleLoggingConfig [-server] <String> [-user] <String> [[-pass] <String>] [-json]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION

The Publish-AriaLifecycleLoggingConfig cmdlet returns logging configuration of VMware Aria Suite Lifecycle.

## EXAMPLES

### EXAMPLE 1

```powershell
Publish-AriaLifecycleLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123!
This example returns the logging configuration of the VMware Aria Suite Lifecycle in your VCF environment.
```

## PARAMETERS

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
