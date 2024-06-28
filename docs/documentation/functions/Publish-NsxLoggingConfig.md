# Publish-NsxLoggingConfig

## Synopsis

Publishes the logging configuration for NSX Managers and NSX Edges.

## Syntax

### All-WorkloadDomains

```powershell
Publish-NsxLoggingConfig -server <String> -user <String> [-pass <String>] [-allDomains] [-json]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-NsxLoggingConfig -server <String> -user <String> [-pass <String>] -workloadDomain <String> [-json]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Publish-NsxLoggingConfig` cmdlet returns logging configuration of NSX Managers and NSX Edges.

## Examples

### Example 1

```powershell
Publish-NsxLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -alldomains
This example returns the logging configuration of the all the NSX Managers and NSX Edge Nodes in your VCF environment.
```

### Example 2

```powershell
Publish-NsxLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -workoadDomain sfo-m01
This example returns the logging configuration of the NSX Manager and NSX Edge Nodes in the given workload domain.
```

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
