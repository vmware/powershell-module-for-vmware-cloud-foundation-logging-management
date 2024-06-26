# Publish-EsxiLoggingConfig

## SYNOPSIS

Publishes the logging configuration for ESXi hosts.

## SYNTAX

### All-WorkloadDomains

```powershell
Publish-EsxiLoggingConfig -server <String> -user <String> [-pass <String>] [-allDomains] [-json]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-EsxiLoggingConfig -server <String> -user <String> [-pass <String>] -workloadDomain <String> [-json]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION

The Publish-EsxiLoggingConfig cmdlet returns logging configuration of all ESXi hosts.
The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity and authentication is possible to SDDC Manager
- Validates that network connectivity and authentication is possible to vCenter Server

## EXAMPLES

### EXAMPLE 1

```powershell
Publish-EsxiLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -allDomains
This example returns the logging configuration of all ESXi hosts in your VCF environment.
```

### EXAMPLE 2

```powershell
Publish-EsxiLoggingConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -workloadDomain sfo-w01
This example returns the logging configuration of all ESXi hosts in the provided workload domain.
```

## PARAMETERS

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
