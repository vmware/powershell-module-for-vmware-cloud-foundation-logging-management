<!-- markdownlint-disable first-line-h1 no-inline-html -->

<img src="assets/images/icon-color.svg" alt="PowerShell Module for VMware Cloud Foundation Logging Management" width="150">

# PowerShell Module for VMware Cloud Foundation Logging Management

[:material-powershell: &nbsp; PowerShell Gallery][psgallery-module-logging-management]{ .md-button .md-button--primary }

`VMware.CloudFoundation.LoggingManagement` is a PowerShell module that supports the ability to generate HTML logging configuration report and manage logging configurations across your [VMware Cloud Foundatiоn][docs-vmware-cloud-foundation] instance.

With these cmdlets, you can perform the following actions on a VMware Cloud Foundation instance or a specific workload domain.

The module provides coverage for the following:

1. Generate a logging configuration report for the components across your VMware Cloud Foundation.

   Components:

   - VMware SDDC Manager
   - VMware vCenter Server
   - VMware ESXi
   - VMware NSX Manager
   - VMware NSX Edges
   - VMware Aria Suite Lifecycle
   - VMware Aria Operations
   - VMware Aria Operations for Logs
   - VMware Aria Automation

## Requirements

### Platforms

The following table lists the supported platforms for this module.

| Platform                                                     | Support                             |
| ------------------------------------------------------------ | ----------------------------------- |
| :fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 5.2 | :fontawesome-solid-check:{ .green } |
| :fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 5.1 | :fontawesome-solid-check:{ .green } |
| :fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 5.0 | :fontawesome-solid-check:{ .green } |
| :fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 4.5 | :fontawesome-solid-check:{ .green } |
| :fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 4.4 | :fontawesome-solid-check:{ .green } |

### Operating Systems

The following table lists the supported operating systems for this module.

| Operating System                                                       | Version    |
| ---------------------------------------------------------------------- | ---------- |
| :fontawesome-brands-windows: &nbsp; Microsoft Windows Server           | 2019, 2022 |
| :fontawesome-brands-windows: &nbsp; Microsoft Windows                  | 10, 11     |
| :fontawesome-brands-linux: &nbsp; [VMware Photon OS][github-os-photon] | 3.0, 4.0   |

### PowerShell

The following table lists the supported editions and versions of PowerShell for this module.

| Edition                                                              | Version  |
| -------------------------------------------------------------------- | -------- |
| :material-powershell: &nbsp; [PowerShell Core][microsoft-powershell] | >= 7.2.0 |

### Module Dependencies

The following table lists the required PowerShell module dependencies for this module.

| PowerShell Module                                    | Version   | Publisher | Reference                                                                  |
| ---------------------------------------------------- | --------- | --------- | -------------------------------------------------------------------------- |
| [VMware.PowerCLI][psgallery-module-powercli]         | >= 13.2.1 | Broadcom  | :fontawesome-solid-book: &nbsp; [Documentation][developer-module-powercli] |
| [VMware.vSphere.SsoAdmin][psgallery-module-ssoadmin] | >= 1.3.9  | Broadcom  | :fontawesome-brands-github: &nbsp; [GitHub][github-module-ssoadmin]        |
| [PowerVCF][psgallery-module-powervcf]                | >= 2.4.1  | Broadcom  | :fontawesome-solid-book: &nbsp; [Documentation][docs-module-powervcf]      |
| [PowerValidatedSolutions][psgallery-module-pvs]      | >= 2.11.0 | Broadcom  | :fontawesome-solid-book: &nbsp; [Documentation][docs-module-pvs]           |

[docs-vmware-cloud-foundation]: https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html
[microsoft-powershell]: https://docs.microsoft.com/en-us/powershell
[psgallery-module-powercli]: https://www.powershellgallery.com/packages/VMware.PowerCLI
[psgallery-module-powervcf]: https://www.powershellgallery.com/packages/PowerVCF
[psgallery-module-logging-management]: https://www.powershellgallery.com/packages/VMware.CloudFoundation.LoggingManagement
[psgallery-module-pvs]: https://www.powershellgallery.com/packages/PowerValidatedSolutions
[psgallery-module-ssoadmin]: https://www.powershellgallery.com/packages/VMware.vSphere.SsoAdmin
[developer-module-powercli]: https://developer.vmware.com/tool/vmware-powercli
[docs-module-powervcf]: https://vmware.github.io/powershell-module-for-vmware-cloud-foundation
[docs-module-pvs]: https://vmware.github.io/power-validated-solutions-for-cloud-foundation
[github-module-ssoadmin]: https://github.com/vmware/PowerCLI-Example-Scripts/tree/master/Modules/VMware.vSphere.SsoAdmin
[github-os-photon]: https://vmware.github.io/photon/
