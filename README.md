<!-- markdownlint-disable first-line-h1 no-inline-html -->

<img src=".github/icon-400px.svg" alt="A PowerShell Module for Cloud Foundation Logging Management" width="150"></br></br>

# PowerShell Module for VMware Cloud Foundation Logging Management

[<img src="https://img.shields.io/badge/Documentation-Read-blue?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Documentation">][docs-module]&nbsp;&nbsp;
[<img src="https://img.shields.io/badge/Changelog-Read-blue?style=for-the-badge&logo=github&logoColor=white" alt="CHANGELOG" >][changelog]

[<img src="https://img.shields.io/powershellgallery/v/VMware.CloudFoundation.LoggingManagement?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell Gallery">][psgallery-module]&nbsp;&nbsp;
<img src="https://img.shields.io/powershellgallery/dt/VMware.CloudFoundation.LoggingManagement?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell Gallery Downloads">

## Overview

`VMware.CloudFoundation.LoggingManagement` is a PowerShell module that supports the ability to generate  HTML logging configuration report and manage logging configurations across your [VMware Cloud Foundatiоn][docs-vmware-cloud-foundation] instance.

With these cmdlets, you can perform the following actions on a VMware Cloud Foundation instance or a specific workload domain.

The module provides coverage for the following:

=== ":material-shield-check: &nbsp; Logging Management"

    1. Generate a logging configuration report for the components across your VMware Cloud Foundation.

    Components:

    * VMware SDDC Manager
    * VMware vCenter Server
    * VMware ESXi
    * VMware NSX Manager
    * VMware NSX Edge
    * VMware Aria Suite Lifecycle
    * VMware Aria Operations
    * VMware Aria Operations for Logs
    * VMware Aria Automation

## Documentation

Please refer to the [documentation][docs-module] for more information on how to use this module.

## Contributing

The project team welcomes contributions from the community. Before you start working with project, please read our
[Developer Certificate of Origin][vmware-cla-dco].

All contributions to this repository must be signed as described on that page. Your signature certifies that you wrote
the patch or have the right to pass it on as an open-source patch.

For more detailed information, refer to the [contribution guidelines][contributing] to get started.

## Support

While this module is not supported by VMware Support Services, it is supported by the project maintainers and its community of users.

Use the GitHub [issues][gh-issues] to report bugs or suggest features and enhancements. Issues are monitored by the maintainers and are prioritized based on criticality and community [reactions][gh-reactions].

Before filing an issue, please search the issues and use the reactions feature to add votes to matching issues. Please include as much information as you can. Details like these are incredibly useful in helping the us evaluate and prioritize any changes:

- A reproducible test case or series of steps.
- Any modifications you've made relevant to the bug.
- Anything unusual about your environment or deployment.

You can also start a discussion on the GitHub [discussions][gh-discussions] area to ask questions or share ideas.

## License

Copyright 2024 Broadcom. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
disclaimer.

1. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES;LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[//]: Links

[changelog]: CHANGELOG.md
[contributing]: CONTRIBUTING.md
[docs-vmware-cloud-foundation]: https://docs.vmware.com/en/VMware-Cloud-Foundation
[docs-module]: https://vmware.github.io/powershell-module-for-vmware-cloud-foundation-logging-management
[gh-discussions]: https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-logging-management/discussions
[gh-issues]: https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-logging-management/issues
[gh-reactions]: https://blog.github.com/2016-03-10-add-reactions-to-pull-requests-issues-and-comments/
[psgallery-module]: https://www.powershellgallery.com/packages/VMware.CloudFoundation.LoggingManagement
[vmware-cla-dco]: https://cla.vmware.com/dco
