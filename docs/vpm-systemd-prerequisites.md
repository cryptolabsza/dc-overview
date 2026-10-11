# VPM host ownership verification

VPM installation, update, and adoption require a Linux systemd host with
`systemctl` and `busctl` supporting `--json=short`. Run the host CLI with its
normal root authority so it can inspect the system manager's loaded unit and
credential reference metadata. An unavailable tool or unreadable metadata blocks
the operation; it does not relax custody verification.

Credential checks read the credential IDs and source references, including the
absence of plain or imported credentials on generated services. They do not
read credential values. File custody requires no generated container service;
an existing undeclared canonical service must be resolved through an explicit
ownership declaration before adoption. Declared source timers must target their
corresponding declared service; unknown or additional targets block transfer.
