# Worker SSH host trust

DC Overview's ordinary worker connections require host keys enrolled by an
administrator before platform checks, privilege checks, key provisioning,
installation, update, verification or recovery. Unknown and changed keys stop
the SSH handshake before worker authentication or commands. A password does
not change this requirement. DC Overview never scans, adds, replaces or writes
host keys automatically.

Key provisioning may create an unused local fleet key before the remote
handshake. Existing fleet keys are retained; a refused remote handshake never
installs that key on the worker or authorizes remote changes.

## Trust file

The normal controller trust file is `/etc/dc-overview/known_hosts`.
`SSHManager` uses `known_hosts` in its configured controller directory. Legacy
deployment/exporter helpers use the normal controller path. An explicit
`DC_OVERVIEW_SSH_KNOWN_HOSTS` environment variable overrides all these paths;
a supplied server adapter's `ssh_known_hosts_path` overrides the normal path
when the environment override is absent. These are transport configuration
inputs, not new CLI flags or persistent inventory fields.

Use an absolute path to an existing, readable, nonempty OpenSSH known_hosts
file. Paths with spaces are supported. Control characters, relative paths and
`$` environment-expansion characters are rejected. Literal `%` characters are
escaped for OpenSSH. A missing, empty, malformed or group/world-writable file
holds the connection with an enrollment diagnostic. There is no fallback to
another file after an explicit path fails.

The file contains **public** host keys, not passwords, private fleet keys or
API credentials. Keep the controller directory administrator-owned, normally
mode `0755`, and the file administrator-owned, normally `0644` (or `0600` if
the process uses the same account). The DC process must be able to read it.
For a controller container, mount the administrator-maintained file read-only
at the configured path. Do not copy private credentials into it.

## Enrollment through the normal OpenSSH file

1. Use a trusted console or an independently authenticated administrator
   channel to obtain the worker's SSH public host key, for example the content
   of `/etc/ssh/ssh_host_ed25519_key.pub`. Record the actual hostname/address and
   SSH port used by the controller. Never retrieve the private host key.
2. Obtain its SHA256 fingerprint independently from the worker owner or trusted
   console. On an administrator machine, inspect the received public key with
   `ssh-keygen -lf /path/to/received-host-key.pub -E sha256` and compare the
   complete fingerprint. An unverified network scan is not proof of identity.
3. After the comparison passes, add the verified public key to the normal
   known_hosts file using standard OpenSSH syntax. For port 22, a line begins
   with `worker.example` or the actual IP followed by the public key's type and
   base64 value. For a different port, use `[worker.example]:2202`. Enroll every
   independently verified address/alias the controller actually uses. Preserve
   existing entries and permissions.
4. Run the normal DC worker operation again. No bootstrap script, trust-on-first
   connection prompt or special installation command is needed.

OpenSSH hashed hostnames and valid host-key algorithms are supported. A hashed
name can be created through the ordinary `ssh-keygen -H -f` workflow after
fingerprint verification. Keep the administrator's trusted source record.

## Routing and certificate authorities

OpenSSH retains ordinary operator routing configuration, including `HostName`
and `ProxyJump`. The target connection pins the selected known_hosts file,
strict verification, no DNS host-key trust, no alternate global trust file or
`KnownHostsCommand`, no automatic host-key updates and no agent forwarding.
It disables multiplex socket reuse so each operation verifies host identity.

A bastion or custom `ProxyCommand` is a separate operator-controlled transport.
Enroll bastion host keys independently and require strict verification in its
own SSH configuration; target options are not automatically forwarded to
OpenSSH jump-host helper processes. The controller's target trust file does
not establish bastion identity or authorize an arbitrary routing command.

If the organization uses host certificates, an explicitly enrolled
`@cert-authority` entry in the selected file is the actual OpenSSH authority;
there is no implicit global/system CA fallback. OpenSSH also retains
`@revoked` policy. Paramiko has no equivalent OpenSSH certificate-authority or
revocation handling, so a file with these markers is refused by that transport.
Use the OpenSSH password transport with its normal `sshpass` prerequisite or
an administrator-approved ordinary pinned-key file for Paramiko. Paramiko
loads only the selected file, rejects missing keys, disables SSH agents and
implicit private-key searches, and uses bounded handshake/authentication waits.
An organization-managed system trust file can be used by explicitly selecting
its absolute path through the same transport configuration; it is never chosen
as an implicit fallback.

## Failure and recovery

If trust is unavailable, check the exact configured path, container mount,
readability, formatting and permissions. If the file has no entry for the
actual hostname/port, complete enrollment above. If the key has changed, stop
and have the worker owner explain and independently verify the replacement.
Preserve the old trust record; only an authorized administrator may retire the
old entry and enroll the verified replacement. DC Overview never silently
replaces a pin, retries with weaker verification or uses `/dev/null` as its
user trust file. Recovery and rollback require the same verified SSH identity.

Passwords used with `sshpass` are passed through its environment input rather
than command arguments. Host trust and worker login credentials remain separate
administrator responsibilities.
