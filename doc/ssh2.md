# Tcl Interface to SSH2 Protocol (libssh2)

A Tcl interface to the SSH2 protocol via libssh2, enabling secure shell connections, remote authentication, and encrypted communication with SSH servers.

**Version:** 0.1 (Work In Progress) \
**Package:** `ssh2` \
**Namespace:** `ssh::`

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Current Status](#current-status)
4. [Installation](#installation)
5. [Command Reference](#command-reference)
   - 5.1 [Connection Management](#connection-management)
   - 5.2 [Authentication](#authentication)
6. [Channel Options](#channel-options)
7. [Usage Examples](#usage-examples)
8. [Security Considerations](#security-considerations)
9. [Best Practices](#best-practices)
10. [Troubleshooting](#troubleshooting)
11. [Technical Details](#technical-details)
12. [License](#license)

---

## Overview

The **ssh2** package provides a Tcl interface to the SSH2 protocol through the libssh2 library. It implements SSH as a stacked Tcl channel, transparently wrapping existing TCP socket connections with SSH protocol encryption and authentication.

This enables Tcl applications to:
- Establish secure shell sessions with remote servers
- Authenticate using multiple methods (password, public key)
- Execute interactive shell commands over encrypted connections
- Access remote systems securely from Tcl scripts

---

## Key Features

- **SSH2 Protocol Support**: Full SSH2 implementation via libssh2
- **Stacked Channel Architecture**: Wraps existing TCP sockets transparently
- **Multiple Authentication Methods**:
  - Password authentication
  - Public key authentication (RSA/DSA/ECDSA)
  - Keyboard-interactive (planned)
- **PTY/Terminal Support**: Pseudo-terminal with configurable dimensions
- **Non-blocking I/O**: Integrates with Tcl event loop
- **Host Fingerprint Retrieval**: SHA1 fingerprints for host verification
- **Standard Tcl Channel Interface**: Uses familiar `gets`, `puts`, `read`, `fconfigure`

---

## Current Status

**Version 0.1 - Work In Progress**

⚠️ **WARNING: This extension is in early development and NOT production-ready**

### Working Features ✓
- SSH session establishment over TCP connections
- Password authentication
- Public key authentication
- Interactive shell sessions with PTY
- Channel read/write operations
- Host fingerprint retrieval (SHA1)
- Terminal dimension configuration
- Non-blocking mode support

### Missing/Incomplete Features ✗
- **Host key verification** ⚠️ CRITICAL SECURITY ISSUE
- Keyboard-interactive authentication
- SFTP file transfers
- Remote command execution (exec mode without PTY)
- Port forwarding (local and remote)
- SCP file transfer
- SSH agent integration
- Comprehensive error handling
- Known_hosts management

### Security Warnings

🔴 **CRITICAL**: No host key verification - vulnerable to MITM attacks \
🔴 Fingerprints retrieved but NOT validated against known_hosts \
🔴 Not suitable for production use or security-critical applications

---

## Installation

```tcl
package require ssh2
```

### Requirements

**Build-time**:
- Tcl 8.5 or later
- libssh2 library and development headers
- C compiler (gcc/clang/MSVC)
- Autoconf and GNU Make
- TEA (Tcl Extension Architecture) 3.9

**Runtime**:
- Tcl 8.5+
- libssh2 library:
  - Windows: `libssh2.dll`
  - Linux: `libssh2.so`

### Building from Source

**Linux**:
```bash
# Install libssh2
sudo apt-get install libssh2-1-dev   # Debian/Ubuntu
sudo yum install libssh2-devel       # RedHat/CentOS

# Build
cd D:\CM.tcltk\tcltk86\external\tclssh2
autoconf
./configure
make
make test
make install
```

**Windows**:
```bash
# Ensure libssh2.dll is in PATH
cd D:\CM.tcltk\tcltk86\external\tclssh2
autoconf
./configure
make
make install
```

---

## Command Reference

### Connection Management

#### `ssh::import`

Wraps a TCP socket channel with SSH2 protocol and performs the SSH handshake.

**Syntax:**
```tcl
set sshChannel [ssh::import socketChannel]
```

**Parameters:**

- `socketChannel` - An existing TCP socket channel connected to an SSH server (port 22)

**Returns:**

- SSH channel identifier (stacked channel handle)

**Description:**

Creates a stacked channel that wraps the TCP socket with SSH encryption. The SSH handshake is performed immediately. The original socket is closed when the SSH channel is closed.

**Errors:**

- Returns error if channel is invalid
- Returns error if SSH handshake fails
- Returns error if socket is not connected

**Example:**
```tcl
set sock [socket example.com 22]
fconfigure $sock -translation binary -buffering none
set ssh [ssh::import $sock]
```

**Side Effects:**
- Performs SSH protocol handshake with remote server
- Retrieves and stores host fingerprint (SHA1)
- Binds to Tcl event loop for non-blocking I/O

---

### Authentication

#### `ssh::authenticate` (Password)

Authenticates to the SSH server using password authentication and starts an interactive shell session.

**Syntax:**
```tcl
ssh::authenticate sshChannel username password
```

**Parameters:**

- `sshChannel` - SSH channel from `ssh::import`
- `username` - Remote system username (string)
- `password` - User password (string)

**Returns:**

- Empty string on success

**Description:**

Performs password authentication with the remote SSH server. Upon successful authentication:
1. Opens an SSH channel
2. Requests a PTY (pseudo-terminal) with default size 80x24
3. Starts an interactive shell session
4. Channel is ready for I/O operations

**Errors:**

- Returns error on authentication failure
- Returns error on channel creation failure
- Returns error on PTY request failure

**Example:**
```tcl
ssh::authenticate $ssh myuser mypassword
```

**Security Notes:**
- Password transmitted encrypted via SSH
- No password is stored by the extension
- Server must allow password authentication (`PasswordAuthentication yes`)

---

#### `ssh::authenticate` (Public Key)

Authenticates to the SSH server using public key authentication and starts an interactive shell session.

**Syntax:**
```tcl
ssh::authenticate sshChannel username publicKeyPath privateKeyPath ?passphrase?
```

**Parameters:**

- `sshChannel` - SSH channel from `ssh::import`
- `username` - Remote system username (string)
- `publicKeyPath` - Path to public key file (e.g., `~/.ssh/id_rsa.pub`)
- `privateKeyPath` - Path to private key file (e.g., `~/.ssh/id_rsa`)
- `passphrase` - (Optional) Passphrase for encrypted private key

**Returns:**

- Empty string on success

**Description:**

Performs public key authentication using RSA, DSA, or ECDSA keys. Key files must be in OpenSSH or PEM format. After authentication, opens a shell session with PTY.

**Supported Key Types:**
- RSA (most common)
- DSA
- ECDSA
- ED25519 (if libssh2 supports)

**Errors:**

- Returns error if key files not found or unreadable
- Returns error if key format is invalid
- Returns error on authentication failure (key not authorized)
- Returns error if passphrase incorrect

**Examples:**
```tcl
# Unencrypted private key
ssh::authenticate $ssh myuser ~/.ssh/id_rsa.pub ~/.ssh/id_rsa

# Encrypted private key with passphrase
ssh::authenticate $ssh myuser id_rsa.pub id_rsa "my_passphrase"

# Windows paths
ssh::authenticate $ssh myuser "C:/Users/me/.ssh/id_rsa.pub" \
                              "C:/Users/me/.ssh/id_rsa"
```

**Security Notes:**
- Keys never transmitted - only signatures sent
- Private key must have secure permissions (600 on Unix)
- Server must have public key in `~/.ssh/authorized_keys`
- Recommended over password authentication

---

## Channel Options

SSH channels support standard Tcl channel operations plus custom options via `fconfigure`.

### `-fingerprint`

Retrieves the SHA1 fingerprint of the remote host's public key.

**Syntax:**
```tcl
set fingerprint [fconfigure sshChannel -fingerprint]
```

**Returns:**

- 20-byte binary string (SHA1 hash)

**Access:**

- Read-only (cannot be set)

**Description:**

Returns the SHA1 hash of the server's host public key. This can be used to verify the server's identity on first connection.

**⚠️ WARNING:** The extension retrieves but does NOT verify this fingerprint. You must implement verification logic.

**Example:**
```tcl
set fp [fconfigure $ssh -fingerprint]
puts "Host fingerprint: [binary encode hex $fp]"

# Expected output format:
# Host fingerprint: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
```

**Common Use:**
```tcl
# Manual verification (not automatic!)
set known_fp "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
set actual_fp [binary encode hex [fconfigure $ssh -fingerprint]]

if {$actual_fp ne $known_fp} {
    puts stderr "WARNING: Host fingerprint mismatch!"
    puts stderr "Expected: $known_fp"
    puts stderr "Got:      $actual_fp"
    close $ssh
    exit 1
}
```

---

### `-ptysize`

Gets or sets the pseudo-terminal (PTY) dimensions.

**Syntax:**
```tcl
# Set terminal size
fconfigure sshChannel -ptysize {columns rows}

# Get current size
set size [fconfigure sshChannel -ptysize]
```

**Parameters:**

- `columns` - Terminal width in characters (integer)
- `rows` - Terminal height in lines (integer)

**Returns:**

- When setting: empty string
- When getting: two-element list `{columns rows}`

**Default:**

- 80 columns × 24 rows (set during authentication)

**Description:**

Controls the terminal dimensions reported to the remote shell. This affects text wrapping, command-line editing, and full-screen applications (vim, top, etc.).

**Common Sizes:**
- 80×24 (standard VT100)
- 80×43 (EGA)
- 132×24 (wide terminal)
- 132×43 (wide EGA)

**Examples:**
```tcl
# Set to 132 columns × 43 rows
fconfigure $ssh -ptysize {132 43}

# Get current size
set size [fconfigure $ssh -ptysize]
lassign $size cols rows
puts "Terminal: ${cols}x${rows}"

# Standard sizes
fconfigure $ssh -ptysize {80 24}   ;# VT100
fconfigure $ssh -ptysize {132 24}  ;# Wide
```

**When to Use:**
- Before running full-screen applications
- When terminal output wraps incorrectly
- For specific application requirements

---

## Usage Examples

### Example 1: Basic Connection and Command

```tcl
package require ssh2

# Open TCP connection to SSH server
set sock [socket example.com 22]
fconfigure $sock -translation binary -buffering none

# Wrap with SSH protocol
set ssh [ssh::import $sock]

# Check fingerprint (manual verification required!)
set fp [binary encode hex [fconfigure $ssh -fingerprint]]
puts "Server fingerprint: $fp"
# TODO: Verify against known_hosts

# Authenticate
ssh::authenticate $ssh myuser mypassword

# Send command
puts $ssh "uname -a"
flush $ssh

# Read response
after 500  ;# Wait for response
while {[gets $ssh line] >= 0} {
    puts $line
}

# Cleanup
close $ssh
```

---

### Example 2: Public Key Authentication

```tcl
package require ssh2

# Connect
set sock [socket secure-server.example.com 22]
fconfigure $sock -translation binary -buffering none
set ssh [ssh::import $sock]

# Authenticate with public key
ssh::authenticate $ssh myuser \
    ~/.ssh/id_rsa.pub \
    ~/.ssh/id_rsa

# Execute command
puts $ssh "whoami"
flush $ssh

gets $ssh username
puts "Logged in as: $username"

close $ssh
```

---

### Example 3: Interactive Shell Session

```tcl
package require ssh2

proc ssh_connect {host user pass} {
    set sock [socket $host 22]
    fconfigure $sock -translation binary -buffering none

    set ssh [ssh::import $sock]
    ssh::authenticate $ssh $user $pass

    return $ssh
}

# Connect
set ssh [ssh_connect example.com myuser mypass]

# Set larger terminal for vim, etc.
fconfigure $ssh -ptysize {132 43}

# Interactive loop
puts "SSH session established. Type 'exit' to quit."
while {1} {
    # Prompt
    puts -nonewline "ssh> "
    flush stdout

    # Get user input
    gets stdin command
    if {$command eq "exit"} break

    # Send to remote
    puts $ssh $command
    flush $ssh

    # Wait and read response
    after 1000
    fconfigure $ssh -blocking 0
    while {[gets $ssh line] >= 0} {
        puts $line
    }
    fconfigure $ssh -blocking 1
}

puts "Closing connection..."
close $ssh
```

---

### Example 4: Non-blocking I/O with Event Loop

```tcl
package require ssh2

set ssh_output ""

proc ssh_readable {chan} {
    global ssh_output

    if {[eof $chan]} {
        close $chan
        set ::done 1
        return
    }

    if {[gets $chan line] >= 0} {
        puts $line
        append ssh_output $line \n
    }
}

# Connect
set sock [socket example.com 22]
fconfigure $sock -translation binary -buffering none
set ssh [ssh::import $sock]
ssh::authenticate $ssh myuser mypass

# Configure non-blocking
fconfigure $ssh -blocking 0 -buffering line

# Set up event handler
fileevent $ssh readable [list ssh_readable $ssh]

# Send command
puts $ssh "ls -la /tmp"
flush $ssh

# Wait for completion
set done 0
vwait done

puts "\nCaptured [string length $ssh_output] bytes"
```

---

### Example 5: Multiple Commands

```tcl
package require ssh2

proc ssh_exec {ssh command} {
    puts $ssh $command
    flush $ssh

    # Wait for response
    after 500

    set output ""
    fconfigure $ssh -blocking 0
    while {[gets $ssh line] >= 0} {
        append output $line \n
    }
    fconfigure $ssh -blocking 1

    return $output
}

# Connect
set sock [socket example.com 22]
fconfigure $sock -translation binary -buffering none
set ssh [ssh::import $sock]
ssh::authenticate $ssh admin adminpass

# Execute multiple commands
set hostname [ssh_exec $ssh "hostname"]
set uptime [ssh_exec $ssh "uptime"]
set disk [ssh_exec $ssh "df -h /"]

puts "Host: $hostname"
puts "Uptime: $uptime"
puts "Disk: $disk"

close $ssh
```

---

### Example 6: Error Handling

```tcl
package require ssh2

proc safe_ssh_connect {host user pass} {
    if {[catch {
        # Open socket
        set sock [socket $host 22]
        fconfigure $sock -translation binary -buffering none

        # SSH handshake
        set ssh [ssh::import $sock]

        # Verify fingerprint
        set fp [binary encode hex [fconfigure $ssh -fingerprint]]
        puts "Server fingerprint: $fp"
        # TODO: Verify against known_hosts

        # Authenticate
        ssh::authenticate $ssh $user $pass

        puts "Connected to $host as $user"
        return $ssh

    } error]} {
        puts stderr "Connection failed: $error"
        return ""
    }
}

# Try connection
set ssh [safe_ssh_connect example.com myuser mypass]
if {$ssh ne ""} {
    # Use connection
    puts $ssh "echo Success"
    flush $ssh
    gets $ssh result
    puts "Result: $result"

    # Cleanup
    close $ssh
} else {
    puts "Could not establish SSH connection"
    exit 1
}
```

---

### Example 7: File Transfer (Workaround Until SFTP)

```tcl
package require ssh2

proc ssh_upload_base64 {ssh localFile remoteFile} {
    # Read local file
    set fp [open $localFile rb]
    set data [read $fp]
    close $fp

    # Encode to base64
    set encoded [binary encode base64 $data]

    # Transfer via shell
    puts $ssh "cat > $remoteFile.b64 << 'EOF'"
    puts $ssh $encoded
    puts $ssh "EOF"
    flush $ssh

    # Decode on remote
    puts $ssh "base64 -d < $remoteFile.b64 > $remoteFile"
    puts $ssh "rm $remoteFile.b64"
    flush $ssh

    # Wait
    after 1000
}

proc ssh_download_base64 {ssh remoteFile localFile} {
    # Encode on remote
    puts $ssh "base64 < $remoteFile"
    flush $ssh

    # Read response
    after 500
    set encoded ""
    fconfigure $ssh -blocking 0
    while {[gets $ssh line] >= 0} {
        append encoded $line
    }
    fconfigure $ssh -blocking 1

    # Decode locally
    set data [binary decode base64 $encoded]

    # Write to file
    set fp [open $localFile wb]
    puts -nonewline $fp $data
    close $fp
}

# Example usage
set sock [socket example.com 22]
fconfigure $sock -translation binary -buffering none
set ssh [ssh::import $sock]
ssh::authenticate $ssh myuser mypass

# Upload
ssh_upload_base64 $ssh "local.txt" "/tmp/remote.txt"
puts "File uploaded"

# Download
ssh_download_base64 $ssh "/tmp/remote.txt" "downloaded.txt"
puts "File downloaded"

close $ssh
```

---

## Security Considerations

### Critical Security Warnings

🔴 **NO HOST KEY VERIFICATION**

The extension does **NOT** verify host keys against known_hosts. Every connection is vulnerable to Man-in-the-Middle (MITM) attacks where an attacker can intercept credentials and communications.

**Impact:**
- Attacker can intercept passwords
- Attacker can capture all communications
- Attacker can inject malicious responses
- No warning given to user

**Current Mitigation:** Manual fingerprint verification (you must implement)

🔴 **FINGERPRINT NOT VALIDATED**

The `-fingerprint` option retrieves the server's key fingerprint but does NOT:
- Compare it against known_hosts
- Warn on fingerprint changes
- Prevent connection on mismatch

**You must implement verification logic yourself.**

---

### Security Best Practices

#### 1. Implement Fingerprint Verification

```tcl
proc verify_fingerprint {ssh host} {
    set known_hosts_file "~/.ssh/known_hosts"
    set fp [binary encode hex [fconfigure $ssh -fingerprint]]

    # Load known fingerprints
    if {[file exists $known_hosts_file]} {
        set fh [open $known_hosts_file r]
        set known_hosts [read $fh]
        close $fh

        if {[string first "$host $fp" $known_hosts] == -1} {
            puts stderr "WARNING: Unknown or changed host fingerprint!"
            puts stderr "Host: $host"
            puts stderr "Fingerprint: $fp"
            puts -nonewline "Accept? (yes/no): "
            flush stdout
            gets stdin answer

            if {$answer ne "yes"} {
                error "Host fingerprint not accepted"
            }

            # Save new fingerprint
            set fh [open $known_hosts_file a]
            puts $fh "$host $fp"
            close $fh
        }
    } else {
        # First connection - save fingerprint
        puts "First connection to $host"
        puts "Fingerprint: $fp"
        set fh [open $known_hosts_file w]
        puts $fh "$host $fp"
        close $fh
    }
}

# Usage
set ssh [ssh::import $sock]
verify_fingerprint $ssh "example.com"
ssh::authenticate $ssh myuser mypass
```

#### 2. Use Public Key Authentication

Password authentication transmits credentials (albeit encrypted). Public keys are more secure:
- Private key never transmitted
- Can be protected with passphrase
- Can be revoked without password change
- Supports forced commands

```tcl
# Generate keys (outside Tcl)
# ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa

# Copy public key to server
# ssh-copy-id -i ~/.ssh/id_rsa.pub user@example.com

# Use in Tcl
ssh::authenticate $ssh myuser ~/.ssh/id_rsa.pub ~/.ssh/id_rsa
```

#### 3. Protect Private Keys

**Unix/Linux:**
```bash
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
```

**Always use passphrases:**
```bash
ssh-keygen -p -f ~/.ssh/id_rsa  # Add/change passphrase
```

#### 4. Use Dedicated Accounts

Don't use root or administrator accounts:
```tcl
# Good - limited account
ssh::authenticate $ssh appuser $pass

# Bad - privileged account
ssh::authenticate $ssh root $pass
```

#### 5. Limit Exposure

- Use SSH only on trusted networks when possible
- Don't hardcode passwords in scripts
- Consider using SSH agent for key management (when supported)
- Rotate keys regularly
- Use certificate-based authentication where available

---

### Suitable Current Uses

Given current security limitations:

✓ **Acceptable:**
- Internal network automation (trusted environment)
- Development and testing
- Laboratory/test equipment control
- Educational demonstrations
- Prototyping

✗ **Not Acceptable:**
- Internet-facing connections
- Production automation
- Sensitive data access
- Financial systems
- Healthcare/PII data
- Any security-critical application

---

## Best Practices

### 1. Always Configure Sockets Properly

```tcl
# Required socket configuration
set sock [socket example.com 22]
fconfigure $sock -translation binary -buffering none

# Without binary translation, SSH protocol will break
```

### 2. Use Error Handling

```tcl
# Good - with error handling
if {[catch {
    set ssh [ssh::import $sock]
    ssh::authenticate $ssh $user $pass
} error]} {
    puts stderr "SSH error: $error"
    catch {close $sock}
    return
}

# Bad - no error handling
set ssh [ssh::import $sock]
ssh::authenticate $ssh $user $pass
```

### 3. Always Close Channels

```tcl
# Ensures cleanup of SSH session and TCP socket
close $ssh

# For safety in error conditions
catch {close $ssh}
```

### 4. Flush After Writes

```tcl
# Ensure command is sent immediately
puts $ssh "ls -la"
flush $ssh

# Without flush, data may be buffered
```

### 5. Wait for Responses

```tcl
# Shell commands need time to execute
puts $ssh "sleep 5; echo done"
flush $ssh
after 5500  ;# Wait for command to complete
gets $ssh result
```

### 6. Use Appropriate Buffering

```tcl
# Line buffering for interactive shells
fconfigure $ssh -buffering line

# Full buffering for performance
fconfigure $ssh -buffering full

# No buffering for real-time
fconfigure $ssh -buffering none
```

---

## Troubleshooting

### Connection Issues

**Problem:** Socket connection refused

**Solutions:**
- Verify SSH server is running: `netstat -an | grep :22`
- Check firewall rules
- Verify hostname/IP address is correct
- Ensure port 22 is accessible

**Problem:** SSH handshake fails

**Solutions:**
- Ensure socket is configured with `-translation binary`
- Verify libssh2 is properly installed
- Check SSH server supports SSH2 protocol
- Review server logs: `/var/log/auth.log`

---

### Authentication Failures

**Problem:** Password authentication fails

**Solutions:**
- Verify username and password
- Check server allows password auth: `PasswordAuthentication yes` in `sshd_config`
- Verify account is not locked: `passwd -S username`
- Check PAM configuration (Linux)

**Problem:** Public key authentication fails

**Solutions:**
- Verify public key is in `~/.ssh/authorized_keys` on server
- Check private key file permissions (must be 600)
- Verify key format is correct (OpenSSH or PEM)
- Try key with `ssh` command-line tool first
- Check server logs for rejection reason

**Problem:** "Permission denied" after correct credentials

**Solutions:**
- User account may be disabled
- SSH access may be restricted in `sshd_config`
- Check `AllowUsers` or `AllowGroups` directives
- Verify user shell is valid: `/etc/passwd`

---

### I/O Issues

**Problem:** No response from commands

**Solutions:**
- Increase wait time: `after 1000` instead of `after 500`
- Check if command requires PTY (full-screen apps)
- Verify command path (not all commands in PATH over SSH)
- Check if command completed: `echo $?`

**Problem:** Truncated output

**Solutions:**
- Read in loop until no more data
- Use non-blocking mode with fileevent
- Check if shell prompt included in output

**Problem:** "Broken pipe" error

**Solutions:**
- Server may have disconnected
- Network interruption
- Server timeout
- Check server keep-alive settings

---

### Terminal Issues

**Problem:** Line wrapping incorrect

**Solutions:**
```tcl
# Set terminal size to match your display
fconfigure $ssh -ptysize {132 43}
```

**Problem:** Full-screen apps don't work

**Solutions:**
- Set `TERM` environment variable: `export TERM=vt100`
- Ensure PTY size is set before launching app
- Some apps may not work over SSH channel

**Problem:** Special characters corrupted

**Solutions:**
- Check locale settings: `locale`
- Set UTF-8 encoding: `export LANG=en_US.UTF-8`
- Configure Tcl encoding: `fconfigure $ssh -encoding utf-8`

---

## Technical Details

### Architecture

**Stacked Channel Design:**

```
┌─────────────────────────────┐
│   Tcl Application           │
│   (gets/puts/read/close)    │
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────┐
│   SSH Channel (tclssh2)     │
│   - Encryption/decryption   │
│   - Authentication          │
│   - Protocol handling       │
│   - PTY management          │
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────┐
│   TCP Socket Channel        │
│   - Network I/O             │
│   - Buffering               │
└─────────────────────────────┘
```

### libssh2 Integration

**Session Flow:**
1. `libssh2_session_init()` - Initialize session
2. `libssh2_session_handshake()` - SSH handshake
3. `libssh2_hostkey_hash()` - Get fingerprint (SHA1)
4. `libssh2_userauth_password()` or `libssh2_userauth_publickey_fromfile()` - Authenticate
5. `libssh2_channel_open_session()` - Open channel
6. `libssh2_channel_request_pty()` - Request PTY
7. `libssh2_channel_shell()` - Start shell
8. `libssh2_channel_read()` / `libssh2_channel_write()` - I/O
9. `libssh2_channel_close()` - Close channel
10. `libssh2_session_disconnect()` - Disconnect

### Event Loop Integration

- Uses Tcl timer-based event handling (borrowed from TclTLS)
- `SshChannelHandlerTimer` - Timer callback for non-blocking I/O
- `SshWatchProc` - Registers interest in events
- `SshNotifyProc` - Handles channel events
- Supports both blocking and non-blocking modes

### Memory Management

- Uses Tcl allocator (`ckalloc/ckfree`) for most allocations
- **Known Issue:** Line 369 uses `strdup()` instead of `ckalloc()` (TODO: fix)
- Proper cleanup in `SshClose2Proc`

### Channel Type

- **Type Name:** "ssh"
- **Version:** `TCL_CHANNEL_VERSION_5`
- **Blocking:** Supports both modes
- **Thread Safety:** Uses Tcl stubs for binary compatibility

---

## See Also

- [libssh2 Documentation](https://www.libssh2.org/)
- [SSH Protocol RFCs](https://www.openssh.com/specs.html)
  - RFC 4251: SSH Protocol Architecture
  - RFC 4252: SSH Authentication Protocol
  - RFC 4253: SSH Transport Layer Protocol
  - RFC 4254: SSH Connection Protocol
- [OpenSSH](https://www.openssh.com/)
- [Tcl Channel Documentation](https://www.tcl.tk/man/tcl/TclCmd/open.htm)

---

## License

This software is licensed under the Scriptics/Tcl-style BSD-like license.

See `license.terms` file for complete license text.

Based on original work from https://github.com/teclabat

---

## Version History

**0.1** (2025-01-04) - Work In Progress
- Initial release (WIP status)
- Basic SSH session establishment
- Password and public key authentication
- PTY support with configurable dimensions
- Channel I/O operations (read/write)
- Host fingerprint retrieval (SHA1)
- Non-blocking I/O support
- Integration with Tcl event loop

**Known Issues:**
- No host key verification (CRITICAL)
- Incomplete error handling (see FIXME in tclssh2.c:455, 471)
- Memory allocation inconsistency (tclssh2.c:369)
- Keyboard-interactive auth not implemented
- No SFTP support
- No exec mode (without PTY)
- No port forwarding
- Limited test coverage

---

## Roadmap

### Critical (Security)
- [ ] Implement host key verification
- [ ] Add known_hosts file support
- [ ] Comprehensive error handling
- [ ] Secure credential handling
- [ ] Fix memory allocation issues

### High Priority (Core)
- [ ] Keyboard-interactive authentication
- [ ] Remote command execution (exec mode)
- [ ] SFTP file transfer support
- [ ] Comprehensive test suite
- [ ] Complete API documentation

### Medium Priority (Enhanced)
- [ ] Port forwarding (local/remote)
- [ ] SCP file transfer
- [ ] SSH agent integration
- [ ] Connection keep-alive
- [ ] Multiple simultaneous channels
- [ ] Compression support

### Low Priority (Convenience)
- [ ] Known_hosts management commands
- [ ] Key generation utilities
- [ ] Connection pooling
- [ ] Configuration file support
- [ ] Logging and debugging utilities

---

## Contributing

Contributions welcome! Priority areas:
1. Host key verification implementation
2. Error handling improvements
3. Test suite development
4. Documentation
5. SFTP support

---

## Contact

For issues, questions, and contributions, please refer to the project repository.

---

**Last Updated:** 2025-01-04 \
**Package Version:** 0.1 \
**Status:** Work In Progress - Not Production Ready
