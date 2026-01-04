# tclssh2 - SSH2 Protocol Extension for Tcl

A Tcl extension providing SSH2 connectivity through libssh2, enabling secure shell sessions, authentication, and remote command execution from Tcl applications.

## Features

- **SSH2 Protocol Support**: Full SSH2 protocol implementation via libssh2
- **Multiple Authentication Methods**:
  - Password authentication
  - Public key authentication
  - Keyboard-interactive (planned)
- **Stacked Channel Architecture**: Wraps existing TCP sockets with SSH encryption
- **PTY Support**: Terminal/pseudo-terminal with configurable dimensions
- **Non-blocking I/O**: Integrates with Tcl event loop for asynchronous operations
- **Host Fingerprint Verification**: Retrieves SHA1 fingerprints of remote hosts

## Status

**Current Version**: 0.1 (Work In Progress)

This extension is in early development. While basic functionality works, several features are incomplete and security features (particularly host key verification) are not yet implemented. **Not recommended for production use.**

### What Works
- SSH session establishment over existing TCP connections
- Password and public key authentication
- Interactive shell sessions with PTY
- Channel I/O (read/write)
- Host fingerprint retrieval
- Terminal size configuration

### What's Missing/Incomplete
- **Host key verification** (SECURITY CRITICAL - vulnerable to MITM attacks)
- Keyboard-interactive authentication
- SFTP support
- Remote command execution (`exec` mode)
- Port forwarding (local and remote)
- SCP file transfer
- SSH agent integration
- Comprehensive error handling
- Test suite
- Complete documentation

## Quick Start

### Installation

```bash
cd D:\CM.tcltk\tcltk86\external\tclssh2
autoconf
./configure
make
make install
```

### Build Requirements

- Tcl 8.5 or higher
- libssh2 library and headers
- C compiler (gcc/clang/MSVC)
- autoconf and TEA build tools

### Windows Build

Ensure libssh2 is installed and available to the linker:

```bash
autoconf
./configure
make
make install
```

### Linux Build

Install libssh2 development package:

```bash
# Debian/Ubuntu
sudo apt-get install libssh2-1-dev

# RedHat/CentOS
sudo yum install libssh2-devel

# Build
autoconf
./configure
make
make install
```

## Basic Usage

### Establishing an SSH Connection

```tcl
package require ssh2

# Open TCP connection to SSH server
set sock [socket example.com 22]
fconfigure $sock -translation binary -buffering none

# Wrap socket with SSH protocol
set ssh [ssh::import $sock]

# Get host fingerprint
set fingerprint [fconfigure $ssh -fingerprint]
puts "Host fingerprint: [binary encode hex $fingerprint]"

# Authenticate with password
ssh::authenticate $ssh username password

# Now you can read/write to $ssh as a shell session
puts $ssh "ls -la"
flush $ssh

# Read response
while {[gets $ssh line] >= 0} {
    puts $line
}

close $ssh
```

### Public Key Authentication

```tcl
package require ssh2

set sock [socket example.com 22]
fconfigure $sock -translation binary -buffering none
set ssh [ssh::import $sock]

# Authenticate with public key
# Syntax: ssh::authenticate channel username publicKeyPath privateKeyPath [passphrase]
ssh::authenticate $ssh username ~/.ssh/id_rsa.pub ~/.ssh/id_rsa

puts $ssh "whoami"
flush $ssh
gets $ssh result
puts "Logged in as: $result"

close $ssh
```

### Setting Terminal Size

```tcl
# Set PTY dimensions (columns x rows)
fconfigure $ssh -ptysize {80 24}

# Get current PTY size
set size [fconfigure $ssh -ptysize]
puts "Terminal size: $size"
```

## API Reference

### Commands

#### ssh::import

Wraps a TCP socket channel with SSH2 protocol.

**Syntax:**
```tcl
ssh::import channelId
```

**Arguments:**
- `channelId` - An existing TCP socket channel connected to an SSH server

**Returns:**
- A new channel identifier representing the SSH-wrapped connection

**Description:**
Performs the SSH handshake and returns a stacked channel that can be used for SSH operations. The original socket channel is closed when the SSH channel is closed.

**Example:**
```tcl
set sock [socket example.com 22]
set ssh [ssh::import $sock]
```

#### ssh::authenticate

Authenticates to the SSH server and starts a shell session.

**Syntax:**
```tcl
ssh::authenticate channelId username password
ssh::authenticate channelId username publicKeyFile privateKeyFile ?passphrase?
```

**Arguments:**
- `channelId` - SSH channel from `ssh::import`
- `username` - Remote username
- For password auth:
  - `password` - User password
- For public key auth:
  - `publicKeyFile` - Path to public key file
  - `privateKeyFile` - Path to private key file
  - `passphrase` - (Optional) Passphrase for encrypted private key

**Returns:**
- Empty string on success
- Raises error on authentication failure

**Description:**
Authenticates using either password or public key authentication. After successful authentication, opens an SSH channel, requests a PTY (pseudo-terminal), and starts a shell session.

**Examples:**
```tcl
# Password authentication
ssh::authenticate $ssh myuser mypassword

# Public key authentication
ssh::authenticate $ssh myuser ~/.ssh/id_rsa.pub ~/.ssh/id_rsa

# Public key with passphrase
ssh::authenticate $ssh myuser id_rsa.pub id_rsa "key_passphrase"
```

### Channel Options

#### -fingerprint

Retrieves the SHA1 fingerprint of the remote host's public key.

**Syntax:**
```tcl
fconfigure channelId -fingerprint
```

**Returns:**
- 20-byte binary string containing SHA1 hash

**Example:**
```tcl
set fp [fconfigure $ssh -fingerprint]
puts "Fingerprint: [binary encode hex $fp]"
```

**Note:** Currently only retrieves the fingerprint. Does NOT verify it against known_hosts. You must implement verification logic yourself.

#### -ptysize

Gets or sets the pseudo-terminal dimensions.

**Syntax:**
```tcl
fconfigure channelId -ptysize {columns rows}
fconfigure channelId -ptysize
```

**Arguments:**
- `columns` - Terminal width in characters
- `rows` - Terminal height in lines

**Returns:**
- When setting: empty string
- When getting: list of {columns rows}

**Example:**
```tcl
# Set to 132 columns x 43 rows
fconfigure $ssh -ptysize {132 43}

# Get current size
set size [fconfigure $ssh -ptysize]
puts "Terminal: [lindex $size 0]x[lindex $size 1]"
```

## Architecture

### Stacked Channel Design

tclssh2 uses Tcl's stacked channel architecture:

```
+-------------------------+
¦   Tcl Application       ¦
¦   (gets/puts/read)      ¦
+-------------------------+
            ¦
+-----------?-------------+
¦   SSH Channel Layer     ¦
¦   (encryption/protocol) ¦
+-------------------------+
            ¦
+-----------?-------------+
¦   TCP Socket Channel    ¦
¦   (network I/O)         ¦
+-------------------------+
```

This design allows transparent SSH encryption over any existing TCP connection.

### libssh2 Integration

The extension wraps these libssh2 operations:

1. **Session Management**: `libssh2_session_*`
2. **Authentication**: `libssh2_userauth_*`
3. **Channel I/O**: `libssh2_channel_*`
4. **Host Key**: `libssh2_hostkey_hash`

### Event Loop Integration

- Integrates with Tcl's event loop for non-blocking I/O
- Uses timer-based event handling borrowed from TclTLS
- Supports both blocking and non-blocking modes

## Security Considerations

**CRITICAL SECURITY WARNING**: This extension does NOT currently verify host keys against known_hosts. Every connection is vulnerable to Man-in-the-Middle (MITM) attacks.

### Current Security Limitations

1. **No Host Key Verification**: Does not check remote host identity
2. **Fingerprint Not Validated**: Retrieved but not compared against known_hosts
3. **No Certificate Validation**: No CA or certificate chain checking
4. **Debug Output**: May leak sensitive data if debug prints are enabled

### Security Best Practices (When Implemented)

- Always verify host fingerprints on first connection
- Store verified fingerprints in known_hosts file
- Use public key authentication instead of passwords when possible
- Protect private key files with appropriate file permissions
- Use passphrases on private keys
- Rotate keys regularly
- Audit SSH access logs

### Suitable Current Uses

- Internal network testing (trusted environment)
- Development and debugging
- Educational purposes
- Prototyping SSH automation

### Not Suitable For

- Production environments
- Internet-facing connections
- Sensitive data transmission
- Any security-critical application

## Running Tests

```bash
make test
```

Or manually:

```bash
cd tests
tclsh all.tcl
```

**Note**: Current tests only verify basic package loading and command existence. Integration tests requiring an actual SSH server are not yet implemented.

## Implementation Details

### Channel Type

- **Type Name**: "ssh"
- **Version**: TCL_CHANNEL_VERSION_5
- **Blocking Modes**: Both blocking and non-blocking supported
- **Thread Safety**: Uses Tcl stubs for binary compatibility

### State Structure

Each SSH channel maintains:
- libssh2 session and channel pointers
- Parent TCP channel reference
- Event timer for non-blocking I/O
- Host fingerprint (SHA1)
- PTY dimensions (columns, rows)
- Tcl interpreter reference

### Memory Management

- Uses Tcl memory allocator (`ckalloc`) for most allocations
- **Known Issue**: Line 369 uses `strdup()` instead of `ckalloc()` (FIXME)
- Proper cleanup in Close2Proc

## Troubleshooting

### Connection Issues

**Problem**: "Connection refused"
```tcl
# Ensure SSH server is running
# Verify firewall allows port 22
# Check server address and port
```

**Problem**: Socket appears to hang
```tcl
# Use non-blocking mode
fconfigure $sock -blocking 0
# Or set timeout with vwait
```

### Authentication Failures

**Problem**: Password authentication fails
```tcl
# Verify username and password
# Check server allows password auth (PasswordAuthentication yes)
# Check user account is not locked
```

**Problem**: Public key authentication fails
```tcl
# Verify key file paths are correct
# Ensure private key permissions are 600
# Check authorized_keys on server
# Verify key format (OpenSSH vs PEM)
```

### PTY/Terminal Issues

**Problem**: Terminal size not updating
```tcl
# Set size after authentication
ssh::authenticate $ssh user pass
fconfigure $ssh -ptysize {80 24}
```

## Examples

### Interactive Shell Session

```tcl
package require ssh2

# Connect
set sock [socket example.com 22]
fconfigure $sock -translation binary -buffering none
set ssh [ssh::import $sock]

# Authenticate
ssh::authenticate $ssh username password

# Interactive loop
while {1} {
    puts -nonewline "ssh> "
    flush stdout
    gets stdin cmd
    if {$cmd eq "exit"} break

    puts $ssh $cmd
    flush $ssh

    # Read response (simple approach)
    after 500
    while {[gets $ssh line] >= 0} {
        puts $line
    }
}

close $ssh
```

### Simple Command Execution

```tcl
proc ssh_exec {host user pass command} {
    set sock [socket $host 22]
    fconfigure $sock -translation binary -buffering none

    set ssh [ssh::import $sock]
    ssh::authenticate $ssh $user $pass

    puts $ssh $command
    flush $ssh

    # Collect output
    set output ""
    after 1000  ;# Wait for command to execute
    while {[gets $ssh line] >= 0} {
        append output $line \n
    }

    close $ssh
    return $output
}

# Usage
set result [ssh_exec example.com myuser mypass "uname -a"]
puts $result
```

### File Transfer (Manual)

```tcl
# Note: This is a workaround until SFTP is implemented
# Uses base64 encoding over shell

proc ssh_upload {ssh localFile remoteFile} {
    # Read local file
    set fd [open $localFile rb]
    set data [read $fd]
    close $fd

    # Base64 encode
    set encoded [binary encode base64 $data]

    # Send via shell
    puts $ssh "base64 -d > $remoteFile << 'EOF'"
    puts $ssh $encoded
    puts $ssh "EOF"
    flush $ssh
}
```

## Version History

### 0.1 (2025-01-04) - WIP

- Initial release (work in progress)
- Basic SSH session establishment
- Password and public key authentication
- PTY support
- Channel I/O operations
- Fingerprint retrieval

## Roadmap

### Critical (Security)
- [ ] Host key verification against known_hosts
- [ ] Comprehensive error handling
- [ ] Secure debug mode (disable sensitive logging)

### High Priority (Core Features)
- [ ] Keyboard-interactive authentication
- [ ] Remote command execution (exec mode without PTY)
- [ ] SFTP support
- [ ] Comprehensive test suite
- [ ] Complete documentation (man pages)

### Medium Priority (Enhanced Features)
- [ ] Port forwarding (local and remote)
- [ ] SCP file transfer
- [ ] SSH agent integration
- [ ] Connection keep-alive
- [ ] Multiple simultaneous channels

### Low Priority (Nice to Have)
- [ ] Known_hosts management commands
- [ ] Key generation utilities
- [ ] Connection pooling
- [ ] Compression support

## Contributing

This is a work-in-progress project. Contributions are welcome, particularly for:

1. Host key verification implementation
2. Error handling improvements
3. Test suite development
4. Documentation
5. SFTP support

## Authors

Based on original work at https://github.com/teclabat

Current development: 2025

## License

See `license.terms` file for details (Scriptics/Tcl-style BSD-like license).

## References

- **libssh2**: https://www.libssh2.org/
- **Tcl/Tk**: https://www.tcl.tk/
- **TEA (Tcl Extension Architecture)**: https://www.tcl.tk/doc/tea/
- **SSH Protocol**: RFC 4251-4254
- **TclTLS** (reference implementation): https://core.tcl.tk/tcltls/

## Related Projects

- **TclTLS**: TLS/SSL support for Tcl
- **expect**: Tcl extension for automating interactive applications
- **tclpty**: Pseudo-terminal support for Tcl

## Support

For bugs and issues, please check:
1. Known limitations in this README
2. FIXME comments in `generic/tclssh2.c`
3. GitHub issues at the project repository

## Disclaimer

This extension is provided as-is with no warranty. Due to incomplete security features, it should not be used in production environments without implementing proper host key verification and comprehensive testing.
