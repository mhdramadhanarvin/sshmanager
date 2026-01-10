# SSH Manager

## Story Behind the Tool

Previously, I used Termius. I liked its elegant user interface, simplicity, and powerful SSH capabilities. However, after frequent use, I needed to sync with the Termius app on my mobile device. Choosing a trial session over a subscription, I felt I still needed time to subscribe. When the trial period ended, I lost all my host vaults and data on Termius without a single trace left on my local machine. This frustrating experience wasted valuable time as I had to rediscover and reconfigure my SSH hosts. Inspired by this inconvenience, I developed SSH Manager—a self-hosted tool for securely managing SSH profiles and keeping data under my control.

## Overview of How the Code Works

SSH Manager is a command-line tool written in Go that securely stores SSH connection profiles. Key components include:

- **Encryption**: Profiles are encrypted with AES-GCM using PBKDF2 key derivation from a master password. Data is stored in a local file (`profiles.enc`).
- **Profile Management**: Each profile includes name, host, port, username, password (optional), and private key content (optional, Base64-encoded).
- **Google Drive Sync**: Optional syncing via Google OAuth2. Uploads/downloads encrypted profiles to/from Drive for cross-device access without dependency on subscriptions.
- **Commands**: CLI commands handle adding, listing, deleting, and connecting to profiles. Authentication uses SSH keys or passwords.
- **Security**: Uses secure random salts and nonces. Temporary files for keys are cleaned up.

The tool stores data in `~/.sshmanager/` and integrates with the Google Drive API for cloud backup.

## Prerequisites

- Go 1.19+ (to build)
- System dependencies: `openssh-client`, `sshpass` (for password-based auth)
- Google Cloud Console account (for Drive sync): Create an OAuth2 app and replace placeholders in `main.go` with your client ID/secret.

## Installation

1. Clone the repository:

   ```
   git clone <repository-url>
   cd ssh-manager
   ```

2. Build the binary:

   ```
   go build -o sshmanager main.go
   ```

3. (Optional) Install globally:
   ```
   sudo mv sshmanager /usr/local/bin/
   ```

## Usage

Run the tool with commands. On first run, it prompts for Google Drive sync.

### Commands

- **Add Profile**: `sshmanager add` (interactive prompts for details)
- **List Profiles**: `sshmanager list` (shows profiles in a table)
- **Delete Profile**: `sshmanager delete <name>`
- **Connect**: `sshmanager connect <name>` (launches SSH session)
- **Auth Google**: `sshmanager auth` (authorize Drive access)
- **Settings**: `sshmanager setting` (enable/disable auto-sync)
- **Sync Manually**: `sshmanager sync` (upload/download to/from Drive)

Examples:

- Add a profile: `sshmanager add`
- Connect to "myserver": `sshmanager connect myserver`
- Enable sync: `sshmanager setting` (answer 'y')

Profiles auto-sync if enabled. Master password required for load/save.

## Building from Source

Ensure Go modules are handled:

```
go mod tidy
go build -o sshmanager main.go
```

For production, consider obfuscation or additional hardening.

This tool provides self-reliant SSH management, avoiding subscription lock-ins. For issues, check logs or enhance security.
