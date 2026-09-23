# DaniAV V1

DaniAV is a lightweight Windows security monitoring project written in Python.

Features

Real-time process monitoring
High-risk file detection
Windows startup inspection
Network connection inspection
Local event logging
Quarantine directory support
Automatic startup registration
Discord Rich Presence
Automatic dependency installation

Discord Rich Presence

Open the Discord Developer Portal.

Create a Discord application.

Copy the Application ID.

Set the Windows environment variable DANIAV_DISCORD_CLIENT_ID to that value.

Start DaniAV while the Discord desktop client is running.

Example PowerShell command:

$env="YOUR_APPLICATION_ID"
python DaniAV_V1.py

The Discord application should remain open while DaniAV is running.

Optional GitHub button

Set DANIAV_GITHUB_URL to your repository URL.

Example:

$env="https://github.com/yourname/daniav"

Notes

DaniAV is a lightweight monitoring tool, not a replacement for Windows Defender or a commercial antivirus engine.

Detection results are indicators that should be reviewed. DaniAV does not automatically kill detected processes or delete suspicious files.

Requirements

Windows
Python 3.10 or newer
Discord desktop client for Rich Presence

The program installs psutil and pypresence automatically when they are missing.
