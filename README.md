# pf-tui: macOS Personal Firewall TUI

A Terminal User Interface (TUI) for managing the macOS firewall (`pfctl`).

## Features

- **Simplified Rule Management:** Add, edit, and reorder firewall rules through an intuitive interface.
- **Port Forwarding:** Configure port forwarding (RDR) rules with support for specifying an external IP.
- **Live PF Control:** Enable or disable the firewall and apply rule changes instantly.
- **Automatic IP Forwarding:** Automatically enables `net.inet.ip.forwarding` when port forwarding rules are active.
- **Configuration Management:** Save and load your firewall rule configurations from JSON files.
- **Startup Control:** Configure the firewall to enable automatically on system startup.
- **Log Viewing:** View system and application logs directly within the TUI.
- **Connection-Safe Rule Application:** Apply rules without dropping existing connections (e.g., SSH).
- **Improved Logging:** Detailed logging for easier troubleshooting.

## Requirements

- macOS
- Python 3
- `curses` library (usually included with Python on macOS)

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/kh813/pf-tui.git
    cd pf-tui
    ```

2.  **Make the script executable:**
    ```bash
    chmod +x pf-tui.py
    ```

## Usage

Run the script with `sudo` or as a user with `sudo` privileges:

```bash
./pf-tui.py
```

The application requires `sudo` access to interact with `pfctl`. You will be prompted for your password for operations that require elevated privileges.

### Main Menu

The main menu provides access to all the core features:

- **Edit Rule:** Modify, reorder, or delete existing firewall rules.
- **Add New Rule:** Create a new firewall rule.
- **Edit Port Forwarding Rule:** Modify, reorder, or delete existing port forwarding rules.
- **Add Port Forwarding Rule:** Create a new port forwarding rule.
- **Apply Rules to System:** Save the current rules and apply them to the live firewall.
- **Show Current System Rules:** Display the currently active firewall rules.
- **PF Status:** Check if the firewall is enabled or disabled.
- **Enable/Disable PF:** Start or stop the firewall.
- **Startup Control:** Enable or disable the firewall on system startup.
- **Log Viewing:** View startup and application trace logs.
- **Configuration:** Save or import rule configurations.

### Rule Management

- **Adding/Editing Rules:** A form-based interface allows you to specify the action, direction, protocol, source/destination addresses, and ports for each rule.
- **Reordering Rules:** In the "Edit Rule" screen, you can use the `k` (up) and `j` (down) keys to change the order of rules.
- **Quick and Keep State:** The 'Edit Rule' screen now displays 'quick' and 'keep state' values for each rule.
- **Port Forwarding:** The "Add/Edit Port Forwarding Rule" screen now includes an `External IP` field.
- **`rdr pass`:** Port forwarding rules are now created with `rdr pass` to automatically create the necessary `pass` rule for the redirected traffic.

## Configuration

- **Rules:** Firewall rules are stored in `~/.config/pf-tui/rules.json`.
- **Logs:** Application logs are stored in `~/.config/pf-tui/pf-tui.log`. Startup script logs are in `/tmp/pf-tui-startup.log`.

## Configuration Files

`pf-tui` uses two main files to manage your firewall configuration:

*   **`~/.config/pf-tui/rules.json`**: This is your primary configuration file. It stores all your firewall and port forwarding rules in a structured JSON format. This file allows `pf-tui` to load, display, and manage your rules with all their details, including descriptions. When you "Save Configuration", you are saving to this file.

*   **`/etc/pf.anchors/pf-tui.rules`**: This is the file that the macOS firewall (`pfctl`) actually uses. When you "Save & Apply Rules to System", `pf-tui` translates the rules from your `rules.json` file into the `pfctl`-compatible format and saves them to this anchor file. The system's firewall then loads the rules from this anchor.

It is necessary to keep both files. The `rules.json` file is the "source of truth" for the application, ensuring that your rule details and descriptions are preserved. The `pf-tui.rules` anchor is the "compiled" version of your rules that the operating system understands.

## How It Works

The TUI uses the `curses` library to create the terminal interface. It interacts with the system's `pfctl` utility to manage the firewall. Rules are managed through a dedicated anchor file (`/etc/pf.anchors/pf-tui.rules`) to avoid interfering with other system firewall configurations.

## License

This project is licensed under the MIT License.
