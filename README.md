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
    git clone https://github.com/your-username/pf-tui.git
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

## How It Works

The TUI uses the `curses` library to create the terminal interface. It interacts with the system's `pfctl` utility to manage the firewall. Rules are managed through a dedicated anchor file (`/etc/pf.anchors/pf-tui`) to avoid interfering with other system firewall configurations.

## License

This project is licensed under the MIT License.