# CryptLink - Secure Peer-to-Peer File Transfer

<!-- Optional: Add a logo here -->
<p align="center">
  <img src="images/cryptlink-logo.jpg" alt="CryptLink Logo" width="400"/>
</p>

# CryptLink

CryptLink is a secure peer-to-peer file transfer application built with Python. It uses TLS for encrypting all communications and provides a graphical user interface (GUI) built with Tkinter for ease of use. The application allows users to establish secure connections with peers by verifying certificate fingerprints and then transfer files directly.

## Features

*   **Secure File Transfer**: All data, including file contents and commands, is encrypted using TLS (Transport Layer Security).
*   **Peer Verification**: Uses self-signed certificates and requires out-of-band fingerprint verification to ensure you are connecting to the intended peer.
*   **GUI Interface**: A user-friendly interface built with Tkinter for managing connections, selecting files, and monitoring transfers.
*   **Certificate Management**:
    -   **Manual Loading**: Users can manually load their CA certificate, client certificate, and client private key.
    -   **Bundle Import/Export**: Certificates and keys can be exported to a password-protected `.clb` (CryptLink Bundle) file for easy sharing and import on another instance or by another user.
    -   **Keyring Persistence**: Optionally save and load your identity (certificates and key) securely using the system's keyring for convenience.
*   **Cross-Platform**: Designed to run on Linux, with potential for macOS and Windows compatibility (though primarily developed/tested on Linux).
*   **Admin Tools**: Includes functionality for CA management (creation, export, clear) and client certificate bundle generation for easy distribution.
*   **Settings**: Configure logging verbosity and manage identity persistence options.
*   **Connection History**: Remembers past successful connections for quick reconnections.
*   **Peer-to-Peer Chat (Initial Implementation)**:
    - Engage in encrypted text-based chat with your connected peer.
    - This is an initial version of the chat functionality, and we're excited to bring more enhancements to it in future updates!
    - Chat is available once a secure connection is established.

## Security

CryptLink prioritizes security through several mechanisms:

1.  **TLS Encryption**: All network communication between peers is encrypted using TLSv1.2 or higher. This includes commands, peer information, and file data.
2.  **Certificate-Based Authentication**: Each peer uses a client certificate signed by a common (or mutually trusted) Certificate Authority (CA).
3.  **Fingerprint Verification**: Before a connection is fully established, users are shown the SHA-256 fingerprint of the peer's certificate. This fingerprint **must** be verified out-of-band (e.g., over a phone call, trusted messenger) with the peer to prevent man-in-the-middle attacks.
4.  **Encrypted Bundles**: The `.clb` bundle files are encrypted using AES-256 derived from a user-provided password via PBKDF2, protecting the certificates and private key within.
5.  **Keyring Integration**: For users who choose to persist their identity, CryptLink leverages the system's native keyring (e.g., GNOME Keyring, macOS Keychain, Windows Credential Manager) to securely store the encryption key for the identity data. The identity data itself (certificates and private key) is encrypted with this key and stored in a local application file.

## Getting Started

### Prerequisites

*   Python 3.8+
*   Required Python libraries:
    *   `cryptography` (for TLS, certificate handling, and encryption)
    *   `keyring` (for secure storage of identity encryption keys)

The application will attempt to check for these dependencies on startup and guide you if any are missing.

### Installation / Running

1.  Clone the repository:
    ```bash
    git clone https://github.com/ashes00/cryptlink.git
    cd cryptlink
    ```
2.  Run the application:
    ```bash
    python3 main.py
    ```
    If dependencies are missing, `main.py` will attempt to guide you through installing them using `pip`.

### First Time Setup & Usage

1.  **Identity Setup**:
    *   **Option A: Using Admin Tools (Recommended for initial setup)**
        1.  Go to `Admin Tools`.
        2.  Click "Load/Create CA". If no CA exists in your keyring, you'll be prompted to create one. Fill in the details (e.g., Common Name: "My Home CA").
        3.  Once the CA is loaded/created, enter a "Client Name" (e.g., "MyLaptop") and click "Generate Bundle".
        4.  Save the `.clb` file. This bundle contains your CA cert, and a new client cert and key signed by your CA.
        5.  Go to the `Identities` view and click "Import Bundle". Select the `.clb` file you just created and enter the password.
        6.  The certificates will load. You can now optionally "Save to Keyring" for easier startup next time.
    *   **Option B: Manual Certificate Loading**
        1.  You will need a CA certificate (`ca.pem`), a client certificate (`client.pem`) signed by that CA, and the corresponding client private key (`client.key`).
        2.  Go to the `Identities` view.
        3.  Click "CA Cert", "Client Cert", and "Client Key" to select your respective PEM files.
        4.  Click "Load Certs".
        5.  If successful, you can "Export Bundle" to create a `.clb` file or "Save to Keyring".
    *   **Option C: Importing a Bundle from Someone Else**
        1.  Obtain a `.clb` file from another CryptLink user (e.g., someone who used Admin Tools to generate a client bundle for you from their CA).
        2.  Go to the `Identities` view, click "Import Bundle", select the file, and enter the password.
        3.  Optionally "Save to Keyring".

2.  **Connecting to a Peer**:
    *   Ensure your peer has also set up their CryptLink identity using the *same CA certificate* (or a CA that your client trusts).
    *   In the `Home` view, enter the peer's IP address or hostname in the "Peer IP/Host" field.
    *   Click "Connect".
    *   A dialog will appear showing your fingerprint and the peer's fingerprint. **Verify the peer's fingerprint with them out-of-band.**
    *   If the fingerprint matches, click "Yes". Your peer will do the same on their end.
    *   The status should change to "Securely Connected".

3.  **Transferring a File**:
    *   Once connected, click "Choose File" to select a file.
    *   Click "Send File".
    *   The peer will be prompted to accept the file.
    *   Progress will be shown during the transfer.

4.  **Chatting**:
    *   Once "Securely Connected", click the "Chat" menu item.
    *   Type your message in the input box at the bottom and click "Send" or press Enter.
    *   Messages will appear in the conversation area.

## Configuration

*   **Settings View**:
    *   **Logging Verbosity**: Control the level of detail in the application logs (DEBUG, INFO, WARN, ERROR).
    *   **Manual Identity Configuration**: Toggle whether the manual certificate selection buttons are enabled in the `Identities` view. If disabled, you must use "Import Bundle" or "Load from Keyring".
    *   **Clear Past Connections**: Remove the history of remembered peers from the connection dropdown.
*   Settings are saved in `~/.cryptlink/settings.json`.

## Future Enhancements (Potential)

*   Directory transfer.
*   Improved UI/UX.
*   More robust error handling and network condition management.
*   Enhanced chat features (e.g., rich text, notifications).
*   Address book / more persistent peer management.

## Contributing

Contributions, bug reports, and feature requests are welcome! Please feel free to open an issue or submit a pull request on the GitHub repository.

## License

This project is licensed under the MIT License - see the LICENSE file for details (if one is created).
