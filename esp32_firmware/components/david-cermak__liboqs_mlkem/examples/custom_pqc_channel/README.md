# Dedicated Secure Channel

This example demonstrates a **dedicated secure channel** built from:

- **ML-KEM-768** key exchange using the `liboqs_mlkem` component.
- **HKDF-SHA256** to derive an **AES-256** key from the shared secret.
- **AES-256-GCM** data channel with sequence-number AAD.
- A swappable underlying transport, currently **plain TCP** wrapped in
  `setup_server_connection()` / `setup_client_connection()`.

One build acts as **server** (keypair + decaps + encrypted welcome), the other as
**client** (encaps + decrypt welcome). This is the code version of "Demo #1:
Dedicated Secure Channel (ESP32)" from the presentation.

## How to build and run

1. **Configure connection (Wi-Fi/Ethernet)**
   - From this directory:
     ```bash
     idf.py menuconfig
     ```
   - Configure Wi-Fi/Ethernet under the standard **Example Connection Configuration**
     menu (used by `protocol_examples_common`).

2. **Select role (server or client)**
   - In `menuconfig`, open **Example Configuration**:
     - Enable **"Is server side"** to build the **server** firmware.
     - Disable it to build the **client** firmware.

3. **Set server address (client side)**
   - In `main/custom_pqc_channel.c`, set:
     - `CUSTOM_PQC_SERVER_ADDR` to the server board's IPv4 address.
     - `CUSTOM_PQC_SERVER_PORT` if you want a port other than `3333`.

4. **Build, flash, and monitor**
   - For each board (server and client), from this directory:
     ```bash
     idf.py build flash monitor
     ```
   - Start the **server** first; once it is listening, start the **client**.

## Example output (server)
```text
I (5818) esp_netif_handlers: example_netif_sta ip: 192.168.0.34, mask: 255.255.255.0, gw: 192.168.0.1
I (5818) example_connect: Got IPv4 event: Interface "example_netif_sta" address: 192.168.0.34
I (5818) example_common: Connected to example_netif_sta
I (5828) example_common: - IPv4 address: 192.168.0.34,
I (5828) example_common: - IPv6 address: fe80:0000:0000:0000:xxxx:xxxx:xxxx:xxxx, type: ESP_IP6_ADDR_IS_LINK_LOCAL
I (5838) custom_pqc_channel: === Demo: Dedicated Secure Channel (SERVER) ===
I (5848) custom_pqc_channel: Setting up server socket on port 3333
I (5858) custom_pqc_channel: Waiting for incoming connection...
I (89308) custom_pqc_channel: Client connected
I (89308) custom_pqc_channel: Server generating ML-KEM-ML-KEM-768 keypair...
W (89308) MLKEM768: Generating ML-KEM-768 keypair
W (89328) MLKEM768: Generated ML-KEM-768 keypair
I (89328) custom_pqc_channel: Server waiting for ciphertext from client
W (90018) MLKEM768: Decapsulating ML-KEM-768 shared secret
W (90038) MLKEM768: Decapsulated ML-KEM-768 shared secret
I (90038) custom_pqc_channel: Server handshake complete, AES key derived
I (90048) custom_pqc_channel: Sent encrypted welcome message (76 bytes)
```

## Example output (client)
```text
I (4556) example_connect: Got IPv6 event: Interface "example_netif_sta" address: I (5796) example_connect: Got IPv4 event: Interface "example_netif_sta" address: 192.168.0.33
I (5796) example_common: Connected to example_netif_sta
I (5806) example_common: - IPv4 address: 192.168.0.33,
I (5806) example_common: - IPv6 address: fe80:0000:0000:0000:xxxx:xxxx:xxxx:xxxx, type: ESP_IP6_ADDR_IS_LINK_LOCAL
I (5816) custom_pqc_channel: === Demo: Dedicated Secure Channel (CLIENT) ===
I (5826) custom_pqc_channel: Connecting to server 192.168.0.34:3333
I (6226) custom_pqc_channel: Connected to server
I (6226) custom_pqc_channel: Client waiting for server public key...
W (6736) MLKEM768: Encapsulating ML-KEM-768 shared secret
W (6756) MLKEM768: Encapsulated ML-KEM-768 shared secret
I (6756) custom_pqc_channel: Client handshake complete, AES key derived
I (7156) custom_pqc_channel: Decrypted welcome: Welcome from ML-KEM server over AES-GCM channel
```