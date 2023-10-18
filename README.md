# zark-network-monitor
```markdown
# Zark Network Monitor

Zark Network Monitor is a simple Python script that allows you to monitor network traffic and log information about incoming and outgoing packets. This tool uses the Scapy library to capture and analyze network packets and provides information such as timestamp, source/destination IP and MAC addresses, packet size, and the protocol used (TCP, UDP, or other).

![Zark Network Monitor](https://firebasestorage.googleapis.com/v0/b/high-mountain-393310.appspot.com/o/Screenshot%20from%202023-10-18%2016-56-11.png?alt=media&token=4cefe6a3-98d4-4dbd-b61a-62498305f04f)

## Features

- Real-time network monitoring.
- Packet information logging to a file (optional).
- Colorful output for better visibility using Colorama.
- ASCII art banner with PyFiglet.
- Supports both incoming and outgoing traffic.

## Usage

1. Clone this repository:

   ```bash
   git clone https://github.com/ZawwanZ/zark-network-monitor.git
   ```

2. Change to the script directory:

   ```bash
   cd zark-network-monitor
   ```

3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the script:

   ```bash
   python3 zark.py
   ```

5. Follow the on-screen instructions to choose whether you want to log network traffic to a file or not.

## Options

- To log network traffic to a file, choose "y" when prompted and enter the log file name.
- To run the script without logging, choose "n" when prompted.

## Author

- Zaw Wanz

## Source

This tool was inspired by the Exploit-DB article: [Network Traffic Capture Using Python and Scapy](https://www.exploit-db.com/docs/48606)

## Credits

- Original source and inspiration: [Exploit-DB Article](https://www.exploit-db.com/docs/48606)

```
