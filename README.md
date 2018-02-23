### Author: Saleh Bin Muhaysin
### Github: https://github.com/salehmuhaysin
### Blog: https://salehsecurity.wordpress.com/

# Windows-Events

In this folder I will put all my scripts to deals with windows event logs.

### CheckRDP.ps1
 Powershell Script used to parse Windows Event logs (.evtx) files to find if there was a Remote Desktop Connection
 File supported:
 * Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
 * Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
 * Security
 * Microsoft-Windows-TerminalServices-RDPClient/Operational
 * Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational

### How to use:
 >_ .\CheckRDP.ps1 \<evtx-file-path\> [\<output-csv-file\>]
