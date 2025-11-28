============================================
  SentinelAI Windows Agent
============================================

Stopping any existing agents...

INFO: No tasks running with the specified criteria.

Starting agent... Press Ctrl+C to stop


    ╔═══════════════════════════════════════════════════════════════════╗
    ║               SentinelAI Windows Agent v1.4                       ║
    ║         Native Windows Protection & Threat Detection              ║
    ║                                                                   ║
    ║  Core:     Process | Network | EventLog | Registry | Firewall     ║
    ║  System:   Startup | Tasks | USB | Hosts | Browser | Services     ║
    ║  Advanced: Clipboard | DNS | PowerShell | WMI | Drivers           ║
    ║  Security: Certificates | Named Pipes | Defender | AVG            ║
    ║  Deep:     AMSI | ETW | Sysmon | DLL Injection Detection          ║
    ║                                                                   ║
    ║     AI Analysis:  ENABLED      |    25 Active Monitors         ║
    ╚═══════════════════════════════════════════════════════════════════╝

2025-11-28 00:27:32,149 - SentinelAgent - INFO - Windows Agent initialized - Dashboard: http://localhost:8015
2025-11-28 00:27:32,150 - SentinelAgent - INFO - AI-powered analysis: Enabled
2025-11-28 00:27:32,150 - SentinelAgent - INFO - Hybrid ML detector: Enabled
2025-11-28 00:27:32,150 - SentinelAgent - INFO - ==================================================
2025-11-28 00:27:32,151 - SentinelAgent - INFO - SentinelAI Windows Agent Starting
2025-11-28 00:27:32,151 - SentinelAgent - INFO - Platform: Windows 10
2025-11-28 00:27:32,151 - SentinelAgent - INFO - Hostname: Bygheart
2025-11-28 00:27:32,151 - SentinelAgent - INFO - Dashboard: http://localhost:8015
2025-11-28 00:27:32,151 - SentinelAgent - INFO - ==================================================
2025-11-28 00:27:32,152 - SentinelAgent - INFO - Process monitor started
2025-11-28 00:27:32,174 - SentinelAgent - INFO - Network monitor started
2025-11-28 00:27:32,202 - SentinelAgent - INFO - Event log monitor started
2025-11-28 00:27:32,712 - SentinelAgent - INFO - Hosts file monitor started
2025-11-28 00:27:32,780 - SentinelAgent - INFO - USB monitor started - tracking 0 devices
2025-11-28 00:27:32,867 - SentinelAgent - INFO - Startup monitor started - tracking 17 items
2025-11-28 00:27:32,944 - SentinelAgent - INFO - DNS monitor started
2025-11-28 00:27:32,955 - SentinelAgent - INFO - Registry monitor started - watching critical keys
2025-11-28 00:27:32,955 - SentinelAgent - INFO - PowerShell monitor started
2025-11-28 00:27:32,975 - SentinelAgent - INFO - WMI monitor started
2025-11-28 00:27:33,015 - SentinelAgent - INFO - Service monitor started
2025-11-28 00:27:33,039 - SentinelAgent - INFO - Driver monitor started
2025-11-28 00:27:33,049 - SentinelAgent - INFO - Firewall rule monitor started
2025-11-28 00:27:33,072 - SentinelAgent - INFO - Certificate monitor started
2025-11-28 00:27:33,222 - SentinelAgent - INFO - Named pipe monitor started
2025-11-28 00:27:33,279 - SentinelAgent - INFO - Windows Defender monitor started
2025-11-28 00:27:33,330 - SentinelAgent - INFO - AMSI monitor started
2025-11-28 00:27:33,388 - SentinelAgent - INFO - ETW monitor started
2025-11-28 00:27:33,404 - SentinelAgent - INFO - Browser extension monitor started - tracking 12 extensions
2025-11-28 00:27:33,404 - SentinelAgent - INFO - Sysmon monitor started
2025-11-28 00:27:33,435 - SentinelAgent - INFO - DLL injection monitor started
2025-11-28 00:27:33,616 - SentinelAgent - INFO - AVG monitor started - watching C:\ProgramData\AVG\Antivirus\report
2025-11-28 00:27:33,620 - SentinelAgent - INFO - Clipboard monitor started
2025-11-28 00:27:33,681 - SentinelAgent - INFO - Service monitor tracking 299 services
2025-11-28 00:27:34,881 - SentinelAgent - INFO - Scheduled task monitor started - tracking 195 tasks
2025-11-28 00:27:34,884 - SentinelAgent - INFO - Certificate monitor tracking 18 certificates
2025-11-28 00:27:38,711 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:27:40,320 - SentinelAgent - INFO - Firewall monitor tracking 376 rules
2025-11-28 00:27:41,192 - SentinelAgent - INFO - Driver monitor tracking 439 drivers
2025-11-28 00:28:02,324 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:28:32,363 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:29:02,437 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:29:32,516 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:30:04,772 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:30:34,800 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:31:04,830 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:31:20,538 - SentinelAgent - WARNING - Suspicious DLL: c:\windows\syswow64\devdispitemprovider.dll in BvSsh.exe
2025-11-28 00:31:25,271 - SentinelAgent - INFO - Event sent [ML]: dll_injection_suspected - Suspicious DLL loaded into BvSsh.exe
2025-11-28 00:31:34,862 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:32:05,665 - SentinelAgent - INFO - Successfully registered with dashboard
Exception in thread Thread-145 (_readerthread):
Traceback (most recent call last):
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 1045, in _bootstrap_inner
    self.run()
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 982, in run
    self._target(*self._args, **self._kwargs)
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\subprocess.py", line 1599, in _readerthread
    buffer.append(fh.read())
                  ^^^^^^^^^
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\encodings\cp1252.py", line 23, in decode
    return codecs.charmap_decode(input,self.errors,decoding_table)[0]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
UnicodeDecodeError: 'charmap' codec can't decode byte 0x81 in position 148: character maps to <undefined>
2025-11-28 00:32:35,793 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:33:05,851 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:33:35,884 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:34:06,093 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:34:36,625 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:35:06,662 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:35:36,760 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:36:07,230 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:36:37,342 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:37:07,365 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:37:37,896 - SentinelAgent - INFO - Successfully registered with dashboard
Exception in thread Thread-286 (_readerthread):
Traceback (most recent call last):
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 1045, in _bootstrap_inner
    self.run()
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 982, in run
    self._target(*self._args, **self._kwargs)
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\subprocess.py", line 1599, in _readerthread
    buffer.append(fh.read())
                  ^^^^^^^^^
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\encodings\cp1252.py", line 23, in decode
    return codecs.charmap_decode(input,self.errors,decoding_table)[0]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
UnicodeDecodeError: 'charmap' codec can't decode byte 0x81 in position 148: character maps to <undefined>
2025-11-28 00:38:08,905 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:38:40,014 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:39:10,042 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:39:45,172 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:40:20,313 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:40:50,463 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:41:21,380 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:41:51,597 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:42:23,708 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:42:53,792 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:43:24,849 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:43:54,893 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:44:25,600 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:44:34,389 - SentinelAgent - WARNING - Suspicious DLL: c:\users\markv\appdata\local\perplexity\comet\application\142.1.7444.29693\chrome.dll in comet.exe
2025-11-28 00:44:55,698 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:45:27,713 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:45:41,758 - SentinelAgent - WARNING - Suspicious DLL: c:\users\markv\appdata\local\perplexity\comet\application\142.1.7444.29693\chrome.dll in comet.exe
2025-11-28 00:45:41,760 - SentinelAgent - WARNING - Suspicious DLL: c:\users\markv\appdata\local\perplexity\comet\application\142.1.7444.29693\chrome_elf.dll in comet.exe
2025-11-28 00:46:02,904 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:46:19,263 - SentinelAgent - WARNING - Suspicious DLL: c:\users\markv\appdata\local\perplexity\comet\application\142.1.7444.29693\chrome.dll in comet.exe
2025-11-28 00:46:38,135 - SentinelAgent - INFO - Successfully registered with dashboard
Exception in thread Thread-483 (_readerthread):
Traceback (most recent call last):
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 1045, in _bootstrap_inner
    self.run()
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 982, in run
    self._target(*self._args, **self._kwargs)
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\subprocess.py", line 1599, in _readerthread
    buffer.append(fh.read())
                  ^^^^^^^^^
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\encodings\cp1252.py", line 23, in decode
    return codecs.charmap_decode(input,self.errors,decoding_table)[0]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
UnicodeDecodeError: 'charmap' codec can't decode byte 0x81 in position 148: character maps to <undefined>
2025-11-28 00:47:08,663 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:47:38,923 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:48:09,328 - SentinelAgent - INFO - Successfully registered with dashboard
Exception in thread Thread-519 (_readerthread):
Traceback (most recent call last):
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 1045, in _bootstrap_inner
    self.run()
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 982, in run
    self._target(*self._args, **self._kwargs)
2025-11-28 00:48:40,659 - SentinelAgent - INFO - Successfully registered with dashboard
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\subprocess.py", line 1599, in _readerthread
    buffer.append(fh.read())
                  ^^^^^^^^^
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\encodings\cp1252.py", line 23, in decode
    return codecs.charmap_decode(input,self.errors,decoding_table)[0]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
UnicodeDecodeError: 'charmap' codec can't decode byte 0x81 in position 148: character maps to <undefined>
2025-11-28 00:49:11,746 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:49:41,961 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:50:11,996 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:50:45,098 - SentinelAgent - INFO - Successfully registered with dashboard
2025-11-28 00:51:11,327 - SentinelAgent - WARNING - New driver: P9Rdr
2025-11-28 00:51:11,328 - SentinelAgent - WARNING - New driver: TPM
2025-11-28 00:51:11,329 - SentinelAgent - WARNING - New driver: WdNisDrv
2025-11-28 00:51:11,329 - SentinelAgent - WARNING - New driver: usbuhci
2025-11-28 00:51:11,330 - SentinelAgent - WARNING - New driver: BTHUSB
2025-11-28 00:51:11,330 - SentinelAgent - WARNING - New driver: b06bdrv
2025-11-28 00:51:11,335 - SentinelAgent - WARNING - New driver: RFCOMM
2025-11-28 00:51:11,336 - SentinelAgent - WARNING - New driver: rdpbus
2025-11-28 00:51:11,337 - SentinelAgent - WARNING - New driver: volmgrx
2025-11-28 00:51:11,338 - SentinelAgent - WARNING - New driver: wanarpv6
2025-11-28 00:51:11,338 - SentinelAgent - WARNING - New driver: VmsProxy
2025-11-28 00:51:11,338 - SentinelAgent - WARNING - New driver: Ucx01000
2025-11-28 00:51:11,338 - SentinelAgent - WARNING - New driver: Filetrace
2025-11-28 00:51:11,338 - SentinelAgent - WARNING - New driver: SdcaHidInbox
2025-11-28 00:51:11,339 - SentinelAgent - WARNING - New driver: bindflt
2025-11-28 00:51:11,339 - SentinelAgent - WARNING - New driver: iaLPSSi_I2C
2025-11-28 00:51:11,339 - SentinelAgent - WARNING - New driver: avgbidsh
2025-11-28 00:51:11,339 - SentinelAgent - WARNING - New driver: PlutonHsp2
2025-11-28 00:51:11,341 - SentinelAgent - WARNING - New driver: vwifimp
2025-11-28 00:51:11,341 - SentinelAgent - WARNING - New driver: usbprint
2025-11-28 00:51:11,341 - SentinelAgent - WARNING - New driver: nvstor
2025-11-28 00:51:11,342 - SentinelAgent - WARNING - New driver: ibtusb
2025-11-28 00:51:11,342 - SentinelAgent - WARNING - New driver: avgRvrt
2025-11-28 00:51:11,342 - SentinelAgent - WARNING - New driver: vpci
2025-11-28 00:51:11,343 - SentinelAgent - WARNING - New driver: iagpio
2025-11-28 00:51:11,343 - SentinelAgent - WARNING - New driver: BthMini
2025-11-28 00:51:11,343 - SentinelAgent - WARNING - New driver: ndiswanlegacy
2025-11-28 00:51:11,344 - SentinelAgent - WARNING - New driver: BthHFEnum
2025-11-28 00:51:11,348 - SentinelAgent - WARNING - New driver: stexstor
2025-11-28 00:51:11,349 - SentinelAgent - WARNING - New driver: KslD
2025-11-28 00:51:11,349 - SentinelAgent - WARNING - New driver: UcmCx0101
2025-11-28 00:51:11,350 - SentinelAgent - WARNING - New driver: mvumis
2025-11-28 00:51:11,351 - SentinelAgent - WARNING - New driver: SpbCx
2025-11-28 00:51:11,351 - SentinelAgent - WARNING - New driver: PlutonHeci
2025-11-28 00:51:11,352 - SentinelAgent - WARNING - New driver: l2bridge
2025-11-28 00:51:11,353 - SentinelAgent - WARNING - New driver: usbehci
2025-11-28 00:51:11,353 - SentinelAgent - WARNING - New driver: vwififlt
2025-11-28 00:51:11,354 - SentinelAgent - WARNING - New driver: arcsas
2025-11-28 00:51:11,354 - SentinelAgent - WARNING - New driver: terminpt
2025-11-28 00:51:11,355 - SentinelAgent - WARNING - New driver: dg_ssudbus
2025-11-28 00:51:11,355 - SentinelAgent - WARNING - New driver: tunnel
2025-11-28 00:51:11,355 - SentinelAgent - WARNING - New driver: MTConfig
2025-11-28 00:51:11,356 - SentinelAgent - WARNING - New driver: NetBT
2025-11-28 00:51:11,356 - SentinelAgent - WARNING - New driver: hvcrash
2025-11-28 00:51:11,356 - SentinelAgent - WARNING - New driver: mshidumdf
2025-11-28 00:51:11,356 - SentinelAgent - WARNING - New driver: CNG
2025-11-28 00:51:11,357 - SentinelAgent - WARNING - New driver: Ndu
2025-11-28 00:51:11,357 - SentinelAgent - WARNING - New driver: WUDFWpdMtp
2025-11-28 00:51:11,357 - SentinelAgent - WARNING - New driver: Beep
2025-11-28 00:51:11,358 - SentinelAgent - WARNING - New driver: i8042prt
2025-11-28 00:51:11,360 - SentinelAgent - WARNING - New driver: ThermalFilter
2025-11-28 00:51:11,362 - SentinelAgent - WARNING - New driver: mpsdrv
2025-11-28 00:51:11,364 - SentinelAgent - WARNING - New driver: ACPI
2025-11-28 00:51:11,364 - SentinelAgent - WARNING - New driver: Usb4HostRouter
2025-11-28 00:51:11,364 - SentinelAgent - WARNING - New driver: BasicDisplay
2025-11-28 00:51:11,364 - SentinelAgent - WARNING - New driver: portcfg
2025-11-28 00:51:11,366 - SentinelAgent - WARNING - New driver: usbcir
2025-11-28 00:51:11,367 - SentinelAgent - WARNING - New driver: genericusbfn
2025-11-28 00:51:11,367 - SentinelAgent - WARNING - New driver: Mup
2025-11-28 00:51:11,368 - SentinelAgent - WARNING - New driver: hwpolicy
2025-11-28 00:51:11,368 - SentinelAgent - WARNING - New driver: WIMMount
2025-11-28 00:51:11,368 - SentinelAgent - WARNING - New driver: fdc
2025-11-28 00:51:11,368 - SentinelAgent - WARNING - New driver: disk
2025-11-28 00:51:11,369 - SentinelAgent - WARNING - New driver: VerifierExt
2025-11-28 00:51:11,369 - SentinelAgent - WARNING - New driver: EhStorTcgDrv
2025-11-28 00:51:11,369 - SentinelAgent - WARNING - New driver: MSPQM
2025-11-28 00:51:11,370 - SentinelAgent - WARNING - New driver: NVHDA
2025-11-28 00:51:11,371 - SentinelAgent - WARNING - New driver: srvnet
2025-11-28 00:51:11,374 - SentinelAgent - WARNING - New driver: WFPLWFS
2025-11-28 00:51:11,375 - SentinelAgent - WARNING - New driver: WacomPen
2025-11-28 00:51:11,376 - SentinelAgent - WARNING - New driver: Netwtw04
2025-11-28 00:51:11,376 - SentinelAgent - WARNING - New driver: RasAcd
2025-11-28 00:51:11,377 - SentinelAgent - WARNING - New driver: WINUSB
2025-11-28 00:51:11,377 - SentinelAgent - WARNING - New driver: cdfs
2025-11-28 00:51:11,378 - SentinelAgent - WARNING - New driver: Msfs
2025-11-28 00:51:11,378 - SentinelAgent - WARNING - New driver: hnswfpdriver
2025-11-28 00:51:11,379 - SentinelAgent - WARNING - New driver: pdc
2025-11-28 00:51:11,379 - SentinelAgent - WARNING - New driver: iaLPSS2i_I2C
2025-11-28 00:51:11,380 - SentinelAgent - WARNING - New driver: UcmUcsiCx0101
2025-11-28 00:51:11,380 - SentinelAgent - WARNING - New driver: AsyncMac
2025-11-28 00:51:11,381 - SentinelAgent - WARNING - New driver: ErrDev
2025-11-28 00:51:11,385 - SentinelAgent - WARNING - New driver: AppleSSD
2025-11-28 00:51:11,388 - SentinelAgent - WARNING - New driver: SignalRgbDriver
2025-11-28 00:51:11,389 - SentinelAgent - WARNING - New driver: devmap
2025-11-28 00:51:11,389 - SentinelAgent - WARNING - New driver: MEIx64
2025-11-28 00:51:11,390 - SentinelAgent - WARNING - New driver: hidinterrupt
2025-11-28 00:51:11,391 - SentinelAgent - WARNING - New driver: storvsc
2025-11-28 00:51:11,391 - SentinelAgent - WARNING - New driver: MsQuic
2025-11-28 00:51:11,392 - SentinelAgent - WARNING - New driver: iaLPSS2i_GPIO2_GLK
2025-11-28 00:51:11,393 - SentinelAgent - WARNING - New driver: buttonconverter
2025-11-28 00:51:11,393 - SentinelAgent - WARNING - New driver: SdcaMfdInbox
2025-11-28 00:51:11,393 - SentinelAgent - WARNING - New driver: Wificx
2025-11-28 00:51:11,394 - SentinelAgent - WARNING - New driver: WUDFRd
2025-11-28 00:51:11,394 - SentinelAgent - WARNING - New driver: aehd
2025-11-28 00:51:11,394 - SentinelAgent - WARNING - New driver: mssmbios
2025-11-28 00:51:11,395 - SentinelAgent - WARNING - New driver: BasicRender
2025-11-28 00:51:11,395 - SentinelAgent - WARNING - New driver: bcmfn2
2025-11-28 00:51:11,395 - SentinelAgent - WARNING - New driver: usbohci
2025-11-28 00:51:11,395 - SentinelAgent - WARNING - New driver: wtd
2025-11-28 00:51:11,395 - SentinelAgent - WARNING - New driver: wdiwifi
2025-11-28 00:51:11,396 - SentinelAgent - WARNING - New driver: Dfsc
2025-11-28 00:51:11,396 - SentinelAgent - WARNING - New driver: SiSRaid4
2025-11-28 00:51:11,398 - SentinelAgent - WARNING - New driver: RasPppoe
2025-11-28 00:51:11,398 - SentinelAgent - WARNING - New driver: UASPStor
2025-11-28 00:51:11,398 - SentinelAgent - WARNING - New driver: swenum
2025-11-28 00:51:11,398 - SentinelAgent - WARNING - New driver: ItSas35i
2025-11-28 00:51:11,399 - SentinelAgent - WARNING - New driver: avgMonFlt
2025-11-28 00:51:11,399 - SentinelAgent - WARNING - New driver: vmsmp
2025-11-28 00:51:11,399 - SentinelAgent - WARNING - New driver: DisplayMux
2025-11-28 00:51:11,400 - SentinelAgent - WARNING - New driver: CimFS
2025-11-28 00:51:11,400 - SentinelAgent - WARNING - New driver: spaceport
2025-11-28 00:51:11,401 - SentinelAgent - WARNING - New driver: sdstor
2025-11-28 00:51:11,401 - SentinelAgent - WARNING - New driver: mausbip
2025-11-28 00:51:11,401 - SentinelAgent - WARNING - New driver: MSPCLOCK
2025-11-28 00:51:11,401 - SentinelAgent - WARNING - New driver: Npfs
2025-11-28 00:51:11,401 - SentinelAgent - WARNING - New driver: KSecDD
2025-11-28 00:51:11,402 - SentinelAgent - WARNING - New driver: Wdf01000
2025-11-28 00:51:11,402 - SentinelAgent - WARNING - New driver: fvevol
2025-11-28 00:51:11,402 - SentinelAgent - WARNING - New driver: pvhdparser
2025-11-28 00:51:11,402 - SentinelAgent - WARNING - New driver: dmvsc
2025-11-28 00:51:11,403 - SentinelAgent - WARNING - New driver: Modem
2025-11-28 00:51:11,403 - SentinelAgent - WARNING - New driver: Tcpip6
2025-11-28 00:51:11,404 - SentinelAgent - WARNING - New driver: wanarp
2025-11-28 00:51:11,404 - SentinelAgent - WARNING - New driver: afunix
2025-11-28 00:51:11,404 - SentinelAgent - WARNING - New driver: percsas3i
2025-11-28 00:51:11,404 - SentinelAgent - WARNING - New driver: WinVerbs
2025-11-28 00:51:11,405 - SentinelAgent - WARNING - New driver: lltdio
2025-11-28 00:51:11,405 - SentinelAgent - WARNING - New driver: acpiex
2025-11-28 00:51:11,405 - SentinelAgent - WARNING - New driver: MbbCx
2025-11-28 00:51:11,405 - SentinelAgent - WARNING - New driver: mountmgr
2025-11-28 00:51:11,405 - SentinelAgent - WARNING - New driver: MSKSSRV
2025-11-28 00:51:11,406 - SentinelAgent - WARNING - New driver: exfat
2025-11-28 00:51:11,406 - SentinelAgent - WARNING - New driver: UCPD
2025-11-28 00:51:11,406 - SentinelAgent - WARNING - New driver: bam
2025-11-28 00:51:11,406 - SentinelAgent - WARNING - New driver: kdnic_legacy
2025-11-28 00:51:11,406 - SentinelAgent - WARNING - New driver: lxss
2025-11-28 00:51:11,408 - SentinelAgent - WARNING - New driver: UcmUcsiAcpiClient
2025-11-28 00:51:11,408 - SentinelAgent - WARNING - New driver: avgbidsdriver
2025-11-28 00:51:11,409 - SentinelAgent - WARNING - New driver: umbus
2025-11-28 00:51:11,409 - SentinelAgent - WARNING - New driver: l1vhlwf
2025-11-28 00:51:11,410 - SentinelAgent - WARNING - New driver: netvsc
2025-11-28 00:51:11,410 - SentinelAgent - WARNING - New driver: IPT
2025-11-28 00:51:11,410 - SentinelAgent - WARNING - New driver: monitor
2025-11-28 00:51:11,410 - SentinelAgent - WARNING - New driver: SerCx2
2025-11-28 00:51:11,410 - SentinelAgent - WARNING - New driver: HyperVideo
2025-11-28 00:51:11,411 - SentinelAgent - WARNING - New driver: e1dexpress
2025-11-28 00:51:11,411 - SentinelAgent - WARNING - New driver: FsDepends
2025-11-28 00:51:11,411 - SentinelAgent - WARNING - New driver: Usb4DeviceRouter
2025-11-28 00:51:11,411 - SentinelAgent - WARNING - New driver: PEAUTH
2025-11-28 00:51:11,411 - SentinelAgent - WARNING - New driver: VMBusHID
2025-11-28 00:51:11,411 - SentinelAgent - WARNING - New driver: usbaudio
2025-11-28 00:51:11,412 - SentinelAgent - WARNING - New driver: iaStorV
2025-11-28 00:51:11,413 - SentinelAgent - WARNING - New driver: ibbus
2025-11-28 00:51:11,413 - SentinelAgent - WARNING - New driver: VMSP
2025-11-28 00:51:11,413 - SentinelAgent - WARNING - New driver: nvlddmkm
2025-11-28 00:51:11,413 - SentinelAgent - WARNING - New driver: usb-platformdetection
2025-11-28 00:51:11,414 - SentinelAgent - WARNING - New driver: Null
2025-11-28 00:51:11,414 - SentinelAgent - WARNING - New driver: volsnap
2025-11-28 00:51:11,414 - SentinelAgent - WARNING - New driver: AppID
2025-11-28 00:51:11,414 - SentinelAgent - WARNING - New driver: mouhid
2025-11-28 00:51:11,415 - SentinelAgent - WARNING - New driver: PRM
2025-11-28 00:51:11,415 - SentinelAgent - WARNING - New driver: drmkaud
2025-11-28 00:51:11,416 - SentinelAgent - WARNING - New driver: WdFilter
2025-11-28 00:51:11,416 - SentinelAgent - WARNING - New driver: Wof
2025-11-28 00:51:11,417 - SentinelAgent - WARNING - New driver: rhproxy
2025-11-28 00:51:11,417 - SentinelAgent - WARNING - New driver: cht4vbd
2025-11-28 00:51:11,417 - SentinelAgent - WARNING - New driver: NDKPing
2025-11-28 00:51:11,417 - SentinelAgent - WARNING - New driver: IndirectKmd
2025-11-28 00:51:11,417 - SentinelAgent - WARNING - New driver: nsiproxy
2025-11-28 00:51:11,417 - SentinelAgent - WARNING - New driver: avgNetHub
2025-11-28 00:51:11,417 - SentinelAgent - WARNING - New driver: pmem
2025-11-28 00:51:11,418 - SentinelAgent - WARNING - New driver: iaStorVD
2025-11-28 00:51:11,418 - SentinelAgent - WARNING - New driver: gencounter
2025-11-28 00:51:11,418 - SentinelAgent - WARNING - New driver: HidUsb
2025-11-28 00:51:11,418 - SentinelAgent - WARNING - New driver: acpipagr
2025-11-28 00:51:11,418 - SentinelAgent - WARNING - New driver: DXGKrnl
2025-11-28 00:51:11,418 - SentinelAgent - WARNING - New driver: e1i68x64
2025-11-28 00:51:11,418 - SentinelAgent - WARNING - New driver: PptpMiniport
2025-11-28 00:51:11,418 - SentinelAgent - WARNING - New driver: ReFSv1
2025-11-28 00:51:11,420 - SentinelAgent - WARNING - New driver: AcpiPmi
2025-11-28 00:51:11,420 - SentinelAgent - WARNING - New driver: stornvme
2025-11-28 00:51:11,420 - SentinelAgent - WARNING - New driver: bttflt
2025-11-28 00:51:11,421 - SentinelAgent - WARNING - New driver: pcw
2025-11-28 00:51:11,421 - SentinelAgent - WARNING - New driver: BTHMODEM
2025-11-28 00:51:11,421 - SentinelAgent - WARNING - New driver: vsmraid
2025-11-28 00:51:11,421 - SentinelAgent - WARNING - New driver: NdisVirtualBus
2025-11-28 00:51:11,421 - SentinelAgent - WARNING - New driver: sermouse
2025-11-28 00:51:11,421 - SentinelAgent - WARNING - New driver: pcmcia
2025-11-28 00:51:11,421 - SentinelAgent - WARNING - New driver: wcifs
2025-11-28 00:51:11,422 - SentinelAgent - WARNING - New driver: avgStm
2025-11-28 00:51:11,423 - SentinelAgent - WARNING - New driver: CLFS
2025-11-28 00:51:11,423 - SentinelAgent - WARNING - New driver: WinMad
2025-11-28 00:51:11,423 - SentinelAgent - WARNING - New driver: UrsChipidea
2025-11-28 00:51:11,423 - SentinelAgent - WARNING - New driver: HidIr
2025-11-28 00:51:11,423 - SentinelAgent - WARNING - New driver: NDIS
2025-11-28 00:51:11,424 - SentinelAgent - WARNING - New driver: vmbus
2025-11-28 00:51:11,424 - SentinelAgent - WARNING - New driver: cnghwassist
2025-11-28 00:51:11,424 - SentinelAgent - WARNING - New driver: partmgr
2025-11-28 00:51:11,424 - SentinelAgent - WARNING - New driver: iaLPSS2i_I2C_BXT_P
2025-11-28 00:51:11,425 - SentinelAgent - WARNING - New driver: VSTXRAID
2025-11-28 00:51:11,425 - SentinelAgent - WARNING - New driver: fastfat
2025-11-28 00:51:11,425 - SentinelAgent - WARNING - New driver: GenPass
2025-11-28 00:51:11,425 - SentinelAgent - WARNING - New driver: RasSstp
2025-11-28 00:51:11,425 - SentinelAgent - WARNING - New driver: VirtualRender
2025-11-28 00:51:11,425 - SentinelAgent - WARNING - New driver: ksthunk
2025-11-28 00:51:11,426 - SentinelAgent - WARNING - New driver: UdeCx
2025-11-28 00:51:11,426 - SentinelAgent - WARNING - New driver: mrxsmb
2025-11-28 00:51:11,427 - SentinelAgent - WARNING - New driver: USBXHCI
2025-11-28 00:51:11,427 - SentinelAgent - WARNING - New driver: iScsiPrt
2025-11-28 00:51:11,427 - SentinelAgent - WARNING - New driver: I3CHost
2025-11-28 00:51:11,427 - SentinelAgent - WARNING - New driver: usbser
2025-11-28 00:51:11,427 - SentinelAgent - WARNING - New driver: KSecPkg
2025-11-28 00:51:11,428 - SentinelAgent - WARNING - New driver: IPNAT
2025-11-28 00:51:11,429 - SentinelAgent - WARNING - New driver: NdisTapi
2025-11-28 00:51:11,430 - SentinelAgent - WARNING - New driver: bowser
2025-11-28 00:51:11,430 - SentinelAgent - WARNING - New driver: ADP80XX
2025-11-28 00:51:11,431 - SentinelAgent - WARNING - New driver: IpFilterDriver
2025-11-28 00:51:11,432 - SentinelAgent - WARNING - New driver: HidBth
2025-11-28 00:51:11,432 - SentinelAgent - WARNING - New driver: luafv
2025-11-28 00:51:11,433 - SentinelAgent - WARNING - New driver: TsUsbGD
2025-11-28 00:51:11,433 - SentinelAgent - WARNING - New driver: ReFS
2025-11-28 00:51:11,433 - SentinelAgent - WARNING - New driver: passthruparser
2025-11-28 00:51:11,434 - SentinelAgent - WARNING - New driver: UrsSynopsys
2025-11-28 00:51:11,434 - SentinelAgent - WARNING - New driver: BthEnum
2025-11-28 00:51:11,434 - SentinelAgent - WARNING - New driver: NetworkPrivacyPolicy
2025-11-28 00:51:11,434 - SentinelAgent - WARNING - New driver: tcpipreg
2025-11-28 00:51:11,435 - SentinelAgent - WARNING - New driver: MSTEE
2025-11-28 00:51:11,435 - SentinelAgent - WARNING - New driver: MsBridge
2025-11-28 00:51:11,435 - SentinelAgent - WARNING - New driver: LSI_SAS
2025-11-28 00:51:11,435 - SentinelAgent - WARNING - New driver: NetBIOS
2025-11-28 00:51:11,435 - SentinelAgent - WARNING - New driver: avgSnx
2025-11-28 00:51:11,435 - SentinelAgent - WARNING - New driver: vwifibus
2025-11-28 00:51:11,435 - SentinelAgent - WARNING - New driver: spaceparser
2025-11-28 00:51:11,435 - SentinelAgent - WARNING - New driver: vhdparser
2025-11-28 00:51:11,437 - SentinelAgent - WARNING - New driver: sbp2port
2025-11-28 00:51:11,437 - SentinelAgent - WARNING - New driver: USBHUB3
2025-11-28 00:51:11,437 - SentinelAgent - WARNING - New driver: MsLldp
2025-11-28 00:51:11,437 - SentinelAgent - WARNING - New driver: NetAdapterCx
2025-11-28 00:51:11,438 - SentinelAgent - WARNING - New driver: avgArDisk
2025-11-28 00:51:11,438 - SentinelAgent - WARNING - New driver: circlass
2025-11-28 00:51:11,438 - SentinelAgent - WARNING - New driver: msisadrv
2025-11-28 00:51:11,438 - SentinelAgent - WARNING - New driver: WUDFWpdFs
2025-11-28 00:51:11,438 - SentinelAgent - WARNING - New driver: iaLPSS2i_GPIO2
2025-11-28 00:51:11,438 - SentinelAgent - WARNING - New driver: hvservice
2025-11-28 00:51:11,439 - SentinelAgent - WARNING - New driver: VMSVSF
2025-11-28 00:51:11,439 - SentinelAgent - WARNING - New driver: Ufx01000
2025-11-28 00:51:11,439 - SentinelAgent - WARNING - New driver: hidspi
2025-11-28 00:51:11,439 - SentinelAgent - WARNING - New driver: QWAVEdrv
2025-11-28 00:51:11,440 - SentinelAgent - WARNING - New driver: vmgid
2025-11-28 00:51:11,440 - SentinelAgent - WARNING - New driver: isapnp
2025-11-28 00:51:11,440 - SentinelAgent - WARNING - New driver: mpi3drvi
2025-11-28 00:51:11,440 - SentinelAgent - WARNING - New driver: HDAudBus
2025-11-28 00:51:11,440 - SentinelAgent - WARNING - New driver: CDD
2025-11-28 00:51:11,440 - SentinelAgent - WARNING - New driver: udfs
2025-11-28 00:51:11,442 - SentinelAgent - WARNING - New driver: srv2
2025-11-28 00:51:11,442 - SentinelAgent - WARNING - New driver: BthPan
2025-11-28 00:51:11,442 - SentinelAgent - WARNING - New driver: ebdrv0
2025-11-28 00:51:11,442 - SentinelAgent - WARNING - New driver: rspndr
2025-11-28 00:51:11,443 - SentinelAgent - WARNING - New driver: flpydisk
2025-11-28 00:51:11,443 - SentinelAgent - WARNING - New driver: MsRPC
2025-11-28 00:51:11,443 - SentinelAgent - WARNING - New driver: kbdhid
2025-11-28 00:51:11,443 - SentinelAgent - WARNING - New driver: BTHPORT
2025-11-28 00:51:11,443 - SentinelAgent - WARNING - New driver: mouclass
2025-11-28 00:51:11,443 - SentinelAgent - WARNING - New driver: UfxChipidea
2025-11-28 00:51:11,444 - SentinelAgent - WARNING - New driver: scmbus
2025-11-28 00:51:11,445 - SentinelAgent - WARNING - New driver: vhf
2025-11-28 00:51:11,445 - SentinelAgent - WARNING - New driver: WpdUpFltr
2025-11-28 00:51:11,445 - SentinelAgent - WARNING - New driver: xinputhid
2025-11-28 00:51:11,446 - SentinelAgent - WARNING - New driver: avgbuniv
2025-11-28 00:51:11,446 - SentinelAgent - WARNING - New driver: Tcpip
2025-11-28 00:51:11,447 - SentinelAgent - WARNING - New driver: wini3ctarget
2025-11-28 00:51:11,447 - SentinelAgent - WARNING - New driver: Serial
2025-11-28 00:51:11,447 - SentinelAgent - WARNING - New driver: pciide
2025-11-28 00:51:11,447 - SentinelAgent - WARNING - New driver: WinNat
2025-11-28 00:51:11,450 - SentinelAgent - WARNING - New driver: VMSNPXY
2025-11-28 00:51:11,450 - SentinelAgent - WARNING - New driver: AFD
2025-11-28 00:51:11,453 - SentinelAgent - WARNING - New driver: avgRdr
2025-11-28 00:51:11,457 - SentinelAgent - WARNING - New driver: vmbusproxy
2025-11-28 00:51:11,457 - SentinelAgent - WARNING - New driver: cht4iscsi
2025-11-28 00:51:11,457 - SentinelAgent - WARNING - New driver: iaStorAVC
2025-11-28 00:51:11,458 - SentinelAgent - WARNING - New driver: rdbss
2025-11-28 00:51:11,458 - SentinelAgent - WARNING - New driver: atapi
2025-11-28 00:51:11,458 - SentinelAgent - WARNING - New driver: mlx4_bus
2025-11-28 00:51:11,459 - SentinelAgent - WARNING - New driver: ws2ifsl
2025-11-28 00:51:11,460 - SentinelAgent - WARNING - New driver: SerCx
2025-11-28 00:51:11,461 - SentinelAgent - WARNING - New driver: mshidkmdf
2025-11-28 00:51:11,461 - SentinelAgent - WARNING - New driver: IPMIDRV
2025-11-28 00:51:11,461 - SentinelAgent - WARNING - New driver: googledrivefs31931
2025-11-28 00:51:11,461 - SentinelAgent - WARNING - New driver: NDKPerf
2025-11-28 00:51:11,461 - SentinelAgent - WARNING - New driver: nvdimm
2025-11-28 00:51:11,461 - SentinelAgent - WARNING - New driver: Hsp
2025-11-28 00:51:11,461 - SentinelAgent - WARNING - New driver: WudfPf
2025-11-28 00:51:11,463 - SentinelAgent - WARNING - New driver: iaLPSS2_I2C_ADL
2025-11-28 00:51:11,464 - SentinelAgent - WARNING - New driver: RDPDR
2025-11-28 00:51:11,468 - SentinelAgent - WARNING - New driver: 3ware
2025-11-28 00:51:11,469 - SentinelAgent - WARNING - New driver: usbhub
2025-11-28 00:51:11,470 - SentinelAgent - WARNING - New driver: Ntfs
2025-11-28 00:51:11,471 - SentinelAgent - WARNING - New driver: applockerfltr
2025-11-28 00:51:11,471 - SentinelAgent - WARNING - New driver: volume
2025-11-28 00:51:11,472 - SentinelAgent - WARNING - New driver: avgKbd
2025-11-28 00:51:11,472 - SentinelAgent - WARNING - New driver: FileCrypt
2025-11-28 00:51:11,472 - SentinelAgent - WARNING - New driver: nvmedisk
2025-11-28 00:51:11,472 - SentinelAgent - WARNING - New driver: Ndisuio
2025-11-28 00:51:11,472 - SentinelAgent - WARNING - New driver: MRxDAV
2025-11-28 00:51:11,472 - SentinelAgent - WARNING - New driver: PNPMEM
2025-11-28 00:51:11,474 - SentinelAgent - WARNING - New driver: avgElam
2025-11-28 00:51:11,474 - SentinelAgent - WARNING - New driver: ufxsynopsys
2025-11-28 00:51:11,474 - SentinelAgent - WARNING - New driver: megasas35i
2025-11-28 00:51:11,474 - SentinelAgent - WARNING - New driver: MMCSS
2025-11-28 00:51:11,475 - SentinelAgent - WARNING - New driver: AcpiAudioCompositorInbox
2025-11-28 00:51:11,476 - SentinelAgent - WARNING - New driver: WdmCompanionFilter
2025-11-28 00:51:11,476 - SentinelAgent - WARNING - New driver: Parport
2025-11-28 00:51:11,477 - SentinelAgent - WARNING - New driver: NdisCap
2025-11-28 00:51:11,477 - SentinelAgent - WARNING - New driver: storflt
2025-11-28 00:51:11,477 - SentinelAgent - WARNING - New driver: CmBatt
2025-11-28 00:51:11,478 - SentinelAgent - WARNING - New driver: WdBoot
2025-11-28 00:51:11,481 - SentinelAgent - WARNING - New driver: scfilter
2025-11-28 00:51:11,482 - SentinelAgent - WARNING - New driver: HidSpiCx
2025-11-28 00:51:11,483 - SentinelAgent - WARNING - New driver: iai2c
2025-11-28 00:51:11,483 - SentinelAgent - WARNING - New driver: PktMon
2025-11-28 00:51:11,483 - SentinelAgent - WARNING - New driver: iaLPSS2i_GPIO2_CNL
2025-11-28 00:51:11,483 - SentinelAgent - WARNING - New driver: vmbusr
2025-11-28 00:51:11,484 - SentinelAgent - WARNING - New driver: nvvad_WaveExtensible
2025-11-28 00:51:11,485 - SentinelAgent - WARNING - New driver: WmiAcpi
2025-11-28 00:51:11,485 - SentinelAgent - WARNING - New driver: npsvctrig
2025-11-28 00:51:11,485 - SentinelAgent - WARNING - New driver: Vid
2025-11-28 00:51:11,485 - SentinelAgent - WARNING - New driver: VfpExt
2025-11-28 00:51:11,485 - SentinelAgent - WARNING - New driver: sfloppy
2025-11-28 00:51:11,486 - SentinelAgent - WARNING - New driver: mausbhost
2025-11-28 00:51:11,486 - SentinelAgent - WARNING - New driver: fse
2025-11-28 00:51:11,486 - SentinelAgent - WARNING - New driver: nvraid
2025-11-28 00:51:11,487 - SentinelAgent - WARNING - New driver: iorate
2025-11-28 00:51:11,487 - SentinelAgent - WARNING - New driver: megasr
2025-11-28 00:51:11,488 - SentinelAgent - WARNING - New driver: hidi2c
2025-11-28 00:51:11,488 - SentinelAgent - WARNING - New driver: FileInfo
2025-11-28 00:51:11,489 - SentinelAgent - WARNING - New driver: pci
2025-11-28 00:51:11,489 - SentinelAgent - WARNING - New driver: xboxgip
2025-11-28 00:51:11,489 - SentinelAgent - WARNING - New driver: tdx
2025-11-28 00:51:11,490 - SentinelAgent - WARNING - New driver: UnionFS
2025-11-28 00:51:11,490 - SentinelAgent - WARNING - New driver: RasAgileVpn
2025-11-28 00:51:11,495 - SentinelAgent - WARNING - New driver: Psched
2025-11-28 00:51:11,495 - SentinelAgent - WARNING - New driver: storqosflt
2025-11-28 00:51:11,497 - SentinelAgent - WARNING - New driver: cdrom
2025-11-28 00:51:11,498 - SentinelAgent - WARNING - New driver: usbvideo
2025-11-28 00:51:11,499 - SentinelAgent - WARNING - New driver: s3cap
2025-11-28 00:51:11,499 - SentinelAgent - WARNING - New driver: Acx01000
2025-11-28 00:51:11,499 - SentinelAgent - WARNING - New driver: pvscsi
2025-11-28 00:51:11,500 - SentinelAgent - WARNING - New driver: acpitime
2025-11-28 00:51:11,500 - SentinelAgent - WARNING - New driver: msgpiowin32
2025-11-28 00:51:11,500 - SentinelAgent - WARNING - New driver: UEFI
2025-11-28 00:51:11,501 - SentinelAgent - WARNING - New driver: HTTP
2025-11-28 00:51:11,501 - SentinelAgent - WARNING - New driver: avgVmm
2025-11-28 00:51:11,501 - SentinelAgent - WARNING - New driver: sdbus
2025-11-28 00:51:11,501 - SentinelAgent - WARNING - New driver: uiomap
2025-11-28 00:51:11,501 - SentinelAgent - WARNING - New driver: storvsp
2025-11-28 00:51:11,502 - SentinelAgent - WARNING - New driver: WinAccelCx0101
2025-11-28 00:51:11,502 - SentinelAgent - WARNING - New driver: FltMgr
2025-11-28 00:51:11,502 - SentinelAgent - WARNING - New driver: avgArPot
2025-11-28 00:51:11,502 - SentinelAgent - WARNING - New driver: dam
2025-11-28 00:51:11,502 - SentinelAgent - WARNING - New driver: 1394ohci
2025-11-28 00:51:11,504 - SentinelAgent - WARNING - New driver: USBSTOR
2025-11-28 00:51:11,504 - SentinelAgent - WARNING - New driver: CompositeBus
2025-11-28 00:51:11,504 - SentinelAgent - WARNING - New driver: MsQuicPrev
2025-11-28 00:51:11,507 - SentinelAgent - WARNING - New driver: ndfltr
2025-11-28 00:51:11,508 - SentinelAgent - WARNING - New driver: iaLPSS2i_GPIO2_BXT_P
2025-11-28 00:51:11,509 - SentinelAgent - WARNING - New driver: CldFlt
2025-11-28 00:51:11,509 - SentinelAgent - WARNING - New driver: PktMonApi
2025-11-28 00:51:11,509 - SentinelAgent - WARNING - New driver: vpcivsp
2025-11-28 00:51:11,510 - SentinelAgent - WARNING - New driver: mrxsmb20
2025-11-28 00:51:11,510 - SentinelAgent - WARNING - New driver: kdnic
2025-11-28 00:51:11,511 - SentinelAgent - WARNING - New driver: usbccgp
2025-11-28 00:51:11,512 - SentinelAgent - WARNING - New driver: condrv
2025-11-28 00:51:11,512 - SentinelAgent - WARNING - New driver: WinFsp
2025-11-28 00:51:11,513 - SentinelAgent - WARNING - New driver: avgSP
2025-11-28 00:51:11,514 - SentinelAgent - WARNING - New driver: SiSRaid2
2025-11-28 00:51:11,514 - SentinelAgent - WARNING - New driver: bfs
2025-11-28 00:51:11,514 - SentinelAgent - WARNING - New driver: BthA2dp
2025-11-28 00:51:11,514 - SentinelAgent - WARNING - New driver: usbaudio2
2025-11-28 00:51:11,515 - SentinelAgent - WARNING - New driver: rdyboost
2025-11-28 00:51:11,515 - SentinelAgent - WARNING - New driver: ssudmdm
2025-11-28 00:51:11,515 - SentinelAgent - WARNING - New driver: iaLPSS2i_I2C_GLK
2025-11-28 00:51:11,516 - SentinelAgent - WARNING - New driver: LSI_SAS2i
2025-11-28 00:51:11,516 - SentinelAgent - WARNING - New driver: megasas2i
2025-11-28 00:51:11,517 - SentinelAgent - WARNING - New driver: EhStorClass
2025-11-28 00:51:11,517 - SentinelAgent - WARNING - New driver: Rasl2tp
2025-11-28 00:51:11,517 - SentinelAgent - WARNING - New driver: ndproxy
2025-11-28 00:51:11,517 - SentinelAgent - WARNING - New driver: hvsocketcontrol
2025-11-28 00:51:11,518 - SentinelAgent - WARNING - New driver: iaLPSSi_GPIO
2025-11-28 00:51:11,522 - SentinelAgent - WARNING - New driver: UcmTcpciCx0101
2025-11-28 00:51:11,523 - SentinelAgent - WARNING - New driver: NdisWan
2025-11-28 00:51:11,523 - SentinelAgent - WARNING - New driver: AcpiDev
2025-11-28 00:51:11,523 - SentinelAgent - WARNING - New driver: CAD
2025-11-28 00:51:11,524 - SentinelAgent - WARNING - New driver: hyperkbd
2025-11-28 00:51:11,524 - SentinelAgent - WARNING - New driver: BthLEEnum
2025-11-28 00:51:11,525 - SentinelAgent - WARNING - New driver: volmgr
2025-11-28 00:51:11,525 - SentinelAgent - WARNING - New driver: storahci
2025-11-28 00:51:11,525 - SentinelAgent - WARNING - New driver: LSI_SAS3i
2025-11-28 00:51:11,525 - SentinelAgent - WARNING - New driver: NdisImPlatform
2025-11-28 00:51:11,526 - SentinelAgent - WARNING - New driver: UmPass
2025-11-28 00:51:11,527 - SentinelAgent - WARNING - New driver: storufs
2025-11-28 00:51:11,527 - SentinelAgent - WARNING - New driver: GPIOClx0101
2025-11-28 00:51:11,527 - SentinelAgent - WARNING - New driver: TsUsbFlt
2025-11-28 00:51:11,528 - SentinelAgent - WARNING - New driver: iaLPSS2i_I2C_CNL
2025-11-28 00:51:11,528 - SentinelAgent - WARNING - New driver: ExecutionContext
2025-11-28 00:51:11,528 - SentinelAgent - WARNING - New driver: HidBatt
2025-11-28 00:51:11,529 - SentinelAgent - WARNING - New driver: vhdmp
2025-11-28 00:51:11,529 - SentinelAgent - WARNING - New driver: percsas2i
2025-11-28 00:51:11,529 - SentinelAgent - WARNING - New driver: asstahci64
2025-11-28 00:51:11,529 - SentinelAgent - WARNING - New driver: UrsCx01000
2025-11-28 00:51:11,529 - SentinelAgent - WARNING - New driver: ebdrv
2025-11-28 00:51:11,529 - SentinelAgent - WARNING - New driver: Processor
2025-11-28 00:51:11,530 - SentinelAgent - WARNING - New driver: BthHFAud
2025-11-28 00:51:11,530 - SentinelAgent - WARNING - New driver: HwNClx0101
2025-11-28 00:51:11,530 - SentinelAgent - WARNING - New driver: NativeWifiP
2025-11-28 00:51:11,531 - SentinelAgent - WARNING - New driver: Serenum
2025-11-28 00:51:11,533 - SentinelAgent - WARNING - New driver: HdAudAddService
2025-11-28 00:51:11,535 - SentinelAgent - WARNING - New driver: kbdclass
2025-11-28 00:51:11,535 - SentinelAgent - WARNING - New driver: vdrvroot
2025-11-28 00:51:11,535 - SentinelAgent - WARNING - New driver: VMSVSP
2025-11-28 00:51:11,536 - SentinelAgent - WARNING - New driver: ahcache
Exception in thread Thread-577 (_readerthread):
Traceback (most recent call last):
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 1045, in _bootstrap_inner
    self.run()
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 982, in run
    self._target(*self._args, **self._kwargs)
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\subprocess.py", line 1599, in _readerthread
    buffer.append(fh.read())
                  ^^^^^^^^^
2025-11-28 00:51:21,342 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\encodings\cp1252.py", line 23, in decode
    return codecs.charmap_decode(input,self.errors,decoding_table)[0]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
UnicodeDecodeError: 'charmap' codec can't decode byte 0x81 in position 148: character maps to <undefined>
2025-11-28 00:51:57,763 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
Exception in thread Thread-603 (_readerthread):
Traceback (most recent call last):
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 1045, in _bootstrap_inner
    self.run()
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 982, in run
    self._target(*self._args, **self._kwargs)
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\subprocess.py", line 1599, in _readerthread
    buffer.append(fh.read())
                  ^^^^^^^^^
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\encodings\cp1252.py", line 23, in decode
    return codecs.charmap_decode(input,self.errors,decoding_table)[0]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
UnicodeDecodeError: 'charmap' codec can't decode byte 0x81 in position 148: character maps to <undefined>
2025-11-28 00:52:33,094 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:53:18,520 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:53:28,974 - SentinelAgent - WARNING - Suspicious DLL: c:\users\markv\appdata\local\perplexity\comet\application\142.1.7444.29693\chrome.dll in comet.exe
2025-11-28 00:53:56,000 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:54:31,593 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:55:07,204 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:55:42,439 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:56:17,781 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:56:18,818 - SentinelAgent - WARNING - New driver: P9Rdr
2025-11-28 00:56:18,971 - SentinelAgent - WARNING - New driver: TPM
2025-11-28 00:56:20,583 - SentinelAgent - WARNING - New driver: WdNisDrv
2025-11-28 00:56:20,706 - SentinelAgent - WARNING - New driver: usbuhci
2025-11-28 00:56:20,726 - SentinelAgent - WARNING - New driver: BTHUSB
2025-11-28 00:56:20,727 - SentinelAgent - WARNING - New driver: b06bdrv
2025-11-28 00:56:20,820 - SentinelAgent - WARNING - New driver: RFCOMM
2025-11-28 00:56:20,821 - SentinelAgent - WARNING - New driver: rdpbus
2025-11-28 00:56:20,824 - SentinelAgent - WARNING - New driver: volmgrx
2025-11-28 00:56:21,422 - SentinelAgent - WARNING - New driver: wanarpv6
2025-11-28 00:56:21,502 - SentinelAgent - WARNING - New driver: VmsProxy
2025-11-28 00:56:21,515 - SentinelAgent - WARNING - New driver: Ucx01000
2025-11-28 00:56:22,551 - SentinelAgent - WARNING - New driver: Filetrace
2025-11-28 00:56:22,562 - SentinelAgent - WARNING - New driver: SdcaHidInbox
2025-11-28 00:56:22,577 - SentinelAgent - WARNING - New driver: bindflt
2025-11-28 00:56:22,608 - SentinelAgent - WARNING - New driver: iaLPSSi_I2C
2025-11-28 00:56:22,633 - SentinelAgent - WARNING - New driver: avgbidsh
2025-11-28 00:56:22,652 - SentinelAgent - WARNING - New driver: PlutonHsp2
2025-11-28 00:56:22,672 - SentinelAgent - WARNING - New driver: vwifimp
2025-11-28 00:56:22,701 - SentinelAgent - WARNING - New driver: usbprint
2025-11-28 00:56:22,758 - SentinelAgent - WARNING - New driver: nvstor
2025-11-28 00:56:22,905 - SentinelAgent - WARNING - New driver: ibtusb
2025-11-28 00:56:22,918 - SentinelAgent - WARNING - New driver: avgRvrt
2025-11-28 00:56:22,961 - SentinelAgent - WARNING - New driver: vpci
2025-11-28 00:56:22,980 - SentinelAgent - WARNING - New driver: iagpio
2025-11-28 00:56:22,981 - SentinelAgent - WARNING - New driver: BthMini
2025-11-28 00:56:23,027 - SentinelAgent - WARNING - New driver: ndiswanlegacy
2025-11-28 00:56:23,027 - SentinelAgent - WARNING - New driver: BthHFEnum
2025-11-28 00:56:23,187 - SentinelAgent - WARNING - New driver: stexstor
2025-11-28 00:56:23,237 - SentinelAgent - WARNING - New driver: KslD
2025-11-28 00:56:23,238 - SentinelAgent - WARNING - New driver: UcmCx0101
2025-11-28 00:56:23,341 - SentinelAgent - WARNING - New driver: mvumis
2025-11-28 00:56:23,755 - SentinelAgent - WARNING - New driver: SpbCx
2025-11-28 00:56:23,935 - SentinelAgent - WARNING - New driver: PlutonHeci
2025-11-28 00:56:24,119 - SentinelAgent - WARNING - New driver: l2bridge
2025-11-28 00:56:24,120 - SentinelAgent - WARNING - New driver: usbehci
2025-11-28 00:56:24,199 - SentinelAgent - WARNING - New driver: vwififlt
2025-11-28 00:56:24,253 - SentinelAgent - WARNING - Suspicious DLL: c:\users\markv\appdata\local\perplexity\comet\application\142.1.7444.29693\chrome.dll in comet.exe
2025-11-28 00:56:24,253 - SentinelAgent - WARNING - New driver: arcsas
2025-11-28 00:56:24,299 - SentinelAgent - WARNING - New driver: terminpt
2025-11-28 00:56:24,317 - SentinelAgent - WARNING - New driver: dg_ssudbus
2025-11-28 00:56:24,925 - SentinelAgent - WARNING - New driver: tunnel
2025-11-28 00:56:24,939 - SentinelAgent - WARNING - New driver: MTConfig
2025-11-28 00:56:25,058 - SentinelAgent - WARNING - New driver: NetBT
2025-11-28 00:56:25,073 - SentinelAgent - WARNING - New driver: hvcrash
2025-11-28 00:56:25,096 - SentinelAgent - WARNING - New driver: mshidumdf
2025-11-28 00:56:25,166 - SentinelAgent - WARNING - New driver: CNG
2025-11-28 00:56:25,185 - SentinelAgent - WARNING - New driver: Ndu
2025-11-28 00:56:25,200 - SentinelAgent - WARNING - New driver: WUDFWpdMtp
2025-11-28 00:56:25,879 - SentinelAgent - WARNING - New driver: Beep
2025-11-28 00:56:25,921 - SentinelAgent - WARNING - New driver: i8042prt
2025-11-28 00:56:27,122 - SentinelAgent - WARNING - New driver: ThermalFilter
2025-11-28 00:56:27,213 - SentinelAgent - WARNING - New driver: mpsdrv
2025-11-28 00:56:27,215 - SentinelAgent - WARNING - New driver: ACPI
2025-11-28 00:56:27,216 - SentinelAgent - WARNING - New driver: Usb4HostRouter
2025-11-28 00:56:27,216 - SentinelAgent - WARNING - New driver: BasicDisplay
2025-11-28 00:56:27,217 - SentinelAgent - WARNING - New driver: portcfg
2025-11-28 00:56:27,217 - SentinelAgent - WARNING - New driver: usbcir
2025-11-28 00:56:27,218 - SentinelAgent - WARNING - New driver: genericusbfn
2025-11-28 00:56:27,219 - SentinelAgent - WARNING - New driver: Mup
2025-11-28 00:56:27,220 - SentinelAgent - WARNING - New driver: hwpolicy
2025-11-28 00:56:27,221 - SentinelAgent - WARNING - New driver: WIMMount
2025-11-28 00:56:27,222 - SentinelAgent - WARNING - New driver: fdc
2025-11-28 00:56:27,222 - SentinelAgent - WARNING - New driver: disk
2025-11-28 00:56:27,222 - SentinelAgent - WARNING - New driver: VerifierExt
2025-11-28 00:56:27,222 - SentinelAgent - WARNING - New driver: EhStorTcgDrv
2025-11-28 00:56:27,223 - SentinelAgent - WARNING - New driver: MSPQM
2025-11-28 00:56:27,223 - SentinelAgent - WARNING - New driver: NVHDA
2025-11-28 00:56:27,224 - SentinelAgent - WARNING - New driver: srvnet
2025-11-28 00:56:27,225 - SentinelAgent - WARNING - New driver: WFPLWFS
2025-11-28 00:56:27,227 - SentinelAgent - WARNING - New driver: WacomPen
2025-11-28 00:56:27,234 - SentinelAgent - WARNING - New driver: Netwtw04
2025-11-28 00:56:27,240 - SentinelAgent - WARNING - New driver: RasAcd
2025-11-28 00:56:27,242 - SentinelAgent - WARNING - New driver: WINUSB
2025-11-28 00:56:27,246 - SentinelAgent - WARNING - New driver: cdfs
2025-11-28 00:56:27,251 - SentinelAgent - WARNING - New driver: Msfs
2025-11-28 00:56:27,254 - SentinelAgent - WARNING - New driver: hnswfpdriver
2025-11-28 00:56:27,256 - SentinelAgent - WARNING - New driver: pdc
2025-11-28 00:56:27,257 - SentinelAgent - WARNING - New driver: iaLPSS2i_I2C
2025-11-28 00:56:27,259 - SentinelAgent - WARNING - New driver: UcmUcsiCx0101
2025-11-28 00:56:27,261 - SentinelAgent - WARNING - New driver: AsyncMac
2025-11-28 00:56:27,262 - SentinelAgent - WARNING - New driver: ErrDev
2025-11-28 00:56:27,263 - SentinelAgent - WARNING - New driver: AppleSSD
2025-11-28 00:56:27,263 - SentinelAgent - WARNING - New driver: SignalRgbDriver
2025-11-28 00:56:27,264 - SentinelAgent - WARNING - New driver: devmap
2025-11-28 00:56:27,266 - SentinelAgent - WARNING - New driver: MEIx64
2025-11-28 00:56:27,269 - SentinelAgent - WARNING - New driver: hidinterrupt
2025-11-28 00:56:27,270 - SentinelAgent - WARNING - New driver: storvsc
2025-11-28 00:56:27,271 - SentinelAgent - WARNING - New driver: MsQuic
2025-11-28 00:56:27,272 - SentinelAgent - WARNING - New driver: iaLPSS2i_GPIO2_GLK
2025-11-28 00:56:27,272 - SentinelAgent - WARNING - New driver: buttonconverter
2025-11-28 00:56:27,273 - SentinelAgent - WARNING - New driver: SdcaMfdInbox
2025-11-28 00:56:27,274 - SentinelAgent - WARNING - New driver: Wificx
2025-11-28 00:56:27,277 - SentinelAgent - WARNING - New driver: WUDFRd
2025-11-28 00:56:27,280 - SentinelAgent - WARNING - New driver: aehd
2025-11-28 00:56:27,281 - SentinelAgent - WARNING - New driver: mssmbios
2025-11-28 00:56:27,283 - SentinelAgent - WARNING - New driver: BasicRender
2025-11-28 00:56:27,283 - SentinelAgent - WARNING - New driver: bcmfn2
2025-11-28 00:56:27,284 - SentinelAgent - WARNING - New driver: usbohci
2025-11-28 00:56:27,284 - SentinelAgent - WARNING - New driver: wtd
2025-11-28 00:56:27,286 - SentinelAgent - WARNING - New driver: wdiwifi
2025-11-28 00:56:27,286 - SentinelAgent - WARNING - New driver: Dfsc
2025-11-28 00:56:27,287 - SentinelAgent - WARNING - New driver: SiSRaid4
2025-11-28 00:56:27,287 - SentinelAgent - WARNING - New driver: RasPppoe
2025-11-28 00:56:27,289 - SentinelAgent - WARNING - New driver: UASPStor
2025-11-28 00:56:27,291 - SentinelAgent - WARNING - New driver: swenum
2025-11-28 00:56:27,293 - SentinelAgent - WARNING - New driver: ItSas35i
2025-11-28 00:56:27,301 - SentinelAgent - WARNING - New driver: avgMonFlt
2025-11-28 00:56:27,310 - SentinelAgent - WARNING - New driver: vmsmp
2025-11-28 00:56:27,319 - SentinelAgent - WARNING - New driver: DisplayMux
2025-11-28 00:56:27,324 - SentinelAgent - WARNING - New driver: CimFS
2025-11-28 00:56:27,325 - SentinelAgent - WARNING - New driver: spaceport
2025-11-28 00:56:27,325 - SentinelAgent - WARNING - New driver: sdstor
2025-11-28 00:56:27,327 - SentinelAgent - WARNING - New driver: mausbip
2025-11-28 00:56:27,329 - SentinelAgent - WARNING - New driver: MSPCLOCK
2025-11-28 00:56:27,330 - SentinelAgent - WARNING - New driver: Npfs
2025-11-28 00:56:27,330 - SentinelAgent - WARNING - New driver: KSecDD
2025-11-28 00:56:27,332 - SentinelAgent - WARNING - New driver: Wdf01000
2025-11-28 00:56:27,333 - SentinelAgent - WARNING - New driver: fvevol
2025-11-28 00:56:27,334 - SentinelAgent - WARNING - New driver: pvhdparser
2025-11-28 00:56:27,337 - SentinelAgent - WARNING - New driver: dmvsc
2025-11-28 00:56:27,341 - SentinelAgent - WARNING - New driver: Modem
2025-11-28 00:56:27,345 - SentinelAgent - WARNING - New driver: Tcpip6
2025-11-28 00:56:27,348 - SentinelAgent - WARNING - New driver: wanarp
2025-11-28 00:56:27,350 - SentinelAgent - WARNING - New driver: afunix
2025-11-28 00:56:27,354 - SentinelAgent - WARNING - New driver: percsas3i
2025-11-28 00:56:27,357 - SentinelAgent - WARNING - New driver: WinVerbs
2025-11-28 00:56:27,359 - SentinelAgent - WARNING - New driver: lltdio
2025-11-28 00:56:27,360 - SentinelAgent - WARNING - New driver: acpiex
2025-11-28 00:56:27,361 - SentinelAgent - WARNING - New driver: MbbCx
2025-11-28 00:56:27,361 - SentinelAgent - WARNING - New driver: mountmgr
2025-11-28 00:56:27,361 - SentinelAgent - WARNING - New driver: MSKSSRV
2025-11-28 00:56:27,362 - SentinelAgent - WARNING - New driver: exfat
2025-11-28 00:56:27,363 - SentinelAgent - WARNING - New driver: UCPD
2025-11-28 00:56:27,364 - SentinelAgent - WARNING - New driver: bam
2025-11-28 00:56:27,365 - SentinelAgent - WARNING - New driver: kdnic_legacy
2025-11-28 00:56:27,365 - SentinelAgent - WARNING - New driver: lxss
2025-11-28 00:56:27,366 - SentinelAgent - WARNING - New driver: UcmUcsiAcpiClient
2025-11-28 00:56:27,369 - SentinelAgent - WARNING - New driver: avgbidsdriver
2025-11-28 00:56:27,373 - SentinelAgent - WARNING - New driver: umbus
2025-11-28 00:56:27,400 - SentinelAgent - WARNING - New driver: l1vhlwf
2025-11-28 00:56:27,416 - SentinelAgent - WARNING - New driver: netvsc
2025-11-28 00:56:27,426 - SentinelAgent - WARNING - New driver: IPT
2025-11-28 00:56:27,430 - SentinelAgent - WARNING - New driver: monitor
2025-11-28 00:56:27,437 - SentinelAgent - WARNING - New driver: SerCx2
2025-11-28 00:56:27,441 - SentinelAgent - WARNING - New driver: HyperVideo
2025-11-28 00:56:27,443 - SentinelAgent - WARNING - New driver: e1dexpress
2025-11-28 00:56:27,444 - SentinelAgent - WARNING - New driver: FsDepends
2025-11-28 00:56:27,445 - SentinelAgent - WARNING - New driver: Usb4DeviceRouter
2025-11-28 00:56:27,445 - SentinelAgent - WARNING - New driver: PEAUTH
2025-11-28 00:56:27,447 - SentinelAgent - WARNING - New driver: VMBusHID
2025-11-28 00:56:27,448 - SentinelAgent - WARNING - New driver: usbaudio
2025-11-28 00:56:27,450 - SentinelAgent - WARNING - New driver: iaStorV
2025-11-28 00:56:27,451 - SentinelAgent - WARNING - New driver: ibbus
2025-11-28 00:56:27,452 - SentinelAgent - WARNING - New driver: VMSP
2025-11-28 00:56:27,452 - SentinelAgent - WARNING - New driver: nvlddmkm
2025-11-28 00:56:27,453 - SentinelAgent - WARNING - New driver: usb-platformdetection
2025-11-28 00:56:27,453 - SentinelAgent - WARNING - New driver: Null
2025-11-28 00:56:27,454 - SentinelAgent - WARNING - New driver: volsnap
2025-11-28 00:56:27,455 - SentinelAgent - WARNING - New driver: AppID
2025-11-28 00:56:27,456 - SentinelAgent - WARNING - New driver: mouhid
2025-11-28 00:56:27,457 - SentinelAgent - WARNING - New driver: PRM
2025-11-28 00:56:27,458 - SentinelAgent - WARNING - New driver: drmkaud
2025-11-28 00:56:27,461 - SentinelAgent - WARNING - New driver: WdFilter
2025-11-28 00:56:27,463 - SentinelAgent - WARNING - New driver: Wof
2025-11-28 00:56:27,463 - SentinelAgent - WARNING - New driver: rhproxy
2025-11-28 00:56:27,465 - SentinelAgent - WARNING - New driver: cht4vbd
2025-11-28 00:56:27,466 - SentinelAgent - WARNING - New driver: NDKPing
2025-11-28 00:56:27,466 - SentinelAgent - WARNING - New driver: IndirectKmd
2025-11-28 00:56:27,466 - SentinelAgent - WARNING - New driver: nsiproxy
2025-11-28 00:56:27,467 - SentinelAgent - WARNING - New driver: avgNetHub
2025-11-28 00:56:27,467 - SentinelAgent - WARNING - New driver: pmem
2025-11-28 00:56:27,467 - SentinelAgent - WARNING - New driver: iaStorVD
2025-11-28 00:56:27,468 - SentinelAgent - WARNING - New driver: gencounter
2025-11-28 00:56:27,469 - SentinelAgent - WARNING - New driver: HidUsb
2025-11-28 00:56:27,469 - SentinelAgent - WARNING - New driver: acpipagr
2025-11-28 00:56:27,469 - SentinelAgent - WARNING - New driver: DXGKrnl
2025-11-28 00:56:27,470 - SentinelAgent - WARNING - New driver: e1i68x64
2025-11-28 00:56:27,470 - SentinelAgent - WARNING - New driver: PptpMiniport
2025-11-28 00:56:27,470 - SentinelAgent - WARNING - New driver: ReFSv1
2025-11-28 00:56:27,470 - SentinelAgent - WARNING - New driver: AcpiPmi
2025-11-28 00:56:27,471 - SentinelAgent - WARNING - New driver: stornvme
2025-11-28 00:56:27,472 - SentinelAgent - WARNING - New driver: bttflt
2025-11-28 00:56:27,477 - SentinelAgent - WARNING - New driver: pcw
2025-11-28 00:56:27,489 - SentinelAgent - WARNING - New driver: BTHMODEM
2025-11-28 00:56:27,494 - SentinelAgent - WARNING - New driver: vsmraid
2025-11-28 00:56:27,498 - SentinelAgent - WARNING - New driver: NdisVirtualBus
2025-11-28 00:56:27,501 - SentinelAgent - WARNING - New driver: sermouse
2025-11-28 00:56:27,502 - SentinelAgent - WARNING - New driver: pcmcia
2025-11-28 00:56:27,502 - SentinelAgent - WARNING - New driver: wcifs
2025-11-28 00:56:27,502 - SentinelAgent - WARNING - New driver: avgStm
2025-11-28 00:56:27,505 - SentinelAgent - WARNING - New driver: CLFS
2025-11-28 00:56:27,506 - SentinelAgent - WARNING - New driver: WinMad
2025-11-28 00:56:27,506 - SentinelAgent - WARNING - New driver: UrsChipidea
2025-11-28 00:56:27,507 - SentinelAgent - WARNING - New driver: HidIr
2025-11-28 00:56:27,507 - SentinelAgent - WARNING - New driver: NDIS
2025-11-28 00:56:27,507 - SentinelAgent - WARNING - New driver: vmbus
2025-11-28 00:56:27,508 - SentinelAgent - WARNING - New driver: cnghwassist
2025-11-28 00:56:27,508 - SentinelAgent - WARNING - New driver: partmgr
2025-11-28 00:56:27,509 - SentinelAgent - WARNING - New driver: iaLPSS2i_I2C_BXT_P
2025-11-28 00:56:27,509 - SentinelAgent - WARNING - New driver: VSTXRAID
2025-11-28 00:56:27,510 - SentinelAgent - WARNING - New driver: fastfat
2025-11-28 00:56:27,510 - SentinelAgent - WARNING - New driver: GenPass
2025-11-28 00:56:27,510 - SentinelAgent - WARNING - New driver: RasSstp
2025-11-28 00:56:27,511 - SentinelAgent - WARNING - New driver: VirtualRender
2025-11-28 00:56:27,511 - SentinelAgent - WARNING - New driver: ksthunk
2025-11-28 00:56:27,511 - SentinelAgent - WARNING - New driver: UdeCx
2025-11-28 00:56:27,511 - SentinelAgent - WARNING - New driver: mrxsmb
2025-11-28 00:56:27,512 - SentinelAgent - WARNING - New driver: USBXHCI
2025-11-28 00:56:27,513 - SentinelAgent - WARNING - New driver: iScsiPrt
2025-11-28 00:56:27,513 - SentinelAgent - WARNING - New driver: I3CHost
2025-11-28 00:56:27,513 - SentinelAgent - WARNING - New driver: usbser
2025-11-28 00:56:27,514 - SentinelAgent - WARNING - New driver: KSecPkg
2025-11-28 00:56:27,514 - SentinelAgent - WARNING - New driver: IPNAT
2025-11-28 00:56:27,514 - SentinelAgent - WARNING - New driver: NdisTapi
2025-11-28 00:56:27,514 - SentinelAgent - WARNING - New driver: bowser
2025-11-28 00:56:27,516 - SentinelAgent - WARNING - New driver: ADP80XX
2025-11-28 00:56:27,516 - SentinelAgent - WARNING - New driver: IpFilterDriver
2025-11-28 00:56:27,516 - SentinelAgent - WARNING - New driver: HidBth
2025-11-28 00:56:27,516 - SentinelAgent - WARNING - New driver: luafv
2025-11-28 00:56:27,517 - SentinelAgent - WARNING - New driver: TsUsbGD
2025-11-28 00:56:27,517 - SentinelAgent - WARNING - New driver: ReFS
2025-11-28 00:56:27,517 - SentinelAgent - WARNING - New driver: passthruparser
2025-11-28 00:56:27,518 - SentinelAgent - WARNING - New driver: UrsSynopsys
2025-11-28 00:56:27,519 - SentinelAgent - WARNING - New driver: BthEnum
2025-11-28 00:56:27,520 - SentinelAgent - WARNING - New driver: NetworkPrivacyPolicy
2025-11-28 00:56:27,521 - SentinelAgent - WARNING - New driver: tcpipreg
2025-11-28 00:56:27,521 - SentinelAgent - WARNING - New driver: MSTEE
2025-11-28 00:56:27,521 - SentinelAgent - WARNING - New driver: MsBridge
2025-11-28 00:56:27,522 - SentinelAgent - WARNING - New driver: LSI_SAS
2025-11-28 00:56:27,522 - SentinelAgent - WARNING - New driver: NetBIOS
2025-11-28 00:56:27,522 - SentinelAgent - WARNING - New driver: avgSnx
2025-11-28 00:56:27,522 - SentinelAgent - WARNING - New driver: vwifibus
2025-11-28 00:56:27,523 - SentinelAgent - WARNING - New driver: spaceparser
2025-11-28 00:56:27,523 - SentinelAgent - WARNING - New driver: vhdparser
2025-11-28 00:56:27,523 - SentinelAgent - WARNING - New driver: sbp2port
2025-11-28 00:56:27,524 - SentinelAgent - WARNING - New driver: USBHUB3
2025-11-28 00:56:27,524 - SentinelAgent - WARNING - New driver: MsLldp
2025-11-28 00:56:27,525 - SentinelAgent - WARNING - New driver: NetAdapterCx
2025-11-28 00:56:27,525 - SentinelAgent - WARNING - New driver: avgArDisk
2025-11-28 00:56:27,525 - SentinelAgent - WARNING - New driver: circlass
2025-11-28 00:56:27,528 - SentinelAgent - WARNING - New driver: msisadrv
2025-11-28 00:56:27,528 - SentinelAgent - WARNING - New driver: WUDFWpdFs
2025-11-28 00:56:27,529 - SentinelAgent - WARNING - New driver: iaLPSS2i_GPIO2
2025-11-28 00:56:27,529 - SentinelAgent - WARNING - New driver: hvservice
2025-11-28 00:56:27,529 - SentinelAgent - WARNING - New driver: VMSVSF
2025-11-28 00:56:27,530 - SentinelAgent - WARNING - New driver: Ufx01000
2025-11-28 00:56:27,530 - SentinelAgent - WARNING - New driver: hidspi
2025-11-28 00:56:27,530 - SentinelAgent - WARNING - New driver: QWAVEdrv
2025-11-28 00:56:27,530 - SentinelAgent - WARNING - New driver: vmgid
2025-11-28 00:56:27,530 - SentinelAgent - WARNING - New driver: isapnp
2025-11-28 00:56:27,532 - SentinelAgent - WARNING - New driver: mpi3drvi
2025-11-28 00:56:27,532 - SentinelAgent - WARNING - New driver: HDAudBus
2025-11-28 00:56:27,532 - SentinelAgent - WARNING - New driver: CDD
2025-11-28 00:56:27,537 - SentinelAgent - WARNING - New driver: udfs
2025-11-28 00:56:27,541 - SentinelAgent - WARNING - New driver: srv2
2025-11-28 00:56:27,544 - SentinelAgent - WARNING - New driver: BthPan
2025-11-28 00:56:27,548 - SentinelAgent - WARNING - New driver: ebdrv0
2025-11-28 00:56:27,560 - SentinelAgent - WARNING - New driver: rspndr
2025-11-28 00:56:27,564 - SentinelAgent - WARNING - New driver: flpydisk
2025-11-28 00:56:27,568 - SentinelAgent - WARNING - New driver: MsRPC
2025-11-28 00:56:27,572 - SentinelAgent - WARNING - New driver: kbdhid
2025-11-28 00:56:27,574 - SentinelAgent - WARNING - New driver: BTHPORT
2025-11-28 00:56:27,578 - SentinelAgent - WARNING - New driver: mouclass
2025-11-28 00:56:27,579 - SentinelAgent - WARNING - New driver: UfxChipidea
2025-11-28 00:56:27,580 - SentinelAgent - WARNING - New driver: scmbus
2025-11-28 00:56:27,584 - SentinelAgent - WARNING - New driver: vhf
2025-11-28 00:56:27,588 - SentinelAgent - WARNING - New driver: WpdUpFltr
2025-11-28 00:56:27,589 - SentinelAgent - WARNING - New driver: xinputhid
2025-11-28 00:56:27,591 - SentinelAgent - WARNING - New driver: avgbuniv
2025-11-28 00:56:27,594 - SentinelAgent - WARNING - New driver: Tcpip
2025-11-28 00:56:27,595 - SentinelAgent - WARNING - New driver: wini3ctarget
2025-11-28 00:56:27,600 - SentinelAgent - WARNING - New driver: Serial
2025-11-28 00:56:27,630 - SentinelAgent - WARNING - New driver: pciide
2025-11-28 00:56:27,638 - SentinelAgent - WARNING - New driver: WinNat
2025-11-28 00:56:27,645 - SentinelAgent - WARNING - New driver: VMSNPXY
2025-11-28 00:56:27,654 - SentinelAgent - WARNING - New driver: AFD
2025-11-28 00:56:27,663 - SentinelAgent - WARNING - New driver: avgRdr
2025-11-28 00:56:27,664 - SentinelAgent - WARNING - New driver: vmbusproxy
2025-11-28 00:56:27,664 - SentinelAgent - WARNING - New driver: cht4iscsi
2025-11-28 00:56:27,664 - SentinelAgent - WARNING - New driver: iaStorAVC
2025-11-28 00:56:27,665 - SentinelAgent - WARNING - New driver: rdbss
2025-11-28 00:56:27,665 - SentinelAgent - WARNING - New driver: atapi
2025-11-28 00:56:27,666 - SentinelAgent - WARNING - New driver: mlx4_bus
2025-11-28 00:56:27,666 - SentinelAgent - WARNING - New driver: ws2ifsl
2025-11-28 00:56:27,666 - SentinelAgent - WARNING - New driver: SerCx
2025-11-28 00:56:27,667 - SentinelAgent - WARNING - New driver: mshidkmdf
2025-11-28 00:56:27,667 - SentinelAgent - WARNING - New driver: IPMIDRV
2025-11-28 00:56:27,667 - SentinelAgent - WARNING - New driver: googledrivefs31931
2025-11-28 00:56:27,668 - SentinelAgent - WARNING - New driver: NDKPerf
2025-11-28 00:56:27,668 - SentinelAgent - WARNING - New driver: nvdimm
2025-11-28 00:56:27,668 - SentinelAgent - WARNING - New driver: Hsp
2025-11-28 00:56:27,669 - SentinelAgent - WARNING - New driver: WudfPf
2025-11-28 00:56:27,669 - SentinelAgent - WARNING - New driver: iaLPSS2_I2C_ADL
2025-11-28 00:56:27,669 - SentinelAgent - WARNING - New driver: RDPDR
2025-11-28 00:56:27,670 - SentinelAgent - WARNING - New driver: 3ware
2025-11-28 00:56:27,670 - SentinelAgent - WARNING - New driver: usbhub
2025-11-28 00:56:27,670 - SentinelAgent - WARNING - New driver: Ntfs
2025-11-28 00:56:27,670 - SentinelAgent - WARNING - New driver: applockerfltr
2025-11-28 00:56:27,671 - SentinelAgent - WARNING - New driver: volume
2025-11-28 00:56:27,671 - SentinelAgent - WARNING - New driver: avgKbd
2025-11-28 00:56:27,678 - SentinelAgent - WARNING - New driver: FileCrypt
2025-11-28 00:56:27,693 - SentinelAgent - WARNING - New driver: nvmedisk
2025-11-28 00:56:27,698 - SentinelAgent - WARNING - New driver: Ndisuio
2025-11-28 00:56:27,700 - SentinelAgent - WARNING - New driver: MRxDAV
2025-11-28 00:56:27,702 - SentinelAgent - WARNING - New driver: PNPMEM
2025-11-28 00:56:27,706 - SentinelAgent - WARNING - New driver: avgElam
2025-11-28 00:56:27,713 - SentinelAgent - WARNING - New driver: ufxsynopsys
2025-11-28 00:56:27,713 - SentinelAgent - WARNING - New driver: megasas35i
2025-11-28 00:56:27,714 - SentinelAgent - WARNING - New driver: MMCSS
2025-11-28 00:56:27,716 - SentinelAgent - WARNING - New driver: AcpiAudioCompositorInbox
2025-11-28 00:56:27,716 - SentinelAgent - WARNING - New driver: WdmCompanionFilter
2025-11-28 00:56:27,717 - SentinelAgent - WARNING - New driver: Parport
2025-11-28 00:56:27,717 - SentinelAgent - WARNING - New driver: NdisCap
2025-11-28 00:56:27,718 - SentinelAgent - WARNING - New driver: storflt
2025-11-28 00:56:27,718 - SentinelAgent - WARNING - New driver: CmBatt
2025-11-28 00:56:27,718 - SentinelAgent - WARNING - New driver: WdBoot
2025-11-28 00:56:27,719 - SentinelAgent - WARNING - New driver: scfilter
2025-11-28 00:56:27,720 - SentinelAgent - WARNING - New driver: HidSpiCx
2025-11-28 00:56:27,722 - SentinelAgent - WARNING - New driver: iai2c
2025-11-28 00:56:27,722 - SentinelAgent - WARNING - New driver: PktMon
2025-11-28 00:56:27,723 - SentinelAgent - WARNING - New driver: iaLPSS2i_GPIO2_CNL
2025-11-28 00:56:27,723 - SentinelAgent - WARNING - New driver: vmbusr
2025-11-28 00:56:27,723 - SentinelAgent - WARNING - New driver: nvvad_WaveExtensible
2025-11-28 00:56:27,723 - SentinelAgent - WARNING - New driver: WmiAcpi
2025-11-28 00:56:27,723 - SentinelAgent - WARNING - New driver: npsvctrig
2025-11-28 00:56:27,724 - SentinelAgent - WARNING - New driver: Vid
2025-11-28 00:56:27,724 - SentinelAgent - WARNING - New driver: VfpExt
2025-11-28 00:56:27,724 - SentinelAgent - WARNING - New driver: sfloppy
2025-11-28 00:56:27,724 - SentinelAgent - WARNING - New driver: mausbhost
2025-11-28 00:56:27,724 - SentinelAgent - WARNING - New driver: fse
2025-11-28 00:56:27,726 - SentinelAgent - WARNING - New driver: nvraid
2025-11-28 00:56:27,726 - SentinelAgent - WARNING - New driver: iorate
2025-11-28 00:56:27,726 - SentinelAgent - WARNING - New driver: megasr
2025-11-28 00:56:27,726 - SentinelAgent - WARNING - New driver: hidi2c
2025-11-28 00:56:27,727 - SentinelAgent - WARNING - New driver: FileInfo
2025-11-28 00:56:27,727 - SentinelAgent - WARNING - New driver: pci
2025-11-28 00:56:27,728 - SentinelAgent - WARNING - New driver: xboxgip
2025-11-28 00:56:27,728 - SentinelAgent - WARNING - New driver: tdx
2025-11-28 00:56:27,728 - SentinelAgent - WARNING - New driver: UnionFS
2025-11-28 00:56:27,729 - SentinelAgent - WARNING - New driver: RasAgileVpn
2025-11-28 00:56:27,729 - SentinelAgent - WARNING - New driver: Psched
2025-11-28 00:56:27,729 - SentinelAgent - WARNING - New driver: storqosflt
2025-11-28 00:56:27,729 - SentinelAgent - WARNING - New driver: cdrom
2025-11-28 00:56:27,730 - SentinelAgent - WARNING - New driver: usbvideo
2025-11-28 00:56:27,730 - SentinelAgent - WARNING - New driver: s3cap
2025-11-28 00:56:27,730 - SentinelAgent - WARNING - New driver: Acx01000
2025-11-28 00:56:27,730 - SentinelAgent - WARNING - New driver: pvscsi
2025-11-28 00:56:27,731 - SentinelAgent - WARNING - New driver: acpitime
2025-11-28 00:56:27,731 - SentinelAgent - WARNING - New driver: msgpiowin32
2025-11-28 00:56:27,732 - SentinelAgent - WARNING - New driver: UEFI
2025-11-28 00:56:27,732 - SentinelAgent - WARNING - New driver: HTTP
2025-11-28 00:56:27,732 - SentinelAgent - WARNING - New driver: avgVmm
2025-11-28 00:56:27,732 - SentinelAgent - WARNING - New driver: sdbus
2025-11-28 00:56:27,733 - SentinelAgent - WARNING - New driver: uiomap
2025-11-28 00:56:27,733 - SentinelAgent - WARNING - New driver: storvsp
2025-11-28 00:56:27,733 - SentinelAgent - WARNING - New driver: WinAccelCx0101
2025-11-28 00:56:27,733 - SentinelAgent - WARNING - New driver: FltMgr
2025-11-28 00:56:27,733 - SentinelAgent - WARNING - New driver: avgArPot
2025-11-28 00:56:27,734 - SentinelAgent - WARNING - New driver: dam
2025-11-28 00:56:27,736 - SentinelAgent - WARNING - New driver: 1394ohci
2025-11-28 00:56:27,736 - SentinelAgent - WARNING - New driver: USBSTOR
2025-11-28 00:56:27,736 - SentinelAgent - WARNING - New driver: CompositeBus
2025-11-28 00:56:27,736 - SentinelAgent - WARNING - New driver: MsQuicPrev
2025-11-28 00:56:27,736 - SentinelAgent - WARNING - New driver: ndfltr
2025-11-28 00:56:27,736 - SentinelAgent - WARNING - New driver: iaLPSS2i_GPIO2_BXT_P
2025-11-28 00:56:27,738 - SentinelAgent - WARNING - New driver: CldFlt
2025-11-28 00:56:27,738 - SentinelAgent - WARNING - New driver: PktMonApi
2025-11-28 00:56:27,738 - SentinelAgent - WARNING - New driver: vpcivsp
2025-11-28 00:56:27,738 - SentinelAgent - WARNING - New driver: mrxsmb20
2025-11-28 00:56:27,738 - SentinelAgent - WARNING - New driver: kdnic
2025-11-28 00:56:27,738 - SentinelAgent - WARNING - New driver: usbccgp
2025-11-28 00:56:27,739 - SentinelAgent - WARNING - New driver: condrv
2025-11-28 00:56:27,740 - SentinelAgent - WARNING - New driver: WinFsp
2025-11-28 00:56:27,740 - SentinelAgent - WARNING - New driver: avgSP
2025-11-28 00:56:27,740 - SentinelAgent - WARNING - New driver: SiSRaid2
2025-11-28 00:56:27,740 - SentinelAgent - WARNING - New driver: bfs
2025-11-28 00:56:27,740 - SentinelAgent - WARNING - New driver: BthA2dp
2025-11-28 00:56:27,740 - SentinelAgent - WARNING - New driver: usbaudio2
2025-11-28 00:56:27,740 - SentinelAgent - WARNING - New driver: rdyboost
2025-11-28 00:56:27,742 - SentinelAgent - WARNING - New driver: ssudmdm
2025-11-28 00:56:27,742 - SentinelAgent - WARNING - New driver: iaLPSS2i_I2C_GLK
2025-11-28 00:56:27,742 - SentinelAgent - WARNING - New driver: LSI_SAS2i
2025-11-28 00:56:27,742 - SentinelAgent - WARNING - New driver: megasas2i
2025-11-28 00:56:27,742 - SentinelAgent - WARNING - New driver: EhStorClass
2025-11-28 00:56:27,743 - SentinelAgent - WARNING - New driver: Rasl2tp
2025-11-28 00:56:27,743 - SentinelAgent - WARNING - New driver: ndproxy
2025-11-28 00:56:27,743 - SentinelAgent - WARNING - New driver: hvsocketcontrol
2025-11-28 00:56:27,743 - SentinelAgent - WARNING - New driver: iaLPSSi_GPIO
2025-11-28 00:56:27,744 - SentinelAgent - WARNING - New driver: UcmTcpciCx0101
2025-11-28 00:56:27,745 - SentinelAgent - WARNING - New driver: NdisWan
2025-11-28 00:56:27,745 - SentinelAgent - WARNING - New driver: AcpiDev
2025-11-28 00:56:27,745 - SentinelAgent - WARNING - New driver: CAD
2025-11-28 00:56:27,745 - SentinelAgent - WARNING - New driver: hyperkbd
2025-11-28 00:56:27,746 - SentinelAgent - WARNING - New driver: BthLEEnum
2025-11-28 00:56:27,746 - SentinelAgent - WARNING - New driver: volmgr
2025-11-28 00:56:27,747 - SentinelAgent - WARNING - New driver: storahci
2025-11-28 00:56:27,747 - SentinelAgent - WARNING - New driver: LSI_SAS3i
2025-11-28 00:56:27,748 - SentinelAgent - WARNING - New driver: NdisImPlatform
2025-11-28 00:56:27,749 - SentinelAgent - WARNING - New driver: UmPass
2025-11-28 00:56:27,749 - SentinelAgent - WARNING - New driver: storufs
2025-11-28 00:56:27,749 - SentinelAgent - WARNING - New driver: GPIOClx0101
2025-11-28 00:56:27,751 - SentinelAgent - WARNING - New driver: TsUsbFlt
2025-11-28 00:56:27,751 - SentinelAgent - WARNING - New driver: iaLPSS2i_I2C_CNL
2025-11-28 00:56:27,752 - SentinelAgent - WARNING - New driver: ExecutionContext
2025-11-28 00:56:27,752 - SentinelAgent - WARNING - New driver: HidBatt
2025-11-28 00:56:27,752 - SentinelAgent - WARNING - New driver: vhdmp
2025-11-28 00:56:27,752 - SentinelAgent - WARNING - New driver: percsas2i
2025-11-28 00:56:27,752 - SentinelAgent - WARNING - New driver: asstahci64
2025-11-28 00:56:27,753 - SentinelAgent - WARNING - New driver: UrsCx01000
2025-11-28 00:56:27,753 - SentinelAgent - WARNING - New driver: ebdrv
2025-11-28 00:56:27,753 - SentinelAgent - WARNING - New driver: Processor
2025-11-28 00:56:27,754 - SentinelAgent - WARNING - New driver: BthHFAud
2025-11-28 00:56:27,754 - SentinelAgent - WARNING - New driver: HwNClx0101
2025-11-28 00:56:27,755 - SentinelAgent - WARNING - New driver: NativeWifiP
2025-11-28 00:56:27,755 - SentinelAgent - WARNING - New driver: Serenum
2025-11-28 00:56:27,756 - SentinelAgent - WARNING - New driver: HdAudAddService
2025-11-28 00:56:27,756 - SentinelAgent - WARNING - New driver: kbdclass
2025-11-28 00:56:27,757 - SentinelAgent - WARNING - New driver: vdrvroot
2025-11-28 00:56:27,758 - SentinelAgent - WARNING - New driver: VMSVSP
2025-11-28 00:56:27,758 - SentinelAgent - WARNING - New driver: ahcache
2025-11-28 00:56:52,872 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:57:31,462 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:58:07,591 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:58:42,615 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
Exception in thread Thread-743 (_readerthread):
Traceback (most recent call last):
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 1045, in _bootstrap_inner
    self.run()
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 982, in run
    self._target(*self._args, **self._kwargs)
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\subprocess.py", line 1599, in _readerthread
    buffer.append(fh.read())
                  ^^^^^^^^^
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\encodings\cp1252.py", line 23, in decode
    return codecs.charmap_decode(input,self.errors,decoding_table)[0]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
UnicodeDecodeError: 'charmap' codec can't decode byte 0x81 in position 148: character maps to <undefined>
2025-11-28 00:59:18,822 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 00:59:55,710 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 01:00:32,143 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 01:01:09,832 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 01:01:45,101 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 01:02:23,031 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
Exception in thread Thread-841 (_readerthread):
Traceback (most recent call last):
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 1045, in _bootstrap_inner
    self.run()
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 982, in run
    self._target(*self._args, **self._kwargs)
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\subprocess.py", line 1599, in _readerthread
    buffer.append(fh.read())
                  ^^^^^^^^^
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\encodings\cp1252.py", line 23, in decode
    return codecs.charmap_decode(input,self.errors,decoding_table)[0]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
UnicodeDecodeError: 'charmap' codec can't decode byte 0x81 in position 148: character maps to <undefined>
2025-11-28 01:02:58,164 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 01:03:33,377 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
Exception in thread Thread-865 (_readerthread):
Traceback (most recent call last):
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 1045, in _bootstrap_inner
    self.run()
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\threading.py", line 982, in run
    self._target(*self._args, **self._kwargs)
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\subprocess.py", line 1599, in _readerthread
    buffer.append(fh.read())
                  ^^^^^^^^^
  File "C:\Users\markv\AppData\Local\Programs\Python\Python311\Lib\encodings\cp1252.py", line 23, in decode
    return codecs.charmap_decode(input,self.errors,decoding_table)[0]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
UnicodeDecodeError: 'charmap' codec can't decode byte 0x81 in position 148: character maps to <undefined>
2025-11-28 01:04:13,012 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 01:04:48,064 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 01:05:23,388 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 01:05:50,486 - SentinelAgent - WARNING - Suspicious DLL: c:\users\markv\appdata\local\perplexity\comet\application\142.1.7444.29693\chrome.dll in comet.exe
2025-11-28 01:05:57,754 - SentinelAgent - WARNING - Suspicious DLL: c:\users\markv\appdata\local\perplexity\comet\application\142.1.7444.29693\chrome.dll in comet.exe
2025-11-28 01:05:57,755 - SentinelAgent - WARNING - Suspicious DLL: c:\users\markv\appdata\local\perplexity\comet\application\142.1.7444.29693\chrome_elf.dll in comet.exe
2025-11-28 01:05:58,952 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)
2025-11-28 01:06:34,054 - SentinelAgent - WARNING - Dashboard not reachable: HTTPConnectionPool(host='localhost', port=8015): Read timed out. (read timeout=5)