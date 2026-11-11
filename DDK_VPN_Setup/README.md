# DDK VPN Setup v4

Double-click `DDK_VPN_Setup.exe` to run the setup. Windows will ask for
Administrator permission, and the setup will then continue in a console window.

Keep these four runtime files together in the same folder:

- `DDK_VPN_Setup.exe`
- `DDK_VPN_Test.ps1`
- `DDK_IE_Mode_Sites.xml`
- `anyconnect-win-4.10.05085-core-vpn-predeploy-k9.msi`

To rebuild the launcher, run:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Build-DDK-VPN-Launcher.ps1
```
