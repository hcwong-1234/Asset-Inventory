[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$outputPath = Join-Path $PSScriptRoot "DDK_VPN_Setup.exe"

$source = @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Principal;

internal static class Program
{
    private const string ElevatedArgument = "--elevated";
    private const string ScriptName = "DDK_VPN_Test.ps1";

    private static bool IsAdministrator()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    private static int Main(string[] args)
    {
        string executablePath = Assembly.GetExecutingAssembly().Location;

        if (!IsAdministrator())
        {
            try
            {
                ProcessStartInfo elevated = new ProcessStartInfo();
                elevated.FileName = executablePath;
                elevated.Arguments = ElevatedArgument;
                elevated.Verb = "runas";
                elevated.UseShellExecute = true;

                Process.Start(elevated);
                return 0;
            }
            catch (Win32Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Administrator access was not granted.");
                Console.ResetColor();
                Console.WriteLine(ex.Message);
                Console.WriteLine();
                Console.Write("Press ENTER to close.");
                Console.ReadLine();
                return 1;
            }
        }

        string applicationDirectory = Path.GetDirectoryName(executablePath);
        string scriptPath = Path.Combine(applicationDirectory, ScriptName);

        if (!File.Exists(scriptPath))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Required script not found:");
            Console.WriteLine(scriptPath);
            Console.ResetColor();
            Console.WriteLine();
            Console.WriteLine("Keep the EXE, PowerShell script, MSI, and XML in the same folder.");
            Console.Write("Press ENTER to close.");
            Console.ReadLine();
            return 2;
        }

        string windowsPowerShell = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"WindowsPowerShell\v1.0\powershell.exe"
        );

        ProcessStartInfo script = new ProcessStartInfo();
        script.FileName = windowsPowerShell;
        script.Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -File \"" + scriptPath + "\"";
        script.UseShellExecute = false;

        try
        {
            using (Process process = Process.Start(script))
            {
                process.WaitForExit();
                return process.ExitCode;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Could not start the DDK VPN setup script.");
            Console.ResetColor();
            Console.WriteLine(ex.Message);
            Console.WriteLine();
            Console.Write("Press ENTER to close.");
            Console.ReadLine();
            return 3;
        }
    }
}
'@

if (Test-Path -LiteralPath $outputPath) {
    Remove-Item -LiteralPath $outputPath -Force
}

Add-Type `
    -TypeDefinition $source `
    -Language CSharp `
    -OutputAssembly $outputPath `
    -OutputType ConsoleApplication

Write-Host "Built successfully:" -ForegroundColor Green
Write-Host $outputPath

