using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace OmniEye.Core.Security;

/// <summary>
/// Native P/Invoke methods for ntdll.dll and kernel32.dll used by OmniEye.
/// </summary>
public static class NtDllNative
{
    public const uint PROCESS_TERMINATE = 0x0001;
    public const uint PROCESS_SUSPEND_RESUME = 0x0800;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtResumeProcess(IntPtr processHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool QueryFullProcessImageName(
        IntPtr hProcess,
        int flags,
        [Out] StringBuilder lpExeName,
        ref int lpdwSize);

    /// <summary>
    /// Suspends all threads in the target process.
    /// </summary>
    public static bool SuspendProcess(int processId, out string? errorMessage)
    {
        errorMessage = null;
        var handle = OpenProcess(PROCESS_SUSPEND_RESUME, false, processId);
        if (handle == IntPtr.Zero)
        {
            var err = Marshal.GetLastWin32Error();
            if (err == 87)
            {
                errorMessage = $"Process {processId} has already exited (Win32 error 87).";
            }
            else
            {
                errorMessage = $"OpenProcess({processId}) failed with Win32 error {err}.";
            }
            return false;
        }

        try
        {
            var ntStatus = NtSuspendProcess(handle);
            if (ntStatus != 0)
            {
                errorMessage = $"NtSuspendProcess returned NTSTATUS 0x{ntStatus:X8}.";
                return false;
            }
            return true;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>
    /// Resumes all threads in the target process.
    /// </summary>
    public static bool ResumeProcess(int processId, out string? errorMessage)
    {
        errorMessage = null;
        var handle = OpenProcess(PROCESS_SUSPEND_RESUME, false, processId);
        if (handle == IntPtr.Zero)
        {
            var err = Marshal.GetLastWin32Error();
            errorMessage = $"OpenProcess({processId}) failed with Win32 error {err}.";
            return false;
        }

        try
        {
            var ntStatus = NtResumeProcess(handle);
            if (ntStatus != 0)
            {
                errorMessage = $"NtResumeProcess returned NTSTATUS 0x{ntStatus:X8}.";
                return false;
            }
            return true;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>
    /// Forcefully terminates the specified process.
    /// </summary>
    public static bool KillProcess(int processId, out string? errorMessage)
    {
        errorMessage = null;
        try
        {
            using var proc = Process.GetProcessById(processId);
            proc.Kill(entireProcessTree: true);
            return true;
        }
        catch (Exception ex)
        {
            // Fallback to Win32 TerminateProcess
            var handle = OpenProcess(PROCESS_TERMINATE, false, processId);
            if (handle != IntPtr.Zero)
            {
                try
                {
                    if (TerminateProcess(handle, 1))
                        return true;
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
            errorMessage = $"Failed to kill process {processId}: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Retrieves the full executable path for a process ID.
    /// </summary>
    public static string GetProcessExecutablePath(int processId)
    {
        try
        {
            using var proc = Process.GetProcessById(processId);
            var path = proc.MainModule?.FileName;
            if (!string.IsNullOrEmpty(path))
                return path;
        }
        catch
        {
            // Try QueryFullProcessImageName for elevated/system processes
        }

        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (handle != IntPtr.Zero)
        {
            try
            {
                var sb = new StringBuilder(1024);
                var size = sb.Capacity;
                if (QueryFullProcessImageName(handle, 0, sb, ref size))
                {
                    return sb.ToString();
                }
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        return $"[Unknown Process: {processId}]";
    }
}
