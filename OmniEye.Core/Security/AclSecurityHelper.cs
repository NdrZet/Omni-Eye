using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace OmniEye.Core.Security;

/// <summary>
/// Hardens the OmniEye storage directory using NTFS Access Control Lists (ACL).
/// SYSTEM & Administrators: Full Control.
/// Users: Read & Execute only.
/// </summary>
public static class AclSecurityHelper
{
    public static bool EnsureHardenedDirectory(string directoryPath, bool developerMode, out string message)
    {
        try
        {
            if (!Directory.Exists(directoryPath))
            {
                Directory.CreateDirectory(directoryPath);
            }

            if (developerMode)
            {
                // In Developer Mode, ensure the directory exists and current process has full read/write access
                message = "Directory ready in Developer Mode (unrestricted permissions for development/testing).";
                return true;
            }

            var dirInfo = new DirectoryInfo(directoryPath);
            var security = new DirectorySecurity();

            // Disable inheritance and preserve existing rules for conversion
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

            var inheritanceFlags = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            var propagationFlags = PropagationFlags.None;

            // SYSTEM: FullControl
            security.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                inheritanceFlags,
                propagationFlags,
                AccessControlType.Allow));

            // Administrators: FullControl
            security.AddAccessRule(new FileSystemAccessRule(
                adminsSid,
                FileSystemRights.FullControl,
                inheritanceFlags,
                propagationFlags,
                AccessControlType.Allow));

            // Users: ReadAndExecute
            security.AddAccessRule(new FileSystemAccessRule(
                usersSid,
                FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
                inheritanceFlags,
                propagationFlags,
                AccessControlType.Allow));

            dirInfo.SetAccessControl(security);
            message = "Directory ACL successfully hardened.";
            return true;
        }
        catch (UnauthorizedAccessException ex)
        {
            message = $"Access denied setting directory ACL (run as Administrator/SYSTEM): {ex.Message}";
            return false;
        }
        catch (Exception ex)
        {
            message = $"Failed to set directory ACL: {ex.Message}";
            return false;
        }
    }
}
