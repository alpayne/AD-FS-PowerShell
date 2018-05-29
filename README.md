# AD-FS-PowerShell
A collection of PowerShell scripts for AD FS administration tasks.

## RelyingPartyXML

This script exports and imports AD FS SAML relying party configurations to and from XML files. 
It serves as a backup/restore tool for relying party configs, and can be used to migrate configurations
from one AD FS farm to another. 

The script accepts two arguments: *-Import* or *-Export*, and a *FilePath*. The *FilePath* is a directory for exports, or a directory, file, or collection of files for imports.
