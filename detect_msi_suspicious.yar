rule suspicious_msi_file
{
   meta:
      author = "Johnk3r"
      description= "Detects common strings and dlls in Banker_BR"
   strings:
      $s0 = "Advanced Installer" wide ascii nocase
      $s1 = "\\custact\\x86\\AICustAct.pdb" wide ascii nocase
      $s2 = "FilesInZip=zipzipp" wide ascii nocase
      $s3 = "ShellExecuteExW" wide ascii nocase
      $d0 = "msi.dll" wide ascii nocase
      $d1 = "ws2_32.dll" wide ascii nocase
      $d2 = "netapi32.dll" wide ascii nocase
      $d3 = "iphlpapi.dll" wide ascii nocase
   condition:
      3 of ($s*) and 3 of ($d*)
}
