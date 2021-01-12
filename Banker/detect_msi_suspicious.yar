rule suspicious_msi_file
{
   meta:
      author = "Johnk3r"
      description= "Detects common strings and dlls in Banker_BR"
   strings:

        //Common Banker_BR STRINGS
      $s0 = "Advanced Installer" wide ascii nocase
      $s1 = ".pdb" wide ascii nocase
      $s2 = "FilesInZip=zipzipp" wide ascii nocase
      $s3 = "ShellExecuteExW" wide ascii nocase

        //Common Banker_BR PE
      $p0 = "msi.dll" wide ascii nocase
      $p1 = "aicustact.dll" wide ascii nocase
      $p2 = "vmdetect.exe" wide ascii nocase
      $p3 = "jli.dll" wide ascii nocase

        //Common Banker_BR API
      $a0 = "EnumWindows"
      $a1 = "GetDesktopWindow"
   condition:
      2 of ($s*) and 2 of ($p*) and 2 of ($a*)
}
