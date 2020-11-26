rule suspicious_msi_file : Amavaldo
{
   meta:
      author = "Johnk3r"
      description = "Test rule for detect suspicious MSI file"
   strings:
      $s0 = "Advanced Installer" wide ascii nocase
      $s1 = "\\custact\\x86\\AICustAct.pdb" wide ascii nocase
      $s2 = "FilesInZip=zipzipp" wide ascii nocase
   condition:
      3 of them
}
