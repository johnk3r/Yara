rule suspicious_msi_file : Amavaldo
{
   meta:
      author = "Johnk3r"
      date = "08102020"
   strings:
      $s0 = "Advanced Installer" wide ascii nocase
      $s1 = "\\custact\\x86\\AICustAct.pdb" wide ascii nocase
      $s2 = "FilesInZip=zipzipp" wide ascii nocase
   condition:
      2 of them
}
