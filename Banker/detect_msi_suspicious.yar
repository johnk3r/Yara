rule suspicious_msi_file
{
   meta:
      author = "Johnk3r"
      description= "Detects common strings, DLL and API in Banker_BR"
      hash1 = "f0df269cb88a5ea4461b54dcd36bb8daa66360b1735bb5c0c2f5ce23d91e0260"
      hash2 = "2b202d0e33047819ee2ece05ea92b00d4cd84aa32ec288764f4789660ea31b37"

   strings:

        //Common Banker_BR strings
      $s0 = "Advanced Installer" wide ascii nocase      //Packing MSI
      $s1 = "AICustAct.pdb" wide ascii nocase           //Debug file
      $s3 = "coriuadwqe32" wide ascii nocase            //String of an Author.

        //Common Banker_BR PE
      $p0 = "msi.dll" wide ascii nocase                 //Safe DLL used for malicious actions
      $p1 = "aicustact.dll" wide ascii nocase           //Checking internet connectivity
      $p2 = "vmdetect.exe" wide ascii nocase            //Detect sandbox
      $p3 = "jli.dll" wide ascii nocase                 //Malicious DLL
      $p4 = "ws3r3.dll" wide ascii nocase               //Malicious DLL
      $p5 = "luiz.dll" wide ascii nocase                //Malicious DLL

        //Common Banker_BR API
      $a0 = "EnumWindows"                               //Enumerates all top-level windows on the screen
      $a1 = "GetDesktopWindow"                          //Retrieves a handle to the desktop window
      $a2 = "GetForegroundWindow"                       //Retrieves a handle to the foreground window (the window with which the user is currently working)
      $a3 = "EnumChildWindows"                          //Enumerates the child windows that belong to the specified parent window

   condition:
      2 of ($s*) and 3 of ($p*) and 3 of ($a*)
}
