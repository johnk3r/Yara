rule detect_suspicious_zip
{
    meta:
        description = "Detects embedded BAT file in the ZIP"
        author = "johnk3r"
        
    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file = ".bat"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_file
}
