rule detect_possible_phishing : Amavaldo
{
    meta:
        description = "Test rule for phishing detection"
        author = "Johnk3r"

    strings:
        $subject1 = "Fwd:" nocase
        $subject2 = "0rcamento" nocase
        $subject3 = "Estamos enviando todas suas fatures em atraso" nocase

        $domain1 = "amazonaws.com" nocase
        $domain2 = "azure.com" nocase

        $body1 = ".pdf" 

    condition:
       1 of ($subject*) and 1 of ($domain*) and 1 of ($body*)
}
