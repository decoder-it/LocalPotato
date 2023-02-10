# LocalPotato
Another Local Windows privilege escalation using a new potato technique ;)

The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege. 

More technical details at --> https://www.localpotato.com

## Usage

```

         LocalPotato (aka CVE-2023-21746)
         by splinter_code & decoder_it


Mandatory Args:
-i Source file to copy
-o Output file - do not specify the drive letter
Example: localpotato -i c:\hacker\evil.dll -o windows\system32\evil.dll

Optional Args:
-c CLSID (Default {854A20FB-2D44-457D-992F-EF13785D2B51})
-p COM server port (Default 10271)
```

## Demo

![image](https://user-images.githubusercontent.com/19797064/218135881-af046286-c299-4f08-856b-2265adc46e64.png)


## Authors: 
- [@decoder_it](https://twitter.com/decoder_it)
- [@splinter_code](https://twitter.com/splinter_code)
