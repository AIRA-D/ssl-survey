# ssl-survey

**C utility that scans SSL (HTTPS) servers and outputs statistics on SSL parameters used:**
- encryption algorithms used;
- used key length in certificates;
- maximum supported TLS version; ( not yet implemented)
- minimum supported TLS version. ( not yet implemented).

------
OpenSSL is used as a library for SSL/TLS connection.

The list of servers is specified either through command line parameters or using an external file. 
**For example:**
- Specifying servers via command line parameters:
 ``` ssl_survey https://google.com https://vk.com https://dsr-corporation.com ```
- Specifying servers using a file: (not yet implemented)
``` ssl_survey -f path/to/file/with/servers.txt ```
where `servers.txt` is a file with an arbitrary name, with each line containing a server to check.
