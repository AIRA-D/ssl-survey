# ssl-survey

**Утилита, сканирующая SSL (HTTPS) серверы и выводящая статистику по используемым параметрам SSL:**.
- используемые алгоритмы шифрования;
- используемая длина ключа в сертификатах;
- максимальная поддерживаемая версия TLS; (пока не реализовано)
- минимальная поддерживаемая версия TLS. ( пока не реализовано).

------
В качестве библиотеки для SSL/TLS-соединения используется OpenSSL.

Список серверов задается либо через параметры командной строки, либо с помощью внешнего файла. 
**Например:**
- Указание серверов через параметры командной строки:
 ```
ssl_survey https://google.com https://vk.com https://dsr-corporation.com
 ```
- Указание серверов с помощью файла: (пока не реализовано)
```
ssl_survey -f path/to/file/with/servers.txt
```
где `servers.txt` - файл с произвольным именем, каждая строка которого содержит сервер для проверки.


------
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
 ```
ssl_survey https://google.com https://vk.com https://dsr-corporation.com
 ```
- Specifying servers using a file: (not yet implemented)
```
ssl_survey -f path/to/file/with/servers.txt
```
where `servers.txt` is a file with an arbitrary name, with each line containing a server to check.

![Снимок экрана от 2024-07-15 09-39-48](https://github.com/user-attachments/assets/2e1de332-3a26-4860-896e-4526d9a579a9)

