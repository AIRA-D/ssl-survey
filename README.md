# ssl-survey

**Утилита, сканирующая SSL (HTTPS) серверы и выводящая статистику по используемым параметрам SSL:**.
- используемые алгоритмы шифрования;
- используемая длина ключа в сертификатах;
- максимальная поддерживаемая версия TLS;
- минимальная поддерживаемая версия TLS.

В качестве библиотеки для SSL/TLS-соединения используется OpenSSL.

------
## Использование

#### Компиляция
```bash
 gcc ssl_survey.c -o ssl_survey -lssl -lcrypto
```
или используйте файл `CMakeLists.txt`

----

#### Передача параметров

Список серверов задается либо через параметры командной строки, либо с помощью внешнего файла. 
- Указание серверов через параметры командной строки:
 ```
ssl_survey https://google.com https://vk.com https://dsr-corporation.com
 ```
- Указание серверов с помощью файла:
```
ssl_survey -f path/to/file/with/servers.txt
```
где `servers.txt` - файл с произвольным именем, каждая строка которого содержит сервер для проверки.

----
Вывод информации о каждом сервере может быть реализован как в терминал, так и в отдельный файл.
- Информация будет выведена в терминал
```
ssl_survey -f path/to/file/with/servers.txt
```
или 
```
ssl_survey https://google.com https://vk.com https://dsr-corporation.com
```
------
- Указание файла для вывода информации
```
ssl_survey -o path/to/report.txt https://google.com https://vk.com https://dsr-corporation.com
```
или
```
ssl_survey -f path/to/file/with/servers.txt -o path/to/report.txt
```

# ssl-survey

**A utility that scans SSL (HTTPS) servers and displays statistics on the SSL parameters used:**.
- encryption algorithms used;
- used key length in certificates;
- maximum supported TLS version;
- minimum supported TLS version.

OpenSSL is used as a library for SSL/TLS connection.

------
## Usage

#### Compilation
```bash
 gcc ssl_survey.c -o ssl_survey -lssl -lcrypto
```
or use the `CMakeLists.txt` file

----

#### Passing parameters

The list of servers is specified either via command line parameters or via an external file. 
- Specifying servers via command line parameters:
 ```
ssl_survey https://google.com https://vk.com https://dsr-corporation.com
 ```
- Specifying servers using a file:
```
ssl_survey -f path/to/file/with/servers.txt
```
where `servers.txt` is a file with an arbitrary name, each line of which contains a server to check.

----
Output of information about each server can be realized either in the terminal or in a separate file.
- The information will be output to the terminal
```
ssl_survey -f path/to/file/with/servers.txt
```
or 
```
ssl_survey https://google.com https://vk.com https://dsr-corporation.com
```
------
- Specifies the file to output the information
```
ssl_survey -o path/to/report.txt https://google.com https://vk.com https://dsr-corporation.com
```
or
```
ssl_survey -f path/to/file/with/servers.txt -o path/to/report.txt
```

