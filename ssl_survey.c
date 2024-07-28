#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <getopt.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#define HOSTNAME_MAX_LEN 256
#define HTTPS_PORT 443
#define HEARTBEAT_TIMEOUT_SEC 5

typedef struct {
    char *input_filename;
    char *output_filename;
    int verbose;
} Options;

void parse_options(int argc, char *argv[], Options *options) {
    static struct option long_options[] = {
            {"input", required_argument, 0, 'f'},
            {"output", required_argument, 0, 'o'},
            {"help", no_argument, 0, 'h'},
            {0, 0 ,0 ,0},
    };
    int index;
    int c;

    while ((c = getopt_long(argc, argv, "f:o:h", long_options, &index)) != -1) {
        switch (c) {
            case 'f':
                options->input_filename = optarg;
                break;
            case 'o':
                options->output_filename = optarg;
                break;
            case 'h':
                fprintf(stderr, "Usage: %s [--input <file>] [--output <file>] [<hostname1> <hostname2> ...]\n", argv[0]);
                fprintf(stderr, "  --input, -f <file>      Input file with hostnames\n");
                fprintf(stderr, "  --output, -o <file>     Output file for results\n");
                fprintf(stderr, "  --help, -h              Show this help message\n");
                exit(0);
            default:
                fprintf(stderr, "Invalid option: %c\n", optopt);
                exit(1);
        }
    }
}
void print_supported_algorithms(SSL *ssl, FILE *output) {
    fprintf(output, "Используемые алгоритмы шифрования: ");
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        fprintf(output, "%s\n", SSL_CIPHER_get_name(cipher));
    } else {
        fprintf(output, "(NONE)\n");
    }
}
void print_certificate_key_length(SSL *ssl, FILE *output) {
    fprintf(output, "Используемая длина ключа в сертификатах: ");
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        EVP_PKEY *pkey = X509_get_pubkey(cert);
        if (pkey) {
            int key_length = EVP_PKEY_bits(pkey);
            fprintf(output, "%d\n", key_length);
            EVP_PKEY_free(pkey);
        } else {
            fprintf(output, "0 (Ошибка получения ключа)\n");
        }
        X509_free(cert);
    } else {
        fprintf(output, "0 (Ошибка получения сертификата)\n");
    }
}
void print_tls_versions(SSL *ssl, FILE *output) {
    long max_version = SSL_get_max_proto_version(ssl);
    long min_version = SSL_get_min_proto_version(ssl);

    fprintf(output, "Максимальная поддерживаемая версия TLS: ");
    if (max_version == TLS1_3_VERSION) {
        fprintf(output, "TLSv1.3\n");
    } else if (max_version == TLS1_2_VERSION) {
        fprintf(output, "TLSv1.2\n");
    } else if (max_version == TLS1_1_VERSION) {
        fprintf(output, "TLSv1.1\n");
    } else if (max_version == TLS1_VERSION) {
        fprintf(output, "TLSv1\n");
    } else {
        fprintf(output, "(NONE)\n");
    }

    fprintf(output, "Минимальная поддерживаемая версия TLS: ");
    if (min_version == TLS1_3_VERSION) {
        fprintf(output, "TLSv1.3\n");
    } else if (min_version == TLS1_2_VERSION) {
        fprintf(output, "TLSv1.2\n");
    } else if (min_version == TLS1_1_VERSION) {
        fprintf(output, "TLSv1.1\n");
    } else if (min_version == TLS1_VERSION) {
        fprintf(output, "TLSv1\n");
    } else {
        fprintf(output, "(NONE)n");
    }

}
int check_heartbleed(SSL *ssl, FILE *output) {
    int is_vulnerable = 0;

    if (SSL_get_version(ssl) == TLS1_VERSION || SSL_get_version(ssl) == TLS1_1_VERSION) {

        int bytes_written = SSL_write(ssl, "\x01\x00\x00\x03", 4);

        if (bytes_written == 4) {
            struct timeval timeout;
            timeout.tv_sec = HEARTBEAT_TIMEOUT_SEC;
            timeout.tv_usec = 0;

            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(SSL_get_fd(ssl), &readfds);

            int result = select(SSL_get_fd(ssl) + 1, &readfds, NULL, NULL, &timeout);

            if (result > 0) {
                char buffer[1024];
                int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
                if (bytes_read > 0) {
                    is_vulnerable = 1;
                    fprintf(output, "!! Сервер уязвим к атаке Heartbleed\n");
                } else {
                    fprintf(output, "!! Сервер ответил на Heartbeat, но не вернул данные (возможно, не уязвим)\n");
                }
            } else if (result == 0) {
                fprintf(output, "!! Сервер не ответил на Heartbeat (возможно, не уязвим)\n");
            } else if (errno == EINTR) {
                fprintf(output, "!! Ошибка при ожидании ответа Heartbeat (возможно, не уязвим)\n");
            }
        }
    } else {
        fprintf(output, "!! Сервер использует более новую версию TLS, не уязвимую к Heartbleed\n");
    }

    return is_vulnerable;
}
void process_hostname(const char *url, FILE *output) {

    if (strncmp(url, "https://", 8) != 0) {
        fprintf(stderr, "Неверный формат URL: %s\n", url);
        return;
    }

    char hostname[HOSTNAME_MAX_LEN + 1]; // +1 для символа '\0'
    memset(hostname, 0, sizeof(hostname));
    strncat(hostname, url + 8, HOSTNAME_MAX_LEN);

    if (strlen(hostname) >= HOSTNAME_MAX_LEN) {
        fprintf(stderr, "Ошибка: Слишком длинное имя хоста: %s\n", hostname);
        return;
    }

    hostname[HOSTNAME_MAX_LEN - 1] = '0'; 

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return;
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    if (sscanf(url, "https://%[^/]", hostname) != 1) {
        fprintf(stderr, "Неверный задан URL: %s\n", url);
        return;
    }

    fprintf(output, "[ %s ]\n", url);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        goto ssl_end;
    }

    struct hostent *he = gethostbyname(hostname);
    if (!he) {
        fprintf(stderr, "gethostbyname() error\n");
        goto ssl_end;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket() error\n");
        goto ssl_end;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(HTTPS_PORT);
    memcpy(&server_addr.sin_addr, he -> h_addr, he -> h_length);

    if (connect(sockfd, (struct sockaddr*) & server_addr, sizeof(server_addr)) == -1) {
        perror("connect() error\n");
        close(sockfd);
        goto ssl_end;
    }

    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(output, "!! Ошибка при установлении SSL-соединения\n");
        close(sockfd);
        goto ssl_end;
    }

    print_supported_algorithms(ssl, output);
    print_certificate_key_length(ssl, output);
    print_tls_versions(ssl, output);
    if (check_heartbleed(ssl, output)) {
        // Сервер уязвим
    } else {
        fprintf(output, "!! Сервер зашищен от Heartbleed\n");
    }

    SSL_shutdown(ssl);
    close(sockfd);

ssl_end:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

int main(int argc, char *argv[]) {
    Options  options = {0};
    parse_options(argc, argv, &options);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    FILE *output = stdout;
    if (options.output_filename) {
        output = fopen(options.output_filename, "w");
        if (!output) {
            perror("Ошибка открытия выходного файла");
            return 1;
        }
    }
    if (options.input_filename) {
        FILE *input = fopen(options.input_filename, "r");
        if (!input) {
            perror("Ошибка открытия входного файла");
            return 1;
        }
        char hostname[HOSTNAME_MAX_LEN + 1];
        int count = 0;
        int total = 0;

        while (fgets(hostname, sizeof(hostname), input) != NULL) {
            hostname[strcspn(hostname, "\n")] = 0;
            total++;
        }
        if (total == 0) {
            fprintf(stderr, "Ошибка: общее количество хостов равно 0\n");
            fclose(input);
            return 1;
        }

        rewind(input);

        while (fscanf(input, "%s", hostname) != EOF) {
            hostname[strcspn(hostname, "\n")] = 0;
            if (strlen(hostname) >= HOSTNAME_MAX_LEN) {
                fprintf(stderr, "Ошибка: Слишком длинное имя хоста: %s\n", hostname);
                continue;
            }
            count++;
            double percentage = (double)count * 100 / total;
            printf("[ Сканирование %s ] %.2lf%%\n", hostname, percentage);
            process_hostname(hostname, output);
        }
        fclose(input);
    } else {
        int count = 0;
        int total = argc - optind;
        for (int i = optind; i < argc; i++) {
            const char *hostname = argv[i];
            count++;
            printf("[ Сканирование %s ] %d%%\n", hostname, (count * 100) / total);
            process_hostname(hostname, output);
        }
    }

    if (options.output_filename) {
        fclose(output);
    }

    return 0;
}
