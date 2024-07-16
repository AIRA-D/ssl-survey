#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>

#define HOSTNAME_MAX_LEN 256

void print_supported_algorithms(SSL *ssl) {
    printf("Используемые алгоритмы шифрования: ");
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        printf("%s\n", SSL_CIPHER_get_name(cipher));
    } else {
        printf("(NONE)\n");
    }
}
void print_certificate_key_length(SSL *ssl) {
    printf("Используемая длина ключа в сертификатах: ");
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        EVP_PKEY *pkey = X509_get_pubkey(cert);
        if (pkey) {
            int key_length = EVP_PKEY_bits(pkey);
            printf("%d\n", key_length);
            EVP_PKEY_free(pkey);
        } else {
            printf("0 (Ошибка получения ключа)\n");
        }
        X509_free(cert);
    } else {
        printf("0 (Ошибка получения сертификата)\n");
    }
}
void print_tls_versions(SSL *ssl) {
    long max_version = SSL_get_max_proto_version(ssl);
    long min_version = SSL_get_min_proto_version(ssl);

    printf("Максимальная поддерживаемая версия TLS: ");
    if (max_version == TLS1_3_VERSION) {
        printf("TLSv1.3\n");
    } else if (max_version == TLS1_2_VERSION) {
        printf("TLSv1.2\n");
    } else if (max_version == TLS1_1_VERSION) {
        printf("TLSv1.1\n");
    } else if (max_version == TLS1_VERSION) {
        printf("TLSv1\n");
    } else {
        printf("(NONE)\n");
    }

    printf("Минимальная поддерживаемая версия TLS: ");
    if (min_version == TLS1_3_VERSION) {
        printf("TLSv1.3\n");
    } else if (min_version == TLS1_2_VERSION) {
        printf("TLSv1.2\n");
    } else if (min_version == TLS1_1_VERSION) {
        printf("TLSv1.1\n");
    } else if (min_version == TLS1_VERSION) {
        printf("TLSv1\n");
    } else {
        printf("(NONE)n");
    }

}
void process_hostname(const char *url, FILE *output) {

    char hostname[HOSTNAME_MAX_LEN];
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    if (sscanf(url, "https://%[^/]", hostname) != 1) {
        fprintf(stderr, "Неверный задан URL: %s\n", url);
    }
    printf("[ Сканирование %s ]\n", url);

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
    server_addr.sin_port = htons(443);
    memcpy(&server_addr.sin_addr, he -> h_addr, he -> h_length);

    if (connect(sockfd, (struct sockaddr*) & server_addr, sizeof(server_addr)) == -1) {
        perror("connect() error\n");
        close(sockfd);
        goto ssl_end;
    }

    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(sockfd);
        goto ssl_end;
    }
    
    SSL_shutdown(ssl);
    close(sockfd);
    goto ssl_end;

    ssl_end:
        SSL_free(ssl);
        SSL_CTX_free(ctx);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-f <file>] [-o <output_file>] [<hostname1> <hostname2> ...]\n", argv[0]);
        return 1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    char *output_filename = NULL;
    char *input_filename = NULL;
    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            input_filename = argv[i + 1];
            i += 2;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_filename = argv[i + 1];
            i += 2;
        } else {
            fprintf(stderr, "Неверный параметр: %s\n", argv[i]);
            return 1;
        }
    }

    FILE *output = stdout;
    if (output_filename) {
        output = fopen(output_filename, "w");
        if (!output) {
            perror("Ошибка открытия выходного файла");
            return 1;
        }
    }

    if (input_filename) {
        FILE *input = fopen(input_filename, "r");
        if (!input) {
            perror("Ошибка открытия входного файла");
            return 1;
        }
        char hostname[256];
        while (fscanf(input, "%s", hostname) != EOF) {
            process_hostname(hostname, output);
        }
        fclose(input);
    } else {
        for (; i < argc; i++) {
            const char *hostname = argv[i];
            process_hostname(hostname, output);
        }
    }

    if (output_filename) {
        fclose(output);
    }

    return 0;
}
