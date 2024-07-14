#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>

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


int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <hostname> [hostname2] ...\n", argv[0]);
        return 1;
    }

//    char *hostname = argv[1];

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    for (int i = 1; i < argc; i++) {
        const char *hostname = argv[i];
        printf("[ Сканирование %s ]\n", hostname);

        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return 1;
        }

        struct hostent *he = gethostbyname(hostname);
        if (!he) {
            fprintf(stderr, "gethostbyname() error\n");
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return 1;
        }

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
            perror("socket() error\n");
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return 1;
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(443);
        memcpy(&server_addr.sin_addr, he -> h_addr, he->h_length);

        if (connect(sockfd, (struct sockaddr*) & server_addr, sizeof (server_addr)) == -1) {
            perror("connect() error\n");
            close(sockfd);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return 1;
        }

        SSL_set_fd(ssl, sockfd);
        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(sockfd);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return 1;
        }

        print_supported_algorithms(ssl);
        print_certificate_key_length(ssl);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        printf("\n");
    }

    SSL_CTX_free(ctx);
    return 0;
}
