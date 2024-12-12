#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <srtp2/srtp.h>
#include <netdb.h>

#define RTSP_PORT 8554
#define RTP_PORT 12345
#define RTCP_PORT 12346
#define BUFFER_SIZE 1024

void debug_callback(const SSL *ssl, int where, int ret) {
    if (where & SSL_CB_HANDSHAKE_START) {
        std::cout << "[CLIENT] Handshake started..." << std::endl;
    } else if (where & SSL_CB_HANDSHAKE_DONE) {
        std::cout << "[CLIENT] Handshake done!" << std::endl;
    } else if (where & SSL_CB_ALERT) {
        std::cout << "[CLIENT] SSL alert: " << SSL_alert_type_string_long(ret) << ", " << SSL_alert_desc_string_long(ret) << std::endl;
    } else if (where & SSL_CB_LOOP) {
        std::cout << "[CLIENT] SSL state (" << SSL_state_string_long(ssl) << "): " << SSL_state_string(ssl) << std::endl;
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            std::cerr << "[CLIENT] SSL state (" << SSL_state_string_long(ssl) << "): failed" << std::endl;
            ERR_print_errors_fp(stderr);
        } else if (ret < 0) {
            std::cerr << "[CLIENT] SSL state (" << SSL_state_string_long(ssl) << "): error" << std::endl;
            ERR_print_errors_fp(stderr);
        }
    }
}

void initialize_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

SSL_CTX* create_dtls_client_context() {
    const SSL_METHOD* method = DTLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);

	SSL_CTX_set_info_callback(ctx, debug_callback);

    return ctx;
}

void configure_context(SSL_CTX* ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "/home/jay/project/rtsp/RaspberryPi-5-RTSP-Server/c_key/client.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "/home/jay/project/rtsp/RaspberryPi-5-RTSP-Server/c_key/client.key", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error configuring SSL context with certificate and key" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (!SSL_CTX_load_verify_locations(ctx, "/home/jay/project/rtsp/RaspberryPi-5-RTSP-Server/ca/ca.crt", nullptr)) {
        std::cerr << "Error loading CA certificate to trust store" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
}

void send_rtsp_request(int rtsp_sockfd, const char* request) {
    if (send(rtsp_sockfd, request, strlen(request), 0) < 0) {
        perror("Failed to send RTSP request");
        close(rtsp_sockfd);
        exit(EXIT_FAILURE);
    }
}

void receive_rtsp_response(int rtsp_sockfd) {
    char response[BUFFER_SIZE] = {0};
    int len = recv(rtsp_sockfd, response, sizeof(response) - 1, 0);
    if (len < 0) {
        perror("Failed to receive RTSP response");
        close(rtsp_sockfd);
        exit(EXIT_FAILURE);
    }
    response[len] = '\0';
    std::cout << "RTSP Response:\n" << response << std::endl;
}

int main() {
    initialize_openssl();

    // Create RTSP socket
    int rtsp_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (rtsp_sockfd < 0) {
        perror("RTSP socket creation failed");
        return -1;
    }

    // Set up RTSP server address
    struct sockaddr_in rtsp_server_addr;
    memset(&rtsp_server_addr, 0, sizeof(rtsp_server_addr));
    rtsp_server_addr.sin_family = AF_INET;
    rtsp_server_addr.sin_port = htons(RTSP_PORT);
    inet_pton(AF_INET, "127.0.0.1", &rtsp_server_addr.sin_addr);

    // Connect to RTSP server
    if (connect(rtsp_sockfd, (struct sockaddr*)&rtsp_server_addr, sizeof(rtsp_server_addr)) < 0) {
        perror("RTSP server connection failed");
        close(rtsp_sockfd);
        return -1;
    }
    std::cout << "Connected to RTSP server on port " << RTSP_PORT << std::endl;

    // Send OPTIONS request to RTSP server
    const char* options_request = "OPTIONS rtsp://127.0.0.1:8554/test RTSP/1.0\r\nCSeq: 1\r\n\r\n";
    send_rtsp_request(rtsp_sockfd, options_request);
    receive_rtsp_response(rtsp_sockfd);

    // Send DESCRIBE request to RTSP server
    const char* describe_request = "DESCRIBE rtsp://127.0.0.1:8554/test RTSP/1.0\r\nCSeq: 2\r\n\r\n";
    send_rtsp_request(rtsp_sockfd, describe_request);
    receive_rtsp_response(rtsp_sockfd);

    // Send SETUP request to RTSP server
    const char* setup_request = "SETUP rtsp://127.0.0.1:8554/test/track1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=12345-12346\r\n\r\n";
    send_rtsp_request(rtsp_sockfd, setup_request);
    receive_rtsp_response(rtsp_sockfd);

    // Send PLAY request to RTSP server
    const char* play_request = "PLAY rtsp://127.0.0.1:8554/test RTSP/1.0\r\nCSeq: 4\r\nSession: 12345678\r\n\r\n";
    send_rtsp_request(rtsp_sockfd, play_request);
    receive_rtsp_response(rtsp_sockfd);

    // Close RTSP connection
    close(rtsp_sockfd);
    std::cout << "RTSP session closed" << std::endl;

    // Set up DTLS and SRTP to receive RTP stream
    SSL_CTX* ctx = create_dtls_client_context();
    configure_context(ctx);

    int rtp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rtp_sockfd < 0) {
        perror("RTP socket creation failed");
        return -1;
    }

    struct sockaddr_in rtp_addr;
    memset(&rtp_addr, 0, sizeof(rtp_addr));
    rtp_addr.sin_family = AF_INET;
    rtp_addr.sin_port = htons(RTP_PORT);
    inet_pton(AF_INET, "127.0.0.1", &rtp_addr.sin_addr);

    BIO* bio = BIO_new_dgram(rtp_sockfd, BIO_NOCLOSE);
    if (!bio) {
        std::cerr << "Failed to create BIO" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        close(rtp_sockfd);
        return -1;
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "Unable to create SSL structure" << std::endl;
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        SSL_CTX_free(ctx);
        close(rtp_sockfd);
        return -1;
    }

    SSL_set_bio(ssl, bio, bio);
	SSL_set_info_callback(ssl, debug_callback);  // 디버깅 로그 추가

	// 핸드셰이크 시작
	std::cout << "Starting DTLS handshake..." << std::endl;

	int handshake_result = SSL_connect(ssl);
    if (handshake_result <= 0) {
        std::cerr << "DTLS handshake failed" << std::endl;
        //ERR_print_errors_fp(stderr);

		unsigned long err_code;
		while ((err_code = ERR_get_error()) != 0) {
			char err_msg[256];
			ERR_error_string_n(err_code, err_msg, sizeof(err_msg));
			std::cerr << "[CLIENT] OpenSSL error: " << err_msg << std::endl;
		}

        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(rtp_sockfd);
        return -1;
    }
    std::cout << "DTLS handshake successful" << std::endl;

    // SRTP session setup
    unsigned char srtp_key[SRTP_MASTER_KEY_LEN];
    if (SSL_export_keying_material(ssl, srtp_key, sizeof(srtp_key), "EXTRACTOR-dtls_srtp", strlen("EXTRACTOR-dtls_srtp"), nullptr, 0, 0) != 1) {
        std::cerr << "Failed to export keying material for SRTP" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(rtp_sockfd);
        return -1;
    }

    srtp_policy_t policy;
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
    policy.ssrc.type = ssrc_any_inbound;
    policy.key = srtp_key;
    policy.next = nullptr;

    srtp_t srtp_session;
    if (srtp_create(&srtp_session, &policy) != srtp_err_status_ok) {
        std::cerr << "Failed to create SRTP session" << std::endl;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(rtp_sockfd);
        return -1;
    }

    // Receive RTP packets and decrypt them using SRTP
    unsigned char buffer[BUFFER_SIZE];
    while (true) {
        socklen_t addr_len = sizeof(rtp_addr);
        int len = recvfrom(rtp_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&rtp_addr, &addr_len);
        if (len < 0) {
            perror("Failed to receive RTP packet");
            break;
        }

        if (srtp_unprotect(srtp_session, buffer, &len) != srtp_err_status_ok) {
            std::cerr << "Failed to unprotect SRTP packet" << std::endl;
            continue;
        }

        std::cout << "Received and unprotected SRTP packet, length: " << len << std::endl;
    }

    // Clean up
    srtp_dealloc(srtp_session);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(rtp_sockfd);
    return 0;
}

