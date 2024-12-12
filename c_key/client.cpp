#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <srtp2/srtp.h>
#include <netdb.h>
#include <vector>

#define RTSP_PORT 8554
#define RTP_PORT 54321
#define RTCP_PORT RTP_PORT + 1
#define BUFFER_SIZE 65535

constexpr uint8_t NALU_NRI_MASK = 0x60;
constexpr uint8_t NALU_F_NRI_MASK = 0xe0;
constexpr uint8_t NALU_TYPE_MASK = 0x1F;

constexpr uint8_t FU_S_MASK = 0x80;
constexpr uint8_t FU_E_MASK = 0x40;
constexpr uint8_t SET_FU_A_MASK = 0x1C;

std::vector<uint8_t> naluBuffer;
bool isReceivingNALU = false;


// 완성된 NALU 처리 함수
void handleCompleteNALU(const uint8_t* naluData, size_t naluSize) {
    std::cout << "Complete NALU received, size: " << naluSize << " bytes" << std::endl;

    // 복호화된 NALU 데이터를 디코더로 전달하거나 파일에 저장
    // 예: std::ofstream output("output.h264", std::ios::binary | std::ios::app);
    // output.write(reinterpret_cast<const char*>(naluData), naluSize);
}


// RTP 페이로드에서 FU-A 헤더 처리 및 NALU 데이터 합치기
void processRTPPacket(const uint8_t* rtpPayload, size_t payloadSize) {
    if (payloadSize < 2) {
        // FU-A 헤더가 없는 경우, 단일 NALU 데이터로 처리
        handleCompleteNALU(rtpPayload, payloadSize);
        return;
    }

    const uint8_t fuIndicator = rtpPayload[0]; // FU Indicator
    const uint8_t fuHeader = rtpPayload[1];    // FU Header

    // FU-A 헤더 감지
    const bool isFUAPacket = (fuIndicator & NALU_TYPE_MASK) == 28;

    if (!isFUAPacket) {
        // 단일 NALU 패킷으로 처리
        handleCompleteNALU(rtpPayload, payloadSize);
        return;
    }

    const uint8_t* data = rtpPayload + 2; // FU-A 헤더를 제외한 데이터
    size_t dataSize = payloadSize - 2;

    const bool isStart = fuHeader & FU_S_MASK; // S 비트 확인
    const bool isEnd = fuHeader & FU_E_MASK;   // E 비트 확인

    if (isStart) {
        // 새 NALU 시작 - FU-A 헤더 제거 후 데이터 추가
        isReceivingNALU = true;
        naluBuffer.clear();

        // 데이터 추가
        naluBuffer.insert(naluBuffer.end(), data, data + dataSize);

        std::cout << "[START] NALU started, size: " << naluBuffer.size()
                  << " bytes (Data Only)" << std::endl;
    } else if (isReceivingNALU) {
        // 중간 또는 마지막 패킷 처리
        naluBuffer.insert(naluBuffer.end(), data, data + dataSize);

        if (isEnd) {
            // NALU 완성
            isReceivingNALU = false;

            std::cout << "[END] Complete NALU received, size: " << naluBuffer.size()
                      << " bytes" << std::endl;

            handleCompleteNALU(naluBuffer.data(), naluBuffer.size());
        }
    } else {
        std::cerr << "[ERROR] Unexpected FU-A fragment without start" << std::endl;
    }
}


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

	//SSL_CTX_set_info_callback(ctx, debug_callback);

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
    const char* setup_request = "SETUP rtsp://127.0.0.1:8554/test/track1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=54321-54322\r\n\r\n";
    send_rtsp_request(rtsp_sockfd, setup_request);
    receive_rtsp_response(rtsp_sockfd);

    // Send PLAY request to RTSP server
    const char* play_request = "PLAY rtsp://127.0.0.1:8554/test RTSP/1.0\r\nCSeq: 4\r\nSession: 12345678\r\n\r\n";
    send_rtsp_request(rtsp_sockfd, play_request);
    receive_rtsp_response(rtsp_sockfd);

    // Close RTSP connection
    close(rtsp_sockfd);
    std::cout << "RTSP session closed" << std::endl;


    int rtp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rtp_sockfd < 0) {
        perror("RTP socket creation failed");
        return -1;
    }


// 클라이언트 주소 바인딩
struct sockaddr_in client_addr;
memset(&client_addr, 0, sizeof(client_addr));
client_addr.sin_family = AF_INET;
client_addr.sin_addr.s_addr = INADDR_ANY;
client_addr.sin_port = htons(RTP_PORT);

if (bind(rtp_sockfd, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
    perror("Client bind failed");
    close(rtp_sockfd);
    return -1;
}
std::cout << "Client is bound to port " << ntohs(client_addr.sin_port) << std::endl;



    struct sockaddr_in rtp_addr;
    memset(&rtp_addr, 0, sizeof(rtp_addr));
    rtp_addr.sin_family = AF_INET;
    rtp_addr.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &rtp_addr.sin_addr);


    if (connect(rtp_sockfd, (struct sockaddr*)&rtp_addr, sizeof(rtp_addr)) < 0) {
        perror("RTP server connection failed");
        close(rtp_sockfd);
        return -1;
    } else {
        std::cout << "Connected to RTP server on port " << ntohs(rtp_addr.sin_port) << std::endl;
    }


    // Set up DTLS and SRTP to receive RTP stream
    SSL_CTX* ctx = create_dtls_client_context();

    const char* srtp_profiles = "SRTP_AES128_CM_SHA1_80";
    if (SSL_CTX_set_tlsext_use_srtp(ctx, srtp_profiles) != 0) {
        std::cerr << "Error setting SRTP profiles" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return -1;
    }

    configure_context(ctx);

    BIO* bio = BIO_new_dgram(rtp_sockfd, BIO_NOCLOSE);
    if (!bio) {
        std::cerr << "Failed to create BIO" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        close(rtp_sockfd);
        return -1;
    }


if (BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &rtp_addr) <= 0) {
    std::cerr << "Failed to set connected BIO for server" << std::endl;
    ERR_print_errors_fp(stderr);
    BIO_free(bio);
    SSL_CTX_free(ctx);
    close(rtp_sockfd);
    return -1;
} else {
    std::cout << "BIO_CTRL_DGRAM_SET_CONNECTED set for server address: "
              << inet_ntoa(rtp_addr.sin_addr) << ":" << ntohs(rtp_addr.sin_port) << std::endl;
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
	//SSL_set_info_callback(ssl, debug_callback);  // 디버깅 로그 추가


	// 핸드셰이크 시작
	std::cout << "Starting DTLS handshake..." << std::endl;

	int handshake_result = SSL_connect(ssl);
    if (handshake_result <= 0) {
        int ssl_error = SSL_get_error(ssl, handshake_result);
        std::cerr << "DTLS handshake failed with SSL error code: " << ssl_error << std::endl;

// SSL_get_error()로부터의 상태에 따라 출력
        switch (ssl_error) {
            case SSL_ERROR_NONE:
                std::cerr << "No error occurred." << std::endl;
                break;
            case SSL_ERROR_ZERO_RETURN:
                std::cerr << "The TLS/SSL connection has been closed." << std::endl;
                break;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                std::cerr << "The operation did not complete and should be retried." << std::endl;
                break;
            case SSL_ERROR_SYSCALL:
                std::cerr << "A system call error occurred." << std::endl;
                perror("System call error");
				std::cerr << "errno: " << errno << " (" << strerror(errno) << ")" << std::endl;
                break;
            case SSL_ERROR_SSL:
                std::cerr << "A failure in the SSL library occurred, usually a protocol error." << std::endl;
                ERR_print_errors_fp(stderr);
                break;
            default:
                std::cerr << "An unknown error occurred." << std::endl;
                break;
        }

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


    const char* cipher_suite = SSL_get_cipher(ssl);
    std::cout << "Negotiated Cipher Suite: " << cipher_suite << std::endl;


    const SRTP_PROTECTION_PROFILE *profile = SSL_get_selected_srtp_profile(ssl);
    if (profile != nullptr) {
        std::cout << "Selected SRTP profile: " << profile->name << std::endl;
    } else {
        std::cerr << "Failed to negotiate SRTP profile" << std::endl;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(rtp_sockfd);
        return -1;
    }


    // SRTP session setup
    unsigned char srtp_key[SRTP_MASTER_KEY_LEN];
    if (SSL_export_keying_material(ssl, srtp_key, SRTP_MASTER_KEY_LEN, "EXTRACTOR-dtls_srtp", strlen("EXTRACTOR-dtls_srtp"), nullptr, 0, 0) != 1) {
        std::cerr << "Failed to export keying material for SRTP" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(rtp_sockfd);
        return -1;
    }

// 디버그 로그 추가
std::cout << "Exported SRTP key: ";
for (int i = 0; i < SRTP_MASTER_KEY_LEN; ++i) {
    printf("%02X ", srtp_key[i]);
}
std::cout << std::endl;

    if (srtp_init() != srtp_err_status_ok) {
        std::cerr << "Failed to initialize SRTP library." << std::endl;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(rtp_sockfd);
        return -1;
    }


    srtp_policy_t policy;
	memset(&policy, 0, sizeof(srtp_policy_t));
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
    policy.ssrc.type = ssrc_any_inbound;
	policy.ssrc.value = 20001102;
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

	std::cout << "SRTP session created successfully." << std::endl;

	// SRTP 세션 생성 후 디버깅
	std::cout << "SRTP session created successfully with policy.ssrc.value: " << policy.ssrc.value << std::endl;
	
	std::cout << "Client waiting on port: " << RTP_PORT << std::endl;

    // Receive RTP packets and decrypt them using SRTP
    while (true) {

		unsigned char buffer[BUFFER_SIZE];
        int len = recv(rtp_sockfd, buffer, sizeof(buffer), 0);
        if (len < 0) {
            perror("Failed to receive RTP packet");
            break;
        } else {
		    std::cout << "Received RTP packet, length: " << len << " bytes" << std::endl;
		}	
		srtp_err_status_t status = srtp_unprotect(srtp_session, buffer, &len);
        if (status != srtp_err_status_ok) {
            std::cerr << "Failed to unprotect SRTP packet" << std::endl;
			std::cerr << "SRTP unprotect failed with error code: " << status << std::endl;
			switch (status) {
			    case srtp_err_status_replay_fail:
			        std::cerr << "Replay check failed." << std::endl;
			        break;
			    case srtp_err_status_bad_param:
			        std::cerr << "Bad parameter or invalid packet." << std::endl;
			        break;
			    case srtp_err_status_auth_fail:
			        std::cerr << "Authentication failed. Data might be corrupted." << std::endl;
			        break;
			    case srtp_err_status_cipher_fail:
			        std::cerr << "Cipher operation failed." << std::endl;
			        break;
			    default:
			        std::cerr << "Unknown error occurred." << std::endl;
			        break;
			}
            continue;
        }

        std::cout << "Received and unprotected SRTP packet, length: " << len << std::endl;

		// RTP 페이로드에서 FU-A 헤더 처리 및 NALU 데이터 조립
	    const uint8_t* rtpPayload = buffer + 12; // RTP 헤더(12 바이트) 건너뛰기
	    size_t payloadSize = len - 12;
	    processRTPPacket(rtpPayload, payloadSize);
    }

    // Clean up
    srtp_dealloc(srtp_session);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(rtp_sockfd);
    return 0;
}


