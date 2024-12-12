#include "rtsp.hpp"
#include "h264.hpp"
#include "rtp_packet.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <srtp2/srtp.h>

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define BUFFER_SIZE 1024
#define RTP_HEADER_LEN 12
#define MAX_BUFFER 65535
RTSP::RTSP(const char *filename) : h264_file(filename)
{
}

RTSP::~RTSP()
{
	close(this->server_rtcp_sock_fd);
	close(this->server_rtp_sock_fd);
	close(this->server_rtsp_sock_fd);
}

int RTSP::Socket(int domain, int type, int protocol)
{
	int sockfd;
	const int optval = 1;

	if((sockfd = socket(domain, type, protocol)) < 0) {
        	fprintf(stderr, "RTSP::Socket() failed: %s\n", strerror(errno));
        	return sockfd;
    	}

    	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        	fprintf(stderr, "setsockopt() failed: %s\n", strerror(errno));
        	return -1;
    	}

    	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &MAX_UDP_PACKET_SIZE,
			sizeof(MAX_UDP_PACKET_SIZE)) < 0)
	{
		fprintf(stderr, "setsockopt() failed: %s\n", strerror(errno));
		return -1;
	}
	return sockfd;
}

bool RTSP::Bind(int sockfd, const char *IP, const uint16_t port)
{
    sockaddr_in addr{};
    memset(&addr, 0 , sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, IP, &addr.sin_addr);
    if (bind(sockfd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        fprintf(stderr, "bind() failed: %s\n", strerror(errno));
        return false;
    }
    return true;
}

bool RTSP::rtsp_sock_init(int rtspSockfd, const char *IP, const uint16_t port, const int64_t ListenQueue)
{
    if (!RTSP::Bind(rtspSockfd, IP, port))
        return false;

    if (listen(rtspSockfd, ListenQueue) < 0) {
        fprintf(stderr, "listen() failed: %s\n", strerror(errno));
        return false;
    }
    return true;
}
 
void RTSP::Start(const int ssrcNum, const char *sessionID, const int timeout, const float fps)
{
    this->server_rtsp_sock_fd = RTSP::Socket(AF_INET, SOCK_STREAM);
    if (!RTSP::rtsp_sock_init(this->server_rtsp_sock_fd, "0.0.0.0", SERVER_RTSP_PORT)) {
        fprintf(stderr, "failed to create RTSP socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    this->server_rtp_sock_fd = RTSP::Socket(AF_INET, SOCK_DGRAM);
    this->server_rtcp_sock_fd = RTSP::Socket(AF_INET, SOCK_DGRAM);

    if (!RTSP::Bind(this->server_rtp_sock_fd, "0.0.0.0", SERVER_RTP_PORT)) {
        fprintf(stderr, "failed to create RTP socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (!RTSP::Bind(this->server_rtcp_sock_fd, "0.0.0.0", SERVER_RTCP_PORT)) {
        fprintf(stderr, "failed to create RTCP socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "rtsp://127.0.0.1:%d\n", SERVER_RTSP_PORT);

    //while (true)
    //{
    sockaddr_in cliAddr{};
    bzero(&cliAddr, sizeof(cliAddr));
    socklen_t addrLen = sizeof(cliAddr);
    auto cli_sockfd = accept(this->server_rtsp_sock_fd, reinterpret_cast<sockaddr *>(&cliAddr), &addrLen);
    if (cli_sockfd < 0) {
        fprintf(stderr, "accept error(): %s\n", strerror(errno));
        //continue;
        return;
    }
    char IPv4[16]{0};
    fprintf(stdout,
            "Connection from %s:%d\n",
            inet_ntop(AF_INET, &cliAddr.sin_addr, IPv4, sizeof(IPv4)),
            ntohs(cliAddr.sin_port));
    this->serve_client(cli_sockfd, cliAddr, this->server_rtp_sock_fd, ssrcNum, sessionID, timeout, fps);
    //}
}

char *RTSP::line_parser(char *src, char *line)
{
    while (*src != '\n')
        *(line++) = *(src++);

    *line = '\n';
    *(++line) = 0;
    return (src + 1);
}

void RTSP::serve_client(int clientfd, const sockaddr_in &cliAddr, int rtpFD, const int ssrcNum, const char *sessionID, const int timeout, const float fps)
{

	std::cout << "cliAddr.sin_family: " << cliAddr.sin_family << std::endl;
	std::cout << "cliAddr.sin_port: " << ntohs(cliAddr.sin_port) << std::endl;
	std::cout << "cliAddr.sin_addr: " << inet_ntoa(cliAddr.sin_addr) << std::endl;

    char method[10]{0};
    char url[100]{0};
    char version[10]{0};
    char line[500]{0};
    int cseq;
    int64_t heartbeatCount = 0;
    char recvBuf[2048]{0}, sendBuf[2048]{0};
    while (true)
    {
        auto recvLen = recv(clientfd, recvBuf, sizeof(recvBuf), 0);
        if (recvLen <= 0)
            break;
        recvBuf[recvLen] = 0;
        fprintf(stdout, "--------------- [C->S] --------------\n");
        fprintf(stdout, "%s", recvBuf);

        char *bufferPtr = RTSP::line_parser(recvBuf, line);

        if (sscanf(line, "%s %s %s\r\n", method, url, version) != 3) {
            fprintf(stdout, "RTSP::line_parser() parse method error\n");
            break;
        }

        bufferPtr = RTSP::line_parser(bufferPtr, line);
        if (sscanf(line, "CSeq: %d\r\n", &cseq) != 1) {
            fprintf(stdout, "RTSP::line_parser() parse seq error\n");
            break;
        }
  
        if (!strcmp(method, "SETUP")) {
            while (true) {
                bufferPtr = RTSP::line_parser(bufferPtr, line);
                if (!strncmp(line, "Transport:", strlen("Transport:"))) {
                    sscanf(line, "Transport: RTP/AVP;unicast;client_port=%d-%d\r\n", &this->client_rtp_port, &this->client_rtcp_port);
                    break;
                }
            }
        }

        if (!strcmp(method, "OPTIONS")) {
            RTSP::replyCmd_OPTIONS(sendBuf, sizeof(sendBuf), cseq);
        } else if (!strcmp(method, "DESCRIBE")) {
            RTSP::replyCmd_DESCRIBE(sendBuf, sizeof(sendBuf), cseq, url);
        } else if (!strcmp(method, "SETUP")) {
            RTSP::replyCmd_SETUP(sendBuf, sizeof(sendBuf), cseq, this->client_rtp_port, ssrcNum, sessionID, timeout);
        } else if (!strcmp(method, "PLAY")) {
            RTSP::replyCmd_PLAY(sendBuf, sizeof(sendBuf), cseq, sessionID, timeout);
        } else {
            fprintf(stderr, "Parse method error\n");
            break;
        }

        fprintf(stdout, "--------------- [S->C] --------------\n");
        fprintf(stdout, "%s", sendBuf);
        if (send(clientfd, sendBuf, strlen(sendBuf), 0) < 0) {
            fprintf(stderr, "RTSP::serve_client() send() failed: %s\n", strerror(errno));
            break;
        }

        if (!strcmp(method, "PLAY")) {

			char IPv4[16]{0};
			inet_ntop(AF_INET, &cliAddr.sin_addr, IPv4, sizeof(IPv4));

			struct sockaddr_in clientSock{};
			bzero(&clientSock, sizeof(sockaddr_in));
			clientSock.sin_family = AF_INET;
			inet_pton(clientSock.sin_family, IPv4, &clientSock.sin_addr);
			clientSock.sin_port = htons(this->client_rtp_port);


            // 1. DTLS 초기화 및 핸드셰이크 수행
            SSL_CTX *ctx = create_dtls_server_context();

			const char* srtp_profiles = "SRTP_AES128_CM_SHA1_80";
			if (SSL_CTX_set_tlsext_use_srtp(ctx, srtp_profiles) != 0) {
				std::cerr << "Error setting SRTP profiles" << std::endl;
				ERR_print_errors_fp(stderr);
				SSL_CTX_free(ctx);
				return;
			}
            configure_context(ctx);

            BIO *bio = BIO_new_dgram(rtpFD, BIO_NOCLOSE);
			if (!bio) {
				std::cerr << "Failed to create BIO" << std::endl;
				ERR_print_errors_fp(stderr);
				SSL_CTX_free(ctx);
				return;
			}

            SSL *ssl = SSL_new(ctx);
			if (!ssl) {
				std::cerr << "Unable to create SSL structure" << std::endl;
				ERR_print_errors_fp(stderr);
				BIO_free(bio);
				SSL_CTX_free(ctx);
				return;
			}
            SSL_set_bio(ssl, bio, bio);
			//SSL_set_info_callback(ssl, debug_callback);

            // 핸드셰이크 수행
			std::cout << "Waiting for DTLS handshake..." << std::endl;
			int handshake_result = SSL_accept(ssl);
            if (handshake_result <= 0) {
				std::cerr << "[SERVER] DTLS handshake failed" << std::endl;

				unsigned long err_code;
				while ((err_code = ERR_get_error()) != 0) {
					char err_msg[256];
					ERR_error_string_n(err_code, err_msg, sizeof(err_msg));
					std::cerr << "[SERVER] OpenSSL error: " << err_msg << std::endl;

					int ssl_error = SSL_get_error(ssl, handshake_result);
					std::cerr << "DTLS handshake failed with SSL error code: " << ssl_error << std::endl;
					ERR_print_errors_fp(stderr);
				}
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                close(clientfd);
                return;
            }
            std::cout << "DTLS handshake successful" << std::endl;


			const char* cipher_suite = SSL_get_cipher(ssl);
			std::cout << "Negotiated Cipher Suite: " << cipher_suite << std::endl;

			const SRTP_PROTECTION_PROFILE *profile = SSL_get_selected_srtp_profile(ssl);
			if (profile != nullptr) {
				//std::cout << "Selected SRTP profile: " << profile->name << std::endl;
			} else {
				std::cerr << "Failed to negotiate SRTP profile" << std::endl;
				SSL_free(ssl);
				SSL_CTX_free(ctx);
				close(clientfd);
				return;
			}

            // 2. SRTP 초기화
            unsigned char srtp_key[SRTP_MASTER_KEY_LEN]; // SRTP 키 자료
            if (SSL_export_keying_material(ssl, srtp_key, SRTP_MASTER_KEY_LEN, "EXTRACTOR-dtls_srtp", strlen("EXTRACTOR-dtls_srtp"), nullptr, 0, 0) != 1) {
                std::cerr << "Failed to export keying material for SRTP." << std::endl;
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                close(clientfd);
                return;
            }

			// 라이브러리 초기화
			if (srtp_init() != srtp_err_status_ok) {
				std::cerr << "Failed to initialize SRTP library." << std::endl;
				SSL_free(ssl);
				SSL_CTX_free(ctx);
				close(clientfd);
				return;
			}

			// 키 자료 로그 확인
			std::cout << "Exported SRTP key: ";
			for (int i = 0; i < SRTP_MASTER_KEY_LEN; ++i) {
			    printf("%02X ", srtp_key[i]);
			}
			std::cout << std::endl;

            srtp_policy_t policy;
            memset(&policy, 0, sizeof(srtp_policy_t));
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
            policy.ssrc.type = ssrc_specific;
			policy.ssrc.value = ssrcNum;
            policy.key = srtp_key;
			policy.next = nullptr;

            srtp_t srtp_session;
            srtp_err_status_t status = srtp_create(&srtp_session, &policy);
            if (status != srtp_err_status_ok) {
                std::cerr << "Failed to create SRTP session" << std::endl;
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                close(clientfd);
                return;
            }

			// SRTP 세션 생성 후 디버깅
			std::cout << "SRTP session created successfully with SSRC: " << ssrcNum << std::endl;

            //uint32_t tmpTimeStamp = 0;
            const auto timeStampStep = uint32_t(90000 / fps);
            const auto sleepPeriod = uint32_t(1000 * 1000 / fps);
            RtpHeader rtpHeader(0, 0, ssrcNum);
            RtpPacket rtpPack{rtpHeader};
			//std::cout << "SSRC set in RtpHeader: " << ssrcNum << std::endl;


            while (true) {
                auto cur_frame = this->h264_file.get_next_frame();
                const auto ptr_cur_frame = cur_frame.first;
                const auto cur_frame_size = cur_frame.second;

                if (cur_frame_size < 0) {
                    fprintf(stderr, "RTSP::serve_client() H264::getOneFrame() failed\n");
                    break;
                } else if (!cur_frame_size) {
                    fprintf(stdout, "Finish serving the user\n");
                    return;
                }



				if (!ptr_cur_frame || cur_frame_size <= 0) {
				    std::cerr << "Invalid frame pointer or size." << std::endl;
				    return;
				}


                const int64_t start_code_len = H264Parser::is_start_code(ptr_cur_frame, cur_frame_size, 4) ? 4 : 3;

				RTSP::push_stream(rtpFD, rtpPack, ptr_cur_frame + start_code_len, cur_frame_size - start_code_len, (sockaddr *)&clientSock, timeStampStep, srtp_session);

	                usleep(sleepPeriod);			
				
            }
			break;
        }
    }
    fprintf(stdout, "finish\n");
    close(clientfd);
}

int64_t RTSP::push_stream(int sockfd, RtpPacket &rtpPack, const uint8_t *data, const int64_t dataSize, const sockaddr *to, const uint32_t timeStampStep, srtp_t srtp_session)
{
	const uint8_t naluHeader = data[0];

    if (dataSize <= MAX_RTP_DATA_SIZE) {

		std::cout << "1 data of length: " << dataSize << std::endl;


        // SRTP 보호 적용
		rtpPack.load_data(data, dataSize);
/*
		std::cout << "RTP Packet data (before SRTP): ";
		for (int i = 0; i < dataSize; ++i) {
		    printf("%02X ", rtpPack.get_payload()[i]);
		}
		std::cout << std::endl;
*/
		int packet_len = static_cast<int>(dataSize + RTP_HEADER_SIZE);
		uint8_t rtpBuffer[MAX_BUFFER];

		// RTP 헤더 복사
		const RtpHeader &header = rtpPack.get_header();
		memcpy(rtpBuffer, &header, RTP_HEADER_SIZE);

	    // RTP 페이로드 복사
	    memcpy(rtpBuffer + RTP_HEADER_SIZE, data, dataSize);

		std::cout << "Packet length before SRTP protect: " << packet_len << std::endl;

	    srtp_err_status_t status = srtp_protect(srtp_session, rtpBuffer, &packet_len);
		if (status != srtp_err_status_ok) {
		    std::cerr << "Failed to protect SRTP data, error code: " << status << std::endl;
		    switch (status) {
		        case srtp_err_status_bad_param:
		            std::cerr << "Invalid parameters provided to srtp_protect" << std::endl;
		            break;
		        case srtp_err_status_auth_fail:
		            std::cerr << "Authentication failed for SRTP packet" << std::endl;
		            break;
		        case srtp_err_status_cipher_fail:
		            std::cerr << "Cipher operation failed during SRTP protection" << std::endl;
		            break;
		        default:
		            std::cerr << "Unknown SRTP protection error occurred" << std::endl;
		    }
		    return -1;
		}


	    // SRTP 보호 결과를 RtpPacket에 반영
		RtpHeader &mutableHeader = rtpPack.mutable_header();
		memcpy(&mutableHeader, rtpBuffer, RTP_HEADER_SIZE);

	    memcpy(rtpPack.get_payload(), rtpBuffer + RTP_HEADER_SIZE, packet_len - RTP_HEADER_SIZE);

	    std::cout << "Packet length after SRTP protect: " << packet_len << std::endl;

	    // 보호된 데이터 전송
		auto ret = rtpPack.rtp_sendto(sockfd, packet_len, 0, to, timeStampStep);
	    if (ret < 0) {
	        fprintf(stderr, "sendto() failed: %s\n", strerror(errno));
	        return -1;
	    } else {
			std::cout << "send 1" << std::endl;
		}	
		return ret;
    }

	std::cout << "2 data of length: " << dataSize << std::endl;
    const int64_t packetNum = dataSize / MAX_RTP_DATA_SIZE;
    const int64_t remainPacketSize = dataSize % MAX_RTP_DATA_SIZE;
    int64_t pos = 1;
    int64_t sentBytes = 0;
    auto payload = rtpPack.get_payload();

	// 패킷 분할 및 전송
	for (int64_t i = 0; i < packetNum; i++) {
	    rtpPack.load_data(data + pos, MAX_RTP_DATA_SIZE, FU_SIZE);
	    payload[0] = (naluHeader & NALU_F_NRI_MASK) | SET_FU_A_MASK;
	    payload[1] = naluHeader & NALU_TYPE_MASK;

	    if (i == 0)
	        payload[1] |= FU_S_MASK; // 첫 번째 패킷
	    else if (i == packetNum - 1 && remainPacketSize == 0)
	        payload[1] |= FU_E_MASK; // 마지막 패킷


	    // SRTP 보호 적용:
	    int packet_len = static_cast<int>(MAX_RTP_DATA_SIZE + RTP_HEADER_SIZE + FU_SIZE);
	    uint8_t rtpBuffer[MAX_RTP_PACKET_LEN];

	    // RTP 헤더 복사
	    const RtpHeader &header = rtpPack.get_header();
	    memcpy(rtpBuffer, &header, RTP_HEADER_SIZE);

		//std::cout << header.get_ssrc() << std::endl;
	    // RTP 페이로드 복사
	    memcpy(rtpBuffer + RTP_HEADER_SIZE, rtpPack.get_payload(), MAX_RTP_DATA_SIZE + FU_SIZE);

		std::cout << "Packet length before SRTP protect: " << packet_len << std::endl;
	    // SRTP 보호 적용
	    srtp_err_status_t status = srtp_protect(srtp_session, rtpBuffer, &packet_len);
		if (status != srtp_err_status_ok) {
		    std::cerr << "Failed to protect SRTP data, error code: " << status << std::endl;
		    switch (status) {
		        case srtp_err_status_bad_param:
		            std::cerr << "Invalid parameters provided to srtp_protect" << std::endl;
		            break;
		        case srtp_err_status_auth_fail:
		            std::cerr << "Authentication failed for SRTP packet" << std::endl;
		            break;
		        case srtp_err_status_cipher_fail:
		            std::cerr << "Cipher operation failed during SRTP protection" << std::endl;
		            break;
		        default:
		            std::cerr << "Unknown SRTP protection error occurred" << std::endl;
		    }
		    return -1;
		}
		// SRTP 보호 결과를 RtpPacket에 반영
		RtpHeader &mutableHeader = rtpPack.mutable_header();
		memcpy(&mutableHeader, rtpBuffer, RTP_HEADER_SIZE);
		memcpy(rtpPack.get_payload(), rtpBuffer + RTP_HEADER_SIZE, packet_len - RTP_HEADER_SIZE);
	
		std::cout << "Packet length after SRTP protect: " << packet_len << std::endl;

		// 보호된 데이터 전송
		//auto ret = sendto(sockfd, rtpBuffer, packet_len, 0, to, sizeof(sockaddr_in));
		auto ret = rtpPack.rtp_sendto(sockfd, MAX_RTP_PACKET_LEN, 0, to, timeStampStep);
		if (ret < 0) {
		    fprintf(stderr, "sendto() failed: %s\n", strerror(errno));
		    return -1;
	    } else {
			std::cout << "send 2" << std::endl;
		}	

		sentBytes += ret;
	    pos += MAX_RTP_DATA_SIZE;
	}

	if (remainPacketSize > 0) {

		std::cout << "3 data of length: " << remainPacketSize << std::endl;
	    rtpPack.load_data(data + pos, remainPacketSize, FU_SIZE);
	    payload[0] = (naluHeader & NALU_F_NRI_MASK) | SET_FU_A_MASK;
	    payload[1] = (naluHeader & NALU_TYPE_MASK) | FU_E_MASK; // 마지막 패킷

	    // SRTP 보호 적용
	    int packet_len = static_cast<int>(remainPacketSize + RTP_HEADER_SIZE + FU_SIZE);
	    uint8_t rtpBuffer[MAX_BUFFER];

	    // RTP 헤더 복사
	    const RtpHeader &header = rtpPack.get_header();
	    memcpy(rtpBuffer, &header, RTP_HEADER_SIZE);

		//std::cout << header.get_ssrc() << std::endl;
	    // RTP 페이로드 복사
	    memcpy(rtpBuffer + RTP_HEADER_SIZE, rtpPack.get_payload(), remainPacketSize + FU_SIZE);

		std::cout << "Packet length before SRTP protect: " << packet_len << std::endl;
	    // SRTP 보호 적용
	    srtp_err_status_t status = srtp_protect(srtp_session, rtpBuffer, &packet_len);
		if (status != srtp_err_status_ok) {
		    std::cerr << "Failed to protect SRTP data, error code: " << status << std::endl;
		    switch (status) {
		        case srtp_err_status_bad_param:
		            std::cerr << "Invalid parameters provided to srtp_protect" << std::endl;
		            break;
		        case srtp_err_status_auth_fail:
		            std::cerr << "Authentication failed for SRTP packet" << std::endl;
		            break;
		        case srtp_err_status_cipher_fail:
		            std::cerr << "Cipher operation failed during SRTP protection" << std::endl;
		            break;
		        default:
		            std::cerr << "Unknown SRTP protection error occurred" << std::endl;
		    }
		    return -1;
		}

		// SRTP 보호 결과를 RtpPacket에 반영
		RtpHeader &mutableHeader = rtpPack.mutable_header();
		memcpy(&mutableHeader, rtpBuffer, RTP_HEADER_SIZE);
		memcpy(rtpPack.get_payload(), rtpBuffer + RTP_HEADER_SIZE, packet_len - RTP_HEADER_SIZE);

		std::cout << "Packet length after SRTP protect: " << packet_len << std::endl;

		// 보호된 데이터 전송
		//auto ret = sendto(sockfd, rtpBuffer, packet_len, 0, to, sizeof(sockaddr_in));
		auto ret = rtpPack.rtp_sendto(sockfd, packet_len, 0, to, timeStampStep);
		if (ret < 0) {
		    fprintf(stderr, "sendto() failed: %s\n", strerror(errno));
		    return -1;
	    } else {
			std::cout << "send 3" << std::endl;
		}	

	    sentBytes += ret;
	}
	return sentBytes;
}


void RTSP::replyCmd_OPTIONS(char *buffer, const int64_t bufferLen, const int cseq)
{
    snprintf(buffer, bufferLen, "RTSP/1.0 200 OK\r\nCseq: %d\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n", cseq);
}

void RTSP::replyCmd_SETUP(char *buffer, const int64_t bufferLen, const int cseq, const int clientRTP_Port, const int ssrcNum, const char *sessionID, const int timeout)
{
    snprintf(buffer, bufferLen, "RTSP/1.0 200 OK\r\nCseq: %d\r\nTransport: RTP/AVP;unicast;client_port=%d-%d;server_port=%d-%d;ssrc=%d;mode=play\r\nSession: %s; timeout=%d\r\n\r\n",
             cseq, clientRTP_Port, clientRTP_Port + 1, SERVER_RTP_PORT, SERVER_RTCP_PORT, ssrcNum, sessionID, timeout);
}

void RTSP::replyCmd_PLAY(char *buffer, const int64_t bufferLen, const int cseq, const char *sessionID, const int timeout)
{
    snprintf(buffer, bufferLen, "RTSP/1.0 200 OK\r\nCseq: %d\r\nRange: npt=0.000-\r\nSession: %s; timeout=%d\r\n\r\n", cseq, sessionID, timeout);
}

void RTSP::replyCmd_HEARTBEAT(char *buffer, const int64_t bufferLen, const int cseq, const char *sessionID)
{
    snprintf(buffer, bufferLen, "RTSP/1.0 200 OK\r\nCseq: %d\r\nRange: npt=0.000-\r\nHeartbeat: %s; \r\n\r\n", cseq, sessionID);
}

void RTSP::replyCmd_DESCRIBE(char *buffer, const int64_t bufferLen, const int cseq, const char *url)
{
    char ip[100]{0};
    char sdp[500]{0};
    sscanf(url, "rtsp://%[^:]:", ip);
    snprintf(sdp, sizeof(sdp), "v=0\r\no=- 9%ld 1 IN IP4 %s\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:track0\r\n", time(nullptr), ip);
    snprintf(buffer, bufferLen, "RTSP/1.0 200 OK\r\nCseq: %d\r\nContent-Base: %s\r\nContent-type: application/sdp\r\nContent-length: %ld\r\n\r\n%s", cseq, url, strlen(sdp), sdp);
}

SSL_CTX* RTSP::create_dtls_server_context() {
    const SSL_METHOD* method = DTLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // DTLS 1.2 설정
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);

	//SSL_CTX_set_info_callback(ctx, debug_callback);

    return ctx;
}


void RTSP::configure_context(SSL_CTX* ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "/home/jay/project/rtsp/RaspberryPi-5-RTSP-Server/s_key/server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "/home/jay/project/rtsp/RaspberryPi-5-RTSP-Server/s_key/server.key", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error configuring SSL context with certificate and key" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 클라이언트 인증서 신뢰 설정 (클라이언트의 self-signed 인증서 또는 CA 인증서)
    if (!SSL_CTX_load_verify_locations(ctx, "/home/jay/project/rtsp/RaspberryPi-5-RTSP-Server/ca/ca.crt", nullptr)) {
        std::cerr << "Error loading CA certificate to trust store" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    } else {
        std::cout << "CA certificate loaded successfully." << std::endl;
    }
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
}

void RTSP::debug_callback(const SSL *ssl, int where, int ret) {
    if (where & SSL_CB_HANDSHAKE_START) {
        std::cout << "[SERVER] Handshake started..." << std::endl;
    } else if (where & SSL_CB_HANDSHAKE_DONE) {
        std::cout << "[SERVER] Handshake done!" << std::endl;
    } else if (where & SSL_CB_ALERT) {
        std::cout << "[SERVER] SSL alert: " << SSL_alert_type_string_long(ret) << ", " << SSL_alert_desc_string_long(ret) << std::endl;
    } else if (where & SSL_CB_LOOP) {
        std::cout << "[SERVER] SSL state (" << SSL_state_string_long(ssl) << "): " << SSL_state_string(ssl) << std::endl;
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            std::cerr << "[SERVER] SSL state (" << SSL_state_string_long(ssl) << "): failed" << std::endl;
            ERR_print_errors_fp(stderr);
        } else if (ret < 0) {
            std::cerr << "[SERVER] SSL state (" << SSL_state_string_long(ssl) << "): error" << std::endl;
            ERR_print_errors_fp(stderr);
        }
    }
}

