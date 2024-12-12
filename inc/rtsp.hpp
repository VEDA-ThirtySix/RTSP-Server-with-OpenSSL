/**
* @file rtsp.hpp
* @brief rtsp 세션 실행
* @details 이 파일은 h264 파일을 받아 rtsp 스트리밍을 시작하는 파일입니다.
* @author HyunJun Song
* @date 2024/11/21
* @version 0.0.1
*/

#pragma once

#include "h264.hpp"
#include "rtp_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <openssl/ssl.h>
#include <srtp2/srtp.h>

constexpr uint16_t SERVER_RTP_PORT = 12345;
constexpr uint16_t SERVER_RTCP_PORT = SERVER_RTP_PORT + 1;
constexpr uint16_t SERVER_RTSP_PORT = 8554;

class RTSP
{
private:
    H264Parser h264_file;
    
    int server_rtsp_sock_fd{-1};
    int server_rtp_sock_fd{-1};
    int server_rtcp_sock_fd{-1};

    int client_rtp_port{-1};
    int client_rtcp_port{-1};

	static SSL_CTX* create_dtls_server_context(); // DTLS 서버 컨텍스트 생성 함수 추가
	void configure_context(SSL_CTX* ctx);  // SSL 컨텍스트 설정 함수 추가
	static void debug_callback(const SSL *ssl, int where, int ret);
	srtp_t srtp_session;  // SRTP 세션 변수 추가

    static int Socket(int domain, int type, int protocol = 0);
    static bool Bind(int sockfd, const char *IP, uint16_t port);
    static bool rtsp_sock_init(int rtspSockfd, const char *IP, uint16_t port, int64_t ListenQueue = 5);

    static void replyCmd_OPTIONS(char *buffer, const int64_t bufferLen, const int cseq);
    static void replyCmd_SETUP(char *buffer, const int64_t bufferLen, const int cseq, const int clientRTP_Port, const int ssrcNum, const char *sessionID, const int timeout);
    static void replyCmd_PLAY(char *buffer, const int64_t bufferLen, const int cseq, const char *sessionID, const int timeout);
    static void replyCmd_HEARTBEAT(char *buffer, const int64_t bufferLen, const int cseq, const char *sessionID);
    static void replyCmd_DESCRIBE(char *buffer, const int64_t bufferLen, const int cseq, const char *url);

    static char *line_parser(char *src, char *line);

    void serve_client(int clientfd, const sockaddr_in &cliAddr, int rtpFD, int ssrcNum, const char *sessionID, int timeout, float fps);

    static int64_t push_stream(int sockfd, RtpPacket &rtpPack, const uint8_t *data, int64_t dataSize, const sockaddr *to, uint32_t timeStampStep, srtp_t srtp_session);

public:
    explicit RTSP(const char *filename);
    ~RTSP();

    void Start(int ssrcNum, const char *sessionID, int timeout, float fps);
};
