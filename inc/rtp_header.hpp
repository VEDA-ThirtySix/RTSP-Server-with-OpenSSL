/**
* @file rtp_header.hpp
* @brief rtp 헤더 정의
* @details 이 파일은 h264 페이로드의 rtp 헤더를 정의한 파일입니다.
* @author HyunJun Song
* @date 2024/11/21
* @version 0.0.1
*/

#pragma once

#include <cstddef>
#include <cstdint>

#include <arpa/inet.h>

constexpr int64_t IP_V4_HEADER_SIZE = 20;
constexpr int64_t UDP_HEADER_SIZE = 8;
constexpr int64_t RTP_HEADER_SIZE = 12;
constexpr int64_t RTP_VERSION = 2;
constexpr int64_t RTP_PAYLOAD_TYPE_H264 = 96;
constexpr int64_t FU_SIZE = 2;

constexpr int64_t MAX_UDP_PACKET_SIZE = 60000;
//constexpr int64_t MAX_UDP_PACKET_SIZE = 2048;
constexpr int64_t MAX_RTP_DATA_SIZE = MAX_UDP_PACKET_SIZE - IP_V4_HEADER_SIZE
                                        - UDP_HEADER_SIZE - RTP_HEADER_SIZE - FU_SIZE - 10;
constexpr int64_t MAX_RTP_PACKET_LEN = MAX_RTP_DATA_SIZE + RTP_HEADER_SIZE + FU_SIZE + 10;

#pragma pack(1)
class RtpHeader
{
public:
    RtpHeader(uint8_t _version,     uint8_t _padding,
              uint8_t _extension,   uint8_t _csrcCount,
              uint8_t _marker,      uint8_t _payloadType,
              uint16_t _seq,        uint32_t _timestamp,
              uint32_t _ssrc);
    RtpHeader(uint16_t _seq, uint32_t _timestamp, uint32_t _ssrc);
    RtpHeader(const RtpHeader &) = default;

    ~RtpHeader() = default;

    void set_timestamp(const uint32_t _newtimestamp);
    void set_ssrc(const uint32_t SSRC);
    void set_seq(const uint32_t _seq);

    void *get_header() const;
    uint32_t get_timestamp() const;
    uint32_t get_seq() const;
	uint32_t get_ssrc() const;
private:
    //byte 0
    uint8_t csrcCount : 4;
    uint8_t extension : 1;
    uint8_t padding : 1;
    uint8_t version : 2;
    //byte 1
    uint8_t payloadType : 7;
    uint8_t marker : 1;
    //byte 2, 3
    uint16_t seq;
    //byte 4-7
    uint32_t timestamp;
    //byte 8-11
    uint32_t ssrc;
};

inline void RtpHeader::set_timestamp(const uint32_t _newtimestamp) {this->timestamp = htonl(_newtimestamp);}
inline void RtpHeader::set_ssrc(const uint32_t SSRC) { this->ssrc = htonl(SSRC); }
inline void RtpHeader::set_seq(const uint32_t _seq) { this->seq = htons(_seq); }
inline void *RtpHeader::get_header() const { return (void *)this; }
inline uint32_t RtpHeader::get_timestamp() const { return ntohl(this->timestamp); }
inline uint32_t RtpHeader::get_seq() const { return ntohs(this->seq); }
inline uint32_t RtpHeader::get_ssrc() const { return ntohl(this->ssrc); }
#pragma pack()
