#pragma once

#include <cstddef>
#include <cstdint>

#include <arpa/inet.h>

#include <rtp_header.hpp>

class RtpPacket
{
private:
    RtpHeader header;
    uint8_t RTP_Payload[MAX_RTP_DATA_SIZE + FU_SIZE]{0};

    uint32_t cached_cur_timestamp = 0;
    uint16_t cached_cur_seq = 0;

public:
    explicit RtpPacket(const RtpHeader &rtpHeader);

    RtpPacket(const RtpPacket &) = default;
    ~RtpPacket() = default;

    void load_data(const uint8_t *data, int64_t dataSize, int64_t bias = 0);
    int64_t rtp_sendto(int sockfd, int64_t _bufferLen, int flags, const sockaddr *to, uint32_t timeStampStep);

    void set_header_seq(const uint32_t _seq);
    void set_header_timestamp(const uint32_t _newtimestamp);

    uint8_t *get_payload() { return this->RTP_Payload; }
    uint32_t get_header_seq();
    uint32_t get_header_timestamp();
	int64_t get_packet_length() const {
		return RTP_HEADER_SIZE + FU_SIZE + MAX_RTP_DATA_SIZE;
	}
	const RtpHeader& get_header() const { return this->header; }
    RtpHeader& mutable_header() { return this->header; }
};
#pragma pack()
