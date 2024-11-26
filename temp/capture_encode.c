#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/videodev2.h>
#include <pthread.h>

#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libavutil/error.h>
#include <libswscale/swscale.h>

#define VIDEODEV "/dev/video0"
#define WIDTH 800
#define HEIGHT 600
#define FRAME_COUNT 60
#define OUTPUT_FILENAME "output.h264"

struct buffer {
	void *start;
	size_t length;
};

static struct buffer *buffers = NULL;
static unsigned int n_buffers = 0;

typedef struct {
	unsigned char *y_data[FRAME_COUNT];
	unsigned char *u_data[FRAME_COUNT];
	unsigned char *v_data[FRAME_COUNT];
	int count;
	pthread_mutex_t lock;
} YUV420Buffer;

// 전역 YUV420 버퍼
YUV420Buffer yuv420_buffer = {.count = 0, .lock = PTHREAD_MUTEX_INITIALIZER};

static void xioctl(int fd, int request, void *arg);
static void init_device(int fd);
static void init_mmap(int fd);

void *capture_frames(void *arg);
void *encode_frames(void *arg);

int main()
{
    	pthread_t capture_thread, encode_thread;

    	pthread_create(&capture_thread, NULL, capture_frames, NULL);
    	pthread_create(&encode_thread, NULL, encode_frames, NULL);

    	pthread_join(capture_thread, NULL);
    	pthread_join(encode_thread, NULL);

    	return 0;
}

static void xioctl(int fd, int request, void *arg)
{
    	int r;
    	do {
        	r = ioctl(fd, request, arg);
    	} while (r == -1 && (errno == EINTR || errno == EAGAIN));

	if (r == -1) {
        	perror("xioctl: ");
        	exit(EXIT_FAILURE);
	}
}

static void init_device(int fd)
{
    	struct v4l2_format fmt;
    	memset(&fmt, 0, sizeof(fmt));

    	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    	fmt.fmt.pix.width = WIDTH;
    	fmt.fmt.pix.height = HEIGHT;
    	fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
    	fmt.fmt.pix.field = V4L2_FIELD_NONE;
    	xioctl(fd, VIDIOC_S_FMT, &fmt);

    	if (fmt.fmt.pix.pixelformat != V4L2_PIX_FMT_YUYV) {
        	fprintf(stderr, "Unsupported Format.\n");
        	exit(EXIT_FAILURE);
    	}

    	if (fmt.fmt.pix.width != WIDTH || fmt.fmt.pix.height != HEIGHT) {
        	fprintf(stderr, "Unsupported Resolution.\n");
        	exit(EXIT_FAILURE);
    	}

    	printf("Device Initialization Complete: %dx%d YUYV\n", WIDTH, HEIGHT);
    	init_mmap(fd);
}

static void init_mmap(int fd) {
    struct v4l2_requestbuffers req;
    memset(&req, 0, sizeof(req));

    req.count = 6;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    xioctl(fd, VIDIOC_REQBUFS, &req);

    if (req.count < 2) {
        fprintf(stderr, "At least 2 buffers required for Memory Mapping.\n");
        exit(EXIT_FAILURE);
    }

    if (!(buffers = calloc(req.count, sizeof(*buffers)))) {
        fprintf(stderr, "Out of memory\n");
        exit(EXIT_FAILURE);
    }

    for (n_buffers = 0; n_buffers < req.count; n_buffers++) {
        struct v4l2_buffer buf;
        memset(&buf, 0, sizeof(buf));

        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = n_buffers;
        xioctl(fd, VIDIOC_QUERYBUF, &buf);

        buffers[n_buffers].length = buf.length;
        buffers[n_buffers].start = mmap(NULL, buf.length, PROT_READ | PROT_WRITE,
	                                MAP_SHARED, fd, buf.m.offset);
        if (buffers[n_buffers].start == MAP_FAILED) {
            perror("mmap: ");
            exit(EXIT_FAILURE);
        }
    }

    printf("Memory Mapping Complete.\n");
}

void *capture_frames(void *arg) {
    int fd = open(VIDEODEV, O_RDWR | O_NONBLOCK, 0);
    if (fd == -1) {
        perror("비디오 장치 열기 실패");
        return NULL;
    }

    init_device(fd);

    for (unsigned int i = 0; i < n_buffers; i++) {
        struct v4l2_buffer buf;
        memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;

        xioctl(fd, VIDIOC_QBUF, &buf);
    }

    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    xioctl(fd, VIDIOC_STREAMON, &type);

    printf("스트리밍 시작\n");

    struct SwsContext *img_convert_ctx = sws_getContext(
        WIDTH, HEIGHT, AV_PIX_FMT_YUYV422,
        WIDTH, HEIGHT, AV_PIX_FMT_YUV420P,
        SWS_BICUBIC, NULL, NULL, NULL
    );
    if (!img_convert_ctx) {
        fprintf(stderr, "sws_getContext 초기화 실패\n");
        close(fd);
        return NULL;
    }

    AVFrame *pFrameIn = av_frame_alloc();
    if (!pFrameIn) {
        fprintf(stderr, "입력 프레임 할당 실패\n");
        sws_freeContext(img_convert_ctx);
        close(fd);
        return NULL;
    }
    pFrameIn->format = AV_PIX_FMT_YUYV422;
    pFrameIn->width = WIDTH;
    pFrameIn->height = HEIGHT;
    av_frame_get_buffer(pFrameIn, 1);

    AVFrame *pFrameOut = av_frame_alloc();
    if (!pFrameOut) {
        fprintf(stderr, "출력 프레임 할당 실패\n");
        av_frame_free(&pFrameIn);
        sws_freeContext(img_convert_ctx);
        close(fd);
        return NULL;
    }
    pFrameOut->format = AV_PIX_FMT_YUV420P;
    pFrameOut->width = WIDTH;
    pFrameOut->height = HEIGHT;
    av_frame_get_buffer(pFrameOut, 1);

    while (1) {
        struct v4l2_buffer buf;
        memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;

        xioctl(fd, VIDIOC_DQBUF, &buf);

        av_image_fill_arrays(pFrameIn->data, pFrameIn->linesize, buffers[buf.index].start, 
                             AV_PIX_FMT_YUYV422, WIDTH, HEIGHT, 1);

        sws_scale(img_convert_ctx, 
                  (const uint8_t * const *)pFrameIn->data, pFrameIn->linesize,
                  0, HEIGHT, pFrameOut->data, pFrameOut->linesize);

        pthread_mutex_lock(&yuv420_buffer.lock);
        if (yuv420_buffer.count < FRAME_COUNT) {
            yuv420_buffer.y_data[yuv420_buffer.count] = malloc(WIDTH * HEIGHT);
            yuv420_buffer.u_data[yuv420_buffer.count] = malloc(WIDTH * HEIGHT / 4);
            yuv420_buffer.v_data[yuv420_buffer.count] = malloc(WIDTH * HEIGHT / 4);

            memcpy(yuv420_buffer.y_data[yuv420_buffer.count], pFrameOut->data[0], WIDTH * HEIGHT);
            memcpy(yuv420_buffer.u_data[yuv420_buffer.count], pFrameOut->data[1], WIDTH * HEIGHT / 4);
            memcpy(yuv420_buffer.v_data[yuv420_buffer.count], pFrameOut->data[2], WIDTH * HEIGHT / 4);

            yuv420_buffer.count++;
            printf("프레임 추가, 현재 버퍼 크기: %d\n", yuv420_buffer.count);
        }
        pthread_mutex_unlock(&yuv420_buffer.lock);

        xioctl(fd, VIDIOC_QBUF, &buf);
    }

    av_frame_free(&pFrameIn);
    av_frame_free(&pFrameOut);
    sws_freeContext(img_convert_ctx);
    close(fd);
    return NULL;
}

void *encode_frames(void *arg) {
    const AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_H264);
    if (!codec) {
        fprintf(stderr, "Can not find H.264 Codec\n");
        return NULL;
    }

    AVCodecContext *c = avcodec_alloc_context3(codec);
    if (!c) {
        fprintf(stderr, "코덱 컨텍스트 할당 실패.\n");
        return NULL;
    }

    c->bit_rate = 400000;
    c->width = WIDTH;
    c->height = HEIGHT;
    c->time_base = (AVRational){1, 30};
    c->framerate = (AVRational){30, 1};
    c->gop_size = 30;
    c->max_b_frames = 0;
    c->pix_fmt = AV_PIX_FMT_YUV420P;

    if (avcodec_open2(c, codec, NULL) < 0) {
        fprintf(stderr, "코덱 열기 실패.\n");
        avcodec_free_context(&c);
        return NULL;
    }

    FILE *f = fopen(OUTPUT_FILENAME, "wb");
    if (!f) {
        perror("출력 파일 열기 실패");
        avcodec_free_context(&c);
        return NULL;
    }

    AVFrame *frame = av_frame_alloc();
    if (!frame) {
        fprintf(stderr, "프레임 할당 실패.\n");
        fclose(f);
        avcodec_free_context(&c);
        return NULL;
    }

    frame->format = c->pix_fmt;
    frame->width = c->width;
    frame->height = c->height;

    if (av_image_alloc(frame->data, frame->linesize, c->width, c->height, c->pix_fmt, 32) < 0) {
        fprintf(stderr, "이미지 버퍼 할당 실패.\n");
        av_frame_free(&frame);
        fclose(f);
        avcodec_free_context(&c);
        return NULL;
    }

    AVPacket *pkt = av_packet_alloc();
    if (!pkt) {
        fprintf(stderr, "패킷 할당 실패.\n");
        av_freep(&frame->data[0]);
        av_frame_free(&frame);
        fclose(f);
        avcodec_free_context(&c);
        return NULL;
    }

    printf("H.264 인코딩 스레드 시작\n");

    while (1) {
        pthread_mutex_lock(&yuv420_buffer.lock);
        if (yuv420_buffer.count >= FRAME_COUNT) {
            printf("버퍼 가득 참: 인코딩 시작\n");
            for (int i = 0; i < FRAME_COUNT; i++) {
                unsigned char *Y_plane = yuv420_buffer.y_data[i];
                unsigned char *U_plane = yuv420_buffer.u_data[i];
                unsigned char *V_plane = yuv420_buffer.v_data[i];

                // 프레임 데이터 채우기 (linesize 고려)
                for (int y = 0; y < HEIGHT; y++) {
                    memcpy(frame->data[0] + y * frame->linesize[0], Y_plane + y * WIDTH, WIDTH);
                }

                int chroma_height = HEIGHT / 2;
                int chroma_width = WIDTH / 2;
                for (int y = 0; y < chroma_height; y++) {
                    memcpy(frame->data[1] + y * frame->linesize[1], U_plane + y * chroma_width, chroma_width);
                    memcpy(frame->data[2] + y * frame->linesize[2], V_plane + y * chroma_width, chroma_width);
                }

                frame->pts = i;

                // 프레임을 인코더로 전송
                if (avcodec_send_frame(c, frame) < 0) {
                    fprintf(stderr, "프레임 전송 실패\n");
                }

                // 인코더로부터 패킷 수신 및 파일에 기록
                while (avcodec_receive_packet(c, pkt) == 0) {
                    fwrite(pkt->data, 1, pkt->size, f);
                    av_packet_unref(pkt);
                }

                free(yuv420_buffer.y_data[i]);
                free(yuv420_buffer.u_data[i]);
                free(yuv420_buffer.v_data[i]);
            }
            yuv420_buffer.count = 0;
        }
        pthread_mutex_unlock(&yuv420_buffer.lock);
        usleep(1000); // CPU 사용량 조절
    }

    fclose(f);
    av_packet_free(&pkt);
    av_freep(&frame->data[0]);
    av_frame_free(&frame);
    avcodec_free_context(&c);

    printf("인코딩 완료, 인코딩 스레드 종료\n");
    return NULL;
}