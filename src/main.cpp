#include <rtsp.hpp>

#include <iostream>
#include <cstdlib>

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stdout, "usage: %s <file name> <fps>\n", argv[0]);
        return 1;
    }
    RTSP rtspServer(argv[1]);
    rtspServer.Start(20001102, "rpi5_picamera", 600, atof(argv[2]));

    return 0;
}
