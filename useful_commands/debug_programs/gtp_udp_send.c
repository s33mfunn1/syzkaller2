/*
 * Простая отправка GTP пакета через обычный UDP сокет (без TAP).
 * Обходит проблемы маршрутизации - шлёт напрямую на 127.0.0.1:2152.
 *
 * gcc -o gtp_udp_send gtp_udp_send.c
 * sudo ./gtp_udp_send
 */
 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/socket.h>
 #include <unistd.h>
 
 #define GTP1U_PORT 2152
 #define GTP_TPDU   255
 
 int main(void)
 {
     unsigned char gtp_buf[64];
     int sock;
     struct sockaddr_in addr = {
         .sin_family = AF_INET,
         .sin_port   = htons(GTP1U_PORT),
         .sin_addr   = { .s_addr = htonl(INADDR_LOOPBACK) },
     };
 
     /* GTP1-U header: flags=0x30, type=TPDU, length=20, tid=0xdeadbeef */
     gtp_buf[0] = 0x30;
     gtp_buf[1] = GTP_TPDU;
     *(unsigned short *)(gtp_buf + 2) = htons(20);
     *(unsigned int *)(gtp_buf + 4) = htonl(0xdeadbeef);
     /* + 20 bytes minimal inner IP */
     memset(gtp_buf + 8, 0, 20);
 
     sock = socket(AF_INET, SOCK_DGRAM, 0);
     if (sock < 0) {
         perror("socket");
         return 1;
     }
 
     if (sendto(sock, gtp_buf, 28, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
         perror("sendto");
         close(sock);
         return 1;
     }
 
     printf("Sent 28 bytes GTP packet to 127.0.0.1:%d\n", GTP1U_PORT);
     close(sock);
     return 0;
 }
 