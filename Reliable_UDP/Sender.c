/*
 * Reliable UDP File Sender
 *
 * Compile:
 *     gcc sender.c -o sender
 *
 * Run:
 *     ./sender
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>


/* =========================================================
   CONFIGURATION
   ========================================================= */

#define PAYLOAD_SIZE    1000
#define MAX_PACKET_SIZE 1500

#define WINDOW_SIZE     5

#define MAGIC           0x55445046
#define VERSION         1

#define SHA256_SIZE     32

#define START           1
#define START_ACK       2
#define DATA            3
#define ACK             4
#define NACK            5
#define FIN             6
#define HASH_OK         7
#define HASH_BAD        8

#define TIMEOUT_SEC     2
#define MAX_RETRIES     10


/* =========================================================
   PACKET HEADER
   ========================================================= */

#pragma pack(push, 1)

typedef struct
{
    uint32_t magic;
    uint16_t type;
    uint16_t version;

    uint32_t seq;
    uint32_t ack;
    uint32_t total;

    uint16_t payload_len;
    uint16_t reserved;

    uint64_t file_size;

} Header;

#pragma pack(pop)


/* =========================================================
   SHA-256
   ========================================================= */

typedef struct
{
    uint8_t data[64];

    uint32_t datalen;

    uint64_t bitlen;

    uint32_t state[8];

} SHA256_CTX;


/*
 * EXACTLY 64 SHA-256 constants.
 */

static const uint32_t K[64] =
{
    0x428a2f98, 0x71374491,
    0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d,
    0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138,
    0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb,
    0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624,
    0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f,
    0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb,
    0xbef9a3f7, 0xc67178f2
};


#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) \
    (((x) & (y)) ^ (~(x) & (z)))

#define MAJ(x,y,z) \
    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define EP0(x) \
    (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))

#define EP1(x) \
    (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))

#define SIG0(x) \
    (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))

#define SIG1(x) \
    (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))


static uint32_t load32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3]);
}


static void store32_be(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}


static void sha256_transform(
    SHA256_CTX *ctx,
    const uint8_t data[])
{
    uint32_t a, b, c, d;
    uint32_t e, f, g, h;

    uint32_t t1, t2;

    uint32_t m[64];

    int i;

    for(i = 0; i < 16; i++)
    {
        m[i] =
            load32_be(&data[i * 4]);
    }

    for(i = 16; i < 64; i++)
    {
        m[i] =
            SIG1(m[i - 2]) +
            m[i - 7] +
            SIG0(m[i - 15]) +
            m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];

    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for(i = 0; i < 64; i++)
    {
        t1 =
            h +
            EP1(e) +
            CH(e, f, g) +
            K[i] +
            m[i];

        t2 =
            EP0(a) +
            MAJ(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;

        d = c;
        c = b;
        b = a;

        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;

    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}


static void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;

    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}


static void sha256_update(
    SHA256_CTX *ctx,
    const uint8_t data[],
    size_t len)
{
    size_t i;

    for(i = 0; i < len; i++)
    {
        ctx->data[ctx->datalen] =
            data[i];

        ctx->datalen++;

        if(ctx->datalen == 64)
        {
            sha256_transform(
                ctx,
                ctx->data
            );

            ctx->bitlen += 512;

            ctx->datalen = 0;
        }
    }
}


static void sha256_final(
    SHA256_CTX *ctx,
    uint8_t hash[])
{
    uint32_t i;

    i = ctx->datalen;

    if(ctx->datalen < 56)
    {
        ctx->data[i++] = 0x80;

        while(i < 56)
            ctx->data[i++] = 0;
    }
    else
    {
        ctx->data[i++] = 0x80;

        while(i < 64)
            ctx->data[i++] = 0;

        sha256_transform(
            ctx,
            ctx->data
        );

        memset(
            ctx->data,
            0,
            56
        );
    }

    ctx->bitlen +=
        ctx->datalen * 8;

    ctx->data[63] =
        ctx->bitlen;

    ctx->data[62] =
        ctx->bitlen >> 8;

    ctx->data[61] =
        ctx->bitlen >> 16;

    ctx->data[60] =
        ctx->bitlen >> 24;

    ctx->data[59] =
        ctx->bitlen >> 32;

    ctx->data[58] =
        ctx->bitlen >> 40;

    ctx->data[57] =
        ctx->bitlen >> 48;

    ctx->data[56] =
        ctx->bitlen >> 56;

    sha256_transform(
        ctx,
        ctx->data
    );

    for(i = 0; i < 8; i++)
    {
        store32_be(
            &hash[i * 4],
            ctx->state[i]
        );
    }
}


static void print_hash(
    const uint8_t hash[])
{
    int i;

    for(i = 0; i < SHA256_SIZE; i++)
    {
        printf(
            "%02x",
            hash[i]
        );
    }

    printf("\n");
}


/* =========================================================
   64-BIT NETWORK CONVERSION
   ========================================================= */

static uint64_t htonll(
    uint64_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

    return
        ((uint64_t)htonl(
            (uint32_t)(x & 0xffffffffULL)
        ) << 32)
        |
        htonl(
            (uint32_t)(x >> 32)
        );

#else

    return x;

#endif
}


/* =========================================================
   SEND PACKET
   ========================================================= */

static int send_packet(
    int sock,
    struct sockaddr_in *addr,
    uint16_t type,
    uint32_t seq,
    uint32_t ack,
    uint32_t total,
    uint64_t file_size,
    const void *payload,
    uint16_t payload_len)
{
    unsigned char buffer[
        MAX_PACKET_SIZE
    ];

    Header h;

    memset(
        &h,
        0,
        sizeof(h)
    );

    h.magic =
        htonl(MAGIC);

    h.type =
        htons(type);

    h.version =
        htons(VERSION);

    h.seq =
        htonl(seq);

    h.ack =
        htonl(ack);

    h.total =
        htonl(total);

    h.payload_len =
        htons(payload_len);

    h.file_size =
        htonll(file_size);

    memcpy(
        buffer,
        &h,
        sizeof(h)
    );

    if(payload_len > 0)
    {
        memcpy(
            buffer + sizeof(h),
            payload,
            payload_len
        );
    }

    return sendto(
        sock,
        buffer,
        sizeof(h) + payload_len,
        0,
        (struct sockaddr *)addr,
        sizeof(*addr)
    );
}


/* =========================================================
   RECEIVE CONTROL PACKET
   ========================================================= */

static int receive_control(
    int sock,
    Header *h)
{
    unsigned char buffer[
        MAX_PACKET_SIZE
    ];

    struct sockaddr_in from;

    socklen_t len =
        sizeof(from);

    int n =
        recvfrom(
            sock,
            buffer,
            sizeof(buffer),
            0,
            (struct sockaddr *)&from,
            &len
        );

    if(n < (int)sizeof(Header))
        return -1;

    Header net;

    memcpy(
        &net,
        buffer,
        sizeof(Header)
    );

    h->magic =
        ntohl(net.magic);

    h->type =
        ntohs(net.type);

    h->version =
        ntohs(net.version);

    h->seq =
        ntohl(net.seq);

    h->ack =
        ntohl(net.ack);

    h->total =
        ntohl(net.total);

    h->payload_len =
        ntohs(net.payload_len);

    if(h->magic != MAGIC)
        return -1;

    if(h->version != VERSION)
        return -1;

    return 0;
}


/* =========================================================
   SOCKET TIMEOUT
   ========================================================= */

static void set_timeout(
    int sock)
{
    struct timeval tv;

    tv.tv_sec =
        TIMEOUT_SEC;

    tv.tv_usec = 0;

    setsockopt(
        sock,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &tv,
        sizeof(tv)
    );
}


/* =========================================================
   MAIN
   ========================================================= */

int main(void)
{
    char filename[300];

    char receiver_ip[100];

    int port;

    printf(
        "Enter file name: "
    );

    if(scanf(
        "%299s",
        filename) != 1)
    {
        return 1;
    }

    printf(
        "Enter receiver IP: "
    );

    if(scanf(
        "%99s",
        receiver_ip) != 1)
    {
        return 1;
    }

    printf(
        "Enter receiver port: "
    );

    if(scanf(
        "%d",
        &port) != 1)
    {
        return 1;
    }


    /* -----------------------------------------------------
       OPEN FILE
       ----------------------------------------------------- */

    FILE *fp =
        fopen(
            filename,
            "rb"
        );

    if(fp == NULL)
    {
        perror("fopen");
        return 1;
    }


    /* -----------------------------------------------------
       FILE SIZE
       ----------------------------------------------------- */

    if(fseek(
        fp,
        0,
        SEEK_END) != 0)
    {
        perror("fseek");

        fclose(fp);

        return 1;
    }

    long file_size_long =
        ftell(fp);

    if(file_size_long < 0)
    {
        perror("ftell");

        fclose(fp);

        return 1;
    }

    uint64_t file_size =
        (uint64_t)file_size_long;

    fseek(
        fp,
        0,
        SEEK_SET
    );


    /* -----------------------------------------------------
       NUMBER OF DATAGRAMS
       ----------------------------------------------------- */

    uint32_t total_packets;

    if(file_size == 0)
    {
        total_packets = 0;
    }
    else
    {
        total_packets =
            (uint32_t)(
                (file_size +
                 PAYLOAD_SIZE - 1)
                /
                PAYLOAD_SIZE
            );
    }


    printf(
        "\nFile size     : %llu bytes\n",
        (unsigned long long)
        file_size
    );

    printf(
        "Total packets : %u\n",
        total_packets
    );


    /* -----------------------------------------------------
       SHA-256
       ----------------------------------------------------- */

    SHA256_CTX sha;

    uint8_t file_hash[
        SHA256_SIZE
    ];

    unsigned char hash_buffer[
        PAYLOAD_SIZE
    ];

    sha256_init(
        &sha
    );

    size_t n;

    while(
        (n = fread(
            hash_buffer,
            1,
            PAYLOAD_SIZE,
            fp
        )) > 0)
    {
        sha256_update(
            &sha,
            hash_buffer,
            n
        );
    }

    sha256_final(
        &sha,
        file_hash
    );

    printf(
        "SHA-256:\n"
    );

    print_hash(
        file_hash
    );

    fseek(
        fp,
        0,
        SEEK_SET
    );


    /* -----------------------------------------------------
       SOCKET
       ----------------------------------------------------- */

    int sock =
        socket(
            AF_INET,
            SOCK_DGRAM,
            0
        );

    if(sock < 0)
    {
        perror("socket");

        fclose(fp);

        return 1;
    }


    /* -----------------------------------------------------
       RECEIVER ADDRESS
       ----------------------------------------------------- */

    struct sockaddr_in receiver;

    memset(
        &receiver,
        0,
        sizeof(receiver)
    );

    receiver.sin_family =
        AF_INET;

    receiver.sin_port =
        htons(
            (uint16_t)port
        );

    if(inet_pton(
        AF_INET,
        receiver_ip,
        &receiver.sin_addr) <= 0)
    {
        printf(
            "Invalid receiver IP.\n"
        );

        close(sock);

        fclose(fp);

        return 1;
    }


    set_timeout(
        sock
    );


    /* =====================================================
       START HANDSHAKE
       ===================================================== */

    int start_ok = 0;

    for(
        int retry = 1;
        retry <= MAX_RETRIES;
        retry++)
    {
        printf(
            "\nSending START "
            "(attempt %d)\n",
            retry
        );

        send_packet(
            sock,
            &receiver,
            START,
            0,
            0,
            total_packets,
            file_size,
            file_hash,
            SHA256_SIZE
        );

        Header response;

        if(receive_control(
            sock,
            &response) == 0)
        {
            if(response.type ==
               START_ACK)
            {
                printf(
                    "START_ACK received.\n"
                );

                start_ok = 1;

                break;
            }
        }

        printf(
            "START timeout.\n"
        );
    }


    if(!start_ok)
    {
        printf(
            "Could not contact receiver.\n"
        );

        close(sock);

        fclose(fp);

        return 1;
    }


    /* =====================================================
       COMPLETE FILE RETRANSMISSION LOOP
       ===================================================== */

    int transfer_success = 0;

    for(
        int attempt = 1;
        attempt <= MAX_RETRIES;
        attempt++)
    {
        printf(
            "\n"
            "====================================\n"
            "FILE TRANSFER ATTEMPT %d\n"
            "====================================\n",
            attempt
        );


        fseek(
            fp,
            0,
            SEEK_SET
        );


        uint32_t base = 1;

        uint32_t next_seq = 1;


        /*
         * Packet window.
         */

        unsigned char window[
            WINDOW_SIZE
        ][PAYLOAD_SIZE];

        uint16_t lengths[
            WINDOW_SIZE
        ];


        /* =================================================
           DATA TRANSFER
           ================================================= */

        while(
            base <= total_packets)
        {
            /*
             * Fill the sending window.
             */

            while(
                next_seq <
                base + WINDOW_SIZE &&
                next_seq <=
                total_packets)
            {
                uint64_t offset =
                    ((uint64_t)
                     (next_seq - 1))
                    *
                    PAYLOAD_SIZE;

                uint64_t remaining =
                    file_size -
                    offset;

                uint16_t payload_len =
                    remaining >
                    PAYLOAD_SIZE
                    ?
                    PAYLOAD_SIZE
                    :
                    (uint16_t)
                    remaining;


                /*
                 * Read packet from file.
                 */

                if(fseek(
                    fp,
                    (long)offset,
                    SEEK_SET) != 0)
                {
                    perror("fseek");

                    close(sock);

                    fclose(fp);

                    return 1;
                }

                size_t read_count =
                    fread(
                        window[
                            next_seq %
                            WINDOW_SIZE
                        ],
                        1,
                        payload_len,
                        fp
                    );

                if(read_count !=
                   payload_len)
                {
                    perror("fread");

                    close(sock);

                    fclose(fp);

                    return 1;
                }

                lengths[
                    next_seq %
                    WINDOW_SIZE
                ] =
                    payload_len;


                /*
                 * Send DATA.
                 */

                send_packet(
                    sock,
                    &receiver,
                    DATA,
                    next_seq,
                    0,
                    total_packets,
                    file_size,
                    window[
                        next_seq %
                        WINDOW_SIZE
                    ],
                    payload_len
                );

                printf(
                    "DATA %u sent\n",
                    next_seq
                );

                next_seq++;
            }


            /* ---------------------------------------------
               WAIT FOR ACK/NACK
               --------------------------------------------- */

            Header response;

            if(receive_control(
                sock,
                &response) < 0)
            {
                /*
                 * Timeout.
                 *
                 * Go-Back-N:
                 * resend all outstanding packets.
                 */

                printf(
                    "Timeout. "
                    "Go-Back-N retransmission "
                    "%u-%u\n",
                    base,
                    next_seq - 1
                );

                for(
                    uint32_t i = base;
                    i < next_seq;
                    i++)
                {
                    send_packet(
                        sock,
                        &receiver,
                        DATA,
                        i,
                        0,
                        total_packets,
                        file_size,
                        window[
                            i %
                            WINDOW_SIZE
                        ],
                        lengths[
                            i %
                            WINDOW_SIZE
                        ]
                    );

                    printf(
                        "RE-SENT DATA %u\n",
                        i
                    );
                }

                continue;
            }


            /* ---------------------------------------------
               ACK
               --------------------------------------------- */

            if(response.type ==
               ACK)
            {
                uint32_t ack =
                    response.ack;

                printf(
                    "ACK %u received\n",
                    ack
                );

                if(
                    ack >= base &&
                    ack < next_seq)
                {
                    base =
                        ack + 1;
                }

                continue;
            }


            /* ---------------------------------------------
               NACK
               --------------------------------------------- */

            if(response.type ==
               NACK)
            {
                uint32_t missing =
                    response.ack;

                printf(
                    "NACK %u received\n",
                    missing
                );

                if(
                    missing >= base &&
                    missing < next_seq)
                {
                    /*
                     * Go-Back-N:
                     * retransmit missing packet
                     * and everything after it.
                     */

                    for(
                        uint32_t i =
                            missing;
                        i < next_seq;
                        i++)
                    {
                        send_packet(
                            sock,
                            &receiver,
                            DATA,
                            i,
                            0,
                            total_packets,
                            file_size,
                            window[
                                i %
                                WINDOW_SIZE
                            ],
                            lengths[
                                i %
                                WINDOW_SIZE
                            ]
                        );

                        printf(
                            "RE-SENT DATA %u\n",
                            i
                        );
                    }
                }

                continue;
            }
        }


        printf(
            "\nAll DATA packets ACKed.\n"
        );


        /* =================================================
           FIN
           ================================================= */

        int restart_transfer = 0;

        for(
            int fin_retry = 1;
            fin_retry <= MAX_RETRIES;
            fin_retry++)
        {
            printf(
                "FIN sent "
                "(attempt %d)\n",
                fin_retry
            );

            send_packet(
                sock,
                &receiver,
                FIN,
                total_packets + 1,
                total_packets,
                total_packets,
                file_size,
                NULL,
                0
            );

            Header response;

            if(receive_control(
                sock,
                &response) < 0)
            {
                printf(
                    "FIN timeout.\n"
                );

                continue;
            }


            /* ---------------------------------------------
               HASH OK
               --------------------------------------------- */

            if(response.type ==
               HASH_OK)
            {
                printf(
                    "\n"
                    "====================================\n"
                    "SHA-256 MATCH\n"
                    "FILE TRANSFER SUCCESSFUL\n"
                    "====================================\n"
                );

                transfer_success = 1;

                break;
            }


            /* ---------------------------------------------
               HASH BAD
               --------------------------------------------- */

            if(response.type ==
               HASH_BAD)
            {
                printf(
                    "\n"
                    "Receiver reported "
                    "SHA-256 mismatch.\n"
                );

                printf(
                    "Complete retransmission "
                    "requested.\n"
                );

                restart_transfer = 1;

                break;
            }
        }


        if(transfer_success)
            break;


        if(restart_transfer)
        {
            printf(
                "Restarting DATA transfer...\n"
            );

            continue;
        }


        printf(
            "FIN acknowledgement failed.\n"
        );
    }


    /* =====================================================
       RESULT
       ===================================================== */

    if(transfer_success)
    {
        printf(
            "\nTransfer completed successfully.\n"
        );
    }
    else
    {
        printf(
            "\nTransfer failed after "
            "maximum retries.\n"
        );
    }


    fclose(fp);

    close(sock);

    return transfer_success
        ? 0
        : 1;
}
