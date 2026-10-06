/*
 * ============================================================
 * Reliable UDP File Receiver
 * ============================================================
 *
 * Compile:
 *
 *     gcc receiver.c -o receiver
 *
 * Run:
 *
 *     ./receiver
 *
 * No OpenSSL required.
 *
 * Protocol:
 *
 * START
 * START_ACK
 * DATA + sequence number
 * ACK
 * NACK
 * FIN
 * HASH_OK
 * HASH_BAD
 *
 * ============================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* ============================================================
 * CONFIGURATION
 * ============================================================
 */

#define PAYLOAD_SIZE       1000
#define MAX_PACKET_SIZE    1500

#define MAGIC              0x55445046
#define VERSION            1

#define SHA256_SIZE        32

#define START              1
#define START_ACK          2
#define DATA               3
#define ACK                4
#define NACK               5
#define FIN                6
#define HASH_OK            7
#define HASH_BAD           8

#define MAX_RESTARTS       10


/* ============================================================
 * PACKET HEADER
 * ============================================================
 */

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


/* ============================================================
 * SHA-256 STRUCTURE
 * ============================================================
 */

typedef struct
{
    uint8_t data[64];

    uint32_t datalen;

    uint64_t bitlen;

    uint32_t state[8];

} SHA256_CTX;


/* ============================================================
 * SHA-256 CONSTANTS
 *
 * EXACTLY 64 VALUES
 * ============================================================
 */

static const uint32_t K[64] =
{
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,

    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,

    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,

    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,

    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,

    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,

    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,

    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,

    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,

    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,

    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,

    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,

    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,

    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,

    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,

    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2
};


/* ============================================================
 * SHA-256 MACROS
 * ============================================================
 */

#define ROTRIGHT(a,b) \
    (((a) >> (b)) | ((a) << (32 - (b))))

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


/* ============================================================
 * SHA-256 HELPER
 * ============================================================
 */

static uint32_t load32_be(
    const uint8_t *p)
{
    return
        ((uint32_t)p[0] << 24) |
        ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8)  |
        ((uint32_t)p[3]);
}


static void store32_be(
    uint8_t *p,
    uint32_t x)
{
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}


/* ============================================================
 * SHA-256 TRANSFORM
 * ============================================================
 */

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
            load32_be(
                &data[i * 4]
            );
    }


    for(i = 16; i < 64; i++)
    {
        m[i] =
            SIG1(m[i - 2])
            + m[i - 7]
            + SIG0(m[i - 15])
            + m[i - 16];
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


/* ============================================================
 * SHA-256 INIT
 * ============================================================
 */

static void sha256_init(
    SHA256_CTX *ctx)
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


/* ============================================================
 * SHA-256 UPDATE
 * ============================================================
 */

static void sha256_update(
    SHA256_CTX *ctx,
    const uint8_t data[],
    size_t len)
{
    size_t i;

    for(i = 0; i < len; i++)
    {
        ctx->data[
            ctx->datalen
        ] = data[i];

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


/* ============================================================
 * SHA-256 FINAL
 * ============================================================
 */

static void sha256_final(
    SHA256_CTX *ctx,
    uint8_t hash[])
{
    uint32_t i;


    i = ctx->datalen;


    /*
     * Add 0x80.
     */

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


    /*
     * Add message length.
     */

    ctx->bitlen +=
        (uint64_t)ctx->datalen * 8;


    ctx->data[63] =
        (uint8_t)(ctx->bitlen);

    ctx->data[62] =
        (uint8_t)(ctx->bitlen >> 8);

    ctx->data[61] =
        (uint8_t)(ctx->bitlen >> 16);

    ctx->data[60] =
        (uint8_t)(ctx->bitlen >> 24);

    ctx->data[59] =
        (uint8_t)(ctx->bitlen >> 32);

    ctx->data[58] =
        (uint8_t)(ctx->bitlen >> 40);

    ctx->data[57] =
        (uint8_t)(ctx->bitlen >> 48);

    ctx->data[56] =
        (uint8_t)(ctx->bitlen >> 56);


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


/* ============================================================
 * PRINT SHA-256
 * ============================================================
 */

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


/* ============================================================
 * 64-BIT NETWORK BYTE ORDER
 * ============================================================
 */

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


static uint64_t ntohll(
    uint64_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

    return
        ((uint64_t)ntohl(
            (uint32_t)(x & 0xffffffffULL)
        ) << 32)
        |
        ntohl(
            (uint32_t)(x >> 32)
        );

#else

    return x;

#endif
}


/* ============================================================
 * SEND PACKET
 * ============================================================
 */

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


    if(payload_len > PAYLOAD_SIZE)
    {
        return -1;
    }


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


/* ============================================================
 * RECEIVE PACKET
 * ============================================================
 */

static int receive_packet(
    int sock,
    Header *h,
    unsigned char *payload,
    struct sockaddr_in *from)
{
    unsigned char buffer[
        MAX_PACKET_SIZE
    ];

    socklen_t addr_len =
        sizeof(*from);


    int n =
        recvfrom(
            sock,
            buffer,
            sizeof(buffer),
            0,
            (struct sockaddr *)from,
            &addr_len
        );


    if(n < (int)sizeof(Header))
    {
        return -1;
    }


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

    h->file_size =
        ntohll(net.file_size);


    if(h->magic != MAGIC)
    {
        return -1;
    }


    if(h->version != VERSION)
    {
        return -1;
    }


    if(h->payload_len > PAYLOAD_SIZE)
    {
        return -1;
    }


    if(
        sizeof(Header) +
        h->payload_len >
        (unsigned)n
    )
    {
        return -1;
    }


    if(h->payload_len > 0)
    {
        memcpy(
            payload,
            buffer + sizeof(Header),
            h->payload_len
        );
    }


    return 0;
}


/* ============================================================
 * MAIN
 * ============================================================
 */

int main(void)
{
    int port;

    char output_file[300];


    /* --------------------------------------------------------
     * USER INPUT
     * --------------------------------------------------------
     */

    printf(
        "Enter receiver port: "
    );

    if(scanf("%d", &port) != 1)
    {
        fprintf(
            stderr,
            "Invalid port.\n"
        );

        return 1;
    }


    printf(
        "Enter output file name: "
    );

    if(scanf(
        "%299s",
        output_file) != 1)
    {
        fprintf(
            stderr,
            "Invalid output filename.\n"
        );

        return 1;
    }


    /* --------------------------------------------------------
     * CREATE UDP SOCKET
     * --------------------------------------------------------
     */

    int sock =
        socket(
            AF_INET,
            SOCK_DGRAM,
            0
        );


    if(sock < 0)
    {
        perror("socket");

        return 1;
    }


    /* --------------------------------------------------------
     * ALLOW PORT REUSE
     * --------------------------------------------------------
     */

    int reuse = 1;


    setsockopt(
        sock,
        SOL_SOCKET,
        SO_REUSEADDR,
        &reuse,
        sizeof(reuse)
    );


    /* --------------------------------------------------------
     * BIND
     * --------------------------------------------------------
     */

    struct sockaddr_in local;


    memset(
        &local,
        0,
        sizeof(local)
    );


    local.sin_family =
        AF_INET;

    local.sin_addr.s_addr =
        htonl(INADDR_ANY);

    local.sin_port =
        htons(
            (uint16_t)port
        );


    if(bind(
        sock,
        (struct sockaddr *)&local,
        sizeof(local)) < 0)
    {
        perror("bind");

        close(sock);

        return 1;
    }


    printf(
        "\n"
        "============================================\n"
        "       RELIABLE UDP FILE RECEIVER\n"
        "============================================\n"
        "Listening on port: %d\n"
        "Output file       : %s\n"
        "============================================\n\n",
        port,
        output_file
    );


    /* ========================================================
     * WAIT FOR TRANSFER
     * ========================================================
     */

    while(1)
    {
        Header h;

        unsigned char payload[
            MAX_PACKET_SIZE
        ];

        struct sockaddr_in sender;


        /* ----------------------------------------------------
         * WAIT FOR START
         * ----------------------------------------------------
         */

        printf(
            "Waiting for START...\n"
        );


        while(1)
        {
            if(receive_packet(
                sock,
                &h,
                payload,
                &sender) < 0)
            {
                continue;
            }


            if(h.type == START)
            {
                break;
            }
        }


        /* ----------------------------------------------------
         * CHECK START
         * ----------------------------------------------------
         */

        if(h.payload_len != SHA256_SIZE)
        {
            printf(
                "Invalid START packet.\n"
            );

            continue;
        }


        uint32_t total_packets =
            h.total;


        uint64_t file_size =
            h.file_size;


        uint8_t expected_hash[
            SHA256_SIZE
        ];


        memcpy(
            expected_hash,
            payload,
            SHA256_SIZE
        );


        printf(
            "\nSTART received.\n"
        );


        printf(
            "File size     : %llu bytes\n",
            (unsigned long long)
            file_size
        );


        printf(
            "Total packets : %u\n",
            total_packets
        );


        printf(
            "Expected SHA-256:\n"
        );


        print_hash(
            expected_hash
        );


        /* ----------------------------------------------------
         * SEND START ACK
         * ----------------------------------------------------
         */

        send_packet(
            sock,
            &sender,
            START_ACK,
            0,
            0,
            total_packets,
            file_size,
            NULL,
            0
        );


        printf(
            "START_ACK sent.\n"
        );


        /* ====================================================
         * TRANSFER ATTEMPTS
         * ====================================================
         */

        int success = 0;


        for(
            int attempt = 1;
            attempt <= MAX_RESTARTS;
            attempt++)
        {
            printf(
                "\n"
                "--------------------------------------------\n"
                "Transfer attempt %d / %d\n"
                "--------------------------------------------\n",
                attempt,
                MAX_RESTARTS
            );


            /* ------------------------------------------------
             * OPEN FILE
             * ------------------------------------------------
             */

            FILE *fp =
                fopen(
                    output_file,
                    "wb"
                );


            if(fp == NULL)
            {
                perror("fopen");

                close(sock);

                return 1;
            }


            /* ------------------------------------------------
             * SHA CONTEXT
             * ------------------------------------------------
             */

            SHA256_CTX sha;

            sha256_init(
                &sha
            );


            uint32_t expected_seq =
                1;


            uint64_t bytes_received =
                0;


            /* =================================================
             * RECEIVE ALL DATA
             * =================================================
             */

            while(
                expected_seq <=
                total_packets)
            {
                if(receive_packet(
                    sock,
                    &h,
                    payload,
                    &sender) < 0)
                {
                    continue;
                }


                /* ---------------------------------------------
                 * DUPLICATE START
                 * ---------------------------------------------
                 */

                if(h.type == START)
                {
                    /*
                     * Sender may have retransmitted START
                     * because START_ACK was lost.
                     */

                    send_packet(
                        sock,
                        &sender,
                        START_ACK,
                        0,
                        0,
                        total_packets,
                        file_size,
                        NULL,
                        0
                    );


                    continue;
                }


                /* ---------------------------------------------
                 * DATA
                 * ---------------------------------------------
                 */

                if(h.type != DATA)
                {
                    continue;
                }


                /* ---------------------------------------------
                 * Validate transfer information
                 * ---------------------------------------------
                 */

                if(
                    h.total !=
                    total_packets
                )
                {
                    continue;
                }


                if(
                    h.file_size !=
                    file_size
                )
                {
                    continue;
                }


                /* ---------------------------------------------
                 * CORRECT PACKET
                 * ---------------------------------------------
                 */

                if(h.seq == expected_seq)
                {
                    size_t written =
                        fwrite(
                            payload,
                            1,
                            h.payload_len,
                            fp
                        );


                    if(written !=
                       h.payload_len)
                    {
                        perror("fwrite");

                        fclose(fp);

                        close(sock);

                        return 1;
                    }


                    sha256_update(
                        &sha,
                        payload,
                        h.payload_len
                    );


                    bytes_received +=
                        h.payload_len;


                    /* -----------------------------------------
                     * ACK
                     * -----------------------------------------
                     */

                    send_packet(
                        sock,
                        &sender,
                        ACK,
                        0,
                        expected_seq,
                        total_packets,
                        file_size,
                        NULL,
                        0
                    );


                    printf(
                        "DATA %u/%u -> ACK %u\n",
                        h.seq,
                        total_packets,
                        expected_seq
                    );


                    expected_seq++;
                }


                /* ---------------------------------------------
                 * FUTURE PACKET
                 * ---------------------------------------------
                 */

                else if(h.seq > expected_seq)
                {
                    printf(
                        "Missing packet %u "
                        "(received %u)\n",
                        expected_seq,
                        h.seq
                    );


                    /*
                     * NACK the missing packet.
                     */

                    send_packet(
                        sock,
                        &sender,
                        NACK,
                        0,
                        expected_seq,
                        total_packets,
                        file_size,
                        NULL,
                        0
                    );


                    printf(
                        "NACK %u sent.\n",
                        expected_seq
                    );
                }


                /* ---------------------------------------------
                 * DUPLICATE PACKET
                 * ---------------------------------------------
                 */

                else
                {
                    /*
                     * Packet was already received.
                     *
                     * Send ACK again.
                     */

                    send_packet(
                        sock,
                        &sender,
                        ACK,
                        0,
                        expected_seq - 1,
                        total_packets,
                        file_size,
                        NULL,
                        0
                    );


                    printf(
                        "Duplicate DATA %u -> "
                        "ACK %u\n",
                        h.seq,
                        expected_seq - 1
                    );
                }
            }


            /* =================================================
             * ALL DATA RECEIVED
             * =================================================
             */

            fflush(fp);


            printf(
                "\nAll data packets received.\n"
            );


            printf(
                "Bytes received: %llu\n",
                (unsigned long long)
                bytes_received
            );


            /* =================================================
             * WAIT FOR FIN
             * =================================================
             */

            printf(
                "Waiting for FIN...\n"
            );


            while(1)
            {
                if(receive_packet(
                    sock,
                    &h,
                    payload,
                    &sender) < 0)
                {
                    continue;
                }


                if(h.type == FIN)
                {
                    printf(
                        "FIN received.\n"
                    );

                    break;
                }


                /*
                 * Sender might retransmit last DATA
                 * if it did not receive the final ACK.
                 */

                if(h.type == DATA)
                {
                    if(
                        h.seq <
                        expected_seq
                    )
                    {
                        send_packet(
                            sock,
                            &sender,
                            ACK,
                            0,
                            expected_seq - 1,
                            total_packets,
                            file_size,
                            NULL,
                            0
                        );
                    }
                }
            }


            /* =================================================
             * FINISH SHA-256
             * =================================================
             */

            uint8_t received_hash[
                SHA256_SIZE
            ];


            sha256_final(
                &sha,
                received_hash
            );


            printf(
                "\nReceived SHA-256:\n"
            );


            print_hash(
                received_hash
            );


            printf(
                "Expected SHA-256:\n"
            );


            print_hash(
                expected_hash
            );


            /* =================================================
             * COMPARE HASH
             * =================================================
             */

            if(
                memcmp(
                    received_hash,
                    expected_hash,
                    SHA256_SIZE
                ) == 0
            )
            {
                /* ---------------------------------------------
                 * SUCCESS
                 * ---------------------------------------------
                 */

                printf(
                    "\n"
                    "============================================\n"
                    "           SHA-256 MATCH\n"
                    "        FILE VERIFIED SUCCESSFULLY\n"
                    "============================================\n"
                );


                fclose(fp);


                /* ---------------------------------------------
                 * HASH_OK
                 * ---------------------------------------------
                 */

                send_packet(
                    sock,
                    &sender,
                    HASH_OK,
                    total_packets,
                    total_packets,
                    total_packets,
                    file_size,
                    NULL,
                    0
                );


                /*
                 * Send it multiple times because UDP can
                 * lose the HASH_OK packet.
                 */

                usleep(100000);


                send_packet(
                    sock,
                    &sender,
                    HASH_OK,
                    total_packets,
                    total_packets,
                    total_packets,
                    file_size,
                    NULL,
                    0
                );


                usleep(100000);


                send_packet(
                    sock,
                    &sender,
                    HASH_OK,
                    total_packets,
                    total_packets,
                    total_packets,
                    file_size,
                    NULL,
                    0
                );


                printf(
                    "HASH_OK sent.\n"
                );


                printf(
                    "File saved as: %s\n",
                    output_file
                );


                success = 1;

                break;
            }


            /* =================================================
             * HASH MISMATCH
             * =================================================
             */

            printf(
                "\n"
                "============================================\n"
                "          SHA-256 MISMATCH\n"
                "============================================\n"
            );


            printf(
                "Requesting complete retransmission...\n"
            );


            fclose(fp);


            /*
             * Delete corrupted/incomplete file.
             */

            remove(
                output_file
            );


            /* ---------------------------------------------
             * HASH_BAD
             * ---------------------------------------------
             */

            send_packet(
                sock,
                &sender,
                HASH_BAD,
                total_packets,
                0,
                total_packets,
                file_size,
                NULL,
                0
            );


            /*
             * Send HASH_BAD again in case the first one
             * is lost.
             */

            usleep(100000);


            send_packet(
                sock,
                &sender,
                HASH_BAD,
                total_packets,
                0,
                total_packets,
                file_size,
                NULL,
                0
            );


            printf(
                "HASH_BAD sent.\n"
            );


            printf(
                "Waiting for complete retransmission...\n"
            );
        }


        /* ====================================================
         * FINAL RESULT
         * ====================================================
         */

        if(success)
        {
            printf(
                "\n"
                "============================================\n"
                "          TRANSFER COMPLETE\n"
                "============================================\n"
            );

            break;
        }


        printf(
            "\n"
            "Transfer failed after %d attempts.\n",
            MAX_RESTARTS
        );


        break;
    }


    close(sock);

    return 0;
}
