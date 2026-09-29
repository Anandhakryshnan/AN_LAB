#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main(int argc, char const *argv[]) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];
    char *server_ip = "127.0.0.1"; // Default to localhost

    if (argc > 1) {
        server_ip = (char *)argv[1];
    }

    // 1. Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n[X] Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // 2. Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        printf("\n[X] Invalid address/ Address not supported \n");
        return -1;
    }

    // 3. Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\n[X] Connection Failed \n");
        return -1;
    }

    printf("[+] Connected to the server at %s:%d\n", server_ip, PORT);
    printf("[*] Type your messages below (Type 'exit' to quit):\n\n");

    // 4. Fork process for bidirectional communication
    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        // Child Process: Handles Sending data to Server
        while (1) {
            memset(buffer, 0, BUFFER_SIZE);
            fgets(buffer, BUFFER_SIZE, stdin);
            send(sock, buffer, strlen(buffer), 0);
            
            if (strncmp(buffer, "exit", 4) == 0) {
                printf("[*] Closing connection...\n");
                kill(getppid(), SIGTERM);
                break;
            }
        }
    } else {
        // Parent Process: Handles Receiving data from Server
        while (1) {
            memset(buffer, 0, BUFFER_SIZE);
            int valread = read(sock, buffer, BUFFER_SIZE);
            if (valread <= 0) {
                printf("\n[!] Server disconnected.\n");
                kill(pid, SIGTERM);
                exit(0);
            }
            printf("\nServer: %s", buffer);
            fflush(stdout);
        }
    }

    close(sock);
    return 0;
}
