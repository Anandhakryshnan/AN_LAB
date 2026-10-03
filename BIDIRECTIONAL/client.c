#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/wait.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main(int argc, char const *argv[]) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];
    char *server_ip = (argc > 1) ? (char *)argv[1] : "127.0.0.1";

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) return -1;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) return -1;
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) return -1;

    printf("[+] Connected to %s:%d\n", server_ip, PORT);
    printf("[*] Type messages (Type 'exit' to quit):\n\n");

    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);

    if (pid == 0) {
        // Child: Sends data
        while (1) {
            memset(buffer, 0, BUFFER_SIZE);
            fgets(buffer, BUFFER_SIZE, stdin);
            buffer[strcspn(buffer, "\n")] = 0; // Strip trailing newline
            
            send(sock, buffer, strlen(buffer), 0);

            if (strncmp(buffer, "exit", 4) == 0) {
                printf("[*] Closing connection...\n");
                kill(getppid(), SIGTERM);
                exit(0);
            }
        }
    } else {
        // Parent: Receives data
        while (1) {
            memset(buffer, 0, BUFFER_SIZE);
            if (read(sock, buffer, BUFFER_SIZE) <= 0) {
                printf("\n[!] Server disconnected.\n");
                kill(pid, SIGTERM);
                wait(NULL); // Reap zombie process
                exit(0);
            }
            printf("\nServer: %s\n", buffer);
            fflush(stdout);
        }
    }

    close(sock);
    return 0;
}
