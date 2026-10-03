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

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) exit(EXIT_FAILURE);

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) exit(EXIT_FAILURE);
    if (listen(server_fd, 3) < 0) exit(EXIT_FAILURE);

    printf("[+] Server listening on port %d...\n", PORT);
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) exit(EXIT_FAILURE);

    printf("[+] Connected! Type messages (Type 'exit' to quit):\n\n");

    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);

    if (pid == 0) {
        // Child: Receives data
        while (1) {
            memset(buffer, 0, BUFFER_SIZE);
            if (read(new_socket, buffer, BUFFER_SIZE) <= 0) {
                printf("\n[!] Client disconnected.\n");
                kill(getppid(), SIGTERM);
                exit(0);
            }
            printf("\nClient: %s\n", buffer);
            fflush(stdout);
        }
    } else {
        // Parent: Sends data
        while (1) {
            memset(buffer, 0, BUFFER_SIZE);
            fgets(buffer, BUFFER_SIZE, stdin);
            buffer[strcspn(buffer, "\n")] = 0; // Strip trailing newline

            send(new_socket, buffer, strlen(buffer), 0);

            if (strncmp(buffer, "exit", 4) == 0) {
                printf("[*] Closing connection...\n");
                kill(pid, SIGTERM);
                wait(NULL); // Reap zombie process
                break;
            }
        }
    }

    close(new_socket);
    close(server_fd);
    return 0;
}
