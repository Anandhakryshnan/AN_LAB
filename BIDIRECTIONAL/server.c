#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];

    // 1. Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // 2. Bind the socket to the port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // 3. Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("[+] Server is listening on port %d...\n", PORT);

    // 4. Accept connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    printf("[+] Connection established with client!\n");
    printf("[*] Type your messages below (Type 'exit' to quit):\n\n");

    // 5. Fork process for bidirectional communication
    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        // Child Process: Handles Receiving data from Client
        while (1) {
            memset(buffer, 0, BUFFER_SIZE);
            int valread = read(new_socket, buffer, BUFFER_SIZE);
            if (valread <= 0) {
                printf("\n[!] Client disconnected.\n");
                kill(getppid(), SIGTERM);
                exit(0);
            }
            printf("\nClient: %s", buffer);
            fflush(stdout);
        }
    } else {
        // Parent Process: Handles Sending data to Client
        while (1) {
            memset(buffer, 0, BUFFER_SIZE);
            fgets(buffer, BUFFER_SIZE, stdin);
            send(new_socket, buffer, strlen(buffer), 0);
            
            if (strncmp(buffer, "exit", 4) == 0) {
                printf("[*] Closing connection...\n");
                kill(pid, SIGTERM);
                break;
            }
        }
    }

    close(new_socket);
    close(server_fd);
    return 0;
}
