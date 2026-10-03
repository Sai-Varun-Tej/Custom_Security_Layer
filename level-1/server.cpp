#include <iostream>
#include <cstring>
#include <cstdint>
#include <string>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

bool send_all(int fd, const char* data, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t sent = send(
            fd,
            data + total,
            len - total,
            0
        );
        if (sent <= 0) {
            return false;
        }
        total += sent;
    }
    return true;
}

bool recv_all(int fd, char* data, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t received = recv(
            fd,
            data + total,
            len - total,
            0
        );
        if (received <= 0) {
            return false;
        }
        total += received;
    }
    return true;
}

bool send_frame(int fd, uint8_t type, const string& payload) {
    uint32_t length = htonl(payload.size());
    if (!send_all(fd,
                  reinterpret_cast<const char*>(&type),
                  sizeof(type))) {
        return false;
    }
    if (!send_all(fd,
                  reinterpret_cast<const char*>(&length),
                  sizeof(length))) {
        return false;
    }
    if (!send_all(fd,
                  payload.data(),
                  payload.size())) {
        return false;
    }
    return true;
}

bool recv_frame(int fd, uint8_t& type, string& payload) {
    uint32_t length;
    if (!recv_all(
            fd,
            reinterpret_cast<char*>(&type),
            sizeof(type))) {
        return false;
    }
    if (!recv_all(
            fd,
            reinterpret_cast<char*>(&length),
            sizeof(length))) {
        return false;
    }
    length = ntohl(length);
    payload.resize(length);
    if (!recv_all(
            fd,
            payload.data(),
            length)) {
        return false;
    }
    return true;
}

int main() {

    // 1. Create a socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        return 1;
    }
    cout << "Socket created\n";

    // 2. Create server address
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8080);

    // 3. Bind socket to address + port
    if (bind(server_fd,
             (struct sockaddr*)&server_addr,
             sizeof(server_addr)) == -1) {

        perror("bind");
        close(server_fd);
        return 1;
    }
    cout << "Bind successful\n";

    // 4. Start listening
    if (listen(server_fd, 5) == -1) {
        perror("listen");
        close(server_fd);
        return 1;
    }
    cout << "Server listening on port 8080...\n";

    // 5. Accept a client
    int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd == -1) {
        perror("accept");
        close(server_fd);
        return 1;
    }
    cout << "Client connected!\n";

    // 6. Receive data
    // char buffer[1024];

    // int bytes_received = recv(
    //     client_fd,
    //     buffer,
    //     sizeof(buffer),
    //     0
    // );

    // if (bytes_received > 0) {
    //     cout << "Received: ";
    //     cout.write(buffer, bytes_received);
    //     cout << '\n';
    // }
    // else if (bytes_received == 0) {
    //     cout << "Client closed the connection.\n";
    // }
    // else {
    //     perror("recv");
    // }

    uint8_t type;
    string payload;

    // if (recv_frame(client_fd, type, payload)) {

    //     cout << "Type: " << (int)type << '\n';
    //     cout << "Payload: " << payload << '\n';

    // }
    // else {
    //     cout << "Failed to receive frame\n";
    // }

    while (recv_frame(client_fd, type, payload)) {
        cout << "Type: " << (int)type << '\n';
        cout << "Payload: " << payload << '\n';
        if (payload == "GOODBYE")
            break;
    }

    send_frame(client_fd, 10, "Hello from server");
    send_frame(client_fd, 20, "ACK");
    send_frame(client_fd, 30, "Goodbye");

    // 7. Close sockets
    close(client_fd);
    close(server_fd);

    return 0;
}