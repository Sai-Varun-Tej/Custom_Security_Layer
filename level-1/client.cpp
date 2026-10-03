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
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == -1) {
        perror("socket");
        return 1;
    }
    cout << "Socket created\n";

    sockaddr_in server_addr{};

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);

    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    if (connect(
            client_fd,
            (struct sockaddr*)&server_addr,
            sizeof(server_addr)
        ) == -1) {

        perror("connect");
        close(client_fd);
        return 1;
    }

    cout << "Connected to server!\n";

    // const char* message = "Hello from client";
    // send(client_fd, message, strlen(message), 0);

    // send_frame(client_fd, 1, "Hello from client");

    send_frame(client_fd, 1, "Hello");
    send_frame(client_fd, 2, "LOGIN");
    send_frame(client_fd, 3, "GOODBYE");

    uint8_t type;
    string payload;

    while (recv_frame(client_fd, type, payload)) {
        cout << "Type: " << (int)type << '\n';
        cout << "Payload: " << payload << '\n';
    }

}