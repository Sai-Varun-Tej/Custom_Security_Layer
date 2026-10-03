#include <iostream>
#include <string>
#include <cstdint>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/x509.h>
#include <openssl/err.h>

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

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8080);

    if (bind(server_fd,
             (struct sockaddr*)&server_addr,
             sizeof(server_addr)) == -1) {

        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) == -1) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd == -1) {
        perror("accept");
        close(server_fd);
        return 1;
    }
    cout << "Client connected!\n";

    uint8_t type;
    string payload;
    if (!recv_frame(client_fd, type, payload)) {
        cerr << "Failed to receive DH public key\n";
        close(client_fd);
        close(server_fd);
        return 1;
    }
    cout << "Received frame!\n";
    cout << "Type: " << (int)type << '\n';
    cout << "Payload size: " << payload.size() << " bytes\n";
    if (type != 1) {
        cerr << "Unexpected frame type\n";
        close(client_fd);
        close(server_fd);
        return 1;
    }

    const unsigned char* ptr =
        reinterpret_cast<const unsigned char*>(payload.data());
    EVP_PKEY* client_public_key =
        d2i_PUBKEY(nullptr, &ptr, payload.size());

    if (client_public_key == nullptr) {
        cerr << "Failed to deserialize client's public key\n";
        close(client_fd);
        close(server_fd);
        return 1;
    }
    cout << "Client public key deserialized successfully!\n";

    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
    if (ctx == nullptr) {
        cerr << "Failed to create DH context\n";
        EVP_PKEY_free(client_public_key);
        close(client_fd);
        close(server_fd);
        return 1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        cerr << "Failed to initialize DH key generation\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(client_public_key);
        close(client_fd);
        close(server_fd);
        return 1;
    }

    if (EVP_PKEY_CTX_set_dh_nid(ctx, NID_ffdhe2048) <= 0) {
        cerr << "Failed to set DH parameters\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(client_public_key);
        close(client_fd);
        close(server_fd);
        return 1;
    }

    EVP_PKEY* server_keypair = nullptr;
    if (EVP_PKEY_keygen(ctx, &server_keypair) <= 0) {
        cerr << "Failed to generate server DH key pair\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(client_public_key);
        close(client_fd);
        close(server_fd);
        return 1;
    }
    cout << "Server DH key pair generated successfully!\n";

    int server_public_key_len = i2d_PUBKEY(server_keypair, nullptr);

    if (server_public_key_len <= 0) {
        cerr << "Failed to get server public key size\n";
        EVP_PKEY_free(server_keypair);
        EVP_PKEY_free(client_public_key);
        EVP_PKEY_CTX_free(ctx);
        close(client_fd);
        close(server_fd);
        return 1;
    }

    unsigned char* server_public_key =
        new unsigned char[server_public_key_len];
    unsigned char* server_ptr = server_public_key;
    int server_result =
        i2d_PUBKEY(server_keypair, &server_ptr);
    if (server_result <= 0) {
        cerr << "Failed to serialize server public key\n";
        delete[] server_public_key;
        EVP_PKEY_free(server_keypair);
        EVP_PKEY_free(client_public_key);
        EVP_PKEY_CTX_free(ctx);
        close(client_fd);
        close(server_fd);
        return 1;
    }
    cout << "Server public key serialized successfully!\n";
    cout << "Serialized size: " << server_result << " bytes\n";

    string server_public_key_data(
        reinterpret_cast<char*>(server_public_key),
        server_public_key_len
    );

    if (!send_frame(client_fd, 1, server_public_key_data)) {
        cerr << "Failed to send server public key\n";
        return 1;
    }
    cout << "Server public key sent!\n";

    // Create a context for deriving the shared secret
    EVP_PKEY_CTX* derive_ctx =
        EVP_PKEY_CTX_new(server_keypair, nullptr);
    if (derive_ctx == nullptr) {
        cerr << "Failed to create derive context\n";
        return 1;
    }

    // Initialize key derivation
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
        cerr << "Failed to initialize key derivation\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(client_public_key);
        EVP_PKEY_free(server_keypair);
        EVP_PKEY_CTX_free(ctx);
        close(client_fd);
        close(server_fd);
        return 1;
    }

    // Tell OpenSSL that the client's public key is the DH peer
    if (EVP_PKEY_derive_set_peer(
            derive_ctx,
            client_public_key
        ) <= 0) {

        cerr << "Failed to set client public key as peer\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(client_public_key);
        EVP_PKEY_free(server_keypair);
        EVP_PKEY_CTX_free(ctx);
        close(client_fd);
        close(server_fd);
        return 1;
    }
    cout << "Client public key set as DH peer!\n";
    // First call: find out how large the shared secret will be
    size_t shared_secret_len = 0;
    if (EVP_PKEY_derive(
            derive_ctx,
            nullptr,
            &shared_secret_len
        ) <= 0) {
        cerr << "Failed to determine shared secret size\n";
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(client_public_key);
        EVP_PKEY_free(server_keypair);
        EVP_PKEY_CTX_free(ctx);
        close(client_fd);
        close(server_fd);
        return 1;
    }
    cout << "Shared secret size: "
        << shared_secret_len
        << " bytes\n";
    // Allocate memory for the shared secret
    unsigned char* shared_secret =
        new unsigned char[shared_secret_len];
    // Second call: actually calculate the shared secret
    if (EVP_PKEY_derive(
            derive_ctx,
            shared_secret,
            &shared_secret_len
        ) <= 0) {
        cerr << "Failed to derive shared secret\n";
        delete[] shared_secret;
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(client_public_key);
        EVP_PKEY_free(server_keypair);
        EVP_PKEY_CTX_free(ctx);
        close(client_fd);
        close(server_fd);
        return 1;
    }
    cout << "Shared secret successfully derived!\n";

    close(client_fd);
    close(server_fd);
}