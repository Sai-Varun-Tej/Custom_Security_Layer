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

    // From Level 1
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == -1) {
        perror("socket");
        return 1;
    }

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

    // Create a context for DH key generation
    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);

    if (ctx == nullptr) {
        cerr << "Failed to create DH context\n";
        return 1;
    }

    // Initialize DH key generation
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        cerr << "Failed to initialize DH key generation\n";
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    // Select the standard 2048-bit FFDHE group
    if (EVP_PKEY_CTX_set_dh_nid(ctx, NID_ffdhe2048) <= 0) {
        cerr << "Failed to set DH parameters\n";
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    // Generate the DH key pair
    EVP_PKEY* keypair = nullptr;

    if (EVP_PKEY_keygen(ctx, &keypair) <= 0) {
        cerr << "Failed to generate DH key pair\n";
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    cout << "DH key pair generated successfully!\n";

    // Serialise the Public Key
    int public_key_len = i2d_PUBKEY(keypair, nullptr);

    if (public_key_len <= 0) {
        cerr << "Failed to get public key size\n";
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    //cout << "Public key size: " << public_key_len << " bytes\n";

    unsigned char* public_key = new unsigned char[public_key_len];
    unsigned char* ptr = public_key;
    int result = i2d_PUBKEY(keypair, &ptr);
    if (result <= 0) {
        cerr << "Failed to serialize public key\n";
        delete[] public_key;
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    cout << "Public key serialized successfully!\n";
    cout << "Serialized size: " << result << " bytes\n";

    string public_key_data(
        reinterpret_cast<char*>(public_key),
        public_key_len
    );
    cout << "Payload size: " << public_key_data.size() << " bytes\n";

    send_frame(client_fd, 1, public_key_data);
    cout << "DH public key sent!\n";

    uint8_t type;
    string payload;
    if (!recv_frame(client_fd, type, payload)) {
        cerr << "Failed to receive server public key\n";
        close(client_fd);
        return 1;
    }
    cout << "Received server public key!\n";
    cout << "Type: " << (int)type << '\n';
    cout << "Payload size: " << payload.size() << " bytes\n";

    const unsigned char* server_ptr =
        reinterpret_cast<const unsigned char*>(payload.data());
    EVP_PKEY* server_public_key =
        d2i_PUBKEY(nullptr, &server_ptr, payload.size());
    if (server_public_key == nullptr) {
        cerr << "Failed to deserialize server public key\n";
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        close(client_fd);
        return 1;
    }
    cout << "Server public key deserialized successfully!\n";

    cout << "Local key type: "
        << EVP_PKEY_get0_type_name(keypair) << '\n';

    cout << "Peer key type: "
        << EVP_PKEY_get0_type_name(server_public_key) << '\n';


    // Create a context for deriving the shared secret
    EVP_PKEY_CTX* derive_ctx =
        EVP_PKEY_CTX_new(keypair, nullptr);
    if (derive_ctx == nullptr) {
        cerr << "Failed to create derive context\n";
        return 1;
    }

    // Initialize key derivation
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
        cerr << "Failed to initialize key derivation\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(server_public_key);
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        close(client_fd);
        return 1;
    }


    // Tell OpenSSL that the server's public key is the DH peer
    if (EVP_PKEY_derive_set_peer(derive_ctx, server_public_key) <= 0) {
        cerr << "Failed to set server public key as peer\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(server_public_key);
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        close(client_fd);
        return 1;
    }
    cout << "Server public key set as DH peer!\n";
    // First call: find out how large the shared secret will be
    size_t shared_secret_len = 0;
    if (EVP_PKEY_derive(
            derive_ctx,
            nullptr,
            &shared_secret_len
        ) <= 0) {
        cerr << "Failed to determine shared secret size\n";
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(server_public_key);
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        close(client_fd);
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
        EVP_PKEY_free(server_public_key);
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        close(client_fd);
        return 1;
    }
    cout << "Shared secret successfully derived!\n";
    
    
    
    // Cleanup
    EVP_PKEY_free(keypair);
    EVP_PKEY_CTX_free(ctx);
    close(client_fd);

    return 0;
}