#include <iostream>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

using namespace std;


// ============================================================
// LEVEL 1: TCP + FRAMING
// ============================================================
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
bool send_frame(
    int fd,
    uint8_t type,
    const string& payload
) {
    uint32_t length = htonl(payload.size());
    // Send type
    if (!send_all(
            fd,
            reinterpret_cast<const char*>(&type),
            sizeof(type)
        )) {
        return false;
    }
    // Send length
    if (!send_all(
            fd,
            reinterpret_cast<const char*>(&length),
            sizeof(length)
        )) {
        return false;
    }
    // Send payload
    if (!send_all(
            fd,
            payload.data(),
            payload.size()
        )) {
        return false;
    }
    return true;
}
bool recv_frame(
    int fd,
    uint8_t& type,
    string& payload
) {
    uint32_t length;
    // Receive type
    if (!recv_all(
            fd,
            reinterpret_cast<char*>(&type),
            sizeof(type)
        )) {

        return false;
    }
    // Receive length
    if (!recv_all(
            fd,
            reinterpret_cast<char*>(&length),
            sizeof(length)
        )) {
        return false;
    }
    length = ntohl(length);
    payload.resize(length);
    // Receive payload
    if (!recv_all(
            fd,
            payload.data(),
            length
        )) {
        return false;
    }
    return true;
}
// ============================================================
// LEVEL 3: KDF
// ============================================================
bool sha256(
    const unsigned char* data,
    size_t data_len,
    unsigned char* output
) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (md_ctx == nullptr) {
        return false;
    }
    if (EVP_DigestInit_ex(
            md_ctx,
            EVP_sha256(),
            nullptr
        ) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    if (EVP_DigestUpdate(
            md_ctx,
            data,
            data_len
        ) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    unsigned int output_len = 0;
    if (EVP_DigestFinal_ex(
            md_ctx,
            output,
            &output_len
        ) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    EVP_MD_CTX_free(md_ctx);
    return output_len == 32;
}
// KDF:
// SHA256(label || shared_secret)
bool derive_key(
    const string& label,
    const unsigned char* shared_secret,
    size_t shared_secret_len,
    unsigned char* derived_key
) {
    string input = label;
    input.append(
        reinterpret_cast<const char*>(shared_secret),
        shared_secret_len
    );
    return sha256(
        reinterpret_cast<const unsigned char*>(
            input.data()
        ),
        input.size(),
        derived_key
    );
}
// Print binary key as hexadecimal
void print_hex(
    const string& name,
    const unsigned char* data,
    size_t len
) {
    cout << name << ": ";
    for (size_t i = 0; i < len; i++) {
        printf(
            "%02x",
            data[i]
        );
    }
    cout << '\n';
}

// ============================================================
// LEVEL 4: HANDSHAKE CONFIRMATION
// ============================================================

// HMAC-SHA256

bool hmac_sha256(
    const unsigned char* key,
    size_t key_len,
    const unsigned char* data,
    size_t data_len,
    unsigned char* output
) {
    unsigned int output_len = 0;

    unsigned char* result = HMAC(
        EVP_sha256(),
        key,
        static_cast<int>(key_len),
        data,
        data_len,
        output,
        &output_len
    );

    return result != nullptr && output_len == 32;
}

// Build the handshake transcript

string build_transcript(
    const string& client_public_key,
    const string& server_public_key
) {
    string transcript = "CSL-HS-V1";

    uint32_t client_len =
        htonl(
            static_cast<uint32_t>(
                client_public_key.size()
            )
        );

    uint32_t server_len =
        htonl(
            static_cast<uint32_t>(
                server_public_key.size()
            )
        );

    // Add client public key length

    transcript.append(
        reinterpret_cast<const char*>(&client_len),
        sizeof(client_len)
    );

    // Add client public key

    transcript.append(
        client_public_key
    );

    // Add server public key length

    transcript.append(
        reinterpret_cast<const char*>(&server_len),
        sizeof(server_len)
    );

    // Add server public key

    transcript.append(
        server_public_key
    );

    return transcript;
}


// ============================================================
// MAIN
// ============================================================

int main() {
    // ========================================================
    // TCP CONNECTION
    // ========================================================
    int client_fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );
    if (client_fd == -1) {
        perror("socket");
        return 1;
    }
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port =
        htons(8080);
    inet_pton(
        AF_INET,
        "127.0.0.1",
        &server_addr.sin_addr
    );
    if (connect(
            client_fd,
            (struct sockaddr*)&server_addr,
            sizeof(server_addr)
        ) == -1) {
        perror("connect");
        close(client_fd);
        return 1;
    }
    // ========================================================
    // LEVEL 2: DH KEY GENERATION
    // ========================================================
    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_id(
            EVP_PKEY_DH,
            nullptr
        );
    if (ctx == nullptr) {
        cerr << "Failed to create DH context\n";
        return 1;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        cerr << "Failed to initialize DH key generation\n";
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    if (EVP_PKEY_CTX_set_dh_nid(
            ctx,
            NID_ffdhe2048
        ) <= 0) {
        cerr << "Failed to set DH parameters\n";
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    EVP_PKEY* keypair = nullptr;
    if (EVP_PKEY_keygen(
            ctx,
            &keypair
        ) <= 0) {
        cerr << "Failed to generate DH key pair\n";
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    cout << "DH key pair generated successfully!\n";
    // ========================================================
    // SERIALIZE CLIENT PUBLIC KEY
    // ========================================================
    int public_key_len =
        i2d_PUBKEY(
            keypair,
            nullptr
        );
    if (public_key_len <= 0) {
        cerr << "Failed to get public key size\n";
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    unsigned char* public_key =
        new unsigned char[public_key_len];
    unsigned char* ptr =
        public_key;
    int result =
        i2d_PUBKEY(
            keypair,
            &ptr
        );
    if (result <= 0) {
        cerr << "Failed to serialize public key\n";
        delete[] public_key;
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    cout << "Public key serialized successfully!\n";
    cout << "Serialized size: "
         << result
         << " bytes\n";
    string public_key_data(
        reinterpret_cast<char*>(public_key),
        public_key_len
    );
    // ========================================================
    // SEND CLIENT PUBLIC KEY
    // ========================================================
    if (!send_frame(
            client_fd,
            1,
            public_key_data
        )) {
        cerr << "Failed to send client public key\n";
        return 1;
    }
    cout << "DH public key sent!\n";
    // ========================================================
    // RECEIVE SERVER PUBLIC KEY
    // ========================================================
    uint8_t type;
    string payload;
    if (!recv_frame(
            client_fd,
            type,
            payload
        )) {
        cerr << "Failed to receive server public key\n";
        close(client_fd);
        return 1;
    }
    cout << "Received server public key!\n";
    if (type != 2) {
        cerr << "Unexpected frame type for server public key\n";
        close(client_fd);
        return 1;
    }
    const unsigned char* server_ptr =
        reinterpret_cast<const unsigned char*>(
            payload.data()
        );
    EVP_PKEY* server_public_key =
        d2i_PUBKEY(
            nullptr,
            &server_ptr,
            payload.size()
        );
    if (server_public_key == nullptr) {
        cerr << "Failed to deserialize server public key\n";
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        close(client_fd);
        return 1;
    }
    cout << "Server public key deserialized successfully!\n";
    // ========================================================
    // DH SHARED SECRET
    // ========================================================
    EVP_PKEY_CTX* derive_ctx =
        EVP_PKEY_CTX_new(
            keypair,
            nullptr
        );
    if (derive_ctx == nullptr) {
        cerr << "Failed to create derive context\n";
        return 1;
    }
    if (EVP_PKEY_derive_init(
            derive_ctx
        ) <= 0) {
        cerr << "Failed to initialize key derivation\n";
        return 1;
    }
    if (EVP_PKEY_derive_set_peer(
            derive_ctx,
            server_public_key
        ) <= 0) {
        cerr << "Failed to set server public key as peer\n";
        return 1;
    }
    cout << "Server public key set as DH peer!\n";
    size_t shared_secret_len = 0;
    if (EVP_PKEY_derive(
            derive_ctx,
            nullptr,
            &shared_secret_len
        ) <= 0) {
        cerr << "Failed to determine shared secret size\n";
        return 1;
    }
    cout << "Shared secret size: "
         << shared_secret_len
         << " bytes\n";
    unsigned char* shared_secret =
        new unsigned char[
            shared_secret_len
        ];
    if (EVP_PKEY_derive(
            derive_ctx,
            shared_secret,
            &shared_secret_len
        ) <= 0) {
        cerr << "Failed to derive shared secret\n";
        delete[] shared_secret;
        return 1;
    }
    cout << "Shared secret successfully derived!\n";
    // ========================================================
    // LEVEL 3: KDF
    // ========================================================
    unsigned char encryption_key[32];
    unsigned char mac_key[32];
    // Derive encryption key
    if (!derive_key(
            "ENC",
            shared_secret,
            shared_secret_len,
            encryption_key
        )) {
        cerr << "Failed to derive encryption key\n";
        delete[] shared_secret;
        return 1;
    }
    // Derive MAC key
    if (!derive_key(
            "MAC",
            shared_secret,
            shared_secret_len,
            mac_key
        )) {
        cerr << "Failed to derive MAC key\n";
        delete[] shared_secret;
        return 1;
    }
    cout << "\nLevel 3 keys derived successfully!\n";
    print_hex(
        "Encryption key",
        encryption_key,
        sizeof(encryption_key)
    );
    print_hex(
        "MAC key",
        mac_key,
        sizeof(mac_key)
    );

    // ========================================================
    // LEVEL 4: HANDSHAKE CONFIRMATION
    // ========================================================

    string transcript =
        build_transcript(
            public_key_data,
            payload
        );


    // ========================================================
    // CLIENT CREATES CONFIRMATION
    // ========================================================

    unsigned char client_confirmation[32];

    if (!hmac_sha256(
            mac_key,
            sizeof(mac_key),

            reinterpret_cast<const unsigned char*>(
                transcript.data()
            ),
            transcript.size(),
            client_confirmation
        )) {

        cerr << "Failed to create handshake confirmation\n";
        return 1;
    }

    string confirmation_data(
        reinterpret_cast<char*>(
            client_confirmation
        ),
        sizeof(client_confirmation)
    );

    // Type 3 = client handshake confirmation

    if (!send_frame(
            client_fd,
            3,
            confirmation_data
        )) {
        cerr << "Failed to send handshake confirmation\n";
        return 1;
    }

    cout << "Client handshake confirmation sent!\n";

    // ========================================================
    // RECEIVE SERVER CONFIRMATION
    // ========================================================

    uint8_t confirmation_type;
    string server_confirmation;

    if (!recv_frame(
            client_fd,
            confirmation_type,
            server_confirmation
        )) {
        cerr << "Failed to receive server handshake confirmation\n";
        return 1;
    }

    if (
        confirmation_type != 4 ||
        server_confirmation.size() != 32
    ) {
        cerr << "Invalid server handshake confirmation\n";
        return 1;
    }


    // ========================================================
    // COMPUTE EXPECTED SERVER CONFIRMATION
    // ========================================================

    unsigned char expected_server_confirmation[32];

    if (!hmac_sha256(
            mac_key,
            sizeof(mac_key),
            reinterpret_cast<const unsigned char*>(
                transcript.data()
            ),
            transcript.size(),
            expected_server_confirmation
        )) {
        cerr << "Failed to compute expected server confirmation\n";
        return 1;
    }


    // ========================================================
    // VERIFY SERVER CONFIRMATION
    // ========================================================

    if (memcmp(
            server_confirmation.data(),
            expected_server_confirmation,
            sizeof(expected_server_confirmation)
        ) != 0) {
        cerr << "HANDSHAKE CONFIRMATION FAILED!\n";
        cerr << "The transcript or derived key does not match.\n";
        return 1;
    }

    cout << "Server handshake confirmation verified!\n";
    cout << "LEVEL 4 HANDSHAKE CONFIRMED!\n";


    // ========================================================
    // CLEANUP
    // ========================================================

    delete[] shared_secret;
    delete[] public_key;

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(server_public_key);
    EVP_PKEY_free(keypair);
    EVP_PKEY_CTX_free(ctx);

    close(client_fd);
    return 0;
}