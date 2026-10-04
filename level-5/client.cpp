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
#include <openssl/rand.h>

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
    uint32_t length =
        htonl(static_cast<uint32_t>(payload.size()));
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
void print_hex(
    const string& name,
    const unsigned char* data,
    size_t len
) {
    cout << name << ": ";
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    cout << '\n';
}
// ============================================================
// LEVEL 4: HANDSHAKE CONFIRMATION
// ============================================================
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
    transcript.append(
        reinterpret_cast<const char*>(&client_len),
        sizeof(client_len)
    );
    transcript.append(client_public_key);
    transcript.append(
        reinterpret_cast<const char*>(&server_len),
        sizeof(server_len)
    );
    transcript.append(server_public_key);
    return transcript;
}

// ============================================================
// LEVEL 5: AES-256-GCM
// ============================================================

const size_t GCM_NONCE_SIZE = 12;
const size_t GCM_TAG_SIZE = 16;

// Encrypt plaintext using AES-256-GCM
bool aes_gcm_encrypt(
    const unsigned char* key,
    const unsigned char* plaintext,
    int plaintext_len,
    unsigned char* nonce,
    unsigned char* ciphertext,
    unsigned char* tag
) {
    // Generate fresh random nonce
    if (RAND_bytes(
            nonce,
            GCM_NONCE_SIZE
        ) != 1) {

        return false;
    }

    EVP_CIPHER_CTX* ctx =
        EVP_CIPHER_CTX_new();

    if (ctx == nullptr) {
        return false;
    }

    // Select AES-256-GCM
    if (EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            nullptr,
            nullptr,
            nullptr
        ) <= 0) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Set nonce length
    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            GCM_NONCE_SIZE,
            nullptr
        ) <= 0) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Give GCM the key and nonce
    if (EVP_EncryptInit_ex(
            ctx,
            nullptr,
            nullptr,
            key,
            nonce
        ) <= 0) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int ciphertext_len = 0;

    // Encrypt plaintext
    if (EVP_EncryptUpdate(
            ctx,
            ciphertext,
            &ciphertext_len,
            plaintext,
            plaintext_len
        ) <= 0) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int final_len = 0;

    // Finish encryption
    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + ciphertext_len,
            &final_len
        ) <= 0) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            GCM_TAG_SIZE,
            tag
        ) <= 0) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    return true;
}


// Decrypt ciphertext using AES-256-GCM
bool aes_gcm_decrypt(
    const unsigned char* key,
    const unsigned char* nonce,
    const unsigned char* ciphertext,
    int ciphertext_len,
    const unsigned char* tag,
    unsigned char* plaintext
) {
    EVP_CIPHER_CTX* ctx =
        EVP_CIPHER_CTX_new();

    if (ctx == nullptr) {
        return false;
    }

    // Select AES-256-GCM
    if (EVP_DecryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            nullptr,
            nullptr,
            nullptr
        ) <= 0) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Set nonce length
    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            GCM_NONCE_SIZE,
            nullptr
        ) <= 0) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Give GCM the key and nonce
    if (EVP_DecryptInit_ex(
            ctx,
            nullptr,
            nullptr,
            key,
            nonce
        ) <= 0) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int plaintext_len = 0;

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(
            ctx,
            plaintext,
            &plaintext_len,
            ciphertext,
            ciphertext_len
        ) <= 0) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Give GCM the received authentication tag
    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            GCM_TAG_SIZE,
            const_cast<unsigned char*>(tag)
        ) <= 0) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int final_len = 0;

    // This verifies the authentication tag
    if (EVP_DecryptFinal_ex(
            ctx,
            plaintext + plaintext_len,
            &final_len
        ) <= 0) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    return true;
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
    server_addr.sin_port = htons(8080);
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
        return 1;
    }
    if (EVP_PKEY_CTX_set_dh_nid(
            ctx,
            NID_ffdhe2048
        ) <= 0) {
        cerr << "Failed to set DH parameters\n";
        return 1;
    }
    EVP_PKEY* keypair = nullptr;
    if (EVP_PKEY_keygen(
            ctx,
            &keypair
        ) <= 0) {
        cerr << "Failed to generate DH key pair\n";
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
        return 1;
    }
    unsigned char* public_key =
        new unsigned char[public_key_len];
    unsigned char* ptr = public_key;
    int result =
        i2d_PUBKEY(
            keypair,
            &ptr
        );
    if (result <= 0) {
        cerr << "Failed to serialize public key\n";
        delete[] public_key;
        return 1;
    }
    cout << "Public key serialized successfully!\n";
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
        return 1;
    }
    if (type != 2) {
        cerr << "Unexpected frame type\n";
        return 1;
    }
    cout << "Received server public key!\n";
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
        return 1;
    }
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
    size_t shared_secret_len = 0;
    if (EVP_PKEY_derive(
            derive_ctx,
            nullptr,
            &shared_secret_len
        ) <= 0) {
        cerr << "Failed to determine shared secret size\n";
        return 1;
    }
    unsigned char* shared_secret =
        new unsigned char[shared_secret_len];
    if (EVP_PKEY_derive(
            derive_ctx,
            shared_secret,
            &shared_secret_len
        ) <= 0) {
        cerr << "Failed to derive shared secret\n";
        return 1;
    }
    cout << "Shared secret successfully derived!\n";
    // ========================================================
    // LEVEL 3: KDF
    // ========================================================
    unsigned char encryption_key[32];
    unsigned char mac_key[32];
    if (!derive_key(
            "ENC",
            shared_secret,
            shared_secret_len,
            encryption_key
        )) {
        cerr << "Failed to derive encryption key\n";
        return 1;
    }
    if (!derive_key(
            "MAC",
            shared_secret,
            shared_secret_len,
            mac_key
        )) {
        cerr << "Failed to derive MAC key\n";
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
    // Type 3 = client confirmation
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
        cerr << "Failed to receive server confirmation\n";
        return 1;
    }
    if (
        confirmation_type != 4 ||
        server_confirmation.size() != 32
    ) {
        cerr << "Invalid server confirmation\n";
        return 1;
    }
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
        cerr << "Failed to compute expected confirmation\n";
        return 1;
    }
    if (memcmp(
            server_confirmation.data(),
            expected_server_confirmation,
            sizeof(expected_server_confirmation)
        ) != 0) {
        cerr << "HANDSHAKE CONFIRMATION FAILED!\n";
        return 1;
    }
    cout << "Server handshake confirmation verified!\n";
    cout << "LEVEL 4 HANDSHAKE CONFIRMED!\n";

    // ========================================================
    // LEVEL 5: ENCRYPTED MESSAGE
    // ========================================================

    cout << "\nLEVEL 5: AES-256-GCM\n";

    string message =
        "Hello from the client!";

    unsigned char nonce[GCM_NONCE_SIZE];
    unsigned char tag[GCM_TAG_SIZE];

    unsigned char ciphertext[1024];

    if (!aes_gcm_encrypt(
            encryption_key,
            reinterpret_cast<const unsigned char*>(
                message.data()
            ),
            message.size(),
            nonce,
            ciphertext,
            tag
        )) {

        cerr << "AES-GCM encryption failed\n";
        return 1;
    }

    cout << "Message encrypted successfully!\n";


    // ========================================================
    // BUILD ENCRYPTED FRAME
    //
    // Payload:
    //
    // nonce || ciphertext || tag
    //
    // ========================================================

    string encrypted_payload;

    encrypted_payload.append(
        reinterpret_cast<char*>(nonce),
        GCM_NONCE_SIZE
    );

    encrypted_payload.append(
        reinterpret_cast<char*>(ciphertext),
        message.size()
    );

    encrypted_payload.append(
        reinterpret_cast<char*>(tag),
        GCM_TAG_SIZE
    );


    // Type 5 = encrypted application data

    if (!send_frame(
            client_fd,
            5,
            encrypted_payload
        )) {

        cerr << "Failed to send encrypted message\n";
        return 1;
    }

    cout << "Encrypted message sent!\n";

    // ========================================================
    // RECEIVE ENCRYPTED SERVER MESSAGE
    // ========================================================

    uint8_t encrypted_type;
    string encrypted_response;

    if (!recv_frame(
            client_fd,
            encrypted_type,
            encrypted_response
        )) {

        cerr << "Failed to receive encrypted response\n";
        return 1;
    }

    if (
        encrypted_type != 5 ||
        encrypted_response.size() < GCM_NONCE_SIZE + GCM_TAG_SIZE
    ) {

        cerr << "Invalid encrypted response\n";
        return 1;
    }


    const unsigned char* response_nonce =
        reinterpret_cast<const unsigned char*>(
            encrypted_response.data()
        );

    size_t response_ciphertext_len =
        encrypted_response.size()
        - GCM_NONCE_SIZE
        - GCM_TAG_SIZE;

    const unsigned char* response_ciphertext =
        reinterpret_cast<const unsigned char*>(
            encrypted_response.data()
            + GCM_NONCE_SIZE
        );

    const unsigned char* response_tag =
        reinterpret_cast<const unsigned char*>(
            encrypted_response.data()
            + GCM_NONCE_SIZE
            + response_ciphertext_len
        );

    unsigned char plaintext[1024];

    if (!aes_gcm_decrypt(
            encryption_key,
            response_nonce,
            response_ciphertext,
            response_ciphertext_len,
            response_tag,
            plaintext
        )) {

        cerr << "AES-GCM authentication/decryption failed\n";
        return 1;
    }

    cout << "Server message decrypted and authenticated!\n";
    cout << "Server says: ";

    cout.write(
        reinterpret_cast<char*>(plaintext),
        response_ciphertext_len
    );

    cout << '\n';


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