#include <ios>
#include <openssl/evp.h>
#include <array>
#include <stdexcept>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>

#include "crypto_guard_ctx.h"


namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    Impl() {
        OpenSSL_add_all_algorithms();
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error{"EVP new error."};
        }
    }

    ~Impl() {
        EVP_CIPHER_CTX_free(ctx);
        EVP_cleanup();
    }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;

        if (!EVP_CipherInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
            throw std::runtime_error{"error encrypt."};
        }

        std::vector<unsigned char> outBuf(N + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(N);
        int outLen;

        try {
            for(; !inStream.eof();) {
                inStream.read(reinterpret_cast<char*>(inBuf.data()), N);

                if (!EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(inStream.gcount()))) {
                    throw (std::runtime_error("Encrypt update error."));
                }
                if (!outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen))
                    throw (std::runtime_error("Write error."));
            }

            // Заканчиваем работу с cipher
            if(!EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen)) {
                throw (std::runtime_error("Encrypt final error."));
            }
            if (!outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen)) 
                throw (std::runtime_error("Write error."));
        } catch (...) {
            outStream.clear();
            throw;
        }
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;

        if (!EVP_DecryptInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data())) {
            throw std::runtime_error{"Decrypt init error."};
        }

        std::vector<unsigned char> outBuf(N + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(N);
        int outLen;

        try {
            for(; !inStream.eof();) {
                inStream.read(reinterpret_cast<char*>(inBuf.data()), N);    

                if (!EVP_DecryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(inStream.gcount()))) {
                    throw (std::runtime_error("Decrypt update error."));
                }
                if (!outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen))
                    throw (std::runtime_error("Write error."));
            }

            // Заканчиваем работу с cipher
            if (!EVP_DecryptFinal_ex(ctx, outBuf.data(), &outLen)) {
                throw std::runtime_error{"Decrypt final error."};
            }
            if (!outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen))
                throw (std::runtime_error("Write error."));
        } catch (...) {
            outStream.clear();
            throw;
        }
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        std::stringstream res;

        unsigned int md_len;
        EVP_MD_CTX* mdctx;
        const EVP_MD* md;
        md = EVP_get_digestbyname("sha256");
        mdctx = EVP_MD_CTX_new();
        if (mdctx == nullptr) {
            throw (std::runtime_error("Message digest create failed."));
        }

        if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
            EVP_MD_CTX_free(mdctx);
            throw (std::runtime_error("Message digest initialization failed."));
        }
        std::vector<unsigned char> md_value(EVP_MAX_MD_SIZE); 
        std::vector<unsigned char> inBuf(N);
        
        for(; !inStream.eof();) {
            try {
                inStream.read(reinterpret_cast<char*>(inBuf.data()), N);
            } catch (...) {
                EVP_MD_CTX_free(mdctx);
                throw;
            }
            if (!EVP_DigestUpdate(mdctx, inBuf.data(), inStream.gcount())) {
                EVP_MD_CTX_free(mdctx);
                throw (std::runtime_error("Message digest update failed."));
            }
        }

        if (!EVP_DigestFinal_ex(mdctx, md_value.data(), &md_len)) {
            EVP_MD_CTX_free(mdctx);
            throw (std::runtime_error("Message digest finalization failed."));
        }

        for (unsigned int i = 0; i < md_len; ++i) {
            res << std::hex << static_cast<int>(md_value[i]);
        }
        
        EVP_MD_CTX_free(mdctx);
        return res.str(); 
    }
private:
    const int N = 1024;
    AesCipherParams params;
    EVP_CIPHER_CTX* ctx;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
CryptoGuardCtx & CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    return pImpl_->CalculateChecksum(inStream); 
}

}  // namespace CryptoGuard
