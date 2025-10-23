#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <iostream>
#include <fstream>

int main(int argc, char *argv[]) {
    try {
        // PO
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
        {
            std::fstream fin(options.GetInputFile(), std::ios::in);
            std::fstream fout(options.GetOutputFile(), std::ios::out);
            cryptoCtx.EncryptFile(fin, fout, options.GetPassword());
            break;
        }
        case COMMAND_TYPE::DECRYPT:
        {
            std::fstream fin(options.GetInputFile(), std::ios::in);
            std::fstream fout(options.GetOutputFile(), std::ios::out);
            cryptoCtx.DecryptFile(fin, fout, options.GetPassword());
            break;
        }
        case COMMAND_TYPE::CHECKSUM:
        {
            std::fstream fin(options.GetInputFile(), std::ios::in);
            std::print("Сумма: '{}'\n", cryptoCtx.CalculateChecksum(fin));
            break;
        }
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}