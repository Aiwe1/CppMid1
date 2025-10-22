#include <gtest/gtest.h>
#include <string>
#include "crypto_guard_ctx.h"

TEST(CryptoGuardCtx, SimpleCheckCTX) { 
    EXPECT_EQ(1 + 1, 2); 
}

TEST(CryptoGuardCtx, TestInput) {
    std::string res;
    std::string s;
    {
        std::stringstream ssin("01234567890123456789");
        std::stringstream ssout;
        CryptoGuard::CryptoGuardCtx ctx;

        ctx.EncryptFile(ssin, ssout, "12341234");
        res = ssout.str();
    }
    // Decrypt
    {
        std::stringstream ssin(res);
        std::stringstream ssout;
        CryptoGuard::CryptoGuardCtx ctx;

        ctx.DecryptFile(ssin, ssout, "12341234");
        s = ssout.str();
    }
    EXPECT_EQ("01234567890123456789", s);
}

TEST(ryptoGuardCtx, TestChechsum1) {
    std::stringstream ssin("01234567890123456789");
    std::stringstream ssout;
    CryptoGuard::CryptoGuardCtx ctx;

    std::string sum = ctx.CalculateChecksum(ssin);

    EXPECT_EQ("4e76ad8354461437c04ef9b9b24254b646d782ff2c3fb28afdab5b423f88fe", sum);
}

TEST(ryptoGuardCtx, TestChechsum2) {
    std::stringstream ssin("0123456789");
    std::stringstream ssout;
    CryptoGuard::CryptoGuardCtx ctx;

    std::string sum = ctx.CalculateChecksum(ssin);

    EXPECT_EQ("84d89877f0d441efb6bf91a16f0248f2fd573e6af5c19f96bedb9f882f7882", sum);
}