#include <gtest/gtest.h>
#include <string>
#include "cmd_options.h"

//TEST(TestComponentName, SimpleCheck) { EXPECT_EQ(1 + 1, 2); }

TEST(ProgramOptions, TestName) { 
    EXPECT_EQ(1 + 1, 2); 
}

TEST(ProgramOptions, TestCommand) {
    char arg1[] = {"name"};
    char arg2[] = {"--command"};
    char arg3[] = {"encrypt"};

    char *argv[3] = {arg1, arg2, arg3};
    CryptoGuard::ProgramOptions po;
    po.Parse(3, argv);
    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptions, TestInput) {
    char arg1[] = {"name"};
    char arg2[] = {"-i"};
    char arg3[] = {"input.txt"};

    char *argv[3] = {arg1, arg2, arg3};
    CryptoGuard::ProgramOptions po;
    po.Parse(3, argv);
    EXPECT_EQ(po.GetInputFile(), std::string(arg3));
}

TEST(ProgramOptions, TestOutput) {
    char arg1[] = {"name"};
    char arg2[] = {"--output"};
    char arg3[] = {"out.txt"};

    char *argv[3] = {arg1, arg2, arg3};
    CryptoGuard::ProgramOptions po;
    po.Parse(3, argv);
    EXPECT_EQ(po.GetOutputFile(), std::string(arg3));
}

TEST(ProgramOptions, TestPwd) {
    char arg1[] = {"name"};
    char arg2[] = {"--p"};
    char arg3[] = {"1234"};

    char *argv[3] = {arg1, arg2, arg3};
    CryptoGuard::ProgramOptions po;
    po.Parse(3, argv);
    EXPECT_EQ(po.GetPassword(), std::string(arg3));
}

TEST(ProgramOptions, TestAll) {
    char arg1[] = {"name"};
    char arg2[] = {"-i"};
    char arg3[] = {"input.txt"};
    char arg4[] = {"--output"};
    char arg5[] = {"out.txt"};
    char arg6[] = {"--p"};
    char arg7[] = {"1234"};
    char arg8[] = {"--command"};
    char arg9[] = {"decrypt"};


    char *argv[9] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9};
    CryptoGuard::ProgramOptions po;
    po.Parse(9, argv);
    EXPECT_EQ(po.GetOutputFile(), std::string(arg5));
    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(po.GetInputFile(), std::string(arg3));
    EXPECT_EQ(po.GetPassword(), std::string(arg7));
}