#include "cmd_options.h"
#include <print>

namespace CryptoGuard {
ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()
    ("help", "Список доступных опций")
    ("command", boost::program_options::value<std::string>(), " команда encrypt, decrypt или checksum")
    ("input,i", boost::program_options::value<std::string>(),"Путь входного файла")
    ("output,o", boost::program_options::value<std::string>(), "Путь до файла, в котором будет сохранён результат")
    ("password,p", boost::program_options::value<std::string>(), "пароль для шифрования и дешифрования")
    ;
    

}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc_), vm);
    boost::program_options::notify(vm);
    
    //std::string inputFile_;
    //std::string outputFile_;
    //std::string password_;
    
    if (vm.count("help")) {
            std::print("command — команда encrypt, decrypt или checksum\ninput — путь до входного файла;\noutput — путь до файла, в котором будет сохранён результат;\npassword — пароль для шифрования и дешифрования.\n");
    }

    if (vm.count("input")) {
        try {  
                inputFile_ = vm["input"].as<std::string>();
            }
            catch(const std::exception &e) {
                throw std::runtime_error{"Нет имени входного файла"};
            }
    }
    
    if (vm.count("output")) {
        try {  
                outputFile_ = vm["output"].as<std::string>();
            }
            catch(const std::exception &e) {
                throw std::runtime_error{"Нет имени выходного файла"};
            }
    }

    if (vm.count("password")) {
        password_ = vm["password"].as<std::string>();
    }

    if (vm.count("command")) {
        try {
            command_ = commandMapping_.at(vm["command"].as<std::string>());
        }
            catch(const std::exception &e) {
                throw std::runtime_error{"Неверная команда"};
            }
    }
    
}

}  // namespace CryptoGuard
