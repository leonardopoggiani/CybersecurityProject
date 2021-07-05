#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <fstream>
#include <regex>
#include "constants.h"

using namespace std;

size_t get_file_size(std::string filename){
	size_t file_size = 0;
	std::ifstream file(filename, std::ios::binary);
	if(file){
		file.seekg(0, std::ios::end);
		file_size = file.tellg();
		file.close();
	}
	return file_size;
}

string readMessage() {
    string message;
    getline(cin, message);
    if (message.length() > constants::MAX_MESSAGE_SIZE) {
        cerr << "Error: the message must be loger than " << endl;
        exit(EXIT_FAILURE);
    }
    return message;
}

std::vector<std::string> split( const std::string& input, const std::string& delims ) {
    std::vector<std::string> ret;
    for (size_t start = 0, pos; ; start = pos + 1) {
        pos = input.find_first_of(delims, start);
        std::string token = input.substr(start, pos - start);
        if (token.length() > 0)  // ignore empty tokens
            ret.push_back(token);
        if (pos == std::string::npos) break;
    }
    return ret;
}

