#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <json/json.h>
#include <fstream>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <limits>
#include <algorithm>
#include <regex>
#include "secret_key.h"  // Include the header file with the secret key
#include "encryption.h"

const int DEFAULT_PORT = 3000;
const char* CLIENT_CERT = "client.crt";
const char* CLIENT_KEY = "client.key";
const char* CA_FILE = "ca.crt";

// Validation patterns
const std::regex ACCOUNT_PATTERN("^[a-z0-9_.-]{1,122}$");
const std::regex FILENAME_PATTERN("^(?!\\.\\.)(?!\\.)([a-z0-9_.-]{1,127})$");
const std::regex IP_PATTERN("^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]?)\\."
                            "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]?)\\."
                            "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]?)\\."
                            "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]?)$");
const std::regex AMOUNT_PATTERN(R"(^\d{1,10}(\.\d{1,2})?$)");

SSL_CTX* InitClientCTX();
std::string generateHMAC(const std::string& message);
void sendRequest(Json::Value& request, const char* ip, int port);
bool createCardFile(const std::string& cardFile, int pin);
std::string readCardFile(const std::string& cardFile);
int getPIN();
bool isValidAccountName(const std::string& account);
bool isValidFileName(const std::string& fileName);
bool isValidIPAddress(const std::string& ip);
bool isValidPort(int port);
bool isValidAmount(const std::string& amountStr);

int main(int argc, char* argv[]) {
    std::string account, operation, cardFile, ipAddress = "127.0.0.1";
    std::string amountStr = "0";
    double amount = 0.0;
    int port = DEFAULT_PORT;
    bool operationSpecified = false; // Initialize operationSpecified

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            account = argv[++i];
            if (!isValidAccountName(account)) {
                std::cerr << "Invalid account name" << std::endl;
                return 255;
            }
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            if (operationSpecified) {
                std::cerr << "Error: Only one operation can be performed per command line." << std::endl;
                return 255;
            }
            operation = "create";
            amountStr = argv[++i];
            amount = atof(amountStr.c_str());
            if (!isValidAmount(amountStr) || amount < 10.0) {
                std::cerr << "Invalid amount for account creation" << std::endl;
                return 255;
            }
            operationSpecified = true; // Mark that an operation is specified
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            if (operationSpecified) {
                std::cerr << "Error: Only one operation can be performed per command line." << std::endl;
                return 255;
            }
            operation = "deposit";
            amountStr = argv[++i];
            amount = atof(amountStr.c_str());
            if (!isValidAmount(amountStr)) {
                std::cerr << "Invalid deposit amount" << std::endl;
                return 255;
            }
            operationSpecified = true; // Mark that an operation is specified
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            if (operationSpecified) {
                std::cerr << "Error: Only one operation can be performed per command line." << std::endl;
                return 255;
            }
            operation = "withdraw";
            amountStr = argv[++i];
            amount = atof(amountStr.c_str());
            if (!isValidAmount(amountStr)) {
                std::cerr << "Invalid withdrawal amount" << std::endl;
                return 255;
            }
            operationSpecified = true; // Mark that an operation is specified
        } else if (strcmp(argv[i], "-g") == 0) {
            if (operationSpecified) {
                std::cerr << "Error: Only one operation can be performed per command line." << std::endl;
                return 255;
            }
            operation = "get_balance";
            operationSpecified = true; // Mark that an operation is specified
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            cardFile = argv[++i];
            if (!isValidFileName(cardFile)) {
                std::cerr << "Invalid card file name" << std::endl;
                return 255;
            }
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            ipAddress = argv[++i];
            if (!isValidIPAddress(ipAddress)) {
                std::cerr << "Invalid IP address" << std::endl;
                return 255;
            }
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
            if (!isValidPort(port)) {
                std::cerr << "Invalid port number" << std::endl;
                return 255;
            }
        }
    }

    if (account.empty() || operation.empty()) {
        std::cerr << "Missing required parameters" << std::endl;
        return 255;
    }

    // Check for negative amount
    if ((operation == "create" && amount < 10) ||
        (operation == "deposit" && amount < 0) ||
        (operation == "withdraw" && amount < 0)) {
        std::cerr << "Error: Amount is invalid." << std::endl;
        return 255;
    }

    // Handle account creation
    if (operation == "create") {
        // Use provided card file name if specified; otherwise, default to account name
        cardFile = cardFile.empty() ? account + ".card" : cardFile;

        if (!isValidFileName(cardFile)) {
            std::cerr << "Invalid card file name" << std::endl;
            return 255;
        }

        std::ifstream cardStream(cardFile);
        if (cardStream.is_open()) {
            std::cerr << "Card file already exists. Account creation not allowed." << std::endl;
            return 255;
        } else {
            int pin = getPIN(); // Get PIN as an integer

            // Create the request to send to the bank
            Json::Value request;
            request["account"] = account;
            request["operation"] = operation;
            request["pin"] = pin; // Include the PIN for account creation
            request["amount"] = amount; // Include initial amount

            // Generate HMAC
            std::string messageForHMAC = Json::writeString(Json::StreamWriterBuilder(), request);
            request["hmac"] = generateHMAC(messageForHMAC);

            // Send request to create account at the bank
            sendRequest(request, ipAddress.c_str(), port);

            // After successfully creating the account at the bank, create the card file
            if (createCardFile(cardFile, pin)) {
                std::cout << "Card file created successfully: " << cardFile << std::endl;
            } else {
                std::cerr << "Failed to create card file." << std::endl;
                return 1;
            }
        }
    } else {
        // For other operations, ensure the card file exists
        decryptFile(cardFile);
        std::string pin = readCardFile(cardFile);
        encryptFile(cardFile);
        if (pin.empty()) {
            std::cerr << "Invalid or missing card file" << std::endl;
            return 255;
        }

        // Add card data to the request
        Json::Value request;
        request["account"] = account;
        request["pin"] = pin; // Send the PIN to the bank
        request["operation"] = operation;

        if (operation == "deposit" || operation == "withdraw") {
            request["amount"] = amount;
        }

        // Generate HMAC
        std::string messageForHMAC = Json::writeString(Json::StreamWriterBuilder(), request);
        request["hmac"] = generateHMAC(messageForHMAC);

        // Send request to the bank server
        sendRequest(request, ipAddress.c_str(), port);
    }

    return 0;
}

bool createCardFile(const std::string& cardFile, int pin) {
    std::ofstream cardStream(cardFile);
    if (!cardStream) {
        std::cerr << "Error: Could not create card file " << cardFile << std::endl;
        return false;
    }
    cardStream << pin << std::endl; // Write the PIN
    cardStream.close(); // Close before encryption
    encryptFile(cardFile); // Encrypt the file after writing
    return true;
}

std::string readCardFile(const std::string& cardFile) {
    // decryptFile(cardFile); // Decrypt the file before reading
    std::ifstream infile(cardFile);
    std::string line;

    if (infile.is_open()) {
        std::getline(infile, line); // Read the PIN from the card file
        infile.close();
        return line;
    }
    std::cerr << "Failed to open card file after decryption." << std::endl;
    // encryptFile(cardFile); // Re-encrypt the file if read fails
    return "";
}

int getPIN() {
    std::string pinStr;
    while (true) {
        std::cout << "Enter a 4 to 6 digit PIN: ";
        std::cin >> pinStr;
        if (pinStr.length() >= 4 && pinStr.length() <= 6 && std::all_of(pinStr.begin(), pinStr.end(), ::isdigit)) {
            return std::stoi(pinStr);
        }
        std::cout << "Invalid PIN. Please try again." << std::endl;
    }
}

SSL_CTX* InitClientCTX() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    if (ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Load client certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Load CA certificate for server validation
    if (!SSL_CTX_load_verify_locations(ctx, CA_FILE, nullptr)) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

std::string generateHMAC(const std::string& message) {
    unsigned char hmacResult[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    HMAC(EVP_sha256(), SECRET_KEY.c_str(), SECRET_KEY.size(), 
         (unsigned char*)message.c_str(), message.size(), 
         hmacResult, &len);

    std::stringstream hmacHex;
    for (unsigned int i = 0; i < len; i++) {
        hmacHex << std::hex << std::setw(2) << std::setfill('0') << (int)hmacResult[i];
    }

    return hmacHex.str();
}

// Helper functions for validation
bool isValidAccountName(const std::string& account) {
    return std::regex_match(account, ACCOUNT_PATTERN);
    //  && account != "." && account != "..";
}

bool isValidFileName(const std::string& fileName) {
    return std::regex_match(fileName, FILENAME_PATTERN);
}

bool isValidIPAddress(const std::string& ip) {
    return std::regex_match(ip, IP_PATTERN);
}

bool isValidPort(int port) {
    return port >= 1024 && port <= 65535;
}

bool isValidAmount(const std::string& amountStr) {
    if (!std::regex_match(amountStr, AMOUNT_PATTERN)) {
        return false;
    }
    double amount = atof(amountStr.c_str());
    if (amount < 0.0 || amount > 4294967295.99) {
        return false;
    }
    return true;
}

void sendRequest(Json::Value& request, const char* ip, int port) {
    SSL_CTX* ctx;
    SSL* ssl;
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    ctx = InitClientCTX(); // Initialize SSL context

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        return;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return;
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(sock);
        return;
    }

    // Convert request to JSON string
    Json::StreamWriterBuilder writer;
    std::string requestString = Json::writeString(writer, request);

    // Send request
    SSL_write(ssl, requestString.c_str(), requestString.size());

    // Read server response
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0'; // Null-terminate the response
        Json::CharReaderBuilder reader;
        Json::Value response;
        std::istringstream ss(buffer);
        std::string errs;

        // Functioinality bug solved
        // Parse the response JSON
        if (Json::parseFromStream(reader, ss, &response, &errs)) {
            // Iterate over all the fields in the response object
            for (const auto& key : response.getMemberNames()) {
                // Skip the "hmac" field
                if (key != "hmac") {
                    // Print the key and its corresponding value
                    std::cout << key << ": " << response[key].asString() << std::endl;
                }
            }
        } else {
            std::cerr << "Failed to parse server response: " << errs << std::endl;
        }
    } else {
        std::cerr << "Error reading response" << std::endl;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
}
