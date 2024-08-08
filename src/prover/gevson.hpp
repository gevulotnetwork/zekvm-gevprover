#ifndef GEVSON_HPP
#define GEVSON_HPP

#include <string>
#include <vector>
#include "utils.hpp"

class Gevson
{
public:
    Gevson(const std::string &keyfile, const std::string &jsonurl);

    json generateProof(const std::vector<json> &jsonFiles, const std::string &proofType);

private:
    std::string keyfile;
    std::string jsonurl;

    bool validateInput(size_t fileCount, const std::string& proofType);
    std::string exec(const char *cmd);
    std::string calculateHash(const std::string &file);
    std::string executeCommand(const std::vector<std::string> &hashes, const std::vector<std::string> &fileUrls, const std::string &proofType);
    void waitForTxTree(const std::string &txHash);
    std::string getFirstNodeHash(const std::string &txHash);
    json getTx(const std::string &nodeHash);
};

#endif // GEVSON_HPP
