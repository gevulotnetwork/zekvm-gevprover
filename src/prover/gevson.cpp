#include "gevson.hpp"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <array>
#include <chrono>
#include <thread>
#include <regex>
#include <fstream>

json Gevson::generateProof(const std::vector<json> &jsonFiles, const std::string &proofType)
{
    if (!validateInput(jsonFiles.size(), proofType))
    {
        throw std::invalid_argument("Invalid input files for the selected proof type.");
    }

    std::vector<std::string> hashes;
    std::vector<std::string> fileUrls;

    for (const auto &j : jsonFiles)
    {
        std::string filename = getUUID();
        std::string fileUrl = json2aws(j, filename);
        fileUrls.push_back(fileUrl);

        std::string filePath = "inputs/" + filename + ".json";

        std::string hash = calculateHash(filePath);
        hashes.push_back(hash);
    }

    // Execute the command and wait for results
    std::string txHash = executeCommand(hashes, fileUrls, proofType);
    waitForTxTree(txHash);
    std::string nodeHash = getFirstNodeHash(txHash);
    return getTx(nodeHash);
}

bool Gevson::validateInput(size_t fileCount, const std::string &proofType)
{
    if (proofType == "BATCH_PROOF" && fileCount != 1)
    {
        return false;
    }
    else if (proofType == "AGGREGATED_PROOF" && fileCount != 2)
    {
        return false;
    }
    else if (proofType == "FINAL_PROOF" && fileCount != 2)
    {
        return false;
    }
    return true;
}

std::string Gevson::exec(const char *cmd)
{
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe)
    {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
        result += buffer.data();
    }
    return result;
}

std::string Gevson::calculateHash(const std::string &file)
{
    std::string cmd = "gevulot-cli calculate-hash --file " + file;
    std::string output = exec(cmd.c_str());

    std::regex hashRegex("The hash of the file is: ([a-fA-F0-9]+)");
    std::smatch match;
    if (std::regex_search(output, match, hashRegex) && match.size() > 1)
    {
        return match.str(1);
    }
    else
    {
        throw std::runtime_error("Failed to calculate hash for file: " + file);
    }
}

std::string Gevson::executeCommand(const std::vector<std::string> &hashes, const std::vector<std::string> &fileUrls, const std::string &proofType)
{
    std::string cmd = "gevulot-cli --keyfile " + config.gevsonKeyfilePath + " --jsonurl " + config.gevulotURL + " exec --tasks '[{\"program\":\"" + config.gevulotProverHash + "\",\"cmd_args\":[{\"name\":\"-proof\",\"value\":\"" + proofType + "\"}],\"inputs\":[";

    for (size_t i = 0; i < hashes.size(); ++i)
    {
        if (i > 0)
            cmd += ",";
        cmd += "{\"Input\": {\"local_path\": \"" + hashes[i] + "\", \"vm_path\": \"/workspace/" + hashes[i] + "\", \"file_url\": \"" + fileUrls[i] + "\"}}";
    }

    cmd += "]},{\"program\":\"" + config.gevulotVerifierHash + "\",\"cmd_args\":[{\"name\":\"-proof\",\"value\":\"VERIFIER\"}],\"inputs\":[]}]'";
    zklog.info(std::string("Gevulot command: ") + cmd);

    std::string output = exec(cmd.c_str());

    std::regex txHashRegex("Tx hash:([a-fA-F0-9]+)");
    std::smatch match;
    if (std::regex_search(output, match, txHashRegex) && match.size() > 1)
    {
        return match.str(1);
    }
    else
    {
        throw std::runtime_error("Failed to execute command and retrieve Tx hash.");
    }
}

void Gevson::waitForTxTree(const std::string &txHash)
{
    std::string cmd = "gevulot-cli --jsonurl " + config.gevulotURL + " print-tx-tree " + txHash;
    while (true)
    {
        std::string output = exec(cmd.c_str());
        if (output.find("no root tx found") == std::string::npos)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

std::string Gevson::getFirstNodeHash(const std::string &txHash)
{
    std::string cmd = "gevulot-cli --jsonurl " + config.gevulotURL + " print-tx-tree " + txHash;
    std::string output = exec(cmd.c_str());

    std::regex nodeHashRegex("Node: ([a-fA-F0-9]+)");
    std::smatch match;
    if (std::regex_search(output, match, nodeHashRegex) && match.size() > 1)
    {
        return match.str(1);
    }
    else
    {
        throw std::runtime_error("Failed to retrieve first node hash.");
    }
}

json Gevson::getTx(const std::string &nodeHash)
{
    std::string cmd = "gevulot-cli --jsonurl " + config.gevulotURL + " get-tx " + nodeHash;
    std::string output = exec(cmd.c_str());
    return json::parse(output);
}
