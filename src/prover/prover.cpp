#include <fstream>
#include <iomanip>
#include <unistd.h>
#include "prover.hpp"
#include "utils.hpp"
#include "scalar.hpp"
#include "proof2zkin.hpp"
#include "main.hpp"
#include "main.recursive1.hpp"
#include "main.recursive2.hpp"
#include "main.recursiveF.hpp"
#include "main.final.hpp"
#include "binfile_utils.hpp"
#include "zkey_utils.hpp"
#include "wtns_utils.hpp"
#include "groth16.hpp"
#include "sm/storage/storage_executor.hpp"
#include "timer.hpp"
#include "execFile.hpp"
#include <math.h> /* log2 */
#include "proof2zkinStark.hpp"

#include "friProofC12.hpp"
#include <algorithm> // std::min
#include <openssl/sha.h>

#include "commit_pols_starks.hpp"
#include "zkevmSteps.hpp"
#include "c12aSteps.hpp"
#include "recursive1Steps.hpp"
#include "recursive2Steps.hpp"
#include "zklog.hpp"
#include "exit_process.hpp"
#include "websocket_client.hpp"

#ifndef __AVX512__
#define NROWS_STEPS_ 4
#else
#define NROWS_STEPS_ 8
#endif

Prover::Prover(Goldilocks &fr,
               PoseidonGoldilocks &poseidon,
               const Config &config) : fr(fr),
                                       poseidon(poseidon),
                                       executor(fr, config, poseidon),
                                       pCurrentRequest(NULL),
                                       config(config),
                                       lastComputedRequestEndTime(0)
{
    mpz_init(altBbn128r);
    mpz_set_str(altBbn128r, "21888242871839275222246405745257275088548364400416034343698204186575808495617", 10);

    try
    {
        if (config.generateProof())
        {
            zkey = BinFileUtils::openExisting(config.finalStarkZkey, "zkey", 1);
            protocolId = Zkey::getProtocolIdFromZkey(zkey.get());
            if (Zkey::GROTH16_PROTOCOL_ID == protocolId)
            {
                zkeyHeader = ZKeyUtils::loadHeader(zkey.get());

                if (mpz_cmp(zkeyHeader->rPrime, altBbn128r) != 0)
                {
                    throw std::invalid_argument("zkey curve not supported");
                }

                groth16Prover = Groth16::makeProver<AltBn128::Engine>(
                    zkeyHeader->nVars,
                    zkeyHeader->nPublic,
                    zkeyHeader->domainSize,
                    zkeyHeader->nCoefs,
                    zkeyHeader->vk_alpha1,
                    zkeyHeader->vk_beta1,
                    zkeyHeader->vk_beta2,
                    zkeyHeader->vk_delta1,
                    zkeyHeader->vk_delta2,
                    zkey->getSectionData(4), // Coefs
                    zkey->getSectionData(5), // pointsA
                    zkey->getSectionData(6), // pointsB1
                    zkey->getSectionData(7), // pointsB2
                    zkey->getSectionData(8), // pointsC
                    zkey->getSectionData(9)  // pointsH1
                );
            }

            lastComputedRequestEndTime = 0;

            sem_init(&pendingRequestSem, 0, 0);
            pthread_mutex_init(&mutex, NULL);
            pCurrentRequest = NULL;
            pthread_create(&proverPthread, NULL, proverThread, this);
            pthread_create(&cleanerPthread, NULL, cleanerThread, this);

            StarkInfo _starkInfo(config, config.zkevmStarkInfo);

            // Allocate an area of memory, mapped to file, to store all the committed polynomials,
            // and create them using the allocated address
            uint64_t polsSize = _starkInfo.mapTotalN * sizeof(Goldilocks::Element) + _starkInfo.mapSectionsN.section[eSection::cm3_2ns] * (1 << _starkInfo.starkStruct.nBitsExt) * sizeof(Goldilocks::Element);

            zkassert(_starkInfo.mapSectionsN.section[eSection::cm1_2ns] * sizeof(Goldilocks::Element) <= polsSize - _starkInfo.mapSectionsN.section[eSection::cm2_2ns] * sizeof(Goldilocks::Element));

            zkassert(PROVER_FORK_NAMESPACE::CommitPols::pilSize() <= polsSize);
            zkassert(PROVER_FORK_NAMESPACE::CommitPols::pilSize() == _starkInfo.mapOffsets.section[cm2_n] * sizeof(Goldilocks::Element));

            if (config.zkevmCmPols.size() > 0)
            {
                pAddress = mapFile(config.zkevmCmPols, polsSize, true);
                zklog.info("Prover::genBatchProof() successfully mapped " + to_string(polsSize) + " bytes to file " + config.zkevmCmPols);
            }
            else
            {
                pAddress = calloc(polsSize, 1);
                if (pAddress == NULL)
                {
                    zklog.error("Prover::genBatchProof() failed calling malloc() of size " + to_string(polsSize));
                    exitProcess();
                }
                zklog.info("Prover::genBatchProof() successfully allocated " + to_string(polsSize) + " bytes");
            }

            prover = new Fflonk::FflonkProver<AltBn128::Engine>(AltBn128::Engine::engine, pAddress, polsSize);
            prover->setZkey(zkey.get());

            StarkInfo _starkInfoRecursiveF(config, config.recursivefStarkInfo);
            pAddressStarksRecursiveF = (void *)malloc(_starkInfoRecursiveF.mapTotalN * sizeof(Goldilocks::Element));

            starkZkevm = new Starks(config, {config.zkevmConstPols, config.mapConstPolsFile, config.zkevmConstantsTree, config.zkevmStarkInfo}, pAddress);
            starkZkevm->nrowsStepBatch = NROWS_STEPS_;
            starksC12a = new Starks(config, {config.c12aConstPols, config.mapConstPolsFile, config.c12aConstantsTree, config.c12aStarkInfo}, pAddress);
            starksRecursive1 = new Starks(config, {config.recursive1ConstPols, config.mapConstPolsFile, config.recursive1ConstantsTree, config.recursive1StarkInfo}, pAddress);
            starksRecursive2 = new Starks(config, {config.recursive2ConstPols, config.mapConstPolsFile, config.recursive2ConstantsTree, config.recursive2StarkInfo}, pAddress);
            starksRecursiveF = new StarkRecursiveF(config, pAddressStarksRecursiveF);
        }
    }
    catch (std::exception &e)
    {
        zklog.error("Prover::Prover() got an exception: " + string(e.what()));
        exitProcess();
    }
}

Prover::~Prover()
{
    mpz_clear(altBbn128r);

    if (config.generateProof())
    {
        Groth16::Prover<AltBn128::Engine> *pGroth16 = groth16Prover.release();
        BinFileUtils::BinFile *pZkey = zkey.release();
        ZKeyUtils::Header *pZkeyHeader = zkeyHeader.release();

        assert(groth16Prover.get() == nullptr);
        assert(groth16Prover == nullptr);
        assert(zkey.get() == nullptr);
        assert(zkey == nullptr);
        assert(zkeyHeader.get() == nullptr);
        assert(zkeyHeader == nullptr);

        delete pGroth16;
        delete pZkey;
        delete pZkeyHeader;

        uint64_t polsSize = starkZkevm->starkInfo.mapTotalN * sizeof(Goldilocks::Element) + starkZkevm->starkInfo.mapSectionsN.section[eSection::cm1_n] * (1 << starkZkevm->starkInfo.starkStruct.nBits) * FIELD_EXTENSION * sizeof(Goldilocks::Element);

        // Unmap committed polynomials address
        if (config.zkevmCmPols.size() > 0)
        {
            unmapFile(pAddress, polsSize);
        }
        else
        {
            free(pAddress);
        }
        free(pAddressStarksRecursiveF);

        delete prover;

        delete starkZkevm;
        delete starksC12a;
        delete starksRecursive1;
        delete starksRecursive2;
        delete starksRecursiveF;
    }
}

void *proverThread(void *arg)
{
    Prover *pProver = (Prover *)arg;
    zklog.info("proverThread() started");

    zkassert(pProver->config.generateProof());

    while (true)
    {
        pProver->lock();

        // Wait for the pending request queue semaphore to be released, if there are no more pending requests
        if (pProver->pendingRequests.size() == 0)
        {
            pProver->unlock();
            sem_wait(&pProver->pendingRequestSem);
        }

        // Check that the pending requests queue is not empty
        if (pProver->pendingRequests.size() == 0)
        {
            pProver->unlock();
            zklog.info("proverThread() found pending requests queue empty, so ignoring");
            continue;
        }

        // Extract the first pending request (first in, first out)
        pProver->pCurrentRequest = pProver->pendingRequests[0];
        pProver->pCurrentRequest->startTime = time(NULL);
        pProver->pendingRequests.erase(pProver->pendingRequests.begin());

        zklog.info("proverThread() starting to process request with UUID: " + pProver->pCurrentRequest->uuid);

        pProver->unlock();

        // Process the request
        switch (pProver->pCurrentRequest->type)
        {
        case prt_genBatchProof:
            pProver->genBatchProof(pProver->pCurrentRequest);
            break;
        case prt_genAggregatedProof:
            pProver->genAggregatedProof(pProver->pCurrentRequest);
            break;
        case prt_genFinalProof:
            pProver->genFinalProof(pProver->pCurrentRequest);
            break;
        case prt_execute:
            pProver->execute(pProver->pCurrentRequest);
            break;
        default:
            zklog.error("proverThread() got an invalid prover request type=" + to_string(pProver->pCurrentRequest->type));
            exitProcess();
        }

        // Move to completed requests
        pProver->lock();
        ProverRequest *pProverRequest = pProver->pCurrentRequest;
        pProverRequest->endTime = time(NULL);
        pProver->lastComputedRequestId = pProverRequest->uuid;
        pProver->lastComputedRequestEndTime = pProverRequest->endTime;

        pProver->completedRequests.push_back(pProver->pCurrentRequest);
        pProver->pCurrentRequest = NULL;
        pProver->unlock();

        zklog.info("proverThread() done processing request with UUID: " + pProverRequest->uuid);

        // Release the prove request semaphore to notify any blocked waiting call
        pProverRequest->notifyCompleted();
    }
    zklog.info("proverThread() done");
    return NULL;
}

void *cleanerThread(void *arg)
{
    Prover *pProver = (Prover *)arg;
    zklog.info("cleanerThread() started");

    zkassert(pProver->config.generateProof());

    while (true)
    {
        // Sleep for 10 minutes
        sleep(pProver->config.cleanerPollingPeriod);

        // Lock the prover
        pProver->lock();

        // Delete all requests older than requests persistence configuration setting
        time_t now = time(NULL);
        bool bRequestDeleted = false;
        do
        {
            bRequestDeleted = false;
            for (uint64_t i = 0; i < pProver->completedRequests.size(); i++)
            {
                if (now - pProver->completedRequests[i]->endTime > (int64_t)pProver->config.requestsPersistence)
                {
                    zklog.info("cleanerThread() deleting request with uuid: " + pProver->completedRequests[i]->uuid);
                    ProverRequest *pProverRequest = pProver->completedRequests[i];
                    pProver->completedRequests.erase(pProver->completedRequests.begin() + i);
                    pProver->requestsMap.erase(pProverRequest->uuid);
                    delete (pProverRequest);
                    bRequestDeleted = true;
                    break;
                }
            }
        } while (bRequestDeleted);

        // Unlock the prover
        pProver->unlock();
    }
    zklog.info("cleanerThread() done");
    return NULL;
}

string Prover::submitRequest(ProverRequest *pProverRequest) // returns UUID for this request
{
    zkassert(config.generateProof());
    zkassert(pProverRequest != NULL);

    zklog.info("Prover::submitRequest() started type=" + to_string(pProverRequest->type));

    // Get the prover request UUID
    string uuid = pProverRequest->uuid;

    // Add the request to the pending requests queue, and release the semaphore to notify the prover thread
    lock();
    requestsMap[uuid] = pProverRequest;
    pendingRequests.push_back(pProverRequest);
    sem_post(&pendingRequestSem);
    unlock();

    zklog.info("Prover::submitRequest() returns UUID: " + uuid);
    return uuid;
}

ProverRequest *Prover::waitForRequestToComplete(const string &uuid, const uint64_t timeoutInSeconds) // wait for the request with this UUID to complete; returns NULL if UUID is invalid
{
    zkassert(config.generateProof());
    zkassert(uuid.size() > 0);
    zklog.info("Prover::waitForRequestToComplete() waiting for request with UUID: " + uuid);

    // We will store here the address of the prove request corresponding to this UUID
    ProverRequest *pProverRequest = NULL;

    lock();

    // Map uuid to the corresponding prover request
    std::unordered_map<std::string, ProverRequest *>::iterator it = requestsMap.find(uuid);
    if (it == requestsMap.end())
    {
        zklog.error("Prover::waitForRequestToComplete() unknown uuid: " + uuid);
        unlock();
        return NULL;
    }

    // Wait for the request to complete
    pProverRequest = it->second;
    unlock();
    pProverRequest->waitForCompleted(timeoutInSeconds);
    zklog.info("Prover::waitForRequestToComplete() done waiting for request with UUID: " + uuid);

    // Return the request pointer
    return pProverRequest;
}

void Prover::processBatch(ProverRequest *pProverRequest)
{
    // TimerStart(PROVER_PROCESS_BATCH);
    zkassert(pProverRequest != NULL);
    zkassert(pProverRequest->type == prt_processBatch);

    if (config.runAggregatorClient)
    {
        zklog.info("Prover::processBatch() timestamp=" + pProverRequest->timestamp + " UUID=" + pProverRequest->uuid);
    }

    // Save input to <timestamp>.input.json, as provided by client
    if (config.saveInputToFile)
    {
        json inputJson;
        pProverRequest->input.save(inputJson);
        json2file(inputJson, pProverRequest->inputFile());
    }

    // Log input if requested
    if (config.logExecutorServerInput)
    {
        json inputJson;
        pProverRequest->input.save(inputJson);
        zklog.info("Input=" + inputJson.dump());
    }

    // Execute the program, in the process batch way
    executor.process_batch(*pProverRequest);

    // Save input to <timestamp>.input.json after execution including dbReadLog
    if (config.saveDbReadsToFile)
    {
        json inputJsonEx;
        pProverRequest->input.save(inputJsonEx, *pProverRequest->dbReadLog);
        json2file(inputJsonEx, pProverRequest->inputDbFile());
    }

    // TimerStopAndLog(PROVER_PROCESS_BATCH);
}

void Prover::genBatchProof(ProverRequest *pProverRequest)
{
    zkassert(config.generateProof());
    zkassert(pProverRequest != NULL);

    TimerStart(PROVER_BATCH_PROOF);

    printMemoryInfo(true);
    printProcessInfo(true);

    zkassert(pProverRequest != NULL);

    zklog.info("Prover::genBatchProof() timestamp: " + pProverRequest->timestamp);
    zklog.info("Prover::genBatchProof() UUID: " + pProverRequest->uuid);
    zklog.info("Prover::genBatchProof() input file: " + pProverRequest->inputFile());
    // zklog.info("Prover::genBatchProof() public file: " + pProverRequest->publicsOutputFile());
    // zklog.info("Prover::genBatchProof() proof file: " + pProverRequest->proofFile());

    // Save input to <timestamp>.input.json, as provided by client
    json inputJson;
    pProverRequest->input.save(inputJson);
    std::string inputFile = json2aws(inputJson, pProverRequest->uuid);

    WebSocketClient client;
    client.connect(config.gevsonURL);
    std::string message = R"(
        {
            "inputs": [
                {
                    "name": ")" + pProverRequest->uuid + R"(.json",
                    "source": {
                        "Url": ")" + inputFile + R"("
                    }
                }
            ],
            "outputs": [
                "proof.dat"
            ],
            "proof": "BATCH_PROOF",
            "prover": {
                "prover_hash": "1ce2fbc27ecb8cb658b25e0db8e13a066159997454df7bd8c532c5aa52244e6e",
                "schema": "Katla",
                "verifier_hash": "457e6d8e87c5320142c80f0f8a933e9595f574819bc50f5eb3f41a677f0e7690"
            },
            "timeout": 900
        }
    )";
    std::string response_str = client.send_and_receive(message);
    json response = json::parse(response_str);
    zklog.info("genBatchProof() Gevulot Response: " + response_str);

    std::string proof_url = response["tx_result"]["payload"]["Verification"]["files"][0]["url"].get<std::string>();
    zklog.info("genBatchProof() Proof file URL: " + proof_url);

    ordered_json proof;
    url2json(proof_url, proof);
    
    pProverRequest->batchProofOutput = proof;

    TimerStopAndLog(PROVER_BATCH_PROOF);
}

void Prover::genAggregatedProof(ProverRequest *pProverRequest)
{

    zkassert(config.generateProof());
    zkassert(pProverRequest != NULL);
    zkassert(pProverRequest->type == prt_genAggregatedProof);

    TimerStart(PROVER_AGGREGATED_PROOF);

    printMemoryInfo(true);
    printProcessInfo(true);

    // Save input to file
    if (config.saveInputToFile)
    {
        json2file(pProverRequest->aggregatedProofInput1, pProverRequest->filePrefix + "aggregated_proof.input_1.json");
        json2file(pProverRequest->aggregatedProofInput2, pProverRequest->filePrefix + "aggregated_proof.input_2.json");
    }

    // Input is pProverRequest->aggregatedProofInput1 and pProverRequest->aggregatedProofInput2 (of type json)

    ordered_json verKey;
    file2json(config.recursive2Verkey, verKey);

    // ----------------------------------------------
    // CHECKS
    // ----------------------------------------------
    // Check chainID

    if (pProverRequest->aggregatedProofInput1["publics"][17] != pProverRequest->aggregatedProofInput2["publics"][17])
    {
        zklog.error("Prover::genAggregatedProof() Inputs has different chainId " + pProverRequest->aggregatedProofInput1["publics"][17].dump() + "!=" + pProverRequest->aggregatedProofInput2["publics"][17].dump());
        pProverRequest->result = ZKR_AGGREGATED_PROOF_INVALID_INPUT;
        return;
    }
    if (pProverRequest->aggregatedProofInput1["publics"][18] != pProverRequest->aggregatedProofInput2["publics"][18])
    {
        zklog.error("Prover::genAggregatedProof() Inputs has different forkId " + pProverRequest->aggregatedProofInput1["publics"][18].dump() + "!=" + pProverRequest->aggregatedProofInput2["publics"][18].dump());
        pProverRequest->result = ZKR_AGGREGATED_PROOF_INVALID_INPUT;
        return;
    }
    // Check midStateRoot
    for (int i = 0; i < 8; i++)
    {
        if (pProverRequest->aggregatedProofInput1["publics"][19 + i] != pProverRequest->aggregatedProofInput2["publics"][0 + i])
        {
            zklog.error("Prover::genAggregatedProof() The newStateRoot and the oldStateRoot are not consistent " + pProverRequest->aggregatedProofInput1["publics"][19 + i].dump() + "!=" + pProverRequest->aggregatedProofInput2["publics"][0 + i].dump());
            pProverRequest->result = ZKR_AGGREGATED_PROOF_INVALID_INPUT;
            return;
        }
    }
    // Check midAccInputHash0
    for (int i = 0; i < 8; i++)
    {
        if (pProverRequest->aggregatedProofInput1["publics"][27 + i] != pProverRequest->aggregatedProofInput2["publics"][8 + i])
        {
            zklog.error("Prover::genAggregatedProof() newAccInputHash and oldAccInputHash are not consistent" + pProverRequest->aggregatedProofInput1["publics"][27 + i].dump() + "!=" + pProverRequest->aggregatedProofInput2["publics"][8 + i].dump());
            pProverRequest->result = ZKR_AGGREGATED_PROOF_INVALID_INPUT;
            return;
        }
    }
    // Check batchNum
    if (pProverRequest->aggregatedProofInput1["publics"][43] != pProverRequest->aggregatedProofInput2["publics"][16])
    {
        zklog.error("Prover::genAggregatedProof() newBatchNum and oldBatchNum are not consistent" + pProverRequest->aggregatedProofInput1["publics"][43].dump() + "!=" + pProverRequest->aggregatedProofInput2["publics"][16].dump());
        pProverRequest->result = ZKR_AGGREGATED_PROOF_INVALID_INPUT;
        return;
    }

    json zkinInputRecursive2 = joinzkin(pProverRequest->aggregatedProofInput1, pProverRequest->aggregatedProofInput2, verKey, starksRecursive2->starkInfo.starkStruct.steps.size());
    json recursive2Verkey;
    file2json(config.recursive2Verkey, recursive2Verkey);

    Goldilocks::Element recursive2VerkeyValues[4];
    recursive2VerkeyValues[0] = Goldilocks::fromU64(recursive2Verkey["constRoot"][0]);
    recursive2VerkeyValues[1] = Goldilocks::fromU64(recursive2Verkey["constRoot"][1]);
    recursive2VerkeyValues[2] = Goldilocks::fromU64(recursive2Verkey["constRoot"][2]);
    recursive2VerkeyValues[3] = Goldilocks::fromU64(recursive2Verkey["constRoot"][3]);

    Goldilocks::Element publics[starksRecursive2->starkInfo.nPublics];

    for (uint64_t i = 0; i < starkZkevm->starkInfo.nPublics; i++)
    {
        publics[i] = Goldilocks::fromString(zkinInputRecursive2["publics"][i]);
    }

    for (uint64_t i = 0; i < recursive2Verkey["constRoot"].size(); i++)
    {
        publics[starkZkevm->starkInfo.nPublics + i] = Goldilocks::fromU64(recursive2Verkey["constRoot"][i]);
    }

    CommitPolsStarks cmPolsRecursive2(pAddress, (1 << starksRecursive2->starkInfo.starkStruct.nBits), starksRecursive2->starkInfo.nCm1);
    CircomRecursive2::getCommitedPols(&cmPolsRecursive2, config.recursive2Verifier, config.recursive2Exec, zkinInputRecursive2, (1 << starksRecursive2->starkInfo.starkStruct.nBits), starksRecursive2->starkInfo.nCm1);

    // void *pointerCmRecursive2Pols = mapFile("config/recursive2/recursive2.commit", cmPolsRecursive2.size(), true);
    // memcpy(pointerCmRecursive2Pols, cmPolsRecursive2.address(), cmPolsRecursive2.size());
    // unmapFile(pointerCmRecursive2Pols, cmPolsRecursive2.size());

    //-------------------------------------------
    // Generate Recursive 2 proof
    //-------------------------------------------

    TimerStart(STARK_RECURSIVE_2_PROOF_BATCH_PROOF);
    uint64_t polBitsRecursive2 = starksRecursive2->starkInfo.starkStruct.steps[starksRecursive2->starkInfo.starkStruct.steps.size() - 1].nBits;
    FRIProof fproofRecursive2((1 << polBitsRecursive2), FIELD_EXTENSION, starksRecursive2->starkInfo.starkStruct.steps.size(), starksRecursive2->starkInfo.evMap.size(), starksRecursive2->starkInfo.nPublics);
    Recursive2Steps recursive2Steps;
    starksRecursive2->genProof(fproofRecursive2, publics, recursive2VerkeyValues, &recursive2Steps);
    TimerStopAndLog(STARK_RECURSIVE_2_PROOF_BATCH_PROOF);

    // Save the proof & zkinproof
    nlohmann::ordered_json jProofRecursive2 = fproofRecursive2.proofs.proof2json();
    nlohmann::ordered_json zkinRecursive2 = proof2zkinStark(jProofRecursive2);
    zkinRecursive2["publics"] = zkinInputRecursive2["publics"];

    // Output is pProverRequest->aggregatedProofOutput (of type json)
    pProverRequest->aggregatedProofOutput = zkinRecursive2;

    // Save output to file
    if (config.saveOutputToFile)
    {
        json2file(pProverRequest->aggregatedProofOutput, pProverRequest->filePrefix + "aggregated_proof.output.json");
    }
    // Save proof to file
    if (config.saveProofToFile)
    {
        jProofRecursive2["publics"] = zkinInputRecursive2["publics"];
        json2file(jProofRecursive2, pProverRequest->filePrefix + "aggregated_proof.proof.json");
    }

    // Add the recursive2 verification key
    json publicsJson = json::array();

    file2json(config.recursive2Verkey, recursive2Verkey);

    for (uint64_t i = 0; i < starkZkevm->starkInfo.nPublics; i++)
    {
        publicsJson[i] = zkinInputRecursive2["publics"][i];
    }
    // Add the recursive2 verification key
    publicsJson[44] = to_string(recursive2Verkey["constRoot"][0]);
    publicsJson[45] = to_string(recursive2Verkey["constRoot"][1]);
    publicsJson[46] = to_string(recursive2Verkey["constRoot"][2]);
    publicsJson[47] = to_string(recursive2Verkey["constRoot"][3]);

    json2file(publicsJson, pProverRequest->publicsOutputFile());

    pProverRequest->result = ZKR_SUCCESS;

    TimerStopAndLog(PROVER_AGGREGATED_PROOF);
}

void Prover::genFinalProof(ProverRequest *pProverRequest)
{
    zkassert(config.generateProof());
    zkassert(pProverRequest != NULL);
    zkassert(pProverRequest->type == prt_genFinalProof);

    TimerStart(PROVER_FINAL_PROOF);

    printMemoryInfo(true);
    printProcessInfo(true);

    // Save input to file
    if (config.saveInputToFile)
    {
        json2file(pProverRequest->finalProofInput, pProverRequest->filePrefix + "final_proof.input.json");
    }

    // Input is pProverRequest->finalProofInput (of type json)
    std::string strAddress = mpz_get_str(0, 16, pProverRequest->input.publicInputsExtended.publicInputs.aggregatorAddress.get_mpz_t());
    std::string strAddress10 = mpz_get_str(0, 10, pProverRequest->input.publicInputsExtended.publicInputs.aggregatorAddress.get_mpz_t());

    json zkinFinal = pProverRequest->finalProofInput;

    Goldilocks::Element publics[starksRecursiveF->starkInfo.nPublics];

    for (uint64_t i = 0; i < starksRecursiveF->starkInfo.nPublics; i++)
    {
        publics[i] = Goldilocks::fromString(zkinFinal["publics"][i]);
    }

    CommitPolsStarks cmPolsRecursiveF(pAddressStarksRecursiveF, (1 << starksRecursiveF->starkInfo.starkStruct.nBits), starksRecursiveF->starkInfo.nCm1);
    CircomRecursiveF::getCommitedPols(&cmPolsRecursiveF, config.recursivefVerifier, config.recursivefExec, zkinFinal, (1 << starksRecursiveF->starkInfo.starkStruct.nBits), starksRecursiveF->starkInfo.nCm1);

    // void *pointercmPolsRecursiveF = mapFile("config/recursivef/recursivef.commit", cmPolsRecursiveF.size(), true);
    // memcpy(pointercmPolsRecursiveF, cmPolsRecursiveF.address(), cmPolsRecursiveF.size());
    // unmapFile(pointercmPolsRecursiveF, cmPolsRecursiveF.size());

    //  ----------------------------------------------
    //  Generate Recursive Final proof
    //  ----------------------------------------------

    TimerStart(STARK_RECURSIVE_F_PROOF_BATCH_PROOF);
    uint64_t polBitsRecursiveF = starksRecursiveF->starkInfo.starkStruct.steps[starksRecursiveF->starkInfo.starkStruct.steps.size() - 1].nBits;
    FRIProofC12 fproofRecursiveF((1 << polBitsRecursiveF), FIELD_EXTENSION, starksRecursiveF->starkInfo.starkStruct.steps.size(), starksRecursiveF->starkInfo.evMap.size(), starksRecursiveF->starkInfo.nPublics);
    starksRecursiveF->genProof(fproofRecursiveF, publics);
    TimerStopAndLog(STARK_RECURSIVE_F_PROOF_BATCH_PROOF);

    // Save the proof & zkinproof
    nlohmann::ordered_json jProofRecursiveF = fproofRecursiveF.proofs.proof2json();
    json zkinRecursiveF = proof2zkinStark(jProofRecursiveF);
    zkinRecursiveF["publics"] = zkinFinal["publics"];
    zkinRecursiveF["aggregatorAddr"] = strAddress10;

    // Save proof to file
    if (config.saveProofToFile)
    {
        json2file(zkinRecursiveF["publics"], pProverRequest->filePrefix + "publics.json");

        jProofRecursiveF["publics"] = zkinRecursiveF["publics"];
        json2file(jProofRecursiveF, pProverRequest->filePrefix + "recursivef.proof.json");
    }

    //  ----------------------------------------------
    //  Verifier final
    //  ----------------------------------------------

    TimerStart(CIRCOM_LOAD_CIRCUIT_FINAL);
    CircomFinal::Circom_Circuit *circuitFinal = CircomFinal::loadCircuit(config.finalVerifier);
    TimerStopAndLog(CIRCOM_LOAD_CIRCUIT_FINAL);

    TimerStart(CIRCOM_FINAL_LOAD_JSON);
    CircomFinal::Circom_CalcWit *ctxFinal = new CircomFinal::Circom_CalcWit(circuitFinal);

    CircomFinal::loadJsonImpl(ctxFinal, zkinRecursiveF);
    if (ctxFinal->getRemaingInputsToBeSet() != 0)
    {
        zklog.error("Prover::genProof() Not all inputs have been set. Only " + to_string(CircomFinal::get_main_input_signal_no() - ctxFinal->getRemaingInputsToBeSet()) + " out of " + to_string(CircomFinal::get_main_input_signal_no()));
        exitProcess();
    }
    TimerStopAndLog(CIRCOM_FINAL_LOAD_JSON);

    TimerStart(CIRCOM_GET_BIN_WITNESS_FINAL);
    AltBn128::FrElement *pWitnessFinal = NULL;
    uint64_t witnessSizeFinal = 0;
    CircomFinal::getBinWitness(ctxFinal, pWitnessFinal, witnessSizeFinal);
    CircomFinal::freeCircuit(circuitFinal);
    delete ctxFinal;

    TimerStopAndLog(CIRCOM_GET_BIN_WITNESS_FINAL);

    TimerStart(SAVE_PUBLICS_JSON);
    // Save public file
    json publicJson;
    AltBn128::FrElement aux;
    AltBn128::Fr.toMontgomery(aux, pWitnessFinal[1]);
    publicJson[0] = AltBn128::Fr.toString(aux);
    json2file(publicJson, pProverRequest->publicsOutputFile());
    TimerStopAndLog(SAVE_PUBLICS_JSON);

    if (Zkey::GROTH16_PROTOCOL_ID != protocolId)
    {
        TimerStart(RAPID_SNARK);
        try
        {
            auto [jsonProof, publicSignalsJson] = prover->prove(pWitnessFinal);
            // Save proof to file
            if (config.saveProofToFile)
            {
                json2file(jsonProof, pProverRequest->filePrefix + "final_proof.proof.json");
            }
            TimerStopAndLog(RAPID_SNARK);

            // Populate Proof with the correct data
            PublicInputsExtended publicInputsExtended;
            publicInputsExtended.publicInputs = pProverRequest->input.publicInputsExtended.publicInputs;
            pProverRequest->proof.load(jsonProof, publicSignalsJson);

            pProverRequest->result = ZKR_SUCCESS;
        }
        catch (std::exception &e)
        {
            zklog.error("Prover::genProof() got exception in rapid SNARK:" + string(e.what()));
            exitProcess();
        }
    }
    else
    {
        // Generate Groth16 via rapid SNARK
        TimerStart(RAPID_SNARK);
        json jsonProof;
        try
        {
            auto proof = groth16Prover->prove(pWitnessFinal);
            jsonProof = proof->toJson();
        }
        catch (std::exception &e)
        {
            zklog.error("Prover::genProof() got exception in rapid SNARK:" + string(e.what()));
            exitProcess();
        }
        TimerStopAndLog(RAPID_SNARK);

        // Save proof to file
        if (config.saveProofToFile)
        {
            json2file(jsonProof, pProverRequest->filePrefix + "final_proof.proof.json");
        }
        // Populate Proof with the correct data
        PublicInputsExtended publicInputsExtended;
        publicInputsExtended.publicInputs = pProverRequest->input.publicInputsExtended.publicInputs;
        pProverRequest->proof.load(jsonProof, publicJson);

        pProverRequest->result = ZKR_SUCCESS;
    }

    /***********/
    /* Cleanup */
    /***********/
    free(pWitnessFinal);

    TimerStopAndLog(PROVER_FINAL_PROOF);
}

void Prover::execute(ProverRequest *pProverRequest)
{
    zkassert(!config.generateProof());
    zkassert(pProverRequest != NULL);

    TimerStart(PROVER_EXECUTE);

    printMemoryInfo(true);
    printProcessInfo(true);

    zkassert(pProverRequest != NULL);

    zklog.info("Prover::execute() timestamp: " + pProverRequest->timestamp);
    zklog.info("Prover::execute() UUID: " + pProverRequest->uuid);
    zklog.info("Prover::execute() input file: " + pProverRequest->inputFile());
    // zklog.info("Prover::execute() public file: " + pProverRequest->publicsOutputFile());
    // zklog.info("Prover::execute() proof file: " + pProverRequest->proofFile());

    // Save input to <timestamp>.input.json, as provided by client
    if (config.saveInputToFile)
    {
        json inputJson;
        pProverRequest->input.save(inputJson);
        json2file(inputJson, pProverRequest->inputFile());
    }

    /*******************/
    /* Allocate memory */
    /*******************/

    // Allocate an area of memory, mapped to file, to store all the committed polynomials,
    // and create them using the allocated address
    uint64_t polsSize = PROVER_FORK_NAMESPACE::CommitPols::pilSize();
    void *pExecuteAddress = NULL;

    if (config.zkevmCmPols.size() > 0)
    {
        pExecuteAddress = mapFile(config.zkevmCmPols, polsSize, true);
        zklog.info("Prover::execute() successfully mapped " + to_string(polsSize) + " bytes to file " + config.zkevmCmPols);
    }
    else
    {
        pExecuteAddress = calloc(polsSize, 1);
        if (pExecuteAddress == NULL)
        {
            zklog.error("Prover::execute() failed calling malloc() of size " + to_string(polsSize));
            exitProcess();
        }
        zklog.info("Prover::execute() successfully allocated " + to_string(polsSize) + " bytes");
    }

    /************/
    /* Executor */
    /************/

    PROVER_FORK_NAMESPACE::CommitPols cmPols(pExecuteAddress, PROVER_FORK_NAMESPACE::CommitPols::pilDegree());

    // Execute all the State Machines
    TimerStart(EXECUTOR_EXECUTE_EXECUTE);
    executor.execute(*pProverRequest, cmPols);
    TimerStopAndLog(EXECUTOR_EXECUTE_EXECUTE);

    // Save input to <timestamp>.input.json after execution including dbReadLog
    if (config.saveDbReadsToFile)
    {
        json inputJsonEx;
        pProverRequest->input.save(inputJsonEx, *pProverRequest->dbReadLog);
        json2file(inputJsonEx, pProverRequest->inputDbFile());
    }

    // Save commit pols to file zkevm.commit
    if (config.zkevmCmPolsAfterExecutor != "")
    {
        TimerStart(PROVER_EXECUTE_SAVE_COMMIT_POLS_AFTER_EXECUTOR);
        void *pointerCmPols = mapFile(config.zkevmCmPolsAfterExecutor, cmPols.size(), true);
        memcpy(pointerCmPols, cmPols.address(), cmPols.size());
        unmapFile(pointerCmPols, cmPols.size());
        TimerStopAndLog(PROVER_EXECUTE_SAVE_COMMIT_POLS_AFTER_EXECUTOR);
    }

    /***************/
    /* Free memory */
    /***************/

    // Unmap committed polynomials address
    if (config.zkevmCmPols.size() > 0)
    {
        unmapFile(pExecuteAddress, polsSize);
    }
    else
    {
        free(pExecuteAddress);
    }

    TimerStopAndLog(PROVER_EXECUTE);
}
