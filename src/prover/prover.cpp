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
#include "gevson.hpp"

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

    json inputJson;
    pProverRequest->input.save(inputJson);

    Gevson gevson("~/img/localkey.pki", "http://localhost:9944");
    std::vector<json> gevInput = {inputJson};
    json gev_tx = gevson.generateProof(gevInput, std::string("BATCH_PROOF"));

    zklog.info("genBatchProof() Getting Gevulot Transaction JSON: " + gev_tx.dump());

    std::string proof_url = gev_tx["payload"]["Proof"]["files"][0]["url"].get<std::string>();
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

    zklog.info("Prover::genAggregatedProof() timestamp: " + pProverRequest->timestamp);
    zklog.info("Prover::genAggregatedProof() UUID: " + pProverRequest->uuid);
    zklog.info("Prover::genAggregatedProof() input file: " + pProverRequest->inputFile());

    Gevson gevson("~/img/localkey.pki", "http://localhost:9944");
    std::vector<json> gevInput = {pProverRequest->aggregatedProofInput1, pProverRequest->aggregatedProofInput2};

    json gev_tx = gevson.generateProof(gevInput, std::string("AGGREGATED_PROOF"));
    zklog.info("genAggregatedProof() Getting Gevulot Transaction JSON: " + gev_tx.dump());

    std::string proof_url = gev_tx["payload"]["Proof"]["files"][0]["url"].get<std::string>();
    zklog.info("genAggregatedProof() Getting Gevulot Transaction JSON: " + gev_tx.dump());

    ordered_json proof;
    url2json(proof_url, proof);

    pProverRequest->aggregatedProofOutput = proof;

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

    zklog.info("Prover::genFinalProof() timestamp: " + pProverRequest->timestamp);
    zklog.info("Prover::genFinalProof() UUID: " + pProverRequest->uuid);
    zklog.info("Prover::genFinalProof() input file: " + pProverRequest->inputFile());

    // json inputJson;
    // pProverRequest->input.save(inputJson);

    Gevson gevson("~/img/localkey.pki", "http://localhost:9944");
    std::vector<json> gevInput = {pProverRequest->finalProofInput};
    json gev_tx = gevson.generateProof(gevInput, std::string("FINAL_PROOF"));

    zklog.info("genFinalProof() Getting Gevulot Transaction JSON: " + gev_tx.dump());

    std::string proof_url = gev_tx["payload"]["Proof"]["files"][0]["url"].get<std::string>();
    std::string public_url = gev_tx["payload"]["Proof"]["files"][1]["url"].get<std::string>();
    zklog.info("genFinalProof() Proof file URL: " + proof_url);
    zklog.info("genFinalProof() Public file URL: " + public_url);

    json proof;
    url2json(proof_url, proof);

    json publicJson;
    url2json(public_url, publicJson);

    pProverRequest->proof.load(proof, publicJson);

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
