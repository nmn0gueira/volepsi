#include "fileBased.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "RsPsi.h"
#include "RsCpsi.h"

#include "coproto/Socket/AsioSocket.h"

namespace volePSI
{

    std::ifstream::pos_type filesize(std::ifstream& file)
    {
        auto pos = file.tellg();
        file.seekg(0, std::ios_base::end);
        auto size = file.tellg();
        file.seekg(pos, std::ios_base::beg);
        return size;
    }

    bool hasSuffix(std::string const& value, std::string const& ending)
    {
        if (ending.size() > value.size()) return false;
        return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
    }

    bool isHexBlock(const std::string& buff)
    {
        if (buff.size() != 32)
            return false;
        auto ret = true;
        for (u64 i = 0; i < 32; ++i)
            ret &= (bool)std::isxdigit(buff[i]);
        return ret;
    }

    block hexToBlock(const std::string& buff)
    {
        assert(buff.size() == 32);

        std::array<u8, 16> vv;
        char b[3];
        b[2] = 0;

        for (u64 i = 0; i < 16; ++i)
        {
            b[0] = buff[2 * i + 0];
            b[1] = buff[2 * i + 1];
            vv[15 - i] = (char)strtol(b, nullptr, 16);;
        }
        return oc::toBlock(vv.data());
    }

    block intStrToBlock(const std::string& buff) {
        int64_t value = std::stoll(buff); 
        std::array<u8, 16> vv = {};
        std::memcpy(vv.data(), &value, sizeof(value));
        return oc::toBlock(vv.data());
    }

    std::vector<block> readSet(const std::string& path, FileType ft, bool debug)
    {
        std::vector<block> ret;
        if (ft == FileType::Bin)
        {
            std::ifstream file(path, std::ios::binary | std::ios::in);
            if (file.is_open() == false)
                throw std::runtime_error("failed to open file: " + path);
            auto size = filesize(file);
            if (size % 16)
                throw std::runtime_error("Bad file size. Expecting a binary file with 16 byte elements");

            ret.resize(size / 16);
            file.read((char*)ret.data(), size);
        }
        else if (ft == FileType::Csv)
        {
            // we will use this to hash large inputs
            oc::RandomOracle hash(sizeof(block));

            std::ifstream file(path, std::ios::in);
            if (file.is_open() == false)
                throw std::runtime_error("failed to open file: " + path);
            std::string buffer;
            while (std::getline(file, buffer))
            {
                // if the input is already a 32 char hex 
                // value, just parse it as is.
                if (isHexBlock(buffer))
                {
                    ret.push_back(hexToBlock(buffer));
                }
                else
                {
                    ret.emplace_back();
                    hash.Reset();
                    hash.Update(buffer.data(), buffer.size());
                    hash.Final(ret.back());
                }
            }
        }
        else
        {
            throw std::runtime_error("unknown file type");
        }

        if (debug)
        {
            u64 maxPrint = 40;
            std::unordered_map<block, u64> hashes;
            for (u64 i = 0; i < ret.size(); ++i)
            {
                auto r = hashes.insert({ ret[i], i });
                if (r.second == false)
                {
                    std::cout << "duplicate at index " << i << " & " << r.first->second << std::endl;
                    --maxPrint;

                    if (!maxPrint)
                        break;
                }
            }


            if (maxPrint != 40)
                throw RTE_LOC;
        }

        return ret;
    }

    template<typename InputIterator >
    void counting_sort(InputIterator first, InputIterator last, u64 endIndex)
    {
        using ValueType = typename std::iterator_traits<InputIterator>::value_type;
        std::vector<u64> counts(endIndex);

        for (auto value = first; value < last; ++value) {
            ++counts[*value];
        }

        for (u64 i = 0; i < counts.size(); ++i) {
            ValueType& value = i;
            u64& size = counts[i];
            std::fill_n(first, size, value);
            std::advance(first, size);
        }
    }

    std::vector<char> writeOutput(const std::string& outPath, FileType ft, const std::vector<u64>& intersection, bool indexOnly, std::string inPath)
    {
        std::vector<char> outputData;
        std::ofstream file;

        if (ft == FileType::Bin)
            file.open(outPath, std::ios::out | std::ios::trunc | std::ios::binary);
        else
            file.open(outPath, std::ios::out | std::ios::trunc);

        if (file.is_open() == false)
            throw std::runtime_error("failed to open the output file: " + outPath);

        if (indexOnly)
        {

            if (ft == FileType::Bin)
            {
                file.write((char*)intersection.data(), intersection.size() * sizeof(u64));
                outputData.resize(intersection.size() * sizeof(u64));
                std::memcpy(outputData.data(), intersection.data(), intersection.size() * sizeof(u64));
            }
            else
            {
                std::ostringstream oss;

                for (auto i : intersection) {
                    file << i << "\n";
                    oss << i << "\n";
                }           

                std::string str = oss.str();
                outputData.assign(std::make_move_iterator(str.begin()), std::make_move_iterator(str.end()));
            }
        }
        else
        {
            if (ft == FileType::Bin)
            {
                std::ifstream inFile(inPath, std::ios::binary | std::ios::in);
                if (inFile.is_open() == false)
                    throw std::runtime_error("failed to open file: " + inPath);
                auto size = filesize(inFile);
                if (size % 16)
                    throw std::runtime_error("Bad file size. Expecting a binary file with 16 byte elements");

                auto n = size / 16;
                std::vector<block> fData(n);
                inFile.read((char*)fData.data(), size);
                outputData.resize(intersection.size() * sizeof(block));
                for (u64 i = 0; i < intersection.size(); ++i)
                {
                    file.write((char*)fData[intersection[i]].data(), sizeof(block));
                    memcpy(outputData.data() + (i * sizeof(block)), fData[intersection[i]].data(), sizeof(block));

                }

            }
            else if (ft == FileType::Csv)
            {
                std::ifstream inFile(inPath, std::ios::in);
                if (inFile.is_open() == false)
                    throw std::runtime_error("failed to open file: " + inPath);

                u64 size = filesize(inFile);
                std::vector<char> fData(size);
                inFile.read(fData.data(), size);


                std::vector<span<char>> beg;
                auto iter = fData.begin();
                for (u64 i = 0; i < size; ++i)
                {
                    if (fData[i] == '\n')
                    {
                        beg.push_back(span<char>(iter, fData.begin() + i));
                        iter = fData.begin() + i + 1;
                        assert(beg.back().size());
                    }
                }

                if (iter != fData.end())
                    beg.push_back(span<char>(iter, fData.end()));

                std::ostringstream oss;
                for (u64 i = 0; i < intersection.size(); ++i)
                {
                    auto w = beg[intersection[i]];
                    file.write(w.data(), w.size());
                    file << '\n';
                    oss.write(w.data(), w.size());
                    oss << '\n';
                }

                std::string str = oss.str();
                outputData.assign(std::make_move_iterator(str.begin()), std::make_move_iterator(str.end()));
            }
            else
            {
                throw std::runtime_error("unknown file type");
            }
        }
        return outputData;
    }


    void doFilePSI(const oc::CLP& cmd)
    {
        try {
            
            auto path = cmd.get<std::string>("in");
            auto outPath = cmd.getOr<std::string>("out", path + ".out");
            bool debug = cmd.isSet("debug");
            bool mal = cmd.isSet("malicious");
            bool indexOnly = cmd.isSet("indexSet");
            bool sortOutput = !cmd.isSet("noSort");
            bool tls = cmd.isSet("tls");
            bool quiet = cmd.isSet("quiet");
            bool verbose = cmd.isSet("v");
            u64 numThreads = cmd.getOr("nt", 1);


            block seed;
            if (cmd.hasValue("seed"))
            {
                auto seedStr = cmd.get<std::string>("seed");
                oc::RandomOracle ro(sizeof(block));
                ro.Update(seedStr.data(), seedStr.size());
                ro.Final(seed);
            }
            else
                seed = oc::sysRandomSeed();

            // The vole type, default to expand accumulate.
            auto type = oc::DefaultMultType;
#ifdef ENABLE_INSECURE_SILVER
            type = cmd.isSet("useSilver") ? oc::MultType::slv5 : type;
#endif
#ifdef ENABLE_BITPOLYMUL
            type = cmd.isSet("useQC") ? oc::MultType::QuasiCyclic : type;
#endif

            FileType ft = FileType::Unspecified;
            if (cmd.isSet("bin")) ft = FileType::Bin;
            if (cmd.isSet("csv")) ft = FileType::Csv;
            if (ft == FileType::Unspecified)
            {
                if (hasSuffix(path, ".bin"))
                    ft = FileType::Bin;
                else if (hasSuffix(path, ".csv"))
                    ft = FileType::Csv;
            }
            if (ft == FileType::Unspecified)
                throw std::runtime_error("unknown file extension, must be .csv or .bin or you must specify the -bin or -csv flags.");

            u64 statSetParam = cmd.getOr("ssp", 40);
            auto ip = cmd.getOr<std::string>("ip", "localhost:1212");
            auto r = (Role)cmd.getOr<int>("r", 2);
            if (r != Role::Sender && r != Role::Receiver)
                throw std::runtime_error("-r tag must be set with value 0 (sender) or 1 (receiver).");

            auto isServer = cmd.getOr<int>("server", (int)r);
            if (r != Role::Sender && r != Role::Receiver)
                throw std::runtime_error("-server tag must be set with value 0 or 1.");
            oc::Timer timer;

            if (!quiet)
                std::cout << "Reading set... " << std::flush;
            auto readBegin = timer.setTimePoint("");
            std::vector<block> set = readSet(path, ft, debug);
            auto readEnd = timer.setTimePoint("");
            if (!quiet)
                std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(readEnd - readBegin).count() << "ms" << std::endl;


            if (!quiet)
                std::cout << "Connecting as " << (tls ? "tls " : "") << (isServer ? "server" : "client") << " at address " << ip << "..." << std::flush;
            coproto::Socket chl;
            auto connBegin = timer.setTimePoint("");
            if (tls)
            {
                std::string CACert = cmd.get<std::string>("CA");
                auto privateKey = cmd.get<std::string>("sk");
                auto publicKey = cmd.get<std::string>("pk");

                if (!exist(CACert) || !exist(privateKey) || !exist(publicKey))
                {
                    std::cout << "\n";
                    if (!exist(CACert))
                        std::cout << "CA cert " << CACert << " does not exist" << std::endl;
                    if (!exist(privateKey))
                        std::cout << "private key " << privateKey << " does not exist" << std::endl;
                    if (!exist(publicKey))
                        std::cout << "public key " << publicKey << " does not exist" << std::endl;

                    std::cout << "Please correctly set -CA=<path> -sk=<path> -pk=<path> to the CA cert, user private key "
                        << " and public key respectively." << std::endl;

                    throw std::runtime_error("bad TLS parameter.");
                }

#ifdef COPROTO_ENABLE_OPENSSL
                boost::asio::ssl::context ctx(!isServer ?
                    boost::asio::ssl::context::tlsv13_client :
                    boost::asio::ssl::context::tlsv13_server
                );

                ctx.set_verify_mode(
                    boost::asio::ssl::verify_peer |
                    boost::asio::ssl::verify_fail_if_no_peer_cert);
                ctx.load_verify_file(CACert);
                ctx.use_private_key_file(privateKey, boost::asio::ssl::context::file_format::pem);
                ctx.use_certificate_file(publicKey, boost::asio::ssl::context::file_format::pem);

                chl = coproto::sync_wait(
                    !isServer ?
                    macoro::make_task(coproto::AsioTlsConnect(ip, coproto::global_io_context(), ctx)) :
                    macoro::make_task(coproto::AsioTlsAcceptor(ip, coproto::global_io_context(), ctx))
                );
#else
                throw std::runtime_error("COPROTO_ENABLE_OPENSSL must be define (via cmake) to use TLS sockets. " COPROTO_LOCATION);
#endif
            }
            else
            {
#ifdef COPROTO_ENABLE_BOOST
                chl = coproto::asioConnect(ip, isServer);
#else
                throw std::runtime_error("COPROTO_ENABLE_BOOST must be define (via cmake) to use tcp sockets. " COPROTO_LOCATION);
#endif
            }
            auto connEnd = timer.setTimePoint("");
            if (!quiet)
                std::cout << ' ' << std::chrono::duration_cast<std::chrono::milliseconds>(connEnd - connBegin).count()
                << "ms\nValidating set sizes... " << std::flush;

            if (set.size() != cmd.getOr((r == Role::Sender) ? "senderSize" : "receiverSize", set.size()))
                throw std::runtime_error("File does not contain the specified set size.");
            u64 theirSize;
            macoro::sync_wait(chl.send(set.size()));
            macoro::sync_wait(chl.recv(theirSize));

            if (theirSize != cmd.getOr((r != Role::Sender) ? "senderSize" : "receiverSize", theirSize))
                throw std::runtime_error("Other party's set size does not match.");



            auto valEnd = timer.setTimePoint("");
            if (!quiet)
                std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(valEnd - connEnd).count()
                << "ms\nRunning PSI... " << std::flush;

            if (r == Role::Sender)
            {
                RsPsiSender sender;

                sender.mDebug = debug;
                sender.setMultType(type);
                sender.init(set.size(), theirSize, statSetParam, seed, mal, numThreads);
                macoro::sync_wait(sender.run(set, chl));

                auto psiEnd = timer.setTimePoint("");
                auto psiBytesSent = chl.bytesSent();

                if (!quiet) {
                    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(psiEnd - valEnd).count() << "ms\nReceiving output file (includes wait time)..." << std::flush;
                }

                size_t fileSize;
                macoro::sync_wait(chl.recv(fileSize));
                std::vector<char> fileData(fileSize);
                macoro::sync_wait(chl.recv(fileData));
                macoro::sync_wait(chl.flush());

                auto recvEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << " " << std::chrono::duration_cast<std::chrono::milliseconds>(recvEnd - psiEnd).count() << "ms\nWriting output to " << outPath << "..." << std::flush;

                std::ofstream outFile(outPath, (ft == FileType::Bin) ? std::ios::binary : std::ios::out);
                if (!outFile.is_open())
                    throw std::runtime_error("failed to open the file: " + outPath);

                outFile.write(fileData.data(), fileSize);
                auto outEnd = timer.setTimePoint("");

                if (!quiet)
                    std::cout << " " << std::chrono::duration_cast<std::chrono::milliseconds>(outEnd - recvEnd).count()
                    << "ms\nBytes sent (PSI only): " << psiBytesSent << std::endl << std::flush;
                
            }
            else
            {
                RsPsiReceiver recver;

                recver.mDebug = debug;
                recver.setMultType(type);
                recver.init(theirSize, set.size(), statSetParam, seed, mal, numThreads);
                macoro::sync_wait(recver.run(set, chl));

                auto psiEnd = timer.setTimePoint("");
                auto psiBytesSent = chl.bytesSent();

                if (sortOutput) {
                    if (!quiet)
                        std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(psiEnd - valEnd).count() << "ms\nSorting output... " << std::flush;
                    counting_sort(recver.mIntersection.begin(), recver.mIntersection.end(), set.size());
                }

                auto sortEnd = timer.setTimePoint("");

                if (!quiet)
                    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(sortEnd - psiEnd).count()
                    << "ms\nWriting output to " << outPath << "..." << std::flush;
                
                std::vector<char> outputData = writeOutput(outPath, ft, recver.mIntersection, indexOnly, path);

                auto outEnd = timer.setTimePoint("");
                if (!quiet) {
                    std::cout << " " << std::chrono::duration_cast<std::chrono::milliseconds>(outEnd - sortEnd).count() << "ms\nSending output file..." << std::flush;
                }

                macoro::sync_wait(chl.send(outputData.size()));
                macoro::sync_wait(chl.send(outputData));
                macoro::sync_wait(chl.flush());
                
                auto sendEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << " " << std::chrono::duration_cast<std::chrono::milliseconds>(sendEnd - outEnd).count()
                    << "ms\nBytes sent (PSI only): " << psiBytesSent << std::endl << std::flush;

                if (verbose)
                    std::cout << "Intesection size: " << recver.mIntersection.size() << std::endl;
            }

        }
        catch (std::exception& e)
        {
            std::cout << oc::Color::Red << "Exception: " << e.what() << std::endl << oc::Color::Default;

            std::cout << "Try adding command line argument -debug" << std::endl;
        }
    }


    std::pair<std::vector<block>, std::vector<std::vector<block>>> readCSV(const std::string& path, bool debug)
    {
        std::vector<block> identifiers;
        std::vector<std::vector<block>> associatedValuesSet;

        oc::RandomOracle hash(sizeof(block));

        std::ifstream file(path, std::ios::in);
        if (!file.is_open()) {
            throw std::runtime_error("failed to open file: " + path);
        }

        std::string line;
        while (std::getline(file, line))
        {
            std::istringstream lineStream(line);
            std::string identifier;
            std::getline(lineStream, identifier, ',');

            // Trim whitespace from identifier (useful for receiver csv with only one column)
            identifier.erase(0, identifier.find_first_not_of(" \t\r\n"));
            identifier.erase(identifier.find_last_not_of(" \t\r\n") + 1);     
            
            if (isHexBlock(identifier)) {
                identifiers.push_back(hexToBlock(identifier));
            } else {
                identifiers.emplace_back();
                hash.Reset();
                hash.Update(identifier.data(), identifier.size());
                hash.Final(identifiers.back());
            }

            std::vector<block> associatedValues;
            std::string value;
            while (std::getline(lineStream, value, ',')) {
                associatedValues.emplace_back(intStrToBlock(value));
            }

            associatedValuesSet.emplace_back(associatedValues);
        }

        if (debug)
        {
            u64 maxPrint = 40;
            std::unordered_map<block, u64> hashes;
            for (u64 i = 0; i < identifiers.size(); ++i)
            {
                auto r = hashes.insert({ identifiers[i], i });
                if (r.second == false)
                {
                    std::cout << "duplicate at index " << i << " & " << r.first->second << std::endl;
                    --maxPrint;

                    if (!maxPrint)
                        break;
                }
            }

            if (maxPrint != 40)
                throw std::runtime_error("Too many duplicates found");
        }

        return std::make_pair(identifiers, associatedValuesSet);
    }

    void writeShares(std::string outPath, u64 num_columns, const oc::BitVector& mFlagBits, const oc::Matrix<u8>& mValues)
    {
        std::ofstream file;

        file.open(outPath, std::ios::out | std::ios::trunc);

        if (file.is_open() == false)
            throw std::runtime_error("failed to open the output file: " + outPath);

        for (u64 i = 0; i < mFlagBits.size(); ++i)
        {
            file << mFlagBits[i];

            for (u64 j = 0; j < num_columns; ++j)
            {
                file << "," << *(block*)&mValues(i, j * sizeof(block));
            }
            
            file << std::endl;
        }

        file.close();
    }

    void writeMapping(std::string outPath, const std::vector<u64>& mMapping)
    {
        std::ofstream file;

        // Open the output file in write mode, truncating any existing content
        file.open(outPath, std::ios::out | std::ios::trunc);

        if (file.is_open() == false)
            throw std::runtime_error("failed to open the output file: " + outPath);

        for (u64 i = 0; i < mMapping.size(); ++i)
        {
            file << mMapping[i] << std::endl;
        }

        file.close();
    }


    void doFileCPSI(osuCrypto::CLP& cmd)
    {
        try {

            auto path = cmd.get<std::string>("in");
            auto outPath = cmd.getOr<std::string>("out", path + ".out");
            bool debug = cmd.isSet("debug");
            bool tls = cmd.isSet("tls");
            bool quiet = cmd.isSet("quiet");
            u64 numThreads = cmd.getOr("nt", 1);
            ValueShareType type = cmd.isSet("add32") ? ValueShareType::add32 : ValueShareType::Xor;

            block seed;
            if (cmd.hasValue("seed"))
            {
                auto seedStr = cmd.get<std::string>("seed");
                oc::RandomOracle ro(sizeof(block));
                ro.Update(seedStr.data(), seedStr.size());
                ro.Final(seed);
            }
            else
                seed = oc::sysRandomSeed();
            
            u64 statSetParam = cmd.getOr("ssp", 40);
            auto ip = cmd.getOr<std::string>("ip", "localhost:1212");
            auto r = (Role)cmd.getOr<int>("r", 2);
            if (r != Role::Sender && r != Role::Receiver)
                throw std::runtime_error("-r tag must be set with value 0 (sender) or 1 (receiver).");

            auto isServer = cmd.getOr<int>("server", (int)r);
            if (r != Role::Sender && r != Role::Receiver)
                throw std::runtime_error("-server tag must be set with value 0 or 1.");

            osuCrypto::Timer timer;

            if (!quiet)
                std::cout << "Reading csv... " << std::flush;
            auto readBegin = timer.setTimePoint("");

            std::pair<std::vector<block>, std::vector<std::vector<block>>> set = readCSV(path, debug);
            std::vector<block> identifiers = set.first;
            std::vector<std::vector<block>> associatedValues = set.second;

            auto readEnd = timer.setTimePoint("");
            if (!quiet)
                std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(readEnd - readBegin).count() << "ms" << std::endl;

            if (!quiet)
                std::cout << "Connecting as " << (tls ? "tls " : "") << (isServer ? "server" : "client") << " at address " << ip << "..." << std::flush;
            coproto::Socket chl;
            auto connBegin = timer.setTimePoint("");
            if (tls)
            {
                std::string CACert = cmd.get<std::string>("CA");
                auto privateKey = cmd.get<std::string>("sk");
                auto publicKey = cmd.get<std::string>("pk");

                if (!exist(CACert) || !exist(privateKey) || !exist(publicKey))
                {
                    std::cout << "\n";
                    if (!exist(CACert))
                        std::cout << "CA cert " << CACert << " does not exist" << std::endl;
                    if (!exist(privateKey))
                        std::cout << "private key " << privateKey << " does not exist" << std::endl;
                    if (!exist(publicKey))
                        std::cout << "public key " << publicKey << " does not exist" << std::endl;

                    std::cout << "Please correctly set -CA=<path> -sk=<path> -pk=<path> to the CA cert, user private key "
                        << " and public key respectively." << std::endl;

                    throw std::runtime_error("bad TLS parameter.");
                }

#ifdef COPROTO_ENABLE_OPENSSL
                boost::asio::ssl::context ctx(!isServer ?
                    boost::asio::ssl::context::tlsv13_client :
                    boost::asio::ssl::context::tlsv13_server
                );

                ctx.set_verify_mode(
                    boost::asio::ssl::verify_peer |
                    boost::asio::ssl::verify_fail_if_no_peer_cert);
                ctx.load_verify_file(CACert);
                ctx.use_private_key_file(privateKey, boost::asio::ssl::context::file_format::pem);
                ctx.use_certificate_file(publicKey, boost::asio::ssl::context::file_format::pem);

                chl = coproto::sync_wait(
                    !isServer ?
                    macoro::make_task(coproto::AsioTlsConnect(ip, coproto::global_io_context(), ctx)) :
                    macoro::make_task(coproto::AsioTlsAcceptor(ip, coproto::global_io_context(), ctx))
                );
#else
                throw std::runtime_error("COPROTO_ENABLE_OPENSSL must be define (via cmake) to use TLS sockets. " COPROTO_LOCATION);
#endif
            }
            else
            {
#ifdef COPROTO_ENABLE_BOOST
                chl = coproto::asioConnect(ip, isServer);
#else
                throw std::runtime_error("COPROTO_ENABLE_BOOST must be define (via cmake) to use tcp sockets. " COPROTO_LOCATION);
#endif
            }
            auto connEnd = timer.setTimePoint("");
            if (!quiet)
                std::cout << ' ' << std::chrono::duration_cast<std::chrono::milliseconds>(connEnd - connBegin).count()
                << "ms\nValidating set sizes... " << std::flush;
            
            u64 size = identifiers.size();
            if (size != cmd.getOr((r == Role::Sender) ? "senderSize" : "receiverSize", size))
                throw std::runtime_error("File does not contain the specified set size.");
            u64 theirSize;

            macoro::sync_wait(chl.send(size));
            macoro::sync_wait(chl.recv(theirSize));

            if (theirSize != cmd.getOr((r != Role::Sender) ? "senderSize" : "receiverSize", theirSize))
                throw std::runtime_error("Other party's set size does not match.");

            u64 their_columns;
            u64 num_columns = r == Role::Sender ? associatedValues[0].size() : cmd.get<int>("senderColumns");
            macoro::sync_wait(chl.send(num_columns));
            macoro::sync_wait(chl.recv(their_columns));

            if (their_columns != num_columns)
                throw std::runtime_error("Other party's number of columns does not match.");
            
            auto valEnd = timer.setTimePoint("");

            if (!quiet) {
                std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(valEnd - connEnd).count() << "ms\nRunning CPSI (" 
                << (type == ValueShareType::Xor ? "XOR" : "additive") << " sharing)... " << std::flush;
            }
            
            auto byteLength = num_columns * sizeof(block);

            if (r == Role::Sender)
            {
                RsCpsiSender sender;
                RsCpsiSender::Sharing ss;
                osuCrypto::Matrix<u8> senderValues(size, byteLength);
                for (size_t row = 0; row < size; ++row)
                {
                    const auto& valueRow = associatedValues[row];
                    
                    if (valueRow.size() != num_columns)
                    {
                        throw std::runtime_error("Number of associated values does not match the expected column count.");
                    }

                    std::memcpy(senderValues.data() + row * byteLength, valueRow.data(), byteLength);      
                }

                sender.init(size, theirSize, byteLength, statSetParam, seed, numThreads, type);

                macoro::sync_wait(sender.send(identifiers, senderValues, ss, chl));
                macoro::sync_wait(chl.flush());

                auto cpsiEnd = timer.setTimePoint("");

                if (!quiet)
                    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(cpsiEnd - valEnd).count()
                    << "ms\nWriting shares to " << outPath << "..." << std::flush;

                writeShares(outPath, num_columns, ss.mFlagBits, ss.mValues);
                auto outEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << " " << std::chrono::duration_cast<std::chrono::milliseconds>(outEnd - cpsiEnd).count()
                    << "ms\nBytes sent: " << chl.bytesSent() << std::endl << std::flush;
                
                if (debug) {
                    std::cout << "sShare.mValues rows: " << ss.mValues.rows() << ", cols: " << ss.mValues.cols() << std::endl;
                    std::cout << "sShare.mFlagBits size: " << ss.mFlagBits.size() << std::endl;
                    std::cout << "sShare.mMapping size: " << ss.mMapping.size() << std::endl;
                }                
            }
            else
            {
                RsCpsiReceiver recv;
                RsCpsiReceiver::Sharing rs;
                recv.init(theirSize, size, byteLength, statSetParam, seed, numThreads, type);

                macoro::sync_wait(recv.receive(identifiers, rs, chl));
                macoro::sync_wait(chl.flush());

                auto cpsiEnd = timer.setTimePoint("");

                if (!quiet)
                    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(cpsiEnd - valEnd).count()
                    << "ms\nWriting shares to " << outPath << "..." << std::flush;

                writeShares(outPath, num_columns, rs.mFlagBits, rs.mValues);
                auto outSharesEnd = timer.setTimePoint("");
                
                std::string mappingPath = outPath.substr(0, outPath.find_last_of('/') + 1) + "mapping.out";
                if (!quiet)
                    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(outSharesEnd - cpsiEnd).count()
                    << "ms\nWriting mapping to " << mappingPath << "..." << std::flush;
                
                writeMapping(mappingPath, rs.mMapping);
                auto outMappingEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << " " << std::chrono::duration_cast<std::chrono::milliseconds>(outMappingEnd - outSharesEnd).count()
                    << "ms\nBytes sent: " << chl.bytesSent() << std::endl << std::flush;

                if (debug) {
                    std::cout << "rShare.mValues rows: " << rs.mValues.rows() << ", cols: " << rs.mValues.cols() << std::endl;
                    std::cout << "rShare.mFlagBits size: " << rs.mFlagBits.size() << std::endl;
                    std::cout << "rShare.mMapping size: " << rs.mMapping.size() << std::endl;
                } 
              
            }
        }
        catch (std::exception& e)
        {
            std::cout << oc::Color::Red << "Exception: " << e.what() << std::endl << oc::Color::Default;

            std::cout << "Try adding command line argument -debug" << std::endl;
        }
    }
}