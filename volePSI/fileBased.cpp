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

    void writeOutput(std::string outPath, FileType ft, const std::vector<u64>& intersection, bool indexOnly, std::string inPath)
    {
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
            }
            else
            {
                for (auto i : intersection)
                    file << i << "\n";
            }
        }
        else
        {
            //std::set<u64> set(intersection.begin(), intersection.end());
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
                for (u64 i = 0; i < intersection.size(); ++i)
                {
                    file.write((char*)fData[intersection[i]].data(), sizeof(block));
                }

            }
            else if (ft == FileType::Csv)
            {
                // we will use this to hash large inputs
                oc::RandomOracle hash(sizeof(block));

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

                for (u64 i = 0; i < intersection.size(); ++i)
                {
                    auto w = beg[intersection[i]];
                    file.write(w.data(), w.size());
                    file << '\n';
                }
            }
            else
            {
                throw std::runtime_error("unknown file type");
            }
        }
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
                std::cout << "reading set... " << std::flush;
            auto readBegin = timer.setTimePoint("");
            std::vector<block> set = readSet(path, ft, debug);
            auto readEnd = timer.setTimePoint("");
            if (!quiet)
                std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(readEnd - readBegin).count() << "ms" << std::endl;


            if (!quiet)
                std::cout << "connecting as " << (tls ? "tls " : "") << (isServer ? "server" : "client") << " at address " << ip << std::flush;
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
                << "ms\nrunning PSI... " << std::flush;

            if (r == Role::Sender)
            {
                RsPsiSender sender;

                sender.mDebug = debug;
                sender.setMultType(type);
                sender.init(set.size(), theirSize, statSetParam, seed, mal, 1);
                macoro::sync_wait(sender.run(set, chl));
                macoro::sync_wait(chl.flush());

                auto psiEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(psiEnd - valEnd).count()
                    << "ms\nDone" << std::endl;
            }
            else
            {
                RsPsiReceiver recver;

                recver.mDebug = debug;
                recver.setMultType(type);
                recver.init(theirSize, set.size(), statSetParam, seed, mal, 1);
                macoro::sync_wait(recver.run(set, chl));
                macoro::sync_wait(chl.flush());


                auto psiEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(psiEnd - valEnd).count()
                    << "ms\nWriting output to " << outPath << std::flush;

                if (sortOutput)
                    counting_sort(recver.mIntersection.begin(), recver.mIntersection.end(), set.size());

                writeOutput(outPath, ft, recver.mIntersection, indexOnly, path);

                auto outEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << " " << std::chrono::duration_cast<std::chrono::milliseconds>(outEnd - psiEnd).count()
                    << "ms\n" << std::flush;


                if (verbose)
                    std::cout << "intesection_size = " << recver.mIntersection.size() << std::endl;
            }

        }
        catch (std::exception& e)
        {
            std::cout << oc::Color::Red << "Exception: " << e.what() << std::endl << oc::Color::Default;

            std::cout << "Try adding command line argument -debug" << std::endl;
        }
    }


    std::vector<std::pair<block, std::vector<u8>>> readCSV(const std::string& path, bool debug)
    {
        std::vector<std::pair<block, std::vector<u8>>> ret;

        // Assuming oc::RandomOracle is used for hashing
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
            std::getline(lineStream, identifier, ','); // Read the first column (identifier)

            block identifierBlock;
            // Check if identifier is hex or should be hashed
            if (isHexBlock(identifier)) {
                identifierBlock = hexToBlock(identifier);
            } else {
                hash.Reset();
                hash.Update(identifier.data(), identifier.size());
                hash.Final(identifierBlock);
            }

            // Read the rest of the columns (associated values)
            std::vector<u8> associatedValues;
            std::string value;
            while (std::getline(lineStream, value, ',')) {
                associatedValues.emplace_back(static_cast<u8>(std::stoi(value)));
            }

            // Store both the identifier (as block) and the associated values
            ret.emplace_back(identifierBlock, associatedValues);
        }

        if (debug)
        {
            u64 maxPrint = 40;
            std::unordered_map<block, u64> hashes;
            for (u64 i = 0; i < ret.size(); ++i)
            {
                auto r = hashes.insert({ ret[i].first, i }); // ret[i].first is the block (identifier)
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

        return ret;
    }


    void doFileCPSI(osuCrypto::CLP& cmd)
    {
        try {

            auto path = cmd.get<std::string>("in");
            auto outPath = cmd.getOr<std::string>("out", path + ".out");
            bool debug = cmd.isSet("debug");
            bool tls = cmd.isSet("tls");
            bool quiet = cmd.isSet("quiet");
            bool verbose = cmd.isSet("v");

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
                std::cout << "reading csv... " << std::flush;
            auto readBegin = timer.setTimePoint("");
            std::vector<std::pair<block, std::vector<u8>>> set = readCSV(path, debug);
            auto readEnd = timer.setTimePoint("");
            if (!quiet)
                std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(readEnd - readBegin).count() << "ms" << std::endl;

            if (!quiet)
                std::cout << "connecting as " << (tls ? "tls " : "") << (isServer ? "server" : "client") << " at address " << ip << std::flush;
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
            
            u64 size = set.size();
            if (size != cmd.getOr((r == Role::Sender) ? "senderSize" : "receiverSize", set.size()))
                throw std::runtime_error("File does not contain the specified set size.");
            u64 theirSize;

            macoro::sync_wait(chl.send(size));
            macoro::sync_wait(chl.recv(theirSize));

            if (theirSize != cmd.getOr((r != Role::Sender) ? "senderSize" : "receiverSize", theirSize))
                throw std::runtime_error("Other party's set size does not match.");

            u64 their_columns;
            u64 num_columns = set[0].second.size();
            macoro::sync_wait(chl.send(num_columns));  // ASSUMES ALL RECORDS HAVE SAME NUMBER OF VALUES
            macoro::sync_wait(chl.recv(their_columns));

            if (their_columns != cmd.getOr((r != Role::Sender) ? "senderColumns" : "receiverColumns", theirSize))
                throw std::runtime_error("Other party's number of columns does not match.");
            
            auto valEnd = timer.setTimePoint("");

            if (!quiet)
                std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(valEnd - connEnd).count() << "ms\nrunning PSI... " << std::flush;
            
            auto byteLength = num_columns * sizeof(block);

            if (r == Role::Sender)
            {
                RsCpsiSender sender;
                RsCpsiSender::Sharing ss;
                std::vector<block> sendSet(size);
                osuCrypto::Matrix<u8> senderValues(size, byteLength);
                for (size_t row = 0; row < size; ++row)
                {
                    sendSet[row] = set[row].first;
                    const auto& associatedValues = set[row].second; // Get the associated values (std::vector<u8>)
                    
                    if (associatedValues.size() != num_columns)
                    {
                        throw std::runtime_error("Number of associated values does not match the expected column count.");
                    }

                    std::memcpy(senderValues.data() + row * byteLength, associatedValues.data(), byteLength);
                }

                if (verbose)
                    std::cout << "sender start\n";
                std::cout << "sender size: " << size << std::endl;
                std::cout << "receiver size: " << theirSize << std::endl;
                sender.init(size, theirSize, byteLength, statSetParam, seed, 1);
                std::cout << "Init done" << std::endl;

                macoro::sync_wait(sender.send(sendSet, senderValues, ss, chl));
                std::cout << "send done" << std::endl;
            }
            else
            {
                RsCpsiReceiver recv;
                RsCpsiReceiver::Sharing rs;
                std::vector<block> recvSet(size);
                for (size_t row = 0; row < size; ++row)
                {
                    recvSet[row] = set[row].first;
                }

                if (verbose)
                    std::cout << "receiver start\n";
                std::cout << "sender size: " << theirSize << std::endl;
                std::cout << "receiver size: " << size << std::endl;
                recv.init(theirSize, size, byteLength, statSetParam, seed, 1);
                std::cout << "Init done" << std::endl;

                macoro::sync_wait(recv.receive(recvSet, rs, chl));
                std::cout << "receive done" << std::endl;
            }
            macoro::sync_wait(chl.flush());

            auto cpsiEnd = timer.setTimePoint("");
            std::cout << "Bytes sent: " << chl.bytesSent() << std::endl;
            if (!quiet)
                std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(cpsiEnd - valEnd).count() << "ms\nDone" << std::endl;
        }
        catch (std::exception& e)
        {
            std::cout << oc::Color::Red << "Exception: " << e.what() << std::endl << oc::Color::Default;

            std::cout << "Try adding command line argument -debug" << std::endl;
        }
    }

    /* void doFileCPSI(osuCrypto::CLP& cmd)
    {
        osuCrypto::Timer timer;
        auto n = 1ull << cmd.getOr("nn", 10);
        std::cout << "Running Circuit-PSI with " << n << " elements" << std::endl;

        auto role = (volePSI::Role) cmd.getOr<int>("r", 2);
        u64 num_columns = cmd.getOr<int>("cols", 4); // Number of columns for payload
        auto byteLength = num_columns * sizeof(block);
        auto ip = cmd.getOr<std::string>("ip", "localhost:1212");

        // The statistical security parameter.
        auto ssp = cmd.getOr("ssp", 40);
        auto verbose = cmd.isSet("v");

        if (role != volePSI::Role::Sender && role != volePSI::Role::Receiver)
            throw std::runtime_error("-r tag must be set with value 0 (sender) or 1 (receiver).");

    #ifdef COPROTO_ENABLE_BOOST
        coproto::Socket chl;
        chl = coproto::asioConnect(ip, (role == volePSI::Role::Sender));
    #else
        throw std::runtime_error("COPROTO_ENABLE_BOOST must be define (via cmake) to use tcp sockets. " COPROTO_LOCATION);
    #endif
        u64 their_n;
        macoro::sync_wait(chl.send(n));
        macoro::sync_wait(chl.recv(their_n));
        auto t_start = timer.setTimePoint("");

        u64 their_columns;
        macoro::sync_wait(chl.send(num_columns));
        macoro::sync_wait(chl.recv(their_columns));
        if (their_columns != num_columns)
            throw std::runtime_error("Other party's payload columns size does not match.");
        else
            std::cout << "Num columns match. Proceeding." << std::endl;

        block seed;
        auto seedStr = cmd.getOr<std::string>("seed", "myseed");
        osuCrypto::RandomOracle ro(sizeof(block));
        ro.Update(seedStr.data(), seedStr.size());
        ro.Final(seed);
        PRNG prng(seed);

        if (role == Role::Sender)
        {
            u64 n_sender = n;
            u64 n_receiver = their_n;

            RsCpsiSender sender;
            RsCpsiSender::Sharing ss;
            std::vector<block> sendSet(n_sender);
            osuCrypto::Matrix<u8> senderValues(sendSet.size(), byteLength);
            std::memcpy(senderValues.data(), sendSet.data(), sendSet.size() * byteLength);

            if (verbose)
                std::cout << "sender start\n";
            std::cout << "sender size" << n_sender << std::endl;
            std::cout << "receiver size" << n_receiver << std::endl;
            sender.init(n_sender, n_receiver, byteLength, ssp, seed, 1);
            std::cout << "Init done" << std::endl;
            prng.get<block>(sendSet);

            macoro::sync_wait(sender.send(sendSet, senderValues, ss, chl));
            std::cout << "send done" << std::endl;
        }
        else
        {
            u64 n_sender = their_n;
            u64 n_receiver = n;
            RsCpsiReceiver recv;
            RsCpsiReceiver::Sharing rs;
            std::vector<block> recvSet(n_receiver);

            if (verbose)
                std::cout << "receiver start\n";
            std::cout << "sender size: " << n_sender << std::endl;
            std::cout << "receiver size: " << n_receiver << std::endl;
            recv.init(n_sender, n_receiver, byteLength, ssp, seed, 1);
            std::cout << "Init done" << std::endl;
            prng.get<block>(recvSet);

            macoro::sync_wait(recv.receive(recvSet, rs,chl));
            std::cout << "receive done" << std::endl;
        }
        macoro::sync_wait(chl.flush());

        auto t_end = timer.setTimePoint("");
        std::cout << "Bytes sent: " << chl.bytesSent() << std::endl;
        std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count()
                << "ms\nDone" << std::endl;
    } */
}