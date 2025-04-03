#include "emp-ot/emp-ot.h"
#include "ole/ole_z2k.h"
#include <thread>

using namespace std;
using namespace emp;

// modify the batch size according to the memory of the machine
const size_t MAX_BATCH_SIZE = 1e5;

std::vector<std::string> read_ip_list(const std::string& filename, size_t total_party) {
    std::ifstream infile(filename);
    std::vector<std::string> ip_list;
    std::string ip;
    size_t count = 0;
    while (count < total_party && std::getline(infile, ip)) {
        ip_list.push_back(ip);
        ++count;
    }
    return ip_list;
}



int main(int argc, char** argv) {
    // execute: ./test_triples total_party party_id base_port
    const int num_triples = int(1e6);
    size_t total_party = atoi(argv[1]);
    size_t party = atoi(argv[2]);
    int base_port = atoi(argv[3]);

    NetIO** ios = new NetIO*[total_party];
    std::vector<std::string> ip_list = read_ip_list("../batch/iplist/ip.txt", total_party);

    for (size_t i = 0; i < total_party; ++i) {
        if (i == party) continue;
        if (i > party) {
            ios[i] = new NetIO(ip_list[i].c_str(), base_port + party * total_party + i);
        } else {
 
            ios[i] = new NetIO(nullptr, base_port + i * total_party + party);
        }
    }

    auto start = chrono::high_resolution_clock::now();
    vector<uint64_t> in_a(num_triples), in_b(num_triples);
    PRG prg;
    prg.random_data(in_a.data(), num_triples * sizeof(uint64_t));
    prg.random_data(in_b.data(), num_triples * sizeof(uint64_t));

    vector<uint64_t> a_extend_b(num_triples << 1), b_extend_a(num_triples << 1);
    for (size_t i = 0; i < num_triples; ++i) {
        a_extend_b[i<<1] = in_a[i];
        b_extend_a[i<<1] = in_b[i];
    }
    for (size_t i = 0; i < num_triples; ++i) {
        a_extend_b[i<<1|1] = in_b[i];
        b_extend_a[i<<1|1] = in_a[i];
    }

    vector<uint64_t> out;
    out.resize(num_triples);
    for (size_t i = 0; i < num_triples; ++i) {
        out[i] = in_a[i] * in_b[i];
    }

    FerretCOT<NetIO> **cots = new FerretCOT<NetIO>*[total_party];
    vector<thread> threads;
    for (size_t i = 0; i < total_party; ++i) if (i != party) {
        threads.push_back(thread([&, i]() {
            cots[i] = new FerretCOT<NetIO>(i > party ? BOB : ALICE, 1, &ios[i], false, 
            true, ferret_b13, "data/pre_file_" + to_string(party) + "_" + to_string(i) + ".txt");
        }));
    }
    
    for (auto& t : threads) {
        t.join();
    }
    threads.clear();

    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    cout << "Initialization time: " << duration.count() << " microseconds" << endl;

    start = chrono::high_resolution_clock::now();
    vector<uint64_t> *tmp_out = new vector<uint64_t>[total_party];
    for (size_t i = 0; i < total_party; ++i) {
        tmp_out[i].resize(MAX_BATCH_SIZE << 1);
    }
    size_t num_remaining = num_triples;
    while (num_remaining > 0) {
        size_t num_to_compute = min(num_remaining, MAX_BATCH_SIZE);
        num_remaining -= num_to_compute;
        for (size_t i = 0; i < total_party; ++i) if (i != party) {
            threads.push_back(thread([&, i]() {
                OLEZ2K<NetIO> ole(ios[i], cots[i], 64);
                if (i > party) {
                    ole.compute(tmp_out[i].data(), a_extend_b.data() + (num_remaining << 1), num_to_compute << 1);
                } else {
                    ole.compute(tmp_out[i].data(), b_extend_a.data() + (num_remaining << 1), num_to_compute << 1);
                }
            }));
        }
        
        for (auto& t : threads) {
            t.join();
        }
        threads.clear();


        for (size_t i = 0; i < total_party; ++i) if (i != party) {
            for (size_t j = 0; j < num_to_compute; ++j) {
                out[j+num_remaining] += tmp_out[i][j<<1] + tmp_out[i][j<<1|1];
            }
        }
    }

    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    cout << "Computation time: " << duration.count() << " microseconds for " << num_triples << " triples" << endl;

    // adhoc: saving the triples
    start = chrono::high_resolution_clock::now();
    ofstream ofile("data/triples_P_" + to_string(party) + ".txt");
    for (size_t i = 0; i < num_triples; ++i) {
      ofile << "a: " << in_a[i] << ", b: " << in_b[i] << ", c: " << out[i]
            << endl;
    }
    ofile.close();
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    cout << "File writing time: " << duration.count() << " microseconds" << endl;

    // test the correctness (should be removed)
    if (party == 0) {
        vector<uint64_t> buf(num_triples);
        for (size_t i = 1; i < total_party; ++i) {
            ios[i]->recv_data(buf.data(), num_triples * sizeof(uint64_t));
            for (size_t j = 0; j < num_triples; ++j) {
                in_a[j] += buf[j];
            }
            ios[i]->recv_data(buf.data(), num_triples * sizeof(uint64_t));
            for (size_t j = 0; j < num_triples; ++j) {
                in_b[j] += buf[j];
            }
            ios[i]->recv_data(buf.data(), num_triples * sizeof(uint64_t));
            for (size_t j = 0; j < num_triples; ++j) {
                out[j] += buf[j];
            }
        }
        for (size_t i = 0; i < num_triples; ++i) {
            if (in_a[i] * in_b[i] != out[i]) {
                error("not correct!!");
            }
        }
    } else {
        ios[0]->send_data(in_a.data(), num_triples * sizeof(uint64_t));
        ios[0]->send_data(in_b.data(), num_triples * sizeof(uint64_t));
        ios[0]->send_data(out.data(), num_triples * sizeof(uint64_t));
    }

    // clean up
    for (size_t i = 0; i < total_party; ++i) if (i != party) {
        delete ios[i];
        delete cots[i];
    }

    delete[] tmp_out;
    delete[] ios;
    delete[] cots;
}
