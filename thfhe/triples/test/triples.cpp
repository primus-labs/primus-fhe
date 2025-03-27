#include "emp-ot/emp-ot.h"
#include "ole/ole_z2k.h"
#include <thread>

using namespace std;
using namespace emp;

int main(int argc, char** argv) {
    // execute: ./test_triples total_party party_id base_port
    const int num_triples = 100000;
    size_t total_party = atoi(argv[1]);
    size_t party = atoi(argv[2]);
    int base_port = atoi(argv[3]);

    NetIO** ios = new NetIO*[total_party];
    for (size_t i = 0; i < total_party; ++i) if (i != party) {
        // party with larger index is the server
        if (i > party) {
            // change to the ip address of the i-th server
            ios[i] = new NetIO("127.0.0.1", base_port + party * total_party + i);
        } else {
            ios[i] = new NetIO(nullptr, base_port + i * total_party + party);
        }
    }

    vector<uint64_t> in_a(num_triples), in_b(num_triples);
    PRG prg;
    prg.random_data(in_a.data(), num_triples * sizeof(uint64_t));
    prg.random_data(in_b.data(), num_triples * sizeof(uint64_t));

    vector<uint64_t> a_extend_b(num_triples << 1), b_extend_a(num_triples << 1);
    for (size_t i = 0; i < num_triples; ++i) {
        a_extend_b[i] = in_a[i];
        b_extend_a[i] = in_b[i];
    }
    for (size_t i = 0; i < num_triples; ++i) {
        a_extend_b[i + num_triples] = in_b[i];
        b_extend_a[i + num_triples] = in_a[i];
    }

    vector<uint64_t> out;
    out.resize(num_triples);
    for (size_t i = 0; i < num_triples; ++i) {
        out[i] = in_a[i] * in_b[i];
    }

    vector<uint64_t> *tmp_out = new vector<uint64_t>[total_party];
    
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
    
    for (size_t i = 0; i < total_party; ++i) if (i != party) {
        tmp_out[i].resize(num_triples << 1);
        threads.push_back(thread([&, i]() {
            OLEZ2K<NetIO> ole(ios[i], cots[i], 64);
            if (i > party) {
                ole.compute(tmp_out[i].data(), a_extend_b.data(), num_triples << 1);
            } else {
                ole.compute(tmp_out[i].data(), b_extend_a.data(), num_triples << 1);
            }
        }));
    }
    
    for (auto& t : threads) {
        t.join();
    }

    for (size_t i = 0; i < total_party; ++i) if (i != party) {
        for (size_t j = 0; j < num_triples; ++j) {
            out[j] += tmp_out[i][j] + tmp_out[i][j + num_triples];
        }
    }

    // adhoc: saving the triples
    ofstream ofile("data/triples_P_" + to_string(party) + ".txt");
    for (size_t i = 0; i < num_triples; ++i) {
      ofile << "a: " << in_a[i] << ", b: " << in_b[i] << ", c: " << out[i]
            << endl;
    }
    ofile.close();

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
