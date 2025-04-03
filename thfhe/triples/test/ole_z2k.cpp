#include "ole/ole_z2k.h"
#include <iostream>

using namespace std;
using namespace emp;

int main(int argc, char **argv)
{
    int port, party;
    const int num_ole = 1000;
    parse_party_and_port(argv, &party, &port);
    NetIO *ios[1];
    for (int i = 0; i < 1; ++i)
        ios[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i);

    IKNP<NetIO> *cot = new IKNP<NetIO>(ios[0]);
    vector<uint64_t> out;
    vector<uint64_t> in;
    in.resize(num_ole);
    out.resize(num_ole);
    PRG prg;
    prg.random_data(in.data(), num_ole * sizeof(uint64_t));

    auto t1 = clock_start();
    OLEZ2K<NetIO> ole(ios[0], cot, 64);
    ole.compute(out.data(), in.data(), num_ole);
    cout << "execute" << time_from(t1) << endl;

    if (party == ALICE)
    {
        for (int i = 0; i < num_ole; ++i)
        {
            ios[0]->send_data(&(in[i]), sizeof(uint64_t));
            ios[0]->send_data(&(out[i]), sizeof(uint64_t));
        }
    }
    else
    {
        for (int i = 0; i < num_ole; ++i)
        {
            uint64_t in2, out2;
            ios[0]->recv_data(&in2, sizeof(uint64_t));
            ios[0]->recv_data(&out2, sizeof(uint64_t));
            in2 = in2 * in[i];
            out2 += out[i];
            if (in2 != out2)
                error("not correct!!");
        }
    }
    delete cot;
    for (int i = 0; i < 1; ++i)
        delete ios[i];
}
