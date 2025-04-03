#include "ole/ole_f2k.h"
#include "ole/utils.h"
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
    vector<block> out;
    vector<block> in;
    in.resize(num_ole);
    out.resize(num_ole);
    PRG prg;
    prg.random_block(in.data());

    auto t1 = clock_start();
    OLEF2K<NetIO> ole(ios[0], cot);
    ole.compute(out.data(), in.data(), num_ole);
    cout << "execute" << time_from(t1) << endl;

    if (party == ALICE)
    {
        for (int i = 0; i < num_ole; ++i)
        {
            ios[0]->send_block(&(in[i]), 1);
            ios[0]->send_block(&(out[i]), 1);
        }
    }
    else
    {
        for (int i = 0; i < num_ole; ++i)
        {
            block in2, out2;
            ios[0]->recv_block(&in2, 1);
            ios[0]->recv_block(&out2, 1);
            in2 = mulBlock(in2, in[i]);
            out2 ^= out[i];
            if (!cmpBlock(&in2, &out2, 1))
                error("not correct!!");
        }
    }
    for (int i = 0; i < 1; ++i)
        delete ios[i];
}
