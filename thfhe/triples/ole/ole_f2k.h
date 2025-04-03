#ifndef PRIMUS_OLE_F2K_H
#define PRIMUS_OLE_F2K_H
#include "emp-ot/emp-ot.h"
#include <iostream>

/* Define OLE for the power-of-2 field with Block */
template <typename IO>
class OLEF2K
{
public:
    IO *io;
    COT<IO> *ot;
    GaloisFieldPacking pack;
    OLEF2K(IO *io, COT<IO> *ot) : io(io), ot(ot) {}

    /* Compute the inner product of two block vectors*/
    void inner_prod(block *res, const block *a, const block *b, int sz)
    {
        block r = zero_block;
        block r1;
        for (int i = 0; i < sz; i++)
        {
            gfmul_reflect(a[i], b[i], &r1);
            r = r ^ r1;
        }
        *res = r;
    }

    /* Compute the OLE protocol with inputs in, and put the output to out */
    void compute(block *out, const block *in, int length)
    {
        block *raw0 = new block[length * 128];
        if (!cmpBlock(&ot->Delta, &zero_block, 1))
        {
            block *raw1 = new block[length * 128];
            ot->send_rot(raw0, raw1, length * 128);
            for (int i = 0; i < length; ++i)
            {
                for (int j = 0; j < 128; ++j)
                {
                    block msg = raw0[i * 128 + j] ^ raw1[i * 128 + j] ^ in[i];
                    io->send_block(&msg, 1);
                }
                inner_prod(out + i, raw0 + i * 128, pack.base, 128);
            }
            delete[] raw1;
        }
        else
        {
            bool *bits = new bool[length * 128];
            for (int i = 0; i < length; ++i)
                block_to_bool(bits + i * 128, in[i]);

            ot->recv_rot(raw0, bits, length * 128);

            for (int i = 0; i < length; ++i)
            {
                block tmp[128];
                io->recv_block(tmp, 128);
                for (int j = 0; j < 128; ++j)
                {
                    if (bits[i * 128 + j])
                        raw0[i * 128 + j] ^= tmp[j];
                }
                // pack.packing(out + i, raw0 + i * 128);
                inner_prod(out + i, raw0 + i * 128, pack.base, 128);
            }
            delete[] bits;
        }
        delete[] raw0;
    }
};
#endif
