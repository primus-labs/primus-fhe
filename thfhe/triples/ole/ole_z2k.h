#ifndef PRIMUS_OLE_Z2K_H
#define PRIMUS_OLE_Z2K_H
#include "emp-ot/emp-ot.h"

/* Define the OLE protocol with integers modulo a power of 2 */
template <typename IO>
class OLEZ2K {
   public:
    IO* io;
    COT<IO>* ot;
    CCRH ccrh;
    size_t bit_length;
    OLEZ2K(IO* io, COT<IO>* ot, size_t bit_length)
        : io(io), ot(ot), bit_length(bit_length) {
    }

    /* Compute the OLE protocol */
    void compute(uint64_t* out, const uint64_t* in, size_t length) {
        block* raw = new block[length * bit_length];
        if (!cmpBlock(&ot->Delta, &zero_block, 1)) {
            ot->send_cot(raw, length * bit_length);
            for (size_t i = 0; i < length; ++i) {
                out[i] = 0;
                block pad[2]; uint64_t msg = 0;
                for (size_t j = 0; j < bit_length; ++j) {
                    pad[0] = raw[i * bit_length + j];
                    pad[1] = raw[i * bit_length + j] ^ ot->Delta;
                    ccrh.H<2>(pad, pad);
                    msg = pad[0][0] + pad[1][0] + in[i];
                    out[i] += (-pad[0][0]) << j;
                    io->send_data(&msg, sizeof(uint64_t));
                }
                io->flush();
            }
        } else {
            bool* bits = new bool[length * bit_length];
            for (size_t i = 0; i < length; ++i)
                for (size_t j = 0; j < bit_length; ++j)
                    bits[i * bit_length + j] = (in[i] >> j) & 1;

            ot->recv_cot(raw, bits, length * bit_length);

            for (size_t i = 0; i < length; ++i) {
                out[i] = 0; uint64_t msg = 0;
                for (size_t j = 0; j < bit_length; ++j) {
                    io->recv_data(&msg, sizeof(uint64_t));
                    uint64_t pad = ccrh.H(raw[i * bit_length + j])[0];
                    if (bits[i * bit_length + j]) {
                        pad = msg - pad;
                    }
                    out[i] += pad << j;
                }
            }
            delete[] bits;
        }
        delete[] raw;
    }
};
#endif
