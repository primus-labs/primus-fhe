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
        uint64_t *msg = new uint64_t[bit_length];
        if (!cmpBlock(&ot->Delta, &zero_block, 1)) {
            block* pad = new block[bit_length << 1];
            ot->send_cot(raw, length * bit_length);
            for (size_t i = 0; i < length; ++i) {
                out[i] = 0;
                for (size_t j = 0; j < bit_length; ++j) {
                    pad[j << 1] = raw[i * bit_length + j];
                    pad[j << 1 | 1] = raw[i * bit_length + j] ^ ot->Delta;
                }
                ccrh.Hn(pad, pad, bit_length << 1);
                for (size_t j = 0; j < bit_length; ++j) {
                    msg[j] = pad[j << 1][0] + pad[j << 1 | 1][0] + in[i];
                    out[i] += (-pad[j << 1][0]) << j;
                }
                io->send_data(msg, sizeof(uint64_t) * bit_length);
                io->flush();
            }
            delete[] pad;
        } else {
            block* pad = new block[bit_length];
            bool* bits = new bool[length * bit_length];
            for (size_t i = 0; i < length; ++i)
                for (size_t j = 0; j < bit_length; ++j)
                    bits[i * bit_length + j] = (in[i] >> j) & 1;

            ot->recv_cot(raw, bits, length * bit_length);

            for (size_t i = 0; i < length; ++i) {
                out[i] = 0;
                for (size_t j = 0; j < bit_length; ++j) {
                    pad[j] = raw[i * bit_length + j];
                }
                ccrh.Hn(pad, pad, bit_length);
                io->recv_data(msg, sizeof(uint64_t) * bit_length);
                for (size_t j = 0; j < bit_length; ++j) {
                    if (bits[i * bit_length + j]) {
                        pad[j][0] = msg[j] - pad[j][0];
                    }
                    out[i] += pad[j][0] << j;
                }
            }
            delete[] pad;
            delete[] bits;
        }
        delete[] msg;
        delete[] raw;
    }
};
#endif
