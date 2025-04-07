#ifndef PRIMUS_OLE_Z2K_H
#define PRIMUS_OLE_Z2K_H
#include "emp-ot/emp-ot.h"

/* Define the OLE protocol with integers modulo a power of 2 */
template <typename IO>
class OLEZ2K {
public:
    IO *io;
    COT<IO> *ot;
    CCRH ccrh;
    size_t bit_length;
    OLEZ2K(IO *io, COT<IO> *ot, size_t bit_length) : 
        io(io), ot(ot), bit_length(bit_length) {
    }

    /* Compute the OLE protocol */
    void compute(uint64_t *out, const uint64_t *in, size_t length, size_t cot_batch_size = 128) {
        block *raw = new block[cot_batch_size * bit_length];
        uint64_t *msg = new uint64_t[bit_length];
        size_t remain_length = length;
        PRG prg;
        if (!cmpBlock(&ot->Delta, &zero_block, 1)) {
            block *pad = new block[bit_length << 1];
            while (remain_length > 0) {
                size_t current_length = std::min(remain_length, cot_batch_size);
                remain_length -= current_length;
                ot->send_cot(raw, current_length * bit_length);
                for (size_t i = 0; i < current_length; ++i) {
                    out[remain_length + i] = 0;
                    for (size_t j = 0; j < bit_length; ++j) {
                        pad[j << 1] = raw[i * bit_length + j];
                        pad[j << 1 | 1] = raw[i * bit_length + j] ^ ot->Delta;
                    }
                    ccrh.Hn(pad, pad, bit_length << 1);
                    for (size_t j = 0; j < bit_length; ++j) {
                        msg[j] = pad[j << 1][0] + pad[j << 1 | 1][0] + in[remain_length + i];
                        out[remain_length + i] += (-pad[j << 1][0]) << j;
                    }
                    io->send_data(msg, sizeof(uint64_t) * bit_length);
                }
            }
            io->flush();
            delete[] pad;
        }
        else {
            block *pad = new block[bit_length];
            bool *bits = new bool[cot_batch_size * bit_length];
            while (remain_length > 0) {
                size_t current_length = std::min(remain_length, cot_batch_size);
                remain_length -= current_length;
                for (size_t i = 0; i < current_length; ++i) {
                    for (size_t j = 0; j < bit_length; ++j) {
                        bits[i * bit_length + j] = (in[remain_length + i] >> j) & 1;
                    }
                }
                ot->recv_cot(raw, bits, current_length * bit_length);
                for (size_t i = 0; i < current_length; ++i) {
                    out[remain_length + i] = 0;
                    for (size_t j = 0; j < bit_length; ++j) {
                        pad[j] = raw[i * bit_length + j];
                    }
                    ccrh.Hn(pad, pad, bit_length);
                    io->recv_data(msg, sizeof(uint64_t) * bit_length);
                    for (size_t j = 0; j < bit_length; ++j) {
                        if (bits[i * bit_length + j]) {
                            pad[j][0] = msg[j] - pad[j][0];
                        }
                        out[remain_length + i] += pad[j][0] << j;
                    }
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
