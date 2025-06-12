#pragma once

#include "emp-tool/emp-tool.h"

namespace emp {

class CountNetIO: public IOChannel<CountNetIO> {
private:
    size_t total_bytes_sent;
    size_t total_bytes_recv;
    NetIO netio;

public:
    CountNetIO(const char * address, int port, bool quiet = true) : 
        total_bytes_sent(0), total_bytes_recv(0), netio(address, port, quiet) {}

    void send_data_internal(const void * data, size_t len) {
        total_bytes_sent += len;
        netio.send_data_internal(data, len);
    }

    void recv_data_internal(void * data, size_t len) {
        total_bytes_recv += len;
        netio.recv_data_internal(data, len);
    }

    void flush() {
        netio.flush();
    }

    size_t get_total_bytes_sent() const {
        return total_bytes_sent;
    }

    size_t get_total_bytes_recv() const {
        return total_bytes_recv;
    }

};

} // namespace emp