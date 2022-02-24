//
// Created by crl on 2/24/22.
//

#ifndef SECURECHAT_MANAGERS_H
#define SECURECHAT_MANAGERS_H
#include <cstddef>
namespace Managers {
    namespace SocketManager {
        int write_n(int socket, size_t amount, void* buff);
        int read_n(int socket, size_t amount, void* buff);

    }
}


#endif //SECURECHAT_MANAGERS_H
