#ifndef NET_H
#define NET_H

#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include "emp-tool/io/net_io_channel.h"
#include "worker_pool.h"

using emp::NetIO;

#define POINT_BYTES 64
#define FRAME_MAGIC 0x54464652u

std::string party_name;
int net_timeout_sec = 600;
WorkerPool *g_pool = nullptr;

// Fail-stop: report why, then exit. Closing our sockets is what tells the other parties; they see
// end-of-stream in net_recv and stop as well.
[[noreturn]] void protocol_abort(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[%s] abort: ", party_name.c_str());
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    fflush(stdout);
    fflush(stderr);
    // _exit: exit() would flush the socket streams, which can block on a reader thread's lock.
    _exit(2);
}

// 0 disables the timeout.
void set_timeout(NetIO *io) {
    struct timeval tv;
    tv.tv_sec = net_timeout_sec;
    tv.tv_usec = 0;
    setsockopt(io->consocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(io->consocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

void net_send(NetIO *io, const void *data, size_t len) {
    io->counter += len;
    size_t sent = 0;
    while (sent < len) {
        errno = 0;
        size_t res = fwrite((const char *)data + sent, 1, len - sent, io->stream);
        sent += res;
        if (sent == len) break;
        if (errno == EINTR) {
            clearerr(io->stream);
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) protocol_abort("peer did not accept data for %d s", net_timeout_sec);
        protocol_abort("send failed, peer is gone (%s)", strerror(errno));
    }
    io->has_sent = true;
}

void net_flush(NetIO *io) {
    errno = 0;
    if (fflush(io->stream) != 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) protocol_abort("peer did not accept data for %d s", net_timeout_sec);
        protocol_abort("send failed, peer is gone (%s)", strerror(errno));
    }
}

void net_recv(NetIO *io, void *data, size_t len) {
    if (io->has_sent) net_flush(io);
    io->has_sent = false;
    size_t got = 0;
    while (got < len) {
        errno = 0;
        size_t res = fread((char *)data + got, 1, len - got, io->stream);
        got += res;
        if (got == len) break;
        if (feof(io->stream)) protocol_abort("peer closed the connection");
        if (errno == EINTR) {
            clearerr(io->stream);
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) protocol_abort("no data from peer for %d s", net_timeout_sec);
        protocol_abort("receive failed (%s)", strerror(errno));
    }
}

struct FrameHeader {
    uint32_t magic, tag, offset, count;
};

struct Chunk {
    uint32_t offset, count;
    std::vector<unsigned char> bytes;
};

// Sends len 64-byte elements as framed chunks. fill(begin, end, out) runs on pool workers and
// writes elements [begin, end) to out; this thread sends each chunk as soon as it is ready, so
// producing and sending overlap. The queue is bounded: if the network is slower than the
// workers, they wait instead of buffering the whole vector.
template <class Fill>
void send_stream(NetIO *io, uint32_t tag, size_t len, Fill fill) {
    size_t chunk = pick_chunk(len, g_pool->size());
    size_t nchunks = (len + chunk - 1) / chunk;
    BoundedQueue<Chunk> ready(2 * g_pool->size());
    std::atomic<size_t> next(0);
    TaskGroup group(*g_pool);
    for (size_t t = 0; t < g_pool->size(); ++t) {
        group.run([&] {
            for (;;) {
                size_t begin = next.fetch_add(chunk);
                if (begin >= len) return;
                size_t end = std::min(begin + chunk, len);
                Chunk c;
                c.offset = begin;
                c.count = end - begin;
                c.bytes.resize(c.count * POINT_BYTES);
                fill(begin, end, c.bytes.data());
                ready.push(std::move(c));
            }
        });
    }
    for (size_t i = 0; i < nchunks; ++i) {
        Chunk c = ready.pop();
        FrameHeader h = {FRAME_MAGIC, tag, c.offset, c.count};
        net_send(io, &h, sizeof(h));
        net_send(io, c.bytes.data(), c.bytes.size());
        net_flush(io);
    }
    group.wait();
}

// Receives one framed stream of len elements into dest. read_all() runs on one thread and only
// reads; for_each_chunk() may run at the same time on another thread and processes chunks on the
// pool as they arrive. Nothing else may use the same NetIO while read_all() is running.
class StreamReceiver {
public:
    StreamReceiver(NetIO *io, uint32_t tag, size_t len, unsigned char *dest)
        : io(io), tag(tag), len(len), dest(dest), seen(len, false) {}

    void read_all() {
        size_t got = 0;
        while (got < len) {
            FrameHeader h;
            net_recv(io, &h, sizeof(h));
            if (h.magic != FRAME_MAGIC) protocol_abort("malformed frame from peer");
            if (h.tag != tag) protocol_abort("unexpected message from peer (stream %u, expected %u)", h.tag, tag);
            if (h.count == 0 || h.offset >= len || h.count > len - h.offset) protocol_abort("frame out of range in stream %u", tag);
            for (size_t i = h.offset; i < (size_t)h.offset + h.count; ++i) {
                if (seen[i]) protocol_abort("repeated element in stream %u", tag);
                seen[i] = true;
            }
            net_recv(io, dest + (size_t)h.offset * POINT_BYTES, (size_t)h.count * POINT_BYTES);
            got += h.count;
            {
                std::lock_guard<std::mutex> lk(mu);
                arrived.push(std::make_pair((size_t)h.offset, (size_t)h.offset + h.count));
            }
            cv.notify_one();
        }
    }

    // sink(begin, end) is called on pool workers once elements [begin, end) are in dest.
    template <class Sink>
    void for_each_chunk(Sink sink) {
        TaskGroup group(*g_pool);
        for (size_t t = 0; t < g_pool->size(); ++t) {
            group.run([this, &sink] {
                for (;;) {
                    std::pair<size_t, size_t> range;
                    {
                        std::unique_lock<std::mutex> lk(mu);
                        cv.wait(lk, [this] { return !arrived.empty() || taken == len; });
                        if (arrived.empty()) return;
                        range = arrived.front();
                        arrived.pop();
                        taken += range.second - range.first;
                        if (taken == len) cv.notify_all();
                    }
                    sink(range.first, range.second);
                }
            });
        }
        group.wait();
    }

private:
    NetIO *io;
    uint32_t tag;
    size_t len;
    unsigned char *dest;
    std::vector<bool> seen;
    std::mutex mu;
    std::condition_variable cv;
    std::queue<std::pair<size_t, size_t>> arrived;
    size_t taken = 0;
};

#endif
