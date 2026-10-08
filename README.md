# Two-Face

## Motivation

Private signaling lets servers find a recipient's messages on a public bulletin board without learning the recipient's metadata. It is a building block for privacy-preserving blockchains and anonymous messaging. Existing constructions that do not rely on a TEE assume the servers are only passively corrupted, which limits how far they can be trusted in practice.

This repository implements the protocol from [Private Signaling Secure Against Actively Corrupted Servers](https://eprint.iacr.org/2025/1056.pdf) (Chu, Wang, Jia). It is a TEE-free, simulation-secure private signaling protocol with two non-colluding servers, either of which may be actively corrupted. Signal retrieval is turned into a problem similar to private set intersection, and custom zero-knowledge proofs keep the servers consistent with the public board. The result is low server-to-server communication and a small digest for the recipient.

## Usage

### 1. Install emp-zk

wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py<br>
python3 install.py --deps --tool --ot --zk

### 2. Build and run

mkdir build<br>
cd build<br>
cmake ..<br>
make<br>
./twoface Sa [threads] [timeout_sec]<br>
./twoface Sb [threads] [timeout_sec]<br>
./twoface C<br>

### Notes

Sa stands for Server a, Sb stands for Server b, C stands for the client.

Number of messages on the board (N), number of pertinent signals (P), and ip of the two servers, can be modified in util.h.

`threads` is the size of the worker pool (default 1). `timeout_sec` is how long a party waits for the others before it stops (default 600, 0 waits forever); the client takes it as its third argument too.

Each server prints its time per phase (Commit, Proof, Round, Cmp, Other) and in total. Computing and transfer overlap, so they are not reported separately.

---

## Concurrency gadgets

This part is engineering around the protocol, not the protocol itself.

The servers' work is dominated by elliptic-curve scalar multiplications over the whole board, followed by exchanging the resulting vectors. The code runs that work on a persistent thread pool whose workers claim contiguous chunks dynamically, streams each vector to the other server chunk by chunk while it is still being computed, and stops all three parties cleanly when any of them fails. Measured against the previous version (threads created per call, work split by striding, compute-then-send, aborts that only printed), the total time is 2–5% lower on localhost and about 12% lower on an emulated 100 Mbps WAN link. Details and limits of these measurements are under [Measurements](#measurements).

### 1. Dynamic chunking

`parallel_for` in `worker_pool.h` splits an index range into contiguous chunks of up to 256 elements. Workers claim the next chunk from a shared atomic counter until the range is used up.

- Neighbouring elements are handled by the same thread, so only chunk boundaries can share a cache line. The previous split by `i % threads` made every pair of neighbours belong to different threads.
- A worker that is descheduled or runs on a slower core claims fewer chunks and the others take the rest, where a static split would wait for the slowest thread.
- Any range length works. The previous send and receive code dropped the tail when the length was not divisible by the thread count.

### 2. Thread pool

`WorkerPool` in `worker_pool.h` creates its threads once at startup and reuses them for every parallel section. Workers sleep on a task queue protected by a mutex and a condition variable, run tasks outside the lock, and drain the queue on shutdown.

`TaskGroup` lets a caller wait for its own batch of tasks only. That is what allows a background receive and a foreground computation to share the pool at the same time.

A worker must not start a `parallel_for` or wait on a `TaskGroup` itself.

### 3. Streaming: computing and networking overlap

Previously a server computed a whole vector, then sent it, and the receiver waited for all of it before starting its next step.

- **Sending** (`send_stream` in `net.h`): workers compute and serialize a chunk and push it into a bounded queue; the calling thread sends each chunk as a frame as soon as it is ready. When the network is slower than the workers, the full queue makes them wait instead of buffering the whole vector.
- **Receiving** (`StreamReceiver` in `net.h`): one thread reads frames into a buffer while the pool processes the chunks that have already arrived.

Sa streams `A_` while Sb receives it in the background and computes `B_`. In each round Sb streams its first vector while Sa receives in the background and computes its own; Sb then decodes and multiplies Sa's reply chunk by chunk as it arrives.

The protocol is unchanged: every message has the same content and is sent in the same order as before, and Sa still replies only after it holds both of Sb's vectors.

### 4. Failure handling

- All I/O goes through `net_send` and `net_recv` in `net.h`, which report a closed connection, a timeout or another error.
- Every connection has send and receive timeouts.
- `protocol_abort` prints which party is stopping and why, and exits with status 2. Its connections close, the other parties see that, and they stop as well.
- Every check that used to print a message and continue now stops the run: the parameter hash, the four batch proofs, the repeated-point check and the client's checks.
- Each streamed chunk carries a header (stream id, start position, element count). The receiver rejects a chunk from the wrong stream, out of range, or repeating an element, and checks that every received point is on the curve.

Tested by killing Sb, pausing Sb with a 3-second timeout, and killing the client during a run; in each case the remaining parties reported the reason and exited.

Not covered: connection setup has no timeout, and there is no retry or recovery, so one failure ends the run.

### Measurements

Setup: Apple M1 Pro (8 performance + 2 efficiency cores), all three parties on that one machine, N = 65536, M = 1024, k = 4. Numbers are Sa's total time in seconds. "Before" is the version with per-call threads, striding and compute-then-send.

**Localhost** (median of 3 runs; mean of 2 runs for 1 thread)

| Threads per server | Before | Now | Change |
|---|---|---|---|
| 1 | 65.78 | 64.32 | −2.2% |
| 4 | 18.81 | 18.03 | −4.2% |
| 8 | 17.30 | 16.40 | −5.2% |

- Contiguous chunks alone made no measurable difference (within ±1%): a scalar multiplication takes about 40 microseconds, so cache effects are negligible next to it.
- The pool with dynamic chunking alone was the same at 4 threads and about 1.5% faster at 8, where the two servers' 16 threads compete for 10 cores.
- Most of the gain comes from streaming: serialization, decoding and point additions run in the workers, and transfer overlaps with computing.
- 8 threads is barely faster than 4 because both servers share one 10-core machine. This is not a scaling result; that needs one machine per server.

**Emulated LAN and WAN** (4 threads per server; the Sa–Sb connection goes through a userspace relay that limits bandwidth and adds delay)

| Link | Before | Now | Change |
|---|---|---|---|
| LAN: 1 Gbps, 1 ms RTT (mean of 2 runs) | 19.29 | 18.07 | −6.3% |
| WAN: 100 Mbps, 80 ms RTT (mean of 2 runs) | 25.36 | 22.36 | −11.8% |
| WAN: 20 Mbps, 80 ms RTT (1 run) | 47.07 | 44.52 | −5.4% |

- Bandwidth is what costs time, not delay. The servers exchange 18·(N+M) points of 64 bytes, about 77 MB here, which is about 6.1 s at 100 Mbps. The number of message rounds is small and does not grow with N.
- Streaming hides about 30% of the transfer time at 100 Mbps. Only the vectors that are computed while they are sent can overlap, and they are a bit over a quarter of the data.
- At 20 Mbps the link is the bottleneck: transfer takes longer than all the computing, so overlap hides little.

Limits: the relay runs in userspace on the same machine, shapes only the Sa–Sb connection, and does not model packet loss or TCP congestion behaviour. The paper's board size (N = 2^19) and separate machines have not been measured with this version.

Checks: the client's verification passes at 1, 3 and 4 threads and with different thread counts on the two servers. A ThreadSanitizer build (N = 4096, 4 threads) reported nothing for this repository's code; OpenSSL itself was not instrumented.
