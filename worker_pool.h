#ifndef WORKER_POOL_H
#define WORKER_POOL_H

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

// Worker threads created once and reused for every parallel section.
class WorkerPool {
public:
    explicit WorkerPool(size_t n) {
        for (size_t t = 0; t < n; ++t)
            workers.emplace_back([this] { worker_loop(); });
    }
    ~WorkerPool() {
        {
            std::lock_guard<std::mutex> lk(mu);
            stop = true;
        }
        cv.notify_all();
        for (auto& w : workers) w.join();
    }
    void submit(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lk(mu);
            tasks.push(std::move(task));
        }
        cv.notify_one();
    }
    size_t size() const { return workers.size(); }

private:
    void worker_loop() {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lk(mu);
                cv.wait(lk, [this] { return stop || !tasks.empty(); });
                if (stop && tasks.empty()) return;
                task = std::move(tasks.front());
                tasks.pop();
            }
            task();
        }
    }
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex mu;
    std::condition_variable cv;
    bool stop = false;
};

// A batch of pool tasks the caller can wait for, independent of other batches on the same pool.
// Must not be waited on from inside a pool worker.
class TaskGroup {
public:
    explicit TaskGroup(WorkerPool& p) : pool(p) {}
    ~TaskGroup() { wait(); }
    void run(std::function<void()> fn) {
        {
            std::lock_guard<std::mutex> lk(mu);
            ++pending;
        }
        pool.submit([this, fn] {
            fn();
            std::lock_guard<std::mutex> lk(mu);
            if (--pending == 0) cv.notify_all();
        });
    }
    void wait() {
        std::unique_lock<std::mutex> lk(mu);
        cv.wait(lk, [this] { return pending == 0; });
    }

private:
    WorkerPool& pool;
    std::mutex mu;
    std::condition_variable cv;
    size_t pending = 0;
};

// Blocking queue with a capacity: push waits while it is full, pop waits while it is empty.
template <class T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity) : cap(capacity) {}
    void push(T v) {
        std::unique_lock<std::mutex> lk(mu);
        not_full.wait(lk, [this] { return q.size() < cap; });
        q.push(std::move(v));
        not_empty.notify_one();
    }
    T pop() {
        std::unique_lock<std::mutex> lk(mu);
        not_empty.wait(lk, [this] { return !q.empty(); });
        T v = std::move(q.front());
        q.pop();
        not_full.notify_one();
        return v;
    }

private:
    size_t cap;
    std::queue<T> q;
    std::mutex mu;
    std::condition_variable not_full, not_empty;
};

// Large enough that claiming a chunk is negligible next to the work in it, small enough that
// every thread claims many chunks.
inline size_t pick_chunk(size_t n, size_t threads) {
    return std::max<size_t>(1, std::min<size_t>(n / (threads * 8), 256));
}

// Runs body(begin, end) over [0, n). Each worker repeatedly claims the next contiguous chunk, so a
// slow or descheduled worker simply claims fewer chunks.
template <class F>
void parallel_for(WorkerPool& pool, size_t n, F body) {
    size_t chunk = pick_chunk(n, pool.size());
    std::atomic<size_t> next(0);
    TaskGroup group(pool);
    for (size_t t = 0; t < pool.size(); ++t) {
        group.run([&next, &body, n, chunk] {
            for (;;) {
                size_t begin = next.fetch_add(chunk);
                if (begin >= n) return;
                body(begin, std::min(begin + chunk, n));
            }
        });
    }
    group.wait();
}

#endif
