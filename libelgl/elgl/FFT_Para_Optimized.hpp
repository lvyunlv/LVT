// FFT_Para_Optimized.hpp
#pragma once
#include <vector>
#include <thread>
#include <future>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <cassert>
#include "BLS12381Element.h"
#include <mcl/bn.hpp>

using namespace std;
using namespace mcl::bn;

// -------------------- 内部线程池 --------------------
class SimpleThreadPool {
public:
    explicit SimpleThreadPool(size_t numThreads) {
        for (size_t i = 0; i < numThreads; ++i) {
            workers.emplace_back([this]() {
                for (;;) {
                    function<void()> task;
                    {
                        unique_lock<mutex> lock(queueMutex);
                        condition.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        task = move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }

    ~SimpleThreadPool() {
        {
            lock_guard<mutex> lock(queueMutex);
            stop = true;
        }
        condition.notify_all();
        for (thread &t : workers) t.join();
    }

    template <class F, class... Args>
    auto enqueue(F&& f, Args&&... args)
        -> future<typename result_of<F(Args...)>::type> {
        using return_type = typename result_of<F(Args...)>::type;
        auto task = make_shared<packaged_task<return_type()>>(
            bind(forward<F>(f), forward<Args>(args)...)
        );
        future<return_type> res = task->get_future();
        {
            lock_guard<mutex> lock(queueMutex);
            tasks.emplace([task]() { (*task)(); });
        }
        condition.notify_one();
        return res;
    }

private:
    vector<thread> workers;
    queue<function<void()>> tasks;
    mutex queueMutex;
    condition_variable condition;
    bool stop = false;
};

// -------------------- 原地并行 FFT --------------------
void fft_inplace_recursive(
    vector<BLS12381Element>& data,
    size_t start,
    size_t stride,
    size_t n,
    const Fr& omega,
    SimpleThreadPool& pool,
    int depth
) {
    if (n == 1) return;

    size_t half = n / 2;
    Fr omega_squared = omega * omega;

    future<void> left_future;
    if (depth > 0) {
        left_future = pool.enqueue([&data, start, stride, half, omega_squared, &pool, depth]() {
            fft_inplace_recursive(data, start, stride * 2, half, omega_squared, pool, depth - 1);
        });
        fft_inplace_recursive(data, start + stride, stride * 2, half, omega_squared, pool, depth - 1);
        left_future.get();
    } else {
        fft_inplace_recursive(data, start, stride * 2, half, omega_squared, pool, 0);
        fft_inplace_recursive(data, start + stride, stride * 2, half, omega_squared, pool, 0);
    }

    Fr w = 1;
    for (size_t j = 0; j < half; ++j) {
        size_t even_idx = start + j * stride * 2;
        size_t odd_idx  = even_idx + stride;
        BLS12381Element even = data[even_idx];
        BLS12381Element odd  = data[odd_idx] * w;
        data[even_idx] = even + odd;
        data[odd_idx]  = even - odd;
        w *= omega;
    }
}

// -------------------- FFT_Para 接口（原地 + 多线程）--------------------
void FFT_Para(
    const vector<BLS12381Element>& input,
    vector<BLS12381Element>& output,
    const Fr& omega,
    size_t N
) {
    assert((N & (N - 1)) == 0); // N must be power of 2
    assert(N == input.size());

    output = input; // make a copy to allow in-place modification

    static SimpleThreadPool pool(thread::hardware_concurrency());
    fft_inplace_recursive(output, 0, 1, N, omega, pool, 3);
}
