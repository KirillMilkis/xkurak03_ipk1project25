#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>

class ThreadPool {
public:
    ThreadPool() : stop_threads(false) {}

    ~ThreadPool() {
        stop();
    }

    void addTask(std::function<void()> task);
    void stop();
    void start(size_t num_threads); 
    void notifyOne();
    void lockMutex();
    void unlockMutex();

private:
    void threadWorker(); 

    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex mtx;
    std::condition_variable cv;
    std::atomic<bool> stop_threads;

};

#endif
