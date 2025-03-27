/*
 * File: threadPool.h
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: XX.03.2025
 * Note:
 */
#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>

/**
 * @brief Class that is responsible for thread pool
 */
class ThreadPool {
public:
    /**
     * @brief Construct a new Thread Pool object
     * 
     * @return
     */
    ThreadPool() : stop_threads(false) {}

    ~ThreadPool() {
        stop();
    }

    /**
     * @brief Add new task to the thread pool
     * 
     * @param task Task to add
     * 
     * @return void
     */
    void addTask(std::function<void()> task);

    /**
     * @brief Stop all threads
     * 
     * @return void
     */
    void stop();

    /**
     * @brief Start the thread pool, specific number of threrads
     * 
     * @param num_threads Number of threads
     */
    void start(size_t num_threads); 

    /**
     * @brief Notify one thread that there is a new task
     * 
     * @return void
     */
    void notifyOne();

    /**
     * @brief Lock the mutex
     * 
     * @return void
     */
    void lockMutex();

    /**
     * @brief Unlock the mutex
     * 
     * @return void
     */
    void unlockMutex();

private:

    /**
     * @brief Worker function that will be executed by the thread
     * 
     * @return void
     */
    void threadWorker(); 

    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks; 
    std::mutex mtx;
    // Condition variable to notify the threads that there is a new task
    std::condition_variable cv;
    std::atomic<bool> stop_threads;

};

#endif
