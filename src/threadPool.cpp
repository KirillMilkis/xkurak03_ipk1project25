/*
 * File: threadPool.cpp
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: XX.03.2025
 * Note:
 */
#include "threadPool.h"

/**
 * @bried Add new task to the thread pool
 * 
 * @param task Task to add
 * 
 * @return void
 */
void ThreadPool::addTask(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(mtx);
        tasks.push(std::move(task));
    }
    cv.notify_one();
}

/**
 * @brief Lock the mutex
 * 
 * @return void
 */
void ThreadPool::lockMutex() {
    this->mtx.lock();
}

/**
 * @brief Unlock the mutex
 * 
 * @return void
 */
void ThreadPool::unlockMutex() {
    this->mtx.unlock();
}

/**
 * @brief Stop all threads
 * 
 * @return void
 */
void ThreadPool::stop() {
    {
        std::lock_guard<std::mutex> lock(mtx);
        stop_threads = true;
    }
    cv.notify_all();

    for (std::thread &worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

/**
 * @brief Worker function that will be executed by the thread
 * 
 * @return void
 */
void ThreadPool::threadWorker() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(mtx);
            // Wait for new task or stop signal
            cv.wait(lock, [this] { return !tasks.empty() || stop_threads; });

            // If there are no tasks and stop signal is received, exit the thread
            if (stop_threads && tasks.empty()) {
                return;
            }

            task = std::move(tasks.front());
            tasks.pop();
        }

        if (task) {
            task();
        }
    }
}

/**
 * @brief Start the thread pool, specific number of threrads
 * 
 * @param num_threads Number of threads
 */
void ThreadPool::start(size_t num_threads) {
    stop_threads = false;
    for (size_t i = 0; i < num_threads; ++i) {
        workers.emplace_back(&ThreadPool::threadWorker, this);
    }
}

/**
 * @brief Notify one thread that there is a new task
 * 
 * @return void
 */
void ThreadPool::notifyOne() {
    cv.notify_one();
}
