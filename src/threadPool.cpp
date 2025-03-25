#include "threadPool.h"

// ThreadPool::~ThreadPool() {
//     stop();
// }

void ThreadPool::addTask(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(mtx);
        tasks.push(std::move(task));
    }
    cv.notify_one();
}

void ThreadPool::lockMutex() {
    this->mtx.lock();
}

void ThreadPool::unlockMutex() {
    this->mtx.unlock();
}

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

void ThreadPool::threadWorker() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [this] { return !tasks.empty() || stop_threads; });

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

void ThreadPool::start(size_t num_threads) {
    stop_threads = false;
    for (size_t i = 0; i < num_threads; ++i) {
        workers.emplace_back(&ThreadPool::threadWorker, this);
    }
}

void ThreadPool::notifyOne() {
    cv.notify_one();
}
