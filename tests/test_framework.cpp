#include "include/core/packet_buffer.hpp"
#include "include/core/spsc_ring_queue.hpp"
#include "include/core/memory_pool.hpp"

#include <iostream>
#include <cassert>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>

using namespace telecom::core;

void test_spsc_basic() {
    std::cout << "[TEST] 1. Checking SpscRingQueue basic push/pop/batch..." << std::endl;
    SpscRingQueue<int, 1024> queue;

    assert(queue.empty());
    assert(queue.capacity() == 1024);
    assert(queue.size() == 0);

    // Push 100 elements
    for (int i = 0; i < 100; ++i) {
        bool ok = queue.push(i);
        assert(ok);
    }
    assert(queue.size() == 100);
    assert(!queue.empty());

    // Pop 50 elements
    for (int i = 0; i < 50; ++i) {
        int val = -1;
        bool ok = queue.pop(val);
        assert(ok);
        assert(val == i);
    }
    assert(queue.size() == 50);

    // Batch push 32 elements
    int batch_in[32];
    for (int i = 0; i < 32; ++i) batch_in[i] = 1000 + i;
    size_t pushed = queue.push_batch(batch_in, 32);
    assert(pushed == 32);
    assert(queue.size() == 82);

    // Batch pop 32 elements
    int batch_out[32];
    size_t popped = queue.pop_batch(batch_out, 32);
    assert(popped == 32);
    for (int i = 0; i < 32; ++i) {
        assert(batch_out[i] == 50 + i);
    }

    std::cout << "  -> PASSED!" << std::endl;
}

void test_spsc_multithread_throughput() {
    std::cout << "[TEST] 2. Checking SpscRingQueue multi-threaded throughput (Producer -> Consumer)..." << std::endl;
    constexpr size_t TOTAL_ITEMS = 10'000'000;
    static SpscRingQueue<uint32_t, 8192> queue;

    auto start_time = std::chrono::high_resolution_clock::now();

    std::thread producer([]() {
        for (uint32_t i = 0; i < TOTAL_ITEMS; ++i) {
            while (!queue.push(i)) {
                // Spin/pause
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
            }
        }
    });

    std::thread consumer([&]() {
        for (uint32_t i = 0; i < TOTAL_ITEMS; ++i) {
            uint32_t val = 0;
            while (!queue.pop(val)) {
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
            }
            if (val != i) {
                std::cerr << "Mismatch at " << i << " got " << val << std::endl;
                assert(false);
            }
        }
    });

    producer.join();
    consumer.join();

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end_time - start_time;
    double mpps = (static_cast<double>(TOTAL_ITEMS) / diff.count()) / 1'000'000.0;

    std::cout << "  - Transferred: " << TOTAL_ITEMS << " items in " << diff.count() << " s" << std::endl;
    std::cout << "  - SPSC Throughput: " << mpps << " Mpps" << std::endl;
    std::cout << "  -> PASSED!" << std::endl;
}

void test_memory_pool_basic() {
    std::cout << "[TEST] 3. Checking MemoryPool pre-allocated slab & auto-release..." << std::endl;
    MemoryPool<1024> pool;

    assert(pool.capacity() == 1024);
    assert(pool.available() == 1024);
    assert(pool.in_use() == 0);

    // Allocate single buffer
    PacketBuffer* pkt1 = pool.allocate();
    assert(pkt1 != nullptr);
    assert(pool.available() == 1023);
    assert(pool.in_use() == 1);
    assert(pool.is_from_this_pool(pkt1));

    // Release via PacketBuffer::release()
    pkt1->release();
    assert(pool.available() == 1024);
    assert(pool.in_use() == 0);

    // Batch allocation of 64 packets
    PacketBuffer* batch[64];
    size_t alloc_count = pool.allocate_batch(batch, 64);
    assert(alloc_count == 64);
    assert(pool.available() == 1024 - 64);
    assert(pool.in_use() == 64);

    // Free batch
    pool.free_batch(batch, 64);
    assert(pool.available() == 1024);
    assert(pool.in_use() == 0);

    std::cout << "  -> PASSED!" << std::endl;
}

void test_memory_pool_multithread_stress() {
    std::cout << "[TEST] 4. Checking MemoryPool multi-threaded concurrent alloc/free stress..." << std::endl;
    constexpr size_t POOL_CAP = 8192;
    static MemoryPool<POOL_CAP> pool;

    constexpr size_t NUM_THREADS = 4;
    constexpr size_t OPS_PER_THREAD = 1'000'000;

    std::vector<std::thread> workers;
    workers.reserve(NUM_THREADS);

    auto start_time = std::chrono::high_resolution_clock::now();

    for (size_t t = 0; t < NUM_THREADS; ++t) {
        workers.emplace_back([&]() {
            for (size_t i = 0; i < OPS_PER_THREAD; ++i) {
                PacketBuffer* pkt = nullptr;
                while ((pkt = pool.allocate()) == nullptr) {
#if defined(__x86_64__) || defined(_M_X64)
                    __builtin_ia32_pause();
#endif
                }

                // Simulate slight work
                pkt->teid_or_rnti = static_cast<uint32_t>(i);
                pkt->release(); // Automatic lock-free return to pool
            }
        });
    }

    for (auto& w : workers) {
        w.join();
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end_time - start_time;
    const size_t total_ops = NUM_THREADS * OPS_PER_THREAD;
    double mops = (static_cast<double>(total_ops) / diff.count()) / 1'000'000.0;

    assert(pool.available() == POOL_CAP);
    assert(pool.in_use() == 0);

    std::cout << "  - Completed: " << total_ops << " concurrent alloc/free cycles in " << diff.count() << " s" << std::endl;
    std::cout << "  - Lock-Free Pool Throughput: " << mops << " Million ops/sec" << std::endl;
    std::cout << "  -> PASSED!" << std::endl;
}

void test_integrated_pipeline() {
    std::cout << "[TEST] 5. Checking Integrated Zero-Copy Pipeline (Generator -> SPSC -> Processor)..." << std::endl;
    constexpr size_t TOTAL_PACKETS = 5'000'000;
    static MemoryPool<8192> pool;
    static SpscRingQueue<PacketBuffer*, 4096> pipeline_queue;

    std::atomic<bool> producer_done{false};

    auto start_time = std::chrono::high_resolution_clock::now();

    // Stage 1: Traffic Generator Thread
    std::thread gen_thread([&]() {
        for (size_t i = 0; i < TOTAL_PACKETS; ++i) {
            PacketBuffer* pkt = nullptr;
            while ((pkt = pool.allocate()) == nullptr) {
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
            }

            // Simulate payload injection
            pkt->seq_num = static_cast<uint32_t>(i);
            pkt->teid_or_rnti = 0x5E01;

            while (!pipeline_queue.push(pkt)) {
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
            }
        }
        producer_done.store(true, std::memory_order_release);
    });

    // Stage 2: Protocol Engine Thread
    std::thread proc_thread([&]() {
        size_t processed = 0;
        while (processed < TOTAL_PACKETS) {
            PacketBuffer* pkt = nullptr;
            if (pipeline_queue.pop(pkt)) {
                // Perform Downlink GTP-U encapsulation
                gtpu_encapsulate(*pkt, pkt->teid_or_rnti);

                // Perform Uplink Decapsulation
                uint32_t teid = 0;
                uint8_t qfi = 0;
                bool ok = gtpu_decapsulate(*pkt, teid, qfi);
                assert(ok);
                assert(teid == 0x5E01);

                // Packet completed: Release directly back to pool
                pkt->release();
                ++processed;
            } else {
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
            }
        }
    });

    gen_thread.join();
    proc_thread.join();

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end_time - start_time;
    double mpps = (static_cast<double>(TOTAL_PACKETS) / diff.count()) / 1'000'000.0;

    assert(pool.available() == 8192);
    assert(pool.in_use() == 0);

    std::cout << "  - Pipeline Processed: " << TOTAL_PACKETS << " full-cycle packets in " << diff.count() << " s" << std::endl;
    std::cout << "  - End-to-End Pipeline Throughput: " << mpps << " Mpps" << std::endl;
    std::cout << "  -> PASSED!" << std::endl;
}

int main() {
    std::cout << "==========================================================" << std::endl;
    std::cout << "   MEMORY POOL & SPSC RING QUEUE VERIFICATION SUITE       " << std::endl;
    std::cout << "==========================================================" << std::endl;

    test_spsc_basic();
    test_spsc_multithread_throughput();
    test_memory_pool_basic();
    test_memory_pool_multithread_stress();
    test_integrated_pipeline();

    std::cout << "==========================================================" << std::endl;
    std::cout << "   ALL FRAMEWORK TESTS PASSED SUCCESSFULLY!               " << std::endl;
    std::cout << "==========================================================" << std::endl;
    return 0;
}
