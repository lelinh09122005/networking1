/**
 * @file main.cpp
 * @brief High-Speed 5G NR / User Plane Packet Processor & Simulator (Production Pipeline).
 *
 * Implements a Multi-Core Pipelined Telecom Data Path with Thread Pinning:
 *
 *   [Core 0] Traffic Generator
 *       |  (Lock-Free SPSC Queue 0)
 *       v
 *   [Core 1] GTP-U Protocol Engine (Downlink Zero-Copy Encap & 5G QFI)
 *       |  (Lock-Free SPSC Queue 1)
 *       v
 *   [Core 2] Wireless Channel Simulator (Bernoulli/Markov Loss & Reorder Delay)
 *       |  (Lock-Free SPSC Queue 2)
 *       v
 *   [Core 3] Receiver / Egress (Uplink Decap, PCAP Capture & Latency Analytics)
 *       |
 *       +--> Automatic Slab Recycling back to MemoryPool (pkt->release())
 */

#include "core/packet_buffer.hpp"
#include "core/memory_pool.hpp"
#include "core/spsc_ring_queue.hpp"
#include "core/timing_wheel.hpp"
#include "protocols/gtpu_processor.hpp"
#include "protocols/rlc_am_entity.hpp"
#include "sim/pcap_writer.hpp"
#include "sim/channel_model.hpp"
#include "sim/traffic_generator.hpp"

#include <iostream>
#include <iomanip>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <csignal>

#if defined(_WIN32)
#include <windows.h>
inline void pin_thread_to_core(uint32_t core_id) noexcept {
    HANDLE thread = GetCurrentThread();
    DWORD_PTR mask = 1ULL << (core_id % std::thread::hardware_concurrency());
    SetThreadAffinityMask(thread, mask);
}
#elif defined(__linux__)
#include <pthread.h>
#include <sched.h>
inline void pin_thread_to_core(uint32_t core_id) noexcept {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id % std::thread::hardware_concurrency(), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}
#else
inline void pin_thread_to_core(uint32_t) noexcept {}
#endif

using namespace telecom::core;
using namespace telecom::protocol;
using namespace telecom::sim;

// Global shutdown flag
static std::atomic<bool> g_running{true};

void signal_handler(int) {
    g_running.store(false, std::memory_order_relaxed);
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);

    std::cout << "================================================================================" << std::endl;
    std::cout << "  5G NR / LTE HIGH-SPEED PACKET PROCESSOR & SIMULATOR PIPELINE                  " << std::endl;
    std::cout << "  Zero-Copy, Lock-Free Multi-Threaded Architecture with CPU Core Pinning       " << std::endl;
    std::cout << "================================================================================" << std::endl;

    const unsigned int num_cores = std::thread::hardware_concurrency();
    std::cout << "[SYSTEM] Detected CPU Cores: " << num_cores << std::endl;

    // Simulation parameters
    const size_t SIMULATION_PACKETS = (argc > 1) ? std::stoull(argv[1]) : 1'000'000;
    const std::string PCAP_FILENAME = "telecom_live_capture.pcap";

    std::cout << "[CONFIG] Target Packets:      " << SIMULATION_PACKETS << std::endl;
    std::cout << "[CONFIG] PCAP Output File:    " << PCAP_FILENAME << " (first 100 packets)" << std::endl;

    // 1. Core Framework Setup
    static MemoryPool<65536> memory_pool; // 64K contiguous pre-allocated slab (~138MB RAM)
    static SpscRingQueue<PacketBuffer*, 8192> queue_gen_to_gtpu;
    static SpscRingQueue<PacketBuffer*, 8192> queue_gtpu_to_channel;
    static SpscRingQueue<PacketBuffer*, 8192> queue_channel_to_rx;

    // 2. Protocol Engine Setup (GTP-U)
    static GtpuProcessor<16384> gtpu_engine;
    const uint32_t TUNNEL_TEID = 0x5E001;
    TunnelContext tunnel;
    tunnel.local_teid  = TUNNEL_TEID;
    tunnel.remote_teid = TUNNEL_TEID;
    tunnel.local_ip    = 0x0A000101; // 10.0.1.1 (gNB)
    tunnel.peer_ip     = 0x0A000102; // 10.0.1.2 (UPF Core)
    tunnel.qfi         = 9;          // 5G Voice / Critical IoT Flow
    tunnel.dscp        = 46;         // Expedited Forwarding (EF)
    gtpu_engine.add_tunnel(tunnel);

    // 3. Simulation Models
    ChannelConfig ch_cfg;
    ch_cfg.loss_model = LossModelType::BERNOULLI;
    ch_cfg.bernoulli_loss_rate = 0.02; // 2% wireless loss
    ch_cfg.reorder_prob = 0.05;        // 5% packet delay/reorder
    ch_cfg.min_delay_tti = 1;
    ch_cfg.max_delay_tti = 3;

    TrafficGenConfig tg_cfg;
    tg_cfg.pattern = TrafficPattern::BURSTY_POISSON;
    tg_cfg.default_teid = TUNNEL_TEID;
    tg_cfg.default_qfi  = 9;
    tg_cfg.min_payload_size = 64;
    tg_cfg.max_payload_size = 1400;

    static TrafficGenerator<65536> traffic_gen(tg_cfg, memory_pool);
    static PcapWriter pcap_writer(PCAP_FILENAME);
    static LatencyTracker latency_tracker;

    std::atomic<uint64_t> completed_packets{0};
    std::atomic<uint64_t> total_bytes_rx{0};

    auto wall_clock_start = std::chrono::high_resolution_clock::now();

    // ------------------------------------------------------------------------
    // STAGE 1: Traffic Generator Thread (Pinned to Core 0)
    // ------------------------------------------------------------------------
    std::thread thread_traffic([&]() {
        pin_thread_to_core(0);
        size_t count = 0;

        while (g_running.load(std::memory_order_relaxed) && count < SIMULATION_PACKETS) {
            PacketBuffer* pkt = traffic_gen.generate_packet();
            if (!pkt) {
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
                continue;
            }

            while (!queue_gen_to_gtpu.push(pkt)) {
                if (!g_running.load(std::memory_order_relaxed)) {
                    pkt->release();
                    return;
                }
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
            }
            ++count;
        }
    });

    // ------------------------------------------------------------------------
    // STAGE 2: GTP-U Protocol Processing Thread (Pinned to Core 1)
    // ------------------------------------------------------------------------
    std::thread thread_gtpu([&]() {
        pin_thread_to_core(1);

        constexpr size_t BATCH_SIZE = 32;
        PacketBuffer* batch[BATCH_SIZE];

        while (g_running.load(std::memory_order_relaxed) || !queue_gen_to_gtpu.empty()) {
            size_t popped = queue_gen_to_gtpu.pop_batch(batch, BATCH_SIZE);
            if (popped == 0) {
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
                continue;
            }

            for (size_t i = 0; i < popped; ++i) {
                // Downlink Encapsulation: Outer IPv4 + Outer UDP + GTP-U + 5G QFI
                gtpu_engine.encapsulate_downlink(*batch[i], TUNNEL_TEID);

                while (!queue_gtpu_to_channel.push(batch[i])) {
#if defined(__x86_64__) || defined(_M_X64)
                    __builtin_ia32_pause();
#endif
                }
            }
        }
    });

    // ------------------------------------------------------------------------
    // STAGE 3: Impaired Wireless Channel Simulator Thread (Pinned to Core 2)
    // ------------------------------------------------------------------------
    std::thread thread_channel([&]() {
        pin_thread_to_core(2);

        ChannelModel channel(ch_cfg);
        std::vector<PacketBuffer*> delivered;
        delivered.reserve(64);

        size_t tti_counter = 0;

        while (g_running.load(std::memory_order_relaxed) || !queue_gtpu_to_channel.empty()) {
            PacketBuffer* pkt = nullptr;
            if (queue_gtpu_to_channel.pop(pkt)) {
                delivered.clear();
                channel.transmit(pkt, delivered);

                // Forward immediately delivered packets
                for (auto* p : delivered) {
                    while (!queue_channel_to_rx.push(p)) {
#if defined(__x86_64__) || defined(_M_X64)
                        __builtin_ia32_pause();
#endif
                    }
                }
            } else {
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
            }

            if (++tti_counter % 32 == 0) {
                delivered.clear();
                channel.step_tti(delivered);
                for (auto* p : delivered) {
                    while (!queue_channel_to_rx.push(p)) {
#if defined(__x86_64__) || defined(_M_X64)
                        __builtin_ia32_pause();
#endif
                    }
                }
            }
        }

        // Flush on finish
        delivered.clear();
        channel.flush(delivered);
        for (auto* p : delivered) {
            while (!queue_channel_to_rx.push(p)) {
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
            }
        }
    });

    // ------------------------------------------------------------------------
    // STAGE 4: Receiver & Telemetry Egress Thread (Pinned to Core 3)
    // ------------------------------------------------------------------------
    std::thread thread_rx([&]() {
        pin_thread_to_core(3);

        size_t pcap_dumps = 0;

        while (g_running.load(std::memory_order_relaxed)) {
            PacketBuffer* pkt = nullptr;
            if (queue_channel_to_rx.pop(pkt)) {
                // Dump first 100 packets to PCAP for Wireshark inspection
                if (pcap_dumps < 100) {
                    pcap_writer.write_packet(*pkt, true);
                    ++pcap_dumps;
                }

                // Uplink Decapsulation: Strip outer headers, parse 5G QFI
                uint32_t teid = 0;
                uint8_t qfi = 0;
                GtpuStatus status = gtpu_engine.decapsulate_uplink(*pkt, teid, qfi);

                if (status == GtpuStatus::SUCCESS) {
                    total_bytes_rx.fetch_add(pkt->length(), std::memory_order_relaxed);
                    latency_tracker.record_packet(*pkt);
                }

                const uint64_t current = completed_packets.fetch_add(1, std::memory_order_relaxed) + 1;

                // Release buffer directly back to MemoryPool
                pkt->release();

                if (current >= SIMULATION_PACKETS * 0.97) {
                    // Reached target packets (allowing for channel drops)
                    g_running.store(false, std::memory_order_relaxed);
                    break;
                }
            } else {
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
            }
        }
    });

    // Wait for pipeline completion
    thread_traffic.join();
    thread_gtpu.join();
    thread_channel.join();
    thread_rx.join();

    auto wall_clock_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_duration = wall_clock_end - wall_clock_start;

    pcap_writer.close();

    const double seconds = total_duration.count();
    const uint64_t total_pkts = completed_packets.load(std::memory_order_relaxed);
    const double mpps = (static_cast<double>(total_pkts) / seconds) / 1'000'000.0;
    const double gbps = (static_cast<double>(total_bytes_rx.load(std::memory_order_relaxed)) * 8.0) / (seconds * 1e9);

    LatencyReport lat = latency_tracker.generate_report();

    // ------------------------------------------------------------------------
    // Final Telemetry Dashboard
    // ------------------------------------------------------------------------
    std::cout << "\n================================================================================" << std::endl;
    std::cout << "                       PIPELINE EXECUTION REPORT                                 " << std::endl;
    std::cout << "================================================================================" << std::endl;
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  Execution Wall-Time:    " << seconds << " seconds" << std::endl;
    std::cout << "  Total Packets Handled:  " << total_pkts << " packets" << std::endl;
    std::cout << "  Throughput (Mpps):      " << mpps << " Million packets/sec" << std::endl;
    std::cout << "  Throughput (Gbps):      " << gbps << " Gbps (Payload line rate)" << std::endl;
    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    std::cout << "  LATENCY DISTRIBUTION (End-to-End 1-Way Delay):" << std::endl;
    std::cout << std::setprecision(1);
    std::cout << "    - Min Latency:        " << (lat.min_ns / 1000.0) << " us" << std::endl;
    std::cout << "    - Mean Latency:       " << (lat.mean_ns / 1000.0) << " us" << std::endl;
    std::cout << "    - Median (p50):       " << (lat.p50_ns / 1000.0) << " us" << std::endl;
    std::cout << "    - 95th Percentile:    " << (lat.p95_ns / 1000.0) << " us" << std::endl;
    std::cout << "    - 99th Percentile:    " << (lat.p99_ns / 1000.0) << " us" << std::endl;
    std::cout << "    - 99.9th Percentile:  " << (lat.p99_9_ns / 1000.0) << " us" << std::endl;
    std::cout << "    - Max Latency:        " << (lat.max_ns / 1000.0) << " us" << std::endl;
    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    std::cout << "  GTP-U TELEMETRY:" << std::endl;
    std::cout << "    - Downlink Packets:   " << gtpu_engine.total_downlink_packets() << std::endl;
    std::cout << "    - Uplink Packets:     " << gtpu_engine.total_uplink_packets() << std::endl;
    std::cout << "    - Dropped / Unknown:  " << gtpu_engine.dropped_unknown_teid() << std::endl;
    std::cout << "  MEMORY POOL STATUS:" << std::endl;
    std::cout << "    - Slab In-Use:        " << memory_pool.in_use() << " / " << memory_pool.capacity() << std::endl;
    std::cout << "    - Alloc Failures:     " << memory_pool.alloc_failures() << std::endl;
    std::cout << "  WIRESHARK PCAP OUTPUT:" << std::endl;
    std::cout << "    - Saved PCAP:         " << PCAP_FILENAME << " (Dissectible with Wireshark)" << std::endl;
    std::cout << "================================================================================" << std::endl;

    return 0;
}
