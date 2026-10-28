#include "include/protocols/rlc_am_entity.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <chrono>

using namespace telecom::protocol;
using namespace telecom::core;

void test_rlc_unsegmented_transfer() {
    std::cout << "[TEST] 1. Checking RLC AM Unsegmented SDU Transfer..." << std::endl;
    MemoryPool<1024> pool;
    TimingWheel<1024> tw;
    RlcAmConfig cfg;
    RlcAmEntity<1024, 1024> rlc_tx(cfg, pool, tw);
    RlcAmEntity<1024, 1024> rlc_rx(cfg, pool, tw);

    // Create 150-byte SDU
    PacketBuffer* sdu = pool.allocate();
    assert(sdu != nullptr);
    sdu->reset();
    uint8_t payload[150];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = static_cast<uint8_t>(i);
    sdu->copy_from(payload, sizeof(payload));

    rlc_tx.push_sdu(sdu);
    assert(rlc_tx.tx_queue_size() == 1);

    // MAC grant = 300 bytes (fits 150 bytes SDU + 2 bytes header)
    std::vector<PacketBuffer*> tx_pdus;
    rlc_tx.generate_pdus(300, tx_pdus);

    assert(tx_pdus.size() == 1);
    assert(rlc_tx.tx_queue_size() == 0);
    assert(tx_pdus[0]->length() == 150 + sizeof(RlcAmHeader12));

    auto* hdr = tx_pdus[0]->header<RlcAmHeader12>();
    assert(hdr->is_data());
    assert(hdr->si() == RlcConstants::SI_FULL_SDU);
    assert(hdr->sn() == 0);

    // Pass PDU to RX entity
    std::vector<PacketBuffer*> rx_sdus;
    rlc_rx.process_rx_pdu(tx_pdus[0], rx_sdus);

    assert(rx_sdus.size() == 1);
    assert(rx_sdus[0]->length() == sizeof(payload));
    assert(std::memcmp(rx_sdus[0]->data(), payload, sizeof(payload)) == 0);
    assert(rlc_rx.rx_next() == 1);

    rx_sdus[0]->release();
    std::cout << "  -> PASSED!" << std::endl;
}

void test_rlc_sdu_segmentation() {
    std::cout << "[TEST] 2. Checking RLC AM Segmentation (1000B SDU over 3 MAC grants)..." << std::endl;
    MemoryPool<1024> pool;
    TimingWheel<1024> tw;
    RlcAmConfig cfg;
    RlcAmEntity<1024, 1024> rlc_tx(cfg, pool, tw);
    RlcAmEntity<1024, 1024> rlc_rx(cfg, pool, tw);

    // Create 1000-byte SDU
    PacketBuffer* sdu = pool.allocate();
    sdu->reset();
    uint8_t payload[1000];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = static_cast<uint8_t>(i & 0xFF);
    sdu->copy_from(payload, sizeof(payload));

    rlc_tx.push_sdu(sdu);

    // Grant 1: 400 bytes -> First Segment (SI = 01, Header = 2B, Payload = 398B)
    std::vector<PacketBuffer*> pdu_batch1;
    rlc_tx.generate_pdus(400, pdu_batch1);
    assert(pdu_batch1.size() == 1);
    assert(pdu_batch1[0]->length() == 400);
    auto* h1 = pdu_batch1[0]->header<RlcAmHeader12>();
    assert(h1->si() == RlcConstants::SI_FIRST_SEGMENT);
    assert(h1->sn() == 0);

    // Grant 2: 400 bytes -> Middle Segment (SI = 11, Header = 4B (2B Base + 2B SO), Payload = 396B)
    std::vector<PacketBuffer*> pdu_batch2;
    rlc_tx.generate_pdus(400, pdu_batch2);
    assert(pdu_batch2.size() == 1);
    assert(pdu_batch2[0]->length() == 400);
    auto* h2 = pdu_batch2[0]->header<RlcAmHeader12>();
    assert(h2->si() == RlcConstants::SI_MID_SEGMENT);
    assert(h2->sn() == 0); // Segments of the same SDU share SN 0

    // Grant 3: 300 bytes -> Last Segment (SI = 10, Header = 4B, Payload = 1000 - 398 - 396 = 206B)
    std::vector<PacketBuffer*> pdu_batch3;
    rlc_tx.generate_pdus(300, pdu_batch3);
    assert(pdu_batch3.size() == 1);
    assert(pdu_batch3[0]->length() == 206 + 4);
    auto* h3 = pdu_batch3[0]->header<RlcAmHeader12>();
    assert(h3->si() == RlcConstants::SI_LAST_SEGMENT);
    assert(h3->sn() == 0); // Segments of the same SDU share SN 0
    assert(rlc_tx.tx_queue_size() == 0); // SDU completely consumed!

    // Feed all 3 segments to RX entity
    std::vector<PacketBuffer*> rx_sdus;
    rlc_rx.process_rx_pdu(pdu_batch1[0], rx_sdus);
    assert(rx_sdus.empty()); // Incomplete, waiting for remaining fragments

    rlc_rx.process_rx_pdu(pdu_batch2[0], rx_sdus);
    assert(rx_sdus.empty()); // Still incomplete

    rlc_rx.process_rx_pdu(pdu_batch3[0], rx_sdus);
    assert(rx_sdus.size() == 1); // Completely reassembled!

    assert(rx_sdus[0]->length() == sizeof(payload));
    assert(std::memcmp(rx_sdus[0]->data(), payload, sizeof(payload)) == 0);

    rx_sdus[0]->release();
    std::cout << "  -> PASSED!" << std::endl;
}

void test_rlc_out_of_order_reordering() {
    std::cout << "[TEST] 3. Checking RLC AM Out-of-Order Reordering & Sliding Window..." << std::endl;
    MemoryPool<1024> pool;
    TimingWheel<1024> tw;
    RlcAmConfig cfg;
    RlcAmEntity<1024, 1024> rlc_tx(cfg, pool, tw);
    RlcAmEntity<1024, 1024> rlc_rx(cfg, pool, tw);

    // Push 5 SDUs
    for (int i = 0; i < 5; ++i) {
        PacketBuffer* sdu = pool.allocate();
        sdu->reset();
        uint8_t val = static_cast<uint8_t>(10 + i);
        sdu->copy_from(&val, 1);
        rlc_tx.push_sdu(sdu);
    }

    std::vector<PacketBuffer*> tx_pdus;
    rlc_tx.generate_pdus(1000, tx_pdus);
    assert(tx_pdus.size() == 5);

    // Deliver out-of-order: 0, 2, 4, 1, 3
    std::vector<PacketBuffer*> rx_sdus;

    // Receive SN 0 -> delivers SDU 0
    rlc_rx.process_rx_pdu(tx_pdus[0], rx_sdus);
    assert(rx_sdus.size() == 1);
    assert(rx_sdus[0]->data()[0] == 10);

    // Receive SN 2 -> buffered (gap at 1)
    rlc_rx.process_rx_pdu(tx_pdus[2], rx_sdus);
    assert(rx_sdus.size() == 1);

    // Receive SN 4 -> buffered (gap at 1, 3)
    rlc_rx.process_rx_pdu(tx_pdus[4], rx_sdus);
    assert(rx_sdus.size() == 1);

    // Receive SN 1 -> fills first gap! In-order flush delivers SN 1 and SN 2!
    rlc_rx.process_rx_pdu(tx_pdus[1], rx_sdus);
    assert(rx_sdus.size() == 3);
    assert(rx_sdus[1]->data()[0] == 11);
    assert(rx_sdus[2]->data()[0] == 12);

    // Receive SN 3 -> fills second gap! Delivers SN 3 and SN 4!
    rlc_rx.process_rx_pdu(tx_pdus[3], rx_sdus);
    assert(rx_sdus.size() == 5);
    assert(rx_sdus[3]->data()[0] == 13);
    assert(rx_sdus[4]->data()[0] == 14);

    assert(rlc_rx.rx_next() == 5);

    for (auto* s : rx_sdus) s->release();
    std::cout << "  -> PASSED!" << std::endl;
}

void test_rlc_arq_status_pdu_retransmission() {
    std::cout << "[TEST] 4. Checking ARQ Retransmission with STATUS PDU (Packet Loss Recovery)..." << std::endl;
    MemoryPool<1024> pool;
    TimingWheel<1024> tw;
    RlcAmConfig cfg;
    cfg.t_reassembly_ticks = 10; // 10 ms reassembly timer
    RlcAmEntity<1024, 1024> rlc_tx(cfg, pool, tw);
    RlcAmEntity<1024, 1024> rlc_rx(cfg, pool, tw);

    // Send 3 SDUs (SN 0, 1, 2)
    for (int i = 0; i < 3; ++i) {
        PacketBuffer* sdu = pool.allocate();
        sdu->reset();
        uint8_t val = static_cast<uint8_t>(100 + i);
        sdu->copy_from(&val, 1);
        rlc_tx.push_sdu(sdu);
    }

    std::vector<PacketBuffer*> tx_pdus;
    rlc_tx.generate_pdus(1000, tx_pdus);
    assert(tx_pdus.size() == 3);

    // Channel simulation: SN 0 delivered, SN 1 LOST, SN 2 delivered
    std::vector<PacketBuffer*> rx_sdus;
    rlc_rx.process_rx_pdu(tx_pdus[0], rx_sdus);
    assert(rx_sdus.size() == 1); // SDU 0 delivered

    // Drop SN 1: tx_pdus[1] is discarded
    tx_pdus[1]->release();

    // SN 2 arrives: gap detected, starts t-Reassembly timer!
    rlc_rx.process_rx_pdu(tx_pdus[2], rx_sdus);
    assert(rx_sdus.size() == 1); // SDU 2 buffered, waiting for SN 1

    // Advance TimingWheel by 10 ticks -> t-Reassembly timer expires!
    tw.tick(10);

    // RX generates STATUS PDU acknowledging SN 0, NACKing SN 1
    PacketBuffer* status_pdu = rlc_rx.generate_status_pdu();
    assert(status_pdu != nullptr);

    // Deliver STATUS PDU back to TX entity
    std::vector<PacketBuffer*> dummy;
    rlc_tx.process_rx_pdu(status_pdu, dummy);

    // On next MAC grant, TX should prioritize retransmitting NACKed SN 1!
    std::vector<PacketBuffer*> retx_pdus;
    rlc_tx.generate_pdus(500, retx_pdus);

    assert(retx_pdus.size() == 1);
    auto* retx_hdr = retx_pdus[0]->header<RlcAmHeader12>();
    assert(retx_hdr->sn() == 1); // Retransmitted SN 1!

    // Feed retransmitted SN 1 to RX entity: Gap filled!
    rlc_rx.process_rx_pdu(retx_pdus[0], rx_sdus);

    assert(rx_sdus.size() == 3); // All 3 SDUs delivered in-order!
    assert(rx_sdus[0]->data()[0] == 100);
    assert(rx_sdus[1]->data()[0] == 101);
    assert(rx_sdus[2]->data()[0] == 102);

    for (auto* s : rx_sdus) s->release();
    std::cout << "  -> PASSED!" << std::endl;
}

void test_rlc_am_benchmark() {
    std::cout << "[TEST] 5. Running High-Throughput RLC AM Benchmark (100,000 SDUs)..." << std::endl;
    constexpr size_t POOL_SIZE = 16384;
    static MemoryPool<POOL_SIZE> pool;
    static TimingWheel<POOL_SIZE> tw;
    RlcAmConfig cfg;
    cfg.poll_pdu = 32;
    static RlcAmEntity<POOL_SIZE, POOL_SIZE> rlc_tx(cfg, pool, tw);
    static RlcAmEntity<POOL_SIZE, POOL_SIZE> rlc_rx(cfg, pool, tw);

    constexpr size_t TOTAL_SDUS = 100'000;
    auto start = std::chrono::high_resolution_clock::now();

    size_t sdu_sent = 0;
    size_t sdu_received = 0;

    std::vector<PacketBuffer*> pdu_list;
    pdu_list.reserve(64);
    std::vector<PacketBuffer*> rx_sdus;
    rx_sdus.reserve(64);

    while (sdu_received < TOTAL_SDUS) {
        // Enqueue batch of SDUs if room
        while (sdu_sent < TOTAL_SDUS && rlc_tx.tx_queue_size() < 128) {
            PacketBuffer* sdu = pool.allocate();
            if (!sdu) break;
            sdu->reset();
            sdu->append(256); // 256 bytes per SDU
            rlc_tx.push_sdu(sdu);
            ++sdu_sent;
        }

        // MAC grant = 1000 bytes per TTI
        pdu_list.clear();
        rlc_tx.generate_pdus(1000, pdu_list);

        // Receive PDUs at RX
        for (auto* pdu : pdu_list) {
            rx_sdus.clear();
            rlc_rx.process_rx_pdu(pdu, rx_sdus);
            sdu_received += rx_sdus.size();
            for (auto* s : rx_sdus) s->release();
        }

        // Periodically exchange STATUS PDUs
        PacketBuffer* status = rlc_rx.generate_status_pdu();
        if (status) {
            std::vector<PacketBuffer*> dummy;
            rlc_tx.process_rx_pdu(status, dummy);
        }

        tw.tick(1);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;

    double mpps = (static_cast<double>(TOTAL_SDUS) / diff.count()) / 1'000'000.0;
    double ns_per_sdu = (diff.count() * 1e9) / static_cast<double>(TOTAL_SDUS);

    std::cout << "  - Processed: " << TOTAL_SDUS << " complete RLC AM SDUs in " << diff.count() << " s" << std::endl;
    std::cout << "  - End-to-End RLC AM Throughput: " << mpps << " Million SDUs/sec" << std::endl;
    std::cout << "  - Processing Latency: " << ns_per_sdu << " ns/SDU" << std::endl;
    std::cout << "  -> PASSED!" << std::endl;
}

int main() {
    std::cout << "==========================================================" << std::endl;
    std::cout << "     3GPP TS 38.322 5G NR RLC AM VERIFICATION SUITE       " << std::endl;
    std::cout << "==========================================================" << std::endl;

    test_rlc_unsegmented_transfer();
    test_rlc_sdu_segmentation();
    test_rlc_out_of_order_reordering();
    test_rlc_arq_status_pdu_retransmission();
    test_rlc_am_benchmark();

    std::cout << "==========================================================" << std::endl;
    std::cout << "   ALL RLC AM PROTOCOL TESTS PASSED SUCCESSFULLY!         " << std::endl;
    std::cout << "==========================================================" << std::endl;
    return 0;
}
