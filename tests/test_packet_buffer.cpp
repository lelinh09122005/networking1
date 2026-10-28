#include "include/core/packet_buffer.hpp"
#include <iostream>
#include <cassert>
#include <chrono>
#include <vector>

void test_memory_layout() {
    std::cout << "[TEST] 1. Checking memory layout and 64-byte alignment..." << std::endl;
    static_assert(alignof(PacketBuffer) == 64, "Must be 64-byte aligned");
    static_assert(offsetof(PacketBuffer, buffer) == 64, "Buffer must start at offset 64");
    static_assert(sizeof(PacketBuffer) == 64 + PacketBuffer::MAX_BUF_SIZE, "Size must match metadata + buffer");

    auto pkt = std::make_unique<PacketBuffer>();
    uintptr_t addr = reinterpret_cast<uintptr_t>(pkt.get());
    uintptr_t buf_addr = reinterpret_cast<uintptr_t>(pkt->buffer);

    std::cout << "  - PacketBuffer address: 0x" << std::hex << addr << std::dec << std::endl;
    std::cout << "  - Buffer address:       0x" << std::hex << buf_addr << std::dec << std::endl;
    std::cout << "  - PacketBuffer size:    " << sizeof(PacketBuffer) << " bytes" << std::endl;

    assert(addr % 64 == 0 && "Heap allocated PacketBuffer must be 64-byte aligned!");
    assert(buf_addr % 64 == 0 && "Internal buffer must be 64-byte aligned!");
    std::cout << "  -> PASSED!" << std::endl;
}

void test_zero_copy_operations() {
    std::cout << "[TEST] 2. Checking Zero-Copy operations (prepend, strip, append, trim)..." << std::endl;
    PacketBuffer pkt;
    pkt.reset();

    assert(pkt.headroom() == PacketBuffer::DEFAULT_HEADROOM);
    assert(pkt.length() == 0);
    assert(pkt.empty());
    assert(pkt.tailroom() == PacketBuffer::MAX_BUF_SIZE - PacketBuffer::DEFAULT_HEADROOM);

    // 1. Append payload: "HELLO_5G_WORLD"
    const char payload[] = "HELLO_5G_WORLD";
    const uint16_t payload_len = static_cast<uint16_t>(sizeof(payload));
    pkt.append_data(payload, payload_len);

    assert(pkt.length() == payload_len);
    assert(!pkt.empty());
    assert(std::memcmp(pkt.data(), payload, payload_len) == 0);
    assert(pkt.headroom() == PacketBuffer::DEFAULT_HEADROOM);

    // 2. Prepend header of 16 bytes
    uint8_t* hdr_ptr = pkt.prepend(16);
    std::memset(hdr_ptr, 0xAA, 16);

    assert(pkt.length() == payload_len + 16);
    assert(pkt.headroom() == PacketBuffer::DEFAULT_HEADROOM - 16);
    assert(pkt.data()[0] == 0xAA);
    assert(pkt.data()[15] == 0xAA);
    assert(std::memcmp(pkt.data() + 16, payload, payload_len) == 0);

    // 3. Strip header of 16 bytes
    pkt.strip(16);
    assert(pkt.length() == payload_len);
    assert(pkt.headroom() == PacketBuffer::DEFAULT_HEADROOM);
    assert(std::memcmp(pkt.data(), payload, payload_len) == 0);

    // 4. Trim 6 bytes from tail
    pkt.trim(6);
    assert(pkt.length() == payload_len - 6);
    assert(std::memcmp(pkt.data(), "HELLO_5G_", 9) == 0);

    std::cout << "  -> PASSED!" << std::endl;
}

void test_gtpu_basic_encap_decap() {
    std::cout << "[TEST] 3. Checking basic GTP-U (3GPP TS 29.281) Encap & Decap..." << std::endl;
    PacketBuffer pkt;
    pkt.reset();

    // Payload: User IPv4 Packet simulation (40 bytes)
    uint8_t ip_packet[40];
    for (size_t i = 0; i < sizeof(ip_packet); ++i) {
        ip_packet[i] = static_cast<uint8_t>(i + 1);
    }
    pkt.copy_from(ip_packet, sizeof(ip_packet));

    const uint32_t TEID = 0x12345678;

    // Encapsulate with GTP-U
    gtpu_encapsulate(pkt, TEID);

    assert(pkt.length() == sizeof(ip_packet) + sizeof(GtpuHeader));
    auto* gtp = pkt.header<GtpuHeader>();
    assert((gtp->flags & 0xE0) == GtpuConstants::VERSION_1);
    assert(gtp->msg_type == GtpuConstants::MSG_TPDU);
    assert(telecom::core::endian::ntohl(gtp->teid) == TEID);
    assert(telecom::core::endian::ntohs(gtp->length) == sizeof(ip_packet));

    // Decapsulate
    uint32_t extracted_teid = 0;
    uint8_t extracted_qfi = 0;
    bool decap_ok = gtpu_decapsulate(pkt, extracted_teid, extracted_qfi);

    assert(decap_ok);
    assert(extracted_teid == TEID);
    assert(extracted_qfi == 0);
    assert(pkt.length() == sizeof(ip_packet));
    assert(std::memcmp(pkt.data(), ip_packet, sizeof(ip_packet)) == 0);

    std::cout << "  -> PASSED!" << std::endl;
}

void test_gtpu_5g_qfi_encap_decap() {
    std::cout << "[TEST] 4. Checking 5G NR GTP-U Encap & Decap with PDU Session Container (QFI)..." << std::endl;
    PacketBuffer pkt;
    pkt.reset();

    uint8_t ip_packet[100];
    for (size_t i = 0; i < sizeof(ip_packet); ++i) {
        ip_packet[i] = static_cast<uint8_t>(i);
    }
    pkt.copy_from(ip_packet, sizeof(ip_packet));

    const uint32_t TEID = 0x9ABCDEF0;
    const uint8_t QFI   = 9; // 5G QoS Flow Identifier 9

    // Encapsulate 5G GTP-U: Base Header (8B) + Opt Header (4B) + PDU Session Container (4B) = 16B
    gtpu_encapsulate_5g(pkt, TEID, QFI);

    assert(pkt.length() == sizeof(ip_packet) + 16);

    // Decapsulate and verify
    uint32_t extracted_teid = 0;
    uint8_t extracted_qfi = 0;
    bool decap_ok = gtpu_decapsulate(pkt, extracted_teid, extracted_qfi);

    assert(decap_ok);
    assert(extracted_teid == TEID);
    assert(extracted_qfi == QFI);
    assert(pkt.length() == sizeof(ip_packet));
    assert(std::memcmp(pkt.data(), ip_packet, sizeof(ip_packet)) == 0);

    std::cout << "  -> PASSED! (Extracted TEID: 0x" << std::hex << extracted_teid 
              << ", QFI: " << std::dec << static_cast<int>(extracted_qfi) << ")" << std::endl;
}

void test_slicing_rlc_segmentation() {
    std::cout << "[TEST] 5. Checking SDU slicing for RLC Segmentation..." << std::endl;
    PacketBuffer sdu;
    sdu.reset();

    // 1000 bytes SDU
    uint8_t raw_sdu[1000];
    for (size_t i = 0; i < sizeof(raw_sdu); ++i) {
        raw_sdu[i] = static_cast<uint8_t>(i & 0xFF);
    }
    sdu.copy_from(raw_sdu, sizeof(raw_sdu));
    sdu.teid_or_rnti = 0x42;
    sdu.seq_num = 105;

    // Simulate MAC grant of 400 bytes, 400 bytes, and 200 bytes
    PacketBuffer seg1, seg2, seg3;
    bool s1 = sdu.slice_into(seg1, 0, 400);
    bool s2 = sdu.slice_into(seg2, 400, 400);
    bool s3 = sdu.slice_into(seg3, 800, 200);

    assert(s1 && s2 && s3);
    assert(seg1.length() == 400);
    assert(seg2.length() == 400);
    assert(seg3.length() == 200);

    assert(std::memcmp(seg1.data(), raw_sdu, 400) == 0);
    assert(std::memcmp(seg2.data(), raw_sdu + 400, 400) == 0);
    assert(std::memcmp(seg3.data(), raw_sdu + 800, 200) == 0);

    std::cout << "  -> PASSED!" << std::endl;
}

void test_performance_mpps() {
    std::cout << "[TEST] 6. Running Performance Benchmark (Zero-Copy Encap/Decap Throughput)..." << std::endl;
    constexpr size_t ITERATIONS = 10'000'000; // 10 Million packets

    auto pkt = std::make_unique<PacketBuffer>();
    pkt->copy_from("1234567890123456789012345678901234567890", 40);

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < ITERATIONS; ++i) {
        // Encap
        gtpu_encapsulate(*pkt, static_cast<uint32_t>(i));
        // Decap
        uint32_t teid = 0;
        uint8_t qfi = 0;
        gtpu_decapsulate(*pkt, teid, qfi);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;

    double seconds = diff.count();
    double mpps = (static_cast<double>(ITERATIONS) / seconds) / 1'000'000.0;
    double ns_per_pkt = (seconds * 1e9) / static_cast<double>(ITERATIONS);

    std::cout << "  - Processed: " << ITERATIONS << " round-trip packets in " << seconds << " s" << std::endl;
    std::cout << "  - Throughput: " << mpps << " Million packets/sec (Mpps)" << std::endl;
    std::cout << "  - Latency:    " << ns_per_pkt << " ns/packet (Encap + Decap)" << std::endl;
    std::cout << "  -> PASSED!" << std::endl;
}

int main() {
    std::cout << "==========================================================" << std::endl;
    std::cout << "   TELECOM ZERO-COPY PACKET BUFFER VERIFICATION SUITE    " << std::endl;
    std::cout << "==========================================================" << std::endl;

    test_memory_layout();
    test_zero_copy_operations();
    test_gtpu_basic_encap_decap();
    test_gtpu_5g_qfi_encap_decap();
    test_slicing_rlc_segmentation();
    test_performance_mpps();

    std::cout << "==========================================================" << std::endl;
    std::cout << "   ALL TESTS PASSED SUCCESSFULLY!                        " << std::endl;
    std::cout << "==========================================================" << std::endl;
    return 0;
}
