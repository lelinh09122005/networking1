#include "include/protocols/gtpu_processor.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <chrono>

using namespace telecom::protocol;
using namespace telecom::core;

void test_fast_tunnel_table() {
    std::cout << "[TEST] 1. Checking FastTunnelTable (Open Addressing Flat Hash Map)..." << std::endl;
    FastTunnelTable<2048> table;

    assert(table.size() == 0);
    assert(table.capacity() == 2048);

    // Insert 1000 tunnels
    for (uint32_t i = 1; i <= 1000; ++i) {
        TunnelContext ctx;
        ctx.local_teid  = 0x10000 + i;
        ctx.remote_teid = 0x20000 + i;
        ctx.local_ip    = 0x0A000001; // 10.0.0.1
        ctx.peer_ip     = 0x0A000002; // 10.0.0.2
        ctx.qfi         = static_cast<uint8_t>(i % 64);
        bool ok = table.insert(ctx);
        assert(ok);
    }
    assert(table.size() == 1000);

    // Lookup every tunnel
    for (uint32_t i = 1; i <= 1000; ++i) {
        TunnelContext* ctx = table.find(0x10000 + i);
        assert(ctx != nullptr);
        assert(ctx->remote_teid == 0x20000 + i);
        assert(ctx->qfi == (i % 64));
    }

    // Lookup non-existent tunnels
    assert(table.find(0x99999) == nullptr);
    assert(table.find(0) == nullptr);

    // Erase 200 tunnels
    for (uint32_t i = 1; i <= 200; ++i) {
        bool ok = table.erase(0x10000 + i);
        assert(ok);
    }
    assert(table.size() == 800);

    // Verify erased are gone and remaining 800 are still found
    for (uint32_t i = 1; i <= 200; ++i) {
        assert(table.find(0x10000 + i) == nullptr);
    }
    for (uint32_t i = 201; i <= 1000; ++i) {
        assert(table.find(0x10000 + i) != nullptr);
    }

    std::cout << "  -> PASSED!" << std::endl;
}

void test_downlink_uplink_roundtrip() {
    std::cout << "[TEST] 2. Checking Basic Downlink Encap & Uplink Decap (Round-Trip)..." << std::endl;
    GtpuProcessor<1024> processor;

    const uint32_t GNB_TEID = 0xAAAA1111;
    const uint32_t UPF_TEID = 0xBBBB2222;
    const uint32_t GNB_IP   = 0xC0A80101; // 192.168.1.1
    const uint32_t UPF_IP   = 0xC0A80102; // 192.168.1.2

    // Setup tunnel context at UPF (Downlink sender)
    TunnelContext upf_ctx;
    upf_ctx.local_teid  = UPF_TEID;
    upf_ctx.remote_teid = GNB_TEID; // Packets sent to gNB with gNB_TEID
    upf_ctx.local_ip    = UPF_IP;
    upf_ctx.peer_ip     = GNB_IP;
    upf_ctx.qfi         = 0; // Standard 4G bearer (no 5G extension header)
    processor.add_tunnel(upf_ctx);

    // Setup tunnel context at gNB (Uplink receiver)
    TunnelContext gnb_ctx;
    gnb_ctx.local_teid  = GNB_TEID; // Expects incoming packets with GNB_TEID
    gnb_ctx.remote_teid = UPF_TEID;
    gnb_ctx.local_ip    = GNB_IP;
    gnb_ctx.peer_ip     = UPF_IP;
    processor.add_tunnel(gnb_ctx);

    // Create user IP datagram
    PacketBuffer pkt;
    pkt.reset();
    const char raw_ip_payload[] = "GET /5g-video-stream HTTP/1.1\r\nHost: cdn.telecom.net\r\n\r\n";
    const uint16_t orig_len = static_cast<uint16_t>(sizeof(raw_ip_payload));
    pkt.copy_from(raw_ip_payload, orig_len);

    // 1. Downlink Encapsulation
    bool encap_ok = processor.encapsulate_downlink(pkt, UPF_TEID);
    assert(encap_ok);

    // Expected outer overhead: IPv4 (20B) + UDP (8B) + GTP-U (8B) = 36B
    assert(pkt.length() == orig_len + 36);

    // Validate Outer IPv4 Header
    auto* ip = pkt.header<Ipv4Header>();
    assert((ip->version_ihl >> 4) == 4);
    assert((ip->version_ihl & 0x0F) == 5);
    assert(ip->protocol == 17); // UDP
    assert(compute_ip_checksum(ip, sizeof(Ipv4Header)) == 0);
    assert(endian::ntohl(ip->src_ip) == UPF_IP);
    assert(endian::ntohl(ip->dst_ip) == GNB_IP);

    // 2. Uplink Decapsulation
    uint32_t extracted_teid = 0;
    uint8_t extracted_qfi = 0;
    GtpuStatus status = processor.decapsulate_uplink(pkt, extracted_teid, extracted_qfi);

    assert(status == GtpuStatus::SUCCESS);
    assert(extracted_teid == GNB_TEID);
    assert(extracted_qfi == 0);
    assert(pkt.length() == orig_len);
    assert(std::memcmp(pkt.data(), raw_ip_payload, orig_len) == 0);

    // Verify telemetry
    TunnelContext* updated_ctx = processor.get_tunnel(GNB_TEID);
    assert(updated_ctx->rx_packets == 1);
    assert(updated_ctx->rx_bytes == orig_len);

    std::cout << "  -> PASSED!" << std::endl;
}

void test_5g_qfi_encap_decap() {
    std::cout << "[TEST] 3. Checking 5G QoS Flow (QFI) PDU Session Container..." << std::endl;
    GtpuProcessor<1024> processor;

    const uint32_t TEID = 0x55556666;
    const uint8_t TARGET_QFI = 9; // QoS Flow ID 9

    TunnelContext ctx;
    ctx.local_teid  = TEID;
    ctx.remote_teid = TEID;
    ctx.local_ip    = 0x0A000101;
    ctx.peer_ip     = 0x0A000102;
    ctx.qfi         = TARGET_QFI; // Enable 5G Extension Header
    processor.add_tunnel(ctx);

    PacketBuffer pkt;
    pkt.reset();
    uint8_t dummy_payload[60];
    for (size_t i = 0; i < sizeof(dummy_payload); ++i) dummy_payload[i] = static_cast<uint8_t>(i);
    pkt.copy_from(dummy_payload, sizeof(dummy_payload));

    // Downlink Encap with 5G QFI: IPv4(20) + UDP(8) + GTP-U(8) + Opt(4) + 5G PDU Container(4) = 44B
    bool encap_ok = processor.encapsulate_downlink(pkt, TEID);
    assert(encap_ok);
    assert(pkt.length() == sizeof(dummy_payload) + 44);

    // Uplink Decap
    uint32_t extracted_teid = 0;
    uint8_t extracted_qfi = 0;
    GtpuStatus status = processor.decapsulate_uplink(pkt, extracted_teid, extracted_qfi);

    assert(status == GtpuStatus::SUCCESS);
    assert(extracted_teid == TEID);
    assert(extracted_qfi == TARGET_QFI);
    assert(pkt.length() == sizeof(dummy_payload));
    assert(std::memcmp(pkt.data(), dummy_payload, sizeof(dummy_payload)) == 0);

    std::cout << "  -> PASSED! (Extracted 5G QFI: " << static_cast<int>(extracted_qfi) << ")" << std::endl;
}

void test_error_handling() {
    std::cout << "[TEST] 4. Checking Error Handling (Unknown TEID, Truncated Buffer, Malformed)..." << std::endl;
    GtpuProcessor<1024> processor;

    PacketBuffer pkt;
    pkt.reset();

    // 1. Buffer too short
    pkt.append(20); // Less than 36 bytes minimum
    uint32_t teid = 0;
    uint8_t qfi = 0;
    assert(processor.decapsulate_uplink(pkt, teid, qfi) == GtpuStatus::BUFFER_TOO_SHORT);

    // 2. Unknown TEID
    pkt.reset();
    uint8_t user_data[40]{};
    pkt.copy_from(user_data, sizeof(user_data));
    gtpu_encapsulate(pkt, 0x99999999); // Unregistered TEID

    auto* udp = pkt.prepend_header<UdpHeader>();
    udp->src_port = htons(GTPU_UDP_PORT);
    udp->dst_port = htons(GTPU_UDP_PORT);
    udp->length   = htons(static_cast<uint16_t>(pkt.data_len));
    udp->checksum = 0;

    auto* ip = pkt.prepend_header<Ipv4Header>();
    ip->version_ihl    = 0x45;
    ip->protocol       = IP_PROTO_UDP;
    ip->total_length   = htons(static_cast<uint16_t>(pkt.data_len));
    ip->checksum       = compute_ip_checksum(ip, sizeof(Ipv4Header));

    assert(processor.decapsulate_uplink(pkt, teid, qfi) == GtpuStatus::UNKNOWN_TEID);
    assert(processor.dropped_unknown_teid() == 1);

    std::cout << "  -> PASSED!" << std::endl;
}

void test_echo_request_response() {
    std::cout << "[TEST] 5. Checking GTP-U Echo Request & Echo Response Keep-alive..." << std::endl;
    GtpuProcessor<1024> processor;

    PacketBuffer echo_req;
    echo_req.reset();

    // Build incoming Echo Request (MsgType 0x01)
    const uint16_t seq = 0x1234;
    auto* opt = echo_req.prepend_header<GtpuHeaderOpt>();
    opt->seq_num = htons(seq);
    opt->npdu_num = 0;
    opt->next_ext_type = 0;

    auto* gtpu = echo_req.prepend_header<GtpuHeader>();
    gtpu->flags    = GtpuConstants::VERSION_1 | GtpuConstants::PROTOCOL_TYPE | GtpuConstants::SEQ_NUM_FLAG;
    gtpu->msg_type = GtpuConstants::MSG_ECHO_REQ;
    gtpu->length   = htons(sizeof(GtpuHeaderOpt));
    gtpu->teid     = 0;

    auto* udp = echo_req.prepend_header<UdpHeader>();
    udp->src_port = htons(GTPU_UDP_PORT);
    udp->dst_port = htons(GTPU_UDP_PORT);
    udp->length   = htons(static_cast<uint16_t>(echo_req.data_len));
    udp->checksum = 0;

    auto* ip = echo_req.prepend_header<Ipv4Header>();
    ip->version_ihl    = 0x45;
    ip->dscp_ecn       = 0;
    ip->total_length   = htons(static_cast<uint16_t>(echo_req.data_len));
    ip->identification = 0;
    ip->flags_offset   = htons(0x4000);
    ip->ttl            = 64;
    ip->protocol       = IP_PROTO_UDP;
    ip->checksum       = 0;
    ip->src_ip         = htonl(0x0A000001);
    ip->dst_ip         = htonl(0x0A000002);
    ip->checksum       = compute_ip_checksum(ip, sizeof(Ipv4Header));

    uint32_t teid = 0;
    uint8_t qfi = 0;
    GtpuStatus status = processor.decapsulate_uplink(echo_req, teid, qfi);
    assert(status == GtpuStatus::ECHO_REQUEST_HANDLED);
    assert(processor.echo_requests_received() == 1);

    // Build Echo Response
    PacketBuffer echo_resp;
    processor.build_echo_response(echo_resp, 0x0A000002, 0x0A000001, seq);

    assert(echo_resp.length() > 0);
    assert(processor.echo_responses_sent() == 1);

    std::cout << "  -> PASSED!" << std::endl;
}

void test_batch_processing_benchmark() {
    std::cout << "[TEST] 6. Running Vector Batch Processing Benchmark (5,000,000 Packets)..." << std::endl;
    GtpuProcessor<8192> processor;

    // Register 100 tunnels
    for (uint32_t i = 1; i <= 100; ++i) {
        TunnelContext ctx;
        ctx.local_teid  = 0x1000 + i;
        ctx.remote_teid = 0x1000 + i; // Loopback test
        ctx.local_ip    = 0x0A000101;
        ctx.peer_ip     = 0x0A000102;
        ctx.qfi         = static_cast<uint8_t>(i % 64);
        processor.add_tunnel(ctx);
    }

    constexpr size_t BATCH_SIZE = 64;
    constexpr size_t ITERATIONS = 78125; // 64 * 78125 = 5,000,000 packets

    std::vector<PacketBuffer> storage(BATCH_SIZE);
    PacketBuffer* batch[BATCH_SIZE];
    uint32_t teids[BATCH_SIZE];

    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        batch[i] = &storage[i];
        teids[i] = static_cast<uint32_t>(0x1000 + (i % 100) + 1);
    }

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t iter = 0; iter < ITERATIONS; ++iter) {
        // 1. Prepare batch of user IP packets
        for (size_t i = 0; i < BATCH_SIZE; ++i) {
            batch[i]->reset();
            batch[i]->append(50); // 50 bytes payload
        }

        // 2. Downlink Encapsulation Batch
        size_t encap_count = processor.process_downlink_batch(batch, teids, BATCH_SIZE);
        assert(encap_count == BATCH_SIZE);

        // 3. Uplink Decapsulation Batch
        size_t decap_count = processor.process_uplink_batch(batch, BATCH_SIZE);
        assert(decap_count == BATCH_SIZE);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;

    const size_t total_packets = BATCH_SIZE * ITERATIONS;
    double mpps = (static_cast<double>(total_packets) / diff.count()) / 1'000'000.0;
    double ns_per_packet = (diff.count() * 1e9) / static_cast<double>(total_packets);

    std::cout << "  - Processed: " << total_packets << " full round-trip packets (Encap + Decap) in " 
              << diff.count() << " s" << std::endl;
    std::cout << "  - Vector Batch Throughput: " << mpps << " Mpps" << std::endl;
    std::cout << "  - Latency: " << ns_per_packet << " ns/packet" << std::endl;
    std::cout << "  -> PASSED!" << std::endl;
}

int main() {
    std::cout << "==========================================================" << std::endl;
    std::cout << "     3GPP TS 29.281 GTP-U PROCESSOR VERIFICATION SUITE    " << std::endl;
    std::cout << "==========================================================" << std::endl;

    test_fast_tunnel_table();
    test_downlink_uplink_roundtrip();
    test_5g_qfi_encap_decap();
    test_error_handling();
    test_echo_request_response();
    test_batch_processing_benchmark();

    std::cout << "==========================================================" << std::endl;
    std::cout << "   ALL GTP-U PROCESSOR TESTS PASSED SUCCESSFULLY!         " << std::endl;
    std::cout << "==========================================================" << std::endl;
    return 0;
}
