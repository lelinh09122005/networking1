#include "include/sim/pcap_writer.hpp"
#include "include/sim/channel_model.hpp"
#include "include/sim/traffic_generator.hpp"
#include "include/protocols/gtpu_processor.hpp"

#include <iostream>
#include <cassert>
#include <vector>
#include <chrono>
#include <cmath>

using namespace telecom::sim;
using namespace telecom::protocol;
using namespace telecom::core;

void test_pcap_writer() {
    std::cout << "[TEST] 1. Checking PcapWriter (Wireshark .pcap format generation)..." << std::endl;
    const std::string test_file = "test_output.pcap";

    PcapWriter writer;
    bool ok = writer.open(test_file);
    assert(ok);
    assert(writer.is_open());

    // Create a dummy GTP-U packet: IPv4(20B) + UDP(8B) + GTP-U(8B) + Payload(40B)
    PacketBuffer pkt;
    pkt.reset();
    uint8_t payload[40];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = static_cast<uint8_t>(i);
    pkt.copy_from(payload, sizeof(payload));

    gtpu_encapsulate(pkt, 0x12345678);

    auto* udp = pkt.prepend_header<UdpHeader>();
    udp->src_port = htons(GTPU_UDP_PORT);
    udp->dst_port = htons(GTPU_UDP_PORT);
    udp->length   = htons(static_cast<uint16_t>(pkt.data_len));
    udp->checksum = 0;

    auto* ip = pkt.prepend_header<Ipv4Header>();
    ip->version_ihl    = 0x45;
    ip->dscp_ecn       = 0;
    ip->total_length   = htons(static_cast<uint16_t>(pkt.data_len));
    ip->identification = 1;
    ip->flags_offset   = htons(0x4000);
    ip->ttl            = 64;
    ip->protocol       = 17; // UDP
    ip->checksum       = 0;
    ip->src_ip         = htonl(0xC0A80101); // 192.168.1.1
    ip->dst_ip         = htonl(0xC0A80102); // 192.168.1.2
    ip->checksum       = compute_ip_checksum(ip, sizeof(Ipv4Header));

    // Write 10 packets into PCAP
    for (int i = 0; i < 10; ++i) {
        bool w_ok = writer.write_packet(pkt, true); // With Ethernet header
        assert(w_ok);
    }

    assert(writer.packet_count() == 10);
    writer.close();
    assert(!writer.is_open());

    // Read back and verify PCAP Magic and Headers
    std::ifstream file(test_file, std::ios::binary);
    assert(file.is_open());

    PcapGlobalHeader gh;
    file.read(reinterpret_cast<char*>(&gh), sizeof(gh));
    assert(gh.magic_number == 0xa1b2c3d4);
    assert(gh.version_major == 2);
    assert(gh.version_minor == 4);
    assert(gh.network == 1); // Ethernet LinkType

    PcapPacketHeader ph;
    file.read(reinterpret_cast<char*>(&ph), sizeof(ph));
    assert(ph.incl_len == sizeof(EthernetHeader) + pkt.length());
    file.close();

    std::cout << "  -> PASSED! (Created valid " << test_file << " dissectible by Wireshark)" << std::endl;
}

void test_channel_model() {
    std::cout << "[TEST] 2. Checking ChannelModel (Bernoulli, Gilbert-Elliott, Reordering)..." << std::endl;
    MemoryPool<8192> pool;

    // 1. Bernoulli Loss Test (Target: 20% loss)
    ChannelConfig cfg_bernoulli;
    cfg_bernoulli.loss_model = LossModelType::BERNOULLI;
    cfg_bernoulli.bernoulli_loss_rate = 0.20;
    cfg_bernoulli.reorder_prob = 0.0; // No delay

    ChannelModel channel_b(cfg_bernoulli);
    std::vector<PacketBuffer*> passed;

    constexpr size_t TEST_PKTS = 5000;
    for (size_t i = 0; i < TEST_PKTS; ++i) {
        PacketBuffer* pkt = pool.allocate();
        pkt->reset();
        channel_b.transmit(pkt, passed);
    }

    double measured_loss = channel_b.actual_loss_rate();
    std::cout << "  - Bernoulli loss target: 20.0%, measured: " << (measured_loss * 100.0) << "%" << std::endl;
    assert(std::abs(measured_loss - 0.20) < 0.03); // Within 3% tolerance

    for (auto* p : passed) p->release();
    passed.clear();

    // 2. Reordering & Jitter Test
    ChannelConfig cfg_reorder;
    cfg_reorder.loss_model = LossModelType::NONE;
    cfg_reorder.reorder_prob = 0.50; // 50% delayed
    cfg_reorder.min_delay_tti = 1;
    cfg_reorder.max_delay_tti = 3;

    ChannelModel channel_r(cfg_reorder);
    std::vector<PacketBuffer*> delivered;

    // Transmit 10 packets with sequence IDs
    for (uint32_t i = 0; i < 10; ++i) {
        PacketBuffer* pkt = pool.allocate();
        pkt->reset();
        pkt->seq_num = i;
        channel_r.transmit(pkt, delivered);
    }

    assert(channel_r.total_delayed() > 0);

    // Advance 5 TTIs to release delayed packets
    for (int t = 0; t < 5; ++t) {
        channel_r.step_tti(delivered);
    }

    assert(delivered.size() == 10);
    assert(channel_r.pending_delayed_packets() == 0);

    for (auto* p : delivered) p->release();
    delivered.clear();

    // 3. Dynamic MAC Scheduler Test
    DynamicMacScheduler mac_sched(200, 1500);
    for (int i = 0; i < 100; ++i) {
        uint32_t grant = mac_sched.get_grant();
        assert(grant >= 200 && grant <= 1500);
    }

    std::cout << "  -> PASSED!" << std::endl;
}

void test_traffic_generator_and_latency() {
    std::cout << "[TEST] 3. Checking TrafficGenerator & High-Resolution Latency Tracking..." << std::endl;
    MemoryPool<2048> pool;

    TrafficGenConfig cfg;
    cfg.pattern = TrafficPattern::BIMODAL_INTERNET; // 40B vs 1400B
    TrafficGenerator<2048> gen(cfg, pool);

    LatencyTracker tracker;

    // Generate 1000 packets
    for (int i = 0; i < 1000; ++i) {
        PacketBuffer* pkt = gen.generate_packet();
        assert(pkt != nullptr);
        assert(pkt->length() == 40 || pkt->length() == 1400);

        // Simulate 50 us pipeline latency
        uint64_t simulated_arrival_ns = pkt->timestamp_ns + 50'000 + (i * 100);
        tracker.record_packet(*pkt, simulated_arrival_ns);

        pkt->release();
    }

    LatencyReport rep = tracker.generate_report();
    assert(rep.sample_count == 1000);
    assert(rep.min_ns >= 50'000);
    assert(rep.p50_ns > 0);
    assert(rep.p99_ns >= rep.p50_ns);

    std::cout << "  - Samples: " << rep.sample_count << std::endl;
    std::cout << "  - Latency p50: " << (rep.p50_ns / 1000.0) << " us, p99: " << (rep.p99_ns / 1000.0) << " us" << std::endl;
    std::cout << "  -> PASSED!" << std::endl;
}

void test_end_to_end_sim_pipeline() {
    std::cout << "[TEST] 4. Running End-to-End Simulation Pipeline with Impaired Channel & PCAP Dump..." << std::endl;
    constexpr size_t POOL_SIZE = 8192;
    MemoryPool<POOL_SIZE> pool;

    // 1. Setup GTP-U Tunnel
    GtpuProcessor<1024> gtpu;
    const uint32_t TEID = 0x5E001;
    TunnelContext ctx;
    ctx.local_teid  = TEID;
    ctx.remote_teid = TEID;
    ctx.local_ip    = 0x0A000001;
    ctx.peer_ip     = 0x0A000002;
    ctx.qfi         = 9; // 5G Voice QoS Flow
    gtpu.add_tunnel(ctx);

    // 2. Setup Impaired Wireless Channel (5% loss, 10% reordering)
    ChannelConfig ch_cfg;
    ch_cfg.loss_model = LossModelType::BERNOULLI;
    ch_cfg.bernoulli_loss_rate = 0.05;
    ch_cfg.reorder_prob = 0.10;
    ChannelModel channel(ch_cfg);

    // 3. Setup Traffic Generator
    TrafficGenConfig tg_cfg;
    tg_cfg.pattern = TrafficPattern::BURSTY_POISSON;
    tg_cfg.default_teid = TEID;
    TrafficGenerator<POOL_SIZE> generator(tg_cfg, pool);

    // 4. Setup PCAP Writer & Latency Tracker
    PcapWriter pcap("telecom_sim_capture.pcap");
    LatencyTracker latency;

    constexpr size_t TOTAL_PACKETS = 50'000;
    std::vector<PacketBuffer*> channel_delivered;
    channel_delivered.reserve(128);

    auto start_time = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < TOTAL_PACKETS; ++i) {
        // Step A: Ingress user packet from traffic generator
        PacketBuffer* pkt = generator.generate_packet();
        if (!pkt) continue;

        // Step B: Downlink GTP-U Encapsulation (Outer IP + UDP + GTP-U + 5G QFI)
        bool encap_ok = gtpu.encapsulate_downlink(*pkt, TEID);
        assert(encap_ok);

        // Dump first 20 packets to PCAP for inspection
        if (i < 20) {
            pcap.write_packet(*pkt, true);
        }

        // Step C: Transmit through Impaired Wireless Channel
        channel_delivered.clear();
        channel.transmit(pkt, channel_delivered);

        // Step D: Step channel TTI every 10 packets to flush delayed packets
        if (i % 10 == 0) {
            channel.step_tti(channel_delivered);
        }

        // Step E: Egress at receiver - Uplink GTP-U Decapsulation
        for (auto* rx_pkt : channel_delivered) {
            uint32_t rx_teid = 0;
            uint8_t rx_qfi = 0;
            GtpuStatus status = gtpu.decapsulate_uplink(*rx_pkt, rx_teid, rx_qfi);
            if (status == GtpuStatus::SUCCESS) {
                assert(rx_teid == TEID);
                assert(rx_qfi == 9);
                latency.record_packet(*rx_pkt);
            }
            rx_pkt->release();
        }
    }

    // Flush any remaining packets in channel
    channel_delivered.clear();
    channel.flush(channel_delivered);
    for (auto* p : channel_delivered) {
        p->release();
    }

    pcap.close();

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end_time - start_time;

    double mpps = (static_cast<double>(TOTAL_PACKETS) / diff.count()) / 1'000'000.0;
    LatencyReport lat_rep = latency.generate_report();

    std::cout << "  - Simulation Results for " << TOTAL_PACKETS << " packets in " << diff.count() << " s:" << std::endl;
    std::cout << "    * System Throughput:  " << mpps << " Mpps" << std::endl;
    std::cout << "    * Channel Loss:       " << (channel.actual_loss_rate() * 100.0) << "%" << std::endl;
    std::cout << "    * Reordered Packets:  " << channel.total_delayed() << std::endl;
    std::cout << "    * Latency p50:        " << lat_rep.p50_ns << " ns" << std::endl;
    std::cout << "    * Latency p99:        " << lat_rep.p99_ns << " ns" << std::endl;
    std::cout << "    * PCAP Output:        " << pcap.filename() << " (" << pcap.packet_count() << " packets)" << std::endl;
    std::cout << "  -> PASSED!" << std::endl;
}

int main() {
    std::cout << "==========================================================" << std::endl;
    std::cout << "     SIMULATION HARNESS & ENVIRONMENT VERIFICATION        " << std::endl;
    std::cout << "==========================================================" << std::endl;

    test_pcap_writer();
    test_channel_model();
    test_traffic_generator_and_latency();
    test_end_to_end_sim_pipeline();

    std::cout << "==========================================================" << std::endl;
    std::cout << "   ALL SIMULATION HARNESS TESTS PASSED SUCCESSFULLY!      " << std::endl;
    std::cout << "==========================================================" << std::endl;
    return 0;
}
