#pragma once

/**
 * @file pcap_writer.hpp
 * @brief Zero-Dependency Standard Libpcap (.pcap) File Generator for Wireshark.
 *
 * Telecom Verification Requirement:
 *   Validates bit/byte compliance with 3GPP TS 29.281 (GTP-U) and TS 38.322 (RLC)
 *   by writing captured frames into standard .pcap files dissectible by Wireshark.
 *
 * File Format (RFC 1071 / libpcap):
 *   - 24-byte Global Header
 *   - 16-byte Packet Header per record
 *   - Automatic Ethernet II encapsulation (14 bytes) for L3/L4/GTP-U Wireshark dissection.
 */

#include "../core/packet_buffer.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <string>
#include <chrono>

namespace telecom::sim {

#pragma pack(push, 1)

/**
 * @brief Standard PCAP Global Header (24 bytes).
 */
struct PcapGlobalHeader {
    uint32_t magic_number{0xa1b2c3d4}; // Standard PCAP magic (microseconds resolution)
    uint16_t version_major{2};
    uint16_t version_minor{4};
    int32_t  thiszone{0};              // GMT to local correction
    uint32_t sigfigs{0};               // Accuracy of timestamps
    uint32_t snaplen{65535};           // Max snapshot length
    uint32_t network{1};               // Data Link Type: 1 = DLT_EN10MB (Ethernet II)
};

/**
 * @brief Standard PCAP Packet Record Header (16 bytes).
 */
struct PcapPacketHeader {
    uint32_t ts_sec{0};   // Timestamp seconds
    uint32_t ts_usec{0};  // Timestamp microseconds
    uint32_t incl_len{0}; // Number of bytes of packet saved in file
    uint32_t orig_len{0}; // Actual length of packet on wire
};

/**
 * @brief Ethernet II Frame Header (14 bytes) for Wireshark dissection.
 */
struct EthernetHeader {
    uint8_t  dst_mac[6]{0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    uint8_t  src_mac[6]{0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint16_t ether_type{0x0008}; // 0x0800 = IPv4 (Big-Endian: stored as 0x0008 on little-endian)
};

#pragma pack(pop)

static_assert(sizeof(PcapGlobalHeader) == 24, "PcapGlobalHeader must be exactly 24 bytes");
static_assert(sizeof(PcapPacketHeader) == 16, "PcapPacketHeader must be exactly 16 bytes");
static_assert(sizeof(EthernetHeader) == 14, "EthernetHeader must be exactly 14 bytes");

class PcapWriter {
    std::ofstream out_file_;
    std::string   filename_;
    size_t        packet_count_{0};
    size_t        bytes_written_{0};

public:
    PcapWriter() = default;

    explicit PcapWriter(const std::string& filename) {
        open(filename);
    }

    ~PcapWriter() {
        close();
    }

    // Non-copyable, movable
    PcapWriter(const PcapWriter&) = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;

    PcapWriter(PcapWriter&& other) noexcept
        : out_file_(std::move(other.out_file_)),
          filename_(std::move(other.filename_)),
          packet_count_(other.packet_count_),
          bytes_written_(other.bytes_written_) {
        other.packet_count_ = 0;
        other.bytes_written_ = 0;
    }

    PcapWriter& operator=(PcapWriter&& other) noexcept {
        if (this != &other) {
            close();
            out_file_ = std::move(other.out_file_);
            filename_ = std::move(other.filename_);
            packet_count_ = other.packet_count_;
            bytes_written_ = other.bytes_written_;
            other.packet_count_ = 0;
            other.bytes_written_ = 0;
        }
        return *this;
    }

    /**
     * @brief Open a new .pcap file and write the Global PCAP Header.
     * @param filename Path to output file.
     * @return true if successfully opened and initialized, false otherwise.
     */
    bool open(const std::string& filename) noexcept {
        close();
        filename_ = filename;
        out_file_.open(filename, std::ios::binary | std::ios::out | std::ios::trunc);
        if (!out_file_.is_open()) return false;

        PcapGlobalHeader gh;
        out_file_.write(reinterpret_cast<const char*>(&gh), sizeof(gh));
        if (!out_file_.good()) {
            close();
            return false;
        }

        packet_count_ = 0;
        bytes_written_ = sizeof(gh);
        return true;
    }

    /**
     * @brief Close active PCAP file.
     */
    void close() noexcept {
        if (out_file_.is_open()) {
            out_file_.flush();
            out_file_.close();
        }
    }

    /**
     * @brief Write a raw frame into the .pcap file.
     * @param data Pointer to frame bytes.
     * @param len Length of frame.
     * @param timestamp_ns Timestamp in nanoseconds (0 = use current steady_clock time).
     * @return true if written successfully, false otherwise.
     */
    bool write_frame(const void* data, size_t len, uint64_t timestamp_ns = 0) noexcept {
        if (!out_file_.is_open() || !data || len == 0) return false;

        if (timestamp_ns == 0) {
            timestamp_ns = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
        }

        PcapPacketHeader ph;
        ph.ts_sec   = static_cast<uint32_t>(timestamp_ns / 1'000'000'000ULL);
        ph.ts_usec  = static_cast<uint32_t>((timestamp_ns % 1'000'000'000ULL) / 1'000ULL);
        ph.incl_len = static_cast<uint32_t>(len);
        ph.orig_len = static_cast<uint32_t>(len);

        out_file_.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
        out_file_.write(static_cast<const char*>(data), len);

        if (!out_file_.good()) return false;

        ++packet_count_;
        bytes_written_ += (sizeof(ph) + len);
        return true;
    }

    /**
     * @brief Write a PacketBuffer containing an outer IPv4 packet (e.g. GTP-U frame).
     * Adds an Ethernet II header so Wireshark immediately parses IPv4 -> UDP -> GTP-U.
     *
     * @param pkt PacketBuffer containing IP datagram.
     * @param add_ethernet True to prepend an Ethernet II header for Wireshark.
     * @return true on success.
     */
    bool write_packet(const telecom::core::PacketBuffer& pkt, bool add_ethernet = true) noexcept {
        if (!out_file_.is_open() || pkt.empty()) return false;

        if (add_ethernet) {
            // Write Ethernet Header (14B) + Packet Data
            const size_t total_frame_len = sizeof(EthernetHeader) + pkt.length();

            uint64_t ts = pkt.timestamp_ns;
            if (ts == 0) {
                ts = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
            }

            PcapPacketHeader ph;
            ph.ts_sec   = static_cast<uint32_t>(ts / 1'000'000'000ULL);
            ph.ts_usec  = static_cast<uint32_t>((ts % 1'000'000'000ULL) / 1'000ULL);
            ph.incl_len = static_cast<uint32_t>(total_frame_len);
            ph.orig_len = static_cast<uint32_t>(total_frame_len);

            EthernetHeader eth;
            eth.ether_type = 0x0008; // 0x0800 Big-Endian (IPv4)

            out_file_.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
            out_file_.write(reinterpret_cast<const char*>(&eth), sizeof(eth));
            out_file_.write(reinterpret_cast<const char*>(pkt.data()), pkt.length());

            if (!out_file_.good()) return false;

            ++packet_count_;
            bytes_written_ += (sizeof(ph) + total_frame_len);
            return true;
        } else {
            return write_frame(pkt.data(), pkt.length(), pkt.timestamp_ns);
        }
    }

    [[nodiscard]] bool is_open() const noexcept { return out_file_.is_open(); }
    [[nodiscard]] size_t packet_count() const noexcept { return packet_count_; }
    [[nodiscard]] size_t bytes_written() const noexcept { return bytes_written_; }
    [[nodiscard]] const std::string& filename() const noexcept { return filename_; }
};

} // namespace telecom::sim
