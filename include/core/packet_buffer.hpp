#pragma once

/**
 * @file packet_buffer.hpp
 * @brief High-Speed Zero-Copy Packet Buffer for Telecom Protocol Processing.
 *
 * Designed for 5G NR / LTE Layer-2 (RLC/PDCP) and User Plane (GTP-U/UPF).
 * Key Features:
 *   - Zero-Copy manipulation: prepend, strip, append, trim.
 *   - 64-byte L1 Cache-Line alignment: avoids false sharing, maximizes memory bus throughput.
 *   - Compact 64-byte metadata header on Cacheline 0; payload buffer begins at Cacheline 1.
 *   - Pre-allocated headroom (128 bytes) for zero-copy header encapsulation (GTP-U, UDP, IP, MAC).
 *   - Portable endianness conversion (Windows / Linux) and packed 3GPP wire headers.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cassert>
#include <bit>
#include <span>
#include <type_traits>

namespace telecom::core {

// ============================================================================
// Portable Endianness Conversion (Network Byte Order <-> Host Byte Order)
// ============================================================================
namespace endian {

#if defined(__cpp_lib_byteswap) && __cpp_lib_byteswap >= 202110L
    using std::byteswap;
#else
    constexpr uint16_t byteswap(uint16_t val) noexcept {
#if defined(_MSC_VER)
        return _byteswap_ushort(val);
#elif defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap16(val);
#else
        return static_cast<uint16_t>((val << 8) | (val >> 8));
#endif
    }

    constexpr uint32_t byteswap(uint32_t val) noexcept {
#if defined(_MSC_VER)
        return _byteswap_ulong(val);
#elif defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap32(val);
#else
        return __builtin_bswap32(val);
#endif
    }

    constexpr uint64_t byteswap(uint64_t val) noexcept {
#if defined(_MSC_VER)
        return _byteswap_uint64(val);
#elif defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap64(val);
#else
        return __builtin_bswap64(val);
#endif
    }
#endif

    template <typename T>
    constexpr T host_to_net(T val) noexcept {
        static_assert(std::is_integral_v<T>, "Endian conversion requires integral type");
        if constexpr (std::endian::native == std::endian::little) {
            return byteswap(val);
        } else {
            return val;
        }
    }

    template <typename T>
    constexpr T net_to_host(T val) noexcept {
        return host_to_net(val);
    }

    inline uint16_t htons(uint16_t v) noexcept { return host_to_net(v); }
    inline uint16_t ntohs(uint16_t v) noexcept { return net_to_host(v); }
    inline uint32_t htonl(uint32_t v) noexcept { return host_to_net(v); }
    inline uint32_t ntohl(uint32_t v) noexcept { return net_to_host(v); }
    inline uint64_t htonll(uint64_t v) noexcept { return host_to_net(v); }
    inline uint64_t ntohll(uint64_t v) noexcept { return net_to_host(v); }

} // namespace endian

// ============================================================================
// Packet Flags (QoS, Retransmission, Segment Status)
// ============================================================================
namespace PacketFlags {
    static constexpr uint8_t NONE           = 0x00;
    static constexpr uint8_t CONTROL        = 0x01; // Control PDU (STATUS PDU, GTP-U Echo)
    static constexpr uint8_t RETRANSMISSION = 0x02; // Retransmitted frame (RLC AM ARQ)
    static constexpr uint8_t POLL           = 0x04; // Polling bit set (RLC AM P-bit)
    static constexpr uint8_t SEGMENTED      = 0x08; // SDU segment
    static constexpr uint8_t LAST_SEGMENT   = 0x10; // Last segment of an SDU
    static constexpr uint8_t DROP_SIM       = 0x20; // Channel simulator drop mark
}

// ============================================================================
// PacketBuffer: Telecom-Grade Zero-Copy Buffer Structure
// ============================================================================
struct alignas(64) PacketBuffer {
    // 2048 bytes buffer fits Ethernet MTU (1500) + IP/UDP/GTP-U/RLC headers + Headroom
    static constexpr size_t MAX_BUF_SIZE     = 2048;
    static constexpr size_t DEFAULT_HEADROOM = 128; // Headroom for L2-L4 encapsulation

    // ------------------------------------------------------------------------
    // Cacheline 0 (Fast-path metadata: 64 bytes)
    // ------------------------------------------------------------------------
    using ReleaseCallback = void(*)(PacketBuffer* pkt) noexcept;

    uint64_t        timestamp_ns{0};     // Offset 0: Latency measurement (RDTSC / steady_clock)
    PacketBuffer*   next{nullptr};       // Offset 8: Single-linked list (Pool free-list / queue)
    PacketBuffer*   prev{nullptr};       // Offset 16: Doubly-linked list (RLC reassembly/sliding window)
    void*           user_data{nullptr};  // Offset 24: MemoryPool context or protocol owner pointer
    uint32_t        teid_or_rnti{0};     // Offset 32: GTP-U TEID (32-bit) or RLC UE RNTI / LCID
    uint32_t        seq_num{0};          // Offset 36: RLC SN (Sequence Number) or GTP SN
    uint16_t        data_offset{DEFAULT_HEADROOM}; // Offset 40: Offset to active packet start
    uint16_t        data_len{0};         // Offset 42: Valid payload length
    uint16_t        pool_index{0};       // Offset 44: Pre-allocated slab pool index
    uint8_t         qfi{0};              // Offset 46: 5G QoS Flow Identifier (0..63)
    uint8_t         flags{PacketFlags::NONE}; // Offset 47: Control/Segment/Retransmit flags
    ReleaseCallback release_cb{nullptr}; // Offset 48: Callback for zero-overhead pool recycling
    uint8_t         _reserved[8]{};      // Offset 56..63: Explicit padding to 64 bytes

    // ------------------------------------------------------------------------
    // Cacheline 1+: Raw Storage Buffer (Aligned to 64-byte boundary)
    // ------------------------------------------------------------------------
    alignas(64) uint8_t buffer[MAX_BUF_SIZE];

    // ------------------------------------------------------------------------
    // Lifecycle Management
    // ------------------------------------------------------------------------
    /**
     * @brief Reset packet state for reuse without touching pool metadata.
     * @param headroom Custom initial headroom (defaults to DEFAULT_HEADROOM = 128 bytes).
     */
    void reset(uint16_t headroom = DEFAULT_HEADROOM) noexcept {
        assert(headroom <= MAX_BUF_SIZE && "Headroom exceeds maximum buffer capacity!");
        timestamp_ns = 0;
        next         = nullptr;
        prev         = nullptr;
        teid_or_rnti = 0;
        seq_num      = 0;
        data_offset  = headroom;
        data_len     = 0;
        qfi          = 0;
        flags        = PacketFlags::NONE;
    }

    /**
     * @brief Release packet back to its owning MemoryPool without needing a pool reference.
     */
    void release() noexcept {
        if (release_cb) {
            release_cb(this);
        } else {
            reset();
        }
    }

    // ------------------------------------------------------------------------
    // Pointer Accessors
    // ------------------------------------------------------------------------
    /**
     * @brief Pointer to the beginning of active packet data.
     */
    [[nodiscard]] inline uint8_t* data() noexcept {
        return buffer + data_offset;
    }

    [[nodiscard]] inline const uint8_t* data() const noexcept {
        return buffer + data_offset;
    }

    /**
     * @brief Pointer to the byte immediately following the active packet data.
     */
    [[nodiscard]] inline uint8_t* data_end() noexcept {
        return buffer + data_offset + data_len;
    }

    [[nodiscard]] inline const uint8_t* data_end() const noexcept {
        return buffer + data_offset + data_len;
    }

    /**
     * @brief Active packet length in bytes.
     */
    [[nodiscard]] inline uint16_t length() const noexcept {
        return data_len;
    }

    [[nodiscard]] inline uint16_t size() const noexcept {
        return data_len;
    }

    /**
     * @brief Check whether active packet length is 0.
     */
    [[nodiscard]] inline bool empty() const noexcept {
        return data_len == 0;
    }

    /**
     * @brief Available headroom (bytes available before active data for headers).
     */
    [[nodiscard]] inline uint16_t headroom() const noexcept {
        return data_offset;
    }

    /**
     * @brief Available tailroom (bytes available after active data for payload/trailers).
     */
    [[nodiscard]] inline uint16_t tailroom() const noexcept {
        return static_cast<uint16_t>(MAX_BUF_SIZE - (data_offset + data_len));
    }

    /**
     * @brief Total physical storage capacity of the packet buffer.
     */
    [[nodiscard]] static constexpr size_t capacity() noexcept {
        return MAX_BUF_SIZE;
    }

    /**
     * @brief View active packet payload as a C++20 std::span.
     */
    [[nodiscard]] inline std::span<uint8_t> as_span() noexcept {
        return { data(), data_len };
    }

    [[nodiscard]] inline std::span<const uint8_t> as_span() const noexcept {
        return { data(), data_len };
    }

    // ------------------------------------------------------------------------
    // Zero-Copy Transformations
    // ------------------------------------------------------------------------
    /**
     * @brief Prepend header space in the headroom (Zero-Copy push head).
     * @param len Number of bytes to prepend.
     * @return Pointer to the newly allocated header location at data().
     */
    inline uint8_t* prepend(uint16_t len) noexcept {
        assert(data_offset >= len && "PacketBuffer::prepend: Out of headroom!");
        data_offset = static_cast<uint16_t>(data_offset - len);
        data_len    = static_cast<uint16_t>(data_len + len);
        return data();
    }

    /**
     * @brief Strip header bytes from the front (Zero-Copy pop head / decapsulation).
     * @param len Number of header bytes to strip.
     * @return Pointer to the new start of the packet data.
     */
    inline uint8_t* strip(uint16_t len) noexcept {
        assert(data_len >= len && "PacketBuffer::strip: Strip length exceeds packet length!");
        data_offset = static_cast<uint16_t>(data_offset + len);
        data_len    = static_cast<uint16_t>(data_len - len);
        return data();
    }

    /**
     * @brief Append payload or trailer space at the tail (Zero-Copy push tail).
     * @param len Number of bytes to append.
     * @return Pointer to the newly appended space.
     */
    inline uint8_t* append(uint16_t len) noexcept {
        assert(static_cast<size_t>(data_offset) + data_len + len <= MAX_BUF_SIZE && "PacketBuffer::append: Out of tailroom!");
        uint8_t* tail = buffer + data_offset + data_len;
        data_len = static_cast<uint16_t>(data_len + len);
        return tail;
    }

    /**
     * @brief Trim bytes from the end of the packet (Zero-Copy pop tail).
     * @param len Number of bytes to trim from tail.
     */
    inline void trim(uint16_t len) noexcept {
        assert(data_len >= len && "PacketBuffer::trim: Trim length exceeds packet length!");
        data_len = static_cast<uint16_t>(data_len - len);
    }

    // ------------------------------------------------------------------------
    // Strongly-Typed Header Helpers
    // ------------------------------------------------------------------------
    /**
     * @brief Prepend a strongly-typed wire header into headroom.
     * @tparam HeaderT Packed struct type (e.g. GtpuHeader, RlcAmHeader).
     * @return Pointer to the newly placed HeaderT.
     */
    template <typename HeaderT>
    [[nodiscard]] HeaderT* prepend_header() noexcept {
        static_assert(std::is_trivially_copyable_v<HeaderT>, "HeaderT must be trivially copyable");
        return reinterpret_cast<HeaderT*>(prepend(sizeof(HeaderT)));
    }

    /**
     * @brief Append a strongly-typed structure / trailer into tailroom.
     * @tparam HeaderT Packed struct type (e.g. RlcNackBlock12).
     * @return Pointer to newly appended space cast to HeaderT.
     */
    template <typename HeaderT>
    [[nodiscard]] HeaderT* append_header() noexcept {
        static_assert(std::is_trivially_copyable_v<HeaderT>, "HeaderT must be trivially copyable");
        return reinterpret_cast<HeaderT*>(append(sizeof(HeaderT)));
    }

    /**
     * @brief Inspect the header at current data pointer.
     */
    template <typename HeaderT>
    [[nodiscard]] HeaderT* header() noexcept {
        static_assert(std::is_trivially_copyable_v<HeaderT>, "HeaderT must be trivially copyable");
        assert(data_len >= sizeof(HeaderT) && "PacketBuffer::header: Packet smaller than header size!");
        return reinterpret_cast<HeaderT*>(data());
    }

    template <typename HeaderT>
    [[nodiscard]] const HeaderT* header() const noexcept {
        static_assert(std::is_trivially_copyable_v<HeaderT>, "HeaderT must be trivially copyable");
        assert(data_len >= sizeof(HeaderT) && "PacketBuffer::header: Packet smaller than header size!");
        return reinterpret_cast<const HeaderT*>(data());
    }

    /**
     * @brief Strip header of type HeaderT, returning a pointer to the stripped header.
     */
    template <typename HeaderT>
    HeaderT* strip_header() noexcept {
        static_assert(std::is_trivially_copyable_v<HeaderT>, "HeaderT must be trivially copyable");
        assert(data_len >= sizeof(HeaderT) && "PacketBuffer::strip_header: Packet smaller than header size!");
        HeaderT* hdr = reinterpret_cast<HeaderT*>(data());
        strip(sizeof(HeaderT));
        return hdr;
    }

    // ------------------------------------------------------------------------
    // Copy and Slice Utilities (For Ingress & RLC Segmentation)
    // ------------------------------------------------------------------------
    /**
     * @brief Initialize buffer and copy external raw data into payload area.
     */
    bool copy_from(const void* src, uint16_t len, uint16_t headroom = DEFAULT_HEADROOM) noexcept {
        if (!src || static_cast<size_t>(headroom) + len > MAX_BUF_SIZE) return false;
        reset(headroom);
        std::memcpy(buffer + headroom, src, len);
        data_len = len;
        return true;
    }

    /**
     * @brief Append external data into the tail of this buffer.
     */
    bool append_data(const void* src, uint16_t len) noexcept {
        if (!src || tailroom() < len) return false;
        uint8_t* dst = append(len);
        std::memcpy(dst, src, len);
        return true;
    }

    /**
     * @brief Slice a segment [offset, offset + slice_len) of this packet into dst.
     * Used directly by RLC AM/UM TX Segmentation Engine.
     */
    bool slice_into(PacketBuffer& dst, uint16_t offset, uint16_t slice_len, uint16_t dst_headroom = DEFAULT_HEADROOM) const noexcept {
        if (static_cast<size_t>(offset) + slice_len > data_len) return false;
        if (static_cast<size_t>(dst_headroom) + slice_len > MAX_BUF_SIZE) return false;
        dst.reset(dst_headroom);
        std::memcpy(dst.data(), data() + offset, slice_len);
        dst.data_len = slice_len;
        dst.teid_or_rnti = teid_or_rnti;
        dst.seq_num = seq_num;
        dst.qfi = qfi;
        return true;
    }
};

// ============================================================================
// Compile-time Structural and Cache-Line Invariants Verification
// ============================================================================
static_assert(alignof(PacketBuffer) == 64, "PacketBuffer must be aligned to 64-byte L1 Cache Line");
static_assert(offsetof(PacketBuffer, buffer) == 64, "Raw buffer storage must start exactly at Cache Line 1 (Offset 64)");
static_assert(sizeof(PacketBuffer) == 64 + PacketBuffer::MAX_BUF_SIZE, "PacketBuffer size must exactly match metadata + buffer");
static_assert(sizeof(PacketBuffer) % 64 == 0, "PacketBuffer size must be an exact multiple of 64 bytes");

// Backward-compatibility alias
using packet_buffer = PacketBuffer;

// ============================================================================
// GTPv1-U Wire Protocol Headers (3GPP TS 29.281)
// ============================================================================
#pragma pack(push, 1)

/**
 * @brief GTPv1-U Base Header (8 bytes mandatory)
 */
struct GtpuHeader {
    uint8_t  flags;       // Version (3b), PT (1b), Reserved (1b), E (1b), S (1b), PN (1b)
    uint8_t  msg_type;    // Message Type: 0xFF = G-PDU (User Data T-PDU)
    uint16_t length;      // Length of payload following 8-byte base header (Big-Endian)
    uint32_t teid;        // Tunnel Endpoint Identifier (Big-Endian)
};

/**
 * @brief GTPv1-U Optional Fields (4 bytes when E, S, or PN flags are set)
 */
struct GtpuHeaderOpt {
    uint16_t seq_num;        // Sequence number (if S flag = 1)
    uint8_t  npdu_num;       // N-PDU number (if PN flag = 1)
    uint8_t  next_ext_type;  // Next extension header type (if E flag = 1, e.g. 0x85)
};

/**
 * @brief 5G PDU Session Container Extension Header (3GPP TS 38.415, Type 0x85)
 * Conveys 5G QoS Flow Identifier (QFI) across GTP-U tunnels between gNB and UPF.
 */
struct GtpuPduSessionContainer {
    uint8_t ext_length;      // Extension length in 4-octet units (typically 1 = 4 octets)
    uint8_t pdu_type_flags;  // 0x00 for DL PDU SESSION INFORMATION, 0x10 for UL
    uint8_t qfi;             // QoS Flow Identifier (6 bits: 0..63)
    uint8_t next_ext_type;   // Next extension header type (0x00 = None)
};

#pragma pack(pop)

// Compile-time checks for 3GPP wire header sizes
static_assert(sizeof(GtpuHeader) == 8, "GtpuHeader must be exactly 8 bytes");
static_assert(sizeof(GtpuHeaderOpt) == 4, "GtpuHeaderOpt must be exactly 4 bytes");
static_assert(sizeof(GtpuPduSessionContainer) == 4, "GtpuPduSessionContainer must be exactly 4 bytes");

namespace GtpuConstants {
    static constexpr uint8_t VERSION_1      = 0x20; // Version 1 (3 bits: 001)
    static constexpr uint8_t PROTOCOL_TYPE  = 0x10; // PT: 1 for GTP
    static constexpr uint8_t EXTENSION_FLAG = 0x04; // E flag: Extension header present
    static constexpr uint8_t SEQ_NUM_FLAG   = 0x02; // S flag: Sequence number present
    static constexpr uint8_t NPDU_NUM_FLAG  = 0x01; // PN flag: N-PDU number present

    static constexpr uint8_t MSG_ECHO_REQ   = 0x01; // GTP-U Echo Request
    static constexpr uint8_t MSG_ECHO_RESP  = 0x02; // GTP-U Echo Response
    static constexpr uint8_t MSG_ERR_IND    = 0x1A; // GTP-U Error Indication
    static constexpr uint8_t MSG_TPDU       = 0xFF; // G-PDU / T-PDU (User plane data)

    static constexpr uint8_t EXT_TYPE_PDU_SESSION = 0x85; // 5G PDU Session Container
}

// ============================================================================
// Zero-Copy Protocol Encapsulation & Decapsulation Inlines
// ============================================================================

/**
 * @brief Downlink GTP-U Encapsulation (Basic 8-byte Header).
 * Prepends GTP-U header into existing headroom with 0 memory copies.
 *
 * @param pkt  PacketBuffer containing raw user IP payload.
 * @param teid Target Tunnel Endpoint Identifier (Host Byte Order).
 */
inline void gtpu_encapsulate(PacketBuffer& pkt, uint32_t teid) noexcept {
    const uint16_t payload_len = pkt.data_len;
    auto* gtpu = pkt.prepend_header<GtpuHeader>();
    gtpu->flags    = GtpuConstants::VERSION_1 | GtpuConstants::PROTOCOL_TYPE; // 0x30
    gtpu->msg_type = GtpuConstants::MSG_TPDU;
    gtpu->length   = endian::htons(payload_len);
    gtpu->teid     = endian::htonl(teid);
}

/**
 * @brief Downlink 5G GTP-U Encapsulation with PDU Session Container (QFI).
 * Encapsulates payload with 5G Extension Header for UPF <-> gNB User Plane.
 *
 * @param pkt  PacketBuffer containing user IP packet.
 * @param teid Target TEID (Host Byte Order).
 * @param qfi  5G QoS Flow Identifier (0..63).
 */
inline void gtpu_encapsulate_5g(PacketBuffer& pkt, uint32_t teid, uint8_t qfi) noexcept {
    // 1. Prepend 5G PDU Session Container Extension Header (4 bytes)
    auto* psc = pkt.prepend_header<GtpuPduSessionContainer>();
    psc->ext_length     = 1; // 1 unit of 4 octets = 4 bytes
    psc->pdu_type_flags = 0x00; // DL PDU SESSION INFORMATION
    psc->qfi            = qfi & 0x3F; // 6-bit QFI
    psc->next_ext_type  = 0x00; // End of extension header chain

    // 2. Prepend GTP-U Optional Header (4 bytes: Sequence Number & Next Ext Type)
    auto* opt = pkt.prepend_header<GtpuHeaderOpt>();
    opt->seq_num       = 0;
    opt->npdu_num      = 0;
    opt->next_ext_type = GtpuConstants::EXT_TYPE_PDU_SESSION; // 0x85

    // 3. Prepend Mandatory GTP-U Header (8 bytes)
    // In 3GPP TS 29.281, 'length' covers all octets following mandatory 8 bytes (i.e. opt + ext + payload)
    const uint16_t gtp_payload_len = static_cast<uint16_t>(pkt.data_len);
    auto* gtpu = pkt.prepend_header<GtpuHeader>();
    gtpu->flags    = GtpuConstants::VERSION_1 | GtpuConstants::PROTOCOL_TYPE | GtpuConstants::EXTENSION_FLAG; // 0x34
    gtpu->msg_type = GtpuConstants::MSG_TPDU;
    gtpu->length   = endian::htons(gtp_payload_len);
    gtpu->teid     = endian::htonl(teid);
}

/**
 * @brief Uplink GTP-U Decapsulation.
 * Validates header, extracts TEID and optional QFI, and strips headers (Zero-Copy).
 *
 * @param pkt       PacketBuffer containing GTP-U packet.
 * @param out_teid  Extracted TEID in Host Byte Order.
 * @param out_qfi   Extracted QFI (0 if standard 4G bearer or not present).
 * @return true if valid GTP-U packet, false if malformed or unsupported.
 */
inline bool gtpu_decapsulate(PacketBuffer& pkt, uint32_t& out_teid, uint8_t& out_qfi) noexcept {
    if (pkt.data_len < sizeof(GtpuHeader)) {
        return false;
    }

    auto* gtpu = pkt.header<GtpuHeader>();
    // Verify Version == 1 and Message Type == T-PDU
    if ((gtpu->flags & 0xE0) != GtpuConstants::VERSION_1 || gtpu->msg_type != GtpuConstants::MSG_TPDU) {
        return false;
    }

    out_teid = endian::ntohl(gtpu->teid);
    out_qfi  = 0;

    const bool has_ext  = (gtpu->flags & GtpuConstants::EXTENSION_FLAG) != 0;
    const bool has_seq  = (gtpu->flags & GtpuConstants::SEQ_NUM_FLAG) != 0;
    const bool has_npdu = (gtpu->flags & GtpuConstants::NPDU_NUM_FLAG) != 0;

    pkt.strip_header<GtpuHeader>();

    if (has_ext || has_seq || has_npdu) {
        if (pkt.data_len < sizeof(GtpuHeaderOpt)) {
            return false;
        }
        auto* opt = pkt.strip_header<GtpuHeaderOpt>();
        uint8_t next_ext = opt->next_ext_type;

        // Parse extension header chain
        while (next_ext != 0) {
            if (pkt.data_len < 4) {
                return false;
            }
            const uint8_t ext_len_units = *pkt.data();
            const uint16_t ext_len_bytes = static_cast<uint16_t>(ext_len_units * 4);
            if (ext_len_bytes == 0 || pkt.data_len < ext_len_bytes) {
                return false;
            }

            if (next_ext == GtpuConstants::EXT_TYPE_PDU_SESSION) {
                auto* psc = pkt.header<GtpuPduSessionContainer>();
                out_qfi = psc->qfi & 0x3F;
            }

            // Next extension type is located at the last octet of the current extension
            next_ext = *(pkt.data() + ext_len_bytes - 1);
            pkt.strip(ext_len_bytes);
        }
    }

    return true;
}

} // namespace telecom::core

// Bring core types into global namespace for convenience if desired
using PacketBuffer = telecom::core::PacketBuffer;
using packet_buffer = telecom::core::PacketBuffer;
using GtpuHeader = telecom::core::GtpuHeader;
using GtpuHeaderOpt = telecom::core::GtpuHeaderOpt;
using GtpuPduSessionContainer = telecom::core::GtpuPduSessionContainer;
namespace GtpuConstants = telecom::core::GtpuConstants;
namespace PacketFlags = telecom::core::PacketFlags;
using telecom::core::gtpu_encapsulate;
using telecom::core::gtpu_encapsulate_5g;
using telecom::core::gtpu_decapsulate;
