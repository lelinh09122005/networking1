#include "include/core/timing_wheel.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <chrono>

using namespace telecom::core;

struct TestContext {
    int id{0};
    uint64_t fired_at_tick{0};
    bool fired{false};
};

void test_callback(void* arg) {
    auto* ctx = static_cast<TestContext*>(arg);
    ctx->fired = true;
}

void test_basic_scheduling() {
    std::cout << "[TEST] 1. Checking TimingWheel basic schedule & expiration..." << std::endl;
    TimingWheel<1024> tw;

    TestContext ctx1{1, 0, false};
    TestContext ctx2{2, 0, false};

    // Schedule ctx1 for 5 ticks, ctx2 for 10 ticks
    TimerId t1 = tw.schedule(5, test_callback, &ctx1);
    TimerId t2 = tw.schedule(10, test_callback, &ctx2);

    assert(t1 != INVALID_TIMER_ID);
    assert(t2 != INVALID_TIMER_ID);
    assert(tw.active_timers() == 2);

    // Advance 4 ticks
    size_t fired = tw.tick(4);
    assert(fired == 0);
    assert(!ctx1.fired && !ctx2.fired);
    assert(tw.current_tick() == 4);

    // Advance 1 tick (tick = 5) -> ctx1 should fire
    fired = tw.tick(1);
    assert(fired == 1);
    assert(ctx1.fired);
    assert(!ctx2.fired);
    assert(tw.active_timers() == 1);

    // Advance 5 ticks (tick = 10) -> ctx2 should fire
    fired = tw.tick(5);
    assert(fired == 1);
    assert(ctx2.fired);
    assert(tw.active_timers() == 0);

    std::cout << "  -> PASSED!" << std::endl;
}

void test_cancellation() {
    std::cout << "[TEST] 2. Checking O(1) Timer Cancellation..." << std::endl;
    TimingWheel<1024> tw;

    TestContext ctx1{1, 0, false};
    TestContext ctx2{2, 0, false};

    TimerId t1 = tw.schedule(10, test_callback, &ctx1);
    TimerId t2 = tw.schedule(20, test_callback, &ctx2);
    (void)t2;

    assert(tw.active_timers() == 2);

    // Cancel t1
    bool ok = tw.cancel(t1);
    assert(ok);
    assert(tw.active_timers() == 1);

    // Second cancel on same ID should fail
    bool ok2 = tw.cancel(t1);
    assert(!ok2);

    // Cancel on invalid ID should fail
    assert(!tw.cancel(INVALID_TIMER_ID));
    assert(!tw.cancel(0x123456789ULL));

    // Advance 15 ticks (tick = 15)
    tw.tick(15);
    assert(!ctx1.fired && "Cancelled timer must not fire!");
    assert(!ctx2.fired);

    // Advance 10 more ticks (tick = 25) -> t2 fires
    tw.tick(10);
    assert(ctx2.fired);
    assert(tw.active_timers() == 0);

    std::cout << "  -> PASSED!" << std::endl;
}

void test_hierarchical_cascading() {
    std::cout << "[TEST] 3. Checking Multi-Level Cascading (Level 1, 2, 3)..." << std::endl;
    TimingWheel<4096> tw;

    TestContext ctx_lvl0{0, 0, false};
    TestContext ctx_lvl1{1, 0, false};
    TestContext ctx_lvl2{2, 0, false};

    // Level 0: 50 ticks (< 256)
    // Level 1: 500 ticks (256 <= 500 < 16384)
    // Level 2: 20,000 ticks (16384 <= 20000 < 1048576)
    tw.schedule(50, test_callback, &ctx_lvl0);
    tw.schedule(500, test_callback, &ctx_lvl1);
    tw.schedule(20000, test_callback, &ctx_lvl2);

    assert(tw.active_timers() == 3);

    // Advance 49 ticks
    tw.tick(49);
    assert(!ctx_lvl0.fired);

    // Advance 1 tick -> tick 50 (Level 0 fires)
    tw.tick(1);
    assert(ctx_lvl0.fired);
    assert(!ctx_lvl1.fired);
    assert(!ctx_lvl2.fired);

    // Advance to tick 499 (cascades from Level 1 to Level 0 at tick 256)
    tw.tick(500 - 50 - 1);
    assert(!ctx_lvl1.fired);

    // Advance 1 tick -> tick 500 (Level 1 timer fires)
    tw.tick(1);
    assert(ctx_lvl1.fired);
    assert(!ctx_lvl2.fired);

    // Advance to tick 20,000 (cascades from Level 2 -> Level 1 -> Level 0)
    tw.tick(20000 - 500);
    assert(ctx_lvl2.fired);
    assert(tw.active_timers() == 0);

    std::cout << "  -> PASSED!" << std::endl;
}

void test_periodic_timer() {
    std::cout << "[TEST] 4. Checking Periodic Timer scheduling..." << std::endl;
    TimingWheel<1024> tw;

    int counter = 0;
    auto periodic_cb = [](void* arg) {
        auto* c = static_cast<int*>(arg);
        (*c)++;
    };

    // Fire every 10 ticks
    TimerId p_timer = tw.schedule_periodic(10, periodic_cb, &counter);
    assert(p_timer != INVALID_TIMER_ID);

    // Advance 55 ticks -> should fire at tick 10, 20, 30, 40, 50 (5 times)
    tw.tick(55);
    assert(counter == 5);
    assert(tw.active_timers() == 1);

    // Cancel periodic timer
    bool ok = tw.cancel(p_timer);
    assert(ok);
    assert(tw.active_timers() == 0);

    // Advance 50 more ticks -> counter should not increment
    tw.tick(50);
    assert(counter == 5);

    std::cout << "  -> PASSED!" << std::endl;
}

void test_rlc_timers_simulation() {
    std::cout << "[TEST] 5. Simulating 5G RLC Protocol Timers (t-PollRetransmit, t-Reassembly)..." << std::endl;
    // Simulate 500 concurrent RLC AM bearers, each having:
    // - t-PollRetransmit (e.g. 20 ms / 20 ticks)
    // - t-Reassembly (e.g. 15 ms / 15 ticks)
    // - t-StatusProhibit (e.g. 10 ms / 10 ticks)
    constexpr size_t NUM_BEARERS = 500;
    TimingWheel<4096> rlc_tw(1000); // 1 tick = 1 ms (1 5G TTI)

    struct BearerContext {
        uint32_t rnti;
        int poll_timeouts{0};
        int reassembly_timeouts{0};
    };

    std::vector<BearerContext> bearers(NUM_BEARERS);
    for (size_t i = 0; i < NUM_BEARERS; ++i) {
        bearers[i].rnti = static_cast<uint32_t>(1000 + i);
    }

    auto poll_timeout_cb = [](void* arg) {
        auto* b = static_cast<BearerContext*>(arg);
        b->poll_timeouts++;
    };

    auto reassembly_timeout_cb = [](void* arg) {
        auto* b = static_cast<BearerContext*>(arg);
        b->reassembly_timeouts++;
    };

    // Schedule timers for all bearers
    std::vector<TimerId> poll_timers(NUM_BEARERS);
    std::vector<TimerId> reassembly_timers(NUM_BEARERS);

    for (size_t i = 0; i < NUM_BEARERS; ++i) {
        poll_timers[i] = rlc_tw.schedule(20, poll_timeout_cb, &bearers[i]);
        reassembly_timers[i] = rlc_tw.schedule(15, reassembly_timeout_cb, &bearers[i]);
    }

    assert(rlc_tw.active_timers() == NUM_BEARERS * 2);

    // Simulate UE 0..99 receiving an ACK at 10 ms -> cancel poll timer
    for (size_t i = 0; i < 100; ++i) {
        bool ok = rlc_tw.cancel(poll_timers[i]);
        assert(ok);
    }

    // Advance to 15 ms: Reassembly timers fire for all 500 bearers!
    rlc_tw.tick(15);
    for (size_t i = 0; i < NUM_BEARERS; ++i) {
        assert(bearers[i].reassembly_timeouts == 1);
    }

    // Advance to 20 ms: Poll timers fire for the remaining 400 bearers (0..99 were cancelled)
    rlc_tw.tick(5);
    for (size_t i = 0; i < 100; ++i) {
        assert(bearers[i].poll_timeouts == 0); // Cancelled
    }
    for (size_t i = 100; i < NUM_BEARERS; ++i) {
        assert(bearers[i].poll_timeouts == 1); // Fired
    }

    assert(rlc_tw.active_timers() == 0);
    std::cout << "  -> PASSED!" << std::endl;
}

void test_timing_wheel_benchmark() {
    std::cout << "[TEST] 6. Running High-Throughput Benchmark (1,000,000 Timers)..." << std::endl;
    constexpr size_t BENCH_TIMERS = 10000; // 10k per batch
    constexpr size_t BATCHES = 100;        // Total 1,000,000 timers
    static TimingWheel<16384> tw;

    uint64_t dummy_counter = 0;
    auto bench_cb = [](void* arg) {
        auto* c = static_cast<uint64_t*>(arg);
        (*c)++;
    };

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t b = 0; b < BATCHES; ++b) {
        // Schedule 10,000 timers with delays between 1 and 200 ticks
        for (size_t i = 0; i < BENCH_TIMERS; ++i) {
            uint64_t delay = (i % 200) + 1;
            tw.schedule(delay, bench_cb, &dummy_counter);
        }

        // Advance 200 ticks to expire all scheduled timers
        tw.tick(200);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;
    const size_t total_ops = BENCH_TIMERS * BATCHES;
    double mops = (static_cast<double>(total_ops) / diff.count()) / 1'000'000.0;
    double ns_per_timer = (diff.count() * 1e9) / static_cast<double>(total_ops);

    assert(dummy_counter == total_ops);
    assert(tw.active_timers() == 0);

    std::cout << "  - Processed: " << total_ops << " timer life-cycles (schedule + cascade + fire) in " 
              << diff.count() << " s" << std::endl;
    std::cout << "  - Timing Wheel Throughput: " << mops << " Million timers/sec" << std::endl;
    std::cout << "  - Latency: " << ns_per_timer << " ns/timer lifecycle" << std::endl;
    std::cout << "  -> PASSED!" << std::endl;
}

int main() {
    std::cout << "==========================================================" << std::endl;
    std::cout << "     HIERARCHICAL TIMING WHEEL VERIFICATION SUITE         " << std::endl;
    std::cout << "==========================================================" << std::endl;

    test_basic_scheduling();
    test_cancellation();
    test_hierarchical_cascading();
    test_periodic_timer();
    test_rlc_timers_simulation();
    test_timing_wheel_benchmark();

    std::cout << "==========================================================" << std::endl;
    std::cout << "   ALL TIMING WHEEL TESTS PASSED SUCCESSFULLY!            " << std::endl;
    std::cout << "==========================================================" << std::endl;
    return 0;
}
