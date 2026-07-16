import Foundation
import Metal

private let shaderSource = #"""
#include <metal_stdlib>
using namespace metal;

constant uint rotation_constants[64] = {
    24u, 13u, 8u, 47u, 8u, 17u, 22u, 37u,
    38u, 19u, 10u, 55u, 49u, 18u, 23u, 52u,
    33u, 4u, 51u, 13u, 34u, 41u, 59u, 17u,
    5u, 20u, 48u, 41u, 47u, 28u, 16u, 25u,
    41u, 9u, 37u, 31u, 12u, 47u, 44u, 30u,
    16u, 34u, 56u, 51u, 4u, 53u, 42u, 41u,
    31u, 44u, 47u, 46u, 19u, 42u, 44u, 25u,
    9u, 48u, 35u, 52u, 23u, 31u, 37u, 20u
};
struct SearchParams {
    uint plaintext[32];
    uint target[32];
    uint control[32];
    uint key_words[32];
    uint tweak_words[4];
    uint first_candidate;
    uint candidate_count;
    uint result_capacity;
};

inline ulong pack64(uint low, uint high) {
    return ulong(low) | (ulong(high) << 32u);
}

inline uint low32(ulong value) {
    return uint(value & 0xfffffffful);
}

inline uint high32(ulong value) {
    return uint(value >> 32u);
}

inline ulong rotl64(ulong value, uint shift) {
    return (value << shift) | (value >> (64u - shift));
}

inline void inject_subkey(
    thread ulong *state,
    thread const ulong *key_schedule,
    thread const ulong *tweak_schedule,
    uint subkey
) {
    for (uint word = 0u; word < 16u; ++word) {
        state[word] += key_schedule[(subkey + word) % 17u];
    }
    state[13] += tweak_schedule[subkey % 3u];
    state[14] += tweak_schedule[(subkey + 1u) % 3u];
    state[15] += ulong(subkey);
}

inline void threefish1024_encrypt(
    thread ulong *state,
    uint candidate,
    constant SearchParams &params
) {
    thread ulong key_schedule[17];
    key_schedule[0] = pack64(candidate, params.key_words[1]);
    ulong parity = 0x1BD11BDAA9FC1A22ul ^ key_schedule[0];
    for (uint word = 1u; word < 16u; ++word) {
        key_schedule[word] = pack64(
            params.key_words[word * 2u],
            params.key_words[word * 2u + 1u]
        );
        parity ^= key_schedule[word];
    }
    key_schedule[16] = parity;

    thread ulong tweak_schedule[3];
    tweak_schedule[0] = pack64(params.tweak_words[0], params.tweak_words[1]);
    tweak_schedule[1] = pack64(params.tweak_words[2], params.tweak_words[3]);
    tweak_schedule[2] = tweak_schedule[0] ^ tweak_schedule[1];

    for (uint word = 0u; word < 16u; ++word) {
        state[word] = pack64(
            params.plaintext[word * 2u],
            params.plaintext[word * 2u + 1u]
        );
    }
    inject_subkey(state, key_schedule, tweak_schedule, 0u);

    for (uint round = 0u; round < 80u; ++round) {
        const uint rotation_offset = (round & 7u) * 8u;
        for (uint pair = 0u; pair < 8u; ++pair) {
            const uint left_index = pair * 2u;
            const uint right_index = left_index + 1u;
            state[left_index] += state[right_index];
            state[right_index] = rotl64(
                state[right_index], rotation_constants[rotation_offset + pair]
            ) ^ state[left_index];
        }
        ulong temporary = state[1];
        state[1] = state[9];
        state[9] = state[7];
        state[7] = state[15];
        state[15] = temporary;
        temporary = state[3];
        state[3] = state[13];
        state[13] = state[5];
        state[5] = state[11];
        state[11] = temporary;
        temporary = state[4];
        state[4] = state[6];
        state[6] = temporary;
        temporary = state[8];
        state[8] = state[10];
        state[10] = state[12];
        state[12] = state[14];
        state[14] = temporary;
        if ((round & 3u) == 3u) {
            inject_subkey(
                state,
                key_schedule,
                tweak_schedule,
                (round + 1u) >> 2u
            );
        }
    }
}

inline bool state_matches(thread const ulong *state, constant uint *expected) {
    for (uint word = 0u; word < 16u; ++word) {
        if (low32(state[word]) != expected[word * 2u]
            || high32(state[word]) != expected[word * 2u + 1u]) {
            return false;
        }
    }
    return true;
}

inline void record_candidate(
    device atomic_uint *count,
    device uint *candidates,
    uint capacity,
    uint candidate
) {
    const uint offset = atomic_fetch_add_explicit(count, 1u, memory_order_relaxed);
    if (offset < capacity) {
        candidates[offset] = candidate;
    }
}

kernel void threefish1024_filter(
    constant SearchParams &params [[buffer(0)]],
    device atomic_uint *counts [[buffer(1)]],
    device uint *factual_candidates [[buffer(2)]],
    device uint *control_candidates [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.candidate_count) {
        return;
    }
    const uint candidate = params.first_candidate + gid;
    thread ulong state[16];
    threefish1024_encrypt(state, candidate, params);
    if (state_matches(state, params.target)) {
        record_candidate(
            &counts[0], factual_candidates, params.result_capacity, candidate
        );
    }
    if (state_matches(state, params.control)) {
        record_candidate(
            &counts[1], control_candidates, params.result_capacity, candidate
        );
    }
}

kernel void threefish1024_blocks(
    constant SearchParams &params [[buffer(0)]],
    device uint *output [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.candidate_count) {
        return;
    }
    const uint candidate = params.first_candidate + gid;
    thread ulong state[16];
    threefish1024_encrypt(state, candidate, params);
    for (uint word = 0u; word < 16u; ++word) {
        output[gid * 32u + word * 2u] = low32(state[word]);
        output[gid * 32u + word * 2u + 1u] = high32(state[word]);
    }
}
"""#

private enum HostError: Error, CustomStringConvertible {
    case invalidRequest(String)
    case metal(String)

    var description: String {
        switch self {
        case .invalidRequest(let message):
            return "invalid request: \(message)"
        case .metal(let message):
            return "Metal failure: \(message)"
        }
    }
}

private struct Configuration {
    let plaintext: [UInt32]
    let target: [UInt32]
    let control: [UInt32]
    let keyWords: [UInt32]
    let tweakWords: [UInt32]
}

private func emit(_ value: [String: Any]) throws {
    let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0A]))
}

private func parseObject(_ line: String) throws -> [String: Any] {
    guard let data = line.data(using: .utf8) else {
        throw HostError.invalidRequest("request is not UTF-8")
    }
    let value = try JSONSerialization.jsonObject(with: data)
    guard let object = value as? [String: Any] else {
        throw HostError.invalidRequest("request must be a JSON object")
    }
    return object
}

private func uint32(_ value: Any?, field: String) throws -> UInt32 {
    guard let number = value as? NSNumber else {
        throw HostError.invalidRequest("\(field) must be an unsigned integer")
    }
    let raw = number.uint64Value
    guard raw <= UInt64(UInt32.max), number.doubleValue >= 0 else {
        throw HostError.invalidRequest("\(field) exceeds uint32")
    }
    return UInt32(raw)
}

private func uint32Array(
    _ value: Any?,
    field: String,
    count: Int
) throws -> [UInt32] {
    guard let values = value as? [Any], values.count == count else {
        throw HostError.invalidRequest("\(field) must contain \(count) words")
    }
    return try values.enumerated().map {
        try uint32($0.element, field: "\(field)[\($0.offset)]")
    }
}

private func makeBuffer(device: MTLDevice, words: [UInt32]) throws -> MTLBuffer {
    let buffer = words.withUnsafeBytes { raw in
        device.makeBuffer(
            bytes: raw.baseAddress!, length: raw.count, options: .storageModeShared
        )
    }
    guard let buffer else {
        throw HostError.metal("buffer allocation failed")
    }
    return buffer
}

private func makeEmptyBuffer(device: MTLDevice, wordCount: Int) throws -> MTLBuffer {
    guard wordCount > 0,
          let buffer = device.makeBuffer(
              length: wordCount * MemoryLayout<UInt32>.stride,
              options: .storageModeShared
          ) else {
        throw HostError.metal("empty buffer allocation failed")
    }
    memset(buffer.contents(), 0, buffer.length)
    return buffer
}

private func parameterWords(
    config: Configuration,
    first: UInt32,
    count: UInt32,
    capacity: UInt32
) -> [UInt32] {
    return config.plaintext
        + config.target
        + config.control
        + config.keyWords
        + config.tweakWords
        + [first, count, capacity]
}

private final class MetalThreefish1024Host {
    private let device: MTLDevice
    private let queue: MTLCommandQueue
    private let filterPipeline: MTLComputePipelineState
    private let blocksPipeline: MTLComputePipelineState

    init() throws {
        guard let device = MTLCreateSystemDefaultDevice() else {
            throw HostError.metal("no default device")
        }
        self.device = device
        let library: MTLLibrary
        do {
            library = try device.makeLibrary(source: shaderSource, options: nil)
        } catch {
            throw HostError.metal("runtime shader compilation: \(error)")
        }
        guard let filter = library.makeFunction(name: "threefish1024_filter"),
              let blocks = library.makeFunction(name: "threefish1024_blocks"),
              let queue = device.makeCommandQueue() else {
            throw HostError.metal("pipeline function or command queue missing")
        }
        do {
            self.filterPipeline = try device.makeComputePipelineState(function: filter)
            self.blocksPipeline = try device.makeComputePipelineState(function: blocks)
        } catch {
            throw HostError.metal("pipeline construction: \(error)")
        }
        self.queue = queue
    }

    var identity: [String: Any] {
        return [
            "device": device.name,
            "filter_execution_width": filterPipeline.threadExecutionWidth,
            "filter_max_threads_per_group": filterPipeline.maxTotalThreadsPerThreadgroup,
            "blocks_execution_width": blocksPipeline.threadExecutionWidth,
            "blocks_max_threads_per_group": blocksPipeline.maxTotalThreadsPerThreadgroup,
            "recommended_max_working_set_bytes": device.recommendedMaxWorkingSetSize,
            "shader_runtime_compiled": true,
            "native_64_bit_integer_arithmetic": true,
        ]
    }

    private func threadsPerGroup(_ pipeline: MTLComputePipelineState) -> MTLSize {
        let limit = min(256, pipeline.maxTotalThreadsPerThreadgroup)
        let width = pipeline.threadExecutionWidth
        let rounded = max(width, (limit / width) * width)
        return MTLSize(width: rounded, height: 1, depth: 1)
    }

    private func finish(_ commandBuffer: MTLCommandBuffer) throws -> Double {
        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()
        guard commandBuffer.status == .completed else {
            throw HostError.metal(
                commandBuffer.error?.localizedDescription
                    ?? "command buffer did not complete"
            )
        }
        return max(0, commandBuffer.gpuEndTime - commandBuffer.gpuStartTime)
    }

    func filter(
        config: Configuration,
        first: UInt32,
        count: UInt32,
        capacity: UInt32
    ) throws -> [String: Any] {
        guard count > 0, capacity > 0 else {
            throw HostError.invalidRequest("count and capacity must be positive")
        }
        let end = UInt64(first) + UInt64(count)
        guard end <= UInt64(UInt32.max) + 1 else {
            throw HostError.invalidRequest("candidate interval wraps uint32")
        }
        let params = try makeBuffer(
            device: device,
            words: parameterWords(
                config: config, first: first, count: count, capacity: capacity
            )
        )
        let counts = try makeEmptyBuffer(device: device, wordCount: 2)
        let factual = try makeEmptyBuffer(device: device, wordCount: Int(capacity))
        let control = try makeEmptyBuffer(device: device, wordCount: Int(capacity))
        guard let commandBuffer = queue.makeCommandBuffer(),
              let encoder = commandBuffer.makeComputeCommandEncoder() else {
            throw HostError.metal("filter command allocation failed")
        }
        encoder.setComputePipelineState(filterPipeline)
        encoder.setBuffer(params, offset: 0, index: 0)
        encoder.setBuffer(counts, offset: 0, index: 1)
        encoder.setBuffer(factual, offset: 0, index: 2)
        encoder.setBuffer(control, offset: 0, index: 3)
        encoder.dispatchThreads(
            MTLSize(width: Int(count), height: 1, depth: 1),
            threadsPerThreadgroup: threadsPerGroup(filterPipeline)
        )
        encoder.endEncoding()
        let gpuSeconds = try finish(commandBuffer)
        let countPointer = counts.contents().bindMemory(to: UInt32.self, capacity: 2)
        let factualCount = countPointer[0]
        let controlCount = countPointer[1]
        guard factualCount <= capacity, controlCount <= capacity else {
            throw HostError.metal("result capacity exhausted")
        }
        let factualPointer = factual.contents().bindMemory(
            to: UInt32.self, capacity: Int(capacity)
        )
        let controlPointer = control.contents().bindMemory(
            to: UInt32.self, capacity: Int(capacity)
        )
        let factualValues = (0..<Int(factualCount)).map { factualPointer[$0] }.sorted()
        let controlValues = (0..<Int(controlCount)).map { controlPointer[$0] }.sorted()
        return [
            "op": "filter",
            "first": first,
            "count": count,
            "factual": factualValues,
            "control": controlValues,
            "gpu_seconds": gpuSeconds,
        ]
    }

    func blocks(
        config: Configuration,
        first: UInt32,
        count: UInt32
    ) throws -> [String: Any] {
        guard count > 0, count <= 4096 else {
            throw HostError.invalidRequest("block count must be in 1...4096")
        }
        let end = UInt64(first) + UInt64(count)
        guard end <= UInt64(UInt32.max) + 1 else {
            throw HostError.invalidRequest("candidate interval wraps uint32")
        }
        let params = try makeBuffer(
            device: device,
            words: parameterWords(config: config, first: first, count: count, capacity: 1)
        )
        let output = try makeEmptyBuffer(device: device, wordCount: Int(count) * 32)
        guard let commandBuffer = queue.makeCommandBuffer(),
              let encoder = commandBuffer.makeComputeCommandEncoder() else {
            throw HostError.metal("block command allocation failed")
        }
        encoder.setComputePipelineState(blocksPipeline)
        encoder.setBuffer(params, offset: 0, index: 0)
        encoder.setBuffer(output, offset: 0, index: 1)
        encoder.dispatchThreads(
            MTLSize(width: Int(count), height: 1, depth: 1),
            threadsPerThreadgroup: threadsPerGroup(blocksPipeline)
        )
        encoder.endEncoding()
        let gpuSeconds = try finish(commandBuffer)
        let wordCount = Int(count) * 32
        let pointer = output.contents().bindMemory(to: UInt32.self, capacity: wordCount)
        let words = (0..<wordCount).map { pointer[$0] }
        return [
            "op": "blocks",
            "first": first,
            "count": count,
            "words": words,
            "gpu_seconds": gpuSeconds,
        ]
    }
}

do {
    let host = try MetalThreefish1024Host()
    try emit([
        "op": "ready",
        "version": "threefish1024-metal-native-v1",
        "metal": host.identity,
    ])
    var configuration: Configuration?
    while let line = readLine() {
        let request = try parseObject(line)
        guard let operation = request["op"] as? String else {
            throw HostError.invalidRequest("op is required")
        }
        if operation == "configure" {
            let config = Configuration(
                plaintext: try uint32Array(
                    request["plaintext"], field: "plaintext", count: 32
                ),
                target: try uint32Array(request["target"], field: "target", count: 32),
                control: try uint32Array(
                    request["control"], field: "control", count: 32
                ),
                keyWords: try uint32Array(
                    request["key_words"], field: "key_words", count: 32
                ),
                tweakWords: try uint32Array(
                    request["tweak_words"], field: "tweak_words", count: 4
                )
            )
            configuration = config
            try emit(["op": "configured", "plaintext_blocks": 1, "filter_words": 32])
            continue
        }
        if operation == "quit" {
            try emit(["op": "quit"])
            break
        }
        guard let config = configuration else {
            throw HostError.invalidRequest("configure must precede execution")
        }
        let first = try uint32(request["first"], field: "first")
        let count = try uint32(request["count"], field: "count")
        if operation == "filter" {
            let capacity = try uint32(request["capacity"] ?? 64, field: "capacity")
            try emit(
                try host.filter(
                    config: config, first: first, count: count, capacity: capacity
                )
            )
        } else if operation == "blocks" {
            try emit(try host.blocks(config: config, first: first, count: count))
        } else {
            throw HostError.invalidRequest("unknown op \(operation)")
        }
    }
} catch {
    let message = String(describing: error)
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}
