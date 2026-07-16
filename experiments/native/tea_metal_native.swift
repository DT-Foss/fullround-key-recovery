import Foundation
import CoreFoundation
import Metal

private let shaderSource = #"""
#include <metal_stdlib>
using namespace metal;

struct SearchParams {
    uint target[4];
    uint control[4];
    uint known_key[4];
    uint plaintext[4];
    uint algorithm;
    uint key_word1_unknown_mask;
    uint outer;
    uint first_candidate;
    uint candidate_count;
    uint result_capacity;
};

inline void tea_encrypt(
    thread uint *output,
    uint plaintext0,
    uint plaintext1,
    uint candidate,
    constant SearchParams &params
) {
    uint value0 = plaintext0;
    uint value1 = plaintext1;
    uint sum = 0u;
    const uint delta = 0x9e3779b9u;
    const uint key0 = candidate;
    const uint key1 = (params.known_key[1] & ~params.key_word1_unknown_mask)
        | (params.outer & params.key_word1_unknown_mask);
    const uint key2 = params.known_key[2];
    const uint key3 = params.known_key[3];
    for (uint cycle = 0u; cycle < 32u; ++cycle) {
        sum += delta;
        value0 += ((value1 << 4u) + key0)
            ^ (value1 + sum)
            ^ ((value1 >> 5u) + key1);
        value1 += ((value0 << 4u) + key2)
            ^ (value0 + sum)
            ^ ((value0 >> 5u) + key3);
    }
    output[0] = value0;
    output[1] = value1;
}

inline void xtea_encrypt(
    thread uint *output,
    uint plaintext0,
    uint plaintext1,
    uint candidate,
    constant SearchParams &params
) {
    uint value0 = plaintext0;
    uint value1 = plaintext1;
    uint sum = 0u;
    const uint delta = 0x9e3779b9u;
    thread uint key[4];
    key[0] = candidate;
    key[1] = (params.known_key[1] & ~params.key_word1_unknown_mask)
        | (params.outer & params.key_word1_unknown_mask);
    key[2] = params.known_key[2];
    key[3] = params.known_key[3];
    for (uint cycle = 0u; cycle < 32u; ++cycle) {
        value0 += (((value1 << 4u) ^ (value1 >> 5u)) + value1)
            ^ (sum + key[sum & 3u]);
        sum += delta;
        value1 += (((value0 << 4u) ^ (value0 >> 5u)) + value0)
            ^ (sum + key[(sum >> 11u) & 3u]);
    }
    output[0] = value0;
    output[1] = value1;
}

inline ulong rotl64(ulong value, uint shift) {
    return (value << shift) | (value >> (64u - shift));
}

inline void sipround(thread ulong *state) {
    state[0] += state[1];
    state[1] = rotl64(state[1], 13u);
    state[1] ^= state[0];
    state[0] = rotl64(state[0], 32u);
    state[2] += state[3];
    state[3] = rotl64(state[3], 16u);
    state[3] ^= state[2];
    state[0] += state[3];
    state[3] = rotl64(state[3], 21u);
    state[3] ^= state[0];
    state[2] += state[1];
    state[1] = rotl64(state[1], 17u);
    state[1] ^= state[2];
    state[2] = rotl64(state[2], 32u);
}

inline void siphash24_8byte(
    thread uint *output,
    uint message_low,
    uint message_high,
    uint candidate,
    constant SearchParams &params
) {
    const ulong key0 = ulong(candidate)
        | (ulong((params.known_key[1] & ~params.key_word1_unknown_mask)
            | (params.outer & params.key_word1_unknown_mask)) << 32u);
    const ulong key1 = ulong(params.known_key[2])
        | (ulong(params.known_key[3]) << 32u);
    const ulong message = ulong(message_low) | (ulong(message_high) << 32u);
    thread ulong state[4];
    state[0] = key0 ^ 0x736f6d6570736575ul;
    state[1] = key1 ^ 0x646f72616e646f6dul;
    state[2] = key0 ^ 0x6c7967656e657261ul;
    state[3] = key1 ^ 0x7465646279746573ul;
    state[3] ^= message;
    sipround(state);
    sipround(state);
    state[0] ^= message;
    const ulong last = 8ul << 56u;
    state[3] ^= last;
    sipround(state);
    sipround(state);
    state[0] ^= last;
    state[2] ^= 0xfful;
    sipround(state);
    sipround(state);
    sipround(state);
    sipround(state);
    const ulong result = state[0] ^ state[1] ^ state[2] ^ state[3];
    output[0] = uint(result);
    output[1] = uint(result >> 32u);
}

inline void family_encrypt(
    thread uint *output,
    uint plaintext0,
    uint plaintext1,
    uint candidate,
    constant SearchParams &params
) {
    if (params.algorithm == 0u) {
        tea_encrypt(output, plaintext0, plaintext1, candidate, params);
    } else if (params.algorithm == 1u) {
        xtea_encrypt(output, plaintext0, plaintext1, candidate, params);
    } else {
        siphash24_8byte(output, plaintext0, plaintext1, candidate, params);
    }
}

inline void tea_family_two_block_output(
    thread uint *output,
    uint candidate,
    constant SearchParams &params
) {
    family_encrypt(
        output,
        params.plaintext[0],
        params.plaintext[1],
        candidate,
        params
    );
    family_encrypt(
        output + 2,
        params.plaintext[2],
        params.plaintext[3],
        candidate,
        params
    );
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

kernel void tea_filter(
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
    thread uint output[4];
    tea_family_two_block_output(output, candidate, params);
    bool factual_match = true;
    bool control_match = true;
    for (uint index = 0u; index < 4u; ++index) {
        factual_match = factual_match && output[index] == params.target[index];
        control_match = control_match && output[index] == params.control[index];
    }
    if (factual_match) {
        record_candidate(
            &counts[0], factual_candidates, params.result_capacity, candidate
        );
    }
    if (control_match) {
        record_candidate(
            &counts[1], control_candidates, params.result_capacity, candidate
        );
    }
}

kernel void tea_blocks(
    constant SearchParams &params [[buffer(0)]],
    device uint *outputs [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.candidate_count) {
        return;
    }
    thread uint output[4];
    tea_family_two_block_output(output, params.first_candidate + gid, params);
    for (uint index = 0u; index < 4u; ++index) {
        outputs[gid * 4u + index] = output[index];
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
    let target: [UInt32]
    let control: [UInt32]
    let knownKey: [UInt32]
    let plaintext: [UInt32]
    let algorithm: UInt32
    let keyWord1UnknownMask: UInt32
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
    guard CFGetTypeID(number) != CFBooleanGetTypeID() else {
        throw HostError.invalidRequest("\(field) must not be boolean")
    }
    let exact = number.doubleValue
    let raw = number.uint64Value
    guard exact.isFinite,
          exact >= 0,
          exact <= Double(UInt32.max),
          exact.rounded(.towardZero) == exact,
          Double(raw) == exact else {
        throw HostError.invalidRequest("\(field) must be an exact uint32")
    }
    return UInt32(raw)
}

private func word32Array(
    _ value: Any?, field: String, count: Int
) throws -> [UInt32] {
    guard let values = value as? [Any], values.count == count else {
        throw HostError.invalidRequest("\(field) must contain \(count) words")
    }
    return try values.enumerated().map {
        try uint32($0.element, field: "\(field)[\($0.offset)]")
    }
}

private func makeBuffer(
    device: MTLDevice,
    words: [UInt32],
    options: MTLResourceOptions = .storageModeShared
) throws -> MTLBuffer {
    let buffer = words.withUnsafeBytes { raw in
        device.makeBuffer(bytes: raw.baseAddress!, length: raw.count, options: options)
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
    outer: UInt32,
    first: UInt32,
    count: UInt32,
    capacity: UInt32
) -> [UInt32] {
    return config.target
        + config.control
        + config.knownKey
        + config.plaintext
        + [config.algorithm, config.keyWord1UnknownMask, outer, first, count, capacity]
}

private final class MetalTEAHost {
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
        guard let filter = library.makeFunction(name: "tea_filter"),
              let blocks = library.makeFunction(name: "tea_blocks"),
              let queue = device.makeCommandQueue() else {
            throw HostError.metal("pipeline function or command queue missing")
        }
        do {
            filterPipeline = try device.makeComputePipelineState(function: filter)
            blocksPipeline = try device.makeComputePipelineState(function: blocks)
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
            "tea_cycles": 32,
            "tea_feistel_updates": 64,
            "algorithms": ["tea", "xtea", "siphash24"],
            "plaintext_blocks": 2,
            "output_words_compared": 4,
        ]
    }

    private func threadsPerGroup(_ pipeline: MTLComputePipelineState) -> MTLSize {
        let limit = min(256, pipeline.maxTotalThreadsPerThreadgroup)
        let width = pipeline.threadExecutionWidth
        return MTLSize(
            width: max(width, (limit / width) * width), height: 1, depth: 1
        )
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
        outer: UInt32,
        first: UInt32,
        count: UInt32,
        capacity: UInt32
    ) throws -> [String: Any] {
        guard count > 0, capacity > 0 else {
            throw HostError.invalidRequest("count and capacity must be positive")
        }
        guard UInt64(first) + UInt64(count) <= UInt64(UInt32.max) + 1 else {
            throw HostError.invalidRequest("candidate interval wraps uint32")
        }
        let params = try makeBuffer(
            device: device,
            words: parameterWords(
                config: config,
                outer: outer,
                first: first,
                count: count,
                capacity: capacity
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
        return [
            "op": "filter",
            "outer": outer,
            "first": first,
            "count": count,
            "factual": (0..<Int(factualCount)).map { factualPointer[$0] }.sorted(),
            "control": (0..<Int(controlCount)).map { controlPointer[$0] }.sorted(),
            "gpu_seconds": gpuSeconds,
        ]
    }

    func blocks(
        config: Configuration,
        outer: UInt32,
        first: UInt32,
        count: UInt32
    ) throws -> [String: Any] {
        guard count > 0, count <= 4096 else {
            throw HostError.invalidRequest("block count must be in 1...4096")
        }
        guard UInt64(first) + UInt64(count) <= UInt64(UInt32.max) + 1 else {
            throw HostError.invalidRequest("candidate interval wraps uint32")
        }
        let params = try makeBuffer(
            device: device,
            words: parameterWords(
                config: config,
                outer: outer,
                first: first,
                count: count,
                capacity: 1
            )
        )
        let output = try makeEmptyBuffer(device: device, wordCount: Int(count) * 4)
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
        let wordCount = Int(count) * 4
        let pointer = output.contents().bindMemory(to: UInt32.self, capacity: wordCount)
        return [
            "op": "blocks",
            "outer": outer,
            "first": first,
            "count": count,
            "words": (0..<wordCount).map { pointer[$0] },
            "gpu_seconds": gpuSeconds,
        ]
    }
}

do {
    let host = try MetalTEAHost()
    try emit([
        "op": "ready",
        "version": "tea-metal-native-v1",
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
                target: try word32Array(request["target"], field: "target", count: 4),
                control: try word32Array(
                    request["control"], field: "control", count: 4
                ),
                knownKey: try word32Array(
                    request["known_key"], field: "known_key", count: 4
                ),
                plaintext: try word32Array(
                    request["plaintext"], field: "plaintext", count: 4
                ),
                algorithm: try uint32(request["algorithm"], field: "algorithm"),
                keyWord1UnknownMask: try uint32(
                    request["key_word1_unknown_mask"],
                    field: "key_word1_unknown_mask"
                )
            )
            guard config.algorithm <= 2 else {
                throw HostError.invalidRequest(
                    "algorithm must be 0 (TEA), 1 (XTEA), or 2 (SipHash-2-4)"
                )
            }
            configuration = config
            let algorithmName = config.algorithm == 0
                ? "tea"
                : (config.algorithm == 1 ? "xtea" : "siphash24")
            try emit([
                "op": "configured",
                "algorithm": algorithmName,
                "algorithm_code": config.algorithm,
                "cycles": 32,
                "feistel_updates": 64,
                "plaintext_blocks": 2,
                "filter_words": 4,
                "complete_128_bit_relation_comparison": true,
                "word_semantics": "TEA_uint32_reference_words",
            ])
            continue
        }
        if operation == "quit" {
            try emit(["op": "quit"])
            break
        }
        guard let config = configuration else {
            throw HostError.invalidRequest("configure must precede execution")
        }
        let outer = try uint32(request["outer"] ?? 0, field: "outer")
        let first = try uint32(request["first"], field: "first")
        let count = try uint32(request["count"], field: "count")
        if operation == "filter" {
            let capacity = try uint32(request["capacity"] ?? 64, field: "capacity")
            try emit(
                try host.filter(
                    config: config,
                    outer: outer,
                    first: first,
                    count: count,
                    capacity: capacity
                )
            )
        } else if operation == "blocks" {
            try emit(
                try host.blocks(
                    config: config, outer: outer, first: first, count: count
                )
            )
        } else {
            throw HostError.invalidRequest("unknown op \(operation)")
        }
    }
} catch {
    FileHandle.standardError.write(Data((String(describing: error) + "\n").utf8))
    exit(1)
}
