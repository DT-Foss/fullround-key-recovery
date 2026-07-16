import Foundation
import CoreFoundation
import Metal

private let shaderSource = #"""
#include <metal_stdlib>
using namespace metal;

struct SearchParams {
    uint target[8];
    uint control[8];
    uint key_words_2_to_7[6];
    uint key_word1_known;
    uint key_word1_unknown_mask;
    uint block_words[16];
    uint block_len;
    uint flags;
    uint outer;
    uint first_candidate;
    uint candidate_count;
    uint result_capacity;
};

constant uint BLAKE3_IV[4] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au
};

constant uint MSG_PERMUTATION[16] = {
    2u, 6u, 3u, 10u, 7u, 0u, 4u, 13u,
    1u, 11u, 12u, 5u, 9u, 14u, 15u, 8u
};

inline uint ror32(uint value, uint shift) {
    return (value >> shift) | (value << (32u - shift));
}

inline void g(
    thread uint *state,
    uint a,
    uint b,
    uint c,
    uint d,
    uint message_x,
    uint message_y
) {
    state[a] = state[a] + state[b] + message_x;
    state[d] = ror32(state[d] ^ state[a], 16u);
    state[c] = state[c] + state[d];
    state[b] = ror32(state[b] ^ state[c], 12u);
    state[a] = state[a] + state[b] + message_y;
    state[d] = ror32(state[d] ^ state[a], 8u);
    state[c] = state[c] + state[d];
    state[b] = ror32(state[b] ^ state[c], 7u);
}

inline void blake3_round(thread uint *state, thread uint *message) {
    g(state, 0u, 4u, 8u, 12u, message[0], message[1]);
    g(state, 1u, 5u, 9u, 13u, message[2], message[3]);
    g(state, 2u, 6u, 10u, 14u, message[4], message[5]);
    g(state, 3u, 7u, 11u, 15u, message[6], message[7]);
    g(state, 0u, 5u, 10u, 15u, message[8], message[9]);
    g(state, 1u, 6u, 11u, 12u, message[10], message[11]);
    g(state, 2u, 7u, 8u, 13u, message[12], message[13]);
    g(state, 3u, 4u, 9u, 14u, message[14], message[15]);
}

inline void permute_message(thread uint *message) {
    thread uint old[16];
    for (uint index = 0u; index < 16u; ++index) {
        old[index] = message[index];
    }
    for (uint index = 0u; index < 16u; ++index) {
        message[index] = old[MSG_PERMUTATION[index]];
    }
}

inline void blake3_keyed_root(
    thread uint *output,
    uint candidate,
    constant SearchParams &params
) {
    thread uint cv[8];
    cv[0] = candidate;
    cv[1] = (params.key_word1_known & ~params.key_word1_unknown_mask)
        | (params.outer & params.key_word1_unknown_mask);
    for (uint index = 0u; index < 6u; ++index) {
        cv[index + 2u] = params.key_words_2_to_7[index];
    }

    thread uint state[16];
    for (uint index = 0u; index < 8u; ++index) {
        state[index] = cv[index];
    }
    for (uint index = 0u; index < 4u; ++index) {
        state[index + 8u] = BLAKE3_IV[index];
    }
    state[12] = 0u;
    state[13] = 0u;
    state[14] = params.block_len;
    state[15] = params.flags;

    thread uint message[16];
    for (uint index = 0u; index < 16u; ++index) {
        message[index] = params.block_words[index];
    }
    for (uint round_index = 0u; round_index < 7u; ++round_index) {
        blake3_round(state, message);
        if (round_index != 6u) {
            permute_message(message);
        }
    }
    for (uint index = 0u; index < 8u; ++index) {
        output[index] = state[index] ^ state[index + 8u];
    }
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

kernel void blake3_keyed_filter(
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
    thread uint output[8];
    blake3_keyed_root(output, candidate, params);
    bool factual_match = true;
    bool control_match = true;
    for (uint index = 0u; index < 8u; ++index) {
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

kernel void blake3_keyed_blocks(
    constant SearchParams &params [[buffer(0)]],
    device uint *outputs [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.candidate_count) {
        return;
    }
    thread uint output[8];
    blake3_keyed_root(output, params.first_candidate + gid, params);
    for (uint index = 0u; index < 8u; ++index) {
        outputs[gid * 8u + index] = output[index];
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
    let keyWords2To7: [UInt32]
    let keyWord1Known: UInt32
    let keyWord1UnknownMask: UInt32
    let blockWords: [UInt32]
    let blockLength: UInt32
    let flags: UInt32
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
        + config.keyWords2To7
        + [config.keyWord1Known, config.keyWord1UnknownMask]
        + config.blockWords
        + [config.blockLength, config.flags, outer, first, count, capacity]
}

private final class MetalBlake3KeyedHost {
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
        guard let filter = library.makeFunction(name: "blake3_keyed_filter"),
              let blocks = library.makeFunction(name: "blake3_keyed_blocks"),
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
            "blake3_rounds": 7,
            "keyed_root_output_words_compared": 8,
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
        let output = try makeEmptyBuffer(device: device, wordCount: Int(count) * 8)
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
        let wordCount = Int(count) * 8
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
    let host = try MetalBlake3KeyedHost()
    try emit([
        "op": "ready",
        "version": "blake3-keyed-metal-native-v1",
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
                target: try word32Array(request["target"], field: "target", count: 8),
                control: try word32Array(
                    request["control"], field: "control", count: 8
                ),
                keyWords2To7: try word32Array(
                    request["key_words_2_to_7"], field: "key_words_2_to_7", count: 6
                ),
                keyWord1Known: try uint32(
                    request["key_word1_known"], field: "key_word1_known"
                ),
                keyWord1UnknownMask: try uint32(
                    request["key_word1_unknown_mask"], field: "key_word1_unknown_mask"
                ),
                blockWords: try word32Array(
                    request["block_words"], field: "block_words", count: 16
                ),
                blockLength: try uint32(request["block_len"], field: "block_len"),
                flags: try uint32(request["flags"], field: "flags")
            )
            configuration = config
            try emit([
                "op": "configured",
                "rounds": 7,
                "filter_words": 8,
                "complete_256_bit_output_comparison": true,
                "byte_semantics": "BLAKE3_little_endian",
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
